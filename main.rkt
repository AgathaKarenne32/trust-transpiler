#lang racket/base

(require racket/cmdline
         racket/file
         racket/string
         racket/match
         racket/list
         racket/path  
         racket/system
         racket/port     
         "src/types.rkt"  
         "src/uir.rkt"
         "src/parser.rkt"
         "src/taint_engine.rkt"
         "src/reporter.rkt"
         "src/stub-registry.rkt"
         "src/fp_scorer.rkt"
         "src/autofix.rkt"
         "src/policy.rkt"
         "src/cross_chunk_tracker.rkt"
         (prefix-in gate: "src/api_gatekeeper.rkt")
         "src/ai_security_linter.rkt"
         )

;; 1. Definição Global da Política (Movido para fora do module+)
(define default-policy
  (security-policy 'default '(source) '(query log) '(sanitize) 
                   (hash 'query (fix-entry 'sanitize "(sanitize ~a)"))))

(define (severity->int s)
  (case (string->symbol (string-downcase (symbol->string s)))
    [(high) 3] [(medium) 2] [(info) 1] [else 1]))

(define (check-violations v-list)
  (define min-sev (severity->int (fail-level)))
  (define (get-severity-from-kind kind)
    (case kind [(unsanitized-sink) 3] [(policy-violation) 2] [else 1]))
  (filter (λ (v) (>= (get-severity-from-kind (violation-kind v)) min-sev)) v-list))

(define active-policy (make-parameter default-policy))
(define watch-path (make-parameter #f))
(define diff-range (make-parameter #f))
(define fail-level (make-parameter 'info))

(define (run-scan! target-file content color? use-cache? lint-only?)
  (with-handlers ([exn:fail? (λ (e) (displayln (format "Erro: ~a" (exn-message e))) (exit 1))])
    
    (let* ([initial-env (and use-cache?
                             (let ([snap (import-taint-snapshot target-file)])
                               (and snap (snapshot->taint-env snap))))]
           [uir-tree (parse-program content target-file)]
           ;; Definimos 'result' aqui dentro do let*
           [result (if lint-only? 
                       (analysis-result '() (make-taint-env))
                       (analyze-program uir-tree (or initial-env (make-taint-env))))]
           [lint-findings (run-linter uir-tree)]
           [lint-violations (map lint-finding->violation lint-findings)]
           ;; Combinamos as violações
           [violations (append (analysis-result-violations result) lint-violations)]
           [patches (generate-patches-for-all violations (active-policy))])

      ;; Agora 'violations' e 'result' estão definidos e visíveis aqui
      (when use-cache? (export-taint-snapshot (analysis-result-final-env result) target-file))
      
      (report-analysis (analysis-result violations (analysis-result-final-env result)) target-file #:color? color?)
      (for-each (λ (p) (displayln (format "Autofix: ~a" (patch-suggestion-code-suggestion p)))) patches)

      (if (> (length (filter (λ (v) (eq? (violation-kind v) 'unsanitized-sink)) violations)) 0)
          (exit 1)
          (exit 0)))))

(define (run-scan-and-return target-file content color? use-cache? lint-only?)
  (with-handlers ([exn:fail? (λ (e) (displayln (format "Erro: ~a" (exn-message e))) '())])
    (let* ([uir-tree (parse-program content target-file)]
           [result (if lint-only? 
                       (analysis-result '() (make-taint-env))
                       (analyze-program uir-tree (make-taint-env)))]

           [_ (displayln (format "Debug: Violações encontradas pelo motor: ~a" (analysis-result-violations result)))]
           (displayln (format "Debug: AST gerada: ~a" uir-tree))
           [lint-findings (run-linter uir-tree)]
           [lint-violations (map lint-finding->violation lint-findings)]
           [violations (append (analysis-result-violations result) (map lint-finding->violation (run-linter uir-tree)))])
      violations)))

(define (run-interactive-fix target-file)
  (load-stubs-from-dir! "./stubs")
  (active-policy default-policy)
  (define content (file->string target-file))
  (define violations (run-scan-and-return target-file content #t #t #f))
  (if (null? violations)
      (displayln "Nenhuma violação encontrada.")
      (process-violations-interactively target-file content violations)))

(module+ main
  (load-stubs-from-dir! "./stubs")
  (active-policy default-policy)

  (define demo-mode (make-parameter #f))
  (define color-mode (make-parameter #t))
  (define watch-path (make-parameter #f))
  (define cache-mode (make-parameter #t))
  (define strict-mode (make-parameter #f))
  (define lint-only-mode (make-parameter #f))
  (define diff-range (make-parameter #f))

  (define (run-scan-and-evaluate! target-file content)
    (let* ([violations (run-scan-and-return target-file content #f #t #f)]
          [verdict (gate:evaluate-violations violations)])
      (if (equal? verdict 'BLOCK)
          (begin (displayln "Gatekeeper: Veto de Segurança!") (exit 1))
          (exit 0))))

  (define (get-changed-files range)
    ;; Range chega como "HEAD~1..HEAD"
    (define-values (sp out in err) 
      (subprocess #f #f #f "/usr/bin/git" "diff" "--name-only" range))
    
    (subprocess-wait sp)
    
    (if (not (= (subprocess-status sp) 0))
        (begin 
          (displayln (format "Erro: O comando 'git diff --name-only ~a' falhou." range)) 
          (exit 2))
        (let* ([output (port->string out)]
               [files (string-split output "\n")])
          (close-input-port out)
          (close-output-port in)
          (close-input-port err)
          (filter (λ (f) (string-suffix? f ".tt")) files))))

  (command-line
    #:program "trust-transpiler"
    #:once-each
    ["--diff" range "Análise incremental de PR" (diff-range range)]
    ["--fail-on" level "Severidade mínima de bloqueio" (fail-level (string->symbol level))]
    ["--demo" "Demo padrão" (demo-mode #t)]
    ["--watch" path "Modo Watch" (watch-path path)]
    ["--no-cache" "Desabilita cross-chunk" (cache-mode #f)]
    ["--strict-mode" "Ativa Gatekeeper" (begin (gate:enable-strict-mode!) (strict-mode #t))]
    ["--lint-only" "Executa apenas Linter" (lint-only-mode #t)]
    ["--no-color" "Sem cor" (color-mode #f)]
    #:args positional-args

    (cond
      [(diff-range)
       (let* ([files (get-changed-files (diff-range))])
         (displayln (format "Trust-Transpiler — Diff Analysis\nRange: ~a\nArquivos: ~a" (diff-range) (length files)))
         (define all-violations 
           (apply append 
                  (for/list ([f files])
                    (displayln (format "Analisando: ~a" f))
                    (run-scan-and-return f (file->string f) (color-mode) #t #f))))
         (define filtered (check-violations all-violations))
         (define verdict (gate:evaluate-violations filtered))
         (displayln (format "\n─────────────────────────────────────\nResultado: ~a violação(ões) encontrada(s)" (length filtered)))
         (if (or (> (length filtered) 0) (equal? verdict 'BLOCK))
             (begin (displayln (format "Status: FALHOU — Gatekeeper Veto")) (exit 1))
             (begin (displayln "Status: PASSOU") (exit 0))))]
      
      [(watch-path) (watch-mode (watch-path))]
      [(demo-mode) (run-scan! "<demo>" *demo-program* (color-mode) (cache-mode) (lint-only-mode))]
      [(and (not (null? positional-args)) (string=? (car positional-args) "fix"))
       (if (and (pair? (cdr positional-args)) (cadr positional-args))
       (run-interactive-fix (cadr positional-args))
       (displayln "Erro: O comando 'fix' requer um nome de arquivo."))]
      [(not (null? positional-args))
       (let* ([target (car positional-args)]
              [content (file->string target)]
              [v-list (run-scan-and-return target content (color-mode) (cache-mode) (lint-only-mode))]
              [verdict (gate:evaluate-violations (check-violations v-list))])
         (if (equal? verdict 'BLOCK) (exit 1) (exit 0)))]
      
      [else (displayln "Uso: trust-transpiler [fix <arquivo> | <arquivo>]") (exit 0)])))


(define *demo-program* "let raw_input = source; let safe_val = raw_input; sanitize(safe_val); let user_query = source; log(user_query); query(safe_val);")
(define (get-mtime path) (if (file-exists? path) (file-or-directory-modify-seconds path) 0))

(define (watch-mode path)
  (displayln (format "Trust-Transpiler Watch Mode — monitorando ~a" path))
  (let loop ([last-mtimes (make-hash)])
    (define files (if (directory-exists? path) (filter (λ (p) (string-suffix? (path->string p) ".tt")) (directory-list path #:build? #t)) (list (string->path path))))
    (for ([f files])
      (define current-mtime (get-mtime f))
      (when (> current-mtime (hash-ref last-mtimes f 0))
        (displayln (format "[~a] modificado..." (file-name-from-path f)))
        (with-handlers ([exn:fail? (λ (e) (displayln (format "Erro: ~a" (exn-message e))))])
          (run-scan! (path->string f) (file->string f) #t #t #f))
        (hash-set! last-mtimes f current-mtime)))
    (sleep 0.5)
    (loop last-mtimes)))

