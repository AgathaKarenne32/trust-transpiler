#lang racket/base

(require racket/cmdline
         racket/file
         racket/string
         racket/match
         racket/list
         racket/path           
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

(define active-policy (make-parameter (security-policy 'default '() '() '() (hash))))
(define watch-path (make-parameter #f))

;; Pipeline principal: arquivo → UIR → análise → linter → relatório
;; Adicionamos parâmetros para controle da Fase 4
(define (run-scan! target-file content color? use-cache? lint-only?)
  (with-handlers ([exn:fail? (λ (e) (displayln (format "Erro: ~a" (exn-message e))) (exit 1))])
    
    ;; FASE 4: Importa snapshot do contexto anterior (se --no-cache não for usado)
    (let* ([initial-env (and use-cache?
                             (let ([snap (import-taint-snapshot target-file)])
                               (and snap (snapshot->taint-env snap))))]
           
           [uir-tree (parse-program content target-file)]
           
           ;; FASE 4: Executa análise com o ambiente inicial (se houver)
           [result (if lint-only? 
                       (analysis-result '() (make-taint-env))
                       (analyze-program uir-tree initial-env))]
           
           ;; FASE 4: Executa o linter de anti-padrões LLM
           [lint-findings (run-linter uir-tree)]
           [lint-violations (map lint-finding->violation lint-findings)]
           
           ;; Mescla violações de taint com violações do linter
           [violations (append (analysis-result-violations result) lint-violations)]
           [patches (generate-patches-for-all violations (active-policy))])

      ;; FASE 4: Exporta snapshot para o próximo módulo
      (when use-cache? (export-taint-snapshot (analysis-result-final-env result) target-file))

      ;; Relatório
      (report-analysis (analysis-result violations (analysis-result-final-env result)) target-file #:color? color?)
      
      ;; Sugestões (Autofix)
      (for-each (λ (p) (displayln (format "Autofix: ~a" (patch-suggestion-code-suggestion p)))) patches)

      ;; Exit code
      (if (> (length (filter (λ (v) (eq? (violation-kind v) 'unsanitized-sink)) violations)) 0)
          (exit 1)
          (exit 0)))))

(module+ main
  (load-stubs-from-dir! "./stubs")
  
  (define-security-policy default-policy
    #:sources (source)
    #:sinks (query log)
    #:sanitizers (sanitize)
    #:fixes ((query -> sanitize #:template "(sanitize ~a)")))
    
  (active-policy default-policy)
  
  ;; Parâmetros da FASE 4
  (define demo-mode (make-parameter #f))
  (define color-mode (make-parameter #t))
  (define cache-mode (make-parameter #t))
  (define strict-mode (make-parameter #f))
  (define lint-only-mode (make-parameter #f))

  (command-line
    #:program "trust-transpiler"
    #:once-each
    ["--demo" "Demo padrão" (demo-mode #t)]
    ["--watch" path "Modo Watch" (watch-path path)] ;; Captura o valor corretamente aqui
    ["--no-cache" "Desabilita cross-chunk" (cache-mode #f)]
    ["--strict-mode" "Ativa Gatekeeper" (begin (gate:enable-strict-mode!) (strict-mode #t))]
    ["--lint-only" "Executa apenas Linter" (lint-only-mode #t)]
    ["--no-color" "Sem cor" (color-mode #f)]
    #:args args

    (cond
      [(watch-path) (watch-mode (watch-path))] ;; A função é chamada aqui, após o parse das flags
      [(demo-mode) (run-scan! "<demo>" *demo-program* (color-mode) (cache-mode) (lint-only-mode))]
      [(and (= (length args) 1) (not (watch-path)))
       (run-scan! (car args) (file->string (car args)) (color-mode) (cache-mode) (lint-only-mode))]
      [else (displayln "Uso: racket main.rkt [flags] <arquivo>") (exit 0)])))


(define *demo-program*
  "let raw_input = source; 
   let safe_val = raw_input; 
   sanitize(safe_val); 
   let user_query = source; 
   log(user_query); 
   query(safe_val);")

(define *demo-ai-antipatterns*
  "let user_id = source;
   let q = string-append;
   exec(user_id);
   md5(user_id);")

(define (get-mtime path)
  (if (file-exists? path) (file-or-directory-modify-seconds path) 0))

(define (watch-mode path)
  (displayln (format "Trust-Transpiler Watch Mode — monitorando ~a" path))
  (displayln "Aguardando alterações... (Ctrl+C para encerrar)")
  (let loop ([last-mtimes (make-hash)])
    ;; Identifica arquivos .tt (lista arquivos se diretório, ou o próprio se arquivo)
    (define files (if (directory-exists? path)
                      (filter (λ (p) (string-suffix? (path->string p) ".tt")) 
                              (directory-list path #:build? #t))
                      (list (string->path path))))
    
    (for ([f files])
      (define current-mtime (get-mtime f))
      (when (> current-mtime (hash-ref last-mtimes f 0))
        (displayln (format "[~a] ~a modificado — analisando..." 
                           (substring (number->string (current-seconds)) 8)
                           (file-name-from-path f)))
        (with-handlers ([exn:fail? (λ (e) (displayln (format "Erro na análise: ~a" (exn-message e))))])
          (run-scan! (path->string f) (file->string f) #t #t #f))
        (hash-set! last-mtimes f current-mtime)))
    
    (sleep 0.5) ; Polling a cada 500ms
    (loop last-mtimes)))
