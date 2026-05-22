#lang racket/base

;;; =============================================================================
;;; trust-transpiler/main.rkt
;;; Ponto de Entrada CLI — Trust-Transpiler Scanner
;;;
;;; Uso:
;;;   raco trust-transpiler <arquivo.tt>
;;;   racket main.rkt <arquivo.tt>
;;;   racket main.rkt --demo       (executa com exemplo embutido)
;;; =============================================================================

(require racket/cmdline
         racket/file
         racket/string
         "src/uir.rkt"
         "src/parser.rkt"
         "src/taint_engine.rkt"
         "src/reporter.rkt")

;; -----------------------------------------------------------------------------
;; Programa de demonstração embutido (usado com --demo)
;; Simula um código com dois fluxos: um seguro e um inseguro.
;; -----------------------------------------------------------------------------
(define *demo-program*
  "let raw_input = source();
   let safe_val = raw_input;
   sanitize(safe_val);
   let user_query = source();
   if (flag) log(user_query);
   query(safe_val);")

;; -----------------------------------------------------------------------------
;; Pipeline principal: arquivo → UIR → análise → relatório
;; -----------------------------------------------------------------------------
(define (run-scan! target-file content)
  (with-handlers
    ([exn:fail?
      (λ (e)
        (displayln (format "Erro durante o scan: ~a" (exn-message e)))
        (exit 1))])
    (let* ([uir-tree (parse-program content target-file)]
           [result   (analyze-program uir-tree)])
      (report-analysis result target-file)
      ;; Exit code 1 se houver violações HIGH (para uso em CI/CD)
      (if (> (length (filter (λ (v) (eq? (violation-kind v) 'unsanitized-sink))
                             (analysis-result-violations result)))
             0)
          (exit 1)
          (exit 0)))))

;; -----------------------------------------------------------------------------
;; CLI
;; -----------------------------------------------------------------------------
(module+ main
  (define demo-mode (make-parameter #f))

  (command-line
    #:program "trust-transpiler"
    #:once-each
    ["--demo"
     "Executa uma análise de demonstração com código embutido"
     (demo-mode #t)]
    ["--no-color"
     "Desabilita saída colorida (útil para CI/CD)"
     (set! *use-color-output* #f)]
    #:args args

    (cond
      ;; Modo demo: usa código embutido
      [(demo-mode)
       (run-scan! "<demo>" *demo-program*)]

      ;; Modo normal: lê arquivo fornecido
      [(= (length args) 1)
       (let ([file (car args)])
         (unless (file-exists? file)
           (displayln (format "Erro: arquivo não encontrado: ~a" file))
           (exit 1))
         (run-scan! file (file->string file)))]

      ;; Sem argumentos: mostra ajuda
      [else
       (displayln "Trust-Transpiler SAST Framework v0.1.0")
       (displayln "Uso: racket main.rkt <arquivo.tt>")
       (displayln "     racket main.rkt --demo")
       (displayln "     racket main.rkt --no-color <arquivo.tt>")
       (exit 0)])))