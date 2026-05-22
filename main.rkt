#lang racket/base

;;; =============================================================================
;;; trust-transpiler/main.rkt
;;; Ponto de Entrada CLI — Trust-Transpiler Scanner
;;; =============================================================================

(require racket/cmdline
         racket/file
         racket/string
         "src/uir.rkt"
         "src/parser.rkt"
         "src/taint_engine.rkt"
         "src/reporter.rkt")

;; -----------------------------------------------------------------------------
;; Programa de demonstração embutido
;; -----------------------------------------------------------------------------
;;(define *demo-program*
;;  "let raw_input = source; 
;;   let safe_val = raw_input; 
;;   sanitize(safe_val); 
;;   let user_query = source; 
;;   log(user_query); 
;;   query(safe_val);")

;; Demostração de erro de vulnerabilidade
(define *demo-program*
  "let raw_input = source; 
   let bad_val = raw_input; 
   query(bad_val);") ;; Aqui não há sanitize, logo deveria acusar falha!

;; -----------------------------------------------------------------------------
;; Pipeline principal: arquivo → UIR → análise → relatório
;; -----------------------------------------------------------------------------
(define (run-scan! target-file content color?)
  (with-handlers
    ([exn:fail?
      (λ (e)
        (displayln (format "Erro durante o scan: ~a" (exn-message e)))
        (exit 1))])
    (let* ([uir-tree (parse-program content target-file)]
           [result   (analyze-program uir-tree)])
      ;; Passamos o parâmetro de cor aqui para o reporter
      (report-analysis result target-file #:color? color?)
      
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
  (define color-mode (make-parameter #t)) ; Padrão #t (colorido)

  (command-line
    #:program "trust-transpiler"
    #:once-each
    ["--demo"
     "Executa uma análise de demonstração com código embutido"
     (demo-mode #t)]
    ["--no-color"
     "Desabilita saída colorida (útil para CI/CD)"
     (color-mode #f)] 
    #:args args

    (cond
      [(demo-mode)
       (run-scan! "<demo>" *demo-program* (color-mode))]

      [(= (length args) 1)
       (let ([file (car args)])
         (unless (file-exists? file)
           (displayln (format "Erro: arquivo não encontrado: ~a" file))
           (exit 1))
         (run-scan! file (file->string file) (color-mode)))]

      [else
       (displayln "Trust-Transpiler SAST Framework v0.1.0")
       (displayln "Uso: racket main.rkt <arquivo.tt>")
       (displayln "     racket main.rkt --demo")
       (displayln "     racket main.rkt --no-color <arquivo.tt>")
       (exit 0)])))