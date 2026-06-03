#lang racket/base

(require racket/list
         racket/string
         "uir.rkt"
         "taint_engine.rkt")

;; Exportações corrigidas
(provide
  report-analysis
  report-violation
  report-summary
  format-violation
  severity->string
  *use-color-output*)

;; Habilita/desabilita saída colorida
(define *use-color-output* #t)

;; Códigos de cor ANSI
(define ANSI-RESET   "\033[0m")
(define ANSI-RED     "\033[0;31m")
(define ANSI-YELLOW  "\033[0;33m")
(define ANSI-GREEN   "\033[0;32m")
(define ANSI-BOLD    "\033[1m")
(define ANSI-CYAN    "\033[0;36m")
(define ANSI-GRAY    "\033[0;90m")

(define (colorize code str)
  (if *use-color-output*
      (string-append code str ANSI-RESET)
      str))

;; -----------------------------------------------------------------------------
;; Funções auxiliares
;; -----------------------------------------------------------------------------

(define (severity->string kind)
  (case kind
    [(unsanitized-sink) "HIGH"]
    [(taint-flow)       "MEDIUM"]
    [else               "INFO"]))

(define (severity->color kind)
  (case kind
    [(unsanitized-sink) ANSI-RED]
    [(taint-flow)       ANSI-YELLOW]
    [else               ANSI-CYAN]))

(define (format-violation v [index 1])
  (let* ([kind     (violation-kind v)]
         [sev      (severity->string kind)]
         [loc      (violation-location v)]
         [file     (if loc (src-location-file loc) "?")]
         [line     (if loc (src-location-line loc) "?")]
         ;; 1. Leia o novo campo
         [conf     (violation-confidence v)] 
         [path-str (string-join (map symbol->string (violation-taint-path v)) " → ")])
    (string-append
      "\n"
      (colorize ANSI-BOLD (format "  [~a] Vulnerability #~a — ~a\n" sev index (violation-kind v)))
      (colorize ANSI-GRAY (format "  Location   : ~a (token position ~a)\n" file line))
      ;; 2. Exiba o campo de confiança formatado como porcentagem
      (format "  Confidence : ~a%\n" (colorize ANSI-GREEN (number->string (* 100 conf))))
      (format "  Source Var : ~a\n" (colorize ANSI-YELLOW (symbol->string (violation-source-var v))))
      (format "  Sink Func  : ~a\n" (colorize ANSI-RED (symbol->string (violation-sink-func v))))
      (if (not (null? (violation-taint-path v)))
          (format "  Taint Path : ~a\n" (colorize ANSI-CYAN path-str))
          "")
      (colorize ANSI-GRAY (format "  Description: Tainted data from '~a' flows unsanitized into sink '~a'.\n"
                                  (violation-source-var v)
                                  (violation-sink-func v))))))

;; -----------------------------------------------------------------------------
;; Relatório
;; -----------------------------------------------------------------------------

(define (report-analysis result scan-target #:color? [use-color #t])
  (set! *use-color-output* use-color)
  (let ([violations (analysis-result-violations result)])
    (report-header scan-target)
    (if (null? violations)
        (report-clean scan-target)
        (begin
          (for-each
            (λ (v idx) (display (format-violation v idx)))
            violations
            (build-list (length violations) (λ (i) (+ i 1))))
          (report-summary violations)))))

(define (report-violation v)
  (display (format-violation v)))

(define (report-header target)
  (displayln (colorize ANSI-BOLD "\n╔══════════════════════════════════════════════╗"))
  (displayln (colorize ANSI-BOLD "║    Trust-Transpiler SAST — Scan Report       ║"))
  (displayln (colorize ANSI-BOLD "╚══════════════════════════════════════════════╝"))
  (displayln (format "  Target  : ~a" (colorize ANSI-CYAN target)))
  (displayln (format "  Engine  : Taint Analysis v0.1.0"))
  (displayln (colorize ANSI-GRAY "  ─────────────────────────────────────────────")))

(define (report-clean target)
  (displayln (colorize ANSI-GREEN "  ✓ No vulnerabilities detected. Target appears clean.\n")))

(define (report-summary violations)
  (let* ([high (length (filter (λ (v) (eq? (violation-kind v) 'unsanitized-sink)) violations))]
         [medium (length (filter (λ (v) (eq? (violation-kind v) 'taint-flow)) violations))]
         [total (length violations)])
    (displayln (colorize ANSI-GRAY "\n  ─────────────────────────────────────────────"))
    (displayln (colorize ANSI-BOLD "  Summary:"))
    (displayln (format "  Total violations : ~a" (colorize ANSI-BOLD (number->string total))))
    (displayln (format "  HIGH severity    : ~a" (if (> high 0) (colorize ANSI-RED (number->string high)) (number->string high))))
    (displayln (format "  MEDIUM severity  : ~a" (if (> medium 0) (colorize ANSI-YELLOW (number->string medium)) (number->string medium))))
    (when (> high 0)
      (displayln (colorize ANSI-RED "\n  ⚠  ACTION REQUIRED: HIGH severity issues must be fixed before deployment.\n")))
    (newline)))