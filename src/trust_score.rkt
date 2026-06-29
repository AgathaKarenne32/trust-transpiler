#lang racket/base

;;; =============================================================================
;;; trust-transpiler/src/trust_score.rkt
;;;
;;; AI Code Trust Score
;;; ─────────────────────
;;; Resume o resultado de uma análise (violações de taint + chamadas de API
;;; desconhecidas detectadas pelo Gatekeeper) em uma nota única de 0 a 100,
;;; pensada para gates de CI/CD: "este código gerado/revisado por IA é
;;; confiável o suficiente para merge?"
;;;
;;; Pesos:
;;;   - unsanitized-sink  -> penalidade alta (risco de exploração direta)
;;;   - policy-violation  -> penalidade média
;;;   - unknown-api       -> penalidade adicional fixa por chamada (risco
;;;                          estrutural: API que pode não existir)
;;; =============================================================================

(require racket/string
         racket/list
         "types.rkt")

(provide compute-trust-score
         trust-score->grade
         trust-report->jsexpr
         (struct-out trust-report))

(struct trust-report (score grade total-violations unknown-api-count breakdown) #:transparent)

(define SINK-PENALTY 18.0)
(define POLICY-PENALTY 10.0)
(define INFO-PENALTY 3.0)
(define UNKNOWN-API-PENALTY 12.0)

(define (violation-penalty v)
  (case (violation-kind v)
    [(unsanitized-sink) SINK-PENALTY]
    [(policy-violation) POLICY-PENALTY]
    [else INFO-PENALTY]))

;; violations: (Listof violation?) — pode incluir violações de kind 'unknown-api
;;   geradas pelo Gatekeeper (src/api_gatekeeper.rkt via taint_engine.rkt).
;; extra-unknown-api-count: contagem adicional de chamadas unknown-api que não
;;   chegaram a virar violation? (ex.: contadas separadamente pelo caller).
(define (compute-trust-score violations [extra-unknown-api-count 0])
  (define sink-count (length (filter (λ (v) (eq? (violation-kind v) 'unsanitized-sink)) violations)))
  (define policy-count (length (filter (λ (v) (eq? (violation-kind v) 'policy-violation)) violations)))
  (define unknown-api-from-violations (length (filter (λ (v) (eq? (violation-kind v) 'unknown-api)) violations)))
  (define unknown-api-count (+ unknown-api-from-violations extra-unknown-api-count))
  (define other-count (- (length violations) sink-count policy-count unknown-api-from-violations))

  (define raw-penalty
    (+ (* sink-count SINK-PENALTY)
       (* policy-count POLICY-PENALTY)
       (* (max 0 other-count) INFO-PENALTY)
       (* unknown-api-count UNKNOWN-API-PENALTY)))

  (define score (max 0.0 (min 100.0 (- 100.0 raw-penalty))))

  (trust-report score
                (trust-score->grade score)
                (length violations)
                unknown-api-count
                (list (cons 'unsanitized-sink sink-count)
                      (cons 'policy-violation policy-count)
                      (cons 'unknown-api unknown-api-count))))

(define (trust-score->grade score)
  (cond
    [(>= score 90) 'A]
    [(>= score 75) 'B]
    [(>= score 60) 'C]
    [(>= score 40) 'D]
    [else 'F]))

;; Serializa para uma jsexpr simples (sem dependência de json.rkt no caller).
(define (trust-report->jsexpr report)
  (hash 'score (trust-report-score report)
        'grade (symbol->string (trust-report-grade report))
        'total_violations (trust-report-total-violations report)
        'unknown_api_count (trust-report-unknown-api-count report)
        'breakdown (for/hash ([pair (trust-report-breakdown report)])
                     (values (car pair) (cdr pair)))))