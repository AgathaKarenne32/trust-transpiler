#lang racket/base

(provide score-finding
         UNKNOWN-API-SCORE)

(require "types.rkt")

;; Score fixo para qualquer finding envolvendo unknown-api
;; 0.95 = alta confiança de que é um verdadeiro positivo estrutural
(define UNKNOWN-API-SCORE 0.95)

(define (score-finding v)
  ;; FASE 4: Identifica risco estrutural via kind ou marcação no path
  (if (or (eq? (violation-kind v) 'unknown-api)
          (memq 'unknown-api (violation-taint-path v)))
      UNKNOWN-API-SCORE
      
      ;; Lógica original para violações de fluxo de dados padrão
      (let* ([path-len (length (violation-taint-path v))]
             [base (case (violation-kind v)
                     [(unsanitized-sink) 0.85]
                     [else 0.50])]
             [depth-penalty (* 0.04 (max 0 (- path-len 2)))]
             [shallow-boost (if (= path-len 1) 0.10 0.0)])
        (max 0.0 (min 1.0 (+ base shallow-boost (- depth-penalty)))))))