#lang racket/base
(provide score-finding)
(require "types.rkt")

(define (score-finding v)
  (let* ([path-len (length (violation-taint-path v))]
         ;; Base de confiança pelo tipo de violação
         [base (case (violation-kind v)
                 [(unsanitized-sink) 0.85]
                 [else 0.50])]
         ;; Penalidade por caminhos longos (risco de over-approximation)
         [depth-penalty (* 0.04 (max 0 (- path-len 2)))]
         ;; Boost para caminhos diretos (source -> sink)
         [shallow-boost (if (= path-len 1) 0.10 0.0)])
    (max 0.0 (min 1.0 (+ base shallow-boost (- depth-penalty))))))