#lang racket/base
(provide (struct-out violation))

;; Uma violação de segurança detectada
(struct violation
  (kind       ; Symbol  — tipo: 'taint-flow | 'unsanitized-sink
   source-var ; Symbol  — variável/expr de origem do taint
   sink-func  ; Symbol  — função sink que recebeu o valor tainted
   taint-path ; (Listof Symbol) — caminho de propagação do taint
   location   ; src-location? — onde a violação ocorre
   confidence ) ;; float (0.0 a 1.0)  
  #:transparent)