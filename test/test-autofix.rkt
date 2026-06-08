#lang racket/base
(require "../src/autofix.rkt"
         "../src/policy.rkt"
         "../src/types.rkt"
         "../src/uir.rkt")

;; 1. Define uma política com fix
(define-security-policy test-policy
  #:sources (source)
  #:sinks (query)
  #:sanitizers (sanitize)
  #:fixes ((query -> sanitize #:template "(sanitize ~a)")))

;; 2. Simula uma violação (igual à que seu motor gera)
(define fake-violation 
  (violation 'unsanitized-sink 'input 'query '(query) (src-location "test.tt" 10 0) 0.9))

;; 3. Testa a geração do patch
(define patch (generate-patch fake-violation test-policy))

(if patch
    (begin
      (displayln "Sucesso: Patch gerado!")
      (displayln (format "Sugestão de código: ~a" (patch-suggestion-code-suggestion patch)))
      (displayln (format "Operação: ~a" (patch-op-describe (car (patch-suggestion-uir-diff patch))))))
    (displayln "Erro: Patch não gerado!"))