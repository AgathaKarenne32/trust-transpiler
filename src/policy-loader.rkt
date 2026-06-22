#lang racket/base

(require json)

(provide current-sources
         current-sinks
         current-sanitizers
         load-policy!)

;; Parâmetros que guardam o estado atual da política (iniciam vazios)
(define current-sources (make-parameter '()))
(define current-sinks (make-parameter '()))
(define current-sanitizers (make-parameter '()))

;; Função que lê o JSON e atualiza os parâmetros
(define (load-policy! filepath)
  (with-handlers ([exn:fail? (lambda (exn)
                               (displayln (format "Aviso: Falha ao carregar ~a. Erro: ~a" filepath (exn-message exn))))])
    (let* ([input-port (open-input-file filepath)]
           [policy-hash (read-json input-port)])
      (close-input-port input-port)
      
      ;; Extrai as listas do JSON
      (define sources (hash-ref policy-hash 'sources '()))
      ;; Sinks e Sanitizers são convertidos para símbolos pois o parser os trata assim ('query, 'log)
      (define sinks (map string->symbol (hash-ref policy-hash 'sinks '())))
      (define sanitizers (map string->symbol (hash-ref policy-hash 'sanitizers '())))
      
      ;; Atualiza o motor com as novas regras
      (current-sources sources)
      (current-sinks sinks)
      (current-sanitizers sanitizers)
      
      (displayln (format "Políticas carregadas com sucesso de '~a'." filepath))
      #t)))