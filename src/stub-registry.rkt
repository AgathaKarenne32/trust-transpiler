#lang racket/base

(require racket/list
         racket/file
         racket/path)

(provide register-stub! 
         load-stubs-from-dir! 
         stub-policy-for 
         lookup-stub       
         calculate-stub-taint)

;; Dicionário em memória para armazenar as políticas dos stubs
(define *stub-registry* (make-hash))

;; Registra uma política para uma biblioteca específica
(define (register-stub! lib-name policy)
  (hash-set! *stub-registry* lib-name policy))

;; lookup-stub: Busca uma função dentro de todas as políticas registradas
;; Esta função percorre o registro para encontrar a política que contém a função.
(define (lookup-stub func-sym)
  (for/or ([policy (hash-values *stub-registry*)])
    (cond
      [(and (assq 'sinks policy) (member func-sym (cdr (assq 'sinks policy)))) 'sink]
      [(and (assq 'sanitizers policy) (member func-sym (cdr (assq 'sanitizers policy)))) 'sanitizer]
      [(and (assq 'sources policy) (member func-sym (cdr (assq 'sources policy)))) 'source]
      [else #f])))

;; calculate-stub-taint: Define o efeito de taint baseado na política da função
(define (calculate-stub-taint func-sym args)
  (let ([type (lookup-stub func-sym)])
    (case type
      [(sanitizer) 'sanitized]
      [(sink)      'tainted]
      [else        'tainted])))

;; Carrega todos os arquivos .stub.rkt de uma pasta
(define (load-stubs-from-dir! dir-path)
  (when (directory-exists? dir-path)
    (for ([file (in-directory dir-path)])
      (when (and (file-exists? file)
                 (equal? (path-get-extension file) #".rkt"))
        ;; O stub deve exportar uma política com o nome da biblioteca
        (dynamic-require file #f)))))

;; Busca a política de uma biblioteca pelo nome
(define (stub-policy-for lib-name)
  (hash-ref *stub-registry* lib-name #f))