#lang racket/base

(require racket/list
         racket/file
         racket/path)

(provide register-stub!
         load-stubs-from-dir!
         stub-policy-for)

;; Dicionário em memória para armazenar as políticas dos stubs
(define *stub-registry* (make-hash))

;; Registra uma política para uma biblioteca específica
(define (register-stub! lib-name policy)
  (hash-set! *stub-registry* lib-name policy))

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