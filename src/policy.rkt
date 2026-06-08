#lang racket/base

;;; =============================================================================
;;; trust-transpiler/src/policy.rkt
;;; =============================================================================

(require (for-syntax racket/base
                     racket/list
                     racket/syntax))

(provide
 define-security-policy
 (struct-out security-policy)
 (struct-out fix-entry)
 policy-source?
 policy-sink?
 policy-sanitizer?
 policy-fix-for)

;; ─────────────────────────────────────────────────────────────────────────────
;; Estruturas de Runtime
;; ─────────────────────────────────────────────────────────────────────────────

(struct fix-entry
  (sanitizer  ; Symbol
   template)  ; String
  #:transparent)

(struct security-policy
  (name
   sources
   sinks
   sanitizers
   fixes-table)
  #:transparent)

;; ─────────────────────────────────────────────────────────────────────────────
;; Predicados de Runtime
;; ─────────────────────────────────────────────────────────────────────────────

(define (policy-source?    pol sym) (and (memq sym (security-policy-sources    pol)) #t))
(define (policy-sink?      pol sym) (and (memq sym (security-policy-sinks      pol)) #t))
(define (policy-sanitizer? pol sym) (and (memq sym (security-policy-sanitizers pol)) #t))

(define (policy-fix-for pol sink-sym)
  (hash-ref (security-policy-fixes-table pol) sink-sym #f))

;; ─────────────────────────────────────────────────────────────────────────────
;; Helpers de Fase de Compilação (for-syntax)
;; ─────────────────────────────────────────────────────────────────────────────

(define-for-syntax (extract-clause clauses kw-sym)
  (let loop ([cs clauses])
    (cond
      [(null? cs)       '()]
      [(null? (cdr cs)) '()]
      [(and (keyword? (syntax-e (car cs)))
            (eq? (syntax-e (car cs)) kw-sym))
       (syntax->list (cadr cs))]
      [else (loop (cdr cs))])))

(define-for-syntax (compile-fix-list fix-stxs)
  (if (null? fix-stxs)
      #'(hash)
      (let ([pairs
             (map (λ (entry-stx)
                    (syntax-case entry-stx (->) ;; Usando -> comum para evitar erro de encoding
                      [(sink-sym -> san-sym #:template tmpl-str)
                       (list #'sink-sym #'san-sym #'tmpl-str)]
                      [(sink-sym -> san-sym)
                       (let ([default-tmpl (format "(~a ~~a)" (syntax-e #'san-sym))])
                         (list #'sink-sym #'san-sym (datum->syntax entry-stx default-tmpl)))]
                      [other
                       (raise-syntax-error 'define-security-policy 
                                           "Entrada #:fixes inválida. Use: (sink -> sanitizer) ou (sink -> sanitizer #:template \"...\")" 
                                           entry-stx)]))
                  fix-stxs)])
        (with-syntax ([(sink ...)  (map car   pairs)]
                      [(san  ...)  (map cadr  pairs)]
                      [(tmpl ...)  (map caddr pairs)])
          #'(hash (~@ 'sink (fix-entry 'san tmpl)) ...)))))

;; ─────────────────────────────────────────────────────────────────────────────
;; MACRO PRINCIPAL
;; ─────────────────────────────────────────────────────────────────────────────

(define-syntax (define-security-policy stx)
  (syntax-case stx ()
    [(_ pol-id . clauses)
     (let* ([cs (syntax->list #'clauses)]
            [srcs (extract-clause cs '#:sources)]
            [snks (extract-clause cs '#:sinks)]
            [sans (extract-clause cs '#:sanitizers)]
            [fixes-raw (extract-clause cs '#:fixes)]
            [fixes-code (compile-fix-list fixes-raw)])
       (with-syntax ([(src ...) srcs]
                     [(snk ...) snks]
                     [(san ...) sans]
                     [fixes-expr fixes-code])
         #'(define pol-id
             (security-policy
               'pol-id
               '(src ...)
               '(snk ...)
               '(san ...)
               fixes-expr))))]))