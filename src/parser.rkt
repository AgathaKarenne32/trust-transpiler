#lang racket/base

(require racket/match
         racket/string
         racket/list
         "uir.rkt")

;;; =============================================================================
;;; trust-transpiler/src/parser.rkt
;;; =============================================================================

(provide parse-program
         parse-string)

;; Conjunto de funções consideradas SINKS
(define *sink-functions*
  '(log query exec eval send write display println))

;; Conjunto de funções/expressões consideradas SOURCES de taint
(define *source-expressions*
  '("source" "source()" "user-input()" "read-line" "getenv"))

;; -----------------------------------------------------------------------------
;; Tokenizer
;; -----------------------------------------------------------------------------
(define (tokenize input)
  (define normalized
    (foldl (λ (ch str)
             (string-replace str (string ch) (format " ~a " (string ch))))
           input
           '(#\( #\) #\; #\= #\{ #\})))
  (filter (λ (t) (not (string=? t "")))
          (string-split normalized)))

;; -----------------------------------------------------------------------------
;; Contexto de Parse
;; -----------------------------------------------------------------------------
(struct parse-ctx
  (tokens pos file)
  #:mutable #:transparent)

(define (ctx-peek ctx)
  (if (null? (parse-ctx-tokens ctx))
      #f
      (car (parse-ctx-tokens ctx))))

(define (ctx-consume! ctx)
  (let ([tok (ctx-peek ctx)])
    (set-parse-ctx-tokens! ctx (if (null? (parse-ctx-tokens ctx))
                                   '()
                                   (cdr (parse-ctx-tokens ctx))))
    (set-parse-ctx-pos! ctx (+ (parse-ctx-pos ctx) 1))
    tok))

(define (ctx-expect! ctx expected)
  (let ([tok (ctx-consume! ctx)])
    (unless (equal? tok expected)
      (error 'parser "Esperado '~a', encontrado '~a' na posição ~a"
             expected tok (parse-ctx-pos ctx)))
    tok))

(define (make-loc ctx)
  (src-location (parse-ctx-file ctx) (parse-ctx-pos ctx) 0))

;; -----------------------------------------------------------------------------
;; Funções de Parse
;; -----------------------------------------------------------------------------

(define (parse-program content filename)
  (let* ([tokens (tokenize content)]
         [ctx    (parse-ctx tokens 0 filename)]
         [stmts  (parse-stmts ctx)])
    (uir:sequence stmts (src-location filename 0 0))))

(define (parse-string content)
  (parse-program content "<string>"))

;; Função única de parse-stmts com o Debug incluído
(define (parse-stmts ctx)
  (let loop ([stmts '()])
    (let ([tok (ctx-peek ctx)])
      ;; Debug para ver o que o parser está lendo
      (displayln (format "DEBUG: Token atual = ~a" tok))
      (if (not tok)
          (reverse stmts)
          (let ([stmt (parse-stmt ctx)])
            (if stmt
                (loop (cons stmt stmts))
                (reverse stmts)))))))

(define (parse-stmt ctx)
  (match (ctx-peek ctx)
    ;; Atribuição: let x = <expr>;
    ["let"
     (ctx-consume! ctx)
     (let* ([var   (string->symbol (ctx-consume! ctx))]
            [_     (ctx-expect! ctx "=")]
            [expr  (ctx-consume! ctx)]
            [_     (ctx-expect! ctx ";")]
            [loc   (make-loc ctx)]
            [initial-taint (if (member expr *source-expressions*)
                               taint:tainted
                               taint:clean)])
       (uir:assign var expr initial-taint loc))]

    ;; Condicional: if (cond) <stmt>
    ["if"
     (ctx-consume! ctx)
     (ctx-expect! ctx "(")
     (let* ([cond-var (string->symbol (ctx-consume! ctx))]
            [_         (ctx-expect! ctx ")")]
            [loc       (make-loc ctx)]
            [then-b    (parse-stmt ctx)]
            [else-b    (if (equal? (ctx-peek ctx) "else")
                           (begin (ctx-consume! ctx) (parse-stmt ctx))
                           (uir:noop loc))])
       (uir:branch cond-var then-b else-b loc))]

    ;; Chamada de função: funcname(arg?);
    [(? string? tok)
     #:when (and (ctx-peek ctx) (not (member tok '("}" "else"))))
     (ctx-consume! ctx)
     (let ([func-sym (string->symbol tok)])
       (ctx-expect! ctx "(")
       (let* ([arg (if (equal? (ctx-peek ctx) ")")
                       #f
                       (string->symbol (ctx-consume! ctx)))]
              [_ (ctx-expect! ctx ")")]
              [_ (when (equal? (ctx-peek ctx) ";") (ctx-consume! ctx))]
              [loc (make-loc ctx)]
              [args (if arg (list arg) '())]
              [is-sink (if (member func-sym *sink-functions*) #t #f)])
         (uir:call func-sym args is-sink loc)))]

    [_ #f]))