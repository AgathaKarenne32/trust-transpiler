#lang racket/base

(require racket/match
         racket/string
         racket/list
         "uir.rkt")

(provide parse-program
         parse-string)

(define *sink-functions*
  '(log query exec eval send write display println))

(define *source-expressions*
  '("source" "source()" "user-input()" "read-line" "getenv"))

;; -----------------------------------------------------------------------------
;; Tokenizer
;; -----------------------------------------------------------------------------
(define (tokenize content)
  (define lines (string-split content "\n" #:trim? #f))
  (apply append
         (for/list ([line-str lines] [l (in-naturals 1)])
           (let* ([normalized
                   (string-replace (string-replace line-str "(" " ( ")
                                   ")" " ) ")]
                  [normalized-final
                   (foldl (λ (ch str)
                            (string-replace str (string ch) (format " ~a " (string ch))))
                          normalized
                          '(#\; #\= #\{ #\}))]
                  [tokens (filter (λ (t) (not (string=? t ""))) (string-split normalized-final))])
             (map (λ (t) (cons t l)) tokens)))))

(struct parse-ctx (tokens file) #:mutable #:transparent)

(define (ctx-peek ctx)
  (if (null? (parse-ctx-tokens ctx)) #f (car (parse-ctx-tokens ctx))))

(define (ctx-consume! ctx)
  (let ([tok-pair (car (parse-ctx-tokens ctx))])
    (set-parse-ctx-tokens! ctx (cdr (parse-ctx-tokens ctx)))
    tok-pair))

(define (ctx-expect! ctx expected)
  (let ([tok-pair (ctx-consume! ctx)])
    (unless (equal? (car tok-pair) expected)
      (error 'parser "Esperado '~a', encontrado '~a' na linha ~a"
             expected (car tok-pair) (cdr tok-pair)))
    tok-pair))

(define (make-loc ctx)
  (let ([tok-pair (ctx-peek ctx)])
    (src-location (parse-ctx-file ctx) (if tok-pair (cdr tok-pair) 0) 0)))

;; -----------------------------------------------------------------------------
;; Parser
;; -----------------------------------------------------------------------------

(define (parse-program content filename)
  (let* ([tokens (tokenize content)]
         [ctx    (parse-ctx tokens filename)]
         [stmts  (parse-stmts ctx)])
    (uir:sequence stmts (src-location filename 0 0))))

(define (parse-string content) (parse-program content "<string>"))

(define (parse-stmts ctx)
  (let loop ([stmts '()])
    (if (not (ctx-peek ctx)) (reverse stmts)
        (let ([stmt (parse-stmt ctx)])
          (if stmt (loop (cons stmt stmts)) (reverse stmts))))))

(define (parse-stmt ctx)
  (let ([peek (ctx-peek ctx)])
    (match peek
      ;; 1. Parênteses de agrupamento
      [(cons "(" _)
       (ctx-consume! ctx)
       (let ([stmt (parse-stmt ctx)])
         (when (and (ctx-peek ctx) (equal? (car (ctx-peek ctx)) ")"))
           (ctx-consume! ctx))
         stmt)]

      ;; 2. Sanitização
      [(cons "sanitize" _)
       (ctx-consume! ctx)
       (ctx-expect! ctx "(")
       (let* ([arg (string->symbol (car (ctx-consume! ctx)))]
              [_   (ctx-expect! ctx ")")])
         (uir:call 'sanitize (list arg) #f (make-loc ctx)))]

      ;; 3. Let  ← displayln removido; variáveis corrigidas
      [(cons "let" _)
       (ctx-consume! ctx)
       (let* ([var   (string->symbol (car (ctx-consume! ctx)))]
              [_     (ctx-expect! ctx "=")]
              [expr  (car (ctx-consume! ctx))]
              [_     (when (and (ctx-peek ctx)
                                (equal? (car (ctx-peek ctx)) ";"))
                       (ctx-consume! ctx))]
              [loc   (make-loc ctx)]
              [taint (if (member expr *source-expressions*)
                         taint:tainted
                         taint:clean)])
         (uir:assign var expr taint loc))]

      ;; 4. Chamada de função (func(arg))
      [(cons func-name _)
       (ctx-consume! ctx)
       (if (and (ctx-peek ctx) (equal? (car (ctx-peek ctx)) "("))
           (begin
             (ctx-consume! ctx)
             (let* ([next (ctx-peek ctx)]
                    [arg  (if (and next (not (equal? (car next) ")")))
                              (string->symbol (car (ctx-consume! ctx)))
                              #f)]
                    [_    (ctx-expect! ctx ")")]
                    [_    (when (and (ctx-peek ctx)
                                     (equal? (car (ctx-peek ctx)) ";"))
                            (ctx-consume! ctx))])
               (uir:call (string->symbol func-name)
                         (if arg (list arg) '())
                         #t
                         (make-loc ctx))))
           #f)]

      ;; 5. Fallback
      [_ (ctx-consume! ctx) (parse-stmt ctx)])))