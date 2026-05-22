#lang racket/base

(require racket/match) ; 

;;; =============================================================================
;;; trust-transpiler/src/parser.rkt
;;; Parser Minimalista — Texto → UIR
;;;
;;; Gramática suportada:
;;;   programa   ::= instrução* EOF
;;;   instrução  ::= atribuição | chamada | condicional
;;;   atribuição ::= "let" ID "=" (NUMBER | STRING | "source()") ";"
;;;   chamada    ::= ID "(" ID? ")" ";"
;;;   condicional::= "if" "(" ID ")" instrução
;;;
;;; O parser é intencionalmente simples: seu papel é apenas demonstrar a
;;; fronteira entre código-fonte e UIR. Em produção, seria substituído
;;; por um front-end específico por linguagem (tree-sitter, LLVM IR, etc.)
;;; =============================================================================

(require racket/string
         racket/list
         "uir.rkt")

(provide parse-program
         parse-string)

;; Conjunto de funções consideradas SINKS (configurável por política)
(define *sink-functions*
  '(log query exec eval send write display println))

;; Conjunto de funções/expressões consideradas SOURCES de taint
(define *source-expressions*
  '("source()" "user-input()" "read-line" "getenv"))

;; -----------------------------------------------------------------------------
;; Tokenizer
;; Converte uma string em tokens — cada token é uma string limpa.
;; -----------------------------------------------------------------------------

;; Normaliza pontuação inserindo espaços ao redor de símbolos especiais,
;; depois divide por whitespace. Simples mas funcional para o MVP.
(define (tokenize input)
  (define normalized
    (foldl (λ (ch str)
              (string-replace str (string ch) (format " ~a " (string ch))))
           input
           '(#\( #\) #\; #\= #\{#\})))
  (filter (λ (t) (not (string=? t "")))
          (string-split normalized)))

;; -----------------------------------------------------------------------------
;; Contexto de Parse
;; Usamos uma estrutura mutável mínima apenas no parser (camada impura isolada).
;; O resultado (UIR) é completamente imutável.
;; -----------------------------------------------------------------------------
(struct parse-ctx
  (tokens  ; Listof String — tokens restantes
   pos     ; Natural       — posição atual (para mensagens de erro)
   file)   ; String        — nome do arquivo (para src-location)
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
;; Funções de Parse (descendente recursivo)
;; -----------------------------------------------------------------------------

;; parse-program : String String → uir:sequence
;; Ponto de entrada principal. Recebe o conteúdo do arquivo e o nome do arquivo.
(define (parse-program content filename)
  (let* ([tokens (tokenize content)]
         [ctx    (parse-ctx tokens 0 filename)]
         [stmts  (parse-stmts ctx)])
    (uir:sequence stmts (src-location filename 0 0))))

;; parse-string : String → uir:sequence
;; Versão conveniente para testes: usa "<string>" como nome de arquivo.
(define (parse-string content)
  (parse-program content "<string>"))

;; parse-stmts : parse-ctx → (Listof uir-node?)
(define (parse-stmts ctx)
  (let loop ([stmts '()])
    (if (not (ctx-peek ctx))
        (reverse stmts)
        (let ([stmt (parse-stmt ctx)])
          (if stmt
              (loop (cons stmt stmts))
              (reverse stmts))))))

;; parse-stmt : parse-ctx → uir-node? | #f
;;
;; Despacha para o parser correto via pattern matching no token lookahead.
;; Esta é a função central de pattern matching do parser.
(define (parse-stmt ctx)
  (match (ctx-peek ctx)
    ;; Atribuição: let x = <expr>;
    ["let"
     (ctx-consume! ctx)  ; consome "let"
     (let* ([var  (string->symbol (ctx-consume! ctx))]
            [_    (ctx-expect! ctx "=")]
            [expr (ctx-consume! ctx)]  ; valor bruto
            [_    (ctx-expect! ctx ";")]
            [loc  (make-loc ctx)]
            ;; Detecta se a expressão é uma fonte de taint (SOURCE)
            [initial-taint
             (if (member expr *source-expressions*)
                 taint:tainted
                 taint:clean)])
       (uir:assign var expr initial-taint loc))]

    ;; Condicional: if (cond) <stmt>
    ["if"
     (ctx-consume! ctx)  ; consome "if"
     (ctx-expect! ctx "(")
     (let* ([cond-var (string->symbol (ctx-consume! ctx))]
            [_        (ctx-expect! ctx ")")]
            [loc      (make-loc ctx)]
            [then-b   (parse-stmt ctx)]
            ;; else-branch opcional: consome "else" se presente
            [else-b   (if (equal? (ctx-peek ctx) "else")
                          (begin (ctx-consume! ctx) (parse-stmt ctx))
                          (uir:noop loc))])
       (uir:branch cond-var then-b else-b loc))]

    ;; Chamada de função: funcname(arg?);
    ;; Detecta se a função é um SINK pela lista *sink-functions*
    [(? string? tok)
     #:when (and (ctx-peek ctx) (not (member tok '("}" "else"))))
     (ctx-consume! ctx)  ; consome nome da função
     (let ([func-sym (string->symbol tok)])
       (if (equal? (ctx-peek ctx) "(")
           (begin
             (ctx-expect! ctx "(")
             (let* ([arg  (if (equal? (ctx-peek ctx) ")")
                              #f
                              (string->symbol (ctx-consume! ctx)))]
                    [_    (ctx-expect! ctx ")")]
                    [_    (when (equal? (ctx-peek ctx) ";") (ctx-consume! ctx))]
                    [loc  (make-loc ctx)]
                    [args (if arg (list arg) '())]
                    [is-sink (if (member func-sym *sink-functions*) #t #f)])
               (uir:call func-sym args is-sink loc)))
           ;; Token não reconhecido como instrução — ignora e avança
           (begin (void) #f)))]

    [_ #f]))