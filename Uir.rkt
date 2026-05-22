#lang racket/base

;;; =============================================================================
;;; trust-transpiler/src/uir.rkt
;;; Universal Intermediate Representation (UIR)
;;;
;;; A linguagem de origem (C, Python, JS...) é irrelevante após a fase de parse.
;;; O motor de análise opera exclusivamente sobre estas estruturas imutáveis.
;;; Todas as structs são definidas com #:transparent para facilitar debugging
;;; e com campos imutáveis (padrão em Racket) para garantir pureza funcional.
;;; =============================================================================

(provide
  ;; Tipos de Taint
  taint-label?
  taint:clean taint:tainted taint:sanitized
  taint-label->string

  ;; Nós da UIR
  uir-node?
  (struct-out uir:assign)
  (struct-out uir:call)
  (struct-out uir:branch)
  (struct-out uir:sequence)
  (struct-out uir:noop)

  ;; Metadados de localização (para relatórios)
  (struct-out src-location))

;; -----------------------------------------------------------------------------
;; Localização no código-fonte original (agnóstica de linguagem)
;; -----------------------------------------------------------------------------
(struct src-location
  (file    ; String — caminho do arquivo de origem
   line    ; Natural — linha no arquivo original
   col)    ; Natural — coluna no arquivo original
  #:transparent)

;; -----------------------------------------------------------------------------
;; Rótulos de Taint (Taint Labels)
;;
;; Representamos taint como um tipo algébrico simples usando símbolos Racket.
;; A função `taint-label?` é o predicado de tipo.
;;
;; Lattice de segurança (ordem parcial):
;;   clean  <  tainted
;;   tainted -> sanitized  (sanitização quebra a propagação)
;; -----------------------------------------------------------------------------
(define (taint-label? v)
  (member v '(clean tainted sanitized)))

;; Construtores simbólicos — usamos define em vez de enum para manter
;; a compatibilidade com pattern matching via `match`.
(define taint:clean      'clean)
(define taint:tainted    'tainted)
(define taint:sanitized  'sanitized)

(define (taint-label->string label)
  (case label
    [(clean)     "CLEAN"]
    [(tainted)   "TAINTED"]
    [(sanitized) "SANITIZED"]
    [else        "UNKNOWN"]))

;; -----------------------------------------------------------------------------
;; Nós da UIR — Cobertura mínima para programas imperativos
;; -----------------------------------------------------------------------------

;; Predicado genérico de nó UIR
(define (uir-node? v)
  (or (uir:assign? v)
      (uir:call? v)
      (uir:branch? v)
      (uir:sequence? v)
      (uir:noop? v)))

;; --- Atribuição ---------------------------------------------------------------
;; Representa:  var = expr
;; `source-taint` indica se esta atribuição é um SOURCE de dados externos
;; (ex: leitura de stdin, parâmetro HTTP, env var).
(struct uir:assign
  (var          ; Symbol  — nome da variável de destino
   expr         ; Any     — valor ou nome de variável de origem (simplificado)
   source-taint ; taint-label? — rótulo inicial injetado nesta atribuição
   location)    ; src-location? — onde ocorreu no código original
  #:transparent)

;; --- Chamada de Função --------------------------------------------------------
;; Representa:  func(arg1, arg2, ...)
;; `sink?` é #t quando esta chamada é um SINK sensível (log, query, exec, etc.)
(struct uir:call
  (func      ; Symbol       — nome da função chamada
   args       ; (Listof Any) — lista de argumentos (vars ou literais)
   sink?      ; Boolean      — marca este call como ponto de sink
   location)  ; src-location?
  #:transparent)

;; --- Salto Condicional --------------------------------------------------------
;; Representa:  if (cond) then-branch else-branch
(struct uir:branch
  (condition    ; Any       — variável ou expr de condição
   then-branch  ; uir-node? — nó executado se verdadeiro
   else-branch  ; uir-node? — nó executado se falso (pode ser uir:noop)
   location)    ; src-location?
  #:transparent)

;; --- Sequência ----------------------------------------------------------------
;; Lista ordenada de instruções — o bloco básico de qualquer programa.
(struct uir:sequence
  (stmts    ; (Listof uir-node?) — instruções em ordem
   location) ; src-location?
  #:transparent)

;; --- No-op --------------------------------------------------------------------
;; Instrução vazia; usada como else-branch padrão e para testes.
(struct uir:noop
  (location) ; src-location?
  #:transparent)