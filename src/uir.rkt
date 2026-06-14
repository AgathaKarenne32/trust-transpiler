#lang racket/base

;;; =============================================================================
;;; trust-transpiler/src/uir.rkt
;;; Universal Intermediate Representation (UIR)
;;;
;;; MUDANÇA FASE 4
;;; ─────────────
;;; Adicionado `taint:unknown-api` à lattice.
;;; Lattice completa: clean(0) < sanitized(1) < tainted(2) < unknown-api(3)
;;; =============================================================================

(provide
  ;; Tipos de Taint
  taint-label?
  taint:clean taint:tainted taint:sanitized taint:unknown-api
  taint-label->string
  taint-rank
  
  ;; Nós da UIR
  uir-node?
  (struct-out uir:assign)
  (struct-out uir:call)
  (struct-out uir:branch)
  (struct-out uir:sequence)
  (struct-out uir:noop)

  ;; Metadados de localização
  (struct-out src-location))

;; -----------------------------------------------------------------------------
;; Localização no código-fonte original
;; -----------------------------------------------------------------------------
(struct src-location
  (file line col)
  #:transparent)

;; -----------------------------------------------------------------------------
;; Rótulos de Taint (Taint Labels)
;; -----------------------------------------------------------------------------

;; FASE 4: Adicionado 'unknown-api' ao predicado
(define (taint-label? v)
  (member v '(clean tainted sanitized unknown-api)))

(define taint:clean       'clean)
(define taint:tainted     'tainted)
(define taint:sanitized   'sanitized)
(define taint:unknown-api 'unknown-api) ;; FASE 4: APIs não registradas

;; FASE 4: Rank atualizado (3 é o mais perigoso/restritivo)
(define (taint-rank label)
  (case label
    [(clean)       0]
    [(sanitized)   1]
    [(tainted)     2]
    [(unknown-api) 3]
    [else          0]))

(define (taint-label->string label)
  (case label
    [(clean)       "CLEAN"]
    [(tainted)     "TAINTED"]
    [(sanitized)   "SANITIZED"]
    [(unknown-api) "UNKNOWN-API"]
    [else          "UNKNOWN"]))

;; -----------------------------------------------------------------------------
;; Nós da UIR
;; -----------------------------------------------------------------------------

(define (uir-node? v)
  (or (uir:assign? v)
      (uir:call? v)
      (uir:branch? v)
      (uir:sequence? v)
      (uir:noop? v)))

(struct uir:assign
  (var expr source-taint location)
  #:transparent)

(struct uir:call
  (func args sink? location)
  #:transparent)

(struct uir:branch
  (condition then-branch else-branch location)
  #:transparent)

(struct uir:sequence
  (stmts location)
  #:transparent)

(struct uir:noop
  (location)
  #:transparent)