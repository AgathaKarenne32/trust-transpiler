#lang racket/base

(require racket/match
         racket/list
         racket/hash
         racket/string
         "types.rkt"
         "stub-registry.rkt"
         "uir.rkt"
         "fp_scorer.rkt"
         (prefix-in gate: "api_gatekeeper.rkt")) 
;;; =============================================================================
;;; trust-transpiler/src/taint_engine.rkt
;;; Motor de Taint Analysis — Puro e Agnóstico à Linguagem de Origem
;;;
;;; Arquitetura:
;;;   analyze-node : uir-node? TaintEnv → AnalysisResult
;;;
;;; TaintEnv é um hash imutável: Symbol → taint-label
;;; (variável → seu rótulo de taint atual)
;;;
;;; AnalysisResult agrega todas as violações encontradas durante o traversal.
;;;
;;; PUREZA: Nenhuma mutação de estado. Toda "atualização" de ambiente gera
;;; um novo hash (hash-set). Toda "acumulação" de violações usa recursão
;;; com acumulador explícito (padrão CPS-lite).
;;; =============================================================================

(provide
  make-taint-env
  env-set
  env-lookup
  (struct-out violation)
  (struct-out analysis-result)
  analyze-node
  analyze-program
  *sanitizer-functions*
  sanitizer? 
  register-sanitizer!)

;; -----------------------------------------------------------------------------
;; Ambiente de Taint (TaintEnv)
;; -----------------------------------------------------------------------------
(define (make-taint-env) (hash))
(define (env-set env var label) (hash-set env var label))
(define (env-lookup env var) (hash-ref env var taint:clean))

;; -----------------------------------------------------------------------------
;; Sanitizadores e Sinks
;; -----------------------------------------------------------------------------
(define *sanitizer-functions*
  (list 'sanitize 'escape 'encode 'validate 'strip-tags 'htmlspecialchars))

(define (sanitizer? func-sym) (member func-sym *sanitizer-functions*))

(define *sink-functions* '(query log))
(define (is-sink? func-sym module-name)
  (let ([stub-policy (stub-policy-for module-name)])
    (if stub-policy
        (let ([sinks-entry (assq 'sinks stub-policy)])
          (if sinks-entry (member func-sym (cdr sinks-entry)) #f))
        (member func-sym *sink-functions*))))

(define (register-sanitizer! func-sym)
  (set! *sanitizer-functions* (cons func-sym *sanitizer-functions*)))

;; -----------------------------------------------------------------------------
;; Estruturas de Resultado
;; -----------------------------------------------------------------------------
(struct analysis-result (violations final-env) #:transparent)

(define (empty-result env) (analysis-result '() env))
(define (result-add-violation result v)
  (analysis-result (cons v (analysis-result-violations result)) (analysis-result-final-env result)))
(define (result-merge r1 r2)
  (analysis-result (append (analysis-result-violations r1) (analysis-result-violations r2))
                   (analysis-result-final-env r2)))

;; -----------------------------------------------------------------------------
;; Motor de Análise
;; -----------------------------------------------------------------------------
(define (analyze-node node env [taint-path '()])
  (match node
    [(uir:assign var expr source-taint loc)
     (let* ([expr-sym (if (string? expr) (string->symbol expr) expr)]
            [expr-taint (if (symbol? expr-sym) (env-lookup env expr-sym) taint:clean)]
            [final-taint (taint-join source-taint expr-taint)]
            [new-env (env-set env var final-taint)])
       (analysis-result '() new-env))]

    [(uir:call func args sink? loc)
     (let* ([arg-taints (map (λ (a) (env-lookup env a)) args)]
            [any-tainted (ormap (λ (t) (eq? t taint:tainted)) arg-taints)]
            [is-sanitizer (sanitizer? func)]
            [module-name (extract-module-name func)]
            ;; FASE 4: Integração Gatekeeper
            [gate-result (gate:analyze-call-node func args (λ (v) (env-lookup env v)))]
            [is-unknown (eq? gate-result taint:unknown-api)])
       (cond
         [is-unknown
          (let ([v (violation 'unknown-api (if (null? args) 'unknown (car args)) func (list func) loc gate:UNKNOWN-API-SCORE)])
            (analysis-result (list v) env))]
         [(and (is-sink? func module-name) any-tainted)
          (let* ([v-base (violation 'unsanitized-sink (if (null? args) 'unknown (car args)) func (cons func taint-path) loc 0.0)]
                 [score (score-finding v-base)]
                 [v (struct-copy violation v-base [confidence score])])
            (analysis-result (list v) env))]
         [is-sanitizer
          (let* ([new-env (if (not (null? args)) (env-set env (car args) taint:sanitized) env)])
            (analysis-result '() new-env))]
         [else (analysis-result '() env)]))]

    [(uir:branch condition then-branch else-branch loc)
     (let* ([then-result (analyze-node then-branch env taint-path)]
            [else-result (analyze-node else-branch env taint-path)]
            [merged-env (env-join (analysis-result-final-env then-result) (analysis-result-final-env else-result))])
       (analysis-result (append (analysis-result-violations then-result) (analysis-result-violations else-result)) merged-env))]

    [(uir:sequence stmts loc)
     (foldl (λ (stmt acc-result)
              (result-merge acc-result (analyze-node stmt (analysis-result-final-env acc-result) taint-path)))
            (empty-result env) stmts)]
    [_ (empty-result env)]))

;; -----------------------------------------------------------------------------
;; Lattice e Helpers
;; -----------------------------------------------------------------------------
(define (taint-join a b)
  (cond
    [(or (eq? a taint:unknown-api) (eq? b taint:unknown-api)) taint:unknown-api]
    [(or (eq? a taint:tainted) (eq? b taint:tainted)) taint:tainted]
    [(or (eq? a taint:sanitized) (eq? b taint:sanitized)) taint:sanitized]
    [else taint:clean]))

(define (env-join env1 env2) (hash-union env1 env2 #:combine taint-join))

(define (extract-module-name func-sym)
  (let ([str (symbol->string func-sym)])
      (if (string-contains? str ".") (string->symbol (car (string-split str "."))) 'global)))

(define (analyze-program root [initial-env #f])
  (analyze-node root (or initial-env (make-taint-env)) '()))