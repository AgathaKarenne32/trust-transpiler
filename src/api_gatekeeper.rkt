#lang racket/base

;;; =============================================================================
;;; trust-transpiler/src/api_gatekeeper.rkt
;;;
;;; Fase 4 — Pilar 2: API Gatekeeper (Alucinações de LLM)
;;;
;;; PROBLEMA QUE RESOLVE
;;; ─────────────────────
;;; LLMs "alucinam" nomes de funções plausíveis que não existem, ou usam
;;; APIs reais de forma semânticamente errada. O motor atual não distingue
;;; uma chamada a `sanitize(x)` de uma chamada a `sanitize_totally_safe(x)`
;;; — ambas passam pelo mesmo caminho de análise.
;;;
;;; SOLUÇÃO: MODO ESTRITO
;;; ──────────────────────
;;; Qualquer função chamada que NÃO esteja registrada no stub-registry é
;;; tratada como `taint:unknown-api` — o nível mais alto da lattice antes
;;; de ⊤. Isso implementa o princípio "deny by default" para APIs.
;;;
;;; LATTICE ESTENDIDA (Fase 4)
;;; ──────────────────────────
;;;   ⊥ < clean < sanitized < tainted < unknown-api
;;;
;;; `unknown-api` propaga como `tainted` mas com score fixo de 0.95 no
;;; fp_scorer, sinalizando ao analista que o risco é estrutural (API
;;; desconhecida), não apenas de fluxo de dados.
;;;
;;; LOOKUP O(1)
;;; ────────────
;;; O registro de funções conhecidas é compilado em um `hash` Racket.
;;; hash-ref é O(1) amortizado — sem iteração sobre listas.
;;;
;;; INTEGRAÇÃO COM O MOTOR
;;; ──────────────────────
;;; taint_engine.rkt chama analyze-call-node ANTES de avaliar o taint
;;; padrão de um uir:call. Se analyze-call-node retorna 'unknown-api,
;;; o motor usa esse label e eleva o score da violação para 0.95.
;;; =============================================================================


(require racket/match
         racket/list
         "types.rkt"
         "stub-registry.rkt"
         "uir.rkt") ;; Importamos uir.rkt para usar taint:unknown-api

(provide
  analyze-call-node
  call-node-risk
  *strict-mode*
  enable-strict-mode!
  disable-strict-mode!
  UNKNOWN-API-SCORE
  evaluate-violations)

;; ─────────────────────────────────────────────────────────────────────────────
;; Constantes e Configuração
;; ─────────────────────────────────────────────────────────────────────────────

(define UNKNOWN-API-SCORE 0.95)
(define *strict-mode* (make-parameter #f))

(define (enable-strict-mode!)  (*strict-mode* #t))
(define (disable-strict-mode!) (*strict-mode* #f))

;; ─────────────────────────────────────────────────────────────────────────────
;; Registro de APIs
;; ─────────────────────────────────────────────────────────────────────────────

(define *known-api-registry* (make-hash))

(struct api-entry (name safe? category) #:transparent)

(define (build-known-api-set functions category [safe? #t])
  (for ([fn functions])
    (hash-set! *known-api-registry* fn (api-entry fn safe? category))))

(define (known-api? func-sym)
  (hash-has-key? *known-api-registry* func-sym))

;; Racket stdlib e Sanitizadores
(build-known-api-set
  '(display displayln write writeln read read-line
    string-append string-length string-split string-join
    number->string string->number symbol->string string->symbol
    format printf fprintf car cdr cons list map filter foldl foldr
    hash hash-ref hash-set hash-has-key? hash->list
    apply append length reverse open-input-file open-output-file
    with-handlers error raise)
  'stdlib)

(build-known-api-set
  '(sanitize escape encode validate html-escape url-encode strip-tags
    sql-escape parameterize-query shell-escape validate-url
    htmlspecialchars strip-html)
  'sanitizer)

;; ─────────────────────────────────────────────────────────────────────────────
;; Lógica Principal
;; ─────────────────────────────────────────────────────────────────────────────

(define (analyze-call-node func-sym args env-lookup-fn)
  (cond
    ;; Se strict-mode está ativo e a API é desconhecida, marca como unknown-api
    [(and (*strict-mode*)
          (not (known-api? func-sym))
          (not (stub-known? func-sym)))
     'taint:unknown-api]
    ;; Se não estamos em strict-mode, o comportamento padrão é ser defensivo
    [(and (not (*strict-mode*))
          (not (known-api? func-sym))
          (not (stub-known? func-sym)))
     'tainted]
    [else #f]))

(define (stub-known? func-sym)
  (for/or ([lib-name (in-list (get-registered-libs))])
    (let ([policy (stub-policy-for lib-name)])
      (and policy
           (or (let ([sinks (assq 'sinks policy)]) (and sinks (memq func-sym (cdr sinks))))
               (let ([sans (assq 'sanitizers policy)]) (and sans (memq func-sym (cdr sans))))
               (let ([srcs (assq 'sources policy)]) (and srcs (memq func-sym (cdr srcs)))))))))

(define (get-registered-libs)
  (with-handlers ([exn:fail? (λ (_) '())])
    (dynamic-require "stub-registry.rkt" 'registered-stub-libs)))

(define (call-node-risk func-sym has-tainted-args?)
  (cond
    [(and (*strict-mode*) (not (known-api? func-sym))) UNKNOWN-API-SCORE]
    [(and has-tainted-args? (known-api? func-sym)) 0.70]
    [else 0.10]))

(define (evaluate-violations violations)
  (let ([severities (map violation-severity violations)])
    (cond
      [(member 'CRITICAL severities) 'BLOCK]
      [(member 'HIGH severities)     'BLOCK]
      [else                          'PASS])))