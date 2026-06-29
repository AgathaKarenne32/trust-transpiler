#lang racket/base

;;; =============================================================================
;;; trust-transpiler/src/ai_security_linter.rkt
;;;
;;; Sprint 3 — "O Cérebro": Cliente de IA para sugestão contextual de sanitizadores.
;;;
;;; CONTRATO PÚBLICO
;;; ──────────────────
;;;   get-smart-sanitizer : Symbol Symbol → String
;;;
;;;   Recebe o sink (ex: 'log) e o nome da variável tainted (ex: 'raw_data),
;;;   e devolve uma STRING com o nome da função sanitizadora recomendada
;;;   (ex: "escape_shell"). Nunca falha: em caso de erro de rede, API key
;;;   ausente, ou resposta malformada, degrada para a heurística local.
;;;
;;; NOTA DE SEGURANÇA
;;; ──────────────────
;;;   A api-key é lida via (getenv "GEMINI_API_KEY") e nunca deve ser
;;;   hardcoded neste arquivo nem logada em mensagens de erro/debug.
;;; =============================================================================

(require net/url
         json
         racket/port
         racket/string
         racket/list)

(provide get-smart-sanitizer)

;; ─────────────────────────────────────────────────────────────────────────────
;; get-smart-sanitizer : Symbol Symbol → String
;;
;; Função principal que orquestra a chamada à IA.
;; sink-func e var-name são SÍMBOLOS (não strings) — consistente com o
;; resto da UIR (uir:call usa símbolos para func e args).
;; ─────────────────────────────────────────────────────────────────────────────
(define (get-smart-sanitizer sink-func var-name)
  (define api-key (getenv "GEMINI_API_KEY"))

  (if api-key
      ;; Se a chave existir, chama a API real
      (call-llm-api sink-func var-name api-key)
      ;; Se não existir (ex: no CI/CD), usa heurística local de fallback
      (fallback-sanitizer sink-func)))

;; ─────────────────────────────────────────────────────────────────────────────
;; fallback-sanitizer : Symbol → String
;;
;; O "Cérebro" de Fallback (usado quando não há internet ou API Key).
;; ─────────────────────────────────────────────────────────────────────────────
(define (fallback-sanitizer sink-func)
  (case sink-func
    [(query) "escape_sql"]
    [(log) "escape_shell"]
    [(display println write) "escape_html"]
    [else "sanitize_generic"]))

;; ─────────────────────────────────────────────────────────────────────────────
;; Integração HTTP com a API do Gemini
;; ─────────────────────────────────────────────────────────────────────────────
(define (call-llm-api sink-func var-name api-key)
  (define sink-str (symbol->string sink-func))
  (define var-str (symbol->string var-name))
  
  ;; Aponta para o seu Oráculo local
  (define endpoint (string->url "http://localhost:8008/api/v1/get-sanitizer"))

  ;; O Pydantic espera: {"sink": "...", "variable": "..."}
  (define payload
    (hasheq 'sink sink-str
            'variable var-str))

  (with-handlers
    ([exn:fail? (lambda (e) 
                  (displayln (format "Erro de conexão com Oráculo: ~a" (exn-message e)))
                  (fallback-sanitizer sink-func))])

    (define response-port
      (post-pure-port endpoint
                      (jsexpr->bytes payload)
                      (list "Content-Type: application/json")))
    
    (define response-json (bytes->jsexpr (port->bytes response-port)))
    (close-input-port response-port)

    ;; Extração conforme o schema SanitizerResponse
    (hash-ref response-json 'sanitizer (fallback-sanitizer sink-func))))

;; ─────────────────────────────────────────────────────────────────────────────
;; valid-sanitizer-name? : String → Boolean
;; ─────────────────────────────────────────────────────────────────────────────
(define (valid-sanitizer-name? s)
  (and (> (string-length s) 0)
       (regexp-match? #px"^[a-zA-Z_][a-zA-Z0-9_]*$" s)))