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

  ;; Usando o modelo mais atualizado (IA)
  (define endpoint
    (string->url
     (format "https://generativelanguage.googleapis.com/v1beta/models/gemini-pro:generateContent?key=~a"
             api-key)))

  ;; Prompt de Engenharia de Segurança
  (define prompt
    (format (string-append
             "Atue como um especialista em AppSec. Uma variável chamada '~a' "
             "está a fluir sem validação para a função sensível '~a'. "
             "Responda APENAS com o nome da função de sanitização ideal para "
             "este caso (ex: escape_sql, escape_html). Não escreva mais nada, "
             "apenas o nome da função.")
            var-str sink-str))

  ;; Corpo da requisição em JSON
  (define payload
    (hasheq 'contents (list (hasheq 'parts (list (hasheq 'text prompt))))))

  (with-handlers
    ([exn:fail?
      (lambda (e)
        (displayln (format "Aviso: Erro interno no Racket. A usar fallback. Detalhe: ~a" (exn-message e)))
        (fallback-sanitizer sink-func))])

    ;; Prepara e envia o POST request
    (define response-port
      (post-pure-port endpoint
                       (jsexpr->bytes payload)
                       (list "Content-Type: application/json")))

    ;; Lê a resposta JSON
    (define response-json (bytes->jsexpr (port->bytes response-port)))
    (close-input-port response-port)

    ;; ── TRATAMENTO DE ERROS DO GOOGLE E EXTRAÇÃO SEGURA ──────────
    (if (hash-has-key? response-json 'error)
        (let* ([err-obj (hash-ref response-json 'error)]
               [err-msg (hash-ref err-obj 'message "Erro desconhecido da Google")])
          (displayln (format "Aviso: A Google rejeitou a requisição. Erro: ~a" err-msg))
          (fallback-sanitizer sink-func))
        
        ;; AQUI ESTÁ A CORREÇÃO: Usando let* para definir as variáveis locais
        (let* ([candidates (hash-ref response-json 'candidates)]
               [candidate-0 (first candidates)]
               [content (hash-ref candidate-0 'content)]
               [parts (hash-ref content 'parts)]
               [part-0 (first parts)]
               [ai-suggestion (hash-ref part-0 'text)]
               [cleaned (string-trim ai-suggestion)])

          ;; Guard Anti-Alucinação
          (if (valid-sanitizer-name? cleaned)
              cleaned
              (begin
                (displayln (format "Aviso: Sugestão da IA malformada ('~a'). A usar fallback." cleaned))
                (fallback-sanitizer sink-func)))))))

;; ─────────────────────────────────────────────────────────────────────────────
;; valid-sanitizer-name? : String → Boolean
;; ─────────────────────────────────────────────────────────────────────────────
(define (valid-sanitizer-name? s)
  (and (> (string-length s) 0)
       (regexp-match? #px"^[a-zA-Z_][a-zA-Z0-9_]*$" s)))