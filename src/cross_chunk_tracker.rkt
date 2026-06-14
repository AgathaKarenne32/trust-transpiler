#lang racket/base

;;; =============================================================================
;;; trust-transpiler/src/cross_chunk_tracker.rkt
;;;
;;; Fase 4 — Pilar 1: Cross-Chunk Taint Tracker
;;;
;;; PROBLEMA QUE RESOLVE
;;; ─────────────────────
;;; LLMs geram código em "chunks" — arquivos separados em janelas de contexto
;;; distintas. Um dado marcado como `tainted` no arquivo A pode chegar como
;;; parâmetro ao arquivo B sem nenhuma marcação. O motor atual analisa cada
;;; arquivo isoladamente, perdendo esse fluxo: "amnésia de contexto".
;;;
;;; SOLUÇÃO
;;; ────────
;;; Serializar o TaintEnv ao final de cada scan e restaurá-lo antes do próximo.
;;; O arquivo de cache `.trust-transpiler/cache/<modulo>.taint-cache` contém
;;; um snapshot do ambiente de taint "exportado" pelo módulo — as variáveis
;;; e funções que ele expõe para o mundo externo.
;;;
;;; FORMATO DO ARQUIVO .taint-cache
;;; ────────────────────────────────
;;; S-expressão Racket nativa (não JSON) — leitura via `read`, sem dependências.
;;;
;;;   (taint-snapshot
;;;     (version 1)
;;;     (source-file "src/handler.rkt")
;;;     (timestamp 1718000000)
;;;     (bindings
;;;       (user_input  . tainted)
;;;       (safe_val    . sanitized)
;;;       (counter     . clean)))
;;;
;;; Escolhemos S-expressões por três razões:
;;;   1. `read`/`write` são nativos — zero dependências externas.
;;;   2. O formato é legível por humanos e versionável em git.
;;;   3. Racket garante leitura segura com `read` (sem eval).
;;;
;;; INTEGRAÇÃO COM O MOTOR
;;; ──────────────────────
;;; taint_engine.rkt chama:
;;;   • import-taint-snapshot antes de analyze-program → semeia o TaintEnv
;;;   • export-taint-snapshot após analyze-program → persiste o resultado
;;;
;;; O TaintEnv importado é passado como argumento inicial para analyze-node,
;;; substituindo o (hash) vazio padrão. Isso implementa análise interprocedural
;;; entre arquivos sem modificar a lógica do motor.
;;; =============================================================================

(require racket/match
         racket/list
         racket/string
         racket/path  
         racket/file
         racket/hash)

(provide
  ;; Estrutura de dados
  (struct-out taint-snapshot)

  ;; I/O do snapshot
  export-taint-snapshot
  import-taint-snapshot

  ;; Integração com TaintEnv
  snapshot->taint-env
  taint-env->snapshot

  ;; Utilitários
  cache-path-for
  snapshot-valid?
  snapshot-merge)

;; ─────────────────────────────────────────────────────────────────────────────
;; Constantes
;; ─────────────────────────────────────────────────────────────────────────────

(define *cache-version* 1)
(define *cache-dir*     ".trust-transpiler/cache")
(define *cache-ext*     ".taint-cache")

;; Mapeamento de símbolo de taint para rank numérico (para merge conservador)
;; Espelha a lattice definida em uir.rkt sem criar dependência circular.
(define *taint-rank*
  (hash 'clean     0
        'sanitized 1
        'tainted   2
        'unknown-api 3))   ; novo nível da Fase 4

(define (taint-rank t)
  (hash-ref *taint-rank* t 0))

;; ─────────────────────────────────────────────────────────────────────────────
;; Estrutura TaintSnapshot
;; ─────────────────────────────────────────────────────────────────────────────

(struct taint-snapshot
  (version      ; Natural — versão do formato de cache
   source-file  ; String  — caminho do arquivo que gerou este snapshot
   timestamp    ; Natural — unix timestamp da geração
   bindings)    ; (Listof (Cons Symbol Symbol)) — lista de (var . taint-label)
  #:transparent)

;; ─────────────────────────────────────────────────────────────────────────────
;; CONVERSÕES: TaintEnv ↔ TaintSnapshot
;;
;; TaintEnv é o hash imutável usado pelo motor: Symbol → Symbol (taint-label)
;; TaintSnapshot é a forma serializada/desserializada
;; ─────────────────────────────────────────────────────────────────────────────

;; taint-env->snapshot : TaintEnv String → taint-snapshot
(define (taint-env->snapshot env source-file)
  (taint-snapshot
    *cache-version*
    source-file
    (current-seconds)
    ;; Converte o hash para lista de pares — formato serializável
    (hash->list env)))

;; snapshot->taint-env : taint-snapshot → TaintEnv
(define (snapshot->taint-env snap)
  ;; Reconstrói o hash imutável a partir dos pares do snapshot
  (for/hash ([pair (taint-snapshot-bindings snap)])
    (values (car pair) (cdr pair))))

;; ─────────────────────────────────────────────────────────────────────────────
;; CAMINHOS DE CACHE
;; ─────────────────────────────────────────────────────────────────────────────

;; cache-path-for : String → String
;; Deriva o caminho do arquivo de cache a partir do caminho do módulo.
;; Substitui separadores de diretório por "__" para achatar a hierarquia.
;;
;; Exemplo:
;;   "src/handlers/user.rkt" → ".trust-transpiler/cache/src__handlers__user.taint-cache"
(define (cache-path-for source-file)
  (let* ([flat (string-replace source-file "/" "__")]
         [flat (string-replace flat  "\\" "__")]
         ;; Remove extensão original se presente
         [base (if (string-suffix? flat ".rkt")
                   (substring flat 0 (- (string-length flat) 4))
                   flat)])
    (string-append *cache-dir* "/" base *cache-ext*)))

;; ─────────────────────────────────────────────────────────────────────────────
;; SERIALIZAÇÃO: export-taint-snapshot
;;
;; export-taint-snapshot : TaintEnv String → Void
;;
;; Serializa o TaintEnv para disco no formato S-expressão.
;; Cria o diretório de cache se não existir.
;; ─────────────────────────────────────────────────────────────────────────────

(define (export-taint-snapshot env source-file)
  (let* ([snap      (taint-env->snapshot env source-file)]
         [filepath  (cache-path-for source-file)]
         ;; Garante que o diretório de cache existe
         [cache-dir (path-only (string->path filepath))])

    ;; Cria diretório recursivamente se não existir
    (when cache-dir
      (make-directory* cache-dir))

    ;; Serializa como S-expressão legível
    (call-with-output-file filepath
      #:exists 'replace
      (λ (port)
        (write
          `(taint-snapshot
             (version   ,(taint-snapshot-version    snap))
             (source-file ,(taint-snapshot-source-file snap))
             (timestamp ,(taint-snapshot-timestamp  snap))
             (bindings  ,(taint-snapshot-bindings   snap)))
          port)
        ;; Newline final para legibilidade no git diff
        (newline port)))))

;; ─────────────────────────────────────────────────────────────────────────────
;; DESSERIALIZAÇÃO: import-taint-snapshot
;;
;; import-taint-snapshot : String → taint-snapshot | #f
;;
;; Lê e valida o arquivo de cache para um módulo.
;; Retorna #f em qualquer condição de erro (arquivo ausente, corrompido,
;; versão incompatível) — o motor trata #f como "começar do zero".
;;
;; SEGURANÇA: usa `read` puro (não `eval`) — não executa código arbitrário.
;; ─────────────────────────────────────────────────────────────────────────────

(define (import-taint-snapshot source-file)
  (let ([filepath (cache-path-for source-file)])
    (with-handlers
      ;; Qualquer falha de leitura/parse → retorna #f silenciosamente
      ([exn:fail?
        (λ (e)
          ;; Log de debug para facilitar troubleshooting
          (eprintf "[cross-chunk-tracker] aviso: cache indisponível para ~a: ~a\n"
                   source-file (exn-message e))
          #f)])
      (if (file-exists? filepath)
          (call-with-input-file filepath
            (λ (port)
              (let ([datum (read port)])
                (parse-snapshot-datum datum source-file))))
          #f))))

;; parse-snapshot-datum : Any String → taint-snapshot | #f (raises on corrupt)
;; Valida a estrutura do datum lido do arquivo de cache.
(define (parse-snapshot-datum datum source-file)
  (match datum
    ;; Formato esperado: (taint-snapshot (version N) (source-file S) ...)
    [(list 'taint-snapshot
           (list 'version     (? exact-nonnegative-integer? ver))
           (list 'source-file (? string? sf))
           (list 'timestamp   (? exact-nonnegative-integer? ts))
           (list 'bindings    bindings))
     ;; Verifica compatibilidade de versão
     (if (= ver *cache-version*)
         (taint-snapshot ver sf ts (validate-bindings bindings))
         (begin
           (eprintf "[cross-chunk-tracker] cache incompatível (v~a) para ~a — ignorando\n"
                    ver source-file)
           #f))]
    ;; Formato não reconhecido: cache corrompido
    [_
     (eprintf "[cross-chunk-tracker] cache corrompido para ~a — ignorando\n" source-file)
     #f]))

;; validate-bindings : Any → (Listof (Cons Symbol Symbol))
;; Filtra apenas pares válidos (symbol . taint-label) da lista de bindings.
;; Descarta silenciosamente entradas malformadas — tolerância a corrupção parcial.
(define (validate-bindings raw)
  (if (list? raw)
      (filter (λ (pair)
                (and (pair? pair)
                     (symbol? (car pair))
                     (symbol? (cdr pair))
                     ;; Aceita taint-labels conhecidos + unknown-api (Fase 4)
                     (memq (cdr pair) '(clean tainted sanitized unknown-api))))
              raw)
      '()))

;; ─────────────────────────────────────────────────────────────────────────────
;; snapshot-valid? : taint-snapshot Natural → Boolean
;;
;; Verifica se um snapshot ainda é "fresco" dado um TTL em segundos.
;; Útil para descartar caches gerados em execuções muito antigas.
;;
;; TTL padrão: 86400s = 24 horas
;; ─────────────────────────────────────────────────────────────────────────────

(define (snapshot-valid? snap [ttl-seconds 86400])
  (let ([age (- (current-seconds) (taint-snapshot-timestamp snap))])
    (<= age ttl-seconds)))

;; ─────────────────────────────────────────────────────────────────────────────
;; snapshot-merge : taint-snapshot taint-snapshot → taint-snapshot
;;
;; Mescla dois snapshots com política CONSERVADORA (join da lattice):
;; para cada variável, usa o taint-label de maior rank.
;;
;; Usado quando um mesmo módulo é importado por múltiplos arquivos que
;; geraram snapshots diferentes — tomamos o pior caso.
;; ─────────────────────────────────────────────────────────────────────────────

(define (snapshot-merge s1 s2)
  (let* ([env1     (snapshot->taint-env s1)]
         [env2     (snapshot->taint-env s2)]
         ;; Para cada variável, join conservador
         [merged   (hash-union env1 env2
                               #:combine (λ (a b)
                                            (if (>= (taint-rank a) (taint-rank b))
                                                a b)))])
    (taint-snapshot
      *cache-version*
      (taint-snapshot-source-file s1)  ; mantém o arquivo original
      (current-seconds)
      (hash->list merged))))