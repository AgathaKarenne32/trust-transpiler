#lang racket/base

;;; =============================================================================
;;; trust-transpiler/src/autofix.rkt
;;;
;;; Motor de Geração de Patches — Fase 3 do Trust-Transpiler
;;;
;;; RESPONSABILIDADE ÚNICA
;;; ──────────────────────
;;; Este módulo recebe violações (puras, sem I/O) e devolve patch-suggestions
;;; (puras, sem I/O). A aplicação ao disco é responsabilidade de main.rkt.
;;; O motor de taint NUNCA importa este módulo — dependência unidirecional.
;;;
;;; FLUXO DE DADOS
;;; ──────────────
;;;
;;;   violation + security-policy
;;;        │
;;;        ▼
;;;   generate-patch          → patch-suggestion | #f
;;;        │
;;;        ▼
;;;   patch-suggestion
;;;     ├── uir-diff          → lista de patch-op (modificações na UIR)
;;;     └── code-suggestion   → string de código pronto para o humano
;;;
;;; PUREZA FUNCIONAL
;;; ─────────────────
;;; Todas as funções são puras. `apply-patches!` é a única com efeito
;;; colateral (escrita em disco) e está claramente marcada com `!`.
;;;
;;; ESTRUTURA DE patch-op
;;; ──────────────────────
;;; Representa uma inserção de nó sanitizador ANTES de um nó sink na UIR.
;;; A operação não modifica o sink — apenas injeta um predecessor na sequência.
;;;
;;;   (patch-op 'insert-before target-loc new-node)
;;;
;;; Semântica: "em qualquer uir:sequence que contenha um nó em target-loc,
;;; insira new-node imediatamente antes desse nó".
;;;
;;; Por que insert-before e não replace?
;;;   A correção canônica de taint é SANITIZAR o dado, não remover o sink.
;;;   O sink continua existindo — o dado que chega a ele é que deve ser limpo.
;;; =============================================================================

(require racket/match
         racket/string
         racket/list
         racket/port
         racket/system
         racket/file
         "uir.rkt"
         "types.rkt"
         "policy.rkt"
         "reporter.rkt")

(provide
  ;; Structs exportados
  (struct-out patch-suggestion)
  (struct-out patch-op)

  ;; Funções principais
  generate-patch
  generate-patches-for-all
  apply-patch-to-sequence
  apply-patches-to-uir
  process-violations-interactively

  ;; Utilitários
  render-code-suggestion
  patch-op-describe)

;; ─────────────────────────────────────────────────────────────────────────────
;; Estruturas de Dados
;; ─────────────────────────────────────────────────────────────────────────────

;; patch-op: uma operação atômica de modificação na UIR
;;
;; `type` é sempre 'insert-before nesta versão.
;; Suporte futuro: 'replace, 'delete, 'wrap.
;;
;; `target-loc`: src-location do nó ANTES do qual inserir.
;; O motor de inserção usa `src-location-line` como chave de busca
;; na sequência de statements (posição aproximada, suficiente para MVP).
;;
;; `new-node`: o nó UIR a inserir — neste caso sempre um uir:call
;; representando a chamada ao sanitizador.
(struct patch-op
  (type        ; Symbol — 'insert-before | 'replace | 'delete
   target-loc  ; src-location? — localização do nó alvo
   new-node)   ; uir-node? — nó a inserir/substituir
  #:transparent)

;; patch-suggestion: resultado de generate-patch
;;
;; `confidence` é herdado da violation base — não recalculado.
;; `kind` sinaliza o que o analista deve fazer com esta sugestão:
;;   'auto-safe   → pode ser aplicado automaticamente (confidence >= 0.80)
;;   'suggest     → mostrar ao analista mas não aplicar sem confirmação
;;   'manual-only → a correção requer refatoração humana
(struct patch-suggestion
  (violation        ; violation? — a violação que originou este patch
   kind             ; Symbol — 'auto-safe | 'suggest | 'manual-only
   sanitizer-fn     ; Symbol — função sanitizadora recomendada
   uir-diff         ; (Listof patch-op) — operações sobre a UIR
   code-suggestion  ; String — código corrigido para exibir ao analista
   confidence)      ; Float — herdado da violation
  #:transparent)

;; ─────────────────────────────────────────────────────────────────────────────
;; FUNÇÃO PRINCIPAL: generate-patch
;;
;; generate-patch : violation security-policy → patch-suggestion | #f
;;
;; Lógica:
;;   1. Consulta policy-fix-for para encontrar o fix associado ao sink.
;;   2. Se não há fix → retorna #f (sem patch automático disponível).
;;   3. Constrói o nó UIR do sanitizador (uir:call-stmt para o sanitizador).
;;   4. Cria um patch-op 'insert-before apontando para o loc do sink.
;;   5. Formata o code-suggestion interpolando source-var no template.
;;   6. Determina `kind` pelo campo confidence da violation.
;; ─────────────────────────────────────────────────────────────────────────────

(define (generate-patch v policy)
  (match v
    [(violation kind source-var sink-func taint-path loc confidence severity)
     (let ([fix (policy-fix-for policy sink-func)])
       (if (not fix)
           ;; Sem mapeamento na política → sem patch automático
           #f
           (let* ([san-fn    (fix-entry-sanitizer fix)]
                  [template  (fix-entry-template  fix)]

                  ;; Nó UIR do sanitizador a inserir:
                  ;; (san-fn source-var) — chamada sem marcação de sink
                  [san-node  (uir:call
                               san-fn
                               (list source-var)
                               #f          ; sanitizador NÃO é sink
                               loc)]       ; mesma localização do sink (aproximação)

                  ;; Operação: inserir o sanitizador ANTES do nó do sink
                  [op        (patch-op 'insert-before loc san-node)]

                  ;; Código sugerido: substitui ~a pelo source-var
                  [code-str  (render-code-suggestion template source-var sink-func)]

                  ;; Nível de automação baseado na confiança
                  [patch-kind (cond
                                [(>= confidence 0.80) 'auto-safe]
                                [(>= confidence 0.50) 'suggest]
                                [else                 'manual-only])])

             (patch-suggestion v patch-kind san-fn
                               (list op) code-str confidence))))]

    ;; Guard: recebemos algo que não é uma violation
    [other
     (error 'generate-patch
            "esperado violation?, recebido: ~a" other)]))

;; ─────────────────────────────────────────────────────────────────────────────
;; generate-patches-for-all : (Listof violation) security-policy
;;                            → (Listof patch-suggestion)
;;
;; Aplica generate-patch a todas as violações, filtrando as que retornam #f.
;; ─────────────────────────────────────────────────────────────────────────────

(define (generate-patches-for-all violations policy)
  (filter-map (λ (v) (generate-patch v policy)) violations))

;; ─────────────────────────────────────────────────────────────────────────────
;; APLICAÇÃO DE PATCHES NA UIR
;;
;; Estas funções modificam a UIR para inserir os nós sanitizadores.
;; São PURAS — retornam uma nova UIR sem modificar a original.
;;
;; ESTRATÉGIA DE INSERÇÃO
;; ──────────────────────
;; A UIR é uma árvore. O caso relevante é uir:sequence (lista de stmts).
;; Para inserir um nó ANTES de outro, buscamos na sequência o nó cujo
;; `location` coincide com o `target-loc` do patch-op, então reconstruímos
;; a lista intercalando o novo nó.
;;
;; Comparação de localização: usamos (src-location-line) como chave.
;; Em caso de colisão de linha (múltiplos nós na mesma linha), inserimos
;; antes da PRIMEIRA ocorrência — comportamento conservador.
;; ─────────────────────────────────────────────────────────────────────────────

;; loc-matches? : src-location src-location → Boolean
;; Dois locais "batem" se arquivo e linha são iguais.
(define (loc-matches? loc1 loc2)
  (and loc1 loc2
       (equal? (src-location-file loc1) (src-location-file loc2))
       (= (src-location-line loc1) (src-location-line loc2))))

;; node-location : uir-node → src-location | #f
;; Extrai o campo `location` de qualquer nó UIR via pattern matching.
(define (node-location node)
  (match node
    [(uir:assign _ _ _ loc)    loc]
    [(uir:call   _ _ _ loc)    loc]
    [(uir:branch _ _ _ loc)    loc]
    [(uir:sequence _ loc)      loc]
    [(uir:noop loc)            loc]
    [_                         #f]))

;; apply-patch-to-sequence : (Listof uir-node) patch-op → (Listof uir-node)
;;
;; Recebe a lista FLAT de statements de um uir:sequence e um único patch-op.
;; Retorna uma nova lista com o nó novo inserido antes do nó alvo.
;;
;; Se o nó alvo não for encontrado (localização não bate), retorna a lista
;; original inalterada — comportamento seguro (não corrompe a UIR).
(define (apply-patch-to-sequence stmts op)
  (match op
    [(patch-op 'insert-before target-loc new-node)
     (let loop ([remaining stmts]
                [done      '()])
       (cond
         ;; Lista esgotada sem encontrar o alvo: retorna original
         [(null? remaining)
          stmts]
         ;; Encontrou o nó alvo: insere o novo nó antes dele
         [(loc-matches? (node-location (car remaining)) target-loc)
          (append (reverse done)
                  (list new-node)      ; ← sanitizador inserido aqui
                  remaining)]          ; ← sink e o resto continuam
         ;; Ainda buscando: avança
         [else
          (loop (cdr remaining)
                (cons (car remaining) done))]))]

    ;; Tipo de operação não suportado nesta versão
    [(patch-op unsupported _ _)
     (error 'apply-patch-to-sequence
            "tipo de patch-op não suportado: ~a" unsupported)]))

;; apply-patches-to-uir : uir-node (Listof patch-op) → uir-node
;;
;; Traversal recursivo da UIR aplicando TODOS os patch-ops.
;; Retorna uma nova UIR com todos os patches aplicados.
;;
;; A recursão desce em uir:sequence (onde ocorre a inserção) e em
;; uir:branch (para garantir que patches em branches também são aplicados).
(define (apply-patches-to-uir root ops)
  (if (null? ops)
      root   ; Nenhum patch: retorna a UIR original sem copiar
      (match root

        ;; ── Sequência: aplica todos os patches na lista de stmts ────────────
        ;; Depois desce recursivamente em cada statement.
        [(uir:sequence stmts loc)
         (let* ([patched-stmts
                 ;; Para cada op, aplica na sequência atual (fold sequencial)
                 (foldl (λ (op acc-stmts)
                          (apply-patch-to-sequence acc-stmts op))
                        stmts
                        ops)]
                ;; Desce recursivamente em cada statement da sequência
                [recursed-stmts
                 (map (λ (s) (apply-patches-to-uir s ops)) patched-stmts)])
           (uir:sequence recursed-stmts loc))]

        ;; ── Branch: aplica em ambos os ramos ────────────────────────────────
        [(uir:branch cond then-b else-b loc)
         (uir:branch cond
                     (apply-patches-to-uir then-b ops)
                     (apply-patches-to-uir else-b ops)
                     loc)]

        ;; ── Folhas (assign, call, noop): retorna sem modificação ────────────
        ;; Patches são inseridos EM TORNO de nós, não dentro deles.
        [leaf leaf])))

;; ─────────────────────────────────────────────────────────────────────────────
;; Utilitários de Formatação
;; ─────────────────────────────────────────────────────────────────────────────

;; render-code-suggestion : String Symbol Symbol → String
;;
;; Interpola source-var e sink-func no template da política.
;; O template usa ~a como placeholder posicional (compatível com `format`).
;;
;; Exemplos:
;;   template = "(parameterize-query conn ~a)"
;;   source-var = 'user_id
;;   → "(parameterize-query conn user_id)"
;;
;;   template = "(html-escape ~a)"
;;   source-var = 'raw_input
;;   → "(html-escape raw_input)"
(define (render-code-suggestion template source-var sink-func)
  (let ([var-str (symbol->string source-var)]
        [sink-str (symbol->string sink-func)])
    (with-handlers
      ;; Caso o template tenha número errado de ~a: mensagem clara
      ([exn:fail?
        (λ (_)
          (format "; ERRO: template inválido '~a' para sink '~a'" template sink-str))])
      ;; Tenta interpolar apenas source-var primeiro; se falhar, tenta com os dois
      (with-handlers
        ([exn:fail? (λ (_) (format template var-str sink-str))])
        (format template var-str)))))

;; patch-op-describe : patch-op → String
;; Representação textual de um patch-op para logs e relatórios.
(define (patch-op-describe op)
  (match op
    [(patch-op 'insert-before loc new-node)
     (let ([line (if loc (src-location-line loc) "?")])
       (format "INSERT ~a BEFORE line ~a"
               (match new-node
                 [(uir:call f args _ _)
                  (format "(~a ~a)" f (string-join (map symbol->string args) " "))]
                 [_ "<node>"])
               line))]
    [(patch-op type _ _)
     (format "~a <op>" type)]))

(define (process-violations-interactively file-path content violations)
  (unless (file-exists? (string-append file-path ".bak"))
    (copy-file file-path (string-append file-path ".bak")))
  
  (define stats (make-hash '([applied . 0] [skipped . 0] [ignored . 0])))
  
  ;; 2. Loop de interação
  (for ([v violations] [idx (in-naturals 1)])
    (display-violation-menu v idx)
    (let loop ()
      (display "> ")
      (flush-output)
      (match (string-downcase (read-line))
        ["s" (begin 
               (apply-patch-to-file! file-path v)
               (hash-update! stats 'applied add1))]
        ["n" (hash-update! stats 'skipped add1)]
        ["d" (show-diff file-path) (loop)]
        ["p" (begin (displayln "Política: (query -> sanitize)") (loop))]
        ["i" (begin (displayln "Regra ignorada.") (hash-update! stats 'ignored add1))]
        [else (displayln "Opção inválida.") (loop)])))
  
  (displayln "\n══════════════════════════════════════════")
  (displayln (format "Autofix concluído: ~a aplicados, ~a pulados, ~a ignorados." 
                     (hash-ref stats 'applied) 
                     (hash-ref stats 'skipped) 
                     (hash-ref stats 'ignored)))) 

(define (display-violation-menu v idx)
  (displayln (format "\n[~a] VULNERABILIDADE: ~a" idx (violation-kind v)))
  (displayln (format "Localização: linha ~a" (src-location-line (violation-location v))))
  (displayln "[s] Aplicar [n] Pular [d] Diff [p] Política [i] Ignorar"))

(define (apply-patch-to-file! path v)
  ;; 1. Cria backup de segurança
  (unless (file-exists? (string-append path ".bak"))
    (copy-file path (string-append path ".bak")))
  
  ;; 2. Extrai a variável E a função sink do objeto violation
  (match v
    [(violation _ source-var sink-func _ loc _ _)
     
     (let* ([lines (file->lines path)]
            [var-name (symbol->string source-var)]
            [sink-name (symbol->string sink-func)])
       
       ;; 3. SMART ANCHOR: Busca a linha exata que contém a função E a variável
       ;; Em vez de confiar cegamente no loc, achamos a linha verdadeira.
       (define target-idx
         (for/first ([i (in-range (length lines))]
                     #:when (and (string-contains? (list-ref lines i) var-name)
                                 (string-contains? (list-ref lines i) sink-name)))
           i))
       
       (if target-idx
           (let* ([target-line (list-ref lines target-idx)]
                  [indent (car (regexp-match #px"^\\s*" target-line))]
                  
                  ;; 4. Cria a instrução correta na sintaxe da linguagem .tt
                  [sanitized-line (format "~asanitize(~a);" indent var-name)]
                  
                  ;; 5. Insere a nova linha ANTES do target-idx exato
                  [new-lines (append (take lines target-idx)
                                     (list sanitized-line)
                                     (drop lines target-idx))])
             
             ;; 6. Salva no disco
             (with-output-to-file path #:exists 'replace
               (λ () (for-each displayln new-lines)))
             (displayln (format "Sucesso: 'sanitize(~a);' inserido antes da linha ~a (ancoragem inteligente)." var-name (+ target-idx 1))))
           
           (displayln "Erro de Patch: Não foi possível localizar a linha exata com o sink no arquivo.")))]
    
    [_ (displayln "Erro: O objeto passado não é uma violação válida.")]))

(define (show-diff path)
  (if (file-exists? (string-append path ".bak"))
      (system (format "diff -u ~a.bak ~a" path path))
      (displayln "Backup não encontrado.")))