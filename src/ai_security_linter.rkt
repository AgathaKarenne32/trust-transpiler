#lang racket/base

;;; =============================================================================
;;; trust-transpiler/src/ai_security_linter.rkt
;;;
;;; Fase 4 — Pilar 3: AI Security Linter
;;;
;;; POSICIONAMENTO NO PIPELINE
;;; ──────────────────────────
;;; O linter opera APÓS a taint analysis, sobre a UIR já anotada.
;;; Não substitui o motor de taint — complementa com heurísticas
;;; de padrão que o taint sozinho não captura.
;;;
;;;   parse → [taint engine] → [AI LINTER] → reporter + autofix
;;;
;;; POR QUE UM LINTER SEPARADO?
;;; ────────────────────────────
;;; O motor de taint rastreia FLUXO DE DADOS. O linter rastreia
;;; ESTRUTURA DE CÓDIGO — padrões sintáticos/semânticos que são
;;; inseguros independentemente do fluxo de taint. Por exemplo:
;;;
;;;   (string-append "SELECT * FROM " x)
;;;
;;; O taint detecta se `x` é tainted. O linter detecta que usar
;;; string-append com um prefixo SQL É um anti-padrão, mesmo que
;;; `x` seja marcado como clean (potencial falso negativo do taint).
;;;
;;; EXTENSIBILIDADE
;;; ────────────────
;;; Novos padrões = adicionar uma função à lista `*lint-rules*`.
;;; Cada regra é uma função: uir-node → (Listof lint-finding) | '()
;;; A lista é percorrida para cada nó da UIR (visitor pattern funcional).
;;;
;;; ASSINATURAS IMPLEMENTADAS (3 obrigatórias + 1 bônus)
;;; ──────────────────────────────────────────────────────
;;;   1. SQL String Injection — string-append/format com prefixo SQL
;;;   2. Weak Crypto — funções criptográficas obsoletas/inseguras
;;;   3. Privileged Escalation — exec/eval em qualquer contexto
;;;   4. Path Traversal (bônus) — concatenação de caminhos com input
;;; =============================================================================

(require racket/match
         racket/list
         racket/string
         "uir.rkt"
         "types.rkt")

(provide
  ;; Estrutura de resultado do linter
  (struct-out lint-finding)

  ;; Funções principais
  run-linter
  lint-node
  lint-sequence

  ;; Registro de regras
  register-lint-rule!
  *lint-rules*

  ;; Conversão para violation (integração com reporter/autofix)
  lint-finding->violation)

;; ─────────────────────────────────────────────────────────────────────────────
;; Estrutura lint-finding
;;
;; Separada de `violation` por três razões:
;;   1. lint-findings são gerados por PADRÃO ESTRUTURAL, não por fluxo de taint
;;   2. Têm um campo `category` que os identifica como 'ai-antipattern
;;   3. Podem ser convertidos para violation via lint-finding->violation
;;      quando precisam entrar no pipeline de autofix
;; ─────────────────────────────────────────────────────────────────────────────

(struct lint-finding
  (rule-id     ; Symbol  — identificador da regra que disparou
   category    ; Symbol  — sempre 'ai-antipattern neste módulo
   severity    ; Symbol  — 'high | 'medium | 'low
   message     ; String  — descrição legível da vulnerabilidade
   cwe         ; String  — CWE de referência (ex: "CWE-89")
   node        ; uir-node? — nó UIR que disparou a regra
   location    ; src-location? — localização no código original
   suggestion) ; String  — sugestão de correção em linguagem natural
  #:transparent)

;; ─────────────────────────────────────────────────────────────────────────────
;; Registro de Regras
;;
;; *lint-rules* é uma lista de funções: uir-node → (Listof lint-finding)
;; Cada função retorna '() quando o padrão NÃO bate.
;; ─────────────────────────────────────────────────────────────────────────────

(define *lint-rules* '())

;; register-lint-rule! : (uir-node → (Listof lint-finding)) → Void
;; Adiciona uma nova regra ao início da lista (LIFO — últimas regras, primeiras verificadas)
(define (register-lint-rule! rule-fn)
  (set! *lint-rules* (cons rule-fn *lint-rules*)))

;; ─────────────────────────────────────────────────────────────────────────────
;; VISITOR: lint-node e lint-sequence
;; ─────────────────────────────────────────────────────────────────────────────

;; lint-node : uir-node → (Listof lint-finding)
;; Aplica todas as regras a um nó e desce recursivamente na árvore UIR.
(define (lint-node node)
  (let ([local-findings  (apply-all-rules node)]
        [child-findings  (lint-children node)])
    (append local-findings child-findings)))

;; lint-children : uir-node → (Listof lint-finding)
;; Desce nos filhos do nó sem reaplicar regras ao nó pai.
(define (lint-children node)
  (match node
    [(uir:sequence stmts _)
     (append-map lint-node stmts)]
    [(uir:branch _ then-b else-b _)
     (append (lint-node then-b) (lint-node else-b))]
    ;; Folhas: nenhum filho
    [_ '()]))

;; lint-sequence : (Listof uir-node) → (Listof lint-finding)
;; Ponto de entrada para linting de um programa inteiro (lista de statements).
(define (lint-sequence stmts)
  (append-map lint-node stmts))

;; run-linter : uir-node → (Listof lint-finding)
;; Ponto de entrada principal. Aceita qualquer nó UIR (tipicamente uir:sequence raiz).
(define (run-linter root)
  (lint-node root))

;; apply-all-rules : uir-node → (Listof lint-finding)
;; Aplica cada regra registrada ao nó e concatena os resultados.
(define (apply-all-rules node)
  (append-map (λ (rule) (rule node)) *lint-rules*))

;; ─────────────────────────────────────────────────────────────────────────────
;; CONVERSÃO: lint-finding → violation
;;
;; Permite que findings do linter entrem no pipeline de autofix
;; sem modificar o autofix engine.
;; ─────────────────────────────────────────────────────────────────────────────

(define (lint-finding->violation lf)
  ;; Extrai source-var e sink-func do nó UIR se possível
  (match (lint-finding-node lf)
    [(uir:call func args _ loc)
     (violation
       (lint-finding-rule-id lf)
       (if (null? args) 'unknown (car args))
       func
       (list func)   ; path mínimo: só o sink
       (lint-finding-location lf)
       ;; Severity → confidence
       (case (lint-finding-severity lf)
         [(high)   0.90]
         [(medium) 0.65]
         [else     0.40]))]
    ;; Para nós não-call, cria uma violation genérica
    [_
     (violation
       (lint-finding-rule-id lf)
       'unknown
       (lint-finding-rule-id lf)
       '()
       (lint-finding-location lf)
       0.70)]))

;; ─────────────────────────────────────────────────────────────────────────────
;; REGRA 1: SQL String Injection
;;
;; Assinatura: string-append, format, string-join usado com argumento
;;             que contém um prefixo reconhecível como SQL.
;;
;; Detecta padrões como:
;;   (string-append "SELECT * FROM users WHERE id = " user_input)
;;   (format "INSERT INTO ~a VALUES (~a)" table value)
;;
;; CWE-89: Improper Neutralization of Special Elements in SQL Command
;; ─────────────────────────────────────────────────────────────────────────────

;; Prefixos SQL que indicam construção dinâmica de query
(define *sql-prefixes*
  '("SELECT" "INSERT" "UPDATE" "DELETE" "DROP" "CREATE"
    "ALTER" "TRUNCATE" "EXEC" "EXECUTE"
    "select" "insert" "update" "delete" "drop" "create"))

(define (sql-prefix? str)
  (for/or ([prefix *sql-prefixes*])
    (string-prefix? (string-upcase str) (string-upcase prefix))))

;; Funções de concatenação de string que podem construir SQL inseguro
(define *string-concat-fns* '(string-append format string-join +))

(define (rule:sql-string-injection node)
  (match node
    ;; Padrão: (string-append "SELECT ..." var) ou similar
    [(uir:call func args _ loc)
     #:when (memq func *string-concat-fns*)
     ;; Verifica se algum argumento é um literal com prefixo SQL
     (let ([sql-args (filter (λ (a)
                               (match a
                                 [(uir:assign _ expr _ _)
                                  (and (string? expr) (sql-prefix? expr))]
                                 [_ #f]))
                             args)])
       (if (not (null? sql-args))
           (list (lint-finding
                   'sql-string-injection
                   'ai-antipattern
                   'high
                   (format "Possível SQL Injection: ~a usado para construir query SQL dinamicamente. LLMs frequentemente geram este padrão inseguro."
                           func)
                   "CWE-89"
                   node
                   loc
                   "Use parameterize-query ou prepared statements ao invés de concatenação de strings."))
           '()))]
    [_ '()]))

;; Registra a regra
(register-lint-rule! rule:sql-string-injection)

;; ─────────────────────────────────────────────────────────────────────────────
;; REGRA 2: Weak Crypto
;;
;; Assinatura: uso de funções criptográficas obsoletas ou inseguras.
;; LLMs tendem a sugerir MD5/SHA1 por serem mais comuns no corpus de treino.
;;
;; CWE-327: Use of a Broken or Risky Cryptographic Algorithm
;; CWE-328: Use of Weak Hash
;; ─────────────────────────────────────────────────────────────────────────────

;; Mapeamento: função insegura → (cwe, mensagem, alternativa)
(define *weak-crypto-map*
  (hash
    'md5         '("CWE-328" "MD5 é criptograficamente quebrado" "use sha256 ou bcrypt")
    'sha1        '("CWE-328" "SHA1 é vulnerável a colisões" "use sha256 ou sha3")
    'md5-hash    '("CWE-328" "MD5 é criptograficamente quebrado" "use sha256 ou bcrypt")
    'sha1-hash   '("CWE-328" "SHA1 é vulnerável a colisões" "use sha256 ou sha3")
    'des-encrypt '("CWE-327" "DES tem chave de 56 bits — inadequado" "use AES-256")
    'rc4-encrypt '("CWE-327" "RC4 tem vulnerabilidades conhecidas" "use AES-GCM")
    'crypt       '("CWE-327" "crypt() com DES é inseguro" "use bcrypt ou argon2")
    'make-md5-input-port '("CWE-328" "MD5 é criptograficamente quebrado" "use sha256")))

(define (rule:weak-crypto node)
  (match node
    [(uir:call func _ _ loc)
     #:when (hash-has-key? *weak-crypto-map* func)
     (let* ([info  (hash-ref *weak-crypto-map* func)]
            [cwe   (car info)]
            [msg   (cadr info)]
            [fix   (caddr info)])
       (list (lint-finding
               'weak-crypto
               'ai-antipattern
               'high
               (format "Criptografia fraca: ~a — ~a. LLMs frequentemente sugerem algoritmos obsoletos do corpus de treino."
                       func msg)
               cwe
               node
               loc
               (format "Substitua ~a por ~a." func fix))))]
    [_ '()]))

(register-lint-rule! rule:weak-crypto)

;; ─────────────────────────────────────────────────────────────────────────────
;; REGRA 3: Privileged Escalation
;;
;; Assinatura: chamadas a exec, eval, system, shell em qualquer contexto.
;; LLMs frequentemente geram código que usa eval/exec para "flexibilidade",
;; sem considerar que isso cria superfície de ataque de execução de código.
;;
;; CWE-78:  OS Command Injection
;; CWE-95:  Improper Neutralization of Directives in Eval
;; CWE-250: Execution with Unnecessary Privileges
;; ─────────────────────────────────────────────────────────────────────────────

(define *privileged-fns*
  (hash
    'eval         '("CWE-95"  "high"   "eval executa código arbitrário"         "Refatore para evitar avaliação dinâmica de código")
    'exec         '("CWE-78"  "high"   "exec executa comandos do sistema"       "Use uma API de mais alto nível com sanitização de argumentos")
    'system       '("CWE-78"  "high"   "system() executa comandos do shell"     "Use process/spawn com lista de argumentos (sem shell interpolation)")
    'shell        '("CWE-78"  "high"   "shell executa via interpretador"        "Evite invocação de shell — use APIs específicas")
    'subprocess   '("CWE-78"  "medium" "subprocess com shell=True é perigoso"  "Use subprocess com lista de argumentos, nunca string")
    'dynamic-require '("CWE-95" "medium" "dynamic-require carrega código externo" "Valide o caminho antes de carregar módulos dinâmicos")))

(define (rule:privileged-escalation node)
  (match node
    [(uir:call func _ _ loc)
     #:when (hash-has-key? *privileged-fns* func)
     (let* ([info (hash-ref *privileged-fns* func)]
            [cwe  (car info)]
            [sev  (string->symbol (cadr info))]
            [msg  (caddr info)]
            [fix  (cadddr info)])
       (list (lint-finding
               'privileged-escalation
               'ai-antipattern
               sev
               (format "Escalada de privilégio: ~a — ~a. LLMs geram este padrão por conveniência sem considerar o risco."
                       func msg)
               cwe
               node
               loc
               fix)))]
    [_ '()]))

(register-lint-rule! rule:privileged-escalation)

;; ─────────────────────────────────────────────────────────────────────────────
;; REGRA 4 (Bônus): Path Traversal
;;
;; Assinatura: string-append/format com argumento que parece um caminho
;;             de arquivo + variável externa.
;;
;; LLMs frequentemente geram código como:
;;   (string-append "/var/www/uploads/" filename)
;;
;; CWE-22: Improper Limitation of a Pathname to a Restricted Directory
;; ─────────────────────────────────────────────────────────────────────────────

(define *path-prefixes*
  '("/" "./" "../" "C:\\" "/var/" "/etc/" "/home/" "/tmp/"
    "/usr/" "/opt/" "~/" "./uploads/" "./files/"))

(define (path-prefix? str)
  (for/or ([prefix *path-prefixes*])
    (string-prefix? str prefix)))

(define (rule:path-traversal node)
  (match node
    [(uir:call func args _ loc)
     #:when (memq func '(string-append format open-input-file
                         open-output-file call-with-input-file
                         call-with-output-file file->string))
     (let ([path-args (filter (λ (a)
                                (match a
                                  [(uir:assign _ expr _ _)
                                   (and (string? expr) (path-prefix? expr))]
                                  [_ #f]))
                              args)])
       (if (not (null? path-args))
           (list (lint-finding
                   'path-traversal
                   'ai-antipattern
                   'high
                   (format "Path Traversal: ~a constrói caminho de arquivo com concatenação. LLMs geram este padrão sem validação de diretório."
                           func)
                   "CWE-22"
                   node
                   loc
                   "Use path-normalize e valide que o caminho final está dentro do diretório permitido antes de abrir o arquivo."))
           '()))]
    [_ '()]))

(register-lint-rule! rule:path-traversal)