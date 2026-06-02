#lang racket/base

(require racket/match) ;
(require net/url) ; 
(require racket/hash) ;
(require racket/string) ;
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

(require racket/list
        "stub-registry.rkt"
         "uir.rkt")

(provide
  make-taint-env
  env-set
  env-lookup
  (struct-out violation)
  (struct-out analysis-result)
  analyze-node
  analyze-program
  ;; Sanitizadores configuráveis
  *sanitizer-functions*
  sanitizer? register-sanitizer!)

;; -----------------------------------------------------------------------------
;; Ambiente de Taint (TaintEnv)
;;
;; Implementado como hash imutável para garantir pureza funcional.
;; A cada "escopo" de branch, passamos cópias independentes do ambiente.
;; -----------------------------------------------------------------------------

(define (make-taint-env) (hash))

(define (env-set env var label)
  ;; Retorna um NOVO hash com a variável atualizada — sem mutação
  (hash-set env var label))

(define (env-lookup env var)
  ;; Retorna o rótulo da variável ou 'clean' (princípio de menor privilégio)
  (hash-ref env var taint:clean))

;; -----------------------------------------------------------------------------
;; Sanitizadores
;;
;; Funções que, ao receberem um argumento tainted, retornam um valor sanitized.
;; Configurável via registro dinâmico (permite extensão sem modificar o core).
;; -----------------------------------------------------------------------------
(define *sanitizer-functions*
  ;; Conjunto inicial de sanitizadores comuns
  (list 'sanitize 'escape 'encode 'validate 'strip-tags 'htmlspecialchars))

(define (sanitizer? func-sym)
  (member func-sym *sanitizer-functions*))

(define *sink-functions* '(query log)) ;;
;; Exemplo de lógica de verificação de Sink
(define (is-sink? func-sym module-name)
  (let ([stub-policy (stub-policy-for module-name)])
    (if stub-policy
        ;; Busca a lista de sinks na lista de associação
        (let ([sinks-entry (assq 'sinks stub-policy)])
          (if sinks-entry
              (member func-sym (cdr sinks-entry)) ; Verifica se func-sym está na lista
              #f))
        ;; Fallback para a lista global hardcoded
        (member func-sym *sink-functions*))))
(define (register-sanitizer! func-sym)
  (set! *sanitizer-functions* (cons func-sym *sanitizer-functions*)))

;; -----------------------------------------------------------------------------
;; Estruturas de Resultado
;; -----------------------------------------------------------------------------

;; Uma violação de segurança detectada
(struct violation
  (kind       ; Symbol  — tipo: 'taint-flow | 'unsanitized-sink
   source-var ; Symbol  — variável/expr de origem do taint
   sink-func  ; Symbol  — função sink que recebeu o valor tainted
   taint-path ; (Listof Symbol) — caminho de propagação do taint
   location)  ; src-location? — onde a violação ocorreu
  #:transparent)

;; Resultado agregado de uma análise
(struct analysis-result
  (violations ; (Listof violation?) — todas as violações encontradas
   final-env)  ; TaintEnv           — estado final do ambiente após análise
  #:transparent)

(define (empty-result env)
  (analysis-result '() env))

(define (result-add-violation result v)
  (analysis-result
    (cons v (analysis-result-violations result))
    (analysis-result-final-env result)))

(define (result-merge r1 r2)
  ;; Mescla dois resultados: une violações e usa env do r2 (sequencial)
  (analysis-result
    (append (analysis-result-violations r1)
            (analysis-result-violations r2))
    (analysis-result-final-env r2)))

;; -----------------------------------------------------------------------------
;; Motor de Análise — Traversal Recursivo
;;
;; Pattern matching central: cada tipo de nó UIR tem sua semântica de taint.
;; -----------------------------------------------------------------------------

;; analyze-node : uir-node? TaintEnv (Listof Symbol) → analysis-result
;;
;; `taint-path` rastreia o caminho de propagação para o relatório final.
(define (analyze-node node env [taint-path '()])
  (match node

    ;; -----------------------------------------------------------------
    ;; Atribuição: var = expr
    ;; Propagação de taint:
    ;;   1. Se `source-taint` é 'tainted → var fica tainted (é um SOURCE)
    ;;   2. Se `expr` é uma variável tainted → var herda o taint
    ;;   3. Se `expr` é literal ou variável clean → var fica clean
    ;; -----------------------------------------------------------------
    [(uir:assign var expr source-taint loc)
     (let* ([expr-sym   (if (string? expr) (string->symbol expr) expr)]
            [expr-taint (if (symbol? expr-sym)
                            (env-lookup env expr-sym)
                            taint:clean)]
            ;; Taint final: o mais "alto" na lattice de segurança
            [final-taint (taint-join source-taint expr-taint)]
            ;; Novo ambiente com a variável atualizada
            [new-env    (env-set env var final-taint)]
            [new-path   (if (eq? final-taint taint:tainted)
                            (cons var taint-path)
                            taint-path)])
       (analysis-result '() new-env))]

    ;; -----------------------------------------------------------------
    ;; Chamada de Função: func(arg1, arg2, ...)
    ;; Se é um SINK:
    ;;   - Verifica se algum argumento está tainted
    ;;   - Se sim e não há sanitização → VIOLAÇÃO
    ;; Se é um SANITIZADOR:
    ;;   - O "retorno" implícito limpa o taint do primeiro argumento
    ;; -----------------------------------------------------------------
    [(uir:call func args sink? loc)
     (let* ([arg-taints (map (λ (a) (env-lookup env a)) args)]
            [any-tainted (ormap (λ (t) (eq? t taint:tainted)) arg-taints)]
            [is-sanitizer (sanitizer? func)]
            ;; PASSAGEM DO MÓDULO: Aqui assumimos que func pode vir como 'modulo.funcao'
            ;; ou simplesmente passamos 'global para buscar no padrão
            [module-name (extract-module-name func)])
          (displayln (format "DEBUG: func=~a, mod=~a" func module-name))

       (cond
         ;; Caso 1: Verifica usando a nova is-sink? que consulta o stub
         [(and (is-sink? func module-name) any-tainted) 
          (let ([v (violation 'unsanitized-sink (if (null? args) 'unknown (car args)) func (cons func taint-path) loc)])
            (analysis-result (list v) env))]

         ;; Caso 2: É um sanitizador → marca primeiro arg como sanitized
         [is-sanitizer 
          (let* ([new-env (if (not (null? args))
                              (env-set env (car args) taint:sanitized)
                              env)])
            (analysis-result '() new-env))]

         ;; Caso 3: Chamada normal (não-sink, não-sanitizador)
         [else
          (analysis-result '() env)]))]

    ;; -----------------------------------------------------------------
    ;; Salto Condicional: if (cond) then else
    ;; Análise de ambos os branches com o mesmo ambiente de entrada.
    ;; O ambiente de saída é a junção conservadora (join) dos dois.
    ;; Conservador = se qualquer branch tainta uma variável, ela fica tainted.
    ;; -----------------------------------------------------------------
    [(uir:branch condition then-branch else-branch loc)
     (let* ([then-result (analyze-node then-branch env taint-path)]
            [else-result (analyze-node else-branch env taint-path)]
            [merged-env  (env-join (analysis-result-final-env then-result)
                                   (analysis-result-final-env else-result))])
       (analysis-result
         (append (analysis-result-violations then-result)
                 (analysis-result-violations else-result))
         merged-env))]

    ;; -----------------------------------------------------------------
    ;; Sequência: executa instruções em ordem, encadeando ambientes
    ;; O ambiente de saída de cada instrução é a entrada da próxima.
    ;; -----------------------------------------------------------------
    [(uir:sequence stmts loc)
     (foldl
       (λ (stmt acc-result)
         (let* ([current-env  (analysis-result-final-env acc-result)]
                [stmt-result  (analyze-node stmt current-env taint-path)])
           (result-merge acc-result stmt-result)))
       (empty-result env)
       stmts)]

    ;; -----------------------------------------------------------------
    ;; No-op: não altera o ambiente
    ;; -----------------------------------------------------------------
    [(uir:noop loc)
     (empty-result env)]

    ;; -----------------------------------------------------------------
    ;; Fallback: nó UIR desconhecido — análise conservadora (ignora)
    ;; -----------------------------------------------------------------
    [_
     (empty-result env)]))

;; analyze-program : uir-node? → analysis-result
;; Ponto de entrada de alto nível com ambiente inicial vazio.
(define (analyze-program root)
  (analyze-node root (make-taint-env) '()))

;; -----------------------------------------------------------------------------
;; Funções Auxiliares — Lattice de Taint
;; -----------------------------------------------------------------------------

;; taint-join : taint-label taint-label → taint-label
;; Operação join na lattice:  clean < sanitized < tainted
;; "sanitized" tem precedência sobre "clean" mas NÃO sobre "tainted".
(define (taint-join a b)
  (cond
    [(or (eq? a taint:tainted) (eq? b taint:tainted)) taint:tainted]
    [(or (eq? a taint:sanitized) (eq? b taint:sanitized)) taint:sanitized]
    [else taint:clean]))

;; env-join : TaintEnv TaintEnv → TaintEnv
;; Mescla dois ambientes conservadoramente:
;; para cada variável, usa o taint mais alto (join).
(define (env-join env1 env2)
  (hash-union env1 env2 #:combine taint-join))

(define (extract-module-name func-sym)
  (let ([str (symbol->string func-sym)])
      (if (string-contains? str ".")
        (string->symbol (car (string-split str ".")))
        'global))) ;; Se não tem ponto, busca no default