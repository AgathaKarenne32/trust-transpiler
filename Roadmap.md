# Trust-Transpiler v3 — Roadmap Estratégico

> Evolução do framework de análise estática (SAST) baseado em Taint Analysis para cobertura de demandas modernas de segurança, com foco em código gerado por IA, redução de falsos positivos, análise híbrida e automação de correções.

---

## Contexto

O Trust-Transpiler v2 estabelece uma base sólida:

- UIR imutável com lattice de taint de cinco níveis (`⊥ < clean < sanitized < tainted < ⊤`)
- Motor puro e funcional (`eval-expr` / `exec-stmt`) com `racket/match` profundo
- DSL de política via macros (`define-security-policy`, `define-taint-rule`, `with-policy`)
- Separação rigorosa entre motor (sem I/O) e reporter (efeitos isolados)

Esta separação é o que viabiliza as quatro extensões do v3 **sem modificar o motor central**.

---

## Visão Geral da Arquitetura v3

```
┌─────────────────────────────────────────────────────────────────┐
│                         INPUT LAYER                             │
│  ┌──────────────────┐  ┌──────────────────┐  ┌──────────────┐  │
│  │ AI code detector │  │ Source front-ends │  │ Dep. stubs   │  │
│  │ (NOVO — v3)      │  │ Python, JS, C ... │  │ (NOVO — v3)  │  │
│  └────────┬─────────┘  └────────┬──────────┘  └──────┬───────┘  │
└───────────┼─────────────────────┼────────────────────┼──────────┘
            └─────────────────────▼────────────────────┘
                        ┌─────────────────┐
                        │   UIR CORE (v2) │   ← inalterado
                        │  uir:assign     │
                        │  uir:call-stmt  │
                        │  uir:if / block │
                        └────────┬────────┘
                                 │
                        ┌────────▼──────────────────────┐
                        │     POLICY LAYER (macros)     │
                        │  define-security-policy       │
                        │  define-taint-rule            │
                        │  #:fixes clause (NOVO — v3)   │
                        └────────┬──────────────────────┘
                                 │
                        ┌────────▼────────┐
                        │  TAINT ENGINE   │   ← inalterado
                        │  eval-expr      │
                        │  exec-stmt      │
                        │  taint-env-join │
                        └────────┬────────┘
                                 │
              ┌──────────────────▼──────────────────────┐
              │             OUTPUT LAYER (v3)           │
              │  ┌──────────────┐  ┌───────────────┐    │
              │  │  FP scorer   │  │   Reporter    │    │
              │  │  confidence  │  │  SARIF / JSON │    │
              │  └──────────────┘  └───────────────┘    │
              │  ┌──────────────────────────────────┐    │
              │  │  Autofix engine  (NOVO — v3)     │    │
              │  │  generate-patch / UIR diff        │    │
              │  └──────────────────────────────────┘    │
              └──────────────────┬──────────────────────┘
                                 │
                        ┌────────▼────────────────────────┐
                        │  CI/CD gate                     │
                        │  exit 0 → clean                 │
                        │  exit 1 → HIGH findings         │
                        │  exit 2 → parse error           │
                        └─────────────────────────────────┘
```

---

## Questão 1 — Vulnerabilidades induzidas por IA

### Problema

Código gerado por LLMs tem padrões de falha distintos do código humano. Três categorias principais:

| Categoria | Descrição | Exemplo |
|-----------|-----------|---------|
| **Alucinação de API** | O modelo inventa funções plausíveis que não existem | `(call db-safe-query ...)` sem nenhuma lib que exporte esse símbolo |
| **Anti-padrão estereotipado** | O modelo reproduz código inseguro visto no treino | `(string-append "SELECT * FROM users WHERE id=" user_input)` |
| **Amnésia de contexto** | Sanitizações definidas em turnos anteriores são "esquecidas" em arquivos subsequentes | Variável marcada como `sanitized` no arquivo A chega `tainted` no arquivo B |

### Solução arquitetural

#### 1.1 Novo nível na lattice: `taint:unknown-api`

Estender a lattice de taint com um nível intermediário posicionado entre `tainted` e `⊤`:

```
⊥ < clean < sanitized < tainted < unknown-api < ⊤
```

Qualquer chamada a uma função **não presente no grafo de APIs conhecidas** recebe automaticamente o rótulo `unknown-api`, tratado com suspeita máxima pelo motor.

```racket
;; Em uir.rkt — estender os símbolos de taint
(define taint:unknown-api 'unknown-api)

;; Rank atualizado em taint-engine.rkt
(define (taint-rank t)
  (case t
    [(⊥)           0]
    [(clean)        1]
    [(sanitized)    2]
    [(tainted)      3]
    [(unknown-api)  4]   ;; ← novo
    [(⊤)           5]))
```

#### 1.2 Macro `define-ai-generated-policy`

Uma política especializada que herda `default-policy` e adiciona comportamento específico para código gerado por IA:

```racket
(define-ai-generated-policy my-ai-policy
  #:extends default-policy
  ;; Qualquer símbolo não presente no grafo de APIs → unknown-api
  #:unknown-api-taint unknown-api
  ;; Anti-padrões LLM conhecidos — força taint na origem
  #:llm-antipatterns
    ((string-append   #:when-args-contain tainted  → tainted)
     (format          #:when-args-contain tainted  → tainted)
     (string-concat   #:when-args-contain tainted  → tainted)))
```

#### 1.3 Módulo `cross-chunk-taint-tracker`

Persiste o `TaintEnv` entre arquivos analisados na mesma sessão de scan, para detectar a "amnésia de contexto":

```racket
;; Interface pública do módulo (src/cross-chunk-tracker.rkt)
(provide
  make-session-tracker
  tracker-save-env!     ; persiste env após análise de um arquivo
  tracker-load-env      ; restaura env acumulado para o próximo arquivo
  tracker-reset!)       ; limpa ao início de uma nova sessão
```

#### 1.4 Grafo de APIs conhecidas

Para o MVP, integrar com um serviço externo (ex: `libraries.io` ou um snapshot do `npm registry`) via um arquivo de configuração:

```racket
;; Exemplo de configuração: known-apis.rkt
(define-known-api-set node-stdlib
  #:version "20.x"
  #:safe-functions (path.join path.resolve fs.readFileSync ...)
  #:unsafe-functions (eval child_process.exec ...))
```

---

## Questão 2 — Redução de falsos positivos

### Problema

A análise over-approximates por design (conservadora): qualquer caminho que *possa* existir é reportado, mesmo que em produção nunca ocorra. O resultado é uma "fadiga de alertas" que leva analistas a ignorar findings legítimos.

### Solução arquitetural

#### 2.1 Campo `confidence` no struct `finding`

Adicionar um campo de pontuação ao struct existente, sem quebrar compatibilidade:

```racket
;; Em taint-engine.rkt — versão v3 do struct finding
(struct finding
  (kind
   message
   taint-label
   source-var
   sink-info
   taint-path
   loc
   confidence)   ;; ← novo campo: Float no intervalo [0.0, 1.0]
  #:transparent)
```

#### 2.2 Heurísticas de scoring

O scorer é uma função pura aplicada pelo reporter — **sem tocar no motor**:

```racket
;; src/fp-scorer.rkt
(define (score-finding f)
  (let* ([path-len  (length (finding-taint-path f))]
         [base      (case (finding-kind f)
                      [(unsanitized-sink)  0.85]
                      [(policy-violation)  0.80]
                      [(taint-propagation) 0.50]
                      [else               0.30])]
         ;; Penalidade por caminho longo (maior chance de FP)
         [depth-penalty (* 0.04 (max 0 (- path-len 2)))]
         ;; Boost para caminhos rasos (source direto ao sink)
         [shallow-boost (if (= path-len 1) 0.10 0.0)])
    (max 0.0 (min 1.0 (+ base shallow-boost (- depth-penalty))))))
```

| Fator | Efeito no score |
|-------|----------------|
| Kind `unsanitized-sink` | base +0.85 |
| Caminho de profundidade 1 (direto) | boost +0.10 |
| Cada nó extra no path além de 2 | penalidade −0.04 |
| Kind `taint-propagation` | base +0.50 |

#### 2.3 Suppression store — feedback humano persistido

Quando um analista marca um finding como falso positivo, o sistema aprende a suprimir findings com a mesma "fingerprint" em scans futuros:

```racket
;; src/suppression-store.rkt
;;
;; Fingerprint = hash de (source-var, sink-func, path-length, kind)
;; Persistido como arquivo .trust-suppression no root do projeto

(provide
  make-suppression-store
  store-suppress!        ; analista marca como FP
  store-suppressed?      ; verifica antes de reportar
  store-load             ; carrega do arquivo em disco
  store-save!)           ; persiste após sessão
```

Exemplo de workflow no reporter:

```racket
(define (render-findings findings target suppression-store)
  (let ([active (filter
                  (λ (f) (not (store-suppressed? suppression-store f)))
                  findings)])
    ...))
```

#### 2.4 Threshold configurável por severidade

```racket
;; No reporter, threshold configurável por nível
(define *confidence-thresholds*
  (make-parameter
    '((high   . 0.30)   ; reporta HIGH com confiança > 30%
      (medium . 0.55)   ; reporta MEDIUM com confiança > 55%
      (low    . 0.75)   ; reporta LOW apenas com confiança > 75%
      )))
```

---

## Questão 3 — Código híbrido e dependências terceiras

### Problema

Em aplicações modernas, 80% do código vem de dependências sem fonte disponível. O motor atual "perde o rastro" do taint ao atravessar uma chamada a uma biblioteca terceira, gerando tanto falsos negativos (taint que continua sem ser detectado) quanto falsos positivos (taint limpo tratado como sujo).

### Solução arquitetural

#### 3.1 Stub de segurança por biblioteca

Para cada biblioteca sem fonte, um arquivo `.stub.rkt` descreve o comportamento de segurança relevante como uma política UIR:

```racket
;; stubs/libpq.stub.rkt — PostgreSQL C client
(define-binary-stub libpq
  #:version "15.x"
  #:sinks      (PQexec PQexecParams)
  #:sanitizers (PQescapeStringConn PQescapeLiteral)
  #:flows
    ((forbid user-input ~> PQexec
       #:via (PQescapeStringConn PQescapeLiteral PQexecParams)
       #:because "CWE-89: SQL Injection via libpq")))

;; stubs/express.stub.rkt — Node.js Express
(define-binary-stub express
  #:version "4.x"
  #:sources    (req.body req.query req.params req.headers)
  #:sinks      (res.send res.json res.write)
  #:sanitizers (express-validator sanitize-html))
```

#### 3.2 Interface de registro em runtime

```racket
;; src/stub-registry.rkt
(provide
  register-stub!          ; adiciona stub ao registry
  load-stubs-from-dir!    ; carrega todos os .stub.rkt de um diretório
  stub-policy-for         ; retorna a policy associada a um módulo
  merge-stub-into-policy) ; compõe stub com a política ativa
```

Uso no pipeline principal:

```racket
;; main.rkt — carrega stubs do projeto antes do scan
(load-stubs-from-dir! "./stubs")
(load-stubs-from-dir! "~/.trust-transpiler/global-stubs")

(define active-policy
  (foldl merge-stub-into-policy
         default-policy
         (discover-project-dependencies "package.json")))
```

#### 3.3 Grafo de dependências como UIR de segundo nível

Cada `require`/`import` é representado na UIR como um `uir:call-expr` anotado com a política do stub correspondente. Isso propaga taint através de chamadas a bibliotecas terceiras usando os stubs, sem precisar do código-fonte:

```racket
;; Exemplo: import express gera automaticamente na UIR
(uir:call-stmt 'require
               (list (uir:lit "express" 'string unknown-loc))
               #f
               unknown-loc)
;; → motor consulta stub-registry, obtém express-stub-policy
;; → req.body passa a ser registrado como source automaticamente
```

#### 3.4 Geração automática de stubs via LLM

Para bibliotecas sem stub manual, um helper usa a API da Anthropic para gerar um stub preliminar a partir da documentação:

```racket
;; tools/stub-generator.rkt
;; Gera um .stub.rkt a partir de README + type signatures
;; Output deve ser auditado manualmente antes de ser usado em produção

(define (generate-stub-draft lib-name version docs-url)
  (call-anthropic-api
    (format "Analise a documentação de ~a v~a em ~a e gere um stub
             define-binary-stub no formato do Trust-Transpiler,
             identificando sources, sinks e sanitizadores."
            lib-name version docs-url)))
```

---

## Questão 4 — Automação de correção (Autofix)

### Problema

O SAST detecta a vulnerabilidade mas o analista ainda precisa decidir como corrigi-la, procurar o sanitizador adequado e aplicar a mudança manualmente. Em pipelines de alta velocidade, isso é um gargalo.

### Solução arquitetural

#### 4.1 Nova cláusula `#:fixes` na DSL de política

A macro `define-security-policy` é estendida com uma cláusula de mapeamento sink → sanitizador recomendado:

```racket
(define-security-policy sql-policy-v3
  #:sources    (get-query-param form-field user-input)
  #:sinks      (query exec db-query raw-sql)
  #:sanitizers (parameterize-query sql-escape validate)
  #:fixes
    ((query      → parameterize-query
       #:template "(parameterize-query conn ~a ~a)")
     (exec       → shell-escape
       #:template "(shell-escape ~a)")
     (raw-sql    → parameterize-query
       #:template "(parameterize-query conn ~a ~a)")
     (display    → html-escape
       #:template "(html-escape ~a)")))
```

A cláusula `#:fixes` é compilada em tempo de expansão da macro para uma hash-table de lookup O(1).

#### 4.2 Struct `patch-suggestion`

```racket
;; src/autofix.rkt
(struct patch-suggestion
  (finding         ; finding? — violação que originou o patch
   kind            ; Symbol — 'insert-sanitizer | 'refactor | 'manual-only
   description     ; String — explicação legível
   uir-diff        ; (Listof patch-op) — operações sobre a UIR
   code-template   ; String | #f — código gerado para o front-end original
   confidence)     ; Float — confiança no patch (0.0–1.0)
  #:transparent)

(struct patch-op
  (type            ; Symbol — 'insert | 'replace | 'delete
   target-loc      ; src-loc — onde aplicar
   new-node)       ; uir-node? | #f
  #:transparent)
```

#### 4.3 Função `generate-patch`

```racket
;; src/autofix.rkt
;;
;; generate-patch : finding security-policy → patch-suggestion | #f
;;
;; Dado um finding e a política ativa, tenta gerar uma correção automática.
;; Retorna #f se o finding não tem correção automática disponível.

(define (generate-patch f policy)
  (match f
    [(finding 'unsanitized-sink msg _ src-var (cons sink-fn sink-loc) path _)
     (let ([fix-fn (lookup-fix policy sink-fn)])
       (if fix-fn
           (patch-suggestion
             f
             'insert-sanitizer
             (format "Inserir ~a antes da chamada a ~a" fix-fn sink-fn)
             (list
               (patch-op 'insert
                         sink-loc
                         (uir:call-stmt fix-fn
                                        (list (uir:var src-var sink-loc))
                                        #f
                                        sink-loc)))
             (format-code-template (policy-fix-template policy sink-fn) src-var)
             0.85)
           #f))]
    [_ #f]))
```

#### 4.4 Modos de aplicação

| Modo | Flag CLI | Comportamento |
|------|----------|---------------|
| **Sugestão** | `--suggest-fix` | Exibe o patch no relatório sem aplicar |
| **Autofix em modo diff** | `--autofix-diff` | Gera um `.patch` unificado para revisão |
| **Autofix direto** | `--autofix` | Aplica a correção diretamente (apenas patches com `confidence >= 0.80`) |
| **Autofix forçado** | `--autofix --force` | Aplica todos os patches independente de confiança (não recomendado em prod) |

```bash
# Exemplo de uso em CI/CD
racket main.rkt --scan src/ --policy sql --autofix-diff > security.patch
git apply security.patch
git commit -m "fix(security): auto-applied Trust-Transpiler patches"
```

#### 4.5 Limites do autofix

É importante distinguir o que é automático do que exige intervenção humana:

| Tipo de correção | Automático? | Exemplo |
|-----------------|-------------|---------|
| Inserção de sanitizador antes de sink | Sim (`confidence >= 0.80`) | Adicionar `html-escape` antes de `display` |
| Substituição de concatenação por prepared statement | Sugestão apenas | Converter `(string-append sql user_input)` para `(parameterize-query ...)` |
| Refatoração arquitetural | Manual | Mover lógica de negócio para fora de handler HTTP |
| Correção em código gerado por LLM | Manual com contexto | Requer entender a intenção original do prompt |

---

## Sequenciamento de implementação

A ordem das fases foi definida para que cada uma **desbloqueie** a próxima:

```
Fase 1 ──────────────────────────────────────────────────────── Fase 4
  │                                                                │
  ▼                                                                ▼
Dep. stubs ──► FP scorer ──► Autofix engine ──► AI detector
(sem stubs,   (reduz        (só funciona bem   (mais complexo,
 autofix       fadiga         com stubs para     requer grafo
 sugere         dos            saber qual         de APIs
 patches        analistas)     sanitizador        atualizado)
 genéricos)                    sugerir)
```

### Fase 1 — Dependency stubs (impacto imediato, baixo risco)

**Objetivo:** Eliminar falsos negativos onde o taint atravessa uma biblioteca terceira e o motor perde o rastro.

**Entregáveis:**
- Módulo `src/stub-registry.rkt` com `register-stub!` e `merge-stub-into-policy`
- Stubs iniciais para as 10–20 bibliotecas mais usadas no ecossistema alvo
- Integração no pipeline de `main.rkt` com `load-stubs-from-dir!`

**Esforço estimado:** 2–3 semanas

### Fase 2 — FP scorer + suppression store (reduz fadiga dos analistas)

**Objetivo:** Reduzir o volume de findings reportados sem reduzir a cobertura de verdadeiros positivos.

**Entregáveis:**
- Campo `confidence` no struct `finding`
- Módulo `src/fp-scorer.rkt` com heurísticas de scoring
- Módulo `src/suppression-store.rkt` com persistência de fingerprints
- Threshold configurável por severidade no reporter

**Esforço estimado:** 1–2 semanas

**Métrica de sucesso:** Redução de 30–50% no volume de findings reportados em projetos reais, sem aumento de falsos negativos verificados.

### Fase 3 — Autofix engine (só viável após Fase 1)

**Objetivo:** Gerar e aplicar correções automáticas para vulnerabilidades com padrão conhecido.

**Entregáveis:**
- Cláusula `#:fixes` na macro `define-security-policy`
- Módulo `src/autofix.rkt` com `generate-patch` e `apply-patches!`
- Flags `--suggest-fix`, `--autofix-diff`, `--autofix` no CLI
- Testes de integração: scan → patch → re-scan deve retornar zero findings

**Esforço estimado:** 3–4 semanas

### Fase 4 — AI code detector (mais complexa)

**Objetivo:** Detectar padrões de vulnerabilidade específicos de código gerado por LLM.

**Entregáveis:**
- Novo nível `taint:unknown-api` na lattice
- Macro `define-ai-generated-policy`
- Módulo `src/cross-chunk-tracker.rkt` para análise multi-arquivo
- Integração com fonte de dados de APIs conhecidas (snapshot ou serviço externo)
- Helper `tools/stub-generator.rkt` para geração automática de stubs via LLM

**Esforço estimado:** 4–6 semanas

**Dependências externas:** Fonte de dados de APIs (npm registry snapshot, PyPI metadata, ou similar).

---

## Referências

- [OWASP Top 10 — 2021](https://owasp.org/Top10/)
- [CWE-89: SQL Injection](https://cwe.mitre.org/data/definitions/89.html)
- [CWE-79: Cross-Site Scripting](https://cwe.mitre.org/data/definitions/79.html)
- [CWE-117: Log Injection](https://cwe.mitre.org/data/definitions/117.html)
- [SARIF v2.1 Specification](https://docs.oasis-open.org/sarif/sarif/v2.1.0/sarif-v2.1.0.html)
- [Static Analysis Results Interchange Format — GitHub](https://github.com/microsoft/sarif-tutorials)
- Racket — [Syntax Objects & Macros](https://docs.racket-lang.org/guide/macros.html)
- Racket — [Pattern Matching](https://docs.racket-lang.org/reference/match.html)

---

*Trust-Transpiler v3 Roadmap — gerado em 2026*
