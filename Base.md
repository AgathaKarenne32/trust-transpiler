## 1. Vulnerabilidades induzidas por IA

O desafio central aqui é que código gerado por LLM tem padrões de falha diferentes de código humano. Três categorias principais:

**Alucinações de API (Package Hallucination):** O LLM inventa nomes de funções plausíveis que não existem, ou usa APIs reais de forma semanticamente errada. No contexto do Trust-Transpiler, a solução é um `hallucination-detector` como uma fase pré-UIR: um módulo que consulta um grafo de conhecimento de APIs conhecidas (extraído de documentação e repositórios públicos) e sinaliza chamadas a funções não reconhecidas como `taint:unknown-api` — um novo nível na lattice, tratado com suspeita máxima pelo motor.

**Padrões de insegurança estereotipados:** LLMs tendem a reproduzir padrões comuns de código inseguro que viram durante o treinamento. O mais perigoso é a concatenação de strings para construção de queries — `(string-append "SELECT * FROM users WHERE id = " user_input)` — que um SAST convencional detectaria, mas um LLM frequentemente gera sem sanitização por "inércia de padrão". A solução é uma macro `define-llm-pattern` que codifica esses anti-padrões e os trata como sources automáticos na UIR.

**Contexto truncado (context window abuse):** Código gerado em janelas longas frequentemente "esquece" sanitizações definidas em turnos anteriores. Isso exige um `cross-chunk-taint-tracker` — um módulo que persiste o `TaintEnv` entre arquivos gerados em uma mesma sessão, algo que a v2 não suporta ainda.

No Racket, a implementação mais elegante seria estender a DSL de política com uma nova forma `define-ai-generated-policy` que herda todas as regras de `default-policy` mas adiciona sinks extras e trata imports não-reconhecidos como `taint:tainted` por padrão.

---

## 2. Redução de falsos positivos com ML/heurísticas

O problema dos falsos positivos num SAST baseado em taint analysis é estrutural: a análise over-approximates por design (conservadora), então qualquer caminho que *possa* existir é reportado, mesmo que em produção nunca ocorra. Três abordagens complementares:

**Scoring por contexto semântico:** Em vez de um threshold binário (violação / não-violação), adicionar um campo `confidence: Float` ao struct `finding`. O motor continua puramente estático, mas um pós-processador treinado com exemplos rotulados (true positive / false positive de scans anteriores) aprende a distinguir padrões. Em Racket, isso é uma função `score-finding : finding TaintState PolicyContext → Float` aplicada como filter na camada do reporter — sem tocar no motor.

**Heurística de profundidade de path:** Findings com `taint-path` de comprimento 1 (source direto ao sink, sem intermediários) têm probabilidade muito maior de ser verdadeiro positivo do que caminhos de profundidade 8+ com múltiplos branches. A regra `(define-taint-rule rule:shallow-path-boost ...)` da v2 já provê a infraestrutura — basta adicionar um peso.

**Feedback loop de anotações:** O mecanismo mais eficaz para reduzir falsos positivos em produção é o feedback humano persistido. Quando um analista marca um finding como falso positivo, o sistema aprende a suprimir findings similares (mesmo source-var + sink-func + path-length) nos próximos scans. Isso requer um módulo `suppression-store` — um hash persistente de fingerprints de findings marcados — integrável com o reporter via um hook `on-dismiss`.

---

## 3. Código híbrido e análise de dependências

Este é o problema mais difícil e o mais comum em produção: 80% do código de uma aplicação moderna vem de terceiros (npm, PyPI, etc.) sem código-fonte disponível.

A abordagem arquitetural correta é separar dois planos de análise:

**Plano de stubs (summary-based analysis):** Para cada biblioteca sem fonte, mantemos um "stub de segurança" — uma UIR simplificada que descreve apenas o comportamento de segurança relevante da biblioteca. Por exemplo, para `libpq` (PostgreSQL C), o stub diz: `(pg-exec conn query)` é um sink se `query` é tainted; `(PQescapeString ...)` é um sanitizador. Esses stubs podem ser gerados automaticamente via análise de documentação + LLM, depois auditados manualmente. O Trust-Transpiler já suporta isso via `define-security-policy` — o stub é apenas uma política adicional.

**Análise de assinatura binária:** Para bibliotecas compiladas, técnicas de pattern matching em bytecode (não disponíveis em Racket puro, mas integráveis via FFI) podem detectar chamadas a funções conhecidas como inseguras por assinatura. O Trust-Transpiler poderia expor uma interface `(register-binary-stub! lib-name version stub-policy)` que o front-end invoca após análise de binário externo.

**Grafo de dependências como UIR de segundo nível:** Em vez de analisar cada dependência isoladamente, modelar o grafo de dependências como um programa UIR onde cada `require` é um `uir:call-expr` anotado com a política da biblioteca. Isso permite propagar taint através de chamadas a bibliotecas terceiras usando os stubs, sem precisar do código-fonte.

---

## 4. Autofix baseado em OWASP

Autofix é viável — e o Trust-Transpiler já tem a infraestrutura necessária. O que falta é uma camada de `patch generation`.

A ideia: cada `finding` carrega informação suficiente para gerar uma correção automática. A correção é sempre da mesma família: inserir uma chamada a um sanitizador entre o source e o sink. A questão é *onde* inserir e *qual* sanitizador usar.

**Estratégia de patch:** Dado um finding com `(source-var X, sink Y, taint-path [X → mid → Y])`, a correção canônica é inserir `(sanitize mid)` imediatamente antes da chamada ao sink. Em Racket, isso é uma função pura `generate-patch : finding security-policy → patch-suggestion` que produz um diff de UIR — inserção de um `uir:call-stmt` com o sanitizador recomendado pela política ativa.

**Seleção do sanitizador:** A política já contém a lista de sanitizadores. A heurística de seleção é baseada no tipo do sink: sinks de SQL sugerem `parameterize-query`, sinks de HTML sugerem `html-escape`, sinks de comando sugerem `shell-escape`. Isso pode ser codificado como uma nova cláusula na `define-security-policy`:

```racket
(define-security-policy sql-policy
  #:sinks      (query exec)
  #:sanitizers (parameterize-query sql-escape)
  #:fixes      ((query → parameterize-query)
                (exec  → shell-escape)))
```

A forma `#:fixes` é outra macro — mapeia sink-name para sanitizador-recomendado, compilada em tempo de expansão para uma hash-table de lookup O(1).

**Limite do autofix:** É importante ser honesto sobre o que é automático vs. sugerido. Correções de inserção de sanitizador são seguras de sugerir — e até aplicar automaticamente em modo CI com `--autofix`. Correções arquiteturais (substituir concatenação de string por prepared statement) requerem intervenção humana e devem ser apresentadas como "sugestão de refatoração", não patch automático.

---

Aqui está um mapa visual do Trust-Transpiler v3 com todas essas extensões posicionadas arquiteturalmente:Clique nos módulos coloridos para explorar cada área. Alguns pontos de prioridade para o roadmap:

<img width="1440" height="1560" alt="image" src="https://github.com/user-attachments/assets/d6b81fb3-ad3c-4acc-86a0-a672218d834b" />

---

## Sequenciamento recomendado

A ordem importa porque cada camada desbloqueia a próxima:

**Fase 1 — Dependency stubs** (impacto imediato, baixo risco): Implementar o mecanismo de `register-binary-stub!` e criar stubs para as 20 bibliotecas mais comuns do ecossistema que você atende. Isso elimina uma classe inteira de falsos negativos — situações em que o taint atravessa uma biblioteca terceira e o motor "perde o rastro".

**Fase 2 — FP scorer + suppression store** (reduz fadiga dos analistas): Com o scorer, cada `finding` passa a ter um `confidence` entre 0.0 e 1.0. O reporter pode filtrar findings abaixo de 0.3 por padrão e exibir apenas os relevantes. O suppression store persistido entre runs transforma o feedback dos analistas em conhecimento do sistema.

**Fase 3 — Autofix engine** (só viável após fase 1): O autofix precisa dos stubs para saber qual sanitizador sugerir em contexto de bibliotecas terceiras. Sem stubs, o autofix sugeriria patches genéricos que não compilam.

**Fase 4 — AI detector** (a mais complexa): Requer um grafo de conhecimento de APIs atualizado continuamente. A forma mais pragmática para um MVP é integrar com um serviço externo de análise de manifests (`package.json`, `requirements.txt`) que já mantém esse grafo, em vez de construir um do zero.

Uma nota arquitetural importante: as fases 1, 2 e 3 são todas implementáveis como módulos puros em Racket, sem tocar no motor de taint — exatamente o que a separação `taint-engine.rkt` / `reporter.rkt` da v2 possibilita. O design da v2 já estava correto para essa expansão.
