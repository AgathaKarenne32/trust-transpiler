# Trust-Transpiler — Documentação Técnica Completa

> Framework de Análise Estática de Segurança (SAST) com foco em rastreamento de fluxo de dados contaminados (Taint Analysis), governança de APIs e autocorreção guiada por políticas.

---

## Sumário

1. [Visão Geral](#visão-geral)
2. [Arquitetura Atual](#arquitetura-atual)
3. [Componentes Implementados](#componentes-implementados)
   - [Representação Intermediária Universal (UIR)](#1-representação-intermediária-universal-uir)
   - [Motor de Taint Analysis](#2-motor-de-taint-analysis)
   - [Gatekeeper — Governança Estrutural](#3-gatekeeper--governança-estrutural)
   - [Contexto Persistente Cross-File](#4-contexto-persistente-cross-file)
   - [Motor de Autocorreção (Autofix)](#5-motor-de-autocorreção-autofix)
   - [Sistema de Scoring e Confiança](#6-sistema-de-scoring-e-confiança)
4. [Implementações Futuras](#implementações-futuras)
   - [F1 — Integração CI/CD de Alta Fidelidade](#f1--integração-cicd-de-alta-fidelidade)
   - [F2 — Avanços na Detecção com IA](#f2--avanços-na-detecção-com-ia)
   - [F3 — Experiência do CLI](#f3--experiência-do-cli)
   - [F4 — Policy Marketplace](#f4--policy-marketplace)
5. [Roadmap Priorizado](#roadmap-priorizado)
6. [Glossário](#glossário)

---

## Visão Geral

O **Trust-Transpiler** nasceu como um pipeline acadêmico de rastreamento de fluxo de dados e evoluiu para uma solução SAST modular completa. Seu objetivo central é funcionar como um **revisor de segurança automatizado**: ele transforma código-fonte em uma Representação Intermediária (UIR) e, a partir dela, executa análise profunda para garantir que dados não confiáveis (inputs de usuários, variáveis de ambiente externas, etc.) nunca alcancem destinos sensíveis — como bancos de dados ou sistemas de log — sem antes passarem por um sanitizador aprovado.

```
Código-Fonte
     │
     ▼
┌─────────────┐
│   Parser /  │   ← Suporte multi-linguagem
│  Transpiler │
└──────┬──────┘
       │
       ▼
┌─────────────┐
│     UIR     │   ← Representação Intermediária Universal
│  (IR Graph) │
└──────┬──────┘
       │
  ┌────┴────┐
  │         │
  ▼         ▼
Taint    Gatekeeper
Analysis   (API Gov.)
  │         │
  └────┬────┘
       │
       ▼
┌─────────────┐
│   Scoring   │   ← Confiança + Severidade
│   Engine    │
└──────┬──────┘
       │
       ▼
┌─────────────┐
│   Autofix   │   ← Patch sugerido por política
│   Engine    │
└──────┬──────┘
       │
       ▼
   Relatório
  (CLI / JSON)
```

---

## Arquitetura Atual

O framework é construído sobre três princípios arquiteturais:

**Modularidade** — cada componente (parser, analisador, scorer, autofix) é intercambiável e pode ser evoluído de forma independente.

**Policy-Driven** — todo comportamento de detecção e correção é guiado por políticas declarativas, não por lógica hardcoded. Isso permite que times de segurança definam regras sem alterar o código do framework.

**Precisão sobre Cobertura** — o sistema prefere reportar menos com alta confiança do que inundar o analista com falsos positivos, endereçado diretamente pelo sistema de scoring.

---

## Componentes Implementados

### 1. Representação Intermediária Universal (UIR)

O primeiro passo do pipeline é a transformação do código-fonte em uma UIR — um grafo interno que representa o programa de forma agnóstica à linguagem de origem.

**O que a UIR captura:**
- Nós de instrução (atribuições, chamadas de função, condicionais)
- Arestas de fluxo de dados (quem produz, quem consome cada valor)
- Arestas de fluxo de controle (ordem de execução)
- Metadados de escopo e módulo

**Por que isso importa:**  
Trabalhar sobre a UIR, e não sobre o texto bruto, permite que todas as análises subsequentes sejam precisas e independentes de sintaxe. Uma vulnerabilidade em Python e a mesma vulnerabilidade em JavaScript produzem o mesmo padrão no grafo UIR.

---

### 2. Motor de Taint Analysis

O núcleo analítico do framework. Rastreia o fluxo de dados "sujos" — chamados de **tainted** — desde sua origem até destinos sensíveis.

**Conceitos fundamentais:**

| Termo | Definição |
|---|---|
| **Source** | Ponto de entrada de dado não confiável (ex: `request.body`, `os.environ`) |
| **Sink** | Destino sensível que não deve receber dado cru (ex: `db.execute()`, `log.write()`) |
| **Sanitizer** | Função que transforma dado sujo em seguro (ex: `escape()`, `parameterize()`) |
| **Taint Path** | Caminho completo de uma source até um sink no grafo UIR |

**Como funciona:**

```
[Source]  request.args['user_id']       ← marcado como TAINTED
    │
    ▼
[Assign]  query = "SELECT * WHERE id=" + user_id   ← taint se propaga
    │
    ▼
[Sink]    db.execute(query)             ← VULNERABILIDADE: taint chegou ao sink
                                           sem passar por sanitizador
```

O motor percorre o grafo UIR em busca de todos os caminhos onde um valor tainted alcança um sink sem ser interceptado por um sanitizador reconhecido pela política ativa.

---

### 3. Gatekeeper — Governança Estrutural

Camada de defesa específica para **código gerado por IA**, que tende a "alucinar" chamadas de APIs inexistentes ou inseguras.

**Problema que resolve:**  
Modelos de linguagem frequentemente geram código sintaticamente correto, mas que chama funções que não existem na biblioteca, usa parâmetros incorretos ou invoca métodos deprecados com vulnerabilidades conhecidas.

**Como funciona:**  
O Gatekeeper mantém um registro de APIs conhecidas e aprovadas pela política de segurança. Durante a análise da UIR, qualquer chamada de função que não esteja no registro é:

1. Sinalizada como **API não reconhecida**
2. Bloqueada de ser considerada como sanitizador válido
3. Incluída no relatório com sugestão de substituição

```yaml
# Exemplo de política de Gatekeeper
gatekeeper:
  approved_apis:
    - name: "db.execute"
      requires_parameterized: true
    - name: "html.escape"
      sanitizes: ["xss"]
  block_unknown: true
  fail_on_hallucination: true
```

---

### 4. Contexto Persistente Cross-File

Solução para um dos maiores desafios do SAST moderno: **vulnerabilidades que atravessam múltiplos arquivos**.

**Problema que resolve:**  
A maioria dos analisadores trata cada arquivo de forma isolada. Isso gera falsos negativos quando uma source está em `routes.py`, passa por `services.py` e chega ao sink em `database.py`.

**Como funciona:**  
O framework mantém um estado de segurança persistente entre análises de arquivos:

- Funções que recebem dados tainted são marcadas no estado global
- Ao analisar um novo arquivo, o contexto é carregado e as chamadas externas são resolvidas com informação de taint correta
- O estado é atualizado ao final de cada arquivo analisado

```
Análise de routes.py
  └─ user_input → handle_request()  [TAINTED, exportado para contexto]

Análise de services.py
  └─ Contexto carregado: handle_request() recebe dado TAINTED
  └─ process_data(handle_request()) → [TAINTED, propagado]

Análise de database.py
  └─ Contexto carregado: process_data() retorna TAINTED
  └─ db.execute(process_data()) → VULNERABILIDADE DETECTADA ✓
```

---

### 5. Motor de Autocorreção (Autofix)

Além de reportar vulnerabilidades, o framework gera **patches sugeridos** baseados na política de segurança ativa.

**Fluxo de autocorreção:**

1. Vulnerabilidade identificada com seu taint path completo
2. Política consultada: qual sanitizador é adequado para este tipo de sink?
3. Patch gerado: o sanitizador correto é inserido no ponto mínimo necessário do caminho

**Exemplo:**

```python
# Código original (vulnerável)
def get_user(user_id):
    query = f"SELECT * FROM users WHERE id = {user_id}"
    return db.execute(query)

# Patch sugerido pelo Autofix
def get_user(user_id):
    # [AUTOFIX] Parameterized query aplicada conforme política sql-injection
    query = "SELECT * FROM users WHERE id = ?"
    return db.execute(query, (user_id,))
```

O patch é apresentado como diff e nunca aplicado automaticamente sem confirmação — o desenvolvedor mantém controle total.

---

### 6. Sistema de Scoring e Confiança

Mecanismo que atribui um score de confiança a cada achado, separando vulnerabilidades críticas de possíveis ruídos.

**Fatores que compõem o score:**

| Fator | Peso | Descrição |
|---|---|---|
| Comprimento do taint path | Alto | Paths mais curtos têm maior confiança |
| Tipo de source | Alto | Input direto de usuário > variável de ambiente |
| Tipo de sink | Alto | Escrita em BD > log interno |
| Resolução de contexto | Médio | Path resolvido cross-file tem menor confiança |
| Sanitizador parcial | Médio | Sanitização incompleta reduz score, não elimina |

**Classificação de saída:**

```
CRITICAL  (score ≥ 0.85) — Bloqueante. Requer correção antes do merge.
HIGH      (score ≥ 0.65) — Reportado com alta visibilidade.
MEDIUM    (score ≥ 0.45) — Incluído no relatório para revisão.
LOW       (score < 0.45) — Listado como ruído potencial, não bloqueia.
```

---

## Implementações Futuras

---

### F1 — Integração CI/CD de Alta Fidelidade

#### F1.1 — PR Diff Analysis

Em vez de analisar o projeto inteiro a cada push, analisar apenas o **delta do PR**. Isso reduz o tempo de feedback de minutos para segundos.

```bash
trust-transpiler scan \
  --diff HEAD~1..HEAD \
  --policy strict \
  --fail-on critical
```

**Comportamento esperado:**
- Identifica apenas arquivos modificados no PR
- Reanálise com contexto persistente carregado do estado anterior
- Resultado em <10s para a maioria dos PRs

#### F1.2 — Status Checks Semânticos

Em vez de um simples pass/fail no CI, o check retorna contexto diretamente na interface do PR:

```
❌ Trust-Transpiler: 1 CRITICAL encontrado

  user_service.py:47 — SQL Injection
  Taint: request.args['id'] → db.execute()
  Sanitizer sugerido: parameterized query
  
  [Ver Autofix] [Ver Taint Path] [Ignorar com justificativa]
```

#### F1.3 — Policy-as-Code Versionado

As políticas de segurança vivem como arquivos no próprio repositório:

```yaml
# .trust-policy.yaml (versionado no repositório)
version: "2.0"
policy: strict

sources:
  - pattern: "request.*"
    taint_level: high
  - pattern: "os.environ.*"
    taint_level: medium

sinks:
  - pattern: "db.execute"
    requires_sanitizer: ["parameterized_query"]
  - pattern: "log.*"
    requires_sanitizer: ["pii_redactor"]

gatekeeper:
  block_unknown_apis: true
```

Isso garante que mudanças nas políticas sejam revisadas em PRs como qualquer outro código — **auditabilidade nativa**.

---

### F2 — Avanços na Detecção com IA

> A IA deve ser aplicada onde a análise baseada em regras tem limitações estruturais — não como substituta, mas como complemento.

#### F2.1 — Inferência de Sanitizadores Desconhecidos

**Problema:** O maior gerador de falsos positivos é quando o sanitizador é uma função interna não declarada na política.

**Solução:** Um modelo treinado em padrões de sanitização (regex, escape, validation, encoding) avalia funções desconhecidas e infere, com score de confiança, se elas provavelmente sanitizam um dado tipo de taint.

```
Função desconhecida: clean_user_input(value)
Análise do modelo:
  - Contém chamada a regex.sub() → +0.3
  - Parâmetro nomeado 'value' → +0.1
  - Retorna string transformada → +0.2
  - Não acessa banco ou I/O → +0.2
  
Score de sanitização inferido: 0.80 (HIGH)
Ação: Reduz score da vulnerabilidade associada
      Adiciona nota: "Possível sanitizador não declarado em política"
```

#### F2.2 — Grafo de Chamadas Probabilístico

O contexto persistente atual resolve caminhos estáticos. O próximo nível é sugerir **arestas de fluxo que a análise estática não consegue resolver** — callbacks, injeção de dependência, chamadas dinâmicas.

O modelo sugere conexões prováveis; o analista confirma ou rejeita. Confirmações retroalimentam o modelo para o projeto específico.

#### F2.3 — Classificação de Severidade Contextual

A mesma vulnerabilidade tem impacto radicalmente diferente dependendo do contexto:

```
SQL Injection em endpoint público autenticado  → CRITICAL
SQL Injection em função de admin interna       → HIGH
SQL Injection em script de manutenção offline  → MEDIUM
```

Um classificador que lê decorators de rota, middleware de autenticação e configuração de ACL ajusta o score de severidade automaticamente — **reduzindo fadiga de alerta** sem sacrificar cobertura.

---

### F3 — Experiência do CLI

#### F3.1 — Modo Interativo de Autofix

```
$ trust-transpiler fix user_service.py

[1/2] CRITICAL — SQL Injection em linha 47
──────────────────────────────────────────
Taint: request.args['id'] → db.execute()
Caminho: routes.py:12 → services.py:34 → user_service.py:47

Patch sugerido:
- query = f"SELECT * FROM users WHERE id = {user_id}"
+ query = "SELECT * FROM users WHERE id = ?"
+ return db.execute(query, (user_id,))

Aplicar fix? [s] Sim  [n] Não  [d] Ver diff completo  [p] Editar política
> _
```

#### F3.2 — Watch Mode para Desenvolvimento Local

```bash
$ trust-transpiler watch src/

Monitorando src/ — análise incremental ativa
Aguardando alterações...

[14:32:01] user_service.py salvo — analisando...
[14:32:02] ✓ Nenhuma vulnerabilidade nova detectada

[14:35:44] auth.py salvo — analisando...
[14:35:45] ⚠ HIGH: Taint path detectado em auth.py:89
           request.headers['token'] → log.write()
           Execute: trust-transpiler fix auth.py para ver sugestão
```

O watch mode muda a percepção da ferramenta: de "bloqueador de CI" para **parceiro de desenvolvimento em tempo real**.

#### F3.3 — Output com Explicabilidade

Cada achado acompanha uma linha de raciocínio em linguagem natural:

```
CRITICAL — SQL Injection
Arquivo: user_service.py, linha 47
Score: 0.92

Raciocínio: Este path é crítico porque o dado entra via request.args
(source de alta confiança), atravessa 3 módulos sem nenhuma
sanitização detectada, e alcança db.execute() com dado de sessão
do usuário — sink de escrita em banco de dados com acesso privilegiado.

A ausência de parameterized query neste contexto representa risco
direto de exfiltração de dados.

Sanitizador recomendado: parameterized_query (política: sql-injection-v2)
```

Isso é especialmente valioso para **times em crescimento** — o framework educa enquanto protege.

---

### F4 — Policy Marketplace

A evolução natural do sistema Policy-as-Code é um **ecossistema de políticas compartilhadas**.

**Conceito:**

```bash
$ trust-transpiler policy add django-security-baseline
$ trust-transpiler policy add owasp-top10-2025
$ trust-transpiler policy add hipaa-data-handlers
```

**Como funcionaria:**
- Políticas publicadas e versionadas pela comunidade ou por organizações
- Stack do projeto detectado automaticamente → políticas relevantes sugeridas
- Empresas publicam políticas internas em registros privados
- Merge de políticas com resolução de conflitos explícita

Isso transforma o Trust-Transpiler de **ferramenta** em **plataforma** — com crescimento orgânico via ecossistema open source.

---

## Roadmap Priorizado

| # | Feature | Impacto | Esforço | Prioridade |
|---|---|---|---|---|
| 1 | Watch Mode (F3.2) | Alto — muda adoção local | Baixo | 🔴 Imediato |
| 2 | PR Diff Analysis (F1.1) | Alto — adoção em times | Médio | 🔴 Imediato |
| 3 | CLI Interativo com Autofix (F3.1) | Alto — UX de correção | Médio | 🟡 Curto prazo |
| 4 | Status Checks Semânticos (F1.2) | Alto — visibilidade no PR | Médio | 🟡 Curto prazo |
| 5 | Policy-as-Code versionado (F1.3) | Médio — governança | Baixo | 🟡 Curto prazo |
| 6 | Output com Explicabilidade (F3.3) | Médio — educação do time | Baixo | 🟡 Curto prazo |
| 7 | Inferência de Sanitizadores (F2.1) | Alto — reduz falsos positivos | Alto | 🟢 Médio prazo |
| 8 | Severidade Contextual (F2.3) | Alto — reduz fadiga | Alto | 🟢 Médio prazo |
| 9 | Grafo Probabilístico (F2.2) | Alto — cobertura cross-file | Muito alto | 🔵 Longo prazo |
| 10 | Policy Marketplace (F4) | Muito alto — ecossistema | Muito alto | 🔵 Longo prazo |

---

## Glossário

| Termo | Definição |
|---|---|
| **SAST** | Static Application Security Testing — análise de segurança em código-fonte sem executá-lo |
| **Taint Analysis** | Técnica de rastreamento de dados não confiáveis através do fluxo de execução |
| **UIR** | Universal Intermediate Representation — representação interna agnóstica à linguagem |
| **Source** | Ponto de entrada de dado não confiável no sistema |
| **Sink** | Destino sensível que não deve receber dados não sanitizados |
| **Sanitizer** | Função que neutraliza o risco de um dado contaminado |
| **Taint Path** | Caminho completo de uma source até um sink no grafo de fluxo |
| **Gatekeeper** | Camada de governança que valida chamadas de API contra uma lista aprovada |
| **Autofix** | Motor de geração de patches sugeridos baseados na política de segurança ativa |
| **Policy-as-Code** | Paradigma onde políticas de segurança são definidas como arquivos versionados |
| **False Positive** | Vulnerabilidade reportada que não representa risco real — principal causa de fadiga de analista |
| **False Negative** | Vulnerabilidade real não detectada — o risco mais grave em SAST |
| **CI/CD** | Continuous Integration / Continuous Delivery — pipeline automatizado de build e deploy |

---
