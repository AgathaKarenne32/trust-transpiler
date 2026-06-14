# Trust-Transpiler — Guia de Testes

> Como verificar, validar e depurar cada camada do framework — do ambiente ao motor de análise.

---

## Sumário

1. [Pré-requisitos e Verificação do Ambiente](#1-pré-requisitos-e-verificação-do-ambiente)
2. [Executando a Suíte de Testes Unitários](#2-executando-a-suíte-de-testes-unitários)
3. [Testando o Parser](#3-testando-o-parser)
4. [Testando o Motor de Taint Analysis](#4-testando-o-motor-de-taint-analysis)
5. [Testando o Gatekeeper](#5-testando-o-gatekeeper)
6. [Testando o Contexto Persistente Cross-File](#6-testando-o-contexto-persistente-cross-file)
7. [Testando o Autofix](#7-testando-o-autofix)
8. [Testando o Reporter e a Saída CLI](#8-testando-o-reporter-e-a-saída-cli)
9. [Testando a Integração CI/CD](#9-testando-a-integração-cicd)
10. [Casos de Teste de Referência](#10-casos-de-teste-de-referência)
11. [Interpretando Resultados](#11-interpretando-resultados)
12. [Problemas Comuns e Soluções](#12-problemas-comuns-e-soluções)

---

## 1. Pré-requisitos e Verificação do Ambiente

Antes de qualquer teste, confirme que o ambiente está corretamente configurado.

### 1.1 Verificar instalação do Racket

```bash
racket --version
```

Saída esperada (versão 8.x ou superior):

```
Welcome to Racket v8.x.x [cs].
```

Se o comando não for encontrado, instale o Racket em [racket-lang.org](https://racket-lang.org/).

### 1.2 Verificar permissão do script de execução

```bash
ls -la run.sh
```

Se necessário, conceda permissão de execução:

```bash
chmod +x run.sh
```

### 1.3 Verificar estrutura do projeto

```bash
ls -R
```

Estrutura esperada:

```
.
├── .trust-transpiler/cache
│   ├── test__policia.tt.taint-cache
│   └── test__vulneravel.tt.taint-cache
├── examples/
│   ├── safe.tt
│   ├── test-stub.tt
│   └── vulnerable.tt
├── src/
│   ├── ai_security_linter.rkt
│   ├── api_gatekeeper.rkt
│   ├── autofix.rkt
│   ├── cross_chunk_tracker.rkt
│   ├── fp_scorer.rkt
│   ├── parser.rkt
│   ├── policy.rkt
│   ├── reporter.rkt
│   ├── stub-registry.rkt
│   ├── taint_engine.rkt
│   ├── types.rkt
│   └── uir.rkt
├── stubs/
│   ├── express.stub.rkt
│   └── lib-exemplo.stub.rkt
└── test/
    ├── policia.tt
    ├── taint_test.rkt
    ├── test-autofix.rkt
    └── vulneravel.tt
├── .gitignore
├── main.rkt
├── run.sh
```

Se algum arquivo estiver ausente, o pipeline não funcionará corretamente.

### 1.4 Smoke test — demonstração rápida

Antes de qualquer teste específico, execute a demonstração embutida. Se ela rodar sem erros, o ambiente está íntegro:

```bash
./run.sh demo
```

Saída esperada: execução completa sem erros de sintaxe ou módulos não encontrados, com pelo menos um relatório de análise exibido no terminal.

---

## 2. Executando a Suíte de Testes Unitários

A suíte `test/taint_test.rkt` usa o framework **`rackunit`** e valida a lógica central do motor de análise de forma isolada do parser e da CLI.

### 2.1 Via script facilitador

```bash
./run.sh test
```

### 2.2 Diretamente via Racket

```bash
racket test/taint_test.rkt
```

### 2.3 Interpretando o resultado

**Todos os testes passando:**

```
rackunit: 0 tests failed, 0 errors.
```

**Testes com falha:**

```
--------------------
FAILURE
name:       check-equal?
location:   test/taint_test.rkt:42:4
expression: (check-equal? (is-tainted? result "user_input") #t)
actual:     #f
expected:   #t
--------------------
```

Cada bloco de falha indica:
- O arquivo e a linha onde o teste está definido (`taint_test.rkt:42`)
- O que foi testado (`is-tainted? result "user_input"`)
- O valor obtido (`#f`) versus o esperado (`#t`)

### 2.4 O que a suíte cobre

| Categoria | O que é validado |
|---|---|
| Propagação básica | Variável recebe valor de source → deve estar tainted |
| Propagação encadeada | `a = source; b = a; c = b` → `c` deve estar tainted |
| Limpeza por sanitizador | Após sanitize(x), x não deve estar tainted |
| Detecção de violação | Tainted alcança sink → violação deve ser reportada |
| Branches conservadores | `if` com branch tainted → variável resultante deve ser tainted |
| Ausência de falsos positivos | Variável nunca tainted não deve gerar violação |

---

## 3. Testando o Parser

O parser (`src/parser.rkt`) converte código-fonte `.tt` em UIR. Teste-o com arquivos de entrada controlados.

### 3.1 Criar um arquivo de teste mínimo

Crie o arquivo `test/samples/minimal.tt`:

```
input x from user
assign y = x
sink db_execute(y)
```

### 3.2 Executar o scan

```bash
./run.sh scan test/samples/minimal.tt
```

### 3.3 O que verificar

O parser está funcionando corretamente se:

- A execução não gera erros de parsing (sem mensagens como `parse-error` ou `unexpected token`)
- O motor de análise recebe a UIR e produz um relatório (mesmo que seja "sem violações")
- Nenhum crash ou stack trace Racket é exibido

### 3.4 Testar com entrada malformada

Crie `test/samples/malformed.tt` com sintaxe inválida:

```
input x from
assign = broken
```

Execute:

```bash
./run.sh scan test/samples/malformed.tt
```

**Comportamento esperado:** mensagem de erro clara descrevendo o problema de sintaxe, sem crash silencioso.

---

## 4. Testando o Motor de Taint Analysis

Cada cenário abaixo valida um comportamento específico do `taint_engine.rkt`. Crie os arquivos de amostra correspondentes e execute o scan.

### 4.1 Cenário: propagação direta — deve detectar violação

**Arquivo:** `test/samples/direct_taint.tt`

```
input user_id from user
sink db_execute(user_id)
```

**Execução:**

```bash
./run.sh scan test/samples/direct_taint.tt
```

**Resultado esperado:** violação de severidade `HIGH` reportando que `user_id` (tainted) alcança `db_execute` sem sanitização.

---

### 4.2 Cenário: propagação encadeada — deve detectar violação

**Arquivo:** `test/samples/chained_taint.tt`

```
input user_name from user
assign a = user_name
assign b = a
assign c = b
sink log_write(c)
```

**Execução:**

```bash
./run.sh scan test/samples/chained_taint.tt
```

**Resultado esperado:** violação reportada para `c` → `log_write`, rastreando o taint até `user_name`.

---

### 4.3 Cenário: sanitização correta — não deve detectar violação

**Arquivo:** `test/samples/sanitized.tt`

```
input user_id from user
assign safe_id = sanitize(user_id)
sink db_execute(safe_id)
```

**Execução:**

```bash
./run.sh scan test/samples/sanitized.tt
```

**Resultado esperado:** nenhuma violação. `safe_id` não está tainted após passar pelo sanitizador.

```
✓ Análise concluída — 0 violações encontradas.
```

---

### 4.4 Cenário: branch conservador — deve detectar violação

**Arquivo:** `test/samples/branch_taint.tt`

```
input user_input from user
if condition
    assign x = sanitize(user_input)
else
    assign x = user_input
endif
sink db_execute(x)
```

**Execução:**

```bash
./run.sh scan test/samples/branch_taint.tt
```

**Resultado esperado:** violação detectada, pois o motor adota postura conservadora — `x` pode ser tainted no branch `else`.

---

### 4.5 Cenário: dado limpo — não deve detectar violação

**Arquivo:** `test/samples/clean_data.tt`

```
assign x = "valor_fixo"
sink db_execute(x)
```

**Execução:**

```bash
./run.sh scan test/samples/clean_data.tt
```

**Resultado esperado:** nenhuma violação. `x` nunca foi marcado como tainted.

---

### 4.6 Cenário: múltiplas sources — deve detectar todas as violações

**Arquivo:** `test/samples/multi_source.tt`

```
input user_name from user
input user_email from user
assign query = user_name
sink db_execute(query)
sink log_write(user_email)
```

**Execução:**

```bash
./run.sh scan test/samples/multi_source.tt
```

**Resultado esperado:** duas violações reportadas — uma para cada sink.

---

## 5. Testando o Gatekeeper

O Gatekeeper bloqueia chamadas a APIs não reconhecidas pela política de segurança.

### 5.1 Cenário: API desconhecida como sanitizador — deve bloquear

**Arquivo:** `test/samples/fake_sanitizer.tt`

```
input user_id from user
assign safe_id = imaginary_cleaner(user_id)
sink db_execute(safe_id)
```

**Execução:**

```bash
./run.sh scan test/samples/fake_sanitizer.tt
```

**Resultado esperado:** o Gatekeeper sinaliza `imaginary_cleaner` como API não reconhecida. A violação **não é eliminada** — `safe_id` permanece tainted porque o sanitizador não está na lista aprovada.

---

### 5.2 Cenário: API aprovada — deve aceitar

**Arquivo:** `test/samples/approved_api.tt`

```
input user_id from user
assign safe_id = sanitize(user_id)
sink db_execute(safe_id)
```

**Execução:**

```bash
./run.sh scan test/samples/approved_api.tt
```

**Resultado esperado:** nenhuma violação. `sanitize` é reconhecida pela política e o taint é removido.

---

## 6. Testando o Contexto Persistente Cross-File

Este teste valida que o framework rastreia taint entre arquivos diferentes.

### 6.1 Criar arquivos encadeados

**Arquivo:** `test/samples/cross/module_a.tt`

```
input user_input from user
assign processed = user_input
```

**Arquivo:** `test/samples/cross/module_b.tt`

```
import processed from module_a
sink db_execute(processed)
```

### 6.2 Executar análise sequencial

```bash
./run.sh scan test/samples/cross/module_a.tt
./run.sh scan test/samples/cross/module_b.tt
```

**Resultado esperado:** o segundo scan, ao carregar o contexto do primeiro, deve detectar que `processed` está tainted e reportar a violação em `module_b.tt`.

Se o contexto não estiver funcionando, o segundo scan reportará "0 violações" — um falso negativo.

---

## 7. Testando o Autofix

O Autofix gera patches sugeridos para cada violação encontrada.

### 7.1 Executar scan com violação conhecida

```bash
./run.sh scan test/samples/direct_taint.tt
```

### 7.2 O que verificar no output do Autofix

Para cada violação reportada, deve aparecer uma sugestão de correção com:

- O tipo de sanitizador recomendado
- O ponto exato do código onde aplicar
- A forma corrigida do trecho vulnerável

**Exemplo de saída esperada:**

```
[AUTOFIX SUGERIDO]
Linha 2: db_execute(user_id)
Substituir por: db_execute_safe("...", user_id)
Política aplicada: sql-injection-v1
```

### 7.3 Verificar que o arquivo original não foi alterado

O Autofix nunca deve modificar o arquivo de entrada sem confirmação explícita:

```bash
# Antes do scan
cat test/samples/direct_taint.tt

# Após o scan
cat test/samples/direct_taint.tt

# Os conteúdos devem ser idênticos
```

---

## 8. Testando o Reporter e a Saída CLI

### 8.1 Modo colorido (padrão)

```bash
./run.sh scan test/samples/direct_taint.tt
```

**O que verificar:**
- Violações de severidade `HIGH` aparecem com destaque visual
- Cada item do relatório inclui: tipo de violação, localização (arquivo:linha), taint path, severidade
- A saída é legível e estruturada

### 8.2 Modo sem cores (`--no-color`)

```bash
racket main.rkt scan test/samples/direct_taint.tt --no-color
```

**O que verificar:**
- Nenhum código de escape ANSI na saída (`\e[31m`, `\033[0m`, etc.)
- Conteúdo idêntico ao modo colorido, apenas sem formatação visual
- Adequado para captura em logs de CI

### 8.3 Verificar códigos de saída

```bash
# Com violação — deve retornar exit 1
./run.sh scan test/samples/direct_taint.tt
echo "Exit code: $?"
# Esperado: Exit code: 1

# Sem violação — deve retornar exit 0
./run.sh scan test/samples/sanitized.tt
echo "Exit code: $?"
# Esperado: Exit code: 0
```

### 8.4 Verificar saída sem violações

```bash
./run.sh scan test/samples/sanitized.tt
```

**O que verificar:**
- Nenhuma violação listada
- Mensagem de confirmação positiva ("análise concluída sem violações" ou equivalente)
- Exit code 0 confirmado

---

## 9. Testando a Integração CI/CD

Valide que o framework se comporta corretamente em um contexto de pipeline automatizado.

### 9.1 Simular pipeline localmente

```bash
#!/bin/bash
set -e  # Abortar em qualquer erro

echo "=== Trust-Transpiler Security Scan ==="
./run.sh scan test/samples/direct_taint.tt --no-color

if [ $? -eq 1 ]; then
  echo "❌ Violações encontradas — build bloqueado"
  exit 1
else
  echo "✓ Nenhuma violação — build liberado"
fi
```

Salve como `test/ci_simulation.sh`, dê permissão e execute:

```bash
chmod +x test/ci_simulation.sh
./test/ci_simulation.sh
```

**Resultado esperado:** script encerra com erro quando há violações, liberando quando não há.

### 9.2 Exemplo de configuração GitHub Actions

```yaml
# .github/workflows/security.yml
name: Security Scan

on: [push, pull_request]

jobs:
  trust-transpiler:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v3

      - name: Install Racket
        run: |
          sudo apt-get update
          sudo apt-get install -y racket

      - name: Run Trust-Transpiler
        run: |
          chmod +x run.sh
          ./run.sh scan src/main.tt --no-color
        # exit 1 bloqueia o PR automaticamente
```

---

## 10. Casos de Teste de Referência

Tabela consolidada com todos os cenários de teste, resultado esperado e o que valida.

| # | Arquivo de Teste | Cenário | Resultado Esperado | Componente |
|---|---|---|---|---|
| T01 | `minimal.tt` | Taint direto: source → sink | 1 violação HIGH | Parser + Engine |
| T02 | `chained_taint.tt` | Propagação em 4 variáveis | 1 violação HIGH com path completo | Engine |
| T03 | `sanitized.tt` | Sanitizador correto no path | 0 violações | Engine |
| T04 | `branch_taint.tt` | Branch com um lado tainted | 1 violação (conservador) | Engine |
| T05 | `clean_data.tt` | Dado estático, nunca tainted | 0 violações | Engine |
| T06 | `multi_source.tt` | Duas sources, dois sinks | 2 violações HIGH | Engine |
| T07 | `fake_sanitizer.tt` | Sanitizador não aprovado | 1 violação + alerta Gatekeeper | Gatekeeper |
| T08 | `approved_api.tt` | API aprovada na política | 0 violações | Gatekeeper |
| T09 | `cross/module_*.tt` | Taint atravessando 2 arquivos | 1 violação em module_b | Contexto persistente |
| T10 | `malformed.tt` | Sintaxe inválida | Erro de parse claro, sem crash | Parser |
| T11 | Qualquer arquivo com violação | Autofix gerado | Sugestão de patch no output | Autofix |
| T12 | Qualquer arquivo | Exit codes corretos | `exit 1` com violação, `exit 0` sem | CLI / Reporter |
| T13 | Qualquer arquivo | Modo `--no-color` | Sem códigos ANSI na saída | Reporter |

---

## 11. Interpretando Resultados

### 11.1 Lendo um relatório de violação

```
[HIGH] SQL Injection detectado
Arquivo : test/samples/direct_taint.tt
Linha   : 2
Taint   : user_id (source: linha 1) → db_execute (sink: linha 2)
Path    : user_id → db_execute
Score   : 0.91

Sugestão: aplicar sanitizador antes do sink
Autofix : db_execute_safe("...", user_id)
```

| Campo | Significado |
|---|---|
| `[HIGH]` | Severidade da violação |
| `Arquivo / Linha` | Onde o sink problemático está no código |
| `Taint` | Qual variável está contaminada e de onde veio |
| `Path` | Caminho completo da source até o sink |
| `Score` | Confiança do achado (0.0 a 1.0) |
| `Autofix` | Substituição sugerida pelo motor de correção |

### 11.2 Níveis de severidade

| Nível | Quando aparece | Ação recomendada |
|---|---|---|
| `HIGH` | Source direta de usuário alcança sink crítico | Corrigir antes de qualquer merge |
| `MEDIUM` | Path indireto ou sink de impacto moderado | Revisar e corrigir antes do deploy |
| `INFO` | Observação de fluxo, sem violação confirmada | Registrar e monitorar |

### 11.3 Quando "0 violações" pode ser um problema

Um resultado limpo é bom — mas pode mascarar falsos negativos se:

- O arquivo de entrada não contém sources reconhecidas pela política
- O contexto cross-file não carregou corretamente
- Um sanitizador não aprovado foi aceito erroneamente

**Como confirmar que a análise está ativa:** execute `T01` (taint direto). Se não detectar, o motor tem um problema.

---

## 12. Problemas Comuns e Soluções

### `racket: command not found`

Racket não está instalado ou não está no `PATH`.

```bash
# macOS (via Homebrew)
brew install minimal-racket

# Ubuntu/Debian
sudo apt-get install racket

# Verificar após instalação
racket --version
```

---

### `./run.sh: Permission denied`

```bash
chmod +x run.sh
```

---

### `cannot open module file` ou `module not found`

O Racket não consegue encontrar um dos arquivos do projeto. Verifique se está executando os comandos a partir da raiz do projeto:

```bash
# Correto
cd /caminho/para/trust-transpiler
./run.sh test

# Incorreto (path relativo quebrado)
cd /outro/lugar
./caminho/trust-transpiler/run.sh test
```

---

### Testes unitários passam mas o scan retorna resultado inesperado

Os testes unitários validam o motor isolado do parser. Se o motor está correto mas o scan falha, o problema está no parser ou na integração entre componentes.

**Diagnóstico:**

```bash
# 1. Confirme que os testes unitários passam
./run.sh test

# 2. Execute o demo (usa casos embutidos, sem parser de arquivo)
./run.sh demo

# 3. Se o demo funciona mas o scan falha, o problema está no parser
./run.sh scan test/samples/minimal.tt
```

---

### Saída com caracteres estranhos no CI

O terminal do CI não suporta ANSI. Use `--no-color`:

```bash
racket main.rkt scan arquivo.tt --no-color
```

---

### Contexto cross-file não detecta taint entre arquivos

O contexto persistente depende da ordem de análise. Sempre analise o arquivo com a source antes do arquivo com o sink:

```bash
# Ordem correta
./run.sh scan test/samples/cross/module_a.tt   # Define a source
./run.sh scan test/samples/cross/module_b.tt   # Usa o contexto

# Ordem errada (contexto não carregado)
./run.sh scan test/samples/cross/module_b.tt   # Contexto vazio
./run.sh scan test/samples/cross/module_a.tt
```

---
