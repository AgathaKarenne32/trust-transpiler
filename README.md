O **Trust-Transpiler** é um framework de análise estática de código (SAST) desenvolvido como parte de um projeto de pesquisa acadêmica. O objetivo principal é automatizar a detecção de vulnerabilidades de segurança, especificamente rastreando o fluxo de dados "sujos" (tainted) desde fontes de entrada (sources) até operações sensíveis (sinks) sem a devida sanitização.

## 🚀 Arquitetura do Pipeline

O pipeline foi projetado de forma modular, seguindo o fluxo clássico de um analisador de código:

1.  **Parser (`src/parser.rkt`)**: Converte código-fonte bruto em uma Representação Intermediária Unificada (UIR).
2.  **Motor de Análise (`src/taint_engine.rkt`)**: O cérebro do projeto. Implementa o rastreamento de taint (data flow analysis), propagando estados de segurança através de atribuições e detectando violações.
3.  **Reporter (`src/reporter.rkt`)**: Responsável por formatar os resultados da análise, gerando relatórios detalhados com severidade, localização e caminho do taint.
4.  **Interface CLI (`main.rkt`)**: Ponto de entrada para execução de análises em arquivos ou modo de demonstração.



## 🛠 Funcionalidades Implementadas

* **Detecção de Taint**: Rastreamento automático de variáveis contaminadas provenientes de `sources`.
* **Suporte a Sanitização**: Identificação de funções `sanitizers` que limpam o estado das variáveis.
* **Análise de Fluxo de Controle**: Suporte básico para branches (`if/else`) com análise conservadora.
* **Relatórios de Segurança**: Identificação de violações com níveis de severidade (HIGH/MEDIUM/INFO).
* **Automação e CI/CD**: Integração pronta para pipelines de CI/CD com suporte a modos sem cores (`--no-color`) e códigos de saída adequados (`exit 0` para sucesso, `exit 1` para violações).
* **Suíte de Testes**: Cobertura de testes unitários automatizados para garantir a integridade do motor de análise.

## ⚙️ Como utilizar

### Pré-requisitos
* [Racket](https://racket-lang.org/) instalado.

### Comandos principais (via `Run.sh`)

O projeto utiliza um script facilitador para execução:

* **Executar demonstração**: `./run.sh demo`
* **Analisar um arquivo**: `./run.sh scan <arquivo.tt>`
* **Executar testes unitários**: `./run.sh test`
* **Ajuda**: `./run.sh help`

## 🧪 Desenvolvimento e Testes

A suíte de testes unitários (`test/taint_test.rkt`) utiliza o framework `rackunit` para validar a lógica de propagação e detecção de taint de forma isolada do parser.

Para rodar os testes manualmente:
```bash
racket test/taint_test.rkt