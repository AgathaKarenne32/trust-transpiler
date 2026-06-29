# Trust-Transpiler — Documentação

## 1. O que é o Trust-Transpiler

Uma plataforma de SAST (Static Application Security Testing) que combina:

- um motor de **taint analysis** agnóstico de linguagem (Racket), via uma
  representação intermediária própria (UIR);
- um **Gatekeeper** que trata chamadas a APIs desconhecidas como risco
  (proteção contra alucinação de LLM em código gerado por IA);
- **Autofix** interativo e **Trust Score** (nota 0–100 / A–F) por
  arquivo/PR;
- um **agente autônomo de revisão de PR** no GitHub Actions, que comenta
  violações e bloqueia merge com base no Trust Score;
- um sistema de **políticas de segurança em duas camadas** —
  padrões globais de mercado + regras específicas extraídas dos
  documentos internos de cada empresa — que alimenta o motor acima sem
  exigir nenhuma mudança nele.

---

## 2. Estado atual por componente

| Componente | Arquivo(s) | Estado |
|---|---|---|
| UIR + Parser | `src/uir.rkt`, `src/parser.rkt` | ✅ Funcional (linguagem `.tt`) |
| Taint Engine | `src/taint_engine.rkt`, `src/types.rkt` | ✅ Funcional, testado |
| Policy Engine | `policy.json`, `src/policy.rkt`, `src/policy-loader.rkt` | ✅ Funcional |
| Gatekeeper | `src/api_gatekeeper.rkt` | ✅ Funcional, testado em CI |
| FP Scorer | `src/fp_scorer.rkt` | ✅ Funcional |
| Autofix interativo | `src/autofix.rkt` | ✅ Funcional |
| AI Security Linter (fallback heurístico local) | `src/ai_security_linter.rkt` | ✅ Funcional |
| Trust Score + `--json-report` | `src/trust_score.rkt`, `main.rkt` | ✅ Funcional, testado (7/7) |
| PR Review Agent | `oracle/pr_review_agent.py` | ✅ Funcional, testado (6/6) |
| CI (sast-check + ai_pr_review) | `.github/workflows/` | ✅ Funcional |
| ~~Security Oracle (RAG: Docling+BM25+ColBERT)~~ | `oracle/server.py`, `src/retriever.py`, `oracle/scripts/ingest.py`, `data/`, `indexes/` | 🔴 **Descontinuado** — ver seção 3 |
| Extrator de regras por IA (Camada 2) | — | 🟡 Em desenho, escopo aberto — ver seção 4 |
| Baselines de padrões globais (Camada 1) | — | 🟡 Não iniciado — ver seção 5 |
| Suporte multi-linguagem (tree-sitter) | — | 🔴 Não iniciado, maior gap para virar produto |
| Dashboard / histórico de Trust Score | — | 🔴 Não iniciado |

---

## 4. Camada 2 — Extração de regras específicas da empresa (em definição)

O agente deve ler documentos da empresa (hoje confirmado: PDF; em aberto:
Markdown, Word, código-fonte interno) e extrair regras de segurança
específicas daquele negócio, que se somam às regras globais (seção 5).

Pipeline proposto (detalhado em `POLICY_EXTRACTOR_DESIGN.md`):

```
documento(s) da empresa
  → extração de texto
  → prompt estruturado ao LLM (extrai sources/sinks/sanitizers/forbidden_patterns)
  → validação por schema (anti-alucinação)
  → revisão humana (gera policy.suggested.json, não sobrescreve direto)
  → merge com baseline global
  → policy.json final → motor de taint analysis (sem alterações)
```

**Decisões ainda abertas** (listadas para acompanhar conforme você for
fechando o escopo):

1. Quais tipos de arquivo o agente vai aceitar além de PDF.
2. Extração roda só na configuração inicial, ou reage a mudanças no
   documento da empresa.
3. Regra de desempate quando a política da empresa conflita com um
   baseline global (ex: empresa é mais permissiva que PCI-DSS).
4. Nível de automação: só sugestão com aprovação humana, ou aplicação
   direta em algum cenário.

---

## 5. Camada 1 — Padrões globais de mercado (não iniciado)

Conjunto de baselines curados manualmente (não gerados por IA), que a
empresa escolhe ativar conforme seu setor/necessidade de compliance:

| Padrão | Foco |
|---|---|
| OWASP Top 10 | Vulnerabilidades web mais comuns |
| OWASP ASVS | Checklist verificável de requisitos de arquitetura de segurança (níveis L1/L2/L3) |
| OWASP API Security Top 10 | Riscos específicos de APIs |
| CWE/SANS Top 25 | Erros de software mais perigosos, com ID CWE rastreável |
| NIST CSF | Gestão de risco de cibersegurança (mais estratégico, bom para relatório executivo) |
| NIST SP 800-218 (SSDF) | Práticas de segurança no ciclo de desenvolvimento (shift-left) |
| ISO/IEC 27001 | SGSI — controles de acesso, criptografia, segurança física/lógica |
| ISO/IEC 27034 | Segurança de aplicações (extensão AppSec da família 27000) |
| PCI-DSS | Dados de cartão/transação financeira (perfil setorial: fintech) |
| HIPAA | Dados de saúde — PHI (perfil setorial: healthtech) |
| LGPD / GDPR | Dados pessoais (perfil transversal) |
| SOC 2 | Controles de segurança/disponibilidade para prestadores de serviço |
| CIS Controls | Lista priorizada de controles de cibersegurança, objetivos e testáveis |

Cada um viraria `policy-baseline-<padrao>.json`, no mesmo formato que
`policy-loader.rkt` já consome.

---

## 6. Como as camadas se conectam ao motor existente

```
Camada 1 (baselines globais, curados manualmente)
   policy-baseline-owasp.json / pci-dss / lgpd / ...
        \
Camada 2 (regras da empresa, extraídas por IA)
   policy-company-<empresa>.json
        /
        ▼
   merge (origem rastreável por regra: "owasp" | "pci-dss" | "company:<doc>")
        ▼
   policy.json final → src/policy-loader.rkt → motor (sem alterações)
```

Nenhuma das duas camadas exige tocar no taint engine, UIR, Gatekeeper,
Autofix, Trust Score ou PR Review Agent — todos já consomem `policy.json`.
O trabalho dos agentes é só produzir esse arquivo.

---

## 7. Roadmap (ordenado por impacto/bloqueio)

1. Fechar o escopo da Camada 2 (extração de regras da empresa).
2. Implementar `policy_extractor.py` + `policy-baseline-owasp.json` como
   primeiro baseline de referência da Camada 1.
3. Multi-linguagem via tree-sitter (Python/JS/Go/...), maior gap para
   virar produto de mercado — decisão de Node.js subprocess vs. FFI
   Racket ainda pendente.
4. Persistência/dashboard do Trust Score ao longo do tempo.
5. Demais baselines da Camada 1 (PCI-DSS, LGPD, ASVS, CWE Top 25) após o
   primeiro validar o formato.
6. Go-to-market: empacotar como GitHub App instalável.
