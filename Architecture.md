# Security Oracle — Arquitetura

## Estrutura de Diretórios

```
security-oracle/
├── data/
│   ├── raw/                    # PDFs/Markdown originais (OWASP Cheat Sheets,
│   │                           # docs de linguagem, guias de sanitização)
│   └── processed/               # Saída do Docling: chunks em JSON/JSONL,
│                                 # um arquivo por documento fonte, versionado
│                                 # separadamente do índice (permite re-indexar
│                                 # sem re-processar PDFs)
│
├── indexes/
│   ├── bm25/                    # Índice lexical (rank_bm25), serializado via
│   │                            # pickle — pequeno, rápido de carregar
│   └── colbert/                 # Índice RAGatouille (.ragatouille/colbert/
│                                 # indexes/<nome>/), gerado por ingest.py
│
├── src/
│   ├── __init__.py
│   ├── config.py                # Paths, hosts, nomes de modelo — single source
│   │                            # of truth, nada hardcoded nos outros módulos
│   ├── chunking.py               # Lógica de chunking semântico pós-Docling
│   ├── retriever.py              # Classe HybridRetriever: BM25 → ColBERT rerank
│   ├── llm_client.py             # Cliente Ollama isolado (fácil trocar por vLLM)
│   ├── prompts.py                # Templates de prompt centralizados
│   └── schemas.py                # Modelos Pydantic (request/response da API)
│
├── scripts/
│   └── ingest.py                 # CLI: lê data/raw/ → Docling → chunks →
│                                  # constrói índices BM25 + ColBERT
│
├── tests/
│   └── test_retriever_smoke.py  # Smoke test do pipeline de retrieval
│
├── server.py                     # Entry point FastAPI
├── requirements.txt
└── .env.example                  # OLLAMA_HOST, MODEL_NAME, etc.
```

## Fluxo de Dados (Ingestão — offline, roda uma vez por base de conhecimento)

```
data/raw/*.pdf, *.md
        │
        ▼
   Docling (DocumentConverter)
        │   → estrutura rica: títulos, tabelas, código, hierarquia
        ▼
   chunking.py (HybridChunker do Docling, com fallback próprio)
        │   → lista de chunks com metadata (fonte, página, seção)
        ▼
   data/processed/<doc>.jsonl
        │
        ├──────────────────────┐
        ▼                      ▼
   BM25Okapi (rank_bm25)   RAGatouille (ColBERT indexer)
        │                      │
        ▼                      ▼
   indexes/bm25/bm25.pkl   indexes/colbert/<index_name>/
```

## Fluxo de Dados (Serving — por requisição, em tempo real)

```
SAST (Racket) ──HTTP POST──▶ /api/v1/get-sanitizer
                              {"sink": "log", "variable": "raw_data"}
                                      │
                                      ▼
                          1. Monta query textual
                             ("sanitização para sink log shell command")
                                      │
                                      ▼
                          2. BM25.get_top_n(query, k=20)
                             → filtra ruído, candidatos lexicais
                                      │
                                      ▼
                          3. RAGatouille rerank(query, candidatos, k=3)
                             → Late Interaction, precisão semântica
                                      │
                                      ▼
                          4. Monta prompt com os 3 chunks top + pergunta
                                      │
                                      ▼
                          5. Ollama (Llama-3-8B / Mistral)
                             → responde APENAS o nome da função
                                      │
                                      ▼
                          6. Validação regex (anti-alucinação)
                             → se inválido: HTTP 422, sem fallback silencioso
                                      │
                                      ▼
                          {"sanitizer": "escape_shell_arg", "confidence": ..., "source_chunks": [...]}
```

## Decisões de Design Relevantes para AppSec

1. **Sem fallback silencioso no servidor.** Diferente do `ai_security_linter.rkt` do lado Racket (que tem fallback heurístico local), este oráculo **falha explicitamente** (HTTP 422/503) quando não tem confiança suficiente. A responsabilidade de "o que fazer quando o oráculo falha" fica do lado do cliente Racket, que já tem essa lógica de fallback. Duplicar fallback nos dois lados esconde silenciosamente erros de configuração.

2. **`source_chunks` sempre retornado.** Para auditoria de segurança, toda resposta inclui de onde veio a recomendação — isto é essencial em AppSec: você precisa poder provar por que uma função foi escolhida.

3. **Separação ingestão/serving.** A ingestão é cara (Docling + indexação ColBERT) e roda offline. O serving é o único caminho "hot" e não toca em PDFs nem em Docling.