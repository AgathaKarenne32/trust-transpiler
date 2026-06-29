#!/usr/bin/env python3
"""
server.py

Microserviço FastAPI — o "Oráculo de Segurança Local".

Expõe POST /api/v1/get-sanitizer, consumido pelo SAST em Racket
(ai_security_linter.rkt) no lugar da chamada direta à API do Gemini.

Pipeline por requisição:
    1. Validação Pydantic do corpo (schemas.py)
    2. Monta query de retrieval (prompts.build_retrieval_query)
    3. HybridRetriever: BM25 (top 20) → RAGatouille rerank (top 3)
    4. Monta prompt final com os chunks recuperados (prompts.build_sanitizer_prompt)
    5. Chama o LLM local via Ollama (llm_client.py)
    6. Valida a resposta do LLM contra regex de identificador seguro
    7. Retorna SanitizerResponse com os chunks-fonte para auditoria

Filosofia de erro: este serviço NUNCA inventa um fallback silencioso.
Se não há confiança suficiente, retorna HTTP 422/503 explícito — a
decisão de "o que fazer quando o oráculo falha" pertence ao cliente
(que já tem fallback heurístico local, do lado Racket).
"""
from __future__ import annotations

import logging
from contextlib import asynccontextmanager

from fastapi import FastAPI, HTTPException
from fastapi.responses import JSONResponse

from src.config import API_HOST, API_PORT, MIN_RERANK_SCORE, ensure_directories
from src.llm_client import LLMUnavailableError, OllamaClient
from src.prompts import build_retrieval_query, build_sanitizer_prompt
from src.retriever import HybridRetriever
from src.schemas import ErrorResponse, SanitizerRequest, SanitizerResponse, SourceChunk

logging.basicConfig(level=logging.INFO, format="%(asctime)s [%(levelname)s] %(message)s")
logger = logging.getLogger("security-oracle")

import sys
from pathlib import Path
sys.path.append(str(Path(__file__).resolve().parent.parent))

# Estado compartilhado da aplicação — carregado uma vez no startup,
# nunca recarregado por requisição (índices ColBERT são caros de carregar).
_app_state: dict = {}


@asynccontextmanager
async def lifespan(app: FastAPI):
    ensure_directories()
    logger.info("Carregando índices BM25 + ColBERT...")
    try:
        _app_state["retriever"] = HybridRetriever.load()
        logger.info("Índices carregados com sucesso.")
    except FileNotFoundError as e:
        # Não derruba o processo — permite que /health reporte o problema
        # claramente em vez do servidor simplesmente não subir.
        logger.error(f"Falha ao carregar índices: {e}")
        _app_state["retriever"] = None
        _app_state["retriever_error"] = str(e)

    _app_state["llm_client"] = OllamaClient()
    yield
    _app_state.clear()


app = FastAPI(
    title="Security Oracle",
    description="Oráculo de Segurança Local (Advanced RAG) para sugestão de sanitizadores.",
    version="1.0.0",
    lifespan=lifespan,
)


@app.get("/health")
def health_check():
    """Endpoint de saúde — o cliente Racket pode chamar isso antes de
    decidir se vale a pena tentar o oráculo ou ir direto pro fallback local."""
    retriever_ok = _app_state.get("retriever") is not None
    return {
        "status": "ok" if retriever_ok else "degraded",
        "retriever_loaded": retriever_ok,
        "detail": _app_state.get("retriever_error") if not retriever_ok else None,
    }


@app.post(
    "/api/v1/get-sanitizer",
    response_model=SanitizerResponse,
    responses={
        422: {"model": ErrorResponse, "description": "Nenhuma resposta confiável encontrada."},
        503: {"model": ErrorResponse, "description": "Índices ou LLM indisponíveis."},
    },
)
def get_sanitizer(request: SanitizerRequest):
    retriever: HybridRetriever | None = _app_state.get("retriever")
    if retriever is None:
        raise HTTPException(
            status_code=503,
            detail=_app_state.get("retriever_error", "Retriever não inicializado."),
        )

    llm_client: OllamaClient = _app_state["llm_client"]

    # ── Estágio 1+2: Retrieval híbrido ──────────────────────────────────
    retrieval_query = build_retrieval_query(request.sink, request.variable, request.language)
    retrieved = retriever.retrieve(retrieval_query)

    if not retrieved:
        logger.warning(
            f"Nenhum chunk recuperado para sink='{request.sink}' "
            f"(language='{request.language}')."
        )
        raise HTTPException(
            status_code=422,
            detail=(
                f"Nenhum trecho relevante encontrado na base de conhecimento "
                f"para o sink '{request.sink}'. A base pode não cobrir este "
                f"caso — considere usar o fallback heurístico local."
            ),
        )

    best_score = max(r["score"] for r in retrieved)
    if best_score < MIN_RERANK_SCORE:
        logger.warning(
            f"Melhor score de rerank ({best_score:.4f}) abaixo do threshold "
            f"({MIN_RERANK_SCORE}) para sink='{request.sink}'."
        )
        raise HTTPException(
            status_code=422,
            detail=(
                f"Confiança insuficiente nos trechos recuperados "
                f"(score={best_score:.4f} < threshold={MIN_RERANK_SCORE})."
            ),
        )

    # ── Estágio 3: Geração via LLM local ────────────────────────────────
    context_texts = [r["text"] for r in retrieved]
    prompt = build_sanitizer_prompt(
        sink=request.sink,
        variable=request.variable,
        language=request.language,
        context_chunks=context_texts,
    )

    try:
        raw_completion = llm_client.generate(prompt)
    except LLMUnavailableError as e:
        logger.error(f"LLM indisponível: {e}")
        raise HTTPException(status_code=503, detail=str(e)) from e

    sanitizer_name = raw_completion.strip()

    if sanitizer_name.upper() == "UNKNOWN" or not sanitizer_name:
        raise HTTPException(
            status_code=422,
            detail=(
                "O modelo não conseguiu identificar uma função de sanitização "
                "confiável a partir do contexto recuperado."
            ),
        )

    # ── Validação final anti-alucinação ─────────────────────────────────
    # Mesmo guard usado no lado Racket: rejeita qualquer coisa que não seja
    # um identificador "limpo" — protege contra o LLM "vazar" texto extra
    # apesar das instruções do prompt.
    try:
        validated_response = SanitizerResponse(
            sanitizer=sanitizer_name,
            confidence=min(best_score, 1.0) if best_score <= 1.0 else 1.0,
            source_chunks=[
                SourceChunk(text=r["text"], source_document=r["source_document"], score=r["score"])
                for r in retrieved
            ],
        )
    except ValueError as e:
        logger.warning(f"LLM retornou sugestão malformada: '{sanitizer_name}' — {e}")
        raise HTTPException(
            status_code=422,
            detail=(
                f"O modelo retornou uma sugestão malformada ('{sanitizer_name}'). "
                "Recomenda-se usar o fallback heurístico local."
            ),
        ) from e

    return validated_response


@app.exception_handler(HTTPException)
async def http_exception_handler(request, exc: HTTPException):
    """Padroniza o corpo de erro no formato ErrorResponse, para que o
    cliente Racket tenha um contrato único de erro independente do
    status code."""
    reason_map = {422: "no_confident_match", 503: "oracle_unavailable"}
    return JSONResponse(
        status_code=exc.status_code,
        content=ErrorResponse(
            detail=exc.detail,
            reason=reason_map.get(exc.status_code, "unknown_error"),
        ).model_dump(),
    )


if __name__ == "__main__":
    import uvicorn

    uvicorn.run("server:app", host=API_HOST, port=API_PORT, reload=False)