"""
src/schemas.py

Modelos Pydantic para validação de entrada/saída da API.
Validar estritamente a entrada é a primeira linha de defesa: o SAST em
Racket é um cliente confiável, mas o endpoint deve assumir que qualquer
JSON pode chegar — inclusive malformado ou adversarial.
"""
import re
from typing import Optional

from pydantic import BaseModel, Field, field_validator

from src.config import SANITIZER_NAME_REGEX

# Sinks conhecidos — mantido como lista aberta (não enum estrito) porque
# o policy.json do lado Racket é extensível pelo usuário. Mas exigimos que
# seja um identificador "limpo", nunca texto livre arbitrário.
_IDENTIFIER_RE = re.compile(r"^[a-zA-Z_][a-zA-Z0-9_\-]*$")


class SanitizerRequest(BaseModel):
    """Corpo esperado em POST /api/v1/get-sanitizer."""

    sink: str = Field(
        ...,
        min_length=1,
        max_length=64,
        description="Nome da função sink vulnerável, ex: 'log', 'query', 'exec'.",
    )
    variable: str = Field(
        ...,
        min_length=1,
        max_length=128,
        description="Nome da variável tainted que flui até o sink.",
    )
    language: Optional[str] = Field(
        default="generic",
        max_length=32,
        description="Linguagem/contexto alvo (ex: 'sql', 'shell', 'html'). Opcional.",
    )

    @field_validator("sink", "variable")
    @classmethod
    def must_be_identifier_like(cls, v: str) -> str:
        if not _IDENTIFIER_RE.match(v):
            raise ValueError(
                f"valor '{v}' não parece um identificador válido "
                "(esperado: letras, números, '_' ou '-')"
            )
        return v


class SourceChunk(BaseModel):
    """Um trecho de conhecimento usado para fundamentar a resposta — para auditoria."""

    text: str
    source_document: str
    score: float


class SanitizerResponse(BaseModel):
    """Resposta de sucesso de POST /api/v1/get-sanitizer."""

    sanitizer: str = Field(..., description="Nome da função sanitizadora recomendada.")
    confidence: float = Field(..., ge=0.0, le=1.0)
    source_chunks: list[SourceChunk] = Field(
        default_factory=list,
        description="Trechos da base de conhecimento que fundamentaram a resposta.",
    )

    @field_validator("sanitizer")
    @classmethod
    def sanitizer_must_be_safe_identifier(cls, v: str) -> str:
        if not re.match(SANITIZER_NAME_REGEX, v):
            raise ValueError(
                f"sanitizer sugerido '{v}' não é um identificador seguro — "
                "rejeitado para evitar injeção de código malformado no patch"
            )
        return v


class ErrorResponse(BaseModel):
    """Formato padronizado de erro — o cliente Racket pode usar isso para decidir fallback."""

    detail: str
    reason: str  # ex: "no_confident_match", "llm_unavailable", "malformed_llm_output"