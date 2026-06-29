from __future__ import annotations
import pickle
import faiss
import numpy as np
from pathlib import Path
from sentence_transformers import SentenceTransformer
from rank_bm25 import BM25Okapi
from src.chunking import KnowledgeChunk
from src.config import BM25_INDEX_PATH

import re
_PUNCTUATION_RE = re.compile(r"[^\w]+", re.UNICODE)

dimension = 384 # Dimensão do modelo MiniLM
index = faiss.IndexFlatL2(dimension)
embeddings = encoder.encode([c.text for c in chunks]).astype('float32')
index.add(embeddings)
faiss.write_index(index, "indexes/bm25.faiss")

def _tokenize(text: str) -> list[str]:
    no_punct = _PUNCTUATION_RE.sub(" ", text.lower())
    return [tok for tok in no_punct.split() if tok]

class HybridRetriever:
    """
    Retriever Híbrido: BM25 (Estágio 1 - Lexical) + FAISS/BGE (Estágio 2 - Semântico).
    """

    def __init__(self, bm25_index: BM25Okapi, faiss_index: faiss.Index, chunks: list[KnowledgeChunk], encoder: SentenceTransformer):
        self._bm25 = bm25_index
        self._faiss = faiss_index
        self._chunks = chunks
        self._encoder = encoder

    @classmethod
    def load(cls, bm25_path: Path = BM25_INDEX_PATH) -> HybridRetriever:
        if not bm25_path.exists():
            raise FileNotFoundError(f"Índice não encontrado em {bm25_path}.")
            
        with open(bm25_path, "rb") as f:
            payload = pickle.load(f)
        
        # Carrega o modelo leve para busca semântica
        encoder = SentenceTransformer('all-MiniLM-L6-v2')
        
        # Carrega o índice FAISS (você deve salvar/carregar este arquivo no ingest.py)
        faiss_path = bm25_path.with_suffix(".faiss")
        index = faiss.read_index(str(faiss_path))
        
        return cls(payload["bm25"], index, [KnowledgeChunk.from_dict(d) for d in payload["chunks"]], encoder)

    def retrieve(self, query: str, k: int = 5) -> list[dict]:
        if not self._chunks:
            return []

        # 1. Busca Lexical (BM25)
        tokenized_query = _tokenize(query)
        bm25_scores = self._bm25.get_scores(tokenized_query)
        
        # 2. Busca Semântica (FAISS)
        query_embedding = self._encoder.encode([query]).astype('float32')
        distances, faiss_indices = self._faiss.search(query_embedding, k * 2) # Pega mais para re-rank

        # Combinação simples ou ranking: aqui retornamos os resultados semânticos
        results = []
        for i, idx in enumerate(faiss_indices[0]):
            chunk = self._chunks[idx]
            results.append({
                "chunk_id": chunk.chunk_id,
                "text": chunk.text,
                "source_document": chunk.source_document,
                "score": float(1 / (1 + distances[0][i])) # Normalização simples de distância
            })
        return sorted(results, key=lambda x: x["score"], reverse=True)[:k]