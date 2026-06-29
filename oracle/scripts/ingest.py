#!/usr/bin/env python3
"""
scripts/ingest.py

CLI de ingestão offline. Roda UMA VEZ (ou sempre que a base de
conhecimento de segurança mudar) para:

  1. Ler todos os documentos em data/raw/ (PDF, MD, DOCX, HTML) 
  2. Converter cada um via Docling, preservando estrutura
  3. Fatiar em chunks semânticos (chunking.py)
  4. Persistir os chunks brutos em data/processed/ (auditável, versionável)
  5. Construir o índice BM25 (rank_bm25) e salvar em indexes/bm25/
  6. Construir o índice ColBERT (RAGatouille) e salvar em indexes/colbert/

Uso:
    python scripts/ingest.py
    python scripts/ingest.py --raw-dir data/raw --force-rebuild
"""
from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path

# Permite rodar `python scripts/ingest.py` a partir da raiz do projeto
sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from src.chunking import KnowledgeChunk, chunk_document, iter_raw_documents
from src.config import (
    BM25_INDEX_PATH,
    COLBERT_INDEX_NAME,
    COLBERT_INDEX_ROOT,
    DATA_PROCESSED_DIR,
    DATA_RAW_DIR,
    ensure_directories,
)
from src.retriever import HybridRetriever


def process_all_documents(raw_dir: Path, processed_dir: Path) -> list[KnowledgeChunk]:
    """Converte e fatia todos os documentos em raw_dir, persistindo o
    resultado intermediário em processed_dir (um .jsonl por documento)."""
    all_chunks: list[KnowledgeChunk] = []

    documents = list(iter_raw_documents(raw_dir))
    if not documents:
        print(f"[ingest] AVISO: nenhum documento encontrado em {raw_dir}. "
              f"Coloque PDFs/MD da OWASP, docs de linguagem etc. lá e rode novamente.")
        return all_chunks

    for doc_path in documents:
        print(f"[ingest] Processando {doc_path.name} via Docling...")
        try:
            chunks = chunk_document(doc_path)
        except Exception as e:
            print(f"[ingest] ERRO ao processar {doc_path.name}: {e}", file=sys.stderr)
            continue

        print(f"[ingest]   → {len(chunks)} chunks gerados.")
        all_chunks.extend(chunks)

        # Persiste em JSONL para auditoria/debug — independente do índice
        out_path = processed_dir / f"{doc_path.stem}.jsonl"
        with open(out_path, "w", encoding="utf-8") as f:
            for chunk in chunks:
                f.write(json.dumps(chunk.to_dict(), ensure_ascii=False) + "\n")

    return all_chunks


def build_bm25_index(chunks: list[KnowledgeChunk]) -> None:
    print(f"[ingest] Construindo índice BM25 sobre {len(chunks)} chunks...")
    bm25_index = HybridRetriever.build_bm25(chunks)
    HybridRetriever.save_bm25(bm25_index, chunks, BM25_INDEX_PATH)
    print(f"[ingest] Índice BM25 salvo em {BM25_INDEX_PATH}")


def build_colbert_index(chunks: list[KnowledgeChunk], index_name: str, index_root: Path) -> None:
    try:
        from ragatouille import RAGPretrainedModel
    except ImportError as e:
        raise ImportError("RAGatouille não está instalado. Rode: pip install ragatouille") from e

    print(f"[ingest] Construindo índice ColBERT (RAGatouille) sobre {len(chunks)} chunks...")
    print("[ingest] Isso pode levar alguns minutos na primeira execução "
          "(download do checkpoint ColBERTv2)...")

    # colbert-ir/colbertv2.0 é o checkpoint pré-treinado padrão do RAGatouille
    rag_model = RAGPretrainedModel.from_pretrained("colbert-ir/colbertv2.0")

    documents = [c.text for c in chunks]
    document_ids = [c.chunk_id for c in chunks]
    document_metadatas = [
        {"source_document": c.source_document, "section_path": c.section_path}
        for c in chunks
    ]

    rag_model.index(
        collection=documents,
        document_ids=document_ids,
        document_metadatas=document_metadatas,
        index_name=index_name,
        index_root=str(index_root),
        max_document_length=256,
        split_documents=False,  # já fizemos chunking semântico via Docling
    )

    print(f"[ingest] Índice ColBERT salvo em {index_root / 'colbert' / 'indexes' / index_name}")


def main() -> None:
    parser = argparse.ArgumentParser(description="Ingestão da base de conhecimento do Security Oracle.")
    parser.add_argument("--raw-dir", type=Path, default=DATA_RAW_DIR)
    parser.add_argument("--processed-dir", type=Path, default=DATA_PROCESSED_DIR)
    parser.add_argument("--index-name", type=str, default=COLBERT_INDEX_NAME)
    parser.add_argument("--index-root", type=Path, default=COLBERT_INDEX_ROOT)
    parser.add_argument(
        "--skip-colbert",
        action="store_true",
        help="Constrói apenas o índice BM25 — útil para testes rápidos sem GPU.",
    )
    args = parser.parse_args()

    ensure_directories()

    chunks = process_all_documents(args.raw_dir, args.processed_dir)
    if not chunks:
        print("[ingest] Nenhum chunk gerado. Abortando construção de índices.", file=sys.stderr)
        sys.exit(1)

    build_bm25_index(chunks)

    if args.skip_colbert:
        print("[ingest] --skip-colbert ativo: índice ColBERT NÃO foi construído. "
              "O servidor não vai funcionar até você rodar a ingestão completa.")
    else:
        build_colbert_index(chunks, args.index_name, args.index_root)

    print("[ingest] Ingestão concluída com sucesso.")


if __name__ == "__main__":
    main()