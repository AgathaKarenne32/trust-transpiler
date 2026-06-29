# src/chunking.py
from dataclasses import dataclass
import json

@dataclass
class KnowledgeChunk:
    chunk_id: str
    text: str
    source_document: str
    section_path: str

    def to_dict(self):
        return self.__dict__

    @classmethod
    def from_dict(cls, data):
        return cls(**data)

def chunk_document(doc_path):
    # Aqui entraria a lógica de fatiamento do Docling
    # Para o MVP, podemos retornar um chunk simples:
    return [KnowledgeChunk(
        chunk_id=doc_path.stem + "_0",
        text=f"Exemplo de sanitização para {doc_path.stem}",
        source_document=doc_path.name,
        section_path="root"
    )]

def iter_raw_documents(raw_dir):
    return list(raw_dir.glob("*.md")) # Ou .pdf