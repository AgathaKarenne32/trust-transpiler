# src/config.py
from pathlib import Path

# Configurações do servidor
API_HOST = "0.0.0.0"
API_PORT = 8008

# Caminhos de dados
DATA_RAW_DIR = Path("data/raw")
DATA_PROCESSED_DIR = Path("data/processed")
BM25_INDEX_PATH = Path("indexes/bm25.pkl")
COLBERT_INDEX_ROOT = Path("indexes")
COLBERT_INDEX_NAME = "security_oracle_index"

# Configurações de precisão
MIN_RERANK_SCORE = 0.5
BM25_TOP_K = 20
COLBERT_RERANK_K = 5

# Regras de segurança para o validator Pydantic
SANITIZER_NAME_REGEX = r"^[a-zA-Z_][a-zA-Z0-9_]*$"

def ensure_directories():
    DATA_RAW_DIR.mkdir(parents=True, exist_ok=True)
    DATA_PROCESSED_DIR.mkdir(parents=True, exist_ok=True)