from fastapi import FastAPI, HTTPException
from pydantic import BaseModel

app = FastAPI(title="Trust-Transpiler Security Oracle")

# Modelo de dados que o Racket vai enviar
class LinterRequest(BaseModel):
    sink_func: str
    var_name: str

# Endpoint que o ai_security_linter.rkt vai consumir
@app.post("/api/v1/get-sanitizer")
async def get_sanitizer(req: LinterRequest):
    print(f"[ORÁCULO] Analisando fluxo de '{req.var_name}' para o sink '{req.sink_func}'...")
    
    # ==========================================
    # FUTURO: Aqui entrará o pipeline RAG:
    # 1. Busca no BM25/ColBERT
    # 2. Envio de prompt para LLM Local (Ollama)
    # ==========================================
    
    # Lógica baseada em regras (enquanto treinamos o RAG)
    sink = req.sink_func.lower()
    if sink == "log":
        suggestion = "escape_shell_arg"
    elif sink == "query":
        suggestion = "escape_sql"
    elif sink in ["display", "println", "write"]:
        suggestion = "escape_html"
    else:
        suggestion = "sanitize_generic"
        
    print(f"[ORÁCULO] Sugestão gerada: {suggestion}")
    
    # Retornamos um JSON simples e limpo, sem a complexidade da Google!
    return {"sanitizer": suggestion}

# Para rodar: uvicorn server:app --reload --port 8000