# src/prompts.py
def build_retrieval_query(sink: str, variable: str, language: str) -> str:
    return f"sanitizer function for {sink} sink with variable {variable} in {language}"

def build_sanitizer_prompt(sink: str, variable: str, language: str, context_chunks: list[str]) -> str:
    context = "\n".join(context_chunks)
    return f"""
    Contexto de Segurança:
    {context}
    
    Tarefa: Dado o contexto acima, qual a função de sanitização ideal para o sink '{sink}' 
    recebendo a variável '{variable}' em {language}? 
    
    Responda APENAS com o nome da função. Sem explicações.
    """