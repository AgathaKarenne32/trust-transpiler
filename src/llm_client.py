# src/llm_client.py
import requests

class LLMUnavailableError(Exception):
    pass

class OllamaClient:
    def __init__(self, model="llama3:8b"):
        self.model = model
        self.url = "http://localhost:11434/api/generate"

    def generate(self, prompt: str) -> str:
        try:
            response = requests.post(
                self.url,
                json={"model": self.model, "prompt": prompt, "stream": False},
                timeout=30
            )
            response.raise_for_status()
            return response.json().get("response", "")
        except Exception as e:
            raise LLMUnavailableError(f"Erro ao conectar no Ollama: {e}")