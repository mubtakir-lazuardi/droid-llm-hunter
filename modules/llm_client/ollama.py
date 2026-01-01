import requests
import json
from .base import BaseLLMClient
from core import log
from typing import Dict, Any

class OllamaClient(BaseLLMClient):
    def __init__(self, model: str, url: str):
        self.model = model
        self.url = f"{url}/api/generate"

    def analyze_code(self, code_snippet: str, context: Dict[str, Any]) -> str:
        prompt = self._construct_prompt(code_snippet, context)
        log.info(f"Sending analysis request to Ollama model: {self.model}...")
        try:
            response = requests.post(
                self.url,
                json={"model": self.model, "prompt": prompt, "stream": False},
                timeout=600, # 10 minutes timeout
            )
            response.raise_for_status()
            result = response.json()["response"]
            log.success("Received analysis from Ollama.")
            return result
        except requests.exceptions.RequestException as e:
            log.error(f"Error connecting to Ollama at {self.url}: {e}")
            raise

    def _construct_prompt(self, code_snippet: str, context: Dict[str, Any]) -> str:
        # This is a basic prompt construction.
        # In a real-world scenario, you would load the system prompt
        # and the specific vulnerability prompt from the config files.
        system_prompt = context.get("system_prompt", "")
        vuln_prompt = context.get("vuln_prompt", "")

        formatted_prompt = vuln_prompt.format(
            code_snippet=code_snippet,
            file_path=context.get("file_path", "N/A")
        )

        return f"{system_prompt}\n\n{formatted_prompt}"
