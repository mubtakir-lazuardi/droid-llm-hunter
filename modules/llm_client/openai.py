import requests
import json
from .base import BaseLLMClient
from core import log
from typing import Dict, Any

class OpenAIClient(BaseLLMClient):
    def __init__(self, model: str, api_key: str):
        self.model = model
        self.api_key = api_key
        self.url = "https://api.openai.com/v1/chat/completions"

    def analyze_code(self, code_snippet: str, context: Dict[str, Any]) -> str:
        prompt = self._construct_prompt(code_snippet, context)
        log.info(f"Sending analysis request to OpenAI model: {self.model}...")

        headers = {
            "Authorization": f"Bearer {self.api_key}",
            "Content-Type": "application/json"
        }
        
        data = {
            "model": self.model,
            "messages": [
                {
                    "role": "user",
                    "content": prompt
                }
            ]
        }

        try:
            response = requests.post(self.url, headers=headers, data=json.dumps(data), timeout=600)
            response.raise_for_status()
            result = response.json()
            log.success("Received analysis from OpenAI.")
            return result['choices'][0]['message']['content']
        except requests.exceptions.RequestException as e:
            log.error(f"An error occurred while communicating with the OpenAI API: {e}")
            raise

    def _construct_prompt(self, code_snippet: str, context: Dict[str, Any]) -> str:
        system_prompt = context.get("system_prompt", "")
        vuln_prompt = context.get("vuln_prompt", "")

        formatted_prompt = vuln_prompt.format(
            code_snippet=code_snippet,
            file_path=context.get("file_path", "N/A")
        )

        return f"{system_prompt}\\n\\n{formatted_prompt}"
