from .base import BaseLLMClient
from core import log
from typing import Dict, Any
import requests
import json

class GeminiClient(BaseLLMClient):
    def __init__(self, model: str, api_key: str):
        self.model = model
        self.api_key = api_key
        self.url = f"https://generativelanguage.googleapis.com/v1beta/models/{self.model}:generateContent"

    def analyze_code(self, code_snippet: str, context: Dict[str, Any]) -> str:
        prompt = self._construct_prompt(code_snippet, context)
        log.info(f"Sending analysis request to Gemini model: {self.model}...")
        
        headers = {
            'Content-Type': 'application/json',
            'X-goog-api-key': self.api_key
        }
        
        data = {
            "contents": [
                {
                    "parts": [
                        {
                            "text": prompt
                        }
                    ]
                }
            ]
        }

        try:
            response = requests.post(self.url, headers=headers, data=json.dumps(data), timeout=600)
            response.raise_for_status()
            result = response.json()
            log.success("Received analysis from Gemini.")
            return result['candidates'][0]['content']['parts'][0]['text']
        except requests.exceptions.RequestException as e:
            log.error(f"An error occurred while communicating with the Gemini API: {e}")
            raise

    def _construct_prompt(self, code_snippet: str, context: Dict[str, Any]) -> str:
        system_prompt = context.get("system_prompt", "")
        vuln_prompt = context.get("vuln_prompt", "")

        formatted_prompt = vuln_prompt.format(
            code_snippet=code_snippet,
            file_path=context.get("file_path", "N/A")
        )

        return f"{system_prompt}\n\n{formatted_prompt}"
