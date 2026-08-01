import requests
import json
import time
from .base import BaseLLMClient
from core import log
from typing import Dict, Any


class Router9Client(BaseLLMClient):
    """Client for 9Router — a self-hosted, OpenAI-compatible LLM router that fans out
    to many providers/models behind ONE endpoint (e.g. model="gc/gemini-2.5-pro" routes
    through to Gemini). `base_url` is configurable since it's self-hosted (host/port vary
    per install), unlike the other clients in this package which hit a fixed public URL.

    Unlike those other OpenAI-compatible clients, 9Router's /v1/chat/completions endpoint
    was observed to return a Server-Sent Events (SSE) stream even for a plain request with
    no `"stream"` key set — responses arrive as `data: {...}` chunks with `chat.completion.chunk`
    objects and per-token `delta.content` fragments, not a single JSON body. This client
    detects that via the `Content-Type` response header and parses accordingly, falling
    back to a normal single-JSON response if the router ever returns one instead.
    """

    def __init__(self, model: str, api_key: str, base_url: str, max_tokens: int = 4096):
        self.model = model
        self.api_key = api_key
        self.max_tokens = max_tokens
        self.url = base_url

    def analyze_code(self, code_snippet: str, context: Dict[str, Any]) -> str:
        prompt = self._construct_prompt(code_snippet, context)
        log.info(f"Sending analysis request to 9Router model: {self.model}...")

        headers = {
            "Authorization": f"Bearer {self.api_key}",
            "Content-Type": "application/json",
        }
        data = {
            "model": self.model,
            "max_tokens": self.max_tokens,
            "messages": [
                {
                    "role": "user",
                    "content": prompt
                }
            ]
        }

        max_retries = 3
        base_delay = 2  # seconds

        for attempt in range(max_retries):
            try:
                response = requests.post(
                    self.url, headers=headers, data=json.dumps(data),
                    timeout=120, stream=True,
                )

                if response.status_code == 429:
                    log.warning(f"Rate limit hit (429). Retrying... (Attempt {attempt + 1})")
                    time.sleep(base_delay * (2 ** attempt))
                    continue

                response.raise_for_status()

                content_type = response.headers.get("Content-Type", "")
                if "text/event-stream" in content_type:
                    content = self._parse_sse_stream(response)
                else:
                    result = response.json()
                    if "error" in result:
                        log.error(f"9Router API returned error: {result['error']}")
                        raise requests.exceptions.RequestException(f"9Router API Error: {result['error']}")
                    choices = result.get("choices") or []
                    content = choices[0]["message"]["content"] if choices else ""

                if content:
                    log.success("Received analysis from 9Router.")
                return content

            except requests.exceptions.RequestException as e:
                log.warning(f"Network error: {e}. Retrying...")
                time.sleep(base_delay * (2 ** attempt))

        log.error(f"9Router API failed after {max_retries} attempts.")
        return ""

    def _parse_sse_stream(self, response) -> str:
        """Accumulates `delta.content` fragments from an OpenAI-style SSE stream
        (`data: {...}` lines, terminated by `data: [DONE]`)."""
        chunks = []
        for raw_line in response.iter_lines(decode_unicode=True):
            if not raw_line or not raw_line.startswith("data:"):
                continue
            payload = raw_line[len("data:"):].strip()
            if payload == "[DONE]":
                break
            try:
                event = json.loads(payload)
            except json.JSONDecodeError:
                continue
            if "error" in event:
                log.error(f"9Router stream returned error: {event['error']}")
                continue
            choices = event.get("choices") or []
            if not choices:
                continue
            delta = choices[0].get("delta") or {}
            piece = delta.get("content")
            if piece:
                chunks.append(piece)
        return "".join(chunks)

    def _construct_prompt(self, code_snippet: str, context: Dict[str, Any]) -> str:
        system_prompt = context.get("system_prompt", "")
        vuln_prompt = context.get("vuln_prompt", "")

        formatted_prompt = vuln_prompt.format(
            code_snippet=code_snippet,
            file_path=context.get("file_path", "N/A")
        )

        return f"{system_prompt}\n\n{formatted_prompt}"
