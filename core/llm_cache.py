import os
import hashlib
from typing import Dict, Any
from core import log


class CachedLLMClient:
    """
    [#4] Content-addressed cache wrapper around any LLM client.

    The cache key is a SHA-256 of (model + system_prompt + vuln_prompt + code_snippet),
    so it is naturally correct: change the model, the rule prompt, or the analyzed code
    and the key changes -> the call re-runs. Identical inputs hit the cache.

    This gives two things at once:
      - Resume: a scan that crashed or hit a rate limit re-uses every completed call
        on the next run instead of paying for it again.
      - Dedup: the same file summarized/analyzed twice costs one call.

    Only NON-EMPTY responses are cached. A failed call (empty string after retries, per
    the clients' soft-fail) is never stored, so a later resume retries it rather than
    permanently caching a failure as if it were a real answer.

    Unknown attribute access is delegated to the wrapped client, so this behaves like a
    drop-in replacement for the real client everywhere in the engine.
    """

    def __init__(self, client, cache_dir: str, model: str, enabled: bool = True):
        # Set via __dict__ to avoid triggering __getattr__ during init.
        self.__dict__["_client"] = client
        self.__dict__["enabled"] = enabled
        self.__dict__["model"] = model or ""
        self.__dict__["cache_dir"] = cache_dir
        self.__dict__["hits"] = 0
        self.__dict__["misses"] = 0
        if enabled:
            try:
                os.makedirs(cache_dir, exist_ok=True)
            except Exception as e:
                log.warning(f"Could not create cache dir '{cache_dir}': {e}. Caching disabled.")
                self.__dict__["enabled"] = False

    def _key(self, code_snippet: str, context: Dict[str, Any]) -> str:
        h = hashlib.sha256()
        for part in (
            self.model,
            context.get("system_prompt", "") or "",
            context.get("vuln_prompt", "") or "",
            code_snippet or "",
        ):
            h.update(part.encode("utf-8", errors="replace"))
            h.update(b"\x00")
        return h.hexdigest()

    def _path(self, key: str) -> str:
        return os.path.join(self.cache_dir, f"{key}.txt")

    def analyze_code(self, code_snippet: str, context: Dict[str, Any]) -> str:
        if not self.enabled:
            return self._client.analyze_code(code_snippet, context)

        key = self._key(code_snippet, context)
        path = self._path(key)

        if os.path.exists(path):
            try:
                with open(path, "r", encoding="utf-8") as f:
                    cached = f.read()
                self.__dict__["hits"] += 1
                log.debug(f"Cache HIT ({key[:12]}) for {context.get('file_path', 'N/A')}")
                return cached
            except Exception as e:
                log.debug(f"Cache read failed for {key[:12]}: {e}")

        result = self._client.analyze_code(code_snippet, context)
        self.__dict__["misses"] += 1

        # Only persist successful responses so failures are retried on resume.
        if result and result.strip():
            try:
                with open(path, "w", encoding="utf-8") as f:
                    f.write(result)
            except Exception as e:
                log.debug(f"Cache write failed for {key[:12]}: {e}")

        return result

    def cache_stats(self) -> dict:
        return {"hits": self.hits, "misses": self.misses, "enabled": self.enabled}

    def __getattr__(self, name):
        # Only reached for attributes not found on this wrapper -> delegate to real client.
        return getattr(self.__dict__["_client"], name)
