import os
import shutil
import subprocess
import tempfile
import time
from .base import BaseLLMClient
from core import log
from typing import Dict, Any


class CodexClient(BaseLLMClient):
    """Client for OpenAI Codex CLI — the only provider in this package that is NOT an
    HTTP API. Codex is a locally installed agent binary, so instead of POSTing to an
    endpoint this client shells out to `codex exec` (its non-interactive mode) and reads
    the agent's final message back.

    Auth is whatever the local `codex` install already uses (ChatGPT login or API key);
    this client never handles credentials itself, which is why there is no `api_key`
    field for it in settings.yaml — run `codex login` once and it works.

    Invocation details that matter:
      * The prompt is piped on **stdin** (with a trailing `-` argument) rather than passed
        as an argv string, so large decompiled-code prompts can't blow the ARG_MAX limit.
      * `--output-last-message FILE` is what makes the output usable. `codex exec` prints
        a banner, session id, the echoed prompt, and a token-usage footer to stdout, so
        scraping stdout would feed all that junk into the JSON parser. The flag writes
        ONLY the agent's final message to a file, which is what gets returned here.
      * `--sandbox read-only` keeps the agent from writing anything: it is being asked to
        analyze a code snippet that is already fully inlined in the prompt, so it has no
        business modifying the machine it runs on.
      * Each call runs in a fresh empty temp directory (`--cd`). Codex is an *agent* and
        will happily explore its working directory; pointing it at an empty one keeps the
        analysis deterministic (it reasons about the prompt, not about whatever repo the
        scan happens to be launched from) and avoids pulling unrelated local files into
        the model context.
      * `--ephemeral` skips writing session files, since a scan makes many short calls.

    `max_tokens` is accepted for interface parity with the HTTP clients but is NOT
    enforced: the Codex CLI manages its own output budget and exposes no per-call output
    limit flag. Truncation controls that matter for the other providers are a no-op here.
    """

    def __init__(self, model: str = None, cli_path: str = "codex", max_tokens: int = 4096,
                 timeout: int = 600, sandbox: str = "read-only", reasoning_effort: str = None):
        self.model = model                      # None -> whatever ~/.codex/config.toml sets
        self.cli_path = cli_path or "codex"
        self.max_tokens = max_tokens            # accepted, not enforced (see docstring)
        self.timeout = timeout
        self.sandbox = sandbox
        self.reasoning_effort = reasoning_effort

    def analyze_code(self, code_snippet: str, context: Dict[str, Any]) -> str:
        prompt = self._construct_prompt(code_snippet, context)
        label = self.model or "default (from ~/.codex/config.toml)"
        log.info(f"Sending analysis request to Codex CLI model: {label}...")

        if not shutil.which(self.cli_path):
            log.error(
                f"Codex CLI not found (looked for '{self.cli_path}'). Install it and ensure "
                "it is on PATH, or set llm.codex_cli_path in settings.yaml."
            )
            return ""

        max_retries = 3
        base_delay = 2  # seconds

        for attempt in range(max_retries):
            try:
                content = self._run_codex(prompt)
            except subprocess.TimeoutExpired:
                log.warning(
                    f"Codex CLI timed out after {self.timeout}s "
                    f"(attempt {attempt + 1}/{max_retries})."
                )
                content = None
            except OSError as e:
                log.warning(f"Failed to launch Codex CLI: {e}. Retrying...")
                content = None

            if content:
                log.success("Received analysis from Codex CLI.")
                return content

            if attempt < max_retries - 1:
                time.sleep(base_delay * (2 ** attempt))

        log.error(f"Codex CLI failed after {max_retries} attempts.")
        return ""

    def cache_fingerprint(self) -> str:
        """Settings that change the answer but never appear in the prompt, so the response
        cache can key on them (see CachedLLMClient). `reasoning_effort` is the one that
        matters: `low` and `xhigh` produce materially different analysis depth, and
        without this the cache would serve a `low` answer to an `xhigh` run.

        Returns "" when no effort is pinned — the effective value then comes from
        ~/.codex/config.toml, which this client cannot see. That also keeps the key
        unchanged for the default configuration. Pin `codex_reasoning_effort` in
        settings.yaml if you want changes to it to invalidate the cache.
        """
        return f"reasoning_effort={self.reasoning_effort}" if self.reasoning_effort else ""

    def _build_command(self, out_file: str, workdir: str) -> list:
        cmd = [
            self.cli_path, "exec",
            "--sandbox", self.sandbox,
            "--skip-git-repo-check",
            "--ephemeral",
            "--color", "never",
            "--output-last-message", out_file,
            "--cd", workdir,
        ]
        if self.model:
            cmd += ["-m", self.model]
        if self.reasoning_effort:
            cmd += ["-c", f"model_reasoning_effort={self.reasoning_effort}"]
        cmd.append("-")  # read the prompt from stdin
        return cmd

    def _run_codex(self, prompt: str) -> str:
        """Runs one `codex exec` turn and returns the agent's final message.

        A fresh temp dir per call serves double duty: it is the agent's (empty) working
        directory and it holds the last-message file, so concurrent deep-scan workers
        never race on the same output path.
        """
        with tempfile.TemporaryDirectory(prefix="dlh_codex_") as tmp:
            workdir = os.path.join(tmp, "workspace")
            os.makedirs(workdir, exist_ok=True)
            out_file = os.path.join(tmp, "last_message.txt")

            proc = subprocess.run(
                self._build_command(out_file, workdir),
                input=prompt,
                capture_output=True,
                text=True,
                timeout=self.timeout,
            )

            if proc.returncode != 0:
                detail = (proc.stderr or proc.stdout or "").strip()
                log.warning(
                    f"Codex CLI exited with code {proc.returncode}: {detail[-400:] or '(no output)'}"
                )
                return ""

            if not os.path.exists(out_file):
                # Exit 0 but nothing written: the agent produced no final message.
                log.warning("Codex CLI returned no final message.")
                return ""

            with open(out_file, "r", encoding="utf-8") as f:
                return f.read().strip()

    def _construct_prompt(self, code_snippet: str, context: Dict[str, Any]) -> str:
        system_prompt = context.get("system_prompt", "")
        vuln_prompt = context.get("vuln_prompt", "")

        # .replace() rather than .format(): decompiled Java/Kotlin is full of braces that
        # would otherwise be read as format placeholders and raise.
        formatted_prompt = vuln_prompt.replace("{code_snippet}", code_snippet)
        formatted_prompt = formatted_prompt.replace("{file_path}", context.get("file_path", "N/A"))

        return f"{system_prompt}\n\n{formatted_prompt}"
