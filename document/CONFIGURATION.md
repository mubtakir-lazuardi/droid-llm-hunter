# ⚙️ Droid LLM Hunter - Configuration Guide

→ [Back to README](../README.md)

---

## Configuration File

All settings are managed in `config/settings.yaml`. This file controls:
- LLM provider & model
- API keys
- Vulnerability rules (enable/disable)
- Filter mode & decompiler mode
- External tool paths (Apktool, JADX)

---

## Filter Mode (`filter_mode`)

Configure the analysis strategy to balance speed, cost, and accuracy.

### 1. `llm_only`

**Decision Maker:** 100% AI (LLM).

**How it works:**

1. All Smali files are chunked and summarized by the LLM (`summarize_chunks`).
2. The summaries are analyzed by the LLM to identify risks (`identify_risky_chunks`).
3. Only files marked as "Risky" are deep-scanned.

| | |
|--|--|
| ✅ **Pros** | Most Intelligent (understands context), Minimal False Negatives |
| ❌ **Cons** | Most Expensive (high token usage), Slowest |

---

### 2. `static_only`

**Decision Maker:** Classic Keyword Matching (`CodeFilter`).

**How it works:**

1. The scanner searches for dangerous keywords (e.g., `WebView`, `SQLite`, `Cipher`).
2. If found, the file is immediately marked for deep scan.
3. LLM is NOT used for filtering.

| | |
|--|--|
| ✅ **Pros** | Super Fast, Zero Token Cost for filtering |
| ❌ **Cons** | "Dumb" (no context), High False Positives, High False Negatives (obfuscation) |

---

### 3. `hybrid` *(Recommended)*

**Decision Maker:** Static Analyzer + LLM Verification.

**How it works:**

1. **Phase 1 (Static):** Find files with dangerous keywords.
2. **Phase 2 (LLM Verification):** Only those specific files are summarized and checked by the LLM to confirm if they are truly risky.

> **[v1.3.0] Recall safeguard:** first-party files whose content matches an enabled rule's `detection_pattern` are deep-scanned even if the LLM risk-triage would skip them — a strong static signal is never dropped. See [Architecture](ARCHITECTURE_EXPLANATION.md).

| | |
|--|--|
| ✅ **Pros** | Extreme Token Savings (ignores safe files), Good Accuracy |
| ❌ **Cons** | Risk of Obfuscation (same as static_only) |

---

### Usage Recommendations

| Scenario | Recommended Mode |
|----------|-----------------|
| Need 100% accuracy, have abundant tokens | `llm_only` |
| Daily usage (balanced speed & cost) | `hybrid` ✅ |
| Low on tokens or need very fast scan | `static_only` |

---

## Decompiler Mode (`decompiler_mode`)

Droid LLM Hunter supports dual decompilation to balance reliability and analysis quality.

### 1. `apktool` *(Classic)*

- **Format:** Smali (Assembly).
- **Pros:** 100% Reliability, critical for Manifest analysis.
- **Cons:** Harder for LLM to understand logic, higher token usage.

### 2. `jadx` *(Modern)*

- **Format:** Java Source Code.
- **Pros:** Native code format, LLM understands it perfectly, logic is clear.
- **Cons:** May fail on some obfuscated apps.

### 3. `hybrid` *(Smart Fallback — Recommended)*

- **Format:** Java (Primary) + Smali (Fallback).
- **Logic:** The engine tries to use JADX output. If JADX fails or produces empty/corrupt code for a file, it automatically switches to the Smali version from Apktool.
- **Result:** Best of both worlds — Analysis quality of Java with the reliability of Smali.

---

## LLM Providers

Supported `llm.provider` values: `ollama`, `gemini`, `groq`, `openai`, `anthropic`, `openrouter`, `router9`.

### 9Router (`router9`)

[9Router](https://github.com/9router/9router) is a **self-hosted, OpenAI-compatible LLM router**: one local endpoint that fans out to many providers/models via a provider-prefixed model name (e.g. `gc/gemini-2.5-pro` routes through to Gemini). Configure it like any other provider:

```yaml
llm:
  provider: router9
  router9_model: gc/gemini-2.5-pro
  router9_api_key: sk-...
  router9_base_url: http://localhost:20128/v1/chat/completions   # your self-hosted instance
```

- **`router9_base_url` is configurable** (unlike the other clients, which hit a fixed public URL) since 9Router is self-hosted — host/port vary per install.
- **Streaming quirk:** 9Router's `/v1/chat/completions` endpoint was observed to return a **Server-Sent Events (SSE) stream** (`Content-Type: text/event-stream`, `data: {...}` chunks) even for a plain, non-streaming request. The client (`modules/llm_client/router9.py`) detects this via the response's `Content-Type` header and parses the SSE chunks accordingly, falling back to a normal single-JSON response if the router ever returns one instead.
- **Reasoning models eat into `max_tokens`:** routing to a reasoning-capable model (e.g. `gemini-2.5-pro`) burns part of the `max_tokens` budget on hidden `reasoning_tokens` before any visible output is produced. A too-low `max_tokens` can silently truncate the answer (`finish_reason: "length"`) — this was confirmed live against a real 9Router instance during testing. If responses look cut off, raise `llm.max_tokens` (same guidance as OpenRouter's `kimi-k3`, which needs `8192`).

### Routing `--generate-exploit` to a different provider (`exploit_provider` / `exploit_model`)

Some models happily analyze code for vulnerabilities but refuse — or silently return empty output — when asked to write a working PoC/verification script, even with authorized-assessment framing in `exploit_prompt.txt`. This was confirmed live: a reasoning model routed through `router9` returned nothing for `intent_redirection`, while Anthropic's `claude-opus-4-6` produced a complete script for the identical finding.

Rather than switching your whole `provider` just for exploit generation, point ONLY that stage at a different (known-permissive) provider/model:

```yaml
llm:
  provider: router9              # used for scanning/analysis (summarize, risk-ID, rule verification, ...)
  router9_model: jem/glm-5.2
  anthropic_api_key: sk-ant-...   # already present for the `anthropic` provider — reused below, no duplication
  anthropic_model: claude-opus-4-6
  exploit_provider: anthropic     # --generate-exploit only: use Anthropic instead of router9
  # exploit_model: claude-sonnet-4-5-20250929   # optional: override the model on exploit_provider (or on `provider`, if exploit_provider is unset)
```

- **Both fields are optional and independent.** `exploit_provider` alone switches provider (using that provider's own default model). `exploit_model` alone keeps the same provider but overrides just the model. Neither set → exploit generation uses the main `provider`/model, unchanged from before this feature existed.
- **No separate API key field** — `exploit_provider: anthropic` reuses `anthropic_api_key`/`anthropic_model` already in this file; there's no `exploit_api_key`.
- **Safe by design:** the exploit-specific client is only built when `--generate-exploit` is actually requested, so a typo'd `exploit_provider` never breaks a normal scan. If building it fails for any reason, DLH logs a warning and falls back to the main provider/model rather than crashing the whole run.
- **Cache-friendly:** the response cache is keyed by model, so exploit-gen calls and scan calls never collide even when routed to different providers; the end-of-run `Response cache: N hit(s), M miss(es)` line reports the combined total.

## JADX Path Configuration

If `jadx` is not in your system PATH, specify the absolute path in `settings.yaml`:

```yaml
jadx:
  path: "/opt/jadx/bin/jadx"
```

---

## Performance & Cost Controls

These live under `analysis:` and `llm:` in `config/settings.yaml` and control speed, token cost, and resumability.

### Response Cache (`analysis.use_cache`) — default `true`

Every **successful** LLM response is cached on disk under `output/.dlh_cache/`, keyed by a hash of `model + system prompt + rule prompt + code`.

- **Resume:** if a scan crashes or exhausts your rate limit, just run the **same command again** — completed calls are reused for free, only the unfinished ones hit the LLM.
- **Dedup:** identical content analyzed twice costs a single call.

Failed (empty) responses are never cached, so they are retried on the next run. The cache is *content-addressed*: change the model, a rule prompt, or the APK and the affected entries recompute automatically — no manual clearing needed.

```bash
# Disable for one run (force fresh calls, no resume):
python dlh.py scan target.apk --no-cache

# Reset the cache entirely:
rm -rf output/.dlh_cache
```

At the end of a scan the log reports effectiveness, e.g. `Response cache: 40 hit(s), 2 miss(es).`

### Parallelism (`analysis.max_workers`) — default `2`

Number of files deep-scanned in parallel. Raise it for fast providers (Groq, Gemini); keep it low if you hit rate limits.

### Input Truncation (`analysis.max_input_chars`) — default `30000`

Caps how much file content is sent to the LLM per call (keeps the head + tail, drops the middle with a `[TRUNCATED …]` marker). Prevents oversized files from blowing the context window or inflating cost. Set `0` to disable.

### Output Tokens (`llm.max_tokens`) — default `4096`

Maximum tokens the LLM may return per call. Raise it if long JSON findings or generated exploits get cut off (a truncated response causes JSON parse failures).

---

## Quick Config via CLI

```bash
# Set LLM provider
python dlh.py config provider gemini

# Set model
python dlh.py config model gemini-2.5-flash

# Set filter mode
python dlh.py config filter-mode hybrid

# Set decompiler mode
python dlh.py config decompiler-mode hybrid

# Show current configuration
python dlh.py config show

# Run interactive setup wizard
python dlh.py config wizard
```
