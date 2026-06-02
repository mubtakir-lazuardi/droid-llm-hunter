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

## JADX Path Configuration

If `jadx` is not in your system PATH, specify the absolute path in `settings.yaml`:

```yaml
jadx:
  path: "/opt/jadx/bin/jadx"
```

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
