# Hybrid Architecture: Smart Engine Filtering + LLM Verification

→ [Back to FEATURES](FEATURES.md)

---

**Smart Engine Filtering** is a major architectural optimization in Droid-LLM-Hunter designed to drastically reduce token usage while increasing scan speed and accuracy.

---

## 🛑 The Problem with the Old Approach
Previously, Droid-LLM-Hunter operated with a simple and somewhat inefficient pipeline:
1.  **Scanner:** Searched for simple "keywords" (e.g., "WebView").
2.  **LLM:** Sent *every* file containing "WebView" to the LLM for analysis.
3.  **Consequence:**
    *   **Token Waste:** Hundreds of safe files were sent to the LLM unnecessarily.
    *   **Slow & Expensive:** Processing non-vulnerable boilerplate code wasted time and API credits.
    *   **False Positives:** Simple keywords often matched harmless comments or library usage.

---

## 🚀 The Solution: Hybrid Approach (Two-Stage Analysis)
We have implemented a **Two-Stage Logic Pipeline** to optimize the detection process:

### Stage 1: "The Smart Filter" (Python Engine 🐍)
This acts as a "Coarse Sieve" running **locally** using **Regex (Regular Expressions)**.

*   **Mechanism:** Searches for specific **Code Patterns**, not just keywords.
*   **Cost:** FREE (0 Tokens).
*   **Speed:** Blazing Fast (< 1 second).
*   **Examples:**
    *   **PendingIntent:** Doesn't just find `PendingIntent`, but looks for the pattern: `PendingIntent` + (`getActivity` OR `getService`) + `FLAG_MUTABLE`.
    *   **ZipSlip:** Doesn't just find `ZipEntry`, but looks for `ZipEntry` + `.getName`.

If the specific regex pattern is **NOT** found, the file is immediately discarded. The LLM is never invoked.

### Stage 2: "The Intelligent Verifier" (LLM / AI 🤖)
This acts as the "Judge", analyzing only the files that survived Stage 1.

*   **Mechanism:** Analyzes code **context**, variable flow, and security checks.
*   **Task:** Confirms if the Stage 1 finding is an actual exploitable bug or a false positive.
*   **Example:**
    *   *Engine* flags a file for ZipSlip pattern.
    *   *LLM* is asked: "I see `ZipEntry.getName` here. Is there a `getCanonicalPath` check preceding it?"

### Stage 3: "Specialized Pipelines" (Resource Files 📄)
Some rules target **configuration files** (XML) rather than source code. These bypass the Regex Filter and use dedicated parsers:

*   **Manifest Analysis:** 
    *   `strandhogg.yaml` (Task Hijacking via `taskAffinity`)
    *   `exported_components.yaml` (Exposed Activities/Receivers)
    *   `deeplink_hijack.yaml` (Missing `autoVerify` in Deep Links)
*   **Strings Analysis:** 
    *   `hardcoded_secrets_xml.yaml` (Secrets in `res/values/strings.xml`)
*   **Mechanism:** The Engine directly locates and analyzes these specific files if the rule is enabled, skipping the generic file scan.

---

## 💾 Cross-Cutting Layer: The Response Cache

Wrapping **every** stage above is a content-addressed **response cache**. Before *any* request reaches the LLM — summarization, risk identification, deep-scan verification, app summary, or exploit generation — the engine computes a hash of `model + system prompt + rule prompt + code` and checks disk (`output/.dlh_cache/`):

```text
        [ Any LLM call ]
              |
              v
     +------------------+     HIT     +--------------------------+
     |   CACHE CHECK    |------------>|  Return stored response  |
     |  (hash lookup)   |             |   (0 tokens, instant)    |
     +------------------+             +--------------------------+
              | MISS
              v
     +------------------+   success   +--------------------------+
     |  Call real LLM   |------------>|  Write response to cache |
     +------------------+             +--------------------------+
              | (empty / failed response -> NOT cached, retried later)
```

*   **HIT:** the stored response is returned instantly, at zero token cost.
*   **MISS:** the LLM is called, and only a **successful** response is written back. Failed (empty) responses are never cached, so a later run retries them.

This turns an interrupted scan (crash, rate limit) into a **free resume** — re-running the same command replays completed work from cache and only spends tokens on what remains — and deduplicates identical chunks within a single run. Because the key includes the model and prompt, changing either recomputes automatically. Toggle via `analysis.use_cache` or `--no-cache`. See [Configuration](CONFIGURATION.md#performance--cost-controls).

---

## 🛠️ Technical Implementation

1.  **Engine (`code_filter.py` & `engine.py`):**
    *   Updated to parse `detection_pattern` fields from YAML rules.
    *   Executes high-performance regex matching locally before queueing LLM requests.

2.  **Rules (`yaml`):**
    *   Vulnerability rules now support a new field: `detection_pattern`.
    *   Example from `pending_intent_hijacking.yaml`:
        ```yaml
        detection_pattern: "PendingIntent\\.(getActivity|getService|getBroadcast).*FLAG_MUTABLE"
        ```

---

## ⚡ Key Benefits
1.  **Cost Efficiency:** Token usage reduced by **50-80%** by filtering out non-candidates locally.
2.  **Speed:** Massively faster scans as the CPU handles the bulk of the filtering, not the Cloud API.
3.  **Accuracy:** Combines the precision of Regex with the contextual understanding of LLMs.
4.  **Large Scale Scalability:** Solves the "Context Overflow" problem by ensuring only relevant file chunks enter the LLM context window.

---

## ❓ FAQ: Backward Compatibility

### Will existing (Legacy) rules break?
**NO.** The architecture is fully **Backward Compatible**.

1.  **Legacy Rules (Keyword Only):**
    *   Rules like `sql_injection` that lack a `detection_pattern` rely on the standard `keywords` list.
    *   The Engine continues to use the standard "Keyword Search" for these.
    *   **Result:** They work exactly as before (slightly less efficient than new rules).

2.  **New Rules (Keyword + Regex):**
    *   Automatically utilize the "Smart Filter" optimization.
    *   **Result:** Higher efficiency and speed.

### How to optimize Legacy Rules?
Simply add a `detection_pattern` field to their YAML definition.
Example for `webview_xss.yaml`:
```yaml
detection_pattern: "setJavaScriptEnabled\\(true\\)|addJavascriptInterface"
```
Once added, the Engine automatically switches to Hybrid Mode for that rule.

## ⚠️ Limitations & Trade-offs (Blind Spots)

For full transparency, it is important to understand the "Blind Spots" of this Regex-based approach. While it covers 95-99% of standard cases, some edge cases might be missed to preserve performance.

### 1. Hardcoded Secrets (Naming Dependency)
*   **Pattern:** `(?i)(api_key|password|secret|token).*=.*["']`
*   **Strength:** Highly efficient, only flags variables that *look* like secrets.
*   **Weakness:** If a developer uses random variable names (e.g., `String x = "AIza...";`), Regex will NOT catch it.
*   **Trade-off:** Scanning *every* string assignment would result in millions of false positives and massive token costs. This is a necessary balance.

### 2. SQL Injection (Standard API Dependency)
*   **Pattern:** `(rawQuery|execSQL)\\s*\\(`
*   **Strength:** Catches the use of standard Android SQLite APIs.
*   **Weakness:** If using obscure 3rd-party ORMs or custom wrapper functions (e.g., `myDatabaseHelper.doQuery(...)`), it might be missed.
*   **Trade-off:** `rawQuery` accounts for the vast majority of SQLi vulnerabilities in native Android.

### 3. Insecure File Permissions (Constant Dependency)
*   **Pattern:** `MODE_WORLD_READABLE`
*   **Weakness:** If a developer uses the integer value (`1`) instead of the constant name, Regex won't know.
*   **Reality Check:** Developers almost always use the IDE auto-completed constants, making this risk negligible.

**Conclusion:** The current configuration represents the "Best Practice" sweet spot. Tightening regex increases False Negatives; loosening it explodes Token Costs.
