# 🔄 Droid LLM Hunter - Scan Workflow

→ [Back to README](../README.md)

---

## Overview

Droid LLM Hunter uses a multi-stage process to analyze an APK:

1.  **Decompilation:** The APK is decompiled using **Apktool** (for Smali/Manifest) and optionally **JADX** (for Java Source), depending on the `decompiler_mode`.
2.  **Smart Filtering:** Based on the `filter_mode`, the engine identifies potentially risky files using Static Analysis (`static_only`), AI Summarization (`llm_only`), or both (`hybrid`).
3.  **Smart Scope Protection:** Irrelevant files (libraries) are discarded based on `package` name and blocklists.
4.  **Risk Identification:** High-level analysis determines which files require deep inspection.
5.  **Deep Dive Analysis:** Risky files are scanned for vulnerabilities.
6.  **Global Context Building:** All findings are summarized to create a "Global Context".
7.  **Chained Exploit Generation:** The engine generates exploits that leverage the Global Context to connect vulnerabilities across files.
8.  **Enrichment & Reporting:** Vulnerabilities are mapped to **OWASP MASVS** standards, and a detailed JSON report is generated.

> **💾 Response Cache (cross-cutting):** Every LLM call in the stages above — summarization, risk identification, deep-scan verification, app summary, and exploit generation — passes through a content-addressed cache first. A HIT returns the stored answer for free; a MISS calls the LLM and stores the successful result. This makes an interrupted scan resume for free on re-run. See [Configuration](CONFIGURATION.md#response-cache-analysisuse_cache).

---

## Pipeline Diagram

```text
+-------------------------------------------------------+
|  PHASE 1: PREPARATION                                 |
|  [ Start ] -> [ Load Config ] -> [ Decompiler Engine ]|
|                      |             (Apktool / JADX)   |
|                      v                                |
|             [ Parse AndroidManifest.xml ]             |
|          (Extract Package Name & Components)          |
+----------------------+--------------------------------+
                       |
                       v
+----------------------+--------------------------------+
|  PHASE 2: SMART SCOPE PROTECTION (The Immune System)  |
|                                                       |
|  [ All Smali/Java Files ]                             |
|          |                                            |
|          v                                            |
|  [ SCOPE FILTER ]                                     |
|     1. Whitelist: Must match App Package Name         |
|     2. Blocklist: Drop known libs (androidx, r0...)   |
|          |                                            |
|          v                                            |
|  [ Relevant Files Only ] (Libraries Discarded)        |
+----------------------+--------------------------------+
                       |
                       v
+----------------------+--------------------------------+
|  PHASE 3: DISCOVERY & RISK ID (Hybrid Pass)           |
|                                                       |
|    [ Loop: Analyze Relevant Files ]                   |
|                 |                                     |
|                 v                                     |
|    [ REGEX FILTER (Zero Cost) ]                       |
|    (Match 'detection_pattern'?)                       |
|       NO |             | YES                          |
|          v             v                              |
|       [ Skip ]   [ CACHE CHECK ] --HIT--> [ Reuse ]   |
|                        | MISS                         |
|                        v                              |
|                  [ LLM VERIFICATION ]                 |
|                  (Context & Logic Check)              |
|                                |                      |
|                                v                      |
|                     [ Validate Finding ]              |
|                                |                      |
|                                v                      |
|                     [ Store in Knowledge Base ]       |
|                   (Do NOT Generate Exploits Yet)      |
+----------------------+--------------------------------+
                       |
                       v
+----------------------+--------------------------------+
|  PHASE 4: INTELLIGENT CHAINING (Pass 2)               |
|                                                       |
|      [ Build Global Context ]                         |
|   (Summarize all findings from Phase 3)               |
|                 |                                     |
|                 v                                     |
|    [ Loop: Generate Exploits ]                        |
|                 |                                     |
|                 v                                     |
|      [ Inject Context + Manifest + Secrets ]          |
|   "Use the token from File A to hack File B"          |
|                 |                                     |
|                 v                                     |
|      [ Generate Chained Exploit Scripts ]             |
|       (Python / Bash / HTML / Frida)                  |
+----------------------+--------------------------------+
                       |
                       v
+----------------------+--------------------------------+
|  PHASE 5: REPORTING                                   |
|                                                       |
|      [ JSON Report ] + [ Exploit Artifacts ]          |
+-------------------------------------------------------+
```

---

## JSON Report Structure

For more detailed information on the **JSON Report** structure, see the [output/](../output/) directory for example reports.
