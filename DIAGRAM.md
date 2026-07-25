# Droid LLM Hunter - Scan Workflow

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