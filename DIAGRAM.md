# Droid LLM Hunter - Scan Workflow (V1.1.3)

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
|  PHASE 2: SMART SCOPE PROTECTION (The Immune System)  |  <-- [NEW v1.1.3]
|                                                       |
|  [ All Smali/Java Files ]                             |
|          |                                            |
|          v                                            |
|  [ SCOPE FILTER ]                                     |
|     1. Whitelist: Must match App Package Name         |
|     2. Blocklist: Drop known libs (androidx, r0...)   |
|          |                                            |
|          v                                            |
|  [ Relevant Files Only ] (Noise Reduced by ~70%)      |
+----------------------+--------------------------------+
                       |
                       v
+----------------------+--------------------------------+
|  PHASE 3: DISCOVERY & RISK ID (Pass 1)                |
|                                                       |
|    [ Loop: Analyze Relevant Files ]                   |
|                 |                                     |
|                 v                                     |
|      [ LLM / Static Scan ] -> [ Validate Finding ]    |
|                 |                                     |
|                 v                                     |
|         [ Store in Knowledge Base ]                   |
|       (Do NOT Generate Exploits Yet)                  |
+----------------------+--------------------------------+
                       |
                       v
+----------------------+--------------------------------+
|  PHASE 4: INTELLIGENT CHAINING (Pass 2)               |  <-- [NEW v1.1.3]
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