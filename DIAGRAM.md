# Droid LLM Hunter - Scan Workflow

```text
+-------------------------------------------------------+
|  PHASE 1: PREPARATION                                 |
|  [ Start ] -> [ Load Config ] -> [ Decompiler Engine ]|
|                      |             (Apktool / JADX)   |
|                      v                                |
|                      v                                |
|             [ Build Call Graph ]                      |
+----------------------+--------------------------------+
                       |
                       v
+----------------------+--------------------------------+
|  PHASE 2: FILTERING & RISK ID (The Funnel)            |
|                                                       |
|  [ All Smali Files ]                                  |
|          |                                            |
|          v                                            |
|  [ FILTER STRATEGY (Static / LLM / Hybrid) ]          |
|          |                                            |
|          v                                            |
|  [ Identify Risky Files ] -> (Discard Safe Files)     |
|          |                                            |
|      (List of Risky Files)                            |
+----------------------+--------------------------------+
                       |
                       v
+----------------------+--------------------------------+
|  PHASE 3: INTELLIGENT DEEP ANALYSIS                   |
|                                                       |
|    [ Loop: Iterate Risky Files Only ] <-----------+   |
|                 |                                 |   |
|                 v                                 |   |
|      [ Context Injection Engine ]                 |   |
|   (Inject Dependencies & Call Graph)              |   |
|                 |                                 |   |
|                 v                                 |   |
|      [ LLM Inference (Deep Scan) ]                |   |
|   ("Is this specific vulnerability present?")     |   |
|                 |                                 |   |
|                 v                                 |   |
|         [ Store Findings ] -----------------------+   |
+----------------------+--------------------------------+
                       |
                       v
+----------------------+--------------------------------+
|  PHASE 4: ENRICHMENT & REPORTING                      |
|                                                       |
|      [ Map Findings to OWASP MASVS ]                  |
|                 |                                     |
|                 v                                     |
|      [ Generate JSON Report ]                         |
+-------------------------------------------------------+
```