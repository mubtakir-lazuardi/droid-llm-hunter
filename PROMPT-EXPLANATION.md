# Droid LLM Hunter - Prompt Architecture Documentation

This document provides a detailed explanation of the role of each prompt file within the Droid LLM Hunter architecture, specifically after the implementation of OWASP MASVS Context Injection.

These prompts act as the "Brain" of the tool, guiding the AI through various stages of analysis.

---

### 1. `system_prompt.txt` (The Core Persona)
**Location:** `config/prompts/system_prompt.txt`
**Function:** 
Defines the core "Identity" of the AI. This file sets the standards and rules that the AI must follow in **every** request (especially during the vulnerability scanning phase).
**Key Roles:**
*   Establishes the role as a "World-Class Android Security Tester".
*   Enforces output in valid JSON format.
*   **[NEW]** Mandates analysis based on **OWASP MASVS** principles.
*   **[NEW]** Serves as the entry point for "Context Injection" (where specific MASVS rule definitions are dynamically injected by the Engine at runtime).

### 2. `summarize_prompt.txt` (Phase 1: The Signal Seeker)
**Location:** `config/prompts/summarize_prompt.txt`
**Function:** 
Used during the `llm_only` or `hybrid` filtering phase. Its task is to condense thousands of lines of raw code into concise summaries focused on security features.
**Key Roles:**
*   Reads raw code chunks (Java/Smali).
*   **[NEW]** Explicitly instructed to look for sensitive categories (MASVS-AUTH, MASVS-CRYPTO, MASVS-NETWORK, etc.).
*   **Output:** Descriptive summaries containing "Tags/Signals" for the next phase.

### 3. `identify_risk_prompt.txt` (Phase 2: The Gatekeeper)
**Location:** `config/prompts/identify_risk_prompt.txt`
**Function:** 
Acts as an intelligent filter. The AI reads the *summaries* (from Phase 1) and decides whether the file is worth a deeper scan (Deep Scan) or should be discarded (Safe/Noise).
**Key Roles:**
*   **[NEW]** Matches "Tags/Signals" from the summary against a Trigger List.
*   If the summary contains MASVS keywords -> Risk = **YES**.
*   If the summary only contains common UI/Utility code -> Risk = **NO**.
*   **Token Efficiency:** Prevents irrelevant files from entering the expensive Phase 3.

### 4. `app_summary_prompt.txt` (Reporting: The Big Picture)
**Location:** `config/prompts/app_summary_prompt.txt`
**Function:** 
Used at the end of the scan process to generate the opening paragraph of the final report (Executive Summary).
**Key Roles:**
*   Reads `AndroidManifest.xml` (Permissions, Activities).
*   Reads code summaries found during analysis.
*   **[NEW]** Generates an application description focusing on: Core Functionality, Security Features, Data Handling, and Dangerous Permissions.

### 5. `attack_surface_prompt.txt` (Reporting: The Map Maker)
**Location:** `config/prompts/attack_surface_prompt.txt`
**Function:** 
Used if the `generate_attack_surface_map` option is enabled. Its task is to map out entry points for attackers.
**Key Roles:**
*   Analyzes components where `exported=true` (Activity, Receiver, Service).
*   Identifies Deep Link URLs that can be triggered externally.
*   **Output:** Used by pentesters to identify initial attack vectors.

---

### Prompt Execution Pipeline

The following diagram illustrates how these prompts interact sequentially during a single scan:

```text
[ START SCAN ]
      |
      v
[ PHASE 1: SUMMARIZATION ]
(Used for all code chunks)
Prompt: `summarize_prompt.txt`
Input : "Raw Code (Java/Smali)"
Output: "Summary + MASVS Tags"
      |
      v
[ PHASE 2: FILTERING (Risk Logic) ]
(Used to decide file fate)
Prompt: `identify_risk_prompt.txt`
Input : "Summary + MASVS Tags"
Output: "YES" (Proceed) or "NO" (Discard)
      |
      v
[ PHASE 3: DEEP ANALYSIS (Vulnerability Scan) ]
(Only for "YES" risky files)
Prompt: `system_prompt.txt` (Persona + MASVS Definition) + `vuln_rules/*.yaml`
Input : "Raw Code" + "Context"
Output: JSON Vulnerability Report
      |
      v
[ PHASE 4: REPORTING ]
(After all scans complete)
Prompt: `app_summary_prompt.txt`
Input : "AndroidManifest.xml" + "All Summaries"
Output: Application Description

Prompt: `attack_surface_prompt.txt` (Optional)
Input : "AndroidManifest.xml" + exported components
Output: Attack Surface Map
```

## Why Multiple Prompts Instead of One Prompt ?

Using a single monolithic prompt leads to:
- Higher token cost
- Poor reasoning consistency
- Increased hallucination risk

Droid LLM Hunter adopts a staged prompt architecture to:
- Isolate reasoning tasks
- Enforce decision boundaries
- Improve reproducibility and auditability