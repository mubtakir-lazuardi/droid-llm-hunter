# ✨ Droid LLM Hunter - Features

→ [Back to README](../README.md)

---

## 🧠 Core Intelligence

- **🧠 Intelligent Analysis Engine:** Droid LLM Hunter goes beyond regex. It breaks down code into chunks, summarizes functionality, and understands context before flagging vulnerabilities, significantly reducing false positives compared to traditional tools.

- **⭐ Staged Prompt Architecture:** Uses a specialized pipeline of prompts (Summarization → Filtering → Deep Scan) to ensure consistent reasoning and reduce hallucination. [Read the Docs](PROMPT-EXPLANATION.md)

- **📚 RAG with OWASP MASVS:** Findings are automatically enriched with the relevant **OWASP Mobile Application Security Verification Standard (MASVS)** ID (e.g., `MASVS-STORAGE-1`) for rules that have a MASVS mapping defined, making your reports audit-ready instantly.

---

## 🔍 Scanning Strategy

- **🔍 Hybrid Filter Modes:** Choose your strategy!
  - **`llm_only`:** Maximum accuracy using pure AI analysis.
  - **`static_only`:** Blazing fast keyword scanning.
  - **`hybrid`:** The best of both worlds — Static keywords filter the noise, AI verifies the danger.

- **🏗️ Hybrid Architecture (v1.1.5):** A revolutionary "Search → Regex Filter → LLM" pipeline that drastically reduces token usage and increases speed. [Read the Docs](ARCHITECTURE_EXPLANATION.md)

- **🛡️ Smart Scope Protection:** The "Immune System" of the scanner. Automatically filters out library code (e.g., `androidx`, `google`, `r0.java`) using a combination of **Package Whitelisting** (via Manifest) and **Library Blocklisting**. [Read the Docs](EXPLOIT_GENERATOR.md#1-smart-scope-filtering-the-immune-system)

- **🕵️‍♂️ Library Hunter Mode (v1.1.7):** A specialized "Supply Chain" scanner that targets malicious behavior in third-party SDKs (`--scan-libraries`). It bypasses the scope protection to find backdoors, droppers (`DexClassLoader`), and spyware behavior in libraries, using Strict Regex Filtering to save tokens.

---

## 🕸️ Context Awareness

- **🕸️ Context-Aware Scanning:** Utilizes a **Call Graph** to understand file dependencies. Use CrossReference Context to let the AI know _who_ calls a function and with _what_ arguments. [Read the Docs](CROSS_REFERENCE_CONTEXT.md)

- **⚔️ Attack Surface Mapper:** Combines **Manifest Structure** (Exported components) with **Code Logic** (AI Summaries) to identify high-risk entry points (e.g., specific activities processing unvalidated URLs). [Read the Docs](ATTACK_SURFACE_MAPPER.md)

- **👑 Cross-Component Chaining:** The "Crown Jewel". Capability that enables the AI to "connect the dots" between different files. It uses a **Two-Pass Analysis** (Discovery → Global Context → Execution) to generate chained exploits (e.g., using a token found in File A to exploit File B). [Read the Docs](EXPLOIT_GENERATOR.md#2-cross-component-chaining-the-crown-jewel)

---

## ⚙️ Configuration & Flexibility

- **🛠️ Flexible Configuration:** A simple yet powerful configuration file (`config/settings.yaml`) allows for easy management of LLM providers, models, rules, and **Decompiler Settings** (Apktool/JADX).

- **🤖 Multi-Provider Support:** Run locally with **Ollama** (free & private) or scale up with **Gemini**, **Groq**, **OpenAI**, **Anthropic**, and **OpenRouter**.

---

## 💥 Output & Exploitation

- **📊 Structured Security Reports:** Get detailed JSON output containing severity, confidence scores, evidence snippets, and even an "Attack Surface Map" of the application.

- **💥 Auto-Exploit Generation:** Automatically generates actionable **Proof-of-Concept (PoC)** scripts (Bash, HTML, Python, JS) for confirmed vulnerabilities, proving the impact instantly. [Read the Docs](EXPLOIT_GENERATOR.md)

- **📦 XAPK Support:** Direct support for `.xapk` files. The engine automatically handles extraction and selects the main APK for seamless analysis.
