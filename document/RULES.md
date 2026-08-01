# 🛡️ Droid LLM Hunter - Available Rules

→ [Back to README](../README.md)

---

## Overview

Droid LLM Hunter ships with **26 vulnerability rules** covering the most critical Android security categories, all mapped to the **OWASP MASVS** framework. Rules are grouped by category below (mirroring the testbed reference in [VulnerAppDLH/VULNER_DLH.md](https://github.com/roomkangali/VulnerAppDLH/blob/main/VULNER_DLH.md)).

Enable or disable rules in `config/settings.yaml` (`true` = included in every scan, `false` = skipped).

---

### 💉 Injection & Input Validation

| Rule | Description | MASVS |
|------|-------------|-------|
| `sql_injection` | Raw SQL built via string concatenation (`rawQuery`/`execSQL`). | MASVS-CODE-4 |
| `graphql_injection` | GraphQL queries assembled from untrusted strings. | MASVS-CODE-4 |
| `path_traversal` | File reads on unvalidated user paths (`../`). | MASVS-CODE-4 |
| `zip_slip` | Archive extraction without a canonical-path check (`../` entry names). | MASVS-CODE-4 |

### 🌐 WebView Security

| Rule | Description | MASVS |
|------|-------------|-------|
| `webview_xss` | `setJavaScriptEnabled(true)` / `addJavascriptInterface` on untrusted content. | MASVS-PLATFORM-2 |
| `insecure_webview` | Dangerous `WebSettings` (file/universal access). | MASVS-PLATFORM-2 |
| `webview_deeplink` | Intent-delivered URLs loaded straight into a WebView (open redirect). | MASVS-PLATFORM-2 |
| `webview_file_access` | File access enabled in a WebView (local file/cookie theft). | MASVS-PLATFORM-2 |

### 🔑 Secrets & Storage

| Rule | Description | MASVS |
|------|-------------|-------|
| `hardcoded_secrets` | API keys / tokens hardcoded in code (`AIza…`, `AKIA…`, etc.). | MASVS-STORAGE-2 |
| `hardcoded_secrets_xml` | Secrets embedded in `res/values/strings.xml`. | MASVS-STORAGE-2 |
| `insecure_storage` | Plain-text credentials in `SharedPreferences`/files. | MASVS-STORAGE-1 |
| `insecure_file_permissions` | World-readable/writable files (`MODE_WORLD_*`, `setReadable(true,false)`). | MASVS-STORAGE-1 |

### 🔐 Cryptography & Authentication

| Rule | Description | MASVS |
|------|-------------|-------|
| `insecure_random_number_generation` | Weak PRNG (`java.util.Random`) for security values. | MASVS-CRYPTO-1 |
| `biometric_bypass` | Flawed `BiometricPrompt` / client-side auth trust. | MASVS-AUTH-2 |

### 🔄 IPC (Inter-Process Communication)

| Rule | Description | MASVS |
|------|-------------|-------|
| `exported_components` | Activities/Services/Providers exported without permission. | MASVS-PLATFORM-1 |
| `intent_spoofing` | Broadcast receivers trusting unvalidated intents. | MASVS-PLATFORM-1 |
| `deeplink_hijack` | Overly broad deep links (`host="*"`, missing `autoVerify`). | MASVS-PLATFORM-1 |
| `deeplink_logic_bypass` | Auth/IDOR bypass via deep-link parameters. | MASVS-PLATFORM-1 |
| `intent_redirection` | Forwarding an attacker's nested Intent unvalidated (confused deputy). | MASVS-PLATFORM-1 |
| `pending_intent_hijacking` | Mutable `PendingIntent` on an implicit Intent. | MASVS-PLATFORM-1 |
| `fragment_injection` | Exported `PreferenceActivity` with a permissive `isValidFragment()`. | MASVS-PLATFORM-1 |
| `strandhogg` | Task hijacking via `taskAffinity` + `launchMode`. | MASVS-PLATFORM-3 |

### 🧨 Deserialization, Reflection & Code Execution

| Rule | Description | MASVS |
|------|-------------|-------|
| `insecure_deserialization` | `ObjectInputStream.readObject()` on untrusted bytes (RCE). | MASVS-CODE-4 |
| `unsafe_reflection` | `Class.forName`/`Method.invoke` driven by untrusted input. | MASVS-CODE-4 |

### 🧩 Advanced Logic & UI

| Rule | Description | MASVS |
|------|-------------|-------|
| `universal_logic_flaw` | Conceptual/business-logic flaws (LLM-exclusive, no static pattern). | MASVS-CODE |
| `jetpack_compose_security` | Security misconfigurations in Jetpack Compose UI. | MASVS-PLATFORM-3 |

---

### 🕵️ Library Hunter Mode (supply-chain, opt-in)

Beyond the 26 rules above, a dedicated **`library_vulnerability`** detector runs only under `--scan-libraries`. It bypasses Smart Scope Protection to audit **third-party SDKs** for backdoors, droppers (`DexClassLoader`), native/command execution, device-identifier spyware, and unsafe JS bridges. It is activated by the flag rather than a `settings.yaml` toggle.

---

## How to Enable/Disable Rules

Edit `config/settings.yaml`:

```yaml
rules:
  sql_injection: true
  webview_xss: true
  hardcoded_secrets: true
  intent_redirection: false   # disabled
  zip_slip: false             # disabled
  # ... etc
```

> **Note:** editing `settings.yaml` by hand preserves the inline comments. The `python dlh.py config rules --enable/--disable` commands rewrite the file via a YAML dumper and will strip those comments.

Or list rules from the CLI:

```bash
python dlh.py list-rules
```

---

## How to Add a New Rule

1. Create a new YAML file in `config/prompts/vuln_rules/` (`name`, `description`, `prompt`, optional `detection_pattern` + `keywords`).
2. Add the rule to the `RulesSettings` class in `core/config_loader.py` (keep it A–Z).
3. Add the rule entry to `config/settings.yaml` (with an inline comment).
4. Add a mapping entry in `config/knowledge_base/masvs_mapping.json` (OWASP MASVS).
5. Add Layer-1 golden coverage in `tests/test_detection_patterns.py` (a sample the `detection_pattern` must match), and — if the testbed exercises it — a `{rule → file}` entry in `tests/golden/vulnerapp_expected.json`.

Contributions of new rules are always welcome — see [Contributing](../README.md#contributing).
