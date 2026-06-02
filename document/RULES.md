# 🛡️ Droid LLM Hunter - Available Rules

→ [Back to README](../README.md)

---

## Overview

Droid LLM Hunter ships with **25 vulnerability rules** covering the most critical Android security categories, all mapped to the **OWASP MASVS** framework.

Enable or disable rules in `config/settings.yaml`:

- `true`: Enable the rule (included in every scan).
- `false`: Disable the rule (skipped entirely).

---

## Rule List

| Rule | Category | MASVS |
|------|----------|-------|
| `sql_injection` | Injection | MASVS-CODE |
| `graphql_injection` | Injection | MASVS-CODE |
| `path_traversal` | Injection | MASVS-STORAGE |
| `webview_xss` | WebView | MASVS-CODE |
| `webview_deeplink` | WebView | MASVS-CODE |
| `insecure_webview` | WebView | MASVS-CODE |
| `webview_file_access` | WebView | MASVS-STORAGE |
| `hardcoded_secrets` | Secrets | MASVS-STORAGE |
| `hardcoded_secrets_xml` | Secrets | MASVS-STORAGE |
| `exported_components` | Components | MASVS-PLATFORM |
| `intent_spoofing` | Components | MASVS-PLATFORM |
| `deeplink_hijack` | Components | MASVS-PLATFORM |
| `strandhogg` | Components | MASVS-PLATFORM |
| `pending_intent_hijacking` | Components | MASVS-PLATFORM |
| `insecure_random_number_generation` | Crypto/Auth | MASVS-CRYPTO |
| `biometric_bypass` | Crypto/Auth | MASVS-AUTH |
| `insecure_deserialization` | Crypto/Auth | MASVS-CODE |
| `insecure_storage` | Storage | MASVS-STORAGE |
| `insecure_file_permissions` | Storage | MASVS-STORAGE |
| `unsafe_reflection` | Code Exec | MASVS-CODE |
| `fragment_injection` | Code Exec | MASVS-PLATFORM |
| `universal_logic_flaw` | Logic | MASVS-CODE |
| `deeplink_logic_bypass` | Logic | MASVS-PLATFORM |
| `jetpack_compose_security` | Logic | MASVS-CODE |
| `zip_slip` | Zip/Supply | MASVS-CODE |

---

## How to Enable/Disable Rules

Edit `config/settings.yaml`:

```yaml
rules:
  sql_injection: true
  webview_xss: true
  hardcoded_secrets: true
  insecure_storage: false   # disabled
  zip_slip: false           # disabled
  # ... etc
```

Or use the CLI:

```bash
# Enable rules
python dlh.py config rules --enable sql_injection,webview_xss

# Disable rules
python dlh.py config rules --disable zip_slip,insecure_storage

# List all available rules
python dlh.py --list-rules
```

---

## How to Add a New Rule

1. Create a new YAML file in `config/prompts/vuln_rules/` (containing `name`, `description`, and `prompt`).
2. Add the rule to the `RulesSettings` class in `core/config_loader.py`.
3. Add the rule entry to `config/settings.yaml`.
4. *(Optional)* Add a mapping entry in `config/knowledge_base/masvs_mapping.json` to link to an OWASP MASVS category.

Contributions of new rules are always welcome — see [Contributing](../README.md#contributing).
