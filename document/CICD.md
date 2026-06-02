# 🔁 Droid LLM Hunter - CI/CD Integration

→ [Back to README](../README.md)

---

## Overview

Droid LLM Hunter is designed for seamless integration into CI/CD pipelines (GitHub Actions, GitLab CI, etc.). The scan command returns **exit code 1** on failure, making it easy to use as a quality gate.

---

## GitHub Actions (Recommended)

We provide a **Gold Standard** workflow example that includes:

- Auto-building your Android APK.
- Running Droid LLM Hunter with specific rules.
- Uploading the security report as an artifact.

👉 **[View the Professional Workflow Example](../examples/github-actions)**

---

## Key Features in CI/CD

- **Dynamic Rules:** Enable/Disable rules directly from YAML (e.g., `rules: "sql_injection:true, webview_xss:false"`).
- **Custom Config:** Load your own `settings.yaml` via `config-path`.
- **Hybrid Fallback:** Automatically switches to Static Analysis if JADX fails in the container.
- **Exit Code:** Returns `exit code 1` on scan failure — detectable by any CI/CD system.

---

## Example Workflow Snippet

```yaml
- name: Run DLH Security Scan
  run: |
    python dlh.py --rules "sql_injection,webview_xss,hardcoded_secrets" scan app.apk
  continue-on-error: false   # Pipeline fails if vulnerabilities found
```
