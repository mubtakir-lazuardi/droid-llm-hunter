# Attack Surface Mapper

→ [Back to FEATURES](FEATURES.md)

---

**Attack Surface Mapper** is a strategic feature in Droid LLM Hunter designed to act like a virtual "Red Teamer". Instead of just listing vulnerabilities, it provides a prioritized map of **Entry Points** that an attacker would likely target.

---

## 🔍 Concept: The "Thief's Blueprint"

If an application is a building:
*   **Vulnerability Scan:** Checks if specific locks are broken.
*   **Attack Surface Map:** Creates a blueprint showing all Doors, Windows, and Vents that connect to the outside world, and annotates which ones look weak.

This feature correlates two critical data sources:
1.  **Structure (manifest):** What components are exposed? (`exported=true`)
2.  **Logic (AI Summary):** What do those components actually *do*?

---

## 🛠️ How It Works

The engine executes the following logic pipeline:

1.  **Manifest Parsing:**
    *   Extracts `AndroidManifest.xml`.
    *   Filters for components with `android:exported="true"`.
    *   Identifies Intent Filters and URL Schemes (Deep Links).

2.  **Code Correlation:**
    *   For every exported component (e.g., `com.example.PaymentActivity`), the engine retrieves the **AI Summary** generated during the initial scan phase.
    *   *Example Summary:* "This class handles credit card input and submits it to an API."

3.  **Strategic Synthesis (LLM):**
    *   **[v1.3.0]** The engine sends a prompt asking for a compact **JSON inventory** — *not* a narrated report: *"Extract these attacker-relevant facts (exported components, deep links, network/IPC/file-io/deserialization/reflection signals, manifest flags) as a flat JSON object. No prose, no per-item impact commentary."* Per-item explanations were deliberately dropped from this feature — they duplicated what the detailed, per-file vulnerability findings already say (see [Scan Workflow](SCAN-WORKFLOW.md)). This map is a **recon-style inventory**, meant to be rendered into bullets/tables by a report layer (e.g. a dashboard), not read as prose itself.

---

## 📊 Example Output

**[v1.3.0]** `report["attack_surface_map"]` is a flat JSON object (engine-parsed via `Engine.generate_attack_surface_map`, not raw LLM text):

```json
"attack_surface_map": {
  "exported_activities": ["MainActivity", "DeepLinkHandlerActivity"],
  "exported_receivers": ["DataReceiver"],
  "exported_services": [],
  "exported_providers": [],
  "deep_links": [
    {"scheme": "myapp", "host": "reset-password", "handler": "DeepLinkHandlerActivity"}
  ],
  "unprotected_broadcasts": [],
  "network": ["http"],
  "file_io": false,
  "ipc": true,
  "deserialization": true,
  "reflection": false,
  "manifest_flags": {"debuggable": false, "allow_backup": true}
}
```

On a failed/unparseable LLM response, this field is `{"error": "..."}` instead of being silently empty or `null` — a failure is never presented as a clean/empty inventory.

## ✅ Why Use This?

1.  **Prioritization:** Auditors can stop wasting time on internal utility classes and focus immediately on the "Public Interface" of the app — the `exported_*` and `deep_links` arrays name it directly.
2.  **Context-Aware Risk:** A vulnerability in an *Exported* component is **Critical**. The same vulnerability in a private component is often just *Medium* or *Low*. Cross-reference this inventory against the per-file findings to see which vulnerable files are actually exposed.
3.  **Red Teaming Ready:** The `deep_links` array (scheme/host/handler) and `ipc`/`file_io`/`deserialization`/`reflection` signals give an instant recon checklist — e.g. "try sending a crafted Intent to `DataReceiver`, deserialization is in play here."

## ⚙️ How to Enable

In `config/settings.yaml`:

```yaml
analysis:
  generate_attack_surface_map: true
```

Or via CLI:
```bash
python dlh.py config attack-surface --enable
```
