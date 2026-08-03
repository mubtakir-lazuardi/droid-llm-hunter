from .config_loader import Settings
from core import log
from modules.decompiler.apktool_handler import ApktoolHandler
from modules.decompiler.jadx_handler import JadxHandler
from modules.static_analyzer.code_filter import CodeFilter
from modules.llm_client.ollama import OllamaClient
from modules.llm_client.gemini import GeminiClient
from modules.llm_client.groq import GroqClient
from modules.llm_client.openai import OpenAIClient
from modules.llm_client.anthropic import AnthropicClient
from modules.llm_client.openrouter import OpenRouterClient
from modules.llm_client.router9 import Router9Client
from core.call_graph import CallGraphBuilder
from core.manifest_parser import ManifestParser
import os
import yaml
import concurrent.futures
import zipfile
import shutil
from rich.progress import track
from core.logger import console

# Rules evaluated ONLY against AndroidManifest.xml (in analyze_manifest), never against
# code files in the deep scan. Single source of truth so the two paths can't drift —
# a missing entry here previously let `strandhogg` leak into the code deep-scan and
# false-positive on every risky Java file.
MANIFEST_RULES = ["webview_deeplink", "intent_spoofing", "exported_components", "deeplink_hijack", "strandhogg"]

# Rules that have their OWN dedicated analysis pass and must NEVER run in the generic code
# deep-scan (analyze_file) — otherwise they leak and false-positive on .java files.
# Manifest rules run in analyze_manifest; hardcoded_secrets_xml runs in analyze_strings_xml.
DEDICATED_PASS_RULES = set(MANIFEST_RULES) | {"hardcoded_secrets_xml"}

# [#E report-dedup] Rules that detect the same underlying issue share a "family". On the
# same file, findings in one family collapse into a single entry; the rest move under
# 'also_detected_by' (never deleted). Rules not listed are their own singleton family.
VULN_FAMILIES = {
    "webview_xss": "webview", "insecure_webview": "webview",
    "webview_file_access": "webview", "webview_deeplink": "webview",
    "insecure_storage": "storage", "insecure_file_permissions": "storage",
    "exported_components": "ipc", "intent_spoofing": "ipc",
    "deeplink_hijack": "deeplink", "deeplink_logic_bypass": "deeplink",
}
# Broad conceptual rule(s): on a file that already has a specific finding, these are folded
# into it (kept under 'also_detected_by') so they don't flood the report. If a generic rule
# is the ONLY finding on a file, it stays as a standalone finding.
GENERIC_RULES = {"universal_logic_flaw"}
_SEVERITY_ORDER = {"critical": 4, "high": 3, "medium": 2, "low": 1, "info": 0}

# [#C] Appended to every RULE prompt (deep-scan + manifest + strings) as the LAST instruction,
# so it overrides any prose-inviting wording inside a rule ("explain...", "say Safe"). Reduces
# parse failures across providers. Brace-free (vuln_prompt is passed through str.format()).
JSON_ONLY_SUFFIX = (
    "\n\n### RESPONSE FORMAT (STRICT)\n"
    "Return ONLY the single JSON object defined in the system prompt. "
    "No markdown, no code fences, no commentary, and no standalone words such as "
    "'Safe', 'VULNERABLE', 'Yes' or 'No' outside the JSON. "
    "Put the explanation in the description field, the exploit walkthrough in attack_scenario, "
    "and the remediation in recommendation."
)

class Engine:
    def __init__(self, settings: Settings):
        self.settings = settings
        self._setup_llm_client()  # sets self.llm_client and self.exploit_llm_client
        self.summaries = {}
        self.masvs_mapping = self._load_masvs_mapping()
        
        self.apk_name = "target_app" # Default fallback
        self.vulnerability_findings = []
        self.analysis_errors = []  # [FIX #2] Files/rules that failed LLM analysis (NOT clean)
        
        # Load Call Graph Builder if enabled

    def _load_masvs_mapping(self):
        try:
            with open("config/knowledge_base/masvs_mapping.json", "r") as f:
                import json
                return json.load(f)
        except Exception as e:
            log.warning(f"Could not load MASVS mapping: {e}")
            return {}

    def _enrich_result(self, rule_name: str, result_dict: dict) -> dict:
        """Enriches the LLM result with static MASVS knowledge."""
        if rule_name in self.masvs_mapping:
            masvs_info = self.masvs_mapping[rule_name]
            result_dict["masvs_reference"] = {
                "id": masvs_info["masvs_id"],
                "description": masvs_info["description"],
                "link": masvs_info["reference"]
            }
        return result_dict

    def _setup_llm_client(self):
        """Builds `self.llm_client` (scanning/analysis) and `self.exploit_llm_client`
        (PoC generation). The two are the SAME object unless `llm.exploit_provider` or
        `llm.exploit_model` is set AND exploit generation is actually requested — some
        models refuse or silently return empty output for exploit/PoC generation while
        being fine for vulnerability analysis (see Updatev1.3.0.md). Building the
        exploit-specific client is skipped entirely when exploit generation is off, so a
        typo'd `exploit_provider` never breaks a normal scan."""
        if self.settings.analysis.use_cache:
            log.info("Response cache: ENABLED 💾")

        self.llm_client = self._build_llm_client(self.settings.llm.provider)
        self.exploit_llm_client = self.llm_client

        exploit_provider = self.settings.llm.exploit_provider
        exploit_model = self.settings.llm.exploit_model
        if self.settings.analysis.generate_exploit and (exploit_provider or exploit_model):
            effective_provider = exploit_provider or self.settings.llm.provider
            try:
                self.exploit_llm_client = self._build_llm_client(effective_provider, model_override=exploit_model)
                log.info(
                    f"Exploit generation routed to provider '{effective_provider}'"
                    + (f" (model override: {exploit_model})" if exploit_model else "")
                )
            except Exception as e:
                log.warning(
                    f"Failed to set up exploit_provider '{effective_provider}' ({e}); "
                    "falling back to the main provider/model for exploit generation."
                )
                self.exploit_llm_client = self.llm_client

    def _build_llm_client(self, provider: str, model_override: str = None):
        """Builds a cached client for `provider`. `model_override` lets a secondary use
        (exploit generation) pick a different model on that same provider than the one
        used for scanning/analysis; when None, that provider's own default model field
        is used (unchanged behavior)."""
        max_tokens = self.settings.llm.max_tokens  # [#6] Configurable output limit

        if provider == "ollama":
            model = model_override or self.settings.llm.model
            raw_client = OllamaClient(model=model, url=self.settings.llm.ollama_url, max_tokens=max_tokens)
        elif provider == "gemini":
            model = model_override or self.settings.llm.gemini_model
            raw_client = GeminiClient(model=model, api_key=self.settings.llm.gemini_api_key, max_tokens=max_tokens)
        elif provider == "groq":
            model = model_override or self.settings.llm.groq_model
            raw_client = GroqClient(model=model, api_key=self.settings.llm.groq_api_key, max_tokens=max_tokens)
        elif provider == "openai":
            model = model_override or self.settings.llm.openai_model
            raw_client = OpenAIClient(model=model, api_key=self.settings.llm.openai_api_key, max_tokens=max_tokens)
        elif provider == "anthropic":
            model = model_override or self.settings.llm.anthropic_model
            raw_client = AnthropicClient(model=model, api_key=self.settings.llm.anthropic_api_key, max_tokens=max_tokens)
        elif provider == "openrouter":
            model = model_override or self.settings.llm.openrouter_model
            raw_client = OpenRouterClient(model=model, api_key=self.settings.llm.openrouter_api_key, max_tokens=max_tokens)
        elif provider == "router9":
            model = model_override or self.settings.llm.router9_model
            raw_client = Router9Client(
                model=model,
                api_key=self.settings.llm.router9_api_key,
                base_url=self.settings.llm.router9_base_url,
                max_tokens=max_tokens,
            )
        else:
            raise ValueError(f"Unsupported LLM provider: {provider}")

        # [#4] Wrap in a content-addressed cache (resume + dedup). Key includes the model,
        # so mixing providers/models never collides.
        from core.llm_cache import CachedLLMClient
        cache_dir = "output/.dlh_cache"
        return CachedLLMClient(raw_client, cache_dir, model=model, enabled=self.settings.analysis.use_cache)

    def get_status(self, result: dict) -> str:
        """Determines status from the structured JSON result."""
        if result.get("is_vulnerable"):
            return "Vulnerable"
        return "Not Vulnerable"

    def _rule_should_run(self, rule_name: str, prompt_data: dict, content: str) -> bool:
        """
        [FIX #1] Per-rule regex gating for the deep-scan phase.

        In non-'llm_only' modes, skip a rule's LLM call when the rule declares one or
        more detection patterns and NONE of them match the file. Rules without any
        pattern (pure-logic rules like universal_logic_flaw) always run. Bad patterns
        fail open (run the LLM) so a broken regex never silently drops a rule.
        """
        if self.settings.analysis.filter_mode == "llm_only":
            return True

        import re
        rule_patterns = []
        if prompt_data.get("detection_pattern"):
            rule_patterns.append(prompt_data["detection_pattern"])
        static_block = prompt_data.get("static_analysis") or {}
        if static_block.get("patterns"):
            rule_patterns.extend(static_block["patterns"])

        if not rule_patterns:
            return True  # No pattern -> logic rule, always run.

        try:
            return any(re.search(p, content, re.IGNORECASE | re.DOTALL) for p in rule_patterns)
        except re.error as e:
            log.warning(f"Invalid detection pattern for rule '{rule_name}' ({e}); running LLM anyway.")
            return True

    def _is_failed_response(self, raw_result: str) -> bool:
        """[FIX #2] True when the LLM client soft-failed (empty response after retries)."""
        return not raw_result or not raw_result.strip()

    def _truncate_for_llm(self, text: str) -> str:
        """
        [#5] Guard against oversized file content blowing the context window / cost.

        Keeps the head (imports, class decl, early logic) and the tail (which holds any
        appended external dependency context), dropping the middle with an explicit marker
        so the LLM knows content was omitted. Controlled by analysis.max_input_chars (0 or
        negative disables truncation).
        """
        limit = self.settings.analysis.max_input_chars
        if not limit or limit <= 0 or len(text) <= limit:
            return text

        head_len = int(limit * 0.7)
        tail_len = limit - head_len
        omitted = len(text) - limit
        log.debug(f"Truncating LLM input: {len(text)} -> {limit} chars ({omitted} omitted).")
        return (
            text[:head_len]
            + f"\n\n... [TRUNCATED {omitted} chars to fit context limit] ...\n\n"
            + text[-tail_len:]
        )

    def _build_error_result(self, file_path: str, rule_name: str, vuln_name: str, reason: str = "empty") -> dict:
        """
        [FIX #2 / B] Report entry for a rule/file that could NOT be analyzed (not clean).

        reason:
          "empty"       -> LLM returned nothing after retries (soft-fail).
          "unparseable" -> LLM returned non-empty output that was not valid JSON
                           (common with local models that answer in prose instead of JSON).
        """
        self.analysis_errors.append({"file": file_path, "rule": rule_name, "reason": reason})
        if reason == "unparseable":
            error_msg = ("LLM returned unparseable output (not valid JSON — likely prose, "
                         "common with small local models). This file/rule was NOT verified — "
                         "treat as unanalyzed, not clean.")
        else:
            error_msg = ("LLM analysis failed (empty response after retries). "
                         "This file/rule was NOT verified — treat as unanalyzed, not clean.")
        return {
            "file": file_path,
            "rule": rule_name,
            "vulnerability": vuln_name,
            "status": "Error",
            "result": {
                "is_vulnerable": False,
                "status_detail": "UNANALYZED",
                "error": error_msg,
                "description": "Analysis could not be completed for this rule.",
            },
        }

    def _dedupe_findings(self, results: list) -> list:
        """
        [#E] Collapse overlapping 'Vulnerable' findings on the same file so the report isn't
        noisy. Two mechanisms, both INFORMATION-PRESERVING (merged findings are kept under
        'also_detected_by', never dropped):
          1. Family merge  — findings whose rules share a VULN_FAMILIES family (e.g. the
             WebView trio) on the same file collapse into the highest-severity one.
          2. Generic fold  — a GENERIC_RULES finding (universal_logic_flaw) on a file that
             also has a specific finding is folded into that finding; if it is the only
             finding on the file, it stays standalone.
        Non-'Vulnerable' entries (Not Vulnerable / Error) pass through untouched.
        """
        from collections import defaultdict

        def sev(r):
            return _SEVERITY_ORDER.get(str((r.get("result") or {}).get("severity", "")).lower(), 0)

        def brief(r):
            res = r.get("result") or {}
            return {
                "rule": r.get("rule"),
                "vulnerability": r.get("vulnerability"),
                "severity": res.get("severity"),
                "description": res.get("description"),
            }

        vulnerable = [r for r in results if str(r.get("status", "")).lower() == "vulnerable"]
        passthrough = [r for r in results if str(r.get("status", "")).lower() != "vulnerable"]

        by_file = defaultdict(list)
        for r in vulnerable:
            by_file[r.get("file")].append(r)

        deduped = []
        for _file, group in by_file.items():
            # (1) family merge
            fam_groups = defaultdict(list)
            for r in group:
                rule = r.get("rule") or r.get("vulnerability")
                fam_groups[VULN_FAMILIES.get(rule, f"__self__:{rule}")].append(r)
            merged = []
            for _fam, items in fam_groups.items():
                if len(items) == 1:
                    merged.append(items[0])
                    continue
                primary = max(items, key=sev)
                primary.setdefault("also_detected_by", [])
                primary["also_detected_by"].extend(brief(o) for o in items if o is not primary)
                merged.append(primary)

            # (2) generic fold
            generic = [m for m in merged if m.get("rule") in GENERIC_RULES]
            specific = [m for m in merged if m.get("rule") not in GENERIC_RULES]
            if generic and specific:
                host = max(specific, key=sev)
                host.setdefault("also_detected_by", [])
                host["also_detected_by"].extend(brief(g) for g in generic)
                deduped.extend(specific)
            else:
                deduped.extend(merged)

        return passthrough + deduped

    def _find_manifest_path(self, start_path: str) -> str:
        """Traverses up the directory tree to find AndroidManifest.xml."""
        current_dir = os.path.dirname(os.path.abspath(start_path))
        while current_dir != "/" and current_dir != "":
            manifest = os.path.join(current_dir, "AndroidManifest.xml")
            if os.path.exists(manifest):
                return manifest
            parent = os.path.dirname(current_dir)
            if parent == current_dir: break
            current_dir = parent
        return ""

    def _get_class_name(self, file_path: str) -> str:
        """Derives class name from file path for Manifest matching."""
        parts = file_path.replace("\\", "/").split("/")
        filename = parts[-1]
        name, _ = os.path.splitext(filename)
        
        # Try to reconstruct package from path (simple heuristic)
        # Stop at common root markers
        package_parts = [name]
        for part in reversed(parts[:-1]):
            if part in ["smali", "java", "src", "main", "decompiled"]:
                break
            package_parts.insert(0, part)
        
        return ".".join(package_parts)

    def _build_global_context(self) -> str:
        """Summarizes all findings into a global context string."""
        if not self.vulnerability_findings:
            return "No previous findings."
        
        summary = "Summary of Vulnerabilities found in other components:\n"
        for finding in self.vulnerability_findings:
            summary += f"- File: {os.path.basename(finding['file_path'])}\n"
            summary += f"  - Vulnerability: {finding['rule_name']}\n"
            summary += f"  - Description: {finding['vuln_description'][:200]}...\n"
        return summary

    def _generate_chained_exploits(self):
        """Iterates through findings and generates exploits using global context."""
        global_context = self._build_global_context()
        log.info("Generating Chained Exploits with Global Context...")
        
        for finding in self.vulnerability_findings:
            self._generate_poc(
                finding["file_path"],
                finding["code_snippet"],
                finding["vuln_description"],
                finding["rule_name"],
                global_context
            )

    def _is_relevant_file(self, file_path: str, package_name: str) -> bool:
        """
        Determines if a file is relevant for analysis based on package scope and blocklist.
        """
        # Blocklist (Libraries to ignore)
        blocklist = [
            "android/", "androidx/", "com/google/", "kotlin/", 
            "okhttp3/", "retrofit2/", "io/reactivex/", "dagger/",
            "b/b/p/", "b/j/a/" # Obfuscated common libs often seen
        ]
        
        # Normalize path
        normalized_path = file_path.replace("\\", "/")
        
        # [FIX] Logic Reordered: Check Whitelist (Package Name) FIRST
        # This prevents apps like 'com.google.myapp' from being blocked by 'com/google/' in blocklist.
        
        # 1. Check Whitelist (Package Name)
        if package_name and "." in package_name:
            package_path = package_name.replace(".", "/")
            if package_path in normalized_path:
                return True
        
        # [V1.1.7 Library Hunter]
        if self.settings.analysis.scan_libraries:
            # If Library Hunter is active, we WANT to see files in the blocklist.
            # We specifically look FOR them.
            # However, we still might want to filter out 'standard java/kotlin' runtime stuff if it's too noisy,
            # but for now, let's just bypass the blocklist check if this mode is on.
            pass 
        else:
            # Standard Mode: Block libraries
            for blocked in blocklist:
                if blocked in normalized_path:
                    # Double Check: Is it actually the app's package?
                    # Sometimes apps use package names that look like libraries? (Rare)
                    return False
            
        # If no package name extracted and not blocked, allow it.
        return True

    def _detect_poc_extension(self, poc_content: str) -> str:
        """Picks the file extension for a generated PoC/verification script.

        The FIRST LINE is authoritative when it matches what `exploit_prompt.txt`
        instructs the model to emit there (a shebang for Bash/Python; an opening
        token for Frida JS/HTML) — checked BEFORE any whole-content substring scan.

        Why: a Bash script may legitimately EMBED another language, e.g. a
        `python3 - << 'EOF' ... EOF` heredoc, because Bash can't easily do things
        like background logcat monitoring on its own. That embedded block contains
        "import "/"def " just like standalone Python would. Scanning the WHOLE
        content for those substrings (the old approach) misclassified such a script
        as ".py" even though it starts with `#!/bin/bash` and is a single, valid,
        directly-executable Bash script — the heredoc is an implementation detail,
        not a second top-level script. The first line is what actually determines
        how the file executes (the OS reads the shebang), so it must win.
        """
        first_line = poc_content.split("\n", 1)[0].strip()

        if first_line.startswith("#!"):
            if "python" in first_line:
                return ".py"
            if "bash" in first_line or first_line.endswith("sh"):
                return ".sh"
        elif first_line.startswith("Java.perform(") or first_line.startswith("setTimeout("):
            return ".js"
        elif first_line.lower().startswith(("<!doctype", "<html")):
            return ".html"

        # No (recognized) first-line signal -> fall back to content sniffing, for the
        # rare case the model doesn't follow the "start with X" instruction.
        if "Java.perform(" in poc_content or "Java.use(" in poc_content or "console.log(" in poc_content:
            return ".js"
        if "<html" in poc_content.lower() or "<script" in poc_content.lower() or "<!doctype" in poc_content.lower():
            return ".html"
        if "import " in poc_content or "def " in poc_content:
            return ".py"
        if "#!/bin/bash" in poc_content or "#!/bin/sh" in poc_content or "adb shell" in poc_content:
            return ".sh"
        return ".txt"

    def _generate_poc(self, file_path: str, code_snippet: str, vuln_description: str, rule_name: str, global_context: str = ""):
        """Generates a PoC script for a confirmed vulnerability."""
        try:
            # [NEW] Manifest Context Injection
            manifest_context = "Manifest not found or Context Injection disabled."
            if self.settings.analysis.use_cross_reference_context: # Reuse context flag or always on? User asked for accuracy.
                manifest_path = self._find_manifest_path(file_path)
                if manifest_path:
                    parser = ManifestParser(manifest_path)
                    class_name = self._get_class_name(file_path)
                    details = parser.get_component_details(class_name)
                    if details and details.get("context_str"):
                        manifest_context = details["context_str"]
                        log.info(f"Injecting Manifest Context for {class_name}")

            # [NEW] Hardcoded Secrets "Auto-Fill"
            # We use a temporary CodeFilter instance to reuse its regex logic, or the main one if available.
            # Since CodeFilter need decompiled_dir, we can pass a dummy one if we just use extract_secrets(content).
            detected_secrets_str = "None detected."
            try:
                # Assuming CodeFilter is imported. We can use a lightweight instance or static method if refactored.
                # But extract_secrets is an instance method.
                # Let's instantiate it with a dummy path since we only process the snippet string here.
                temp_filter = CodeFilter(decompiled_dir="/tmp", mode="java") 
                secrets = temp_filter.extract_secrets(code_snippet)
                if secrets:
                    detected_secrets_str = ""
                    for s in secrets:
                        detected_secrets_str += f"- {s['type']}: \"{s['value']}\"\n"
                    log.info(f"Injecting {len(secrets)} detected secrets into prompt.")
            except Exception as e:
                log.warning(f"Secret extraction failed: {e}")

            # [LOGIC GUARD] Skip exploit generation if "Hardcoded Secrets" is the issue but Regex found nothing.
            if rule_name == "Hardcoded Secrets" and detected_secrets_str == "None detected.":
                log.warning(f"Skipping exploit generation for {os.path.basename(file_path)}: Vulnerability is 'Hardcoded Secrets' but no actual secrets extracted by Regex.")
                return "" # Return empty string to signal skip

            with open("config/prompts/exploit_prompt.txt", "r") as f:
                prompt_template = f.read()
            
            prompt = prompt_template.replace("{vulnerability_description}", vuln_description)
            prompt = prompt.replace("{file_path}", file_path)
            prompt = prompt.replace("{manifest_context}", manifest_context) # Inject Manifest
            prompt = prompt.replace("{detected_secrets}", detected_secrets_str) # Inject Secrets
            prompt = prompt.replace("{global_context}", global_context) # [V1.1.3] Inject Global Context
            prompt = prompt.replace("{code_snippet}", code_snippet[:8000]) 

            
            log.info(f"Generating PoC for {rule_name} in {os.path.basename(file_path)}...")
            
            # The 'prompt' variable is now fully constructed with all placeholders replaced.
            # We pass this as the 'system_prompt' (or 'vuln_prompt') to the LLM client.
            # We pass "" as the code_snippet to analyze_code because we already injected it into the prompt.
            
            context_wrapper = {
                "system_prompt": "You are a Red Team Exploit Developer.",
                "vuln_prompt": prompt, 
                "file_path": file_path
            }
            
            # Note: analyze_code in some clients might try to formatting vuln_prompt if code_snippet is provided.
            # Since we pass prompt (which has no braces left ideally) and empty code_snippet, it should be safe.
            # However, prompt likely contains code with braces.
            # To be safe against client-side formatting, we can pass the whole prompt as system_prompt
            # and empty vuln_prompt, or rely on client implementation.
            # Most clients: f"{system_prompt}\n\n{vuln_prompt}" (no format called if code_snippet is empty or if client checks).
            
            # Let's try passing the full prompt as system_prompt to avoid any client-side formatting magic on '{...}' inside code.
            
            context_wrapper_safe = {
                "system_prompt": prompt,
                "vuln_prompt": "",
                "file_path": file_path
            }
            
            poc_content = self.exploit_llm_client.analyze_code("", context_wrapper_safe)
            
            if not poc_content:
                log.warning("PoC generation returned empty.")
                return

            # [FIX] Strip markdown code fences that LLMs often wrap output with.
            # e.g. ```bash\n...\n``` or ```python\n...\n```
            # This ensures the saved file is directly executable without manual editing.
            import re as _re
            # Strategy 1: Extract content inside a fenced block if present
            _fence_match = _re.search(r'^```[a-zA-Z]*\s*\n(.*?)\n```\s*$', poc_content.strip(), _re.DOTALL)
            if _fence_match:
                poc_content = _fence_match.group(1).strip()
                log.debug("Stripped markdown code fence from PoC content.")
            else:
                # Strategy 2: Strip leading/trailing fence markers if partial
                poc_content = _re.sub(r'^```[a-zA-Z]*\s*\n?', '', poc_content.strip())
                poc_content = _re.sub(r'\n?```\s*$', '', poc_content.strip())
                poc_content = poc_content.strip()

            ext = self._detect_poc_extension(poc_content)

            # Use the pre-calculated exploit directory from 'run' if available, otherwise fallback
            if hasattr(self, 'final_exploit_dir') and self.final_exploit_dir:
                 exploit_dir = self.final_exploit_dir
            else:
                 # Fallback (shouldn't happen in normal flow)
                 clean_name = self.apk_name
                 if clean_name.lower().endswith(".apk"):
                     clean_name = clean_name[:-4]
                 exploit_dir = f"output/{clean_name}_exploits"

            os.makedirs(exploit_dir, exist_ok=True)
            
            filename = f"{rule_name}_{os.path.basename(file_path)}{ext}"
            save_path = os.path.join(exploit_dir, filename)
            
            with open(save_path, "w") as f:
                f.write(poc_content)
            
            # [FIX] Auto chmod +x for shell scripts so they are immediately runnable
            if ext == ".sh":
                import stat as _stat
                current_mode = os.stat(save_path).st_mode
                os.chmod(save_path, current_mode | _stat.S_IXUSR | _stat.S_IXGRP | _stat.S_IXOTH)
                log.debug(f"chmod +x applied to {filename}")
                
            log.success(f"PoC saved to {save_path}")

        except Exception as e:
            log.error(f"Failed to generate PoC: {e}")

    def _extract_json_str(self, text: str) -> str:
        """
        Extracts the first balanced JSON object by counting braces, while ignoring
        any braces that appear INSIDE string values.

        String-awareness matters because the `evidence` field routinely contains a
        code snippet with its own `{`/`}` and even nested markdown fences (```java
        ... ```). A naive counter miscounts those braces, and stripping fences with a
        non-greedy regex truncates the JSON at the first inner ``` — both silently
        drop otherwise-valid findings. Respecting string boundaries (and `\\` escapes)
        makes brace-counting robust to arbitrary content inside string values.
        """
        text = text.strip()
        start_idx = text.find('{')
        if start_idx == -1:
            return ""

        balance = 0
        in_string = False
        escaped = False
        for i in range(start_idx, len(text)):
            char = text[i]
            if in_string:
                if escaped:
                    escaped = False
                elif char == '\\':
                    escaped = True
                elif char == '"':
                    in_string = False
                continue

            if char == '"':
                in_string = True
            elif char == '{':
                balance += 1
            elif char == '}':
                balance -= 1
                if balance == 0:
                    return text[start_idx:i+1]
        return ""

    def _parse_llm_response(self, response: str) -> dict:
        """Parses the LLM response string into a dictionary, handling potential formatting issues."""
        import json
        import re
        import ast

        # Strategy 0: String-aware brace counting on the RAW response.
        # find('{') skips any leading ```json fence automatically, and the counter
        # ignores braces / nested ``` fences that live inside string values (e.g. a
        # code snippet in the "evidence" field). Running this FIRST — before any
        # fence stripping — avoids the classic failure where a non-greedy fence regex
        # truncates the JSON at the first ``` found inside a string value.
        json_candidate = self._extract_json_str(response)

        # Strategy 1: Fallback — strip surrounding markdown fences, then retry.
        # Covers responses where the object isn't cleanly balanced in the raw text.
        cleaned_response = re.sub(r'^```[a-zA-Z]*\s*\n?', '', response.strip())
        cleaned_response = re.sub(r'\n?\s*```\s*$', '', cleaned_response).strip()
        if not json_candidate:
            json_candidate = self._extract_json_str(cleaned_response)
        if not json_candidate:
            # Last resort: greedy brace match (may over-capture, tried after the above)
            match = re.search(r'\{.*\}', cleaned_response, re.DOTALL)
            json_candidate = match.group(0) if match else cleaned_response

        # List of candidate strings to try parsing
        candidates = [json_candidate, cleaned_response, response]
        
        for candidate in candidates:
            if not candidate: continue
            try:
                # strict=False allows control characters like newlines in strings
                return json.loads(candidate, strict=False)
            except json.JSONDecodeError:
                # Sub-strategy: Fix common JSON issues (trailing commas)
                try:
                    fixed_json = re.sub(r',\s*([\]\}])', r'\1', candidate)
                    return json.loads(fixed_json, strict=False)
                except:
                    pass
                
                # Sub-strategy: Python AST Fallback (Single quotes, etc.)
                try:
                    return ast.literal_eval(candidate)
                except:
                    pass

        log.warning(f"Failed to parse LLM response as JSON. Raw: {response[:100]}...")
        return {
                "_parse_failed": True,  # [B] Signals unparseable (non-empty) output to callers.
                "is_vulnerable": False,
                "severity": "Info",
                "confidence": "Low",
                "evidence": "",
                "description": "Failed to parse LLM response. Please review raw output.",
                "attack_scenario": "N/A (Parsing Failed)",
                "attacker_priority": "N/A",
                "recommendation": "Check raw LLM output for details.",
                "false_positive_analysis": "Parsing failed."
            }

    def _file_to_class_dotted(self, file_path: str):
        """Best-effort fully-qualified (dotted) class name from a decompiled file path,
        used to look up the component's AndroidManifest entry. Handles JADX (`.../sources/`)
        and apktool (`.../smali/` or `.../smali_classesN/`) layouts."""
        import re
        p = str(file_path).replace("\\", "/")
        rel = None
        if "/sources/" in p:
            rel = p.split("/sources/", 1)[1]
        else:
            m = re.search(r"/smali(?:_classes\d+)?/", p)
            if m:
                rel = p[m.end():]
        if not rel:
            return None
        for ext in (".java", ".smali"):
            if rel.endswith(ext):
                rel = rel[: -len(ext)]
                break
        return rel.replace("/", ".") if rel else None

    def _manifest_context_for(self, file_path: str) -> str:
        """[B] Inject the component's AndroidManifest entry (exported status, permission,
        intent-filters) into the LLM input so IPC/exported-dependent rules (intent_redirection,
        pending_intent_hijacking, fragment_injection, …) do not have to GUESS reachability.
        The parsing already exists in ManifestParser.get_component_details()."""
        parser = getattr(self, "manifest_parser", None)
        if parser is None:
            return ""
        cls = self._file_to_class_dotted(file_path)
        if not cls:
            return ""
        try:
            details = parser.get_component_details(cls)
        except Exception:
            return ""
        if not details or not details.get("context_str"):
            return ""
        return (
            "\n\n### COMPONENT CONTEXT (from AndroidManifest.xml)\n"
            "Authoritative reachability facts for this class — use them, do NOT guess the exported status:\n"
            + details["context_str"]
        )

    def analyze_file(self, file_path, rules_to_run: list = None):
        results = []
        with open(file_path, "r", encoding="utf-8") as f:
            code_snippet = f.read()
            
        # Context Injection via Call Graph
        external_context = ""
        if self.call_graph_builder and self.settings.analysis.use_cross_reference_context:
            dependency_classes = self.call_graph_builder.get_dependencies(file_path)
            if dependency_classes:
                # Map each summarized file to its class name, so a dependency's summary
                # can be attached whether it was summarized as .java (JADX/hybrid) or
                # .smali (apktool). This is what makes context injection work in hybrid
                # mode, where analyzed files are .java but the call graph is Smali-based.
                class_to_summary = {}
                for summ_path, summ in self.summaries.items():
                    cls = self.call_graph_builder.path_to_class(summ_path)
                    if cls:
                        class_to_summary[cls] = summ

                # Smart Filtering: only inject a dependency's context when we actually
                # have its summary AND its short class name is referenced in this file.
                relevant_summaries = []
                for dep_class in dependency_classes:
                    short_name = dep_class.split("/")[-1]
                    summary = class_to_summary.get(dep_class)

                    # JADX bundles inner classes into the parent .java; fall back to the outer class.
                    if not summary and "$" in dep_class:
                        summary = class_to_summary.get(dep_class.split("$", 1)[0])

                    if summary:
                        java_ref = short_name.replace("$", ".")
                        if short_name in code_snippet or java_ref in code_snippet:
                            relevant_summaries.append(f"- Class {java_ref}: {summary}")

                if relevant_summaries:
                    external_context = "\n\n### EXTERNAL CONTEXT (Dependencies)\n"
                    external_context += "The following are summaries of classes called by this file. Use this to verify inputs/outputs and reduce false positives.\n"
                    external_context += "\n".join(relevant_summaries)
        
        # Combine snippets for the prompt
        full_code_context = code_snippet + external_context
        # [#5] Cap oversized content before it reaches the LLM.
        full_code_context = self._truncate_for_llm(full_code_context)

        # [B] Reachability context from the manifest. Kept OUT of `full_code_context` so it
        # doesn't affect per-rule pattern gating; appended only to what the LLM actually sees
        # (it's small, so it survives after truncation).
        llm_input = full_code_context + self._manifest_context_for(file_path)

        # [V1.1.7 Library Hunter - Exclusive Mode]
        # Logic: If this is a 3rd party library file, we run ONLY the specialized audit prompt.
        # This saves tokens by not running the 20+ standard rules on generic library code.
        
        is_library_file = False
        library_prefixes = [
            "android/", "androidx/", "com/google/", "kotlin/", 
            "okhttp3/", "retrofit2/", "io/reactivex/", "dagger/",
            "b/b/p/", "b/j/a/"
        ]
        normalized_path = file_path.replace("\\", "/")
        
        for prefix in library_prefixes:
            if prefix in normalized_path:
                is_library_file = True
                break
        
        if self.settings.analysis.scan_libraries and is_library_file:
             log.info(f"Library Scan Triggered for: {os.path.basename(file_path)}")
             prompt_path = "config/prompts/vuln_rules/library_vulnerability.yaml"
             if os.path.exists(prompt_path):
                 with open(prompt_path, "r") as f:
                     prompt_data = yaml.safe_load(f)
                 
                 # [V1.1.7 Optimization] Hybrid Filter
                 # Check regex pattern before calling LLM
                 if self.settings.analysis.filter_mode != "llm_only":
                     pattern = prompt_data.get("detection_pattern")
                     if pattern:
                         import re
                         if not re.search(pattern, full_code_context, re.IGNORECASE | re.DOTALL):
                             log.debug(f"Skipping library file {os.path.basename(file_path)}: No suspicious pattern found.")
                             return results

                 # Prepare Context
                 system_prompt = self._load_system_prompt()
                 
                 context = {
                    "system_prompt": system_prompt,
                    "vuln_prompt": prompt_data["prompt"] + JSON_ONLY_SUFFIX,
                    "file_path": file_path,
                    "expect_json": True  # [A] Rule analysis requires JSON output
                 }

                 # Run Analysis
                 try:
                     raw_result = self.llm_client.analyze_code(llm_input, context)

                     # [FIX #2] A failed LLM call must not read as a clean library.
                     if self._is_failed_response(raw_result):
                         log.warning(f"LLM library scan failed for {os.path.basename(file_path)}; marking as Error (not clean).")
                         results.append(self._build_error_result(file_path, "library_vulnerability", "Library Hunter"))
                         return results

                     parsed_result = self._parse_llm_response(raw_result)

                     # [B] Non-empty but unparseable (e.g. prose from a local model) -> Error, not clean.
                     if parsed_result.get("_parse_failed"):
                         log.warning(f"Unparseable LLM output for library scan of {os.path.basename(file_path)}; marking as Error.")
                         results.append(self._build_error_result(file_path, "library_vulnerability", "Library Hunter", reason="unparseable"))
                         return results

                     status = self.get_status(parsed_result)

                     if status == "Vulnerable":
                         parsed_result = self._enrich_result("library_vulnerability", parsed_result)
                         if self.settings.analysis.generate_exploit:
                              self.vulnerability_findings.append({
                                  "file_path": file_path,
                                  "code_snippet": full_code_context,
                                  "vuln_description": parsed_result.get("description", ""),
                                  "rule_name": "library_vulnerability"
                              })

                         results.append({
                            "file": file_path,
                            "rule": "library_vulnerability",
                            "vulnerability": "Library Hunter",
                            "status": status,
                            "result": parsed_result
                         })
                 except Exception as e:
                     log.error(f"Library Scan failed for {file_path}: {e}")
             
             # [CRITICAL OPTIMIZATION] Early Return!
             # We assume standard logic rules (like 'Intent Spoofing' in App Logic) are less relevant 
             # for granular library internals, or are covered by the general 'Library Audit' prompt.
             return results

        for rule_name, enabled in self.settings.rules.model_dump().items():
            if enabled and rule_name not in DEDICATED_PASS_RULES:
                if rules_to_run and rule_name not in rules_to_run:
                    continue
                prompt_path = f"config/prompts/vuln_rules/{rule_name}.yaml"
                with open(prompt_path, "r") as f:
                    prompt_data = yaml.safe_load(f)

                # [FIX #1] Skip this rule's LLM call if its detection pattern doesn't match.
                if not self._rule_should_run(rule_name, prompt_data, full_code_context):
                    log.debug(f"Gated: rule '{rule_name}' skipped for {os.path.basename(file_path)} (no pattern match).")
                    continue

                # --- MASVS CONTEXT INJECTION (LITE RAG) ---
                system_prompt = self._load_system_prompt()
                
                
                # Check if this rule maps to a MASVS ID
                if rule_name in self.masvs_mapping:
                    masvs_info_data = self.masvs_mapping[rule_name]
                    masvs_id = masvs_info_data.get("masvs_id", "Unknown")
                    masvs_desc = masvs_info_data.get("description", "No description available.")
                    
                    # Append guidance to the system prompt
                    system_prompt += f"\n\n### OWASP MASVS GUIDANCE\n"
                    system_prompt += f"This analysis relates to **{masvs_id}**.\n"
                    system_prompt += f"Standard: \"{masvs_desc}\"\n"
                    system_prompt += f"Ensure your verification aligns strictly with this standard."

                # [A] Rule prompts are language-agnostic ("Java or Smali"), so the old
                # vuln_prompt.replace("smali","java") hack has been retired.
                vuln_prompt = prompt_data["prompt"]

                context = {
                    "system_prompt": system_prompt,
                    "vuln_prompt": vuln_prompt + JSON_ONLY_SUFFIX,
                    "file_path": file_path,
                    "expect_json": True  # [A] Rule analysis requires JSON output
                }

                # Pass the ENRICHED context (code + cross-ref + manifest reachability)
                raw_result = self.llm_client.analyze_code(llm_input, context)

                # [FIX #2] Distinguish a failed LLM call from a genuine "clean" verdict.
                if self._is_failed_response(raw_result):
                    log.warning(f"LLM analysis failed for rule '{rule_name}' on {os.path.basename(file_path)}; marking as Error (not clean).")
                    results.append(self._build_error_result(file_path, rule_name, prompt_data["name"]))
                    continue

                parsed_result = self._parse_llm_response(raw_result)

                # [B] Non-empty but unparseable (e.g. prose from a local model) -> Error, not clean.
                if parsed_result.get("_parse_failed"):
                    log.warning(f"Unparseable LLM output for rule '{rule_name}' on {os.path.basename(file_path)}; marking as Error.")
                    results.append(self._build_error_result(file_path, rule_name, prompt_data["name"], reason="unparseable"))
                    continue

                status = self.get_status(parsed_result)

                # Enrich with MASVS
                if status == "Vulnerable":
                    parsed_result = self._enrich_result(rule_name, parsed_result)
                    
                    # Instead of generating PoC immediately, we store the finding.
                    if self.settings.analysis.generate_exploit:
                         self.vulnerability_findings.append({
                             "file_path": file_path,
                             "code_snippet": full_code_context,
                             "vuln_description": parsed_result.get("description", ""),
                             "rule_name": rule_name
                         })

                results.append({
                    "file": file_path,
                    "rule": rule_name,
                    "vulnerability": prompt_data["name"],
                    "status": status,
                    "result": parsed_result # Store the full structured object
                })
        return results

    def analyze_manifest(self, manifest_path, rules_to_run: list = None):
        results = []
        with open(manifest_path, "r", encoding="utf-8") as f:
            code_snippet = f.read()

        for rule_name in MANIFEST_RULES:
            if getattr(self.settings.rules, rule_name):
                if rules_to_run and rule_name not in rules_to_run:
                    continue
                prompt_path = f"config/prompts/vuln_rules/{rule_name}.yaml"
                with open(prompt_path, "r") as f:
                    prompt_data = yaml.safe_load(f)

                context = {
                    "system_prompt": self._load_system_prompt(),
                    "vuln_prompt": prompt_data["prompt"] + JSON_ONLY_SUFFIX,
                    "file_path": manifest_path,
                    "expect_json": True  # [A] Rule analysis requires JSON output
                }

                raw_result = self.llm_client.analyze_code(code_snippet, context)

                # [FIX #2] Failed manifest analysis is not a clean verdict.
                if self._is_failed_response(raw_result):
                    log.warning(f"LLM analysis failed for manifest rule '{rule_name}'; marking as Error (not clean).")
                    results.append(self._build_error_result(manifest_path, rule_name, prompt_data["name"]))
                    continue

                parsed_result = self._parse_llm_response(raw_result)

                # [B] Non-empty but unparseable output -> Error, not clean.
                if parsed_result.get("_parse_failed"):
                    log.warning(f"Unparseable LLM output for manifest rule '{rule_name}'; marking as Error.")
                    results.append(self._build_error_result(manifest_path, rule_name, prompt_data["name"], reason="unparseable"))
                    continue

                status = self.get_status(parsed_result)

                # Enrich with MASVS
                if status == "Vulnerable":
                    parsed_result = self._enrich_result(rule_name, parsed_result)
                    
                    if self.settings.analysis.generate_exploit:
                         self.vulnerability_findings.append({
                             "file_path": manifest_path,
                             "code_snippet": code_snippet,
                             "vuln_description": parsed_result.get("description", ""),
                             "rule_name": rule_name
                         })

                results.append({
                    "file": manifest_path,
                    "rule": rule_name,
                    "vulnerability": prompt_data["name"],
                    "status": status,
                    "result": parsed_result
                })
        return results

    def analyze_strings_xml(self, decompiled_dir: str, rules_to_run: list = None):
        """Scans res/values/strings.xml for hardcoded secrets."""
        results = []
        rule_name = "hardcoded_secrets_xml"
        
        if not getattr(self.settings.rules, rule_name):
            return []

        if rules_to_run and rule_name not in rules_to_run:
            return []

        # Find strings.xml
        strings_path = None
        for root, _, files in os.walk(decompiled_dir):
            if "strings.xml" in files:
                # Prioritize res/values/strings.xml
                potential = os.path.join(root, "strings.xml")
                if "values" in root.split(os.sep): 
                     strings_path = potential
                     break
                # Fallback to any strings.xml if not in valus (unlikely but possible)
                if not strings_path:
                    strings_path = potential

        if not strings_path:
            log.warning("strings.xml not found in decompiled output.")
            return []

        log.info(f"Analyzing {strings_path} for Hardcoded Secrets...")
        
        with open(strings_path, "r", encoding="utf-8") as f:
            code_snippet = f.read()

        prompt_path = f"config/prompts/vuln_rules/{rule_name}.yaml"
        with open(prompt_path, "r") as f:
            prompt_data = yaml.safe_load(f)

        context = {
            "system_prompt": self._load_system_prompt(),
            "vuln_prompt": prompt_data["prompt"] + JSON_ONLY_SUFFIX,
            "file_path": strings_path,
            "expect_json": True  # [A] Rule analysis requires JSON output
        }

        raw_result = self.llm_client.analyze_code(code_snippet, context)

        # [FIX #2] Failed strings.xml analysis is not a clean verdict.
        if self._is_failed_response(raw_result):
            log.warning(f"LLM analysis failed for '{rule_name}' on strings.xml; marking as Error (not clean).")
            return [self._build_error_result(strings_path, rule_name, prompt_data["name"])]

        parsed_result = self._parse_llm_response(raw_result)

        # [B] Non-empty but unparseable output -> Error, not clean.
        if parsed_result.get("_parse_failed"):
            log.warning(f"Unparseable LLM output for '{rule_name}' on strings.xml; marking as Error.")
            return [self._build_error_result(strings_path, rule_name, prompt_data["name"], reason="unparseable")]

        status = self.get_status(parsed_result)

        if status == "Vulnerable":
            # [V1.1.3] DEFERRED GENERATION
            if self.settings.analysis.generate_exploit:
                    self.vulnerability_findings.append({
                        "file_path": strings_path,
                        "code_snippet": code_snippet,
                        "vuln_description": parsed_result.get("description", ""),
                        "rule_name": rule_name
                    })

        results.append({
            "file": strings_path,
            "rule": rule_name,
            "vulnerability": prompt_data["name"],
            "status": status,
            "result": parsed_result
        })
        return results

    def summarize_chunks(self, decompiled_dir: str, file_list: list = None):
        log.info("Starting code summarization...")
        summaries = {}
        summarize_prompt = self._load_summarize_prompt()

        files_to_process = []
        if file_list:
             files_to_process = file_list
        else:
            for root, _, files in os.walk(decompiled_dir):
                for file in files:
                    if file.endswith(".smali"):
                        files_to_process.append(os.path.join(root, file))

        for file_path in track(files_to_process, description="Summarizing code...", console=console):
            with open(file_path, "r", encoding="utf-8") as f:
                content = f.read()

            # Chunk by class only for Smali, where each class is its own ".class " block.
            # Java/Kotlin sources (JADX/hybrid) don't use that token — splitting on it would
            # either leave the whole file as one misleadingly-prefixed chunk or mis-slice at
            # class literals (e.g. `Foo.class ==`), so treat the file as a single chunk.
            if file_path.endswith(".smali"):
                chunks = [".class " + c for c in content.split(".class ") if c.strip()]
            else:
                chunks = [content] if content.strip() else []

            # [FIX #3] Accumulate every chunk's summary per file instead of overwriting.
            # A multi-class Smali file has several ".class" chunks; keeping only the last
            # one lost context used by risk identification and cross-reference injection.
            file_summaries = []
            for full_chunk in chunks:
                context = {
                    "system_prompt": "",
                    "vuln_prompt": summarize_prompt,
                    "file_path": file_path
                }

                # [#5] Cap oversized chunks before summarization too.
                summary = self.llm_client.analyze_code(self._truncate_for_llm(full_chunk), context)
                if summary and summary.strip():
                    file_summaries.append(summary.strip())
                log.debug(f"Summary for {file_path}: {summary}")

            summaries[file_path] = "\n".join(file_summaries)

        log.success("Code summarization complete.")
        return summaries

    def identify_risky_chunks(self, summaries: dict):
        log.info("Identifying risky code chunks...")
        risky_files = []
        identify_risk_prompt = self._load_identify_risk_prompt()

        for file_path, summary in track(summaries.items(), total=len(summaries), description="Identifying risky files...", console=console):
            context = {
                "system_prompt": "",
                "vuln_prompt": identify_risk_prompt,
                "file_path": file_path
            }
            
            response = self.llm_client.analyze_code(summary, context)
            
            if "yes" in response.lower():
                risky_files.append(file_path)
                log.debug(f"Identified risky file: {file_path}")

        log.success(f"Identified {len(risky_files)} risky files.")
        return risky_files

    def _pattern_matched_files(self, files: list, patterns: list, app_package_name: str = "") -> list:
        """First-party files whose content matches an enabled rule's detection_pattern.

        A static pattern hit is a STRONG signal, so these files must reach the deep-scan
        (where per-rule gating + the rule LLM decide the verdict) and must NOT be dropped
        by the coarse LLM risk-triage. Layer-2 bug this fixes: ZipSlipActivity matched the
        zip_slip pattern yet identify_risky_chunks judged it "not risky" and dropped it
        before any rule ran. Scoped to the app package so the added deep-scan cost stays
        bounded to first-party code (library files still go through the normal triage).
        """
        import re
        compiled = []
        for p in patterns:
            try:
                compiled.append(re.compile(p, re.IGNORECASE | re.DOTALL))
            except re.error:
                continue
        if not compiled:
            return []
        pkg_frag = app_package_name.replace(".", os.sep) if app_package_name else None
        hits = []
        for f in files:
            if pkg_frag and pkg_frag not in f:
                continue  # only rescue first-party files from the risk-triage
            try:
                with open(f, "r", encoding="utf-8", errors="ignore") as fh:
                    content = fh.read()
            except OSError:
                continue
            if any(rx.search(content) for rx in compiled):
                hits.append(f)
        return hits

    def summarize_app(self, manifest_path: str, summaries: dict):
        log.info("Summarizing application capabilities...")
        
        with open(manifest_path, "r", encoding="utf-8") as f:
            manifest = f.read()
            
        summaries_text = "\n".join(f"- {file_path}: {summary}" for file_path, summary in summaries.items())
        
        prompt = self._load_app_summary_prompt().format(manifest=manifest, summaries=summaries_text)
        # Escape curly braces to prevent double formatting issues in analyze_code
        prompt = prompt.replace("{", "{{").replace("}", "}}")
        
        context = {
            "system_prompt": "",
            "vuln_prompt": prompt,
            "file_path": manifest_path
        }
        
        app_summary = self.llm_client.analyze_code("", context)
        log.success("Application capabilities summarized.")
        return app_summary

    def generate_attack_surface_map(self, manifest_path: str, summaries: dict):
        """[v1.3.0] Returns a compact, structured INVENTORY dict (exported components,
        deep links, network/IPC/file-io/deserialization/reflection signals, manifest
        flags) — not a narrative report. A downstream tool (e.g. an HTML report) is
        expected to render this into bullets/tables itself. Kept small on purpose:
        the per-file vulnerability findings already carry the detailed explanations."""
        log.info("Generating attack surface map...")

        with open(manifest_path, "r", encoding="utf-8") as f:
            manifest = f.read()

        summaries_text = "\n".join(f"- {file_path}: {summary}" for file_path, summary in summaries.items())

        prompt = self._load_attack_surface_prompt().format(manifest=manifest, summaries=summaries_text)
        # Escape curly braces to prevent double formatting issues in analyze_code
        prompt = prompt.replace("{", "{{").replace("}", "}}")

        context = {
            "system_prompt": "",
            "vuln_prompt": prompt,
            "file_path": manifest_path,
            "expect_json": True  # force JSON mode on providers that support it (e.g. Ollama)
        }

        raw_result = self.llm_client.analyze_code("", context)

        if self._is_failed_response(raw_result):
            log.warning("Attack surface map generation failed (empty LLM response).")
            return {"error": "LLM call failed (empty response)"}

        parsed = self._parse_llm_response(raw_result)
        if parsed.get("_parse_failed"):
            log.warning("Attack surface map response was not valid JSON.")
            return {"error": "Unparseable LLM output", "raw": raw_result[:500]}

        log.success("Attack surface map generated.")
        return parsed

    def _find_smali_fallback(self, java_path: str, output_dir: str) -> str:
        """Helper to find corresponding smali file for a java file."""
        # Java: output/src_jadx/com/example/MainActivity.java
        # Smali: output/smali/com/example/MainActivity.smali
        # This is a heuristic translation
        try:
             # Remove prefix up to package
             rel_path = java_path.split("sources/")[-1] 
             if not rel_path: return None
             
             smali_path = os.path.join(output_dir, "smali", rel_path.replace(".java", ".smali"))
             if os.path.exists(smali_path):
                 return smali_path
        except:
             pass
        return None

    def run(self, apk_path: str, output_file: str = None, no_decompile: bool = False, rules: str = None):
        log.info(f"Starting analysis of {apk_path}...")
        
        rules_to_run = rules.split(',') if rules else None
        
        # [V1.1.4] XAPK Auto-Extraction Support
        if apk_path.lower().endswith(".xapk"):
             log.info(f"Detected XAPK file: {apk_path}. Attempting to extract...")
             xapk_name = os.path.basename(apk_path)
             temp_extract_dir = f"output/temp_xapk_{xapk_name}"
             os.makedirs(temp_extract_dir, exist_ok=True)
             
             try:
                 with zipfile.ZipFile(apk_path, 'r') as zip_ref:
                     zip_ref.extractall(temp_extract_dir)
                 
                 # Find the largest .apk file (heuristically the base/main APK)
                 largest_apk = None
                 max_size = 0
                 
                 for root, dirs, files in os.walk(temp_extract_dir):
                     for file in files:
                         if file.lower().endswith(".apk"):
                             full_path = os.path.join(root, file)
                             size = os.path.getsize(full_path)
                             if size > max_size:
                                 max_size = size
                                 largest_apk = full_path
                 
                 if largest_apk:
                     log.success(f"Extracted XAPK and selected main APK: {largest_apk}")
                     apk_path = largest_apk # Override valid APK path
                 else:
                     log.error("Could not find any .apk file inside the XAPK archive.")
                     return # Abort
                     
             except zipfile.BadZipFile:
                 log.error(f"Failed to extract XAPK: {apk_path} is not a valid zip file.")
                 return
             except Exception as e:
                 log.error(f"Error handling XAPK: {e}")
                 return

        self.apk_name = os.path.basename(apk_path) # Store for later use
        apk_name = self.apk_name
        output_dir = f"output/{apk_name}_decompiled"
        
        # [Moved from end] Calculate unique output file/dir options EARLY
        if output_file is None:
            base_filename = f"{os.path.basename(apk_path)}_results.json"
            base_exploit_dir_name = f"{os.path.basename(apk_path).replace('.apk', '')}_exploits"
            
            # Initial candidates
            candidate_file = f"output/{base_filename}"
            candidate_exploit_dir = f"output/{base_exploit_dir_name}"
            
            # Versioning loop
            scan_count = 1
            while os.path.exists(candidate_file):
                 # Create suffix _scan1, _scan2...
                 candidate_file = f"output/{base_filename.replace('.json', '')}_scan{scan_count}.json"
                 candidate_exploit_dir = f"output/{base_exploit_dir_name}_scan{scan_count}"
                 scan_count += 1
            
            self.final_output_file = candidate_file
            self.final_exploit_dir = candidate_exploit_dir
        else:
            self.final_output_file = output_file
            filename_no_ext = os.path.splitext(os.path.basename(output_file))[0]
            self.final_exploit_dir = f"output/{filename_no_ext}_exploits"
        
        decomp_mode = self.settings.analysis.decompiler_mode
        log.info(f"Decompiler Mode: {decomp_mode}")

        if not no_decompile:
            os.makedirs(output_dir, exist_ok=True)
            
            # 1. Always run Apktool (Need Manifest + Resources + Smali Fallback)
            log.info("Running Apktool...")
            decompiler = ApktoolHandler(apktool_path=self.settings.apktool.path or "apktool")
            decompiler.decompile(apk_path, output_dir)
            
            # 2. Run JADX if needed
            if decomp_mode in ["jadx", "hybrid"]:
                log.info("Running JADX...")
                jadx_path = self.settings.jadx.path if self.settings.jadx else None
                jadx = JadxHandler(jadx_path=jadx_path)
                # JADX typically outputs to 'sources' dir inside output_dir when -d is used? 
                # Handler uses -d output_dir. Jadx usually creates 'sources' structure.
                # Let's ensure JadxHandler puts it in output_dir/sources or we handle it.
                # Our handler: cmd = [self.jadx_path, "-d", output_dir, ...]
                # Jadx default behavior: creates 'sources' folder inside output_dir.
                jadx.decompile(apk_path, output_dir)

        # BUILD CALL GRAPH (Only supports Smali for now)
        if self.settings.analysis.use_cross_reference_context:
            self.call_graph_builder = CallGraphBuilder(output_dir)
            self.call_graph_builder.build()
        else:
            self.call_graph_builder = None

        smali_rules_enabled = any(
            enabled and rule_name not in DEDICATED_PASS_RULES
            for rule_name, enabled in self.settings.rules.model_dump().items()
        )

        self.summaries = {}
        target_files = [] # Files we will actually scan (either .smali or .java)
        
        if smali_rules_enabled:
            filter_mode = self.settings.analysis.filter_mode
            log.info(f"Using filter mode: {filter_mode}")

            # --- DYNAMIC KEYWORD & REGEX GATHERING ---
            extra_keywords = []
            extra_regex = [] # [V1.2] Regex Support
            for rule_name, enabled in self.settings.rules.model_dump().items():
                if enabled and rule_name not in DEDICATED_PASS_RULES:
                     try:
                        prompt_path = f"config/prompts/vuln_rules/{rule_name}.yaml"
                        with open(prompt_path, "r") as f:
                            rule_data = yaml.safe_load(f)
                            if "keywords" in rule_data and rule_data["keywords"]:
                                extra_keywords.extend(rule_data["keywords"])
                            
                            # [V1.2] Support for 'detection_pattern' (regex) and 'static_analysis' block
                            if "detection_pattern" in rule_data and rule_data["detection_pattern"]:
                                extra_regex.append(rule_data["detection_pattern"])
                            elif "static_analysis" in rule_data:
                                if "patterns" in rule_data["static_analysis"]:
                                    extra_regex.extend(rule_data["static_analysis"]["patterns"])
                                    
                     except Exception as e:
                         log.warning(f"Could not load matching logic from {rule_name}: {e}")
            
            # Deduplicate
            extra_keywords = list(set(extra_keywords))
            extra_regex = list(set(extra_regex))
            
            if extra_keywords:
                log.info(f"Loaded high-value keywords: {len(extra_keywords)}")
            if extra_regex:
                log.info(f"Loaded high-value regex patterns: {len(extra_regex)}")

            # --- SCOPE IDENTIFICATION ---
            # Parse Manifest early to get package name for filtering
            manifest_path = os.path.join(output_dir, "AndroidManifest.xml")
            app_package_name = ""
            if os.path.exists(manifest_path):
                try:
                    parser = ManifestParser(manifest_path)
                    app_package_name = parser.package_name
                    self.manifest_parser = parser  # [B] reused by analyze_file for reachability context
                    log.info(f"Identified App Package: {app_package_name}")
                except Exception as e:
                    log.warning(f"Failed to parse package name: {e}")

            # --- STRATEGY SELECTION ---
            
            # Set scan roots
            smali_dir = output_dir # Root of decompiled dir, CodeFilter walks this
            # JADX usually creates 'sources' inside output_dir
            java_dir = os.path.join(output_dir, "sources") 
            
            potential_targets = []
            
            # A. STATIC FILTER PHASE
            # A. STATIC FILTER PHASE
            if filter_mode in ["static_only", "hybrid"]:
                use_strict = (filter_mode == "hybrid")
                
                # [V1.1.7 Optimization] Library Hunter Strict Mode
                # If Library Scan is requested, we override standards to be VERY STRICT.
                # We do NOT want generic 'WebView' or 'File' keywords matching 100 library files.
                # We ONLY want 'readObject', 'DexClassLoader', etc.
                if self.settings.analysis.scan_libraries:
                    log.info("Library Hunter Mode: Enforcing STRICT regex targeting to save tokens.")
                    
                    # 1. Load ONLY the library regex
                    strict_lib_regex = []
                    lib_prompt_path = "config/prompts/vuln_rules/library_vulnerability.yaml"
                    if os.path.exists(lib_prompt_path):
                         with open(lib_prompt_path, "r") as f:
                             d = yaml.safe_load(f)
                             if "detection_pattern" in d:
                                 strict_lib_regex.append(d["detection_pattern"])
                    
                    # 2. Run CodeFilter in STRICT MODE (No default keywords)
                    # Support JADX or HYBRID (if Java sources exist)
                    if decomp_mode in ["jadx", "hybrid"] and os.path.exists(java_dir):
                        cf = CodeFilter(java_dir, mode="java", additional_keywords=[], additional_regex=strict_lib_regex, strict_mode=True)
                        potential_targets = cf.find_high_value_targets()
                    # Fallback to Smali (Apktool or missing Java sources)
                    else:
                        cf = CodeFilter(smali_dir, mode="smali", additional_keywords=[], additional_regex=strict_lib_regex, strict_mode=True)
                        potential_targets = cf.find_high_value_targets()
                     
                else:
                    # Standard Mode (Broad)
                    if decomp_mode == "apktool":
                        cf = CodeFilter(smali_dir, mode="smali", additional_keywords=extra_keywords, additional_regex=extra_regex, strict_mode=use_strict)
                        potential_targets = cf.find_high_value_targets()
                        
                    elif decomp_mode == "jadx":
                        if os.path.exists(java_dir):
                            cf = CodeFilter(java_dir, mode="java", additional_keywords=extra_keywords, additional_regex=extra_regex, strict_mode=use_strict)
                            potential_targets = cf.find_high_value_targets()
                        else:
                            log.error("JADX sources not found. Falling back to Smali.")
                            cf = CodeFilter(smali_dir, mode="smali", additional_keywords=extra_keywords, additional_regex=extra_regex, strict_mode=use_strict)
                            potential_targets = cf.find_high_value_targets()

                    elif decomp_mode == "hybrid":
                        # HYBRID DECOMPILER + HYBRID FILTER
                        if os.path.exists(java_dir):
                            cf = CodeFilter(java_dir, mode="java", additional_keywords=extra_keywords, additional_regex=extra_regex, strict_mode=use_strict)
                            java_targets = cf.find_high_value_targets()
                            potential_targets = java_targets
                        else:
                            cf = CodeFilter(smali_dir, mode="smali", additional_keywords=extra_keywords, additional_regex=extra_regex, strict_mode=use_strict)
                            potential_targets = cf.find_high_value_targets()

            # B. LLM_ONLY PHASE (Get everything)
            else: 
                # This is risky/expensive for JADX if huge source tree. 
                # But logic is "summarize everything".
                if decomp_mode == "apktool":
                     # Walk smali
                     for root, _, files in os.walk(smali_dir):
                        for file in files:
                            if file.endswith(".smali"): potential_targets.append(os.path.join(root, file))
                else: 
                     # Walk java
                     if os.path.exists(java_dir):
                        for root, _, files in os.walk(java_dir):
                            for file in files:
                                if file.endswith(".java"): potential_targets.append(os.path.join(root, file))
            
            # --- STRINGS.XML ANALYSIS ---
            strings_results = self.analyze_strings_xml(output_dir, rules_to_run)
            
            # --- SMART FALLBACK & SELECTION ---
            # Now we have 'potential_targets'. 
            # If we are in 'hybrid' DECOMPILER mode, we check content quality.
            
            final_targets_for_summary = []
            
            for target in potential_targets:
                if decomp_mode == "hybrid" and target.endswith(".java"):
                    # Check if valid
                    try:
                        if os.path.getsize(target) < 50: # Empty or just package decl
                             # Fallback
                             fallback = self._find_smali_fallback(target, output_dir)
                             if fallback:
                                 log.info(f"Smart Fallback: Switching {os.path.basename(target)} to Smali due to low quality.")
                                 final_targets_for_summary.append(fallback)
                             else:
                                 final_targets_for_summary.append(target) # Keep it if no fallback
                        else:
                             final_targets_for_summary.append(target)
                    except:
                        final_targets_for_summary.append(target)
                else:
                    final_targets_for_summary.append(target)

            # [V1.1.4] Apply Scope Filtering
            filtered_targets = []
            skipped_count = 0
            for target in final_targets_for_summary:
                if self._is_relevant_file(target, app_package_name):
                    filtered_targets.append(target)
                else:
                    skipped_count += 1
            
            if skipped_count > 0:
                log.info(f"Scope Filter: Ignored {skipped_count} library/irrelevant files.")
            
            final_targets_for_summary = filtered_targets

            
            # --- SUMMARIZATION & RISK ID PHASE ---
            
            if filter_mode == "static_only":
                 target_files = final_targets_for_summary
                 # No summarization logic for pure static, just pass to analyze
                 
            elif filter_mode == "hybrid":
                # Static found targets -> Summarize them -> Ask LLM
                if final_targets_for_summary:
                    self.summaries = self.summarize_chunks(output_dir, file_list=final_targets_for_summary)
                    llm_risky = self.identify_risky_chunks(self.summaries)
                    # A first-party file that matches a rule's detection_pattern is a strong
                    # static signal; deep-scan it even if the LLM risk-triage said "no" (it
                    # dropped a real hit — ZipSlipActivity — before any rule could run).
                    pattern_risky = self._pattern_matched_files(
                        final_targets_for_summary, extra_regex, app_package_name
                    )
                    target_files = list(dict.fromkeys(llm_risky + pattern_risky))
                    log.info(
                        f"Deep-scan targets: {len(llm_risky)} via risk-triage + "
                        f"{len(pattern_risky)} first-party static-pattern hits = "
                        f"{len(target_files)} unique."
                    )
                else:
                    target_files = []

            else: # llm_only
                # We summarized EVERYTHING (expensive!). 
                self.summaries = self.summarize_chunks(output_dir, file_list=final_targets_for_summary)
                target_files = self.identify_risky_chunks(self.summaries)


        manifest_path = os.path.join(output_dir, "AndroidManifest.xml")
        
        # Always attempt to summarize app (even if only based on Manifest)
        app_summary = self.summarize_app(manifest_path, self.summaries)
        
        attack_surface_map = None
        if self.settings.analysis.generate_attack_surface_map:
            attack_surface_map = self.generate_attack_surface_map(manifest_path, self.summaries)

        # Clear previous findings before scan
        self.vulnerability_findings = []
        self.analysis_errors = []  # [FIX #2] Reset unanalyzed-file tracker

        # Analyze the manifest file
        all_results = self.analyze_manifest(manifest_path, rules_to_run)

        if smali_rules_enabled and target_files:
            # Append strings.xml results
            try:
                if strings_results:
                    all_results.extend(strings_results)
            except NameError:
                pass # strings_results might not be defined if scope skipped
            # Analyze the identified files (may be .smali or .java).
            # Context injection works for both: the call graph is Smali-based, but
            # get_dependencies()/path_to_class() normalize .java paths (sources/) to the
            # same class names, so JADX/hybrid Java files still receive dependency context.
            
            max_workers = max(1, self.settings.analysis.max_workers)  # [#6] Configurable parallelism
            log.info(f"Deep scanning with {max_workers} worker(s)...")
            with concurrent.futures.ThreadPoolExecutor(max_workers=max_workers) as executor:
                future_to_file = {executor.submit(self.analyze_file, file_path, rules_to_run): file_path for file_path in target_files}
                for future in track(concurrent.futures.as_completed(future_to_file), total=len(future_to_file), description="Deep scanning files...", console=console):
                    file_path = future_to_file[future]
                    try:
                        results = future.result()
                        all_results.extend(results)
                    except Exception as exc:
                        log.error(f"{file_path} generated an exception: {exc}")

        # [#E] Collapse overlapping same-file findings (info-preserving via 'also_detected_by').
        all_results = self._dedupe_findings(all_results)

        final_report = {
            "app_summary": app_summary,
            "attack_surface_map": attack_surface_map,
            "results": all_results,
            # [FIX #2] Surface unanalyzed file/rule pairs so a failed scan can't be
            # mistaken for a clean one.
            "analysis_errors": self.analysis_errors,
        }

        # [V1.1.3] Generate Chained Exploits (Phase 2)
        if self.settings.analysis.generate_exploit and self.vulnerability_findings:
            self._generate_chained_exploits()

        # Output the report to the pre-calculated path
        with open(self.final_output_file, "w") as f:
            import json
            json.dump(final_report, f, indent=2)
        log.success(f"Analysis complete. Results saved to {self.final_output_file}")

        # [FIX #2] Warn loudly when some files/rules could not be analyzed.
        if self.analysis_errors:
            log.warning(
                f"{len(self.analysis_errors)} file/rule check(s) could NOT be analyzed "
                f"(LLM failures). These are marked status='Error' and must NOT be read as clean. "
                f"See 'analysis_errors' in the report."
            )

        # [#4] Report cache effectiveness. Merge in exploit_llm_client's own stats when it's
        # a separate client (different exploit_provider/exploit_model) so the count is complete.
        if hasattr(self.llm_client, "cache_stats"):
            stats = self.llm_client.cache_stats()
            hits, misses, enabled = stats.get("hits", 0), stats.get("misses", 0), stats.get("enabled")
            if self.exploit_llm_client is not self.llm_client and hasattr(self.exploit_llm_client, "cache_stats"):
                exploit_stats = self.exploit_llm_client.cache_stats()
                hits += exploit_stats.get("hits", 0)
                misses += exploit_stats.get("misses", 0)
                enabled = enabled or exploit_stats.get("enabled")
            if enabled:
                log.info(f"Response cache: {hits} hit(s), {misses} miss(es).")

    def _load_system_prompt(self) -> str:
        with open("config/prompts/system_prompt.txt", "r") as f:
            return f.read()

    def _load_summarize_prompt(self) -> str:
        with open("config/prompts/summarize_prompt.txt", "r") as f:
            return f.read()

    def _load_identify_risk_prompt(self) -> str:
        with open("config/prompts/identify_risk_prompt.txt", "r") as f:
            return f.read()

    def _load_app_summary_prompt(self) -> str:
        with open("config/prompts/app_summary_prompt.txt", "r") as f:
            return f.read()

    def _load_attack_surface_prompt(self) -> str:
        with open("config/prompts/attack_surface_prompt.txt", "r") as f:
            return f.read()
