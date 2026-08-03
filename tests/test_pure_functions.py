"""
Golden test — Layer 1 (deterministic, no LLM).

Locks in the v1.2.0 engine fixes so future refactors can't silently regress them:
per-rule gating (#1), input truncation (#5), failure/parse handling (#2 / Ollama-JSON),
the response cache (#4), and cross-language call-graph mapping.
"""
import types

from core.engine import Engine
from core.llm_cache import CachedLLMClient
from core.call_graph import CallGraphBuilder
from modules.llm_client.router9 import Router9Client


def _engine():
    # Bypass __init__ (which builds a real LLM client); we only test pure methods.
    return object.__new__(Engine)


# ---- #1 per-rule regex gating -------------------------------------------------
def test_rule_should_run_gating():
    e = _engine()
    e.settings = types.SimpleNamespace(analysis=types.SimpleNamespace(filter_mode="hybrid"))
    pd = {"detection_pattern": r"execSQL\s*\("}
    assert e._rule_should_run("sql", pd, "db.execSQL(x)") is True
    assert e._rule_should_run("sql", pd, "int x = 1;") is False
    assert e._rule_should_run("logic", {"prompt": "..."}, "anything") is True  # no pattern -> run
    # llm_only bypasses gating entirely
    e.settings.analysis.filter_mode = "llm_only"
    assert e._rule_should_run("sql", pd, "int x = 1;") is True
    # bad regex fails open (runs the LLM rather than silently dropping the rule)
    e.settings.analysis.filter_mode = "hybrid"
    assert e._rule_should_run("x", {"detection_pattern": r"([unclosed"}, "y") is True


# ---- #5 input truncation ------------------------------------------------------
def test_truncate_for_llm():
    e = _engine()
    e.settings = types.SimpleNamespace(analysis=types.SimpleNamespace(max_input_chars=100))
    big = "H" * 80 + "M" * 100 + "T" * 80
    out = e._truncate_for_llm(big)
    assert len(out) < len(big) and "TRUNCATED" in out
    assert out.startswith("H") and out.rstrip().endswith("T")
    assert e._truncate_for_llm("short") == "short"
    e.settings.analysis.max_input_chars = 0  # disabled
    assert e._truncate_for_llm(big) == big


# ---- #2 / Ollama-JSON: failure & parse handling -------------------------------
def test_is_failed_response():
    e = _engine()
    assert e._is_failed_response("") is True
    assert e._is_failed_response("   ") is True
    assert e._is_failed_response(None) is True
    assert e._is_failed_response('{"x": 1}') is False


def test_parse_prose_is_flagged_not_clean():
    e = _engine()
    parsed = e._parse_llm_response("Yes, there is a SQL injection vulnerability here.")
    assert parsed.get("_parse_failed") is True
    assert parsed.get("is_vulnerable") is False


def test_parse_valid_json():
    e = _engine()
    ok = e._parse_llm_response('{"is_vulnerable": true, "severity": "High"}')
    assert ok["is_vulnerable"] is True
    assert "_parse_failed" not in ok


def test_parse_fenced_json_with_nested_braces_in_evidence():
    e = _engine()
    raw = '```json\n{"is_vulnerable": true, "evidence": "if (a) {b();}"}\n```'
    parsed = e._parse_llm_response(raw)
    assert parsed["is_vulnerable"] is True
    assert "{" in parsed["evidence"]  # nested braces inside a string value survived


# ---- #4 response cache --------------------------------------------------------
class _FakeClient:
    def __init__(self):
        self.calls = 0

    def analyze_code(self, code, ctx):
        self.calls += 1
        return "" if code == "FAIL" else f"R:{code}"

    def other(self):
        return "delegated"


def test_cache_hit_and_no_cache_of_failures(tmp_path):
    fake = _FakeClient()
    cc = CachedLLMClient(fake, str(tmp_path / "c"), model="m", enabled=True)
    ctx = {"system_prompt": "s", "vuln_prompt": "v", "file_path": "F"}
    assert cc.analyze_code("x", ctx) == cc.analyze_code("x", ctx)
    assert fake.calls == 1  # second call served from cache
    # empty responses must NOT be cached -> retried each time
    cc.analyze_code("FAIL", ctx)
    cc.analyze_code("FAIL", ctx)
    assert fake.calls == 3
    # unknown attributes delegate to the wrapped client
    assert cc.other() == "delegated"


def test_cache_resume_across_new_wrapper(tmp_path):
    d = str(tmp_path / "c")
    fake1 = _FakeClient()
    ctx = {"system_prompt": "s", "vuln_prompt": "v", "file_path": "F"}
    CachedLLMClient(fake1, d, model="m", enabled=True).analyze_code("x", ctx)
    fake2 = _FakeClient()
    assert CachedLLMClient(fake2, d, model="m", enabled=True).analyze_code("x", ctx) == "R:x"
    assert fake2.calls == 0  # served from disk cache written by the first wrapper


def test_cache_disabled_bypasses(tmp_path):
    fake = _FakeClient()
    cc = CachedLLMClient(fake, str(tmp_path / "c"), model="m", enabled=False)
    ctx = {"system_prompt": "s", "vuln_prompt": "v", "file_path": "F"}
    cc.analyze_code("x", ctx)
    cc.analyze_code("x", ctx)
    assert fake.calls == 2


# ---- cross-language call graph mapping ----------------------------------------
def _finding(file, rule, vuln, sev="High", status="Vulnerable"):
    return {"file": file, "rule": rule, "vulnerability": vuln, "status": status,
            "result": {"severity": sev, "description": f"{vuln} detail"}}


def test_dedupe_family_merge():
    """[#E] WebView-family findings on the same file collapse to one + also_detected_by."""
    e = _engine()
    out = e._dedupe_findings([
        _finding("W.java", "webview_xss", "WebView XSS", "High"),
        _finding("W.java", "insecure_webview", "Insecure WebView", "Medium"),
        _finding("W.java", "webview_file_access", "WebView File Access", "Low"),
    ])
    assert len(out) == 1
    assert out[0]["rule"] == "webview_xss"  # highest severity kept as primary
    also = {a["rule"] for a in out[0]["also_detected_by"]}
    assert also == {"insecure_webview", "webview_file_access"}


def test_dedupe_generic_fold_when_specific_present():
    """[#E] universal_logic_flaw folds into a specific finding on the same file (kept, not dropped)."""
    e = _engine()
    out = e._dedupe_findings([
        _finding("C.java", "biometric_bypass", "Biometric", "High"),
        _finding("C.java", "universal_logic_flaw", "Conceptual Logic Flaw Detection", "Medium"),
    ])
    top = {r["rule"] for r in out}
    assert "universal_logic_flaw" not in top and "biometric_bypass" in top
    host = next(r for r in out if r["rule"] == "biometric_bypass")
    folded = [a for a in host["also_detected_by"] if a["rule"] == "universal_logic_flaw"]
    assert folded and folded[0]["description"]  # detail preserved


def test_dedupe_generic_standalone_kept():
    """[#E] universal_logic_flaw alone on a file stays as a real finding."""
    e = _engine()
    out = e._dedupe_findings([_finding("X.java", "universal_logic_flaw", "Conceptual Logic Flaw Detection")])
    assert len(out) == 1 and out[0]["rule"] == "universal_logic_flaw"


def test_dedupe_keeps_distinct_files_and_passes_through_non_vulnerable():
    e = _engine()
    out = e._dedupe_findings([
        _finding("A.java", "webview_xss", "WebView XSS"),
        _finding("B.java", "insecure_webview", "Insecure WebView"),
        _finding("A.java", "sql_injection", "SQL Injection", status="Not Vulnerable"),
        _finding("A.java", "path_traversal", "Path Traversal", status="Error"),
    ])
    # 2 distinct-file vulnerable (not merged) + 2 passthrough
    assert len(out) == 4


def test_json_only_suffix_is_format_safe():
    """[#C] The appended JSON-only suffix must be brace-free (vuln_prompt goes through str.format())."""
    from core.engine import JSON_ONLY_SUFFIX
    assert "{" not in JSON_ONLY_SUFFIX and "}" not in JSON_ONLY_SUFFIX
    assert "JSON" in JSON_ONLY_SUFFIX
    # sanity: a rule prompt + suffix still formats without KeyError
    ("Analyze {code_snippet} at {file_path}" + JSON_ONLY_SUFFIX).format(code_snippet="x", file_path="y")


def test_manifest_rules_are_single_source_of_truth():
    """Regression: strandhogg is manifest-only. It previously leaked into the code
    deep-scan (missing from the exclusion list) and false-positived on every risky
    Java file. MANIFEST_RULES is now the single source used by both paths."""
    from core.engine import MANIFEST_RULES
    from core.config_loader import RulesSettings
    valid = set(RulesSettings.model_fields)
    assert "strandhogg" in MANIFEST_RULES
    for r in MANIFEST_RULES:
        assert r in valid, f"MANIFEST_RULES has unknown rule: {r}"


def test_dedicated_pass_rules_excluded_from_code_scan():
    """Regression: rules with their own pass must NOT run in the code deep-scan.
    hardcoded_secrets_xml (strings.xml-only) leaked onto .java files and false-positived."""
    from core.engine import MANIFEST_RULES, DEDICATED_PASS_RULES
    from core.config_loader import RulesSettings
    valid = set(RulesSettings.model_fields)
    assert "hardcoded_secrets_xml" in DEDICATED_PASS_RULES
    assert set(MANIFEST_RULES) <= DEDICATED_PASS_RULES
    for r in DEDICATED_PASS_RULES:
        assert r in valid, f"DEDICATED_PASS_RULES has unknown rule: {r}"


def test_pattern_matched_files_rescues_first_party_only(tmp_path):
    """v2 recall fix: files matching a rule detection_pattern must bypass the LLM
    risk-triage (which dropped ZipSlipActivity pre-gating), but only FIRST-PARTY ones
    so the added deep-scan cost stays bounded (library files still go through triage)."""
    import os
    e = _engine()
    pkg = tmp_path / "sources" / "com" / "dlh" / "vulnerapp"
    lib = tmp_path / "sources" / "kotlinx" / "coroutines"
    pkg.mkdir(parents=True)
    lib.mkdir(parents=True)
    app_hit = pkg / "ZipSlipActivity.java"
    app_hit.write_text("ZipEntry e = zis.getNextEntry(); new File(dir, e.getName());")
    app_miss = pkg / "Boring.java"
    app_miss.write_text("int x = 1;")
    lib_hit = lib / "FastServiceLoader.java"
    lib_hit.write_text("ZipEntry e; e.getName();")
    files = [str(app_hit), str(app_miss), str(lib_hit)]
    patterns = [r"ZipEntry.*(?:\.|->)getName"]
    out = e._pattern_matched_files(files, patterns, "com.dlh.vulnerapp")
    assert str(app_hit) in out       # first-party pattern hit -> rescued from triage
    assert str(app_miss) not in out  # no pattern match -> not added
    assert str(lib_hit) not in out   # library file -> left to the normal triage


def test_file_to_class_dotted():
    """[B] map a decompiled file path -> dotted class for manifest component lookup."""
    e = _engine()
    assert (e._file_to_class_dotted(
        "/o/App.apk_decompiled/sources/com/dlh/vulnerapp/IntentRedirectionActivity.java")
        == "com.dlh.vulnerapp.IntentRedirectionActivity")
    assert e._file_to_class_dotted("/o/dec/smali/com/a/b/C.smali") == "com.a.b.C"
    assert e._file_to_class_dotted("/o/dec/smali_classes3/com/a/D.smali") == "com.a.D"
    assert e._file_to_class_dotted("/o/nowhere/Foo.java") is None


def test_manifest_get_component_details_childless(tmp_path):
    """Regression: an <activity/> with NO child nodes is a *falsy* ElementTree Element, so
    get_component_details used to wrongly return {} for it (e.g. IntentRedirectionActivity,
    which has no intent-filter). It must be found via `is not None`."""
    from core.manifest_parser import ManifestParser
    m = tmp_path / "AndroidManifest.xml"
    m.write_text(
        '<?xml version="1.0"?>\n'
        '<manifest xmlns:android="http://schemas.android.com/apk/res/android" package="com.x">\n'
        '  <application>\n'
        '    <activity android:name="com.x.NoFilterActivity" android:exported="true"/>\n'
        '    <activity android:name="com.x.WithFilter" android:exported="true">\n'
        '      <intent-filter><action android:name="a"/></intent-filter>\n'
        '    </activity>\n'
        '  </application>\n'
        '</manifest>\n'
    )
    p = ManifestParser(str(m))
    assert p.get_component_details("com.x.NoFilterActivity").get("exported") == "true"
    assert p.get_component_details("com.x.WithFilter").get("exported") == "true"
    assert p.get_component_details("com.x.DoesNotExist") == {}


# ---- PoC extension detection: shebang/first-line wins over content sniffing ---
def test_poc_extension_bash_with_embedded_python_heredoc():
    """Regression: a real generated PoC was `#!/bin/bash` that embeds a
    `python3 - << 'EOF' ... EOF` heredoc (to do background logcat monitoring, which
    Bash can't easily do alone). The old whole-content scan matched "import "/"def "
    INSIDE the heredoc and saved this valid, directly-executable Bash script as
    ".py". The shebang must win: it's what the OS actually uses to run the file."""
    e = _engine()
    bash_with_heredoc = (
        "#!/bin/bash\n"
        "echo starting\n"
        "python3 - << 'PYEOF'\n"
        "import subprocess\n"
        "import threading\n"
        "def monitor_logcat():\n"
        "    pass\n"
        "PYEOF\n"
    )
    assert e._detect_poc_extension(bash_with_heredoc) == ".sh"


def test_poc_extension_bash_with_embedded_frida_js():
    """Same principle, different embedded language: shebang still wins."""
    e = _engine()
    bash_with_js = "#!/bin/bash\necho hi\n" + "Java.perform(function() { console.log(1); });"
    assert e._detect_poc_extension(bash_with_js) == ".sh"


def test_poc_extension_pure_python():
    e = _engine()
    assert e._detect_poc_extension("#!/usr/bin/env python3\nimport os\ndef f(): pass") == ".py"


def test_poc_extension_pure_frida_js():
    e = _engine()
    assert e._detect_poc_extension("Java.perform(function(){ console.log(1); });") == ".js"


def test_poc_extension_pure_html():
    e = _engine()
    assert e._detect_poc_extension("<!DOCTYPE html>\n<html><body></body></html>") == ".html"


def test_poc_extension_falls_back_to_content_sniffing_without_shebang():
    """No shebang / first-line signal at all -> content-sniffing fallback still works."""
    e = _engine()
    assert e._detect_poc_extension("some notes\nadb shell am start -n a/b\n") == ".sh"
    assert e._detect_poc_extension("some notes\nimport os\nrest of script\n") == ".py"


def test_poc_extension_unknown_content_is_txt():
    e = _engine()
    assert e._detect_poc_extension("just some random output with no signals") == ".txt"


# ---- exploit-generation provider routing (llm.exploit_provider/exploit_model) --
def _llm_settings(**overrides):
    base = dict(
        provider="ollama", model="deepseek-coder-v2:latest", ollama_url="http://localhost:11434",
        gemini_model="gemini-2.0-flash", gemini_api_key="g",
        groq_model="llama-3.1-8b-instant", groq_api_key="g",
        openai_model="gpt-4-turbo", openai_api_key="o",
        anthropic_model="claude-opus-4-6", anthropic_api_key="a",
        openrouter_model="moonshotai/kimi-k3", openrouter_api_key="or",
        router9_model="gc/gemini-2.5-pro", router9_api_key="r9", router9_base_url="http://localhost:20128/v1/chat/completions",
        max_tokens=4096, exploit_provider=None, exploit_model=None,
    )
    base.update(overrides)
    return types.SimpleNamespace(**base)


def _engine_with_settings(generate_exploit, use_cache=False, **llm_overrides):
    e = _engine()
    e.settings = types.SimpleNamespace(
        llm=_llm_settings(**llm_overrides),
        analysis=types.SimpleNamespace(use_cache=use_cache, generate_exploit=generate_exploit),
    )
    return e


def test_build_llm_client_model_override():
    e = _engine()
    e.settings = types.SimpleNamespace(llm=_llm_settings(), analysis=types.SimpleNamespace(use_cache=False))
    client = e._build_llm_client("anthropic", model_override="custom-model")
    assert client.model == "custom-model"  # override wins over anthropic_model default
    default_client = e._build_llm_client("anthropic")
    assert default_client.model == "claude-opus-4-6"  # no override -> that provider's own default


def test_exploit_client_defaults_to_main_when_unset():
    """No exploit_provider/exploit_model set -> exploit generation reuses the main client
    (no second object built at all)."""
    e = _engine_with_settings(generate_exploit=True)
    e._setup_llm_client()
    assert e.exploit_llm_client is e.llm_client


def test_exploit_client_skipped_when_generate_exploit_is_off():
    """A typo'd/unused exploit_provider must NEVER affect a normal scan: the separate
    client is only built when exploit generation is actually requested."""
    e = _engine_with_settings(generate_exploit=False, exploit_provider="anthropic")
    e._setup_llm_client()
    assert e.exploit_llm_client is e.llm_client


def test_exploit_client_routes_to_separate_provider():
    e = _engine_with_settings(generate_exploit=True, exploit_provider="anthropic")
    e._setup_llm_client()
    assert e.exploit_llm_client is not e.llm_client
    assert e.exploit_llm_client.model == "claude-opus-4-6"
    assert e.llm_client.model == "deepseek-coder-v2:latest"  # main (ollama) client untouched


def test_exploit_client_model_override_without_changing_provider():
    """exploit_model alone (same provider as main) must still build a separate client."""
    e = _engine_with_settings(generate_exploit=True, provider="anthropic", exploit_model="claude-sonnet-4-5")
    e._setup_llm_client()
    assert e.exploit_llm_client is not e.llm_client
    assert e.exploit_llm_client.model == "claude-sonnet-4-5"
    assert e.llm_client.model == "claude-opus-4-6"


def test_exploit_client_falls_back_on_bad_provider():
    """A misconfigured exploit_provider must not crash the scan -> falls back to main."""
    e = _engine_with_settings(generate_exploit=True, exploit_provider="not_a_real_provider")
    e._setup_llm_client()  # must not raise
    assert e.exploit_llm_client is e.llm_client


# ---- attack surface map: structured inventory, not narrative text -------------
class _StubLLM:
    def __init__(self, response):
        self.response = response

    def analyze_code(self, code, ctx):
        return self.response


def test_attack_surface_map_returns_parsed_dict_on_success(tmp_path):
    """v1.3.0: was a raw narrative string; now a small structured inventory dict."""
    e = _engine()
    e.llm_client = _StubLLM(
        '{"exported_activities": ["WebViewActivity"], "deep_links": '
        '[{"scheme": "dlh", "host": "webview", "handler": "WebViewActivity"}], '
        '"network": ["webview"], "file_io": false, "ipc": true, '
        '"deserialization": false, "reflection": false, "manifest_flags": {"debuggable": true}}'
    )
    manifest = tmp_path / "AndroidManifest.xml"
    manifest.write_text("<manifest/>")
    result = e.generate_attack_surface_map(str(manifest), {})
    assert isinstance(result, dict)
    assert result["exported_activities"] == ["WebViewActivity"]
    assert result["deep_links"][0]["handler"] == "WebViewActivity"
    assert result["ipc"] is True
    assert "error" not in result


def test_attack_surface_map_reports_error_on_empty_response(tmp_path):
    e = _engine()
    e.llm_client = _StubLLM("")
    manifest = tmp_path / "AndroidManifest.xml"
    manifest.write_text("<manifest/>")
    result = e.generate_attack_surface_map(str(manifest), {})
    assert "error" in result  # transparent failure, not a silent empty/null map


def test_attack_surface_map_reports_error_on_unparseable_response(tmp_path):
    e = _engine()
    e.llm_client = _StubLLM("Sure, here is the attack surface: WebViewActivity is exported...")
    manifest = tmp_path / "AndroidManifest.xml"
    manifest.write_text("<manifest/>")
    result = e.generate_attack_surface_map(str(manifest), {})
    assert "error" in result
    assert "is_vulnerable" not in result  # must NOT leak the vuln-verdict fallback shape


# ---- 9Router client: SSE stream parsing -----------------------------------------
class _FakeSSEResponse:
    """Mimics requests.Response.iter_lines() for a 9Router-style SSE stream."""
    def __init__(self, lines):
        self._lines = lines

    def iter_lines(self, decode_unicode=True):
        return iter(self._lines)


def _router9():
    return Router9Client(model="gc/gemini-2.5-pro", api_key="k", base_url="http://x/v1/chat/completions")


def test_router9_parses_real_world_sse_stream():
    """Regression fixture: the exact SSE shape observed from a real 9Router instance
    (chat.completion.chunk objects, role-only first delta, content delta, then a
    finish_reason chunk with usage) — no `stream:true` was even requested."""
    r9 = _router9()
    lines = [
        '',
        'data: {"id":"chatcmpl-1","object":"chat.completion.chunk","created":1,"model":"gemini-2.5-pro","choices":[{"index":0,"delta":{"role":"assistant"},"finish_reason":null}]}',
        '',
        'data: {"id":"chatcmpl-1","object":"chat.completion.chunk","created":1,"model":"gemini-2.5-pro","choices":[{"index":0,"delta":{"content":"Hello "},"finish_reason":null}]}',
        'data: {"id":"chatcmpl-1","object":"chat.completion.chunk","created":1,"model":"gemini-2.5-pro","choices":[{"index":0,"delta":{"content":"9Router!"},"finish_reason":null}]}',
        'data: {"id":"chatcmpl-1","object":"chat.completion.chunk","created":1,"model":"gemini-2.5-pro","choices":[{"index":0,"delta":{},"finish_reason":"stop"}],"usage":{"prompt_tokens":10,"completion_tokens":2,"total_tokens":12}}',
        'data: [DONE]',
    ]
    assert r9._parse_sse_stream(_FakeSSEResponse(lines)) == "Hello 9Router!"


def test_router9_sse_stream_stops_at_done_and_skips_malformed():
    r9 = _router9()
    lines = [
        'data: {"choices":[{"delta":{"content":"A"}}]}',
        'data: not-json-garbage',
        'data: {"choices":[{"delta":{"content":"B"}}]}',
        'data: [DONE]',
        'data: {"choices":[{"delta":{"content":"C-should-not-appear"}}]}',
    ]
    assert r9._parse_sse_stream(_FakeSSEResponse(lines)) == "AB"


def test_router9_sse_stream_empty_on_no_data_lines():
    r9 = _router9()
    assert r9._parse_sse_stream(_FakeSSEResponse(["", "not an sse line"])) == ""


def test_router9_construct_prompt_survives_braces_in_code():
    """Java/Kotlin code is full of '{' '}' — .format() must not choke on the VALUE,
    only on stray braces in the TEMPLATE (already covered by test_json_only_suffix_is_format_safe)."""
    r9 = _router9()
    prompt = r9._construct_prompt(
        "if (a) { b(); }",
        {"system_prompt": "SYS", "vuln_prompt": "Analyze {code_snippet} at {file_path}", "file_path": "F.java"},
    )
    assert "if (a) { b(); }" in prompt and "F.java" in prompt and prompt.startswith("SYS")


def test_path_to_class_java_and_smali(tmp_path):
    import os
    cg = CallGraphBuilder(str(tmp_path))
    java = os.path.join(str(tmp_path), "sources", "com", "example", "Foo.java")
    smali = os.path.join(str(tmp_path), "smali", "com", "example", "Foo.smali")
    assert cg.path_to_class(java) == "com/example/Foo"
    assert cg.path_to_class(smali) == "com/example/Foo"
    assert cg.path_to_class(os.path.join(str(tmp_path), "other", "X.txt")) is None
