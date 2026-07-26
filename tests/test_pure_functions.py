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
def test_path_to_class_java_and_smali(tmp_path):
    import os
    cg = CallGraphBuilder(str(tmp_path))
    java = os.path.join(str(tmp_path), "sources", "com", "example", "Foo.java")
    smali = os.path.join(str(tmp_path), "smali", "com", "example", "Foo.smali")
    assert cg.path_to_class(java) == "com/example/Foo"
    assert cg.path_to_class(smali) == "com/example/Foo"
    assert cg.path_to_class(os.path.join(str(tmp_path), "other", "X.txt")) is None
