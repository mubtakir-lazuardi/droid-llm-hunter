"""
Golden test — Layer 1 (deterministic, no LLM).

Locks in config-schema invariants: the shipped settings validate, rules stay A-Z
(list-rules order), the rule count is stable, and the Gemini key field is consistent
with the other providers (v1.2.0 #16 rename).
"""
from core.config_loader import load_settings, RulesSettings, LLMSettings


def test_shipped_settings_are_valid():
    s = load_settings()
    assert s.llm.provider
    assert s.analysis is not None
    assert s.rules is not None


def test_rules_are_alphabetical():
    fields = list(RulesSettings.model_fields)
    assert fields == sorted(fields), "RulesSettings must stay A-Z (drives list-rules order)"


def test_rule_count_stable():
    assert len(RulesSettings.model_fields) == 25


def test_gemini_api_key_field_is_consistent():
    # v1.2.0 #16: Gemini used the generic `api_key`; renamed to `gemini_api_key`.
    assert "gemini_api_key" in LLMSettings.model_fields
    assert "api_key" not in LLMSettings.model_fields


def test_new_v120_settings_exist():
    for field in ("max_workers", "use_cache", "max_input_chars"):
        assert field in __import__("core.config_loader", fromlist=["AnalysisSettings"]).AnalysisSettings.model_fields
    assert "max_tokens" in LLMSettings.model_fields
