"""
Golden Test — Layer 2 (SEMANTIC, calls a real LLM).

Runs a full DLH scan of VulnerAppDLHv2.apk and checks the findings against the
curated ground-truth baseline (tests/golden/vulnerapp_expected.json):

  - RECALL contract: every expected {rule -> file} true-positive is detected.
  - PRECISION guards: `must_not_fire` rules/files do NOT appear.

This is OPT-IN and never runs in the default suite:
    pytest -m llm

Requirements: VulnerAppDLHv2.apk present at repo root, a configured LLM provider in
config/settings.yaml (uses whatever provider is set), apktool + jadx installed.
The response cache (v1.2.0) makes re-runs cheap; changing a prompt busts its key.
"""
import json
import os

import pytest
import yaml

pytestmark = pytest.mark.llm

REPO = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
APK = os.path.join(REPO, "VulnerAppDLHv2.apk")
BASELINE_PATH = os.path.join(REPO, "tests", "golden", "vulnerapp_expected.json")
RULES_DIR = os.path.join(REPO, "config", "prompts", "vuln_rules")


def _load_baseline():
    with open(BASELINE_PATH) as f:
        return json.load(f)


def _rule_name(rule_key):
    """Map a rule key (sql_injection) to the report's vulnerability name ('SQL Injection')."""
    with open(os.path.join(RULES_DIR, rule_key + ".yaml")) as f:
        return yaml.safe_load(f).get("name", rule_key)


def _stem(path):
    return os.path.splitext(os.path.basename(str(path)))[0]


def _rules_to_enable(baseline):
    keys = set(baseline["expected"])
    keys |= {k for k in baseline.get("must_not_fire", {}) if not k.startswith("_") and k != "*"}
    return sorted(keys)


@pytest.fixture(scope="module")
def findings():
    """Run one scan and return {vulnerability_name -> set(file stems)} of Vulnerable results."""
    if not os.path.exists(APK):
        pytest.skip(f"VulnerAppDLHv2.apk not found at {APK}")

    from core.config_loader import load_settings
    from core.engine import Engine

    baseline = _load_baseline()
    rules = _rules_to_enable(baseline)

    settings = load_settings()
    for r in rules:
        if hasattr(settings.rules, r):
            setattr(settings.rules, r, True)
    settings.analysis.generate_exploit = False  # findings only, no PoC

    out = os.path.join(REPO, "output", "_golden_layer2_report.json")
    engine = Engine(settings)
    engine.run(APK, output_file=out, no_decompile=False, rules=",".join(rules))

    with open(out) as f:
        report = json.load(f)

    vuln_map = {}
    for r in report.get("results", []):
        if str(r.get("status", "")).lower() == "vulnerable":
            stem = _stem(r.get("file", ""))
            vuln_map.setdefault(r.get("vulnerability"), set()).add(stem)
            # [#E] merged/folded findings live under 'also_detected_by' — still count them.
            for extra in (r.get("also_detected_by") or []):
                vuln_map.setdefault(extra.get("vulnerability"), set()).add(stem)
    return vuln_map


def test_recall_contract(findings):
    """
    Regression contract: detected findings must cover the recall FLOOR
    (expected ground-truth MINUS documented known_gaps). Dropping below the floor
    is a regression and fails. known_gaps are pre-existing detection-pattern gaps
    tracked for v1.3.0; if one starts getting detected, tighten the baseline.
    """
    baseline = _load_baseline()
    gaps = {k: set(v) for k, v in baseline.get("known_gaps", {}).items()
            if not k.startswith("_") and isinstance(v, list)}

    total = sum(len(v) for v in baseline["expected"].values())
    missing_floor = []        # required TPs not detected -> REGRESSION (fail)
    gap_now_detected = []     # known gaps that DID get detected -> tighten baseline
    gap_still_missing = 0

    for rule_key, files in baseline["expected"].items():
        name = _rule_name(rule_key)
        detected = findings.get(name, set())
        gap_files = gaps.get(rule_key, set())
        for f in files:
            if f in gap_files:
                if f in detected:
                    gap_now_detected.append(f"{rule_key} on {f}")
                else:
                    gap_still_missing += 1
            elif f not in detected:
                missing_floor.append(f"  - {rule_key} ({name}) expected on {f}")

    floor = total - sum(len(v) for v in gaps.values())
    hit_floor = floor - len(missing_floor)
    summary = (f"RECALL: floor {hit_floor}/{floor} met; "
               f"{gap_still_missing} known-gap(s) still missing; "
               f"total ground-truth {total - len(missing_floor) - gap_still_missing}/{total}.")
    print("\n" + summary)
    if gap_now_detected:
        print("known_gaps now DETECTED (consider tightening baseline): " + ", ".join(gap_now_detected))

    assert not missing_floor, (
        summary + "\nREGRESSION — recall dropped below floor:\n" + "\n".join(missing_floor)
    )


def test_precision_guards(findings):
    """`must_not_fire` rules/files must NOT be reported."""
    baseline = _load_baseline()
    violations = []
    for rule_key, spec in baseline.get("must_not_fire", {}).items():
        if rule_key.startswith("_"):
            continue
        name = _rule_name(rule_key)
        detected = findings.get(name, set())
        if spec == "*":
            if detected:
                violations.append(f"  - {rule_key} ({name}) must NOT fire at all, but hit: {sorted(detected)}")
        elif isinstance(spec, list):
            bad = detected & set(spec)
            if bad:
                violations.append(f"  - {rule_key} ({name}) must NOT fire on library files, but hit: {sorted(bad)}")

    assert not violations, "PRECISION violations:\n" + "\n".join(violations)
