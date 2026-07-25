"""
Golden test — Layer 1 (deterministic, no LLM).

Validates that every rule's `detection_pattern` actually matches representative code
in the DEFAULT `hybrid` (JADX / Java) mode. This is the layer that catches "dead rule"
bugs where a Smali-only pattern never matches Java source (see the fragment_injection
regression below). It mirrors CodeFilter, which compiles patterns with no extra flags.
"""
import glob
import os
import re

import pytest
import yaml

RULES_DIR = os.path.join(
    os.path.dirname(os.path.dirname(os.path.abspath(__file__))),
    "config", "prompts", "vuln_rules",
)


def _load(name):
    with open(os.path.join(RULES_DIR, name + ".yaml")) as f:
        return yaml.safe_load(f)


def _all_rules():
    return sorted(os.path.basename(p)[:-5] for p in glob.glob(os.path.join(RULES_DIR, "*.yaml")))


# Representative snippets each rule's detection_pattern MUST match.
# Java snippets reflect the default hybrid (JADX) mode; manifest rules use XML.
POSITIVE = {
    "biometric_bypass": "BiometricPrompt p = new BiometricPrompt(activity, exec, cb);",
    "deeplink_hijack": '<data android:scheme="myapp" android:host="open"/>',
    "deeplink_logic_bypass": 'String t = uri.getQueryParameter("token");',
    "exported_components": '<activity android:name=".A" android:exported="true"/>',
    "fragment_injection": "public class SettingsActivity extends PreferenceActivity {",
    "graphql_injection": 'String query = "query { user(id:1){name} }";',
    "hardcoded_secrets": 'String password = "hunter2";',
    "insecure_deserialization": "ObjectInputStream ois = new ObjectInputStream(is); ois.readObject();",
    "insecure_file_permissions": "openFileOutput(name, MODE_WORLD_READABLE);",
    "insecure_random_number_generation": "Random r = new Random();",
    "insecure_storage": 'getSharedPreferences("p", MODE_PRIVATE);',
    "insecure_webview": 'webView.addJavascriptInterface(new Bridge(), "app");',
    "intent_spoofing": '<receiver android:name=".R" android:exported="true"/>',
    "jetpack_compose_security": "@Composable fun LoginScreen() {}",
    "library_vulnerability": "DexClassLoader cl = new DexClassLoader(path, opt, null, parent);",
    "path_traversal": "public ParcelFileDescriptor openFile(Uri uri, String mode) {",
    "pending_intent_hijacking": "PendingIntent.getActivity(ctx, 0, i, PendingIntent.FLAG_MUTABLE);",
    "sql_injection": 'db.rawQuery("SELECT * FROM u WHERE n=" + name, null);',
    "unsafe_reflection": 'Class.forName(intent.getStringExtra("cls"));',
    "universal_logic_flaw": "public boolean shouldOverrideUrlLoading(WebView v, String url) {",
    "webview_deeplink": '<action android:name="android.intent.action.VIEW"/>',
    "webview_file_access": "settings.setAllowFileAccess(true);",
    "webview_xss": "settings.setJavaScriptEnabled(true);",
    "zip_slip": "for (ZipEntry e : zip.entries()) { new File(dir, e.getName()); }",
}

# Rules that intentionally have NO detection_pattern (keyword-only / manifest heuristic).
NO_PATTERN = {"strandhogg", "hardcoded_secrets_xml"}


def test_every_rule_has_golden_coverage():
    """If a new rule is added, force adding a snippet here (or listing it in NO_PATTERN)."""
    for rule in _all_rules():
        assert rule in POSITIVE or rule in NO_PATTERN, f"Rule '{rule}' has no golden coverage"


@pytest.mark.parametrize("rule", sorted(POSITIVE))
def test_detection_pattern_matches_sample(rule):
    data = _load(rule)
    pat = data.get("detection_pattern")
    assert pat, f"Rule '{rule}' is expected to have a detection_pattern"
    rx = re.compile(pat)  # mirrors CodeFilter (no external flags)
    assert rx.search(POSITIVE[rule]), (
        f"detection_pattern for '{rule}' does not match its default-mode sample: {POSITIVE[rule]!r}"
    )


def test_all_detection_patterns_compile():
    for rule in _all_rules():
        pat = _load(rule).get("detection_pattern")
        if pat:
            re.compile(pat)  # raises re.error if invalid


def test_fragment_injection_matches_both_java_and_smali():
    """Regression for the v1.2.0 [B] fix: this rule was Smali-only and dead in hybrid mode."""
    rx = re.compile(_load("fragment_injection")["detection_pattern"])
    assert rx.search("class X extends PreferenceActivity {"), "must match JADX/Java (default mode)"
    assert rx.search(".super Landroid/preference/PreferenceActivity;"), "must still match apktool/Smali"


@pytest.mark.parametrize("rule,benign", [
    ("fragment_injection", "public class X extends Activity {"),
    ("sql_injection", "int total = a + b;"),
    ("insecure_random_number_generation", "int x = getRandomFromSecureSource();"),
])
def test_negative_cases_do_not_match(rule, benign):
    rx = re.compile(_load(rule)["detection_pattern"])
    assert not rx.search(benign), f"'{rule}' pattern should NOT match benign code: {benign!r}"
