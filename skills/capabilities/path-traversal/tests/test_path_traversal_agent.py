"""Regression tests for path-traversal agent FP-prone logic."""
import os
import sys
from pathlib import Path

BASE = Path(__file__).resolve().parents[1]
SCRIPT_DIR = BASE / "performing-directory-traversal-testing" / "scripts"
sys.path.insert(0, str(SCRIPT_DIR))

import importlib.util
_SPEC = importlib.util.spec_from_file_location("path_traversal_agent", SCRIPT_DIR / "agent.py")
agent = importlib.util.module_from_spec(_SPEC)
_SPEC.loader.exec_module(agent)


def test_normal_200_not_vulnerable():
    body = "<html><body>Welcome to our site</body></html>" * 5
    result = agent.evaluate_traversal_response(200, body)
    assert result["vulnerable"] is False
    assert result["severity"] is None


def test_false_positive_content_match_not_critical():
    # HTTP 200, length>100, no '404', but no meaningful file content.
    body = "A" * 200
    result = agent.evaluate_traversal_response(200, body)
    assert result["vulnerable"] is False
    assert result["severity"] is None
    # Ensure no CRITICAL auto-mark anywhere in wrapper path.
    assert "CRITICAL" not in str(result)


def test_genuine_file_retrieval_vulnerable():
    body = "root:x:0:0:root:/root:/bin/bash\nbin:x:1:1:bin:/bin:/sbin/nologin"
    result = agent.evaluate_traversal_response(200, body)
    assert result["vulnerable"] is True
    assert result["severity"] != "CRITICAL"
    assert result["severity"] in ("MEDIUM", "HIGH")


def test_sensitive_file_retrieval_higher_severity():
    body = "root:$6$abc$hash:0:0:root:/root:/bin/bash\n-----BEGIN RSA PRIVATE KEY-----\nSECRET"
    result = agent.evaluate_traversal_response(200, body)
    assert result["vulnerable"] is True
    assert result["sensitive"] is True
    assert result["severity"] == "HIGH"


def test_encoded_traversal_normalization():
    assert agent.normalize_traversal_value("..%2f..%2f..%2fetc%2fpasswd") == "../../../etc/passwd"
    assert agent.is_traversal_payload("..%2f..%2f..%2fetc%2fpasswd") is True
    assert agent.is_traversal_payload("../../../etc/passwd") is True


def test_normalization_behavior():
    # redundant separators collapse
    assert agent.normalize_traversal_value("a//b///c") == "a/b/c"
    # backslashes normalized to forward slashes
    assert "\\" not in agent.normalize_traversal_value("a\\b\\c")
    # null bytes removed
    assert "\x00" not in agent.normalize_traversal_value("a\x00/b")


def test_wrapper_no_auto_critical():
    class Resp:
        status_code = 200
        text = "A" * 300  # no '404', long, but no file content

    class Session:
        def get(self, *a, **k):
            return Resp()

    # patch requests.Session used by agent? agent.test_wrapper_protocols accepts session.
    results = agent.test_wrapper_protocols("http://example.com/view?file=x", "file", Session())
    assert results == []


if __name__ == "__main__":
    tests = [
        test_normal_200_not_vulnerable,
        test_false_positive_content_match_not_critical,
        test_genuine_file_retrieval_vulnerable,
        test_sensitive_file_retrieval_higher_severity,
        test_encoded_traversal_normalization,
        test_normalization_behavior,
        test_wrapper_no_auto_critical,
    ]
    for t in tests:
        try:
            t()
            print(f"PASS {t.__name__}")
        except AssertionError as e:
            print(f"FAIL {t.__name__}: {e}")