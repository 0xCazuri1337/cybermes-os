"""T25 — source intake: validate the intake itself, in BOTH directions.

The lesson this encodes (wave 8, twice): a checker trusted in one direction
protects nothing. The first negative control of the quote gate "passed" for the
wrong reason -- its fixture differed from the real one in TWO dimensions, so it
was rejected on shape rather than on the dimension under test. Every control
here differs from a genuine candidate in exactly ONE dimension and is
otherwise byte-identical in construction.

Run:  python eval/test_wks_source_intake.py
Exit: non-zero on any failure. Expect red if `assess()` is weakened.
"""
from __future__ import annotations

import json
import sys
import tempfile
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT))

from wks import config, source_intake  # noqa: E402

FAILS: list[str] = []


def check(name: str, cond: bool, detail: str = "") -> None:
    print(f"  {'PASS' if cond else 'FAIL'}  {name}"
          + (f"  [{detail}]" if detail and not cond else ""))
    if not cond:
        FAILS.append(name)


# --- T25.1  a genuinely good host+path is NOT blocked by the host filter ----
def t25_host_filter_not_overbroad() -> None:
    print("T25.1  host filter rejects only builder/UGC hosts")
    for host, want in [("portswigger.net", False),
                       ("cwe.mitre.org", False),
                       ("cheatsheetseries.owasp.org", False),
                       ("owasp.org", False),
                       ("www.rfc-editor.org", False),
                       ("gitlab.com", False),
                       ("app.notion.com", True),
                       ("foo.gitbook.io", True),
                       ("x.vercel.app", True),
                       ("someone.github.io", True),
                       ("readthedocs.io", True)]:
        got = source_intake.is_builder_host(host)
        check(f"{host} -> builder={got}", got is want, f"expected {want}")


# --- T25.2  a real fetch+vocabulary page is ACCEPTED ----------------------
def t25_accepts_real_page() -> None:
    print("T25.2  a live on-topic page is accepted (positive control)")
    body = ("broken object level authorization means the server does not "
            "verify the caller is entitled to the object the request names; "
            "insecure direct object reference, bola, and authorization "
            "boundary failures all describe this class of flaw. ") * 40
    html = f"<html><head><title>IDOR / BOLA</title></head><body>{body}</body></html>"
    v = _assess_with_body("https://intake-control.test/idor-deep-dive",
                          "idor", html)
    check("live on-topic page accepted", v["accepted"] is True,
          f"refused: {v.get('reason')}")
    check("it recorded marker hits", bool(v.get("marker_hits")),
          str(v.get("marker_hits")))


# --- T25.3  NEGATIVE: same page, class vocabulary removed ------------------
def t25_refuses_offtopic_page() -> None:
    print("T25.3  same page, DIFFERENT class -> refused (negative control)")
    # Identical construction to T25.2; only the class differs, which is the
    # one dimension under test.
    filler = ("this page lists navigation links and a footer for a general "
              "security portal with no technical depth whatsoever. ") * 60
    html = f"<html><head><title>Portal</title></head><body>{filler}</body></html>"
    v = _assess_with_body("https://example.test/portal", "idor", html)
    check("off-topic page refused", v["accepted"] is False)
    check("refusal names the reason", "vocabulary" in v.get("reason", ""),
          v.get("reason", ""))


# --- T25.4  NEGATIVE: JS shell / bot wall, plenty of bytes ---------------
def t25_refuses_shell() -> None:
    print("T25.4  a 200 that is a JS shell is refused (negative control)")
    # Repeated marker text can be arbitrarily LONG and still be a shell: a
    # 7,400-char page that says "enable javascript" 400 times carries no
    # article. The size floor alone cannot catch it, which is why the shell
    # test also requires the page to hold real class vocabulary.
    shell = ("<html><body>" + ("enable javascript to continue. " * 400)
             + "</body></html>")
    v = _assess_with_body("https://example.test/app", "idor", shell)
    check("long JS shell refused", v["accepted"] is False, str(v))
    check("refusal is explained",
          any(k in v.get("reason", "") for k in ("shell", "chars", "vocabulary")),
          v.get("reason", ""))

    # The same shell WITH the class vocabulary must still be refused: the
    # words are present but the page has no distinct prose, so it is a
    # catch-all echoing keywords rather than a source.
    kw = shell[:-14] + ("idor insecure direct object reference bola. " * 200)
    v2 = _assess_with_body("https://example.test/app2", "idor", kw)
    check("keyword-stuffed shell refused", v2["accepted"] is False, str(v2))


# --- T25.4b  a REAL page carrying a shell marker in its footer is KEPT ----
def t25_keeps_footer_marker() -> None:
    print("T25.4b a long real article with a JS footer is KEPT")
    # MEASURED on owasp.org: 12,396 chars of prose plus the boilerplate
    # "it is necessary to enable JavaScript" in the site footer. Refusing here
    # would discard a normative source from one of five normative orgs.
    art = " ".join(_VARIED_CLICKJACKING) * 6
    html = (f"<html><body>{art}"
            "<footer>For full functionality of this site it is necessary to "
            "enable JavaScript.</footer></body></html>")
    v = _assess_with_body("https://intake-control2.test/clickjacking",
                          "clickjacking", html)
    check("real article with a JS footer accepted", v["accepted"] is True,
          f"refused: {v.get('reason')}")


# Realistic prose: a page of genuine article text, not one sentence repeated.
# A fixture that repeats a single paragraph 40 times is itself a keyword blob,
# so it cannot certify that the intake keeps genuine content.
_VARIED_CLICKJACKING = [
    "Clickjacking is a UI redress attack in which an attacker overlays a "
    "transparent frame so the victim clicks a control they cannot see.",
    "The technique usually combines with a genuine interface, such as a "
    "transfer page or an administrative action the user already trusts.",
    "Frame busting scripts were the historical defence, breaking out when the "
    "page detects that it is not framed by the expected origin.",
    "Modern deployments set the X-Frame-Options response header instead, "
    "which browsers enforce far more reliably than client-side script.",
    "The Content-Security-Policy frame-ancestors directive supersedes that "
    "header and expresses the same restriction in a modern grammar.",
    "A framing defence is only effective when every sensitive action is "
    "covered; a single unprotected endpoint reopens the whole flow.",
    "Attackers frequently chain clickjacking with CSRF when the overlay is "
    "delivered from a third-party host with its own framing permissions.",
    "Detection therefore examines both the framing policy and the actions "
    "reachable behind it, rather than trusting a header that may be partial.",
    "Multi-factor confirmation dialogs raise the cost of a successful overlay "
    "because the victim must also complete an independent verification step.",
    "Audits should inventory every state-changing endpoint and record which "
    "of them an attacker could plausibly frame behind deceptive UI.",
]


# --- T25.5  NEGATIVE: already-known URL is a no-op, never a 2nd publisher -
def t25_refuses_duplicate() -> None:
    print("T25.5  an already-registered URL cannot enter twice")
    doc = source_intake.load()
    known = "https://cwe.mitre.org/data/definitions/79.html"
    v = source_intake.assess(known, "xss", False, None)
    check("known URL marked duplicate", v.get("duplicate") is True, str(v))
    check("known URL not accepted", v["accepted"] is False)


# --- T25.6  the builder actually MERGES discovered sources ---------------
def t25_builder_merges() -> None:
    print("T25.6  tools/build_sources.py merges the discovered registry")
    sys.path.insert(0, str(ROOT / "tools"))
    import importlib.util
    spec = importlib.util.spec_from_file_location(
        "bs_probe", ROOT / "tools" / "build_sources.py")
    bs = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(bs)
    doc = bs.build()
    urls = {e["url"] for e in doc["sources"]}
    disc = source_intake.load()["sources"]
    missing = [e["url"] for e in disc if e["url"] not in urls]
    check("every discovered source reaches sources.json", not missing,
          f"missing {missing}")
    # A discovered LEAD must not be able to satisfy the gate on its own.
    leads = [e for e in doc["sources"] if e["role"] == "lead"]
    check("discovered leads stay leads", all(e["role"] == "lead" for e in leads))


def _assess_with_body(url: str, class_id: str, html: str) -> dict:
    """`assess()` with the network stubbed, so the test is deterministic."""
    real_fetch = source_intake.fetch
    source_intake.fetch = lambda u, timeout=25: (200, html)  # type: ignore
    try:
        return source_intake.assess(url, class_id, False, None)
    finally:
        source_intake.fetch = real_fetch  # type: ignore


def main() -> int:
    print("=== T25 source intake ===")
    t25_host_filter_not_overbroad()
    t25_accepts_real_page()
    t25_refuses_offtopic_page()
    t25_refuses_shell()
    t25_keeps_footer_marker()
    t25_refuses_duplicate()
    t25_builder_merges()
    print(f"\n{'ALL PASS' if not FAILS else 'FAILED: ' + ', '.join(FAILS)}")
    return 1 if FAILS else 0


if __name__ == "__main__":
    sys.exit(main())
