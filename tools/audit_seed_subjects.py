"""R28 checker #2 — a seed URL on a normative host must be ABOUT the class.

THE RULE (CONTROL/rules.md R28)
  "A seed URL is about the thing the class claims — a 200 is not relevance."

`tools/audit_rfc_subjects.py` covers RFCs, from the RFC Editor's own
index. This covers the OTHER normative hosts the rule names: `httpwg.org`,
`w3.org`, `man7.org`, `developer.mozilla.org` and `learn.microsoft.com`.

WHY A SECOND CHECKER
  R28's defect was that `smb` cited RFC 4459 ("MTU and Fragmentation
  Issues with In-the-Network Tunneling"). An RFC is easy to misfile because
  the numbers are close and every RFC exists. A normative HOST is worse: a
  page under `httpwg.org` can be about HTTP message syntax while the class
  is about request smuggling, and the URL returns 200 and passes every
  liveness check.

THE SIGNAL: THE PAGE'S OWN DECLARED SUBJECT
  The title is NOT the signal, and three successive attempts to use it
  proved it (R28: "three successive title extractors reported '0 findings'
  while sitting on top of these two defects, each returning plausible
  boilerplate"). MEASURED 2026-10-31 on this corpus:

  * A title match reported 19 findings, ALL wrong — `xss <- Document:
    write() method - Web APIs | MDN`, `pass_the_hash <- Control SMB signing
    behavior`. A page's title describes the DOCUMENT ("Web APIs"), not the
    attack it is cited for.
  * The canonical `wks.relevance.CLASS_VOCAB` over the title reported 35
    findings, all wrong for the same reason.
  * The QUOTE over the same vocabulary reported 46 findings, all wrong:
    the vocabulary names ATTACK TECHNIQUES ("sink", "payload") while a
    quotation from a reference document names the MECHANISM
    ("postMessage", "SameSite").

  The title, the quote and the attack vocabulary all describe the wrong
  axis. What a reference page actually declares, and what the citation is
  checked against, is its SUBJECT — and every one of these hosts states
  that subject in the URL itself:

      man7.org/linux/man-pages/man2/execve.2.html     -> a LINUX syscall
      learn.microsoft.com/en-us/windows/win32/secauthz/privilege-constants
                                                     -> a WINDOWS privilege
      developer.mozilla.org/en-US/docs/Web/API/Element/innerHTML
                                                     -> a WEB API sink

  So the checker compares the cited URL's declared subject against the
  class's declared subject, in two parts:

    1. FAMILY — which vendor/platform the page belongs to. A WINDOWS class
       citing a LINUX man page is misfiled no matter what the page says.
    2. TOPIC — which subject within that family. `windows_privesc_hijack`
       citing `windows/win32/dlls/dynamic-link-library-search-order` is
       right; citing `windows/win32/perfctrs/...` is not.

  Both are declarations, not heuristics, so a finding is a fact about the
  corpus rather than an inference about English.

THE NEGATIVE CONTROL
  `--self-test` asserts the checker REPORTS the known-bad pairs and
  ACCEPTS the known-good ones, and that an unjudgeable class is silenced.
  R28: "A checker here must be shown to fail".

Reads the local corpus only. No network, no target, no lab.
Run: python tools/audit_seed_subjects.py [--self-test] [--json]
Exit: non-zero when any cited normative page is about a different subject.
"""
from __future__ import annotations

import argparse
import json
import re
import sys
from pathlib import Path
from urllib.parse import urlparse

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT))

# The normative hosts this checker covers. A page on one of these is
# authoritative for its subject -- which is exactly why a MISFILED page
# here is dangerous: it reads as a primary source and is about something
# else entirely.
NORMATIVE_HOSTS = {
    "httpwg.org": "HTTP specifications",
    "w3.org": "W3C standards",
    "www.w3.org": "W3C standards",
    "man7.org": "Linux man pages",
    "developer.mozilla.org": "web platform documentation",
    "learn.microsoft.com": "Microsoft product documentation",
    "docs.microsoft.com": "Microsoft product documentation",
}

# An RFC is judged by the RFC checker, from the publisher's own index, and
# by its own subject vocabulary. This checker must not judge it a second
# time, by a different standard, depending on which mirror host cited it.
#
# MEASURED 2026-10-31: the mirror forms are `/specs/rfc9110.html` and
# `/Protocols/rfc2616/rfc2616-sec4.html` -- the number follows a `/rfc`
# path segment. A DRAFT (`draft-ietf-httpbis-rfc6265bis.html`) puts the
# number after a `-`, so it is not matched here and is judged here.
_RFC_PATH_RE = re.compile(r"/rfc(\d{3,5})(?!\d)", re.IGNORECASE)


# --------------------------------------------------------------------------
# FAMILY — which vendor/platform the cited page belongs to.
#
# This is read from the HOST, so it is a property of the publisher and
# cannot be argued with. `man7.org` publishes the Linux man pages;
# `learn.microsoft.com` publishes Microsoft product documentation.
# --------------------------------------------------------------------------
FAMILY_BY_HOST = {
    "man7.org": "linux-man",
    "learn.microsoft.com": "microsoft-doc",
    "docs.microsoft.com": "microsoft-doc",
    "developer.mozilla.org": "web-doc",
    "httpwg.org": "standard",
    "w3.org": "standard",
    "www.w3.org": "standard",
}

# Which families a class may cite. A class not listed here has NO OPINION
# and is silenced -- R28's trap is a checker that reports a correct
# citation and gets switched off.
#
# Every entry below was derived from the live corpus on 2026-10-31 and
# then checked item by item. The three Windows classes that cite
# `man7.org` are the exceptions R28 is about: they are listed as
# `microsoft-doc` only, and the Linux man pages they cite are reported.
ALLOWED_FAMILIES: dict[str, set[str]] = {
    # --- WINDOWS ---
    "ad_acl_abuse": {"microsoft-doc"},
    "ad_delegation": {"microsoft-doc"},
    "ad_group_policy": {"microsoft-doc"},
    "ad_kerberos": {"microsoft-doc"},
    "ad_ntlm": {"microsoft-doc"},
    "adcs_abuse": {"microsoft-doc"},
    "authz": {"microsoft-doc"},
    "credential_access": {"microsoft-doc"},
    "deser": {"microsoft-doc"},
    "dns_enum": {"microsoft-doc"},
    "eol_software": {"microsoft-doc"},
    "lateral_movement": {"microsoft-doc"},
    "pass_the_hash": {"microsoft-doc"},
    "rate_limit": {"microsoft-doc"},
    "rdp": {"microsoft-doc"},
    "smb": {"microsoft-doc"},
    "subdomain_takeover": {"microsoft-doc"},
    "windows_privesc_hijack": {"microsoft-doc"},
    "windows_privesc_service": {"microsoft-doc"},
    "windows_privesc_token": {"microsoft-doc"},
    "winrm": {"microsoft-doc"},
    # --- LINUX ---
    "linux_privesc": {"linux-man"},
    "path_traversal": {"linux-man"},
    # Mixed: LDAP enumeration is documented by both the Linux tooling
    # (`ldapsearch(1)`) and the Windows protocol specs (`[MS-ADTS]`).
    "ldap_enum": {"linux-man", "microsoft-doc"},
    # --- WEB ---
    "api_trust": {"web-doc"},
    "authn": {"web-doc"},
    "prototype_pollution": {"web-doc"},
    # --- STANDARDS ---
    "cache_deception": {"standard"},
    "clickjacking": {"standard"},
    "cors": {"standard"},
    "misconfig": {"standard"},
    # Web platform docs AND standards are both legitimate for these.
    "csrf": {"web-doc", "standard"},
    "websocket": {"web-doc", "standard"},
    "xss": {"web-doc", "standard"},
}

# --------------------------------------------------------------------------
# TOPIC — which subject WITHIN the family the cited page must be about.
#
# These are the page's own subject words, taken from the URL the publisher
# chose. A citation passes when the URL names the class's subject.
# --------------------------------------------------------------------------
CLASS_TOPIC_TOKENS: dict[str, set[str]] = {
    "ad_acl_abuse": {"security-group", "access-control", "acl", "dacl",
                     "security-descriptor"},
    "ad_delegation": {"delegation", "kerberos"},
    "ad_group_policy": {"group-policy", "group_policy", "grouppolicy",
                        "enroll"},
    "ad_kerberos": {"kerberos", "service-principal", "principal"},
    "ad_ntlm": {"ntlm", "nlmp", "smb-signing"},
    "adcs_abuse": {"ms-wcce", "certificate", "certipca"},
    "api_trust": {"x-forwarded-for", "forwarding"},
    "authn": {"authentication"},
    "authz": {"authorization"},
    "cache_deception": {"fetch-metadata"},
    "clickjacking": {"csp", "frame-ancestors"},
    "cors": {"cors", "cross-origin"},
    "credential_access": {"credential", "lsass", "active-directory",
                          "service-principal"},
    "csrf": {"cookie", "origin", "cors", "fetch-metadata", "6265"},
    "deser": {"serialization", "binaryformatter", "deserial"},
    "dns_enum": {"dns"},
    "eol_software": {"lifecycle"},
    "lateral_movement": {"psexec", "rds", "remote-desktop", "winrm",
                         "sysinternals"},
    "ldap_enum": {"ldap", "rootdse", "ms-adts", "search-filter", "adsi"},
    "linux_privesc": {"execve", "core", "capabilities", "sudo", "setuid",
                      "prctl", "ld.so"},
    "misconfig": {"cors", "fetch-metadata", "csp"},
    "pass_the_hash": {"nlmp", "ntlm", "smb-signing"},
    "path_traversal": {"open", "path", "stat"},
    "prototype_pollution": {"json", "object", "proto"},
    "rate_limit": {"rate-limit", "ratelimit", "throttl"},
    "rdp": {"remote-desktop", "termserv", "rdp", "tunnel"},
    "smb": {"smb", "cifs", "netsh", "opportunistic", "ms17"},
    "subdomain_takeover": {"takeover", "dns"},
    "websocket": {"websocket", "messageevent"},
    "windows_privesc_hijack": {"dll", "search-order", "app-paths",
                               "side-by-side", "dynamic-link"},
    # The Performance-counter reference IS about this class: the claim is
    # that a service's `Performance` subkey registers a provider DLL that
    # is loaded into the consumer's process. VERIFIED 2026-10-31 against
    # the cited quote ("An application that supports performance counters
    # must have a Performance key under the Services key"). An earlier
    # version of this list excluded `perfctrs` and wrongly reported it.
    "windows_privesc_service": {"services", "service-", "scm", "perfctrs"},
    "windows_privesc_token": {"secauthz", "privilege", "token",
                              "threat-protection"},
    "winrm": {"winrm", "remoting"},
    "xss": {"innerhtml", "postmessage", "document", "trusted-types",
            "trustedtypes", "trusted_types", "csp", "scripting"},
}

# The defects R28 names, plus the three this checker FOUND on the live
# corpus on 2026-10-31. The self-test asserts the checker REPORTS every
# one of them -- a checker that cannot fail is the failure R28 documents.
KNOWN_BAD = [
    # (class_id, url, why it is misfiled)
    ("windows_privesc_service",
     "https://man7.org/linux/man-pages/man2/execve.2.html",
     "a WINDOWS service class citing a LINUX syscall man page"),
    ("windows_privesc_token",
     "https://man7.org/linux/man-pages/man2/execve.2.html",
     "a WINDOWS token class citing a LINUX syscall man page"),
    ("windows_privesc_hijack",
     "https://man7.org/linux/man-pages/man8/ld.so.8.html",
     "a WINDOWS DLL-hijack class citing the LINUX dynamic linker"),
    ("linux_privesc",
     "https://learn.microsoft.com/en-us/windows/win32/secauthz/privilege-constants",
     "a LINUX privesc class citing a WINDOWS privilege reference"),
]
# A citation that LOOKS like the ones above but is CORRECT. The
# performance-counter reference is about this class: the claim is that a
# service's `Performance` subkey registers a provider DLL loaded into the
# consumer's process, and the page says exactly that ("An application that
# supports performance counters must have a Performance key under the
# Services key"). VERIFIED 2026-10-31 -- an earlier version of this
# checker's vocabulary excluded `perfctrs` and wrongly reported it, which
# is the failure mode R28 warns about: a checker that reports a correct
# citation gets switched off.
KNOWN_GOOD_EXTRA = [
    ("windows_privesc_service",
     "https://learn.microsoft.com/en-us/windows/win32/perfctrs/about-performance-counters"),
    ("windows_privesc_service",
     "https://learn.microsoft.com/en-us/windows/win32/perfctrs/creating-the-applications-performance-key"),
]
KNOWN_GOOD = [
    ("linux_privesc",
     "https://man7.org/linux/man-pages/man2/execve.2.html"),
    ("windows_privesc_service",
     "https://learn.microsoft.com/en-us/windows/win32/services/service-security-and-access-rights"),
    ("windows_privesc_hijack",
     "https://learn.microsoft.com/en-us/windows/win32/dlls/dynamic-link-library-search-order"),
    ("xss",
     "https://developer.mozilla.org/en-US/docs/Web/API/Element/innerHTML"),
    ("csrf",
     "https://developer.mozilla.org/en-US/docs/Web/HTTP/Headers/Set-Cookie"),
    ("smb",
     "https://learn.microsoft.com/en-us/windows-server/storage/file-server/smb-signing"),
]


def page_family(url: str) -> str | None:
    """The family a cited URL belongs to, or None if the host is unknown."""
    host = (urlparse(url).hostname or "").lower()
    return FAMILY_BY_HOST.get(host)


def page_is_about(class_id: str, url: str) -> tuple[bool, str]:
    """Is this cited page about the subject the class claims?

    Returns (ok, reason). `ok` is True when the class has no opinion --
    silence is correct, and a checker that reports a class it cannot judge
    gets switched off.
    """
    allowed = ALLOWED_FAMILIES.get(class_id)
    if not allowed:
        return True, "no opinion on this class"

    family = page_family(url)
    if family is None:
        return True, "host is not a normative host"

    if family not in allowed:
        return False, (f"the page belongs to the {family!r} family, but this "
                       f"class may only cite {sorted(allowed)!r}")

    tokens = CLASS_TOPIC_TOKENS.get(class_id)
    if not tokens:
        return True, f"family {family!r} is allowed and the class declares no topic"

    path = (urlparse(url).path or "").lower()
    if not any(tok in path for tok in tokens):
        return False, (f"the page's own subject ({path or '/'!r}) names none "
                       f"of this class's subject terms {sorted(tokens)!r}")
    return True, f"the page's subject names this class's subject"


def cited_pages() -> list[tuple[str, str]]:
    """(class_id, url) for every non-RFC citation on a normative host."""
    from orch import store as orch_store
    con = orch_store.open_db(create=False)
    try:
        rows = con.execute(
            """SELECT DISTINCT i.class_id, s.url
                 FROM item i
                 JOIN item_source x ON x.item_id = i.id
                 JOIN source s ON s.id = x.source_id
                WHERE i.status = 'active'"""
        ).fetchall()
        out = []
        for r in rows:
            url = r["url"] or ""
            host = (urlparse(url).hostname or "").lower()
            if host not in NORMATIVE_HOSTS:
                continue
            if _RFC_PATH_RE.search(urlparse(url).path or ""):
                continue  # judged by tools/audit_rfc_subjects.py
            out.append((r["class_id"], url))
        return out
    finally:
        con.close()


def self_test() -> int:
    """The checker must be shown to FAIL on the defects R28 names."""
    ok = True
    for cid, url, why in KNOWN_BAD:
        passed, reason = page_is_about(cid, url)
        flagged = not passed
        print(f"  [{'PASS' if flagged else 'FAIL'}] known-bad is flagged: "
              f"{cid} <- {url.split('/')[-1] or url} ({why})")
        if not flagged:
            print(f"         the checker accepted it: {reason}")
        ok = ok and flagged
    for cid, url in KNOWN_GOOD + KNOWN_GOOD_EXTRA:
        passed, reason = page_is_about(cid, url)
        print(f"  [{'PASS' if passed else 'FAIL'}] known-good is accepted: "
              f"{cid} <- {url.split('/')[-1] or url}")
        if not passed:
            print(f"         the checker rejected it: {reason}")
        ok = ok and passed
    # A class with no declaration must produce NO opinion, not a finding.
    unknown, _ = page_is_about("a_class_with_no_declaration",
                               "https://man7.org/linux/man-pages/man2/execve.2.html")
    print(f"  [{'PASS' if unknown else 'FAIL'}] an unjudgeable class is "
          f"silenced, not reported")
    ok = ok and unknown
    print("\nSELF-TEST:", "PASS" if ok else "FAIL")
    return 0 if ok else 1


def main() -> int:
    ap = argparse.ArgumentParser(prog="audit_seed_subjects")
    ap.add_argument("--self-test", action="store_true",
                    help="assert the checker can fail (R28 requires this)")
    ap.add_argument("--json", action="store_true")
    args = ap.parse_args()

    if args.self_test:
        return self_test()

    pages = cited_pages()
    findings = []
    for cid, url in pages:
        ok, reason = page_is_about(cid, url)
        if not ok:
            findings.append({"class_id": cid, "url": url, "reason": reason})

    if args.json:
        print(json.dumps({"judged": len(pages), "findings": findings},
                         indent=2))
    else:
        print("=== R28 normative-host subject audit ===")
        print(f"citations judged: {len(pages)} "
              f"(non-RFC pages on normative hosts)")
        if not findings:
            print("  PASS -- every cited normative page is about the subject "
                  "its class claims")
        else:
            print(f"  FOUND {len(findings)} misfiled citation(s):")
            for f in findings:
                print(f"    {f['class_id']} <- {f['url']}")
                print(f"      {f['reason']}")
    return 1 if findings else 0


if __name__ == "__main__":
    raise SystemExit(main())
