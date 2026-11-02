"""T25 - a GitHub write-up must NOT be able to corroborate itself.

The failure this locks shut: `github.com/repo/blob/...` and
`raw.githubusercontent.com/repo/...` are the SAME author's words on two
GitHub-owned domains. Before the collapse they counted as two independent
publishers, so a walkthrough repository could promote an item by citing
itself twice. Since HTB write-ups live almost entirely on GitHub, that made
the most common source of technique claims self-certifying.

The checker is validated in BOTH directions: a genuine cross-publisher item
PASSES, a self-corroborating GitHub-only item FAILS. A test that cannot fail
proves nothing.
"""
import sys

sys.path.insert(0, ".")
from wks import config

FAILED = []


def check(name, cond, detail=""):
    print(f"  {'PASS' if cond else 'FAIL'}  {name}{('  -- ' + detail) if detail and not cond else ''}")
    if not cond:
        FAILED.append(name)


def _ev(url, host, quote, stype="blog"):
    return {"url": url, "host": host, "publisher": config.publisher_org(host),
            "quote": quote, "source_type": stype, "locator": "body",
            "retrieved_at": "2026-10-03", "authority": 3}


def orgs(sources):
    hosts = {e["host"] for e in sources if not config.is_builder_host(e["host"])}
    return {config.publisher_org(h) for h in hosts if config.publisher_org(h)}


print("T25.1 GitHub-owned domains collapse to one org")
for h, want in [
    ("github.com", "github.com"),
    ("raw.githubusercontent.com", "github.com"),
    ("gist.githubusercontent.com", "github.com"),
    ("gtfobins.github.io", "github.com"),
    ("www.github.com", "github.com"),
]:
    check(f"publisher_org({h}) == {want}", config.publisher_org(h) == want,
          f"got {config.publisher_org(h)}")

print("\nT25.2 unrelated publishers stay distinct")
for a, b in [("portswigger.net", "owasp.org"), ("ired.team", "hackthebox.com"),
             ("go.dev", "github.com"), ("hackthebox.com", "ired.team")]:
    check(f"{a} != {b}", config.publisher_org(a) != config.publisher_org(b),
          f"both -> {config.publisher_org(a)}")

# Regression guard on the PRE-EXISTING collapse: MITRE's two sites are one
# publisher by design (OPERATOR.md R1), not an accident of this change.
check("cwe.mitre.org == attack.mitre.org == mitre.org",
      config.publisher_org("cwe.mitre.org") == config.publisher_org("attack.mitre.org") == "mitre.org",
      "MITRE collapse is documented behaviour and must be preserved")

print("\nT25.3 THE FAILURE CASE: one write-up repo citing itself must NOT reach 2 orgs")
selfcite = [
    _ev("https://github.com/ajcriado/htb-writeups/blob/main/Blue/writeup.md",
        "github.com", "nmap -sC -sV reveals the web server and the SMB service."),
    _ev("https://raw.githubusercontent.com/ajcriado/htb-writeups/main/Blue/writeup.md",
        "raw.githubusercontent.com", "nmap -sC -sV reveals the web server and the SMB service."),
]
o = orgs(selfcite)
check("github+raw resolves to 1 org", len(o) == 1, f"got {sorted(o)}")
check("github+raw < MIN_PUBLISHER_HOSTS", len(o) < config.MIN_PUBLISHER_HOSTS,
      f"{len(o)} >= {config.MIN_PUBLISHER_HOSTS}")

print("\nT25.4 THE PASS CASE: write-up + normative publisher must still reach 2 orgs")
good = selfcite + [_ev("https://portswigger.net/web-security/ssrf", "portswigger.net",
                       "SSRF attacks can be used to reach internal services.")]
o = orgs(good)
check("github+portswigger == 2 orgs", len(o) == 2, f"got {sorted(o)}")
check("passes MIN_PUBLISHER_HOSTS", len(o) >= config.MIN_PUBLISHER_HOSTS)

print("\nT25.5 three GitHub-only sources are still one publisher")
three = [
    _ev("https://github.com/a/b/blob/main/x.md", "github.com", "q1"),
    _ev("https://raw.githubusercontent.com/a/b/main/x.md", "raw.githubusercontent.com", "q1"),
    _ev("https://gist.github.com/a/123", "gist.github.com", "q1"),
]
check("3 github sources -> 1 org", len(orgs(three)) == 1, f"got {sorted(orgs(three))}")

print("\nT25.6 mitigation stack: 3 independent publishers still pass")
three_ind = [
    _ev("https://github.com/a/b/blob/main/x.md", "github.com", "q1"),
    _ev("https://portswigger.net/web-security/ssrf", "portswigger.net", "q1"),
    _ev("https://owasp.org/www-project-web-security-testing-guide/", "owasp.org", "q1"),
]
check("github+psw+owasp == 3 orgs", len(orgs(three_ind)) == 3, f"got {sorted(orgs(three_ind))}")

print("\n" + ("ALL T25 CHECKS PASSED" if not FAILED else f"{len(FAILED)} FAILED: {FAILED}"))
sys.exit(1 if FAILED else 0)