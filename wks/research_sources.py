"""Research-source registry — the code-level source list for hunting knowledge.

This is deliberately SEPARATE from `taxonomy._SEED`, and the separation is the
whole point.

`taxonomy._SEED` is *normative*: OWASP / PortSwigger / MITRE CWE define what a
class IS, and those URLs are what let a class satisfy the corroboration gate.
The sources here are *practitioner, intel and tooling* material — Medium
writeups, community GitBooks, personal Notion pages, CVE aggregators, tool
repos. They are excellent for techniques, bypasses, recon and tooling, and they
are NOT authoritative about what a vulnerability class means.

If they were mixed into a class seed set, two practitioner blog posts would
satisfy `MIN_PUBLISHER_HOSTS` and a claim with no normative backing could reach
`supported`. That is the exact failure this system was built to prevent — the
previous one promoted 1,378 unsourced items to `validated`.

So: registered as `source` rows (provenance preserved, quotes still verified
live by `wks/verify_quotes.py`), never as class seeds, never as authority.

Tier model (the five-tier reliability hierarchy; 1 strongest):

  T1  local trusted knowledge   — the Cyber OS itself, MASTER workflow, WKS rows
  T2  primary / normative       — NVD, CWE, OWASP, PortSwigger, RFC-editor
  T3  practitioner / real-world — writeups, disclosures, community guides
  T4  CVE / exploit intelligence — cvebase, Vulners, Sploitus, CISA KEV
  T5  tooling / project repos   — reconftw, AI-hunter projects

Access tier, measured live 2026-10-02 rather than assumed:

  open   plain HTTP fetch returns the content
  json   a machine endpoint returns structured data (may be rate limited)
  key    usable free tier, but an API key must be supplied
  js     HTTP returns only a loader; content needs a script or the Notion
         cached-page endpoint (see notes)
  walled a bot wall or paywall; HTTP 200 does NOT mean the content arrived

R20 (`CONTROL/rules.md`): a source in this registry is a LEAD. It may be linked
to an item as evidence, but an item whose evidence is only registry sources is
practitioner- or tooling-tier evidence and must not be described as
normatively backed.
"""
from __future__ import annotations

from dataclasses import dataclass

# Source-type vocabulary is closed by `config.SOURCE_AUTHORITY`. A value outside
# it silently degrades to authority 3, which is how "standards_body" and "cwe"
# rows in the db ended up scored as weak practitioner sources. Every entry below
# uses a key that exists in that map.
#   taxonomy 1 · advisory 1 · docs/knowledge/materials/cheatsheet/vendor 2
#   report/writeup/dataset 3 · blog 4 · social 5

TIERS = {
    1: "local trusted knowledge",
    2: "primary / normative",
    3: "practitioner / real-world",
    4: "CVE / exploit intelligence",
    5: "tooling / project repo",
}

ACCESS = {
    "open": "plain HTTP fetch returns content",
    "json": "machine endpoint returns structured data",
    "key": "free tier available, API key required",
    "js": "HTTP returns a loader only; needs a script or the Notion endpoint",
    "walled": "bot wall or paywall; HTTP 200 does not mean content arrived",
}


@dataclass(frozen=True)
class ResearchSource:
    url: str
    publisher: str          # org, for independence assessment (R1 counts hosts)
    title: str
    source_type: str        # MUST be a key of config.SOURCE_AUTHORITY
    tier: int               # 1..5, the reliability hierarchy above
    access: str             # MUST be a key of ACCESS
    note: str = ""
    # Which seeded classes this source is most useful for. Advisory routing only:
    # it does not attach the source to the class's seed set.
    classes: tuple[str, ...] = ()

    @property
    def host(self) -> str:
        from urllib.parse import urlparse
        h = (urlparse(self.url).hostname or "").lower()
        return h[4:] if h.startswith("www.") else h


_MEDIUM = (
    "Practitioner writeups. Redaction is common (targets withheld), so a "
    "writeup teaches a technique, not a reproducible target."
)

RESEARCH_SOURCES: tuple[ResearchSource, ...] = (
    # ---------------- T3 · community methodology / personal notes ----------
    ResearchSource(
        "https://app.notion.com/p/Methodology-19697ed6f07880179b26e4db8bdeb054",
        "Notion (user-published)",
        "Bug Bounty Methodology — vulnerability class index",
        "writeup", 3, "js",
        "19 top-level class entries (XSS, SQLi, RCE, JWT, OAuth, XXE, CRLF, "
        "cache attacks, smuggling). A table of contents, not a body of work. "
        "Public Notion pages return only a JS shell to curl; content requires "
        "loadCachedPageChunk (records are nested value.value and child order "
        "lives in the parent's content array).",
    ),
    ResearchSource(
        "https://sedate-session-3ae.notion.site/Web-Penetration-Testing-22828247500f80c089bcd1eedc18a539",
        "Notion (user-published)",
        "Web Penetration Testing — personal notes",
        "writeup", 3, "js",
        "169 extracted lines and the densest of the three Notion pages: recon, "
        "ffuf/dirsearch/feroxbuster, .git exposure, JS analysis, nuclei, SQLi, "
        "XSS+CSRF, PDF-generation vulnerabilities. Same Notion extraction path.",
    ),
    ResearchSource(
        "https://tested-corleggy-562.notion.site/Rem01x-Red-Teaming-Journey-52de31285d97490fa13db4567d7b3c4f",
        "Notion (user-published)",
        "Rem01x — Red Teaming Journey (index page)",
        "writeup", 3, "js",
        "Four hub links only: OSCE3, VulnLab, mobile app pentest, HTB "
        "writeups. An index, not knowledge.",
    ),
    ResearchSource(
        "https://kathan19.gitbook.io/howtohunt",
        "HowToHunt (community, kathan19)",
        "HowToHunt — per-vulnerability-class hunting guides",
        "writeup", 3, "open",
        "84 guides across 38 classes (idor, csrf, ssrf, jwt, oauth, saml, "
        "graphql, race-condition, rate-limit, status-code-bypass, "
        "subdomain-takeover, waf-bypasses, sqli, ssti, xxe, http-desync, cms, "
        "recon, sensitive-info-leaks). The root page is the table of contents "
        "and lists every guide path; /introduction 404s. Highest-value "
        "per-class hunting material in this registry.",
        ("idor", "csrf", "authz", "jwt", "oauth", "race", "sqli", "ssti",
         "deser", "path_traversal", "graphql", "mass_assign", "bizlogic"),
    ),
    ResearchSource(
        "https://oreobiscuit.gitbook.io/introduction",
        "Biscuit's Bug Bounty Playbook (community)",
        "OreoBiscuit — Bug Bounty Playbook",
        "writeup", 3, "open",
        "Platform mechanics (HackerOne, Bugcrowd, Intigriti, OBB), writeup "
        "collections by class, Android section (Frida, objection, drozer), "
        "GraphQL/API section. Links are /introduction/<section>/<slug>. Good "
        "for what classes exist; less dense on exploitation than HowToHunt.",
    ),
    ResearchSource(
        "https://github.com/Cyber-note/Full-Bug-Bounty-Hunting-Methodology-2026",
        "Cybernote",
        "Full Bug Bounty Hunting & Red Teamers Methodology 2026",
        "writeup", 3, "open",
        "15 recon phases ordered by signal-to-noise. Phase 4 (WAF bypass / "
        "origin IP discovery) is what most hunters skip: favicon-hash via "
        "favUp/favirecon, historical DNS via originiphunter, GA-ID "
        "analyticsrelationships for corporate-family expansion. Phase 8 JS "
        "secret extraction, phase 13 subdomain takeover. MIT licensed.",
    ),

    # ---------------- T3 · writeup aggregators ----------------------------
    ResearchSource(
        "https://medium.com/feed/tag/bug-bounty",
        "Medium",
        "Medium tag: bug bounty",
        "writeup", 3, "open",
        _MEDIUM + " Use /feed/tag/<slug> (clean XML, real dates) rather than "
        "the /tag/ HTML page, which is duplicated and undated.",
    ),
    ResearchSource(
        "https://medium.com/feed/tag/bug-bounty-tips",
        "Medium",
        "Medium tag: bug bounty tips",
        "writeup", 3, "open", _MEDIUM,
    ),
    ResearchSource(
        "https://medium.com/feed/tag/bug-bounty-writeup",
        "Medium",
        "Medium tag: bug bounty writeup",
        "writeup", 3, "open",
        _MEDIUM + " Distinct from the bugbounty-writeup slug; the two drift "
        "by a few articles, so both are kept deliberately.",
    ),
    ResearchSource(
        "https://medium.com/feed/tag/bugbounty-writeup",
        "Medium",
        "Medium tag: bugbounty writeup (alternate slug)",
        "writeup", 3, "open",
        _MEDIUM + " Same publisher as bug-bounty-writeup: one publisher, so "
        "these two can never corroborate each other (R1).",
    ),
    ResearchSource(
        "https://medium.com/feed/tag/bug-bounty-hunter",
        "Medium",
        "Medium tag: bug bounty hunter",
        "writeup", 3, "open", _MEDIUM,
    ),
    ResearchSource(
        "https://medium.com/feed/tag/bugbounty-tips",
        "Medium",
        "Medium tag: bugbounty tips (alternate slug)",
        "writeup", 3, "open",
        _MEDIUM + " Same publisher as bug-bounty-tips.",
    ),

    # ---------------- T3 · disclosed-report sources -----------------------
    ResearchSource(
        "https://hackerone.com/hacktivity",
        "HackerOne",
        "HackerOne Hacktivity — public disclosed reports",
        "report", 3, "walled",
        "Bot-walled. An unauthenticated fetch returns HTTP 200 whose body is "
        "browser-not-supported.html — a 200 here is a lie, do not record it as "
        "retrieved. Disclosed reports are partially mirrored by reddelexc below.",
    ),
    ResearchSource(
        "https://github.com/reddelexc/hackerone-reports",
        "reddelexc",
        "Mirror of disclosed HackerOne reports",
        "report", 3, "open",
        "Mirror of public disclosed H1 reports. data.csv served 0 bytes at "
        "check time; prefer the HTML report links in the README. Still one "
        "publisher per underlying program, so a mirrored report and the "
        "original H1 entry are not independent corroboration.",
    ),

    # ---------------- T3 · training / labs --------------------------------
    ResearchSource(
        "https://bugbountyhunter.com",
        "BugBountyHunter (ZSeano)",
        "BugBountyHunter — no-flag web challenges and ZSeano's Playground",
        "writeup", 3, "walled",
        "ZSeano's methodology challenges. Site is self-flagged as out of date "
        "pending v2. Open redirect (id=7), misc/app-logic (id=15), CSRF "
        "(id=3). The no-flag Playground (25+ undisclosed findings) is the "
        "mindset training worth the time. Challenges need a browser session.",
    ),
    ResearchSource(
        "https://hackthrough.live",
        "HackThrough",
        "HackThrough — interactive writeup cases",
        "writeup", 3, "walled",
        "Paid, auth-gated. Public marketing page states its cases are built "
        "from public HackerOne / Medium / blog writeups, so it is a reformat "
        "of T3 material, not an independent publisher. Free tier exists; "
        "content is not fetchable without an account.",
    ),

    # ---------------- T4 · CVE / exploit intelligence ---------------------
    ResearchSource(
        "https://cvebase.io",
        "cvebase.io",
        "cvebase — CVE search with exploitation context",
        "dataset", 4, "json",
        "The highest-value source here and the only free, keyless JSON API "
        "measured: /api/search?q= returns per hit in_kev, exploited_in_wild, "
        "exploit_available, epss, ransomware and a priority level, plus "
        "namespaced doc ids (cisa:CVE-…, exploitdb:…, mitre_cwe:…). Anonymous "
        "tier is 10 requests/minute — batch and respect rate_limit.remaining. "
        "Doc ids are namespaced: filter to bare CVE-* for one advisory.",
    ),
    ResearchSource(
        "https://vulners.com",
        "Vulners",
        "Vulners — aggregated vulnerability intelligence",
        "dataset", 4, "key",
        "Aggregates 200+ sources (NVD, CISA KEV, vendor/distro advisories, "
        "Exploit-DB, Metasploit, GitHub PoCs) with CVSS/EPSS/CWE/CPE context. "
        "Requires a free X-Api-Key header; /llms.txt documents it as the "
        "supported path for agent traffic. Also ships an MCP server and a "
        "Python SDK. Web UI is browser-checked, so the API is the route.",
    ),
    ResearchSource(
        "https://sploitus.com",
        "Sploitus",
        "Sploitus — exploit and PoC search cross-linked to CVEs",
        "dataset", 4, "json",
        "Free without a key: /llms.txt, /rss, /atom, /sitemap.xml. The JSON "
        "API (/api/v1/search, /api/v1/cve/{id}/exploits) returns 401 without "
        "a key. Its /llms.txt requires attribution, forbids bulk HTML "
        "crawling and is non-commercial — link back to Sploitus when quoting. "
        "Its own caveat holds: a record proves code was published, not that it "
        "works.",
    ),

    # ---------------- T5 · tooling / automation repos ----------------------
    ResearchSource(
        "https://github.com/six2dez/reconftw",
        "six2dez",
        "reconFTW — automated reconnaissance orchestration",
        "docs", 5, "open",
        "Recon orchestration, not a method. Its value here is the config that "
        "prevents real-world failures: HTTPX_RATELIMIT, DNSX_RATE_LIMIT "
        "(NAT-safe), DNS_RESOLVER=auto (detects NAT/CGNAT), FFUF_FLAGS, and "
        "per-engine timeouts. MIT licensed.",
        ("idor", "sqli", "ssti", "authz", "mass_assign", "bizlogic", "race"),
    ),
    ResearchSource(
        "https://github.com/awarexone/Agentic-Bug-Hunter",
        "awarexone",
        "Agentic-Bug-Hunter — AI hunting toolkit",
        "docs", 5, "open",
        "Read for agent-design patterns and tool inventory, not for adoption. "
        "Drives real requests: the scope allowlist and authorization gate from "
        "the web-pentest skill apply unchanged. Unsupervised write access is "
        "destructive — an agent that confirms an IDOR by writing or deleting a "
        "record has damaged the program. Read-only until a human confirms each "
        "write.",
    ),
    ResearchSource(
        "https://github.com/The-XSS-Rat/BountySkiller",
        "The-XSS-Rat",
        "BountySkiller — XSS hunting tooling",
        "docs", 5, "open",
        "XSS-focused tooling, small project. Tooling tier: read for technique "
        "and detection patterns.",
    ),
    ResearchSource(
        "https://github.com/The-XSS-Rat/SecurityTesting",
        "The-XSS-Rat",
        "SecurityTesting — web application testing toolkit",
        "docs", 5, "open",
        "Broad web testing toolkit. Tooling tier.",
    ),
    ResearchSource(
        "https://github.com/Monesgoda/offensive-Agent-s",
        "Monesgoda",
        "offensive-Agent-s — orchestrator with 24 specialised sub-agents",
        "docs", 5, "open",
        "Agent architecture reference: one orchestrator plus 24 specialised "
        "agents. Small project, unpadded star count — judge the design, not "
        "the popularity. Same real-request and write-safety constraints as "
        "above.",
    ),
    ResearchSource(
        "https://github.com/usestrix/strix",
        "usestrix",
        "Strix — open-source AI penetration testing tool",
        "docs", 5, "open",
        "The most-starred project in this registry. Tooling tier. Treat an "
        "agent-driven pentest as an active engagement: scope, authorization "
        "and the no-unsupervised-writes rule all still apply.",
    ),
)

BY_URL = {s.url: s for s in RESEARCH_SOURCES}


def by_host() -> dict[str, list[ResearchSource]]:
    out: dict[str, list[ResearchSource]] = {}
    for s in RESEARCH_SOURCES:
        out.setdefault(s.host, []).append(s)
    return out


def problems() -> list[str]:
    """Self-check: vocabulary closure, so a typo cannot silently degrade authority.

    `config.SOURCE_AUTHORITY.get(t, 3)` means an unknown `source_type` does not
    raise — it quietly becomes authority 3. That is how a CWE row ended up
    scored as a weak blog post. This makes the drift a hard, visible failure.
    """
    from . import config
    bad: list[str] = []
    for s in RESEARCH_SOURCES:
        if s.source_type not in config.SOURCE_AUTHORITY:
            bad.append(f"{s.url}: source_type {s.source_type!r} not in "
                       f"config.SOURCE_AUTHORITY")
        if s.access not in ACCESS:
            bad.append(f"{s.url}: access {s.access!r} not a known access tier")
        if s.tier not in TIERS:
            bad.append(f"{s.url}: tier {s.tier!r} not in 1..5")
        if not s.note.strip():
            bad.append(f"{s.url}: no note — an unexplained registry entry "
                       f"becomes a mystery citation later")
    dupes = [u for u in BY_URL if sum(1 for s in RESEARCH_SOURCES if s.url == u) > 1]
    bad += [f"duplicate url: {u}" for u in dupes]
    return bad
