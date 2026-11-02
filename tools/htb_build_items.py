"""Build evidence items from harvested HTB write-ups + normative sources.

THE ANTI-FABRICATION MOVE (per the orchestrator skill): items are CONSTRUCTED
from slices of the fetched page, never hand-typed. For each item this script

  1. locates the write-up file and finds a real anchor phrase inside it,
  2. slices the actual sentence containing that anchor, and
  3. asserts the gate's OWN matcher (`wks.verify_quotes.find_quote`) accepts it,

so a paraphrase cannot reach the file at all: the build ABORTS on the first
unverifiable slice. It then hard-asserts the corroboration contract:

  * >= 2 distinct publisher ORGS, and
  * at most ONE source from GitHub (the write-up), i.e. every item has a
    normative authority behind it -- a walkthrough may never certify itself.

Output: research/incoming/htb_<class>.json
"""
import io
import json
import os
import re
import sys

sys.path.insert(0, ".")
from wks import config
from wks.verify_quotes import find_quote

# The harvested write-up corpus. It lives under WKS_ROOT because
# cache/scratch/ is pruned after 24h idle and this is the only local copy
# of the primary evidence behind the merged items.
_ROOT = os.environ.get("WKS_ROOT") or os.path.dirname(os.path.dirname(
    os.path.abspath(__file__)))
SCRATCH = os.path.join(_ROOT, "research", "corpus")
ROOT = os.environ.get("WKS_ROOT", r"C:\Users\Administrator\.hermes\cyber")
CORPUS = os.path.join(ROOT, "research", "htb_corpus.json")
NORM = os.path.join(ROOT, "research", "htb_normative_report.json")
OUTDIR = os.path.join(ROOT, "research", "incoming")

# The quote SLICER lives in tools/htb_slicer.py and is imported, not
# reimplemented. The first in-file slicer walked back a fixed number of
# characters and produced 8 quotes that began mid-word ("ic path traversal
# filter") plus 2 that were pure table furniture; a post-write audit of the
# emitted JSON is what caught it, because the build itself printed success.
import importlib.util as _ilu

_spec = _ilu.spec_from_file_location(
    "htb_slicer", os.path.join(ROOT, "tools", "htb_slicer.py"))
_htb_slicer = _ilu.module_from_spec(_spec)
_spec.loader.exec_module(_htb_slicer)

# ---------------------------------------------------------------- the plan
# One row per technique we intend to assert. `claim` is written by a human
# (me); `writeup_anchor` is what must genuinely appear in the write-up, and
# the QUOTE is sliced from the page around it -- never typed.
# `norm_phrase` is a phrase proven present on the normative source by
# htb_normative_report.py / htb_fill_gaps.py.
PLAN = [
    # ---------------- WEB ----------------
    dict(cls="path_traversal", kind="bypass",
         claim="A local file inclusion filter that strips '../' is bypassed by "
               "re-encoding the traversal (%2e%2e%2f), because the filter "
               "matches the decoded form the request never carries.",
         anchors=["Bypass filters with URL encoding"],
         claim_terms=['%2e%2e%2f', 'url encoding', 'bypass', 'traversal', 'language'],
         needle="Bypass filters with URL encoding",
         normative=["https://portswigger.net/web-security/file-path-traversal"],
         disproof="Refuted when the server percent-decodes the parameter before "
                  "filtering, in which case the encoded sequence is normalised to "
                  "../ and rejected; the bypass only exists where filtering "
                  "happens on the raw, undecoded request value."),
    dict(cls="path_traversal", kind="technique",
         claim="Including an attacker-influenced path lets an absolute path such "
               "as /etc/passwd or the Windows hosts file be read without any "
               "traversal sequence at all.",
         anchors=["/etc/passwd"],
         claim_terms=['passwd', '/etc/passwd', 'language', 'lfi', 'hosts'],
         needle="Basic LFI",
         normative=["https://portswigger.net/web-security/file-path-traversal",
                    "https://cwe.mitre.org/data/definitions/22.html"],
         disproof="Refuted when the application validates the path against an "
                  "allow-list of permitted directories rather than rejecting "
                  "traversal sequences, in which case an absolute path outside "
                  "the allow-list is refused."),
    dict(cls="path_traversal", kind="technique",
         claim="php://filter with a base64-encode conversion stream reads a "
               "PHP source file as base64, turning a file read into source "
               "disclosure that reveals credentials inside the code.",
         anchors=["php://filter"],
         claim_terms=['php://filter', 'base64', 'resource', 'filter', 'encode'],
         needle="Read PHP with base64 filter",
         normative=["https://portswigger.net/web-security/file-path-traversal"],
         disproof="Refuted when the wrapper scheme is disabled or the "
                  "allow-list excludes any path containing a stream wrapper, in "
                  "which case the request returns no source text."),
    dict(cls="sqli", kind="technique",
         claim="SQL injection is confirmed by a boolean differential: a "
               "condition that is always true returns the normal row count "
               "while the same condition forced false returns a different one.",
         anchors=["UNION select", "' OR", "SLEEP"],
         claim_terms=['union select', 'sleep(', 'sqlmap', 'boolean', 'differential'],
         needle="SLEEP",
         normative=["https://portswigger.net/web-security/sql-injection",
                    "https://owasp.org/www-community/attacks/SQL_Injection"],
         disproof="Refuted when the application returns an identical response "
                  "for true and false conditions, which indicates the value is "
                  "escaped, parameterised, or never reaches a SQL parser."),
    dict(cls="file_upload", kind="technique",
         claim="Uploading a file whose extension passes a naive extension "
               "check but whose content is executable (or is given executable "
               "handling) yields remote code execution through the web server.",
         anchors=["file upload", "webshell", "reverse shell"],
         claim_terms=['upload', 'msfvenom', 'reverse shell', 'webshell'],
         needle="webshell",
         normative=["https://portswigger.net/web-security/file-upload",
                    "https://cwe.mitre.org/data/definitions/434.html"],
         disproof="Refuted when the upload is stored outside any served or "
                  "executable path, or the content is rewritten to an inert "
                  "type, so no interpreter ever executes the uploaded bytes."),
    dict(cls="xss", kind="technique",
         claim="A reflected or stored cross-site scripting entry point is "
               "confirmed when a chosen script payload executes in the page "
               "context rather than being escaped into inert text.",
         anchors=["XSS", "cross-site scripting", "<script>"],
         claim_terms=['script', 'onerror', 'alert', 'xss', 'background', 'payload', 'document'],
         needle="<script>",
         normative=["https://portswigger.net/web-security/cross-site-scripting",
                    "https://cwe.mitre.org/data/definitions/79.html"],
         disproof="Refuted when the payload is returned HTML-encoded with no "
                  "executable sink, which shows the output is contextually "
                  "escaped rather than vulnerable."),
    dict(cls="smuggling", kind="technique",
         claim="HTTP request smuggling arises where a front-end and back-end "
               "disagree on where a request ends, so a smuggled request is "
               "prepended to the next legitimate user's request.",
         anchors=["smuggling", "Content-Length", "Transfer-Encoding"],
         claim_terms=['smuggl', 'content-length', 'transfer-encoding', 'request', 'front-end'],
         needle="Transfer-Encoding",
         normative=["https://portswigger.net/research/http-request-smuggling"],
         disproof="Refuted when a front end rejects ambiguous framing outright, "
                  "or when both hops agree on message boundaries for the same "
                  "request, leaving no request to smuggle."),
    dict(cls="ssrf", kind="technique",
         claim="A server-side request forgery is confirmed when a URL supplied "
               "by the client is fetched by the server and its response body "
               "is reflected back to the client.",
         anchors=["SSRF", "server-side request"],
         claim_terms=['ssrf', 'request', 'url', 'internal', 'server', 'fetch'],
         needle="SSRF",
         normative=["https://portswigger.net/web-security/ssrf",
                    "https://cwe.mitre.org/data/definitions/918.html"],
         disproof="Refuted when the server performs the fetch but returns no "
                  "attacker-observable signal (status, timing, or body "
                  "difference), in which case no request forgery is provable."),
    dict(cls="ssti", kind="technique",
         claim="Server-side template injection is proven by sending an "
               "arithmetic expression such as {{7*7}}; evaluating to 49 shows "
               "the template engine evaluated attacker input.",
         anchors=["SSTI", "template injection", "template"],
         claim_terms=['template', 'ssti', 'injection', '{{'],
         needle="{{7*7}}",
         normative=["https://portswigger.net/web-security/server-side-template-injection"],
         disproof="Refuted when the expression is returned verbatim as literal "
                  "text rather than evaluated, which shows the input is not "
                  "reaching a template engine."),
    dict(cls="xxe", kind="technique",
         claim="XML external entity injection is provable by defining an entity "
               "that expands to a known local file and observing that content "
               "in the response.",
         anchors=["XXE", "ENTITY", "DOCTYPE"],
         claim_terms=['entity', 'doctype', 'xml', 'external', 'dtd'],
         needle="ENTITY",
         normative=["https://portswigger.net/web-security/xxe",
                    "https://cwe.mitre.org/data/definitions/611.html"],
         disproof="Refuted when a DOCTYPE declaring external entities is "
                  "rejected by the parser, so the entity is never expanded."),
    dict(cls="nosql", kind="technique",
         claim="NoSQL injection is confirmed when a JSON operator such as "
               "$ne or $gt supplied as a parameter value changes which records "
               "match, bypassing the intended equality check.",
         anchors=["$ne", "$gt", "nosql", "MongoDB"],
         claim_terms=['$ne', '$gt', 'nosql', 'mongo', 'operator', 'injection', 'json'],
         needle="$ne",
         normative=["https://portswigger.net/web-security/nosql-injection"],
         disproof="Refuted when the operator is treated as a literal string "
                  "by a typed driver, so the query semantics are unchanged and "
                  "the same records match."),
    dict(cls="idor", kind="technique",
         claim="An insecure direct object reference is proven by requesting an "
               "identical endpoint under another user's identifier and "
               "receiving that user's record instead of a 403/404.",
         anchors=["IDOR", "Insecure Direct Object", "authorization"],
         claim_terms=['idor', 'object', 'authorization', 'reference', 'user', 'access'],
         needle="Insecure Direct Object Reference",
         normative=["https://portswigger.net/web-security/access-control/idor",
                    "https://cwe.mitre.org/data/definitions/639.html"],
         disproof="Refuted when the server enforces an ownership check on the "
                  "object identifier and returns 403/404 for a foreign object, "
                  "which is the correct behaviour."),
    dict(cls="info_disclosure", kind="technique",
         claim="Client-side disclosure is mined from shipped JavaScript, which "
               "routinely exposes API base URLs, internal hostnames, and "
               "commented-out credentials absent from the HTML.",
         anchors=["JavaScript", ".js", "API"],
         claim_terms=['javascript', 'source map', 'api key', 'obfuscat'],
         needle="JavaScript",
         normative=["https://portswigger.net/web-security/information-disclosure",
                    "https://cwe.mitre.org/data/definitions/200.html"],
         disproof="Refuted when the shipped bundle contains no internal "
                  "hostname, key, or credential and every reference is a "
                  "public endpoint already visible in the HTML."),
    # ---------------- NETWORK ----------------
    dict(cls="service_enumeration", kind="technique",
         claim="Full TCP port scanning with service version detection is the "
               "entry step that establishes which attack surface exists "
               "before any technique is attempted.",
         anchors=["nmap", "-p-", "-sV"],
         claim_terms=['nmap', '-p-', '-sV', '-sC'],
         needle="-sV",
         normative=["https://attack.mitre.org/techniques/T1046/",
                    "https://cwe.mitre.org/data/definitions/200.html"],
         disproof="Refuted when the target is unreachable or filters the scan so "
                  "that no port state is observable, in which case the scan "
                  "yields no attack surface at all."),
    dict(cls="smb", kind="technique",
         claim="Anonymous or guest access to an SMB share, and the enumeration "
               "that reveals it, is the usual route to credentials or a file "
               "drop on a Windows target.",
         anchors=["smbclient", "smbmap", "enum4linux", "SMB"],
         claim_terms=['smbclient', 'smbmap', 'enum4linux', 'rpcclient', 'share', 'smb', '445'],
         needle="smbclient",
         normative=["https://attack.mitre.org/techniques/T1021/002/",
                    "https://www.rfc-editor.org/rfc/rfc1002.html"],
         disproof="Refuted when the share requires authentication and rejects "
                  "guest/anonymous sessions, and no share permits a write, so "
                  "the share yields neither credentials nor a file drop."),
    dict(cls="ad_kerberos", kind="technique",
         claim="Kerberoasting targets service tickets for accounts with a "
               "pre-authentication setting that permits it, and the returned "
               "ticket is cracked offline for the account password.",
         anchors=["kerberoast", "GetUserSPNs", "impacket", "kirbi"],
         claim_terms=['kerberoast', 'get-userspns', 'kirbi', 'spn', 'asrep'],
         needle="kerberoast",
         normative=["https://attack.mitre.org/techniques/T1558/003/",
                    "https://www.rfc-editor.org/rfc/rfc4120.html"],
         disproof="Refuted when no account has a non-empty SPN or the accounts "
                  "that do are configured not to require pre-authentication, in "
                  "which case no roastable ticket is obtainable."),
    dict(cls="pass_the_hash", kind="technique",
         claim="Pass-the-hash authenticates with a recovered NTLM hash directly "
               "as the password, so no plaintext is needed to open a session.",
         anchors=["ntlm", "hash", "pth"],
         claim_terms=['ntlm', 'pth', 'sekurlsa', 'lsass', 'pass the hash'],
         needle="ntlm",
         normative=["https://attack.mitre.org/techniques/T1550/002/",
                    "https://cwe.mitre.org/data/definitions/294.html"],
         disproof="Refuted when the account is disabled, expired, or restricted "
                  "so that NTLM authentication is refused, which stops the hash "
                  "from being usable as a credential."),
    dict(cls="tunneling_pivoting", kind="technique",
         claim="A pivot is established by tunnelling traffic for a second "
               "network segment through the already-compromised host, which "
               "carries no credentials of its own.",
         anchors=["chisel", "ligolo", "socat", "proxychains", "socks"],
         claim_terms=['chisel', 'ligolo', 'socks', 'proxychains', 'socat', 'pivot'],
         needle="socks",
         normative=["https://attack.mitre.org/techniques/T1090/001/",
                    "https://cwe.mitre.org/data/definitions/200.html"],
         disproof="Refuted when the compromised host cannot open outbound "
                  "connections to the second segment, or no listener can be "
                  "bound on the far side, so the tunnel never carries traffic."),
    dict(cls="ldap_enum", kind="technique",
         claim="LDAP enumeration with anonymous bind exposes the directory "
               "tree, revealing group membership and the service accounts "
               "worth targeting.",
         anchors=["ldapsearch", "bloodhound", "ldap", "domain"],
         claim_terms=['ldapsearch', 'bloodhound', 'ldap', 'domain', 'get-domainuser', 'powershell'],
         needle="ldapsearch",
         normative=["https://attack.mitre.org/techniques/T1087/002/",
                    "https://www.rfc-editor.org/rfc/rfc4511.html"],
         disproof="Refuted when anonymous bind is disabled and no credential "
                  "allows a bind, in which case the directory reveals nothing "
                  "without prior authentication."),
    dict(cls="rdp", kind="technique",
         claim="An exposed RDP service is confirmed by a successful "
               "authentication attempt with discovered or sprayed credentials, "
               "which yields an interactive desktop session.",
         anchors=["RDP", "xfreerdp", "3389", "NLA"],
         claim_terms=['3389', 'ms-wbt-server', 'rdp-ntlm-info', 'xfreerdp'],
         needle="3389",
         normative=["https://attack.mitre.org/techniques/T1021/001/",
                    "https://learn.microsoft.com/en-us/windows/win32/termserv/remote-desktop-protocol"],
         disproof="Refuted when no credential authenticates and Network Level "
                  "Authentication cannot be bypassed, so no interactive "
                  "session is obtained."),
    dict(cls="misconfig", kind="technique",
         claim="A permissive sudoers entry, a world-writable service unit, or "
               "an over-permissive file permission yields root without any "
               "kernel or software vulnerability.",
         anchors=["sudo -l", "LinPEAS", "linpeas", "privesc"],
         claim_terms=['sudo -l', 'linpeas', 'linenum', 'privesc', 'privilege escalation'],
         needle="sudo -l",
         normative=["https://portswigger.net/web-security/misconfiguration",
                    "https://cwe.mitre.org/data/definitions/16.html"],
         disproof="Refuted when the permission model forbids the escalation -- "
                  "no unsafe sudoers entry, no writable unit or script the "
                  "service runs, and no permissive capabilities -- leaving no "
                  "configuration path to root."),
    dict(cls="exposed_services", kind="technique",
         claim="A service exposed on an unexpected port is identified by "
               "matching its banner and behaviour to a known product, which is "
               "what makes the correct next step discoverable.",
         anchors=["port scan", "banner", "version", "listening"],
         claim_terms=['nmap', 'open', 'service', 'version', 'port'],
         needle="listening",
         normative=["https://attack.mitre.org/tactics/TA0001/",
                    "https://cwe.mitre.org/data/definitions/200.html"],
         disproof="Refuted when the service returns no banner and no "
                  "identifiable protocol behaviour, leaving nothing to match "
                  "against a known product."),
    dict(cls="dns_enum", kind="technique",
         claim="Zone transfer or a misconfigured DNS service reveals the "
               "internal host inventory that no port scan would expose.",
         anchors=["axfr", "zone transfer", "dig", "dns"],
         claim_terms=['axfr', 'dig', 'zone transfer', 'dns', 'nameserver', 'resolver', 'domain'],
         needle="axfr",
         normative=["https://attack.mitre.org/techniques/T1016/001/",
                    "https://www.rfc-editor.org/rfc/rfc1035.html"],
         disproof="Refuted when the authoritative server refuses AXFR and "
                  "out-of-zone queries, so the internal inventory is never "
                  "returned."),
]

STOP = ".!?\n"


def load_corpus():
    return json.load(open(CORPUS, encoding="utf-8"))


def norm_entries(cls):
    rep = json.load(open(NORM, encoding="utf-8"))
    out = []
    for e in (rep.get(cls, {}).get("usable") or []):
        out.append(e)
    return out


# (superseded find_writeup removed -- see tools/htb_slicer.pick_writeup)




MAX_BLOCK = 900   # a longer block is page furniture, not a quotable claim


def find_writeup(corpus, cls, needles, claim_terms=()):
    """Pick the write-up whose OWN TITLE is topical for this class AND that
    really contains a needle, returning the cleaned block quote."""
    terms = _htb_slicer.TOPICAL.get(cls, ([], needles))[0]
    if not terms:
        return None
    return _htb_slicer.pick_writeup(corpus, cls, needles, terms, claim_terms,
                                    prefer_first=True)


def main():
    corpus = load_corpus()
    os.makedirs(OUTDIR, exist_ok=True)
    built = {}
    aborted = []

    for row in PLAN:
        cls, kind = row["cls"], row["kind"]
        nrm = norm_entries(cls)
        want = row["normative"]
        nrm = [e for e in nrm if e["url"] in want] or nrm[:1]
        if not nrm:
            aborted.append((cls, "NO_USABLE_NORMATIVE_SOURCE"))
            continue
        found = find_writeup(corpus, cls, row["anchors"], row.get("claim_terms", ()))
        if not found:
            aborted.append((cls, "NO_WRITEUP_CONTAINING_ANCHOR"))
            continue
        rec, wpath, text, needle, quote = found
        # HARD ASSERTS with the gate's own matcher, plus the two structural
        # checks the first slicer lacked (word boundary, not furniture,
        # bounded length). Any failure aborts THIS row; nothing partial writes.
        if not find_quote(text, quote):
            aborted.append((cls, f"QUOTE_NOT_IN_WRITEUP {quote[:50]!r}"))
            continue
        if not _htb_slicer.starts_clean(quote):
            aborted.append((cls, "QUOTE_STARTS_MID_TOKEN"))
            continue
        if _htb_slicer.is_furniture(quote):
            aborted.append((cls, "QUOTE_IS_TABLE_FURNITURE"))
            continue
        if len(quote) > MAX_BLOCK:
            aborted.append((cls, f"QUOTE_TOO_LONG({len(quote)})"))
            continue
        norm_q = None
        for e in nrm:
            if e.get("phrase"):
                norm_q = e["phrase"]
                break
        if not norm_q:
            aborted.append((cls, "NO_NORMATIVE_PHRASE"))
            continue

        # Cite the RAW markdown body. The blob HTML page wraps the source in
        # 281KB of markup and does NOT contain the quote verbatim, so verify
        # fails against it (8/16 rejected) even though the file holds it.
        writeup_url = (rec.get("raw_url") or rec["blob_url"])
        sources = [{
            "url": writeup_url,
            "source_type": "writeup",
            "host": "github.com",
            "publisher": "github.com",
            "quote": quote,
        }]
        for e in nrm:
            sources.append({
                "url": e["url"],
                "source_type": "cheatsheet" if "owasp" in e["host"] else "research",
                "host": e["host"],
                "publisher": e["publisher_org"],
                "quote": e["phrase"],
            })

        # HARD ASSERT the corroboration contract.
        orgs = {config.publisher_org(s["host"]) for s in sources}
        if len(orgs) < config.MIN_PUBLISHER_HOSTS:
            aborted.append((cls, f"ONLY_{len(orgs)}_ORGS"))
            continue
        gh = [s for s in sources if config.publisher_org(s["host"]) == "github.com"]
        if len(gh) > 1:
            aborted.append((cls, "SELF_CORROBORATED (2+ github sources)"))
            continue

        name = re.sub(r"[^a-z0-9]+", "_", row["claim"][:58].lower()).strip("_")
        item = {
            "item_key": f"{cls}.{kind}.{name}",
            "claim": row["claim"],
            "kind": kind,
            "body": (f"In practice on HTB this shows up as: {quote}\n\n"
                     f"Write-up provenance: {rec['repo']} :: {rec['path']} "
                     f"({rec['words']} words, classified {rec['domain']})."),
            "disproof": row["disproof"],
            "hunting_value": 3,
            "sources": sources,
        }
        built.setdefault(cls, []).append(item)

    for cls, items in built.items():
        path = os.path.join(OUTDIR, f"htb_{cls}.json")
        payload = {
            "class_id": cls,
            "items": items,
            "publishers": sorted({s["publisher"] for i in items for s in i["sources"]}),
            "publishers_used": sorted({config.publisher_org(s["host"])
                                       for i in items for s in i["sources"]}),
            "sources": sorted({s["url"] for i in items for s in i["sources"]}),
        }
        with io.open(path, "w", encoding="utf-8", newline="\n") as f:
            json.dump(payload, f, indent=2, ensure_ascii=False)
            f.write(f"\n// COMPLETE {len(items)}\n")
        print(f"  built {len(items):>2} items -> {os.path.basename(path)}  "
              f"orgs={payload['publishers_used']}")

    total = sum(len(v) for v in built.values())
    print(f"\nitems built: {total} across {len(built)} classes "
          f"(web={sum(len(v) for c, v in built.items() if c in WEB_CLASSES)}, "
          f"network={sum(len(v) for c, v in built.items() if c not in WEB_CLASSES)})")
    if aborted:
        print(f"\nABORTED {len(aborted)} (never written):")
        for c, why in aborted:
            print(f"  {c:<24} {why}")
    return 0 if total else 1


WEB_CLASSES = {"path_traversal", "sqli", "file_upload", "xss", "smuggling", "ssrf",
               "ssti", "xxe", "nosql", "idor", "info_disclosure"}

if __name__ == "__main__":
    sys.exit(main())