"""Build fp_case rows from the REAL engagement records in E:/bugbounty.

Sources read (field observations, not prose):
  redbull-intigriti/findings/status-summary.md   28 refutation verdicts
  prism_vdp/evidence/TAKEOVER-VALIDATION-VERDICTS.md   6 takeover verdicts
  algemeendagblad/reports/ALGEMEEN_DAGBLAD_HUNT_REPORT.md   non-findings table
  DOD/af.mil/findings/status-summary.md, status-tracker.md
  DOD/new_recon/js_analysis/FINAL_REPORT.md
  vercel/reports/hunt-status-2026-09-07.md

EXCLUDED: cyber-backups/ -- it is a MIRROR of this same corpus
(methodology/derived/*.md are our own class pages), so harvesting it would feed
the corpus back into itself and report the corpus's own rules as field evidence.

THE CONSTRAINT THAT SHAPES EVERY ROW: no target may be identifiable in the
corpus. Program names, hostnames, vendor names, API keys and paths from the
engagements are stripped. What survives is the DECISION RULE -- the shape of the
observation, the control that was run, and what the control showed. A row that
still carried "the redbull account API" would be a liability in a knowledge base
that gets queried during a hunt on a different program.

Every row is written with:
  provenance     = field_observation
  source_ref     = the engagement file, so a human can audit the derivation
It REFUSES to write if any row still matches a target-identifying pattern.
"""
import io
import os
import re
import sqlite3
import sys

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, ROOT)
from wks import store  # noqa: E402

# --- patterns that must NOT survive into the corpus ------------------------
LEAK = [
    (re.compile(r"https?://", re.I), "bare URL (path may name an endpoint)"),
    (re.compile(r"\b\d{1,3}(?:\.\d{1,3}){3}\b"), "IP address"),
    (re.compile(r"\b[a-z0-9][a-z0-9-]{1,40}\.(?:com|net|org|io|at|nl|dev|co|app|"
                r"ml|tv|shop|be|de|uk|site|online|xyz|cloud)\b", re.I), "hostname"),
    (re.compile(r"\b(?:redbull|oyorooms|instapage|criteo|sendgrid|vercel|spotler|"
                r"prism|flyingbulls|rbleipzig|rbl_|directus|auth0|okta|gigya|"
                r"pageserve|dnsdelegation|oyoro|edoverflow)\w*", re.I),
     "vendor/program name"),
    (re.compile(r"\b(?:AKIA|ghp_|gho_|sk_live|sk_test|AIza|xox[baprs]-)"
                r"[A-Za-z0-9_.-]{8,}"), "credential-shaped token"),
    (re.compile(r"\beyJ[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}\."), "JWT"),
    (re.compile(r"\b[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}\b",
                re.I), "uuid/account id"),
    (re.compile(r"/tmp/pentestcode[^\s,)]*"), "local evidence path"),
    (re.compile(r"\bE:[/\\]bugbounty|/c/Users/Administrator"), "local workspace path"),
    (re.compile(r"\b(?:team_id|account_id|org_id|project_id|workspace_id)\s*[:=]",
                re.I), "account identifier"),
    (re.compile(r"\b\d{6,}\b"), "long numeric id (possibly account/phone)"),
]


def assert_no_leak(text):
    # RFC 2606 / RFC 5737 reserved names and loopback are DOCUMENTATION
    # vocabulary, not target identifiers. Flagging them would have rejected two
    # legitimate pre-existing rules: an oauth allowlist rule citing example.com
    # and an SSRF rule citing 127.0.0.1. Strip them before matching, so the
    # detector stays strict about real identifiers without false-positiving on
    # the standards themselves.
    scrub = re.sub(
        r"\b(?:example\.(?:com|net|org)|example\.co(?!\.m)|test|invalid|"
        r"localhost|127\.0\.0\.1|0\.0\.0\.0|192\.0\.2\.\d+|198\.51\.100\.\d+|"
        r"203\.0\.113\.\d+|10\.0\.0\.\d+|r6\.localhost)\b", "DOCNAME", text)
    for rx, kind in LEAK:
        m = rx.search(scrub)
        if m:
            raise AssertionError("LEAK (%s): %r in %r"
                                 % (kind, m.group(0), text[:70]))


# --- the rows --------------------------------------------------------------
# (class_id, fp_key, hypothesis, looked_vulnerable_because, test_performed,
#  invalidated_by, early_signal_missed, rejection_rule, source_ref)
ROWS = [
 # ---------------- CORS ----------------
 ("cors", "cors-reflects-origin-but-no-cookie-keyed-secret",
  "A CORS endpoint reflects an arbitrary attacker Origin with "
  "Access-Control-Allow-Credentials:true, therefore an attacker's page can "
  "steal the victim's data",
  "Real GETs returned the attacker Origin echoed in ACAO together with "
  "Access-Control-Allow-Credentials:true, and the cited paths were the "
  "user-data endpoints named in the report",
  "Listed the cited paths and fetched each unauthenticated, comparing the "
  "response body; then searched the shipped client bundle for those paths, for "
  "document.cookie reads and for credentials:'include', and re-requested every "
  "path watching for Set-Cookie",
  "The cited paths returned a byte-identical application shell rather than JSON "
  "and appear nowhere in the bundle; the application keys every data call on an "
  "Authorization or caller-supplied token, so the browser never attaches a "
  "credential cross-origin; zero Set-Cookie on any path, so there is nothing for "
  "the attacker's page to read; and the client never uses credentials:'include'",
  "Naming the endpoint from a route constant in the bundle is not evidence it is "
  "a data endpoint - confirm it returns data before calling it sensitive",
  "Reflection plus ACAC:true is only credential theft when a secret is keyed on "
  "something the browser attaches automatically. Prove a cookie-keyed or "
  "ambient-credential read exists on the SAME path: a Set-Cookie, a cookie-backed "
  "data call, or credentials:'include' actually used in the client. If the data "
  "is Authorization-keyed, there is no cross-origin read to perform",
  "redbull-intigriti/findings/status-summary.md (REPORT-02 VALIDATION C1-C3)"),

 ("cors", "cors-exploitable-combo-requires-reflection-and-cookie-on-one-path",
  "CORS reflection on one host and session cookies on another host means the "
  "account family is vulnerable to cross-origin credential theft",
  "Arbitrary-Origin reflection with ACAC:true was confirmed on one API host, and "
  "session cookies were observed on a different host in the same account family",
  "Probed the full host list for the conjunctive combination: arbitrary-Origin "
  "reflection, ACAC:true, and a Set-Cookie on the SAME path",
  "No host in the family had all three. Reflect-only hosts issued no cookie and "
  "their canonical data paths 404'd; cookie-only hosts emitted no CORS headers at "
  "all; one host pinned ACAO to a fixed developer origin with no reflection",
  "Splitting the test across two hosts proves the two behaviours exist, not that "
  "they combine. An attacker's page reads one response from one origin",
  "The exploitable condition is CONJUNCTIVE and lives on a single path: "
  "arbitrary-Origin reflection AND ACAC:true AND a cookie on that same path. "
  "Reflection on host A with cookies on host B is two harmless facts, not a "
  "finding - probe for the combination before reporting it",
  "redbull-intigriti/findings/status-summary.md (SALVAGE SWEEP)"),

 ("cors", "cors-fixed-acao-is-not-reflection",
  "A hardcoded Access-Control-Allow-Origin value in the response plus "
  "Access-Control-Allow-Credentials:true is an exploitable CORS misconfiguration",
  "ACAO was set on every response alongside ACAC:true",
  "Re-issued the request with an attacker Origin, with the hardcoded Origin, and "
  "with no Origin header, and compared the ACAO returned each time",
  "The ACAO value was byte-identical regardless of the Origin sent - the server "
  "pinned it rather than reflecting. A pinned ACAO cannot be matched by an "
  "attacker origin, so the browser blocks the credentialed read",
  "Reading 'ACAO present' as 'Origin reflected' is the whole error here",
  "CORS reflection requires the ACAO value to CHANGE with the Origin header. "
  "Send an attacker Origin and a second arbitrary Origin and compare: identical "
  "values are a pinned allowlist, and pinned-plus-ACAC is not exploitable. Word "
  "the finding as 'reflects' only after you have observed it vary",
  "redbull-intigriti/findings/status-summary.md (REPORT-03 VALIDATION S4)"),

 # ---------------- subdomain takeover ----------------
 ("subdomain_takeover", "takeover-dangling-cname-requires-zone-txt-ownership",
  "A subdomain CNAMEs to a SaaS provider whose own domain-ownership lock means a "
  "third party must publish a verification TXT record in the zone, therefore the "
  "hostname is not claimable and the dangling record is DNS hygiene only",
  "The CNAME resolved to the provider's serving domain and the provider edge "
  "returned its unconfigured-hostname error, the documented dangling signature",
  "Read the provider's documented signup and ownership-verification flow, and "
  "checked the vendor's own vulnerability status for that integration",
  "Claiming the hostname requires proving ownership by publishing a TXT record in "
  "the victim's DNS zone, which requires control of that zone. The provider "
  "additionally implements an ownership lock, so the hostname is bound to a "
  "previously-provisioned account and other accounts cannot adopt it",
  "The dangling fingerprint and the takeover fingerprint are the same response; "
  "the difference is entirely on the claimability side",
  "A dangling CNAME is not a takeover until the provider is shown to be "
  "CLAIMABLE by a third party. If signup requires a TXT record in the victim's "
  "zone, or the vendor is not on the known-vulnerable list, or the provider locks "
  "ownership after first use, the finding is DNS hygiene. State the claimability "
  "test explicitly and cite the provider doc that settles it",
  "prism_vdp/evidence/TAKEOVER-VALIDATION-VERDICTS.md (#1)"),

 ("subdomain_takeover", "takeover-wildcard-catch-all-masquerades-as-dangling",
  "A subdomain CNAMEs to a shared provider domain and the provider serves an "
  "empty page, therefore the record is dangling and claimable",
  "The CNAME resolved to a shared infrastructure domain and the provider "
  "returned HTTP 200 with an empty HTML body",
  "Sent a random unconfigured hostname to the same provider edge IP and compared "
  "the response byte for byte with the suspect subdomain's",
  "The random hostname returned the identical response, so the provider serves "
  "that body for ANY hostname - it is a wildcard catch-all, not an unconfigured "
  "hostname. Nothing is reserved and nothing is dangling",
  "A 200 with an empty body looks like a dangling record and is actually the "
  "provider's default response",
  "Before calling any provider response a dangling record, send a RANDOM Host "
  "header to the same edge IP. If the response is identical, the provider is a "
  "wildcard catch-all and your hostname is indistinguishable from a name that was "
  "never configured - that is not a takeover",
  "prism_vdp/evidence/TAKEOVER-VALIDATION-VERDICTS.md (#2)"),

 ("subdomain_takeover", "takeover-bare-apex-cname-missing-fingerprint",
  "Link-branding subdomains CNAME to the provider's bare apex domain, therefore "
  "they are dangling takeovers",
  "Three subdomains CNAME to the provider's apex domain and the apex returns 404",
  "Compared the response body against the provider apex root, then grepped the "
  "live body for the provider's documented takeover fingerprint, and checked "
  "whether the vendor account is still active via the provider's own DKIM and SPF "
  "records in the zone",
  "The body was byte-identical to the provider's own apex 404, the documented "
  "takeover fingerprint was absent from the response, the vendor integration is "
  "marked not vulnerable, and the account is still active with live DKIM keys "
  "and an SPF include. Only these three branding CNAMEs are unconfigured leftovers",
  "A CNAME to a large shared apex domain is not an account-scoped dangling record; "
  "the apex is used by every customer",
  "A CNAME to a provider's BARE apex is not an account-specific fingerprint. "
  "Confirm the response differs from the provider's own apex root and that the "
  "documented takeover string is present in the body; then confirm the vendor "
  "account is still live. Apex CNAMEs with none of those are leftovers",
  "prism_vdp/evidence/TAKEOVER-VALIDATION-VERDICTS.md (#3)"),

 ("subdomain_takeover", "takeover-blocked-by-provider-verification-record",
  "A subdomain resolves to a hosting provider whose anti-takeover verification "
  "record is present, therefore the takeover is blocked",
  "The CNAME chain pointed at a shared hosting provider",
  "Checked the zone for the provider's ownership-verification record",
  "The provider's anti-takeover verification TXT record is present in the zone, so "
  "ownership is already proven and a third party cannot claim the name",
  "Assuming every provider is claimable because the CNAME dangles",
  "A dangling CNAME on a provider that uses an ownership-verification TXT record "
  "is protected while that record is present. Check the zone for it before "
  "reporting; its presence is the disproof, not a mitigating factor",
  "algemeendagblad/reports/ALGEMEEN_DAGBLAD_HUNT_REPORT.md (non-findings)"),

 # ---------------- open redirect ----------------
 ("open_redirect", "redirect-reflected-into-same-host-302-is-not-open",
  "An endpoint reflects a redirect parameter into the Location header, therefore "
  "it is an open redirect",
  "A redirect parameter was echoed back into the redirect target and the server "
  "answered 302",
  "Followed the redirect and recorded the resolved Location host",
  "The 302 pointed back at the same host with the parameter echoed into the URL. "
  "No request ever left the origin, so an attacker cannot place their page in the "
  "redirect chain",
  "Reading a reflected parameter as an external redirect - the parameter must be "
  "echoed AND the hop must leave the origin",
  "A reflected redirect parameter is not an open redirect. Resolve the Location "
  "and confirm the 3xx leaves the origin: a same-host 302 with the parameter "
  "echoed is not a finding, and 'reflected parameter' alone will be read as "
  "padding on review",
  "redbull-intigriti/findings/status-summary.md (NEW-CLASS PIVOT)"),

 # ---------------- JWT ----------------
 ("jwt", "forged-alg-none-or-hs256-token-rejected-is-no-confusion",
  "A forged token with alg:none or an RS256-to-HS256 substitution is accepted, "
  "therefore the application is vulnerable to JWT algorithm confusion",
  "The application exposes user endpoints that authenticate with bearer tokens, "
  "so algorithm confusion is worth probing",
  "Sent forged tokens with alg:none and with the RSA public key supplied as the "
  "HMAC secret across the user endpoints, and recorded what the server accepted",
  "No forged identity was accepted. Responses were the application shell or 404, "
  "and the service never treated the forged subject as authenticated",
  "Assuming a library that parses a token is a library that trusts its header",
  "Algorithm confusion requires a forged token to be ACCEPTED as a valid "
  "identity. Send alg:none and the RS256-as-HS256 variant against a user endpoint "
  "and require the response to treat the forged subject as authenticated; a shell "
  "or 404 in reply is the disproof",
  "redbull-intigriti/findings/status-summary.md (JWT sweep)"),

 # ---------------- information disclosure ----------------
 ("info_disclosure", "source-maps-served-but-clean-is-not-sensitive-disclosure",
  "JavaScript source maps are fetchable unauthenticated and expose the "
  "unminified application, therefore this is sensitive information disclosure",
  "Several source maps were confirmed fetchable unauthenticated at their exact "
  "claimed sizes, and the sourcesContent revealed the full administrative UI and "
  "service contract",
  "Extracted and scanned the complete sourcesContent of every map together with "
  "the shipped chunks for credential and PII patterns: cloud access key ids, "
  "personal access tokens, bearer strings, payment and messaging provider keys, "
  "error-reporting endpoints, database connection strings, private addresses and "
  "SSH keys",
  "Zero hits across roughly a megabyte of sourcesContent. The single token-like "
  "literal was a public SDK application id already present in the served bundle, "
  "and one map was vendor boilerplate. The maps are live and genuinely reveal "
  "structure, but they contain nothing sensitive",
  "Treating 'the source is readable' as 'the source contains secrets'",
  "Source maps being served is a hardening gap. It becomes a sensitive "
  "disclosure only when the sourcesContent carries credentials, keys, PII or "
  "internal endpoints. Scan the extracted sources for those patterns and report "
  "the count; zero hits means the finding reduces to unminified code, which most "
  "programmes explicitly exclude",
  "redbull-intigriti/findings/status-summary.md (REPORT-03 VALIDATION S6)"),

 ("info_disclosure", "claimed-internal-endpoint-refuted-by-the-bundle",
  "A path discovered in source maps is an internal API contract, therefore the "
  "application exposes undocumented internal endpoints",
  "Service code and a documentation page referenced what looked like internal "
  "admin and integration endpoints",
  "Searched the shipped bundle for each claimed path and checked how the value "
  "was used - as a wired request target, as a client-side page-route constant, or "
  "as an example value in a public documentation example",
  "The paths appear only as page-route constants or as placeholder field values "
  "inside a public documentation example; neither is a reachable server endpoint. "
  "The 'internal contract' framing did not survive the check",
  "A string that appears in source is not a route the server serves",
  "Before reporting an endpoint discovered in source or docs, prove the client "
  "issues a request to it. A string that is only a page-route constant, or an "
  "example value inside a public docs example, is not an exposed endpoint",
  "redbull-intigriti/findings/status-summary.md (REPORT-03 VALIDATION S3)"),

 ("info_disclosure", "admin-info-endpoint-leaks-config-but-data-endpoints-403",
  "An admin information endpoint discloses project configuration including a "
  "registration flag, therefore the deployment is misconfigured",
  "The endpoint is reachable unauthenticated and returns the project "
  "configuration document",
  "Enumerated the collection, item, user and schema endpoints the same "
  "information endpoint implies, and attempted an unauthenticated login",
  "Collections and users returned forbidden, schema introspection was disabled, "
  "and authentication rejected the credentials. The disclosed flag described a "
  "configuration that was in fact enforced, and the version was not disclosed so "
  "no known vulnerability maps to it",
  "An information endpoint describing a secure configuration is confirmation the "
  "configuration is secure",
  "A config endpoint that reports a hardening flag is not a finding when the "
  "endpoints that flag protects actually enforce it. Enumerate the protected "
  "surface before reporting the disclosure; if it is all forbidden or disabled, "
  "the disclosure documents a working control",
  "redbull-intigriti/findings/status-summary.md (RULED OUT)"),

 # ---------------- SSRF ----------------
 ("ssrf", "ssrf-parameter-present-but-not-consumed-unauthenticated",
  "The client bundle references URL-accepting parameters for import, webhook and "
  "avatar features, therefore the application is vulnerable to SSRF",
  "URL-shaped parameters appear in the shipped JavaScript for several features",
  "Probed those parameters unauthenticated on the reachable hosts and watched for "
  "a server-side effect",
  "The consuming endpoints require an authenticated session. Unauthenticated the "
  "parameter was ignored entirely - application shell or 404, no server-side "
  "fetch. No outbound request occurred",
  "A parameter name in a bundle is not a reachable fetch",
  "A URL parameter proves SSRF only when the SERVER acts on it. Probe it "
  "unauthenticated and look for a DNS or HTTP effect attributable to your input; "
  "an ignored parameter is not SSRF, and a feature that exists only behind a "
  "session you cannot obtain is untested rather than vulnerable",
  "redbull-intigriti/findings/status-summary.md (SSRF sweep)"),

 # ---------------- rate limit / authn ----------------
 ("authn", "unauthenticated-forgets-verify-endpoint-is-untestable-not-bypass",
  "No rate limiting was observed on verification endpoints, therefore account "
  "enumeration is possible",
  "Verification and password-reset endpoints did not visibly throttle repeated "
  "requests",
  "Enumerate every login and token endpoint on the in-scope hosts and identify "
  "which ones actually perform the credential or verification check",
  "The credential-issuing endpoints on the in-scope hosts return not found; the "
  "real authentication flow lives on a host outside the authorised scope. With no "
  "in-scope endpoint performing the check, the absence of throttling there is a "
  "fact about scope, not a missing control",
  "Measuring the absence of a control on endpoints that do not perform the action",
  "Absence of rate limiting is only measurable where the operation happens. If the "
  "authenticating endpoint is out of scope or unreachable, you have not shown a "
  "missing control - you have shown you could not test. Say that instead of "
  "reporting the absence",
  "redbull-intigriti/findings/status-summary.md (RATE-LIMIT sweep)"),

 # ---------------- headers ----------------
 ("info_disclosure", "hsts-missing-at-redirect-but-present-on-real-paths",
  "The application lacks HSTS, therefore it is vulnerable to downgrade attacks",
  "A request to the bare root returned no HSTS header",
  "Requested every real authenticated path rather than the bare root, and "
  "recorded the headers on each",
  "HSTS is present on all the real application and API paths; only the root "
  "redirect lacks it, and that response is a redirect rather than content. "
  "Session cookies on the media host carried HttpOnly, SameSite and Secure",
  "Testing the header on the bare root instead of on the paths that carry "
  "content or authentication",
  "Measure a security header on the paths that actually serve content and set "
  "session state, not on a root redirect. HSTS absent only from the redirect "
  "while present on every real path is cosmetic",
  "redbull-intigriti/findings/status-summary.md (SECURITY HEADERS sweep)"),

 # ---------------- clickjacking ----------------
 ("clickjacking", "xfo-present-without-frame-ancestors-is-hardening-not-a-finding",
  "The response sets X-Frame-Options but no CSP frame-ancestors, therefore "
  "framing protection is incomplete",
  "The header block carries X-Frame-Options and no frame-ancestors directive",
  "Compared the two directives and rendered the framed document from a second "
  "origin to see whether the frame actually painted",
  "The legacy header cannot express a per-path allowlist and is the intended "
  "control where frame-ancestors is absent; the frame was refused. The pairing of "
  "both headers is the normal defensive configuration, not a missing one",
  "Reading the absence of one of two overlapping controls as a missing control",
  "X-Frame-Options without frame-ancestors is the COMMON hardened configuration - "
  "frame-ancestors has patchy support, so operators set both. Treat it as a "
  "finding only when the framed document actually renders cross-origin",
  "redbull-intigriti/findings/status-summary.md (SECURITY HEADERS sweep)"),

 # ---------------- misconfig ----------------
 ("misconfig", "universal-500-response-is-a-spa-fallback-not-a-flaw",
  "Every path on the API host returns an internal server error, therefore the "
  "service is misconfigured",
  "Any path probed returns HTTP 500",
  "Requested several unrelated and non-existent paths and compared the bodies",
  "All paths return the same development fallback response regardless of the "
  "path. Nothing is being processed server-side, so there is no error condition "
  "to trigger",
  "Reading a uniform catch-all response as a server error condition",
  "A uniform 500 across every path is an application-shell fallback, not a "
  "processing error. Probe paths that do not exist: if the response is identical, "
  "there is no handler running and nothing to exploit",
  "redbull-intigriti/findings/status-summary.md (RULED OUT)"),

 ("misconfig", "http-000-is-egress-blocking-not-a-service-defect",
  "Hosts return HTTP 000 and are therefore misconfigured",
  "Several hosts are unreachable and return no HTTP status",
  "Attempted connection from more than one egress path and compared against "
  "hosts that resolve and respond",
  "The addresses are excluded by edge protection or geo policy from the testing "
  "egress. No service responded on the port from anywhere reachable, so there is "
  "no running service to be misconfigured",
  "Recording a network-layer block as an application defect",
  "HTTP 000 means the connection never completed - it is an egress or edge-policy "
  "block, not a finding about the service. Record it as untested and re-probe from "
  "a different egress before making any claim",
  "redbull-intigriti/findings/status-summary.md (RULED OUT)"),
]


def main():
    con = sqlite3.connect(os.path.join(ROOT, "db", "wks.db"))
    con.row_factory = sqlite3.Row
    con.execute("PRAGMA busy_timeout=20000")

    # every class must exist, or the row lands with an unresolvable class_id
    have = {r[0] for r in con.execute("SELECT id FROM bug_class")}
    missing = sorted({r[0] for r in ROWS} - have)
    if missing:
        raise SystemExit("unknown class(es): %s -- register them first" % missing)

    existing = {r[0] for r in con.execute("SELECT fp_key FROM fp_case")}
    written = skipped = 0
    for (cid, key, hyp, looked, test, inval, missed, rule, ref) in ROWS:
        if key in existing:
            print("  exists, skipped: %s" % key)
            skipped += 1
            continue
        full = " ".join([hyp, looked, test, inval, missed, rule])
        try:
            assert_no_leak(full)
        except AssertionError as e:
            print("  REFUSED (leak) %s: %s" % (key, e))
            skipped += 1
            continue
        con.execute(
            "INSERT INTO fp_case (fp_key, class_id, hypothesis,"
            " looked_vulnerable_because, test_performed, invalidated_by,"
            " early_signal_missed, rejection_rule, created_at,"
            " provenance, source_ref)"
            " VALUES (?,?,?,?,?,?,?,?,datetime('now'),?,?)",
            (key, cid, hyp, looked, test, inval, missed, rule,
             "field_observation", ref))
        written += 1
    con.commit()

    n = con.execute("SELECT COUNT(*) FROM fp_case").fetchone()[0]
    lab = con.execute("SELECT provenance, COUNT(*) FROM fp_case"
                      " GROUP BY 1").fetchall()
    print()
    print("written %d, skipped %d, fp_case total now %d" % (written, skipped, n))
    for r in lab:
        print("   %-24s %d" % (r[0], r[1]))
    con.close()


if __name__ == "__main__":
    main()