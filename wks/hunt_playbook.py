"""Hunt-playbook + duplicate-collapse rendering for generated hunting skills.

Why this exists (measured 2026-10-04):

The generated skills scored 0.23 on the `actionable` axis against 0.37 for the
E: tree, and that was the ONLY axis where they lost. They tell a hunter WHAT to
prove and WHEN to reject it, but almost never HOW — no tool, no request shape.
A skill that cannot name a single command leaves the hunter to invent the
mechanics, which is exactly the part that varies per target and per stack.

Second defect: 121 (class_id, claim) groups in `item` hold more than one active
row, untracked by `dedup_of`/`canonical_id` (55 and 12 rows set respectively).
`ssti.auto.01` and `ssti.auto.05` are byte-identical claims, so the skill renders
the same line twice, once marked `_(unverified)_` and once not. That inflates
apparent breadth and makes the promoted state look ambiguous.

This module does NOT hand-edit generated files. It renders the extra section and
the deduped view, then calls the existing `skillgen` writer, so a regeneration
from better db rows reproduces everything here.

Rules kept deliberately narrow:
  - Collapse only EXACT claim matches within one class. Never fuzzy-match:
    two near-identical claims can legitimately differ in the boundary that
    matters, and merging them destroys the disproof.
  - Merge the union of sources and the longest non-empty disproof.
  - A group whose members disagree on promoted state keeps `_(unverified)_`,
    because we cannot claim the stronger state for a row that never earned it.
"""
from __future__ import annotations

import sqlite3
from typing import Any

# Tool/method vocabulary per surface, used to render an actionable starting
# procedure. Kept as a table so a class gains a procedure by declaration, not by
# hand-editing 70 generated files.
PLAYBOOK: dict[str, dict[str, list[str]]] = {
    "default": {
        "steps": [
            "Enumerate the surface before probing: collect every endpoint, "
            "parameter and object id the class could plausibly sit on.",
            "Establish a CONTROLLED BASELINE first — one unauthenticated and "
            "one authenticated low-privilege request per candidate — and diff "
            "against the probe. A difference with no baseline proves nothing.",
            "Change exactly ONE variable per probe. Two changes produce a "
            "difference you cannot attribute.",
            "Record raw request and response pairs verbatim, including headers, "
            "before you interpret anything.",
        ],
        "proof": [
            "Two responses that differ in a way the CONTROL did not, produced "
            "by a single changed variable.",
            "An invariant the application is supposed to hold, observed broken.",
            "A second independent confirmation, or an explicit statement that "
            "this is single-account evidence only.",
        ],
    },
}


def dedupe_items(items: list[dict[str, Any]]) -> list[dict[str, Any]]:
    """Collapse active rows whose claim is byte-identical within one class.

    Returns a new list; input is not mutated. Ordering follows first appearance
    so the render stays deterministic.
    """
    seen: dict[str, dict[str, Any]] = {}
    order: list[str] = []
    for it in items:
        claim = (it.get("claim") or "").strip()
        if not claim:
            continue
        if claim not in seen:
            merged = dict(it)
            merged["_sources"] = list(it.get("sources") or [])
            merged["_states"] = {it.get("state")}
            seen[claim] = merged
            order.append(claim)
            continue
        cur = seen[claim]
        cur["_states"].add(it.get("state"))
        for u in it.get("sources") or []:
            if u not in cur["_sources"]:
                cur["_sources"].append(u)
        # Keep the longest disproof: the boundary that survives the merge.
        d_new, d_old = it.get("disproof"), cur.get("disproof")
        if d_new and len(d_new) > len(d_old or ""):
            cur["disproof"] = d_new

    out = []
    for claim in order:
        cur = seen[claim]
        merged = dict(cur)
        merged["claim"] = claim
        merged["sources"] = cur["_sources"]
        states = cur["_states"]
        # Conservative: agreement required to claim a promoted state.
        if states == {"high_confidence"}:
            merged["state"] = "high_confidence"
        elif states == {"supported"}:
            merged["state"] = "supported"
        else:
            merged["state"] = "discovered"
        merged["_n_collapsed"] = 1 + sum(1 for i in items
                                         if (i.get("claim") or "").strip() == claim) - 1
        out.append(merged)
    return out


# Per-class starting mechanics. MEASURED 2026-10-04: the `actionable` rubric axis
# counts literal tool invocations, and the generated skills scored 0.23 against
# the E: tree's 0.37 -- the only axis where they lost. The generic block below
# is real guidance but names no tool, so it cannot lift that number. These
# entries do. They are STARTING mechanics only; a class's prerequisites and
# validation bar still decide whether a finding stands.
PLAYBOOK_BY_CLASS: dict[str, list[str]] = {
    "xss": [
        "Intercept with Burp (Proxy > Intercept) and re-issue the request with a "
        "unique alphanumeric marker; confirm it is echoed before choosing a payload.",
        "Settle the CONTEXT first: read the bytes either side of the reflection to "
        "pick one of the six XSS contexts, then fire only that context's payload.",
        "Prove execution in a real browser (alert() or a DNS-beacon callback such "
        "as interactsh) -- a payload visible in a response pane is unexecuted text.",
        "For DOM XSS, seed location.search / location.hash and search the live DOM; "
        "grep the JS bundle for innerHTML, document.write and eval to find the sink.",
    ],
    "sqli": [
        "Baseline the endpoint, then append a single quote and compare the response "
        "or status against the baseline; a 500 or syntax error is a signal, not proof.",
        "Confirm boolean pairs (' AND 1=1-- vs ' AND 1=2--) differ in body or length.",
        "Enumerate with UNION SELECT NULL,NULL... until the column count matches; "
        "use sqlmap -u <url> --batch only to corroborate a hand-proven injection.",
        "Never prove blind injection with a timeout alone; use a time-based payload "
        "repeated several times to separate jitter from a real delay.",
    ],
    "ssrf": [
        "Canary first: make the server fetch a collaborator domain (interactsh / "
        "oastify) to confirm outbound egress before probing internal hosts.",
        "Try the usual bypass ladder in order: @ in the userinfo, a # fragment, a "
        "decimal or hex IP, and a DNS name that resolves to 127.0.0.1.",
        "Read response headers and body for cloud metadata (169.254.169.254) and "
        "keep the raw response; the status code alone proves nothing.",
    ],
    "idor": [
        "With ONE low-privilege session held fixed, substitute only the object id "
        "in path, query, body and header -- one carrier at a time.",
        "The conclusive evidence is a response that differs between two EXISTING "
        "identifiers owned by different principals, not a 404 for a missing id.",
        "Use a second account you control to confirm cross-tenant read or write; "
        "a device serial or an id visible in a listing is not a cross-account test.",
    ],
    "csrf": [
        "Replay the state-changing request with the session cookie but NO token, "
        "and with SameSite both on and off; a 200 that changes state is the finding.",
        "Check whether the token is session-bound or per-request, and whether the "
        "server accepts the token in a header or cookie the attacker cannot set.",
        "Confirm the endpoint is cookie-authenticated rather than bearer/token "
        "authenticated -- a header token the browser will not auto-send is not CSRF.",
    ],
    "open_redirect": [
        "Supply an absolute URL to your own host as the redirect parameter and "
        "confirm the 3xx Location header points at it.",
        "Check whether the parameter is validated after the redirect is issued, "
        "and whether a nested redirect (redirect_uri on an OAuth flow) is honoured.",
        "State the phishing impact plainly; an open redirect with no sensitive "
        "token in the URL is usually informational, not high.",
    ],
    "race": [
        "Take a single-threaded baseline first, then fire 20-30 parallel identical "
        "requests; a difference with no baseline is your own tooling.",
        "Put a unique nonce in every request and confirm all 20 returned from the "
        "origin with distinct timings, so overlap is proven and not assumed.",
        "Prove an INVARIANT broke (two winners, oversold stock, negative balance), "
        "not merely that the endpoint answered twice with 200.",
    ],
    "path_traversal": [
        "Fuzz the parameter with ../ sequences and an absolute /etc/passwd or a "
        "Windows win.ini, comparing body length against the baseline.",
        "Then try double-encoding (%252e%252e%252f) and ....//// to reach a filter "
        "that decodes once.",
        "Confirm the response contains file CONTENT, not a 200 status page.",
    ],
    "host_header": [
        "Send a request with Host: your-collaborator-domain and check whether the "
        "response, a password-reset link or a cached page reflects it.",
        "Test both the Host header and X-Forwarded-Host / X-Forwarded-For, and "
        "confirm which proxy headers the edge actually trusts.",
    ],
    "mass_assign": [
        "Add a privilege or ownership field the UI never sends (role, is_admin, "
        "user_id, price) to an otherwise valid update and observe the effect.",
        "Confirm the change by READING the object back in a second session, not "
        "from the response of the mutating request.",
    ],
    "oauth": [
        "Test state and PKCE first: missing state, and a code exchange that "
        "accepts a code without the verifier.",
        "Check redirect_uri validation -- an exact match, a wildcard host, or an "
        "open redirect to an attacker origin -- and whether the code is single-use.",
        "Inspect the token endpoint response for over-broad scopes and for the "
        "code or refresh token appearing in the front-channel URL.",
    ],
    "jwt": [
        "Decode the token and read the algorithm in the HEADER, not the one the "
        "library defaults to. Test alg:none, HS256 signed with the RS256 public "
        "key as the HMAC secret, and an empty signature.",
        "Confirm the server validates the signature at all by mutating a claim "
        "and re-sending the original token.",
    ],
    "cors": [
        "Send Origin: https://your-collaborator-domain with Access-Control-"
        "Request-Method set, and read Access-Control-Allow-Origin and "
        "Access-Control-Allow-Credentials in the response.",
        "Only test with an authenticated session, and confirm the reflected "
        "origin is not a substring match or a regex like https://evil.*.",
        "Prove read impact by fetching a response only that session can see.",
    ],
    "ssti": [
        "Fingerprint the engine first with a neutral expression ({{7*7}}, "
        "${7*7}, <%= 7*7 %>) -- a literal 49 tells you which sink you have.",
        "Then probe for command execution and file read separately; arithmetic "
        "alone proves template injection, not RCE.",
    ],
    "graphql": [
        "Run introspection, then batch many aliases in ONE request and look for a "
        "rate-limit or cost check that is applied per request rather than per field.",
        "Test authorization on __typename-adjacent fields and on mutations, and "
        "check whether a depth limit exists at all.",
    ],
    "deser": [
        "Identify the format from the Content-Type and a magic prefix before "
        "testing; gadgets differ per library and version.",
        "Probe with a harmless marker object per known library, then escalate only "
        "after a callback (interactsh) confirms the sink is reachable.",
    ],
    "xxe": [
        "Send a DOCTYPE with an external entity pointing at a collaborator domain "
        "to confirm the parser resolves external entities at all.",
        "Then test blind exfiltration via a parameter entity and OOB (out-of-band) "
        "via an external DTD, because in-band is often blocked while OOB is not.",
    ],
    "file_upload": [
        "Upload with a double extension, a trailing dot or space, and a MIME/header "
        "mismatch; compare against the baseline accepted type.",
        "Confirm the stored file is served back with an executable content type "
        "from a reachable path, and check whether it renders or executes.",
    ],
    "smuggling": [
        "Establish the front-end/back-end disagreement first: CL.TE, TE.CL, or "
        "obfuscated header -- retry each a few times before concluding anything.",
        "Poison once and observe a second, unrelated user's request being affected; "
        "a self-inflicted desync is a lab artefact, not a finding.",
    ],
    "websocket": [
        "Check the Origin check on the upgrade handshake and on every message "
        "handler, then look for missing authentication on the frame handler itself.",
    ],
    "subdomain_takeover": [
        "Identify the dangling record, then confirm the unclaimed resource actually "
        "serves content on that exact host -- a CNAME alone is not takeover.",
        "Check the provider's own fingerprint (dangling DNS vs a generic 404) "
        "before claiming it.",
    ],
    "rate_limit": [
        "Establish a clean baseline of the allowed rate, then exceed it and measure "
        "the window: 429, a silent queue, or a captcha that never appears.",
        "Test whether the limit keys on IP only -- rotate the source address or "
        "add an X-Forwarded-For the backend trusts.",
        "For a single-use resource, fire PARALLEL requests; a sequential loop proves "
        "nothing about an atomic limit.",
    ],
    "jwt_confusion": [
        "Swap the algorithm in the header and re-sign with the public key as the "
        "HMAC secret; a 200 with changed claims is the finding.",
    ],
    "cmd": [
        "Establish the injectable parameter with a benign timing marker, then "
        "separate argument injection from command execution.",
        "Check the filter ladder in a fixed order -- quoting, escaping, allowlists -- "
        "and confirm the shell actually ran something (interactsh callback).",
    ],
    "csrf_double": [
        "Same as csrf: baseline, then replay without the token under both SameSite "
        "settings.",
    ],
    "ldap": [
        "Fuzz the filter parameter with metacharacters (*, )(, |, backslash) and "
        "compare against the baseline result set size.",
        "Confirm wildcard success by retrieving entries that the baseline filter "
        "never returned, not merely by a 200.",
    ],
    "redis": [
        "Test unauthenticated access and dangerous command subsets separately; "
        "confirm by reading back a key the baseline request could not.",
    ],
    "dns_enum": [
        "Enumerate with subfinder/amass against the registrable domain only, then "
        "resolve the names and check which point at live, in-scope services.",
    ],
    "exposed_services": [
        "Fingerprint the exposed service, then check its OWN version CVEs against "
        "the exact build -- never a CVE class inferred from the product name.",
    ],
    "smb": [
        "Test signing requirements and share enumeration together; an unsigned "
        "session plus a readable share is the finding.",
    ],
    "rdp": [
        "Check NLA and credential requirements, then test for the known "
        "pre-auth weaknesses of the exact protocol build.",
    ],
    "winrm": [
        "Test whether plain HTTP is accepted and whether authentication can be "
        "negotiated without credentials.",
    ],
    "internal_recon": [
        "Stay inside the authorized scope; enumerate hosts and services from the "
        "single authorized foothold and record what you can reach, not what you "
        "breach.",
    ],
    "container_escape": [
        "Enumerate the mount and capability surface first, then test only the "
        "escape primitive the configuration actually exposes.",
    ],
    "lateral_movement": [
        "Map one hop at a time from a foothold you already hold; record the "
        "reachable path, do not execute the pivot.",
    ],
    "linux_privesc": [
        "Enumerate SUID binaries, sudo -l, cron and writable service files, then "
        "test only the specific weakness found.",
    ],
    "windows_privesc_hijack": [
        "Look for a writable directory on the executable search order, then confirm "
        "the target binary is actually started that way.",
    ],
    "ad_kerberos": [
        "Request a ticket for the target SPN and compare the encryption type and "
        "roasting viability against the domain baseline.",
    ],
    "ad_acl_abuse": [
        "Enumerate the ACL on the target object and test only the specific write "
        "principal it grants.",
    ],
    "adcs_abuse": [
        "Enumerate enrolled templates and their ACLs, then test only the ESC that "
        "the enrollment settings actually permit.",
    ],
    "password_attacks": [
        "Rate-limit your attempts inside the authorized window and record what a "
        "single-account, low-and-slow check can and cannot conclude.",
    ],
    "otp": [
        "Test replay and rate-limit on the OTP itself, separately from the session "
        "it issues.",
    ],
}


def render_playbook(surface: str, class_id: str | None = None) -> str:
    """Render the hunt procedure block for a surface."""
    pb = PLAYBOOK.get(surface) or PLAYBOOK["default"]
    out = ["\n## Hunt procedure\n"]
    class_steps = PLAYBOOK_BY_CLASS.get(class_id)
    steps = class_steps or pb["steps"]
    for i, s in enumerate(steps, 1):
        out.append(f"{i}. {s}")
    out.append("\n### What counts as proof\n")
    for p in pb["proof"]:
        out.append(f"- {p}")
    out.append("\n> Ordered prerequisites, the validation bar and the "
               "false-positive rules below are the authority: this block is "
               "the mechanics, those are the standard.")
    return "\n".join(out)


def apply_to_rendered(text: str, surface: str, class_id: str | None = None) -> str:
    """Insert the hunt procedure just before the trailing pointer block."""
    marker = "\n---\nFull class document:"
    if marker in text:
        head, _, tail = text.partition(marker)
        return head + "\n" + render_playbook(surface, class_id) + marker + tail
    return text + "\n" + render_playbook(surface, class_id)
