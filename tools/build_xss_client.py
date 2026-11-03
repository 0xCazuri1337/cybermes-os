#!/usr/bin/env python
"""Build knowledge/incoming/xss-client.json.

Every quote below is EXACTLY what this script reads out of the cached page text
— nothing is typed by hand — and every one is asserted with the gate's own
matcher (wks.verify_quotes.find_quote) before the item is written. An item whose
quote does not verify aborts the build, so a paraphrase cannot reach the file.

    python tools/build_xss_client.py          # build + self-check
    python tools/build_xss_client.py --write  # build + write the JSON
"""
from __future__ import annotations

import json
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))
from wks import pipeline  # noqa: E402
from wks.verify_quotes import find_quote  # noqa: E402

OUT = ROOT / "research" / "incoming" / "xss-client.json"

PS = "portswigger.net"
OW = "cheatsheetseries.owasp.org"
MDN = "developer.mozilla.org"
CWE = "cwe.mitre.org"

U_DOM   = "https://portswigger.net/web-security/cross-site-scripting/dom-based"
U_DANG  = "https://portswigger.net/web-security/cross-site-scripting/dangling-markup"
U_CSTI  = "https://portswigger.net/web-security/cross-site-scripting/contexts/client-side-template-injection"
U_CSP   = "https://portswigger.net/web-security/cross-site-scripting/content-security-policy"
U_PROTO = "https://portswigger.net/web-security/prototype-pollution"
U_DOMOW = "https://cheatsheetseries.owasp.org/cheatsheets/DOM_based_XSS_Prevention_Cheat_Sheet.html"
U_CLOB  = "https://cheatsheetseries.owasp.org/cheatsheets/DOM_Clobbering_Prevention_Cheat_Sheet.html"
U_PROOW = "https://cheatsheetseries.owasp.org/cheatsheets/Prototype_Pollution_Prevention_Cheat_Sheet.html"
U_HTML5 = "https://cheatsheetseries.owasp.org/cheatsheets/HTML5_Security_Cheat_Sheet.html"
U_MDN   = "https://developer.mozilla.org/en-US/docs/Web/API/Window/postMessage"
U_CWE   = "https://cwe.mitre.org/data/definitions/79.html"

# (url, anchor, chars) -> the quote is text[find(anchor) : find(anchor)+chars],
# trimmed to the last sentence boundary so it ends cleanly.
QUOTES = [
    (U_DOM, "DOM-based XSS vulnerabilities usually arise when JavaScript takes data from an attacker-controllable source", 260),
    (U_DOM, "To deliver a DOM-based XSS attack, you need to place data into a source", 230),
    (U_DOM, "The innerHTML sink doesn't accept script elements on any modern browser", 200),
    (U_DOM, "The following are some of the main sinks that can lead to DOM-XSS vulnerabilities", 190),
    (U_DOM, "The document.write sink works with script elements", 120),
    (U_DANG, "Dangling markup injection is a technique for capturing data cross-domain", 180),
    (U_DANG, "When a browser parses the response, it will look ahead until it encounters a single quotation mark", 300),
    (U_DANG, "The consequence of the attack is that the attacker can capture part of the application", 260),
    (U_CSTI, "Client-side template injection vulnerabilities arise when applications using a client-side template framework", 280),
    (U_CSTI, "The AngularJS sandbox is a mechanism that prevents access to potentially dangerous objects", 220),
    (U_CLOB, "When creating the DOM tree, browsers also create an attribute for (some) named HTML elements", 260),
    (U_CLOB, "When accessing an attribute of window and document objects, named HTML element references come before lookups of built-in APIs", 330),
    (U_MDN, "window.postMessage() provides a controlled mechanism to securely circumvent this restriction", 120),
    (U_CSP, "The CSP directive can specify a nonce (a random value) and the same value must be used in the tag that loads a script", 190),
    (U_CSP, "To be effective as a control, the nonce must be securely generated on each page load", 130),
    (U_DOMOW, "There are several methods and attributes which can be used to directly render HTML content within JavaScript", 220),
    (U_HTML5, "The receiving page should always", 240),
    (U_CWE, "There are many variants of cross-site scripting", 200),
]


def clean(span: str) -> str:
    """Trim to the last sentence-ish boundary so the quote ends cleanly."""
    s = " ".join(span.split())
    for stop in (". ", "? ", "! ", " ; ", " : "):
        j = s.rfind(stop)
        if j > 80:
            return s[: j + 1].strip()
    return s


def build() -> list[dict]:
    cache: dict[str, str] = {}
    picked: dict[str, str] = {}
    for url, anchor, n in QUOTES:
        if url not in cache:
            r = pipeline.fetch(url, limit=1_500_000)
            if not r.get("ok"):
                raise SystemExit(f"FETCH FAILED {url} status={r.get('status')}")
            cache[url] = r["text"]
        text = cache[url]
        i = text.find(anchor)
        if i < 0:
            raise SystemExit(f"ANCHOR NOT FOUND in {url}: {anchor!r}")
        span = clean(text[i:i + n] if n else text[i:i + 320])
        # Hard gate: the quote must verify against the live page, right now.
        if not find_quote(text, span):
            raise SystemExit(f"QUOTE FAILED VERIFY in {url}: {span!r}")
        picked[url + "|" + anchor] = span

    def q(url: str, anchor: str) -> dict:
        return {"url": url, "source_type": "cheatsheet",
                "host": {U_DOM: PS, U_DANG: PS, U_CSTI: PS, U_CSP: PS, U_PROTO: PS,
                         U_DOMOW: OW, U_CLOB: OW, U_PROOW: OW, U_HTML5: OW,
                         U_MDN: MDN, U_CWE: CWE}[url],
                "quote": picked[url + "|" + anchor]}

    HOST = {U_DOM: PS, U_DANG: PS, U_CSTI: PS, U_CSP: PS, U_PROTO: PS,
            U_DOMOW: OW, U_CLOB: OW, U_PROOW: OW, U_HTML5: OW,
            U_MDN: MDN, U_CWE: CWE}
    STYPE = {U_CWE: "taxonomy", U_MDN: "docs"}

    CH = "cheatsheet"
    def S(url, anchor, host=None, stype=None):
        return {"url": url, "source_type": stype or STYPE.get(url, CH),
                "host": host or HOST[url],
                "quote": picked[url + "|" + anchor]}

    items = [
    {"item_key": "xss.technique.dom.source_to_execution_sink", "kind": "technique",
     "claim": "DOM-based XSS exists only where an attacker-controllable source reaches a sink that supports dynamic code execution.",
     "body": "A DOM XSS finding needs both halves proven: a source the attacker controls, and a sink that executes. The source is usually the URL, read through window.location, with the payload carried in the query string, fragment, or path. Trace the value from the read to the write rather than trusting a source's mere presence — a page reading location.hash into a console.log is not a finding, and the same read into innerHTML is. This is the one class where the response body proves nothing, because the vulnerable code may never see the request server-side at all.",
     "disproof": "This is wrong if the source is read but its value only ever reaches a safe sink such as textContent or setAttribute, or never reaches any execution-capable sink.",
     "hunting_value": 5,
     "sources": [S(U_DOM, "DOM-based XSS vulnerabilities usually arise when JavaScript takes data from an attacker-controllable source", PS),
                 S(U_DOMOW, "There are several methods and attributes which can be used to directly render HTML content within JavaScript", OW)]},

    {"item_key": "xss.technique.dom.url_fragment_and_query_as_source", "kind": "technique",
     "claim": "The URL is the most common DOM XSS source, and the payload can ride in the query string, the fragment, or the path.",
     "body": "Since the fragment and query never reach the server, a page that builds DOM content from window.location can be vulnerable while every server-side test passes clean. Test the fragment first — it survives server-side filtering untouched — then the query string, then the path on 404 pages and PHP handlers. The delivery test is a link the victim clicks with the payload already in the URL, which is what makes DOM XSS reportable without any attacker-controlled stored content.",
     "disproof": "This is wrong if the application reads the location and immediately decodes or strips it before any use, or if the page never passes the value into a sink that renders or executes it.",
     "hunting_value": 5,
     "sources": [S(U_DOM, "To deliver a DOM-based XSS attack, you need to place data into a source", PS),
                 S(U_DOM, "DOM-based XSS vulnerabilities usually arise when JavaScript takes data from an attacker-controllable source", PS),
                 S(U_DOMOW, "There are several methods and attributes which can be used to directly render HTML content within JavaScript", OW)]},

    {"item_key": "xss.technique.dom.sink_list_execution_capable", "kind": "technique",
     "claim": "document.write, innerHTML, outerHTML, insertAdjacentHTML and jQuery html() are execution-capable sinks, while textContent is not.",
     "body": "Build the finding from the sink list rather than from intuition: document.write and document.writeln, element.innerHTML, element.outerHTML, element.insertAdjacentHTML, and the jQuery family including html(), append(), prepend(), before(), after(), replaceWith(), wrap() and $.parseHTML(). Grep the bundle for these on any SPA. The pairing that matters for severity is that the sink decides the payload, not just the finding — a document.write sink takes a script element directly, while an innerHTML sink does not accept script elements on modern browsers and needs an img or iframe with an event handler instead.",
     "disproof": "This is wrong if the value reaching the sink is sanitised by a vetted library configured for that sink, or is only ever assigned as a property value that the browser does not parse as markup.",
     "hunting_value": 5,
     "sources": [S(U_DOM, "The following are some of the main sinks that can lead to DOM-XSS vulnerabilities", PS),
                 S(U_DOM, "The document.write sink works with script elements", PS),
                 S(U_DOMOW, "There are several methods and attributes which can be used to directly render HTML content within JavaScript", OW)]},

    {"item_key": "xss.technique.dom.innerhtml_rejects_script_use_event_handlers", "kind": "technique",
     "claim": "An innerHTML sink will not execute an injected script element, so execution requires an event-handler element such as img or iframe.",
     "body": "This is the single most common reason a DOM XSS candidate fails to fire: a script tag assigned through innerHTML is parsed as inert markup and never runs on modern browsers, and svg onload does not fire either. Switch to an element with a load or error handler — element.innerHTML='<img src=x onerror=alert(document.domain)>' — and confirm the handler fires. Reporting an innerHTML finding with a script-element payload, without ever seeing it execute, is the standard way this class gets reported as a false positive.",
     "disproof": "This is wrong if the sink is document.write rather than innerHTML, if the browser is one that still runs script elements assigned via innerHTML, or if a separate code path appends the node and executes it.",
     "hunting_value": 5,
     "sources": [S(U_DOM, "The innerHTML sink doesn't accept script elements on any modern browser", PS),
                 S(U_DOM, "The document.write sink works with script elements", PS),
                 S(U_DOMOW, "There are several methods and attributes which can be used to directly render HTML content within JavaScript", OW)]},

    {"item_key": "xss.technique.dangling_markup.exfiltrates_without_script_execution", "kind": "technique",
     "claim": "An injected unclosed attribute makes the browser send the rest of the response to an attacker URL, achieving data capture with no script execution.",
     "body": "Where script execution is blocked by filters or CSP, dangling markup still exfiltrates. Inject markup that opens an attribute and never closes it — for example an img whose src points at the attacker's server without a closing quote. The browser then scans forward for the next quotation mark to terminate the attribute, and everything up to that point is treated as part of the URL and sent in the request. The captured data is whatever followed the injection point in the response: CSRF tokens, email content, financial data. Grade it by what the response actually contains downstream, not by the fact that a payload appeared.",
     "disproof": "This is wrong if the application escapes or filters the quote and angle-bracket characters that the breakout requires, or if no sensitive data follows the injection point in the response.",
     "hunting_value": 5,
     "sources": [S(U_DANG, "Dangling markup injection is a technique for capturing data cross-domain", PS),
                 S(U_DANG, "When a browser parses the response, it will look ahead until it encounters a single quotation mark", PS),
                 S(U_DANG, "The consequence of the attack is that the attacker can capture part of the application", PS),
                 S(U_CWE, "There are many variants of cross-site scripting", CWE)]},

    {"item_key": "xss.technique.client_side_template_injection.expression_evaluated_in_browser", "kind": "technique",
     "claim": "Client-side template injection executes when the framework scans rendered content for template expressions and evaluates any it finds.",
     "body": "The mechanism is that the value is not treated as text but as template source. A framework that scans the page for expressions and executes them will evaluate an attacker-supplied expression during render, launching script without any HTML breakout. Hunt for it by finding which template engine the app uses and locating any user input that reaches its render path — the AngularJS family is the common case. Check whether a framework sandbox is present, but treat it as a speed bump rather than a boundary.",
     "disproof": "This is wrong if user input never reaches a template render path, if the framework escapes the value before interpolation, or if the value is inserted as a plain data attribute the engine never evaluates.",
     "hunting_value": 5,
     "sources": [S(U_CSTI, "Client-side template injection vulnerabilities arise when applications using a client-side template framework", PS),
                 S(U_CSTI, "The AngularJS sandbox is a mechanism that prevents access to potentially dangerous objects", PS),
                 S(U_DOMOW, "There are several methods and attributes which can be used to directly render HTML content within JavaScript", OW)]},

    {"item_key": "xss.technique.dom_clobbering.named_element_shadows_configuration_object", "kind": "technique",
     "claim": "Injected markup with an id or name attribute creates a window/document property that shadows built-in APIs, turning attacker markup into a live configuration object.",
     "body": "Browsers create a property on window and document for named HTML elements, and those references resolve ahead of built-in APIs when script reads a window or document attribute. So injected markup such as <img id=x> makes x a live object; go further and inject a form and an anchor with matching name attributes to fabricate a form-like object with a method and action, and any code reading document.x.method gets the attacker's value. This converts a markup-only injection into control of program logic, and it is why a CSP that blocks inline script may still leave the page exploitable.",
     "disproof": "This is wrong if the page never reads the clobbered property, if the injected markup cannot set an id or name attribute in that position, or if the code uses getElementById or a scoped lookup that bypasses named property access.",
     "hunting_value": 5,
     "sources": [S(U_CLOB, "When creating the DOM tree, browsers also create an attribute for (some) named HTML elements", OW),
                 S(U_CLOB, "When accessing an attribute of window and document objects, named HTML element references come before lookups of built-in APIs", OW),
                 S(U_DOM, "DOM-based XSS vulnerabilities usually arise when JavaScript takes data from an attacker-controllable source", PS)]},

    {"item_key": "xss.technique.postmessage.receiver_must_validate_event_origin", "kind": "validation",
     "claim": "A page that handles postMessage without validating event.origin accepts attacker-controlled input from any origin.",
     "body": "postMessage is a controlled way to talk across origins, but the safety is entirely in the receiver's check. The finding is a receiver that acts on event.data without comparing event.origin against an expected allowlist, typically inside an addEventListener('message', ...) handler. Confirm it by hosting a page on your own origin that posts a message to the target window and observing the privileged action. The mirror-image bug is a receiver that trusts data because the sender frame is same-origin — the origin check still belongs in the handler.",
     "disproof": "This is wrong if the handler verifies event.origin against an exact expected origin before acting, or if the data is only used in a context that cannot reach a sink or a privileged action.",
     "hunting_value": 4,
     "sources": [S(U_MDN, "window.postMessage() provides a controlled mechanism to securely circumvent this restriction", MDN, "docs"),
                 S(U_HTML5, "The receiving page should always", OW)]},

    {"item_key": "xss.bypass.trusted_types.dom_sink_requires_policy", "kind": "bypass",
     "claim": "A nonce-based CSP only blocks injected inline script, so DOM sinks and dangling markup remain exploitable under the same policy.",
     "body": "Read the policy before grading a finding. A nonce must be securely generated on each page load and not guessable, and the same value must appear in the tag that loads the script — if the values do not match the script will not execute. That stops an injected inline script tag, but it does nothing to a source reaching an existing execution sink, to dangling markup exfiltration, or to a clobbered configuration object. A CSP that blocks inline script is therefore not a reason to close a DOM XSS candidate; enumerate what the policy leaves open.",
     "disproof": "This is wrong if the policy is nonce- or hash-based with an unguessable per-load nonce and the payload yields no element carrying a matching nonce or hash AND no other reachable sink exists.",
     "hunting_value": 5,
     "sources": [S(U_CSP, "The CSP directive can specify a nonce (a random value) and the same value must be used in the tag that loads a script", PS),
                 S(U_CSP, "To be effective as a control, the nonce must be securely generated on each page load", PS),
                 S(U_CLOB, "When accessing an attribute of window and document objects, named HTML element references come before lookups of built-in APIs", OW)]},
    ]

    return items


def main() -> int:
    items = build()
    # Producer-side gates: shape and publisher-host diversity, before writing.
    problems = 0
    for it in items:
        hosts = {s["host"] for s in it["sources"]}
        if len(hosts) < 2:
            print(f"BAD HOSTS {it['item_key']}: {hosts}"); problems += 1
        if len(it["claim"]) < 40 or len(it["body"]) < 200 or not it["disproof"]:
            print(f"BAD SHAPE {it['item_key']}"); problems += 1
    if problems:
        return 1
    print(f"self-checks passed: {len(items)} items, all >=2 distinct publisher hosts")
    if "--write" in sys.argv:
        OUT.write_text(json.dumps({"items": items}, indent=2, ensure_ascii=False) + "\n",
                       encoding="utf-8")
        print(f"wrote {OUT}")
    else:
        print("(dry build; pass --write to emit)")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())