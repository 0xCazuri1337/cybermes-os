# Debate turn 1 — state your position

CLASS UNDER DISCUSSION: xss
YOUR LENS: standards/cheatsheet framing — what does the normative rule require?

## What the corpus already knows (do not repeat it — build on or dispute it)
{
  "class_id": "xss",
  "existing_items": [
    {
      "key": "xss.test.execution.confirm_in_real_browser",
      "claim": "A payload only counts as XSS once a real browser parses the delivered page and the injected JavaScript actually runs; a payload visible in Repeater's response pane is unexecuted source text, not a finding.",
      "kind": "test",
      "disproof": "The procedure is wrong if a payload executes with no visible trace you chose to look for - e.g. the proof writes to a network beacon instead of the DOM, so 'no alert' reads as failure when execution actually happened. It is also wrong to require a visible popup as the sole gate: CSP report-only mode, Trusted Types default policies, and headless profiles can all suppress alert() while script still runs. Confirm with a second, independent observable (network egress, DOM mutation, console log) before calling it a failure."
    },
    {
      "key": "xss.chain_link.csrf_token_read_defeats_csrf_defence",
      "claim": "An anti-CSRF token provides no protection against XSS, because script executing in the victim's origin can read the token out of the page or the response and replay the state-changing request with it.",
      "kind": "chain_link",
      "disproof": "If the state-changing request is refused with a token-validation error even when the script supplies the token read from the same page, the defence is holding and this chain link does not apply to that endpoint."
    },
    {
      "key": "xss.fp_rule.self_xss.payload_renders_only_in_submitter_browser",
      "claim": "Reject an XSS candidate as unproven when the payload can only be made to render by pasting attacker-supplied JavaScript into the submitter's own address bar or console, because that is self-XSS and not a cross-user finding.",
      "kind": "fp_rule",
      "disproof": "The candidate stops being self-XSS the moment a working delivery exists: a crafted URL (or a CSRF-style auto-submitting form) that fires the payload automatically in any other user's browser, on a page an authenticated victim visits. Then it is ordinary reflected XSS and this rejection rule is wrong. Equally, if the 'pasting' step is not required because the value is stored and later rendered to other users, the finding is stored XSS, not self-XSS."
    },
    {
      "key": "xss.fp_rule.html_encoding.entity_encoded_reflection_cannot_break_context",
      "claim": "Reject a reflected XSS candidate when the reflected value appears in the response only as HTML entities or percent/unicode escapes that the browser decodes back to inert text in that context, because encoding is what makes the reflection non-exploitable.",
      "kind": "fp_rule",
      "disproof": "The rule is wrong if the encoding is applied for the wrong context - for example only HTML-entity-encoded output dropped inside a JavaScript string, a URL, a CSS value or an unquoted attribute, where &quot; and &#39; do not neutralise a quote delimiter and a ';alert(1)// payload still breaks the string. It is also wrong if the entity is decoded and re-serialised anywhere before rendering (a client-side read of .innerHTML followed by a re-write, or a client-side template that re-interprets the text as HTML), because then the inert text becomes live markup."
    },
    {
      "key": "xss.fp_rule.json_api.content_type_json_is_not_html_execution",
      "claim": "Reject a JSON API endpoint reported as XSS when the response Content-Type is application/json and no client-side code path inserts the reflected value into an HTML document.",
      "kind": "fp_rule",
      "disproof": "The rule is wrong if the same reflected value reaches an HTML-executing context through any code path: the API is called by a front end that assigns the response into innerHTML or a framework's raw-HTML binding, the endpoint is reachable at the same path with a text/html or JSONP callback content type, or the server renders the stored value into an HTML page for other users. Then the JSON body is only the delivery mechanism, and the finding is a genuine XSS located at the sink."
    },
    {
      "key": "xss.test.entrypoints.unique_alnum_marker_sweep",
      "claim": "A short unique alphanumeric marker echoed verbatim in the response, from every request-controlled entry point tested one at a time, is the pass condition that proves reflection exists before any payload is chosen.",
      "kind": "test",
      "disproof": "The procedure is wrong if the marker reflects yet no XSS is reachable - that is a real possibility the method cannot detect: the reflection may sit inside a comment, inside an HTML entity-encoded attribute the app later re-decodes and re-renders on another page, or inside a JSON field that a second script writes into innerHTML on a different route. It is also wrong if the 'static string' control is insufficient, because an app that echoes a per-session value (a CSRF token built from your marker, a request-id cache) will pass step 4 and still tell you nothing about general reflection."
    }
  ],
  "publishers_already_cited": [
    "cheatsheetseries.owasp.org",
    "cwe.mitre.org",
    "developer.mozilla.org",
    "guides.rubyonrails.org",
    "html.spec.whatwg.org",
    "jorianwoltjer.com",
    "kathan19.gitbook.io",
    "oreobiscuit.gitbook.io",
    "owasp.org",
    "portswigger.net",
    "raw.githubusercontent.com",
    "sonarsource.com"
  ]
}

## Your task
State THREE claims about xss. For each:
- `claim`     — ONE falsifiable sentence naming a MECHANISM, >= 40 chars.
- `mechanism` — why it is true at the mechanism level, >= 120 chars.
- `disproof`  — the exact condition that would make it FALSE.
- `confidence`- high | medium | low
- `novelty`   — state plainly whether the corpus ALREADY covers this
                (say which item_key) or whether it is NEW.

Pick at least ONE claim you believe the others will dispute. Flag it with
`DISPUTE:` and say what the opposing view would be.

Rank your claims by how confident you are. If you are unsure, say so — an
honest "medium" is worth more than a confident invention.

## OUTPUT FORMAT — read carefully, this has broken three rounds
**Do NOT write any file.** Do not create claims.json or anything else. Writing
outside the project directory is auto-rejected by permission on this host, and
an earlier attempt died on exactly that (`Write /tmp/claims.json failed`).

Instead, print your claims **inline in your reply**, like this:

CLAIM 1
claim: <one falsifiable sentence, >= 40 chars>
mechanism: <why it is true, >= 120 chars>
disproof: <the exact condition that would make it FALSE>
confidence: high | medium | low
novelty: NEW | or the item_key in the corpus that already covers this
DISPUTE: <only on the claim you think others will attack; say what the opposing
view would be>

CLAIM 2
...

Repeat the block for each claim. Plain text only — no JSON, no files.
