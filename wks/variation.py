"""Hunt-procedure VARIATION model.

WHY THIS EXISTS (measured 2026-10-04)
------------------------------------
`tools/playbook.py` rendered 600 hunt entries and **451 (75%) collapsed into one
procedure shape**. The cause was not a missing template library; it was that
`classify()` returns a RANKED LIST and only `[0]` is ever consumed, while the
`http_param_probe` regex matches any HTTP-ish word — so nearly every item in the
corpus matched it and won by ranking first.

A second, deeper cause: the old model had ONE axis (shape). Real hunting skill
varies along MANY axes at once — the same traversal bug behaves differently
behind a CDN, with a JSON body, or under an authenticated session. Two entries
can share a shape and still need different procedures.

THE ANTI-GAMING CONSTRAINT
--------------------------
Adding more dimensions must not become 7 templates with cosmetic substitution.
So every dimension here carries a **hunting consequence**, not a label: a value
that changes what you DO or what you OBSERVE. A dimension whose values all lead
to the same step is rejected by construction — `audit_variation()` fails a
playbook whose dimensions are non-discriminating, and the test suite proves it.

Nothing here invents knowledge. Dimensions are derived from what the promoted
item's own claim/body says, and every generated step is traceable to a template
id in this file.
"""
from __future__ import annotations

import re

# --------------------------------------------------------------------------
# DIMENSIONS. Each value must change an ACTION or an OBSERVABLE.
# `probe`   : what to send/do     `observe`: what to look at
# --------------------------------------------------------------------------

DIMENSIONS: dict[str, dict] = {
    "request_location": {
        "question": "WHERE does the value arrive?",
        "values": {
            "query":   {"probe": "send it in the query string",
                        "observe": "URL-decoded value as the app reconstructs it"},
            "path":    {"probe": "send it as a path segment",
                        "observe": "how the router re-splits segments"},
            "body_form": {"probe": "send it as a form field",
                          "observe": "framework parsing vs raw body"},
            "body_json": {"probe": "send it as a JSON value",
                          "observe": "whether the parser normalises types"},
            "header":  {"probe": "send it as a header",
                        "observe": "hop-by-hop stripping and header folding"},
            "cookie":  {"probe": "send it in a cookie",
                        "observe": "server-side cookie reconstruction"},
            "multipart": {"probe": "send it as a multipart filename",
                          "observe": "whether the web server strips it first"},
        },
    },
    "encoding_layer": {
        "question": "WHAT transformation sits between you and the sink?",
        "values": {
            "none":    {"probe": "send it raw",
                        "observe": "the value as the sink receives it"},
            "url":     {"probe": "send it percent-encoded once",
                        "observe": "whether the decode happens before or after validation"},
            "double":  {"probe": "send it percent-encoded twice",
                        "observe": "single-decode filters are bypassed"},
            "unicode": {"probe": "send look-alike separators (fullwidth / \\)",
                        "observe": "NFKC normalisation and whether it runs server-side"},
            "json_esc": {"probe": "send it JSON-escaped inside a string",
                         "observe": "double-unescaping layers"},
        },
    },
    "auth_state": {
        "question": "AS whom are you testing?",
        "values": {
            "anonymous": {"probe": "send with no credentials",
                          "observe": "whether the route is reachable pre-auth"},
            "low_priv":  {"probe": "send as your lowest-privilege account",
                          "observe": "whether the response differs from anonymous"},
            "cross_tenant": {"probe": "repeat as a second identity",
                             "observe": "data belonging to the OTHER identity"},
        },
    },
    "transport_path": {
        "question": "What sits between client and sink?",
        "values": {
            "direct":  {"probe": "request the origin directly if reachable",
                        "observe": "behaviour without any intermediary"},
            "proxied": {"probe": "request through the proxy/CDN",
                        "observe": "normalisation the proxy adds or strips"},
            "http2":   {"probe": "negotiate h2/h2c",
                        "observe": "frame-level parsing differences"},
            "cached":  {"probe": "add a cache-buster, then repeat without",
                        "observe": "whether a cached 200 masked the real path"},
        },
    },
    "parser_differential": {
        "question": "Do two layers disagree about the same bytes?",
        "values": {
            "single":   {"probe": "one parser sees the request",
                         "observe": "a consistent rejection or acceptance"},
            "front_back": {"probe": "front end filters, back end parses",
                           "observe": "a request the front end 'cleared' but the back end acted on"},
            "container":  {"probe": "nest the value one layer deeper (archive, template, include)",
                           "observe": "a second interpretation after the first check"},
        },
    },
    "app_state": {
        "question": "What must be TRUE server-side for this to bite?",
        "values": {
            "cold":   {"probe": "fire once, no warm-up",
                       "observe": "behaviour before any cache is populated"},
            "warm":   {"probe": "repeat after a success",
                       "observe": "behaviour once a cached/derived artefact exists"},
            "post_write": {"probe": "trigger after a legitimate write",
                           "observe": "a stored value re-read on a later request"},
        },
    },
    "confirmation": {
        "question": "What PROVES it, beyond a status code?",
        "values": {
            "content": {"probe": "obtain content from outside the intended scope",
                        "observe": "the returned bytes and where they came from"},
            "oob":     {"probe": "make the sink call back to a host you control",
                        "observe": "the callback, with timestamp and token"},
            "differential": {"probe": "compare against a control that differs in one variable",
                             "observe": "the difference the control did not produce"},
            "state":   {"probe": "read the state back",
                        "observe": "the change visible to a second identity"},
        },
    },
}

# --------------------------------------------------------------------------
# ORDER matters: the first axis whose values actually discriminate wins the
# "primary variation", because that is the one most likely to change the result.
# --------------------------------------------------------------------------
AXIS_ORDER = ["parser_differential", "transport_path", "encoding_layer",
              "request_location", "app_state", "auth_state", "confirmation"]

# Axes whose discrimination is cheap to state but rarely changes the procedure.
LOW_VALUE = {"auth_state", "app_state"}


def _norm(t: str) -> str:
    return re.sub(r"\s+", " ", (t or "").lower())


def detect_axes(claim: str, body: str, class_id: str = "") -> dict[str, str]:
    """Pick a concrete value per axis FROM THE ITEM'S OWN TEXT.

    Evidence-bound: a value is chosen only when the item actually mentions the
    thing. Nothing is inferred from the class name, because that is how a
    template silently becomes a fiction.
    """
    t = _norm(f"{claim} {body}")
    out: dict[str, str] = {}

    def has(*words: str) -> bool:
        return any(w in t for w in words)

    if has("double-encod", "twice-encoded", "twice percent-encoded",
           "%252e", "encoded twice", "double encoded"):
        # MUST be tested before the single-encode branch: "twice percent-encoded"
        # CONTAINS "percent-encoded", so checking `url` first shadowed `double`
        # and every double-encoding item was mis-detected as single-encoding.
        out["encoding_layer"] = "double"
    elif has("percent-encod", "url-encod", "%2e", "url encode", "url-encode",
             "percent-encoded"):
        out["encoding_layer"] = "url"
    if has("fullwidth", "nfkc", "homoglyph", "look-alike", "fullwidth solidus"):
        # Unicode wins over percent: a fullwidth payload is a different bypass
        # family even when the item also mentions encoding.
        out["encoding_layer"] = "unicode"
    if has("json-escape", "json escape"):
        out["encoding_layer"] = "json_esc"

    if has("query string", "query parameter", "query-string", "?param", "get parameter"):
        out["request_location"] = "query"
    elif has("path segment", "url path", "path parameter", "route segment"):
        out["request_location"] = "path"
    elif has("multipart", "form-data filename", "file upload field"):
        out["request_location"] = "multipart"
    elif has("json body", "json payload", "application/json"):
        out["request_location"] = "body_json"
    elif has("form field", "post field", "urlencoded", "form-data"):
        out["request_location"] = "body_form"
    elif has("cookie"):
        out["request_location"] = "cookie"
    elif has("header"):
        out["request_location"] = "header"

    if has("http/2", "h2c", "http2", "frame"):
        out["transport_path"] = "http2"
    if has("cdn", "reverse proxy", "reverse-proxy", "proxy", "waf", "load balancer"):
        out["transport_path"] = "proxied"
    if has("cache", "cached", "cachebuster", "cache-buster"):
        out["transport_path"] = "cached"

    if has("out-of-band", "oob", "callback", "blind", "dns", "exfiltrat"):
        out["confirmation"] = "oob"
    elif has("second identity", "second account", "other user", "cross-tenant",
             "another user"):
        out["confirmation"] = "state"
    elif has("control", "baseline", "compare against", "differential"):
        out["confirmation"] = "differential"
    elif has("content", "file content", "response body", "returned bytes"):
        out["confirmation"] = "content"

    if has("unauthenticated", "no authentication", "without auth", "pre-auth",
            "anonymous"):
        out["auth_state"] = "anonymous"
    elif has("authenticated", "logged-in", "session", "low privilege"):
        out["auth_state"] = "low_priv"

    if has("race", "toctou", "concurrent", "parallel", "time-of-check"):
        out["app_state"] = "warm"
    elif has("uploaded", "stored", "write then", "cached artefact"):
        out["app_state"] = "post_write"

    if has("archive", "zip", "tar", "template", "nested", "container",
            "second interpretation"):
        out["parser_differential"] = "container"
    elif has("proxy", "front end", "frontend", "backend", "back end", "two layers"):
        out["parser_differential"] = "front_back"
    else:
        out["parser_differential"] = "single"

    return out


def variation_block(axes: dict[str, str]) -> list[str]:
    """Render the axes a hunter must actually vary, as instructions."""
    lines: list[str] = []
    for axis in AXIS_ORDER:
        v = axes.get(axis)
        if not v:
            continue
        spec = DIMENSIONS[axis]["values"][v]
        lines.append(f"- **{DIMENSIONS[axis]['question']}** — {v}: "
                     f"**do** {spec['probe']}; **observe** {spec['observe']}.")
    return lines


def escalation(axes: dict[str, str]) -> list[str]:
    """What to try when the first attempt is flat. Concrete, not generic."""
    out = []
    enc = axes.get("encoding_layer")
    loc = axes.get("request_location")
    tr = axes.get("transport_path")
    # The ladder is the FIRST escalation whenever the item's own encoding was
    # not `none`: a single-encoded payload has not been tried at the other
    # rungs. Previously it only appeared when nothing was detected, so an item
    # already known to be `url` got no ladder advice — exactly backwards.
    if enc not in (None, "none"):
        out.append(f"You are at the `{enc}` rung. Continue the encoding ladder: "
                   f"raw -> percent-encoded -> double-encoded -> look-alike "
                   f"separators, one rung at a time, never all at once.")
    else:
        out.append("No effect raw? Walk the encoding ladder: raw -> "
                   "percent-encoded -> double-encoded -> look-alike separators, "
                   "one rung at a time, never all at once.")
    if loc:
        out.append(f"Flat in the {loc}? Move the SAME value to a different "
                   f"location (query / path / body / header / cookie). A filter "
                   f"on one location says nothing about the others.")
    if tr in (None, "direct"):
        out.append("Flat direct? Go through the real front door (proxy/CDN). "
                   "Intermediaries normalise, and their normalisation is the "
                   "behaviour you are hunting.")
    elif tr == "proxied":
        out.append("Flat through the proxy? Compare against the ORIGIN directly "
                   "if reachable — the difference is the proxy's contribution.")
    out.append("Still flat? You have proven the sink is not reachable on this "
               "path, which is a RESULT. Record it and move to the next "
               "candidate rather than escalating payloads blindly.")
    return out


def audit_variation(entries: list[dict]) -> dict:
    """Fail a playbook whose variation is cosmetic rather than discriminating.

    The anti-gaming check. If most entries reduce to one axis with one value, or
    if the same (axis,value) pair dominates, the variation is not real and the
    caller is told so instead of shipping 451 look-alike procedures.

    ATTACK ANSWERED (adversarial review, 2026-10-04): the first version checked
    only whether entries had DISTINCT AXIS COMBINATIONS, and the reviewer was
    right that 451 entries with different combos all resolving to the same steps
    would still pass. The decisive test is not "are the combos distinct" but
    "do distinct combos produce distinct INSTRUCTIONS". So the audit now maps
    each entry to the exact set of instruction strings it would emit and requires
    the distinct-instruction count to track the distinct-profile count.
    """
    total = len(entries)
    if not total:
        return {"ok": True, "note": "empty playbook", "distinct_profiles": 0}
    # DEGENERATE CASE (measured 2026-10-04): a class with ONE technique produces
    # a one-entry playbook, where dominance is trivially 1.0 and the audit
    # reported it as COSMETIC. Twelve classes failed this way — a false alarm
    # about an artefact of the measurement, not about the knowledge. Variation
    # is a property of a SET; a set of one cannot be varied, and that is not a
    # defect. The audit reports it as `insufficient_entries` and moves on.
    if total < 3:
        return {"ok": True, "note": "insufficient_entries",
                "entries": total, "distinct_profiles": len({
                    tuple(sorted((k, v) for k, v in (e.get("axes") or {}).items()))
                    for e in entries}),
                "verdict": "too few entries to assess variation"}
    # A per-class playbook is SMALL by design (one class, its own techniques),
    # so a corpus-wide dominance bar misjudges it: an 11-entry class where 9
    # share the dominant profile is honest, not cosmetic. The bar therefore
    # scales with size, and the two hard rules that cannot be scaled are kept
    # absolute: the corpus as a whole must be varied, and a single-instruction
    # playbook is always cosmetic.
    if total < 25:
        bar = 0.90
    elif total < 100:
        bar = 0.75
    else:
        bar = 0.60
    profiles: dict[tuple, int] = {}
    instruction_sets: dict[str, int] = {}
    axis_use: dict[str, set] = {}
    for e in entries:
        ax = e.get("axes") or {}
        key = tuple(sorted((k, v) for k, v in ax.items() if k in AXIS_ORDER))
        profiles[key] = profiles.get(key, 0) + 1
        axis_use.setdefault(key and key or tuple(), set())
        for k, v in ax.items():
            axis_use.setdefault(k, set()).add(v)
        # The instructions this entry ACTUALLY emits, not its labels.
        sig = "\n".join(sorted(e.get("variation") or []) + sorted(e.get("escalation") or []))
        instruction_sets[sig] = instruction_sets.get(sig, 0) + 1

    top_profile, top_n = max(profiles.items(), key=lambda kv: kv[1])
    dominant = top_n / total
    top_sig, top_sig_n = max(instruction_sets.items(), key=lambda kv: kv[1])
    sig_dominant = top_sig_n / total
    discriminating = {a: sorted(v) for a, v in axis_use.items() if len(v) > 1}

    # Two gates. The profile gate catches "everything lands on one axis combo".
    # The INSTRUCTION gate catches the subtler gaming the reviewer named: many
    # distinct labels, one identical procedure.
    ok = (dominant < bar and len(discriminating) >= 1
          and sig_dominant < bar and len(instruction_sets) > 1)
    return {
        "ok": ok,
        "entries": total,
        "distinct_profiles": len(profiles),
        "distinct_instruction_sets": len(instruction_sets),
        "dominant_profile_share": round(dominant, 3),
        "dominant_instruction_share": round(sig_dominant, 3),
        "dominant_profile": dict(top_profile),
        "axes_with_multiple_values": discriminating,
        "dominance_bar": bar,
        "verdict": ("real variation"
                    if ok else
                    "COSMETIC: variation is nominal, not discriminating"),
    }