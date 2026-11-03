"""The tree spec. Adding a class = adding a row here, nothing else.

`TREE` is read top to bottom. Each entry is (path, spec) where spec is either
  ("class",  name, cwe, owasp, one_line)      a canonical bug-class file
  ("stub",   name, canonical_path)            a pointer to a canonical file
  ("readme", body)                            a navigational README
  ("dir",    label)                            a directory needing no extra file

READMEs are navigational only: what the directory is, what belongs, what does
NOT belong, how children are organised, related classes, how to add. They state
no technical claim, so they need no evidence and cannot go stale in the way a
prose claim does.
"""
from __future__ import annotations

# Reusable README fragments -------------------------------------------------

R = {
    "bug-classes": """# Bug classes — the canonical vulnerability map

Every vulnerability class in this knowledge base has **exactly one canonical
page** here. This directory is the map; it is not a duplicate of anything else.

## What belongs here

One `.md` file per distinct vulnerability class, organised by the security
domain it lives in (`web/`, `api/`). Each file follows one schema — see
`tools/taxonomy/build_taxonomy.py` (`BUG_SECTIONS`) — and is either
rendered from gated evidence in `db/wks.db` or explicitly marked
`Not yet researched.` per section.

## What does NOT belong here

| Not here | Where it goes instead |
|---|---|
| How to hunt a class (ordered procedure) | `methodology/` |
| Attack *relationships* between classes | `attack-chains/` |
| A second copy of a class that exists elsewhere | a pointer stub — see `miscellaneous/` |
| Raw research output from a subagent | `knowledge/activity/evidence/` |
| Unverified claims | nowhere — they are rejected, not filed |

## How children are organised

```
web/     browser-and-server HTTP surfaces, grouped by the security boundary
         the flaw breaks: authentication, authorization, injection, xss,
         request-forgery, file-security, server-side, client-side,
         business-logic, miscellaneous
api/     the same boundaries seen through an API surface: rest, graphql,
         websocket, other
```

A class that spans both is **canonical once** and referenced from the other
side. `web/authorization/idor.md` is canonical for IDOR; `api/rest/idor-bola.md`
is a pointer that carries only the API-specific delta.

## The canonical-home rule

When a concept appears to belong in two places, it gets one home and a pointer.
The registry that decides this is `CLASS_HOME` in
`tools/taxonomy/build_taxonomy.py` — edit that map, not the files.

## Related

- `attack-chains/` — how these classes combine
- `methodology/` — the ordered hunt per domain
- `validation/` — what counts as proven

## Added beyond the initial taxonomy

Recorded per the completeness rule — a new class is only added after checking
that no existing class covers it, and the reason is written down here.

| Class | Why it was added | Canonical home |
|---|---|---|
| **JWT / Token Validation Failures** (CWE-347) | Present in `db/wks.db` as a registered class with 14 items, but the initial tree had no home for token-validation failures. Distinct from session management: the flaw is that a *stateless* token is trusted without verifying signature, algorithm or claims. | `web/authentication/jwt-token-validation.md` |
| **OAuth 2.0 / OIDC Misconfiguration** (CWE-346) | Registered in the db with 14 gated items and one full attack chain, with no home in the initial tree. Distinct from authentication bypass: the credentials may be correct while the flow's validation is wrong. | `web/authentication/oauth-oidc-misconfiguration.md` |
| **GraphQL-Specific Attack Surface** (CWE-1004) | The initial tree listed GraphQL *techniques* but had no page for the class-level flaw the db had 13 items on. A technique file is not a home for it. | `api/graphql/graphql-surface.md` |
| **Prototype Pollution** (CWE-1321) | Server-side and client-side are separate entries because the reach differs — one yields code execution in the server process, the other reaches a browser gadget. Same weakness, two canonical homes by surface, cross-referenced. | `web/server-side/prototype-pollution.md`, `web/client-side/client-side-prototype-pollution.md` |

### Resolved duplicates

The initial tree listed some concepts twice. Rule 9 requires one canonical home,
so the second occurrence became a pointer stub that carries a link and a
one-line reason, and no vulnerability content:

| Appeared twice | Canonical | Stub |
|---|---|---|
| `clickjacking.md` | `web/client-side/` | `web/miscellaneous/` |
| `open-redirect.md` | `web/client-side/` | `web/miscellaneous/` |
| `ssti.md` and `template-injection.md` | `web/injection/template-injection.md` | `web/server-side/ssti.md` |
| `lfi.md`, `rfi.md`, `arbitrary-file-read-write.md` | `web/file-security/path-traversal.md` | `web/file-security/` |
| `idor.md` and `idor-bola.md` | `web/authorization/idor.md` | `api/rest/idor-bola.md` |

LFI, RFI and arbitrary file read/write are the *impacts* of path traversal, not
distinct weaknesses. They are recorded as Variations of the canonical class.

## Adding a class

1. Check `CLASS_HOME` and the target directory first — the class may already
   exist under a different name (this is the most common duplicate).
2. Add the row to `TREE` in this file, with CWE and OWASP ids.
3. If it is a distinct weakness class not already covered, note *why* in the
   parent README's "Added beyond the initial taxonomy" section.
4. Run `python tools/taxonomy/build_taxonomy.py`. Never hand-write the
   skeleton; the schema is enforced by the generator.
5. Content arrives only through gated research — see `knowledge/activity/README.md`.
""",

    "web": """# Web security classes

Browser-and-server HTTP surfaces. Grouped by **the security boundary the flaw
breaks**, not by payload type — that grouping is what makes the map navigable
during a hunt.

## What belongs here

A class where the attacker and the victim share a browser-mediated HTTP
conversation: forms, cookies, sessions, rendered HTML, file uploads, state
transitions.

## What does NOT belong here

- API-only surfaces → `bug-classes/api/`
- Injection *payloads* → `methodology/injection-testing.md`
- Cross-class combinations → `attack-chains/`

## How children are organised

| Directory | The boundary broken |
|---|---|
| `authentication/` | proving **who you are** |
| `authorization/` | proving **what you may touch** |
| `injection/` | attacker data interpreted as a language |
| `xss/` | attacker data interpreted as a script |
| `request-forgery/` | the server making a request, or trusting its origin |
| `file-security/` | the filesystem boundary |
| `server-side/` | code execution and object graphs on the server |
| `client-side/` | browser state and navigation the server does not control |
| `business-logic/` | a correct step in the wrong order, or the wrong number |
| `miscellaneous/` | real classes with no better home — pointers only |

## Related

- Canonical classes referenced by the API side: `api/rest/` holds pointers here.
""",

    "api": """# API security classes

The same security boundaries as `web/`, observed through an API surface. The
API differs not in *what* is broken but in **where the decision is made**: one
universal resolver, one verb set, one schema.

## What belongs here

Classes whose detection depends on API mechanics — verb and content-type
handling, schema-driven resolution, batching, field-level authorisation.

## What does NOT belong here

A second copy of a web class. `api/rest/idor-bola.md` is a **pointer** to
`web/authorization/idor.md`, carrying only what is true of REST.

## How children are organised

| Directory | Why it is separate |
|---|---|
| `rest/` | verb + content-type are part of the authorization decision; mass assignment binds request JSON straight to a model |
| `graphql/` | authorisation must hold per *resolved field*, not per route; batching and aliases multiply one request |
| `websocket/` | the upgrade handshake carries auth once; messages after it do not re-authorise |
| `other/` | RPC and SOAP shapes that do not fit the above |

## Related

- Every API class links back to its canonical home under `web/`.
- `attack-chains/api-chains.md` for cross-surface API chains.
""",

    "chains": """# Attack chains

A chain is a **relationship between classes**: an initial weakness that makes a
later one reachable or severe. It is not a vulnerability and gets no bug-class
file.

## The families here

| File | Chains that |
|---|---|
| [authentication-chains.md](authentication-chains.md) | begin at identity — a failure to prove *who you are* becomes access |
| [authorization-chains.md](authorization-chains.md) | begin at an authorization decision — a refused object becomes the entry to something wider |
| [xss-chains.md](xss-chains.md) | begin with script execution in a victim's browser |
| [ssrf-chains.md](ssrf-chains.md) | begin with the server fetching a URL the attacker chose |
| [api-chains.md](api-chains.md) | sit on an API surface, where one missing check yields both a read and a write |
| [business-logic-chains.md](business-logic-chains.md) | turn a low-severity logic flaw into a priced outcome |
| [cross-class-chains.md](cross-class-chains.md) | cross domains — an injection yields a credential, which yields an object |

Per-chain evidence digests, rendered from the db one row at a time, live in
[`chains/`](../chains/); the narratives here are the canonical chain documents.

## What belongs here

Ordered sequences where each step is justified by *why* it is possible, and
every step references a bug class that already passed the evidence gate.

## What does NOT belong here

- A single vulnerability → `bug-classes/`
- An unproven sequence. A chain step on a missing or unpromoted item is a
  story, and a story in a knowledge base is worse than no chain.

## How children are organised

One file per chain family: authentication, authorization, xss, ssrf, api,
business-logic, and cross-class for chains that span domains.

## Related

- Each step names its class; each class links back here.
""",

    "methodology": """# Methodology

**How to approach** a class of problem. A procedure, not a payload list.

## What belongs here

Ordered hunts. Every step states what to do **and what would disprove the
hypothesis** — a test that cannot fail proves nothing.

## What does NOT belong here

- Vulnerability definitions → `bug-classes/`
- Payloads and evidence → `knowledge/activity/knowledge/`, `db/wks.db`
- Class→procedure mappings are generated: `derived/`

## How children are organised

`*-hunting.md` and `*-testing.md` files are entry points per domain.
`derived/` holds one generated page per registered competency.
`scripts/` holds the checkers that make the coverage claim falsifiable.

## Related

- `bug-classes/` — what each class *is*
- `validation/` — what counts as proven
""",

    "learning": """# Learning workspace

The **working area** of the learning loop. Nothing here is canonical knowledge
until it has passed the gate.

## What belongs here

| Directory | Holds |
|---|---|
| `goals/` | the active Goal, its measurable criteria, and current wave |
| `tasks/` | task briefs, one per delegated specialist, with status |
| `evidence/` | raw research output — staging only, never trusted |
| `knowledge/` | findings promoted after review |
| `gaps/` | what the last wave failed to close |

## What does NOT belong here

- Canonical class definitions → `bug-classes/`
- Anything promoted without `wks/ingest.py` verifying every quote against the
  live page

## The loop

```
goals/ → tasks/ → evidence/ → (gate) → db/wks.db → knowledge/ → gaps/ → goals/
```

## Related

- The gate: `validation/validation-gates.md`
- The orchestrator: skill `cyber-learning-orchestrator`
""",

    "validation": """# Validation

**What counts as proven.** Separate from methodology (how to hunt) and from
knowledge (what is true).

## What belongs here

The hard gates a finding must clear, the evidence a report needs, and the
false-positive rules that reject a hypothesis before it wastes a report slot.

## What does NOT belong here

- Per-class rejection rules → those live in `db/wks.db` (`fp_case`) and render
  into each class file's *Common False Positives*
- Severity scoring → `reporting/severity.md`

## How children are organised

- `validation-gates.md` — the four hard gates and their implementations
- `evidence-requirements.md` — what a report must carry
- `false-positives.md` — rejection discipline, including testing the checker

## Related

- `CONTROL/rules.md` — R1–R13, each with how it is checked
""",

    "reporting": """Turning a validated finding into a report a triager can act on.

## What belongs here

- [report-structure.md](report-structure.md) — the shape of a report
- [severity.md](severity.md) — how severity is assigned and justified

## What does NOT belong here

- Unvalidated findings. A report is written from gated knowledge only.
- Vulnerability knowledge → [`bug-classes/`](../bug-classes/README.md)
- How to hunt → [`methodology/`](../skills/web/methodology/)

## How children are organised

One file per concern. `REPORT_FORMAT.md` was the original short form; it has
been superseded by [report-structure.md](report-structure.md) and archived
outside the tree (2026-10-02 audit).

## Related

- [evidence-requirements.md](../validation/evidence-requirements.md) — what a
  report must carry before it is written
- [false-positives.md](../validation/false-positives.md) — what disqualifies one
""",
}

README_FOR = {
    "bug-classes/web/authentication": ("authentication", """# Authentication — proving *who you are*

## What this directory represents

Flaws in the credential-checking step itself: how a subject is established,
how that establishment is re-checked, and how it is recovered when lost.

## What belongs inside it

- Bypasses of the check: `authentication-bypass.md`
- The token lifecycle after authentication: `session-management.md`
- The second factor as an attack surface: `mfa-bypass.md`
- The weakest link — usually the recovery path: `account-recovery.md`
- Token *validation* failures: `jwt-token-validation.md`
- Federated-issuer configuration: `oauth-oidc-misconfiguration.md`

## What does NOT belong inside it

- *What you may touch* once authenticated → `../authorization/`
- Token theft via XSS → `../xss/`, chained in `../../attack-chains/authentication-chains.md`
- Identity provider internals → not in scope for a web/API taxonomy

## How children are organised

One file per mechanism, ordered by the stage of the login lifecycle it breaks.

## Related bug classes

`session-management.md` chains to every class in `../authorization/`; a session
that cannot be revoked turns any single authorization bug into a persistent one.

## How new entries should be added

Only for a mechanism distinct from those above. "Credential stuffing" is a
technique under `authentication-bypass.md`, not a new file. Add to
`TREE` in `tools/taxonomy/build_taxonomy.py` and regenerate.
"""),

    "bug-classes/web/authorization": ("authorization", """# Authorization — proving *what you may touch*

## What this directory represents

Flaws where the subject is correctly identified and the wrong decision is still
made about an object or a function.

## What belongs inside it

- Object-level: `idor.md` (**canonical for IDOR/BOLA**)
- Vertical: `privilege-escalation.md`
- Function-level: `function-level-authorization.md`
- The multi-tenant boundary: `tenant-isolation.md`

## What does NOT belong inside it

- Being the wrong user → `../authentication/`
- The same IDOR seen through GraphQL or REST → pointer stubs under `../../api/`
- Chaining an authorization bug into takeover → `../../attack-chains/authorization-chains.md`

## How children are organised

By the *granularity* of the decision that failed: object, function, role,
tenant. Each is a separate check in a separate place in the code.

## Related bug classes

`../injection/` (a session token read out of a page) and `../business-logic/`
(state transitions that skip an approval) both reach this directory.

## How new entries should be added

Check `idor.md` first — most "new" authorization classes are a granularity of
it. Only add a file when the missing check has no existing home.
"""),

    "bug-classes/web/injection": ("injection", """# Injection — attacker data interpreted as a language

## What this directory represents

One root cause with many interpreters: input that reaches a parser, evaluator or
command line without being constrained to data.

## What belongs inside it

`sql-injection.md`, `nosql-injection.md`, `command-injection.md`,
`template-injection.md` (**canonical for SSTI**), `ldap-injection.md`.

## What does NOT belong inside it

- Attacker data executed as script in a browser → `../xss/`
- Server-side template injection living at `../server-side/ssti.md` — that is a
  **pointer stub**; the canonical page is `template-injection.md`
- A payload list → `methodology/injection-testing.md`

## How children are organised

One file per **interpreter**, because the escape rules, the sinks and the
blind-detection technique differ per language even when the flaw is identical.

## Related bug classes

Injection that *reads* server-side network state → `../request-forgery/ssrf.md`.
Injection into an ORM expression is SQL injection; injection into a template
engine is template injection.

## How new entries should be added

By interpreter, not by product. "Log4Shell" is command-injection-shaped; it is
a `command-injection.md` variant, not a new class.
"""),

    "bug-classes/web/xss": ("xss", """# XSS — attacker data interpreted as script

## What this directory represents

Attacker-controlled data reaching an execution context in another user's
browser without neutralisation.

## What belongs inside it

`reflected-xss.md`, `stored-xss.md`,
`dom-xss.md`, `blind-xss.md`,
`mutation-xss.md`, `framework-xss.md`.

(These are the XSS sub-documents. Under the merged tree they live in the `xss`
bundle's `topics/`, not beside this README — the generator renders them there
from `SUBDOCS`, and `tools/fill_subdocs.py` fills them from gated db items.)

## What does NOT belong inside it

- Script execution on the *server* → `../server-side/`
- DOM clobbering and postMessage → `../client-side/` (they change behaviour,
  not parsing)
- XSS chained into session theft or CSRF-token exfiltration →
  `../../attack-chains/xss-chains.md` — **not** a new class

## How children are organised

By **how the payload arrives and where it lands**: reflected vs stored vs DOM
sink, plus the two variants that break naive filters (mutation) and naive
escaping (framework-specific contexts).

## Related bug classes

`../client-side/open-redirect.md` and `../request-forgery/csrf.md` are the two
standard chain partners.

## How new entries should be added

By sink and delivery. A new framework context is a section in
`framework-xss.md` unless it changes the detection method.
"""),

    "bug-classes/web/request-forgery": ("request-forgery", """# Request forgery — the server or the origin is misled

## What this directory represents

Flaws where a request the server makes, or a request's origin, is not what it
appears to be.

## What belongs inside it

`csrf.md`, `ssrf.md`, `request-smuggling.md`, `cache-poisoning.md`.

## What does NOT belong inside it

- The response being poisoned after the fact → `../xss/stored-xss.md`
- Desync exploited only as DoS → `request-smuggling.md` covers the class

## How children are organised

Grouped by **what is being forged**: the victim's intent (`csrf`), the
server's network position (`ssrf`), the request framing between hops
(`request-smuggling`), or the cache key (`cache-poisoning`).

## Related bug classes

`cache-poisoning.md` and `request-smuggling.md` are frequently the same
underlying framing disagreement; `ssrf.md` chains to cloud metadata access.

## How new entries should be added

Ask what is being forged. If the answer is "nothing, it is just malformed",
it is smuggling, not forgery.
"""),

    "bug-classes/web/file-security": ("file-security", """# File security — the filesystem boundary

## What this directory represents

Flaws where a path, a filename or an uploaded file crosses a boundary it was
not meant to cross.

## What belongs inside it

`file-upload.md` (**canonical**), `path-traversal.md` (**canonical for LFI,
RFI and arbitrary file read/write**).

`lfi.md`, `rfi.md` and `arbitrary-file-read-write.md` are **pointer stubs**:
they are path traversal differing only in what the server does with the file it
reached. Keeping them as separate classes would duplicate knowledge for no
navigational gain.

## What does NOT belong inside it

- Inclusion of a *remote* URL by the application itself → a variant of
  `path-traversal.md`
- Command execution via an uploaded file → `../server-side/rce.md`, chained
  from `file-upload.md`

## How children are organised

By the direction of the violation: **inbound** (a file the client sends) versus
**outbound** (a path the client steers). Upload and traversal are the two
directions.

## Related bug classes

`file-upload.md` chains to `../server-side/rce.md`;
`path-traversal.md` chains to `../../attack-chains/ssrf-chains.md` when the
reachable path is a URL.

## How new entries should be added

Only for a direction that is neither inbound nor outbound. LFI/RFI-style
variants belong in the `Variations` section of `path-traversal.md`.
"""),

    "bug-classes/web/server-side": ("server-side", """# Server-side — execution and object graphs on the server

## What this directory represents

Flaws whose consequence is reached inside the server process: code execution, or
an object graph whose type system invokes attacker-reachable behaviour.

## What belongs inside it

`rce.md`, `deserialization.md`, `prototype-pollution.md`.

## What does NOT belong inside it

- `ssti.md` — a **pointer stub**; the canonical page is
  `../injection/template-injection.md`, because SSTI is an interpreter
  injection, not a distinct weakness
- Prototype pollution in the *browser* → `../client-side/client-side-prototype-pollution.md`

## How children are organised

By what the attacker supplies: **code** (`rce.md`), a **serialised object
graph** (`deserialization.md`), or a **property write** that later resolves to
code (`prototype-pollution.md`).

## Related bug classes

`../injection/command-injection.md` is `rce.md` reached through input rather
than through a deserialiser; both are recorded, and the distinction is the
entry point, not the outcome.

## How new entries should be added

By the mechanism that yields execution. A new serialisation format is a section
in `deserialization.md`, not a new file.
"""),

    "bug-classes/web/client-side": ("client-side", """# Client-side — browser behaviour the server does not control

## What this directory represents

Flaws in state and navigation that live in the browser: what the page does with
data it already trusts, and where it is willing to send the user.

## What belongs inside it

`dom-clobbering.md`, `postmessage.md`, `clickjacking.md` (**canonical**),
`open-redirect.md` (**canonical**), `client-side-prototype-pollution.md`.

## What does NOT belong inside it

- `clickjacking.md` and `open-redirect.md` **also** appearing under
  `../miscellaneous/` — those are pointer stubs back to this directory
- Script injection into markup → `../xss/`
- CORS and cache-deception → `../miscellaneous/`

## How children are organised

By what the attacker manipulates: the **DOM namespace** (`dom-clobbering.md`),
the **message channel** (`postmessage.md`), the **rendered UI layer**
(`clickjacking.md`), the **navigation target** (`open-redirect.md`), or the
**object model** (`client-side-prototype-pollution.md`).

## Related bug classes

`../request-forgery/csrf.md` (the origin is assumed),
`../xss/` (code runs rather than state being confused).

## How new entries should be added

Ask what browser mechanism is abused. If the server response is wrong, it is not
client-side.
"""),

    "bug-classes/web/business-logic": ("business-logic", """# Business logic — correct steps, wrong order or wrong number

## What this directory represents

Every individual request is handled correctly. The flaw is in the sequence, the
invariant, or the arithmetic across requests.

## What belongs inside it

`workflow-bypass.md` (**canonical for the class**), `race-condition.md`,
`price-manipulation.md`, `payment-logic.md`, `coupon-abuse.md`,
`state-machine-flaws.md`.

## What does NOT belong inside it

- A missing authorisation check → `../authorization/` (the check is absent, not
  mis-sequenced)
- Payment gateway integration bugs owned by the processor

## How children are organised

`workflow-bypass.md` and `state-machine-flaws.md` are the general forms; the
rest are concrete, testable instances (price, payment, coupon). `race-condition.md`
is canonical for TOCTOU and is the one class here with a timing prerequisite.

## Related bug classes

Every chain in `../../attack-chains/business-logic-chains.md` starts here,
because business-logic findings are low-severity alone and severe when chained.

## How new entries should be added

Only for an invariant that is neither a state transition nor a numeric field.
A new discount type is a `coupon-abuse.md` variation.
"""),

    "bug-classes/web/miscellaneous": ("miscellaneous", """# Miscellaneous — real classes with no better home

## What this directory represents

Genuine vulnerability classes that do not belong to any domain directory above.
This is a small directory by design: it is a staging position, not a dumping
ground.

## What belongs inside it

`cors.md`, `cache-deception.md`, `information-disclosure.md` — and **pointer
stubs only** for classes that already have a canonical home:

- `clickjacking.md` → `../client-side/clickjacking.md`
- `open-redirect.md` → `../client-side/open-redirect.md`

## What does NOT belong inside it

A second copy of anything. If a class is listed here **and** has a canonical
home, the file here must be a stub that links. Duplicated vulnerability
knowledge is the specific failure this taxonomy is built to prevent.

## How children are organised

Canonical files and stubs are visually distinct: a stub contains only a
canonical-path line and a one-line reason.

## Related bug classes

`information-disclosure.md` is the sink most chains terminate in; see
`../authorization/idor.md` for the case where the disclosure is the finding.

## How new entries should be added

Only after checking all nine domain directories. Record here why no domain fit.
A class that fits a domain moves there and its stub is deleted.
"""),

    "bug-classes/api/rest": ("rest", """# REST APIs

## What this directory represents

Classes whose detection depends on REST mechanics: the verb, the content type,
and the binding of request JSON onto a model.

## What belongs inside it

Canonical API classes: `mass-assignment.md`, `parameter-pollution.md`,
`excessive-data-exposure.md`, `rate-limit.md`.

Pointer stubs carrying the REST-specific delta: `authentication.md`,
`authorization.md`, `idor-bola.md`, `business-logic.md`.

## What does NOT belong inside it

A full copy of a web class. `idor-bola.md` says: canonical home is
`../../web/authorization/idor.md`, and then only what is true of REST.

## How children are organised

Canonical API-native classes first, then pointers. `idor-bola.md` exists because
OWASP names BOLA separately — the *name* differs even when the *concept* does
not, and an agent searching "BOLA" must find the file.

## Related bug classes

`../../attack-chains/api-chains.md` for API-specific chains.

## How new entries should be added

Ask whether the class exists for web. If yes, add a pointer; if the REST
mechanic genuinely differs (verb override, content-type confusion), that delta
belongs in the pointer.
"""),

    "bug-classes/api/graphql": ("graphql", """# GraphQL

## What this directory represents

One endpoint, one schema, many resolvers. Authorization must hold per resolved
field rather than per route, and one request can carry many operations.

## What belongs inside it

`introspection.md`, `authorization.md`, `idor.md`, `batching.md`,
`alias-abuse.md`, `query-complexity.md`, `injection.md`.

`authorization.md`, `idor.md` and `injection.md` are **pointers** — the
canonical homes are `../../web/authorization/`, `../../web/injection/`.

## What does NOT belong inside it

- The general exposure problem → `../../knowledge/activity/knowledge/`
- Node-ID decoding as a technique → it is a `idor.md` variant here and a
  technique in the canonical class

## How children are organised

By what the schema lets you do that REST does not: enumerate it
(`introspection.md`), resolve more than the UI asked for (`authorization.md`,
`idor.md`), multiply one request (`batching.md`, `alias-abuse.md`), or make it
expensive (`query-complexity.md`).

## Related bug classes

`../../attack-chains/api-chains.md` — excessive exposure chains directly into
enumeration and mass assignment, because read and write share one missing check.

## How new entries should be added

Only for a capability inherent to the GraphQL surface. A REST-only flaw is not a
GraphQL class.
"""),

    "bug-classes/api/websocket": ("websocket", """# WebSocket

## What this directory represents

A connection that authenticates **once** at the upgrade handshake, then carries
messages that are never re-authorised.

## What belongs inside it

`authentication.md`, `authorization.md` (both **pointers** to
`../../web/authentication/` and `../../web/authorization/`),
`message-manipulation.md`.

## What does NOT belong inside it

Handshake and framing specifics that are transport, not vulnerability.

## How children are organised

By lifecycle position: the handshake (`authentication.md`, `authorization.md`)
versus the message stream (`message-manipulation.md`).

## Related bug classes

`../../attack-chains/authentication-chains.md` — a stolen or unvalidated
upgrade token chains to every message the socket accepts.

## How new entries should be added

Only for a capability unique to a persistent connection. Anything expressible
over plain HTTP is not a WebSocket class.
"""),

    "bug-classes/api/other": ("other", """# Other API shapes

## What this directory represents

RPC and SOAP surfaces that do not fit the REST/GraphQL/WebSocket mechanics.

## What belongs inside it

`grpc.md`, `soap.md`.

## What does NOT belong inside it

Anything that is REST-shaped with a different content type.

## How children are organised

One file per protocol shape, focusing on where the authorization decision is
made in that protocol.

## Related bug classes

The authorization and injection concepts are canonical under `../../web/`; these
files carry only the protocol-specific mechanics.

## How new entries should be added

When a protocol's *authorisation model* differs from REST's, not merely its
encoding.
"""),
}

# NETWORK navigational READMEs. Declared here so the tree shape lives in ONE
# place — the same reasoning that moved SUBDOCS out of two generators. They
# exist because R22 reported every one of the 25 NETWORK pages as an ORPHAN:
# nothing linked to them, so a 25-page branch was unreachable from the index.
# They state no technical claim, so they need no evidence and cannot go stale.
try:
    from network_readmes import NETWORK_README, SPEC_READMES
except Exception as _exc2:  # noqa: BLE001
    raise RuntimeError(
        f"NETWORK README bodies could not be imported: {_exc2!r}. Without them "
        f"the 25 NETWORK pages render as unreferenced orphans (R22) and the "
        f"branch is unreachable from the taxonomy index."
    ) from _exc2

README_FOR["bug-classes/network"] = ("Network security classes", NETWORK_README)
for _spec, _body in SPEC_READMES.items():
    README_FOR[f"bug-classes/network/{_spec}"] = (
        _spec.replace("-", " ").title(), _body)

STUBS = {
    "bug-classes/web/miscellaneous/clickjacking.md":
        ("Clickjacking", "../client-side/clickjacking.md",
         "Clickjacking is a client-side UI-redress flaw; it has one canonical home."),
    "bug-classes/web/miscellaneous/open-redirect.md":
        ("Open Redirect", "../client-side/open-redirect.md",
         "Open redirect is a client-side navigation flaw; it has one canonical home."),
    "bug-classes/web/server-side/ssti.md":
        ("Server-Side Template Injection", "../injection/template-injection.md",
         "SSTI is template injection. The canonical page is under `injection/` "
         "because the flaw is an interpreter injection, not a distinct weakness."),
    "bug-classes/web/file-security/lfi.md":
        ("Local File Inclusion", "path-traversal.md",
         "LFI is path traversal where the reached file is read. Recorded as a "
         "Variation of the canonical class, not as a duplicate."),
    "bug-classes/web/file-security/rfi.md":
        ("Remote File Inclusion", "path-traversal.md",
         "RFI is path traversal where the reached file is executed. Recorded as "
         "a Variation of the canonical class."),
    "bug-classes/web/file-security/arbitrary-file-read-write.md":
        ("Arbitrary File Read / Write", "path-traversal.md",
         "Arbitrary file read and write are the *impacts* of path traversal. "
         "Recorded as Variations of the canonical class."),
    "bug-classes/api/rest/idor-bola.md":
        ("IDOR / BOLA — REST view", "../../web/authorization/idor.md",
         "Canonical home: `web/authorization/idor.md`. OWASP names BOLA "
         "separately from IDOR, so this pointer exists to make the name "
         "searchable — but the knowledge is not duplicated here."),
    "bug-classes/api/rest/authentication.md":
        ("Authentication — REST view", "../../web/authentication/README.md",
         "Canonical home: `web/authentication/`. REST-specific delta: the "
         "credential travels in a header rather than a form, so leakage moves "
         "from logs and referrers to token storage and client-side script."),
    "bug-classes/api/rest/authorization.md":
        ("Authorization — REST view", "../../web/authorization/README.md",
         "Canonical home: `web/authorization/`. REST-specific delta: the verb "
         "and content type are part of the authorization decision, so method "
         "override and content-type swaps bypass gateway rules."),
    "bug-classes/api/rest/business-logic.md":
        ("Business Logic — REST view", "../../web/business-logic/README.md",
         "Canonical home: `web/business-logic/`. REST-specific delta: state "
         "transitions are reachable as any verb, so workflow bypass rarely "
         "needs a UI sequence."),
    "bug-classes/api/graphql/authorization.md":
        ("Authorization — GraphQL view", "../../web/authorization/README.md",
         "Canonical home: `web/authorization/`. GraphQL-specific delta: the "
         "check must hold per resolved field, not per route; a field the "
         "frontend never requests may still resolve."),
    "bug-classes/api/graphql/idor.md":
        ("IDOR — GraphQL view", "../../web/authorization/idor.md",
         "Canonical home: `web/authorization/idor.md`. GraphQL-specific delta: "
         "global node IDs are base64 and decode to type plus internal id, and "
         "`node`/`nodes` often exist unintentionally."),
    "bug-classes/api/graphql/injection.md":
        ("Injection — GraphQL view", "../../web/injection/README.md",
         "Canonical home: `web/injection/`. GraphQL-specific delta: arguments "
         "reach resolvers, ORM query builders and template renderers from one "
         "endpoint, so several interpreter classes share a single entry point."),
    "bug-classes/api/websocket/authentication.md":
        ("Authentication — WebSocket view", "../../web/authentication/README.md",
         "Canonical home: `web/authentication/`. WebSocket-specific delta: the "
         "handshake authenticates once; every message afterwards inherits that "
         "result without re-checking."),
    "bug-classes/api/websocket/authorization.md":
        ("Authorization — WebSocket view", "../../web/authorization/README.md",
         "Canonical home: `web/authorization/`. WebSocket-specific delta: "
         "per-message authorisation must be implemented explicitly because the "
         "transport does not re-evaluate it."),
}

# The class table: (path, title, cwe, owasp, one_line)
CLASSES = [
    # --- added from field evidence in E:/bugbounty ---------------------------
    # These three classes exist because a real engagement produced a rejection
    # rule with no home: an unpatchable platform, a throttle question, and an OTP
    # endpoint that looked like issuance without being it. taxonomy_write.py builds
    # its page list from THIS tuple list, so a class registered in the db without
    # an entry here gets no page and `wks.domains --check` reports it missing --
    # which is exactly what happened.
    ('web/configuration/eol-software.md', 'End-of-Life Platform', 'CWE-1104',
     'A06:2021',
     'A version past end of life receives no fixes, so every future vulnerability '
     'on that line is standing risk on a reachable surface.'),
    ('web/authentication/rate-limit.md', 'Rate Limiting', 'CWE-770',
     'A04:2021',
     'A security-relevant operation is not throttled, and the operation is '
     'reachable in a way that makes the absence meaningful.'),
    ('web/authentication/otp.md', 'One-Time Password', 'CWE-287',
     'A07:2021',
     'One-time-password issuance and verification, where the common trap is an '
     'endpoint that answers every request or returns a token that never varies.'),


    # ---- classes registered by wks/taxonomy_ext.py ---------------------
    # Added to the tree so the gated items these classes hold are visible;
    # R15 reports ORPHANED EVIDENCE when the db has items and the tree has
    # no page for them.
    ("web/authentication/authentication-failures.md", "Authentication Failures", "CWE-287", "A07:2021",
     "The mechanism that establishes identity can be bypassed, reused, or subverted end to end."),
    ("web/injection/xml-external-entity.md", "XML External Entity Injection", "CWE-611", "A05:2021",
     "An XML parser resolves external or entity-expanded content the attacker controls."),
    ("web/client-side/clickjacking.md", "Clickjacking / UI Redressing", "CWE-1021", "A05:2021",
     "A foreign page can frame and overlay the target so the user's click means something unintended."),
    ("web/request-forgery/host-header-injection.md", "Host Header Injection", "CWE-644", "A05:2021",
     "The server builds a security-relevant URL or decision from a caller-controlled Host header."),
    ("web/injection/crlf-header-injection.md", "CRLF / Header Injection", "CWE-93", "A03:2021",
     "User input reaches a header or line boundary the protocol treats as a delimiter."),
    ("web/websocket/websocket-weaknesses.md", "WebSocket Weaknesses", "CWE-1004", "A04:2021",
     "The persistent channel inherits origin, authorisation and message-validation weaknesses of its upgrade request."),
    ("web/configuration/security-misconfiguration.md", "Security Misconfiguration", "CWE-16", "A05:2021",
     "A deployable default or an absent control leaves a capability the design assumed was closed."),
    ("web/supply-chain/dependency-supply-chain.md", "Dependency / Supply-Chain Risk", "CWE-1104", "A06:2021",
     "Trust placed in a component, its registry or its build exceeds what was verified."),
    ("web/infrastructure/subdomain-takeover.md", "Subdomain Takeover", "CWE-404", "A10:2021",
     "A DNS record still points at a de-provisioned service anyone can now claim."),
    ("api/api-to-api/api-to-api-trust.md", "API-to-API Trust Failures", "CWE-918", "API8:2023",
     "A backend assumes its caller is trusted because the caller is internal, and the boundary is never enforced."),
    ("web/authentication/authentication-bypass.md", "Authentication Bypass", "CWE-287", "A07:2021",
     "The credential check is skipped, misordered, or satisfiable without the credential."),
    ("web/authentication/session-management.md", "Session Management Flaws", "CWE-384", "A07:2021",
     "The established session can be fixed, hijacked, or never invalidated."),
    ("web/authentication/mfa-bypass.md", "Multi-Factor Authentication Bypass", "CWE-308", "A07:2021",
     "The second factor is satisfied without possessing it."),
    ("web/authentication/account-recovery.md", "Account Recovery Flaws", "CWE-640", "A07:2021",
     "The reset path is weaker than the login path it replaces."),

    ("web/authentication/jwt-token-validation.md", "JWT / Token Validation Failures", "CWE-347", "API8:2023",
     "The application makes an authorization decision without verifying the token's signature, algorithm or claims."),
    ("web/authentication/oauth-oidc-misconfiguration.md", "OAuth 2.0 / OIDC Misconfiguration", "CWE-346", "API8:2023",
     "The authorization server or client accepts a redirect, scope, token audience or PKCE flow it should reject."),

    ("web/authorization/idor.md", "Insecure Direct Object Reference (IDOR) / BOLA", "CWE-639", "API1:2023",
     "A server fails to verify the caller is entitled to the specific object the request names."),
    ("web/authorization/privilege-escalation.md", "Privilege Escalation", "CWE-269", "A01:2021",
     "A low-privilege subject reaches an administrative capability."),
    ("web/authorization/function-level-authorization.md", "Missing Function-Level Authorization", "CWE-862", "API5:2023",
     "An endpoint checks that a caller is authenticated but not that they hold the required role."),
    ("web/authorization/tenant-isolation.md", "Tenant Isolation Failure", "CWE-1220", "—",
     "Data crosses an organisation boundary that the model is supposed to enforce."),

    ("web/injection/sql-injection.md", "SQL Injection", "CWE-89", "A03:2021",
     "Attacker-controlled input is concatenated into a SQL statement."),
    ("web/injection/nosql-injection.md", "NoSQL Injection", "CWE-943", "A03:2021",
     "Attacker-controlled input changes the structure of a NoSQL query rather than its values."),
    ("web/injection/command-injection.md", "Command Injection", "CWE-78", "A03:2021",
     "Attacker-controlled input reaches a shell or process command line."),
    ("web/injection/template-injection.md", "Server-Side Template Injection (SSTI)", "CWE-1336", "A03:2021",
     "Untrusted input is compiled by a template engine rather than treated as data."),
    ("web/injection/ldap-injection.md", "LDAP Injection", "CWE-90", "A03:2021",
     "Attacker-controlled input changes the structure of an LDAP filter or distinguished name."),

    ("web/xss/xss.md", "Cross-Site Scripting", "CWE-79", "A03:2021",
     "Attacker-controlled data reaches a script execution context in another user's browser without neutralisation. The class-level page; the delivery and sink variants are its siblings."),

    # NOTE: the six XSS delivery/sink variants (reflected, stored, dom, blind,
    # mutation, framework) are deliberately NOT rows here. They are declared in
    # SUBDOCS below and rendered by `tools/fill_subdocs.py` from the gated
    # corpus. Listing them in BOTH made `taxonomy_write.py` overwrite
    # evidence-backed sub-documents with "Not yet researched." skeletons on
    # every run — the spec claimed 57 canonical classes while only 51 ever
    # were. One path, one owning generator.

    ("web/request-forgery/csrf.md", "Cross-Site Request Forgery", "CWE-352", "A01:2021",
     "A state-changing request is accepted from another origin without proof of intent."),
    ("web/request-forgery/ssrf.md", "Server-Side Request Forgery", "CWE-918", "A10:2021",
     "The server fetches an attacker-influenced URL, crossing into networks the attacker cannot reach."),
    ("web/request-forgery/request-smuggling.md", "HTTP Request Smuggling", "CWE-444", "A01:2021",
     "Two HTTP implementations disagree about where one request ends and the next begins."),
    ("web/request-forgery/cache-poisoning.md", "Web Cache Poisoning", "CWE-444", "A01:2021",
     "An unkeyed request component changes which response a cache stores and serves."),

    ("web/file-security/file-upload.md", "Unrestricted File Upload", "CWE-434", "A04:2021",
     "A client-supplied file is stored and later served or executed."),
    ("web/file-security/path-traversal.md", "Path Traversal / File Inclusion", "CWE-22", "A01:2021",
     "A path built from user input escapes its intended directory."),

    ("web/server-side/rce.md", "Remote Code Execution", "CWE-94", "A03:2021",
     "Attacker input is evaluated as code inside the server process."),
    ("web/server-side/deserialization.md", "Insecure Deserialization", "CWE-502", "A08:2021",
     "Data is reconstructed into a live object graph whose type system invokes attacker-reachable behaviour."),
    ("web/server-side/prototype-pollution.md", "Prototype Pollution (Server-Side)", "CWE-1321", "A08:2021",
     "Attacker input writes a property that later changes the behaviour of unrelated objects."),

    ("web/client-side/dom-clobbering.md", "DOM Clobbering", "CWE-1021", "A05:2021",
     "Attacker-controlled markup introduces named elements that scripts then read as configuration."),
    ("web/client-side/postmessage.md", "postMessage Misuse", "CWE-345", "A04:2021",
     "A message handler trusts its origin, its source, or its payload shape."),
    ("web/client-side/clickjacking.md", "Clickjacking", "CWE-1021", "A01:2021",
     "A UI redress attack induces a click on an element the user did not intend to activate."),
    ("web/client-side/open-redirect.md", "Open Redirect", "CWE-601", "A01:2021",
     "The application sends the user to an arbitrary attacker-chosen URL."),
    ("web/client-side/client-side-prototype-pollution.md", "Prototype Pollution (Client-Side)", "CWE-1321", "A08:2021",
     "A browser-side pollution reaches a gadget that turns it into script execution."),

    ("web/business-logic/workflow-bypass.md", "Workflow Bypass", "CWE-841", "A04:2021",
     "Each step is handled correctly in isolation and the sequence as a whole is not enforced."),
    ("web/business-logic/race-condition.md", "Race Condition / TOCTOU", "CWE-367", "A04:2021",
     "State is checked, acted on, then persisted non-atomically."),
    ("web/business-logic/price-manipulation.md", "Price Manipulation", "CWE-472", "A04:2021",
     "The client can influence the price the server accepts."),
    ("web/business-logic/payment-logic.md", "Payment Logic Flaws", "CWE-841", "A04:2021",
     "Payment state transitions can be reached out of order or repeated."),
    ("web/business-logic/coupon-abuse.md", "Coupon and Promotion Abuse", "CWE-840", "A04:2021",
     "A single-use entitlement can be applied more than once."),
    ("web/business-logic/state-machine-flaws.md", "State Machine Flaws", "CWE-691", "A04:2021",
     "A workflow state can be advanced or rewound outside its permitted transitions."),

    ("web/miscellaneous/cors.md", "CORS Misconfiguration", "CWE-942", "A05:2021",
     "The cross-origin policy grants a read to an origin that should not have it."),
    ("web/miscellaneous/cache-deception.md", "Web Cache Deception", "CWE-525", "A01:2021",
     "A cache serves a private response to a request for a public-looking path."),
    ("web/miscellaneous/information-disclosure.md", "Information Disclosure", "CWE-200", "A01:2021",
     "A response returns more than the requester is entitled to know."),

    ("api/rest/mass-assignment.md", "Mass Assignment", "CWE-915", "API3:2023",
     "The server binds client-supplied fields straight onto a model, including privilege fields."),
    ("api/rest/parameter-pollution.md", "HTTP Parameter Pollution", "CWE-235", "A01:2021",
     "Duplicate parameters are resolved differently by the framework and by upstream components."),
    ("api/rest/excessive-data-exposure.md", "Excessive Data Exposure", "CWE-213", "API3:2023",
     "A response returns fields the client never asked for and should not receive."),
    ("api/rest/rate-limit.md", "Rate Limit and Resource Consumption", "CWE-770", "API4:2023",
     "An endpoint can be driven to exhaustion or bypassed through an unenforced limit."),

    ("api/graphql/introspection.md", "GraphQL Introspection", "CWE-200", "—",
     "The schema is enumerable, turning an unknown surface into a mapped one."),
    ("api/graphql/graphql-surface.md", "GraphQL-Specific Attack Surface", "CWE-1004", "API8:2023",
     "One flexible endpoint replaces many REST routes, so authorization must hold per resolved object rather than per route."),
    ("api/graphql/batching.md", "GraphQL Batch and Alias Abuse", "CWE-400", "API4:2023",
     "One HTTP request carries many operations or aliases, multiplying the work and the identifiers."),
    ("api/graphql/alias-abuse.md", "GraphQL Alias Abuse", "CWE-400", "API4:2023",
     "Aliases let a single selection set fetch the same field many times under different names."),
    ("api/graphql/query-complexity.md", "GraphQL Query Complexity and DoS", "CWE-400", "API4:2023",
     "Nesting depth and field count are unbounded, so one query becomes expensive work."),
    ("api/websocket/message-manipulation.md", "WebSocket Message Manipulation", "CWE-345", "A04:2021",
     "A message is trusted for its shape or effect without re-authorising the sender."),

    ("api/other/grpc.md", "gRPC", "CWE-1004", "—",
     "A binary RPC surface where field presence and method selection carry the authorization decision."),
    ("api/other/soap.md", "SOAP", "CWE-1004", "—",
     "An XML RPC surface where the envelope and the operation are both attacker-reachable."),

    # ---- NETWORK domain -------------------------------------------------
    # GENERATED from `wks.network_taxonomy.NET_CLASSES`, not hand-written. The
    # 25 rows below therefore cannot drift from the seeded taxonomy: adding a
    # class there adds its page here. See `build_taxonomy.network_class_rows()`.
]

# The NETWORK half of the class table, appended after the literal block above so
# the WEB rows stay readable as a plain list. Both halves end up in one CLASSES
# because `taxonomy_write.py` consumes a single list — two class tables would
# mean two generators racing for the same tree, which is the duplicate-writer
# defect that once overwrote six evidence-backed XSS sub-documents.
try:
    import sys as _sys
    from pathlib import Path as _Path
    _sys.path.insert(0, str(_Path(__file__).resolve().parents[2]))
    from build_taxonomy import network_class_rows as _netrows
    CLASSES = CLASSES + list(_netrows())
except Exception as _exc:  # noqa: BLE001 - never let the spec fail to import
    # A silent empty NETWORK branch would render a domain that looks registered
    # in the db but has no pages — the "declared but missing" defect R15 exists
    # to catch. So the failure is loud.
    raise RuntimeError(
        f"network class rows could not be generated from "
        f"wks.network_taxonomy: {_exc!r}. The NETWORK branch of the tree will "
        f"not be written. Fix the import path rather than shipping an empty "
        f"domain."
    ) from _exc

CHAINS = [
    ("authentication-chains.md", "Authentication Chains",
     "Chains that begin at identity: a weakness in proving who you are becomes "
     "access to something that should require proof."),
    ("authorization-chains.md", "Authorization Chains",
     "Chains that begin at an authorization decision: an object that should have "
     "been refused becomes the entry to a wider capability."),
    ("xss-chains.md", "XSS Chains",
     "Chains that begin with script execution in a victim's browser and end with "
     "a session, an action, or data the attacker can read."),
    ("ssrf-chains.md", "SSRF Chains",
     "Chains that begin with the server making a request the attacker chose and "
     "end with internal network reach or a credential."),
    ("api-chains.md", "API Chains",
     "Chains specific to an API surface, where one missing check commonly yields "
     "both a read and a write."),
    ("business-logic-chains.md", "Business Logic Chains",
     "Chains that convert a low-severity logic flaw into a priced outcome by "
     "applying it to money, stock, or a control."),
    ("cross-class-chains.md", "Cross-Class Chains",
     "Chains whose steps belong to different domains — an injection that yields "
     "a credential which then yields an object."),
]

# --------------------------------------------------------------------------
# SUBDOCS — non-class documents that live BESIDE a canonical class page.
#
# WHY THIS EXISTS. `bug-classes/web/xss/` holds one canonical class page
# (`xss.md`) plus per-sub-type documents rendered from the same gated corpus by
# `tools/fill_subdocs.py`. Two generators wrote that directory with two
# different schemas and nothing recorded the arrangement, so:
#   * `audit_taxonomy.py` read a sub-doc's `## How it works` heading as a
#     class-page section, called `BUG_SECTIONS.index(...)` on it and CRASHED —
#     rule R14 was silently uncheckable for as long as the file existed;
#   * the arrangement was invisible, so the second generator looked like a
#     stray hand-edit (rule R11) rather than a declared part of the tree.
#
# Declaring them here puts the tree shape in ONE place, which is what
# `taxonomy_write.py` and `audit_taxonomy.py` both read. Adding a sub-doc is
# then a spec edit, and a sub-doc that is deleted becomes a visible finding
# instead of a file nobody notices is missing.
#
# A sub-document is NOT a class page: it carries no BUG_SECTIONS schema, is not
# a canonical home, and never owns a `bug_class` row.
SUBDOCS = {
    "bug-classes/web/xss": [
        "reflected-xss.md",
        "stored-xss.md",
        "dom-xss.md",
        "blind-xss.md",
        "mutation-xss.md",
        "framework-xss.md",
    ],
}