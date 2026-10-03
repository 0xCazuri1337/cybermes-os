# Bug classes — the canonical vulnerability map

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
| Raw research output from a subagent | `learning/evidence/` |
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
side. `web/idor/knowledge/CLASS.md` is canonical for IDOR; `web/idor/topics/idor-bola.md`
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
| **JWT / Token Validation Failures** (CWE-347) | Present in `db/wks.db` as a registered class with 14 items, but the initial tree had no home for token-validation failures. Distinct from session management: the flaw is that a *stateless* token is trusted without verifying signature, algorithm or claims. | `web/jwt/knowledge/CLASS.md` |
| **OAuth 2.0 / OIDC Misconfiguration** (CWE-346) | Registered in the db with 14 gated items and one full attack chain, with no home in the initial tree. Distinct from authentication bypass: the credentials may be correct while the flow's validation is wrong. | `web/oauth/knowledge/CLASS.md` |
| **GraphQL-Specific Attack Surface** (CWE-1004) | The initial tree listed GraphQL *techniques* but had no page for the class-level flaw the db had 13 items on. A technique file is not a home for it. | `web/graphql/knowledge/CLASS.md` |
| **Prototype Pollution** (CWE-1321) | Server-side and client-side are separate entries because the reach differs — one yields code execution in the server process, the other reaches a browser gadget. Same weakness, two canonical homes by surface, cross-referenced. | `web/prototype_pollution/knowledge/CLASS.md`, `web/topics/client-side/client-side-prototype-pollution.md` |

### Resolved duplicates

The initial tree listed some concepts twice. Rule 9 requires one canonical home,
so the second occurrence became a pointer stub that carries a link and a
one-line reason, and no vulnerability content:

| Appeared twice | Canonical | Stub |
|---|---|---|
| `web/clickjacking/knowledge/CLASS.md` | `web/client-side/` | `web/miscellaneous/` |
| `web/open_redirect/knowledge/CLASS.md` | `web/client-side/` | `web/miscellaneous/` |
| `web/ssti/topics/ssti.md` and `web/ssti/knowledge/CLASS.md` | `web/ssti/knowledge/CLASS.md` | `web/ssti/topics/ssti.md` |
| `web/path_traversal/topics/lfi.md`, `web/path_traversal/topics/rfi.md`, `web/path_traversal/topics/arbitrary-file-read-write.md` | `web/path_traversal/knowledge/CLASS.md` | `web/file-security/` |
| `web/idor/knowledge/CLASS.md` and `web/idor/topics/idor-bola.md` | `web/idor/knowledge/CLASS.md` | `web/idor/topics/idor-bola.md` |

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
5. Content arrives only through gated research — see `learning/README.md`.
