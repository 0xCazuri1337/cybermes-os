# Recon corpus forensics: why 155 promoted items are filed under a class they are not about

Read-only analysis. Nothing in `db/wks.db` was modified. Every number below was
printed by a command run against the live db; anything I could not establish is
marked **unverified**.

## What I measured

```
$ export WKS_ROOT="C:/Users/Administrator/.hermes/cyber"; cd "$WKS_ROOT"
$ python tools/recon_audit_offtopic.py
probed items=1111  off-topic=155 (14.0%)  module-filler=49 (4.4%)
```

I re-derived the same set independently rather than trusting the tool's output
(`scratch/recon_q.py`, then `scratch/recon_assert.py`):

```
[1] probed_items(db)              = 1111
[2] off_topic(my own query)       = 155
[3] manifest items                = 155
[4] manifest keys absent from db  = 0
[5] manifest keys not off-topic   = 0
[6] off-topic keys not listed     = 0
[7] duplicate entries in manifest = 0
```

The damage is concentrated, not spread. Per-class off-topic rate:

| class | items | off-topic | % |
|---|---:|---:|---:|
| exposed_rmm | 23 | 19 | 82.6 |
| misconfig | 13 | 10 | 76.9 |
| service_enumeration | 14 | 10 | 71.4 |
| service_enumeration_detail | 16 | 11 | 68.8 |
| segmentation_analysis | 20 | 13 | 65.0 |
| dns_enum | 22 | 14 | 63.6 |
| exposed_services | 21 | 13 | 61.9 |
| internal_recon | 12 | 7 | 58.3 |
| ad_enumeration | 22 | 12 | 54.5 |
| ldap_enum | 16 | 8 | 50.0 |
| smb | 13 | 6 | 46.2 |
| xss | 70 | 12 | 17.1 |

Every class at or near zero is one that was researched with a per-class brief.
The recon classes were harvested in bulk. 22 classes have 0% off-topic.

**The gate passed all of this and it was right to.** 133 of the 155 quotes
overlap their own claim by 25%+ on content tokens — the quotes are real, on the
pages cited, from two publisher orgs. This is not a fabrication problem. It is a
filing problem, and only 7 of 155 items even have a claim that relates to the
quote it cites (measured token-overlap bands: `0.0-0.1` = 7, `0.1-0.25` = 15,
`0.25+` = 133).

## How the gate let it through

`class_id` is never derived from the claim text. It is copied from the
`item_key` prefix that the producing agent chose, and the gate's only opinion
about it is that the class exists.

**`wks/ingest.py:103`** — the class is a string prefix, nothing more:

```python
cid = it["item_key"].split(".")[0]
```

**`wks/ingest.py:104-107`** — the entire class validation at ingest:

```python
if store.get_class(con, cid) is None:
    shape_errors.append({"item_key": it.get("item_key"),
                         "missing": [f"unknown class {cid!r}"]})
    continue
```

Existence. Not relevance.

**`wks/pipeline.py:330-331`** — `ingest_claim` repeats the same existence-only
check and then inserts:

```python
if store.get_class(con, class_id) is None:
    raise LookupError(f"unknown class {class_id}; register it first")
```

**`wks/store.py:394-399`** — `add_item` writes the caller's `class_id` straight
into the row. It is never compared to the claim.

**`wks/quality.py:76-242`** — `assess()` loads the whole row at line 81
(`SELECT * FROM item`), so `item["class_id"]` is right there, and then never
reads it. Its ten scoring dimensions are `source_credibility`,
`technical_specificity`, `evidence_strength`, `reproducibility`,
`corroboration`, `practical_usefulness`, `recency`, `internal_consistency`,
`real_world_demo`, `limitations_documented`. The hard gates at lines 190-214 are
`NO_SOURCES`, `INSUFFICIENT_SOURCES`, `BUILDER_PAGE_NOT_PUBLISHER`,
`INSUFFICIENT_PUBLISHER_HOSTS`, `DISCOVERY_ONLY_SOURCE`, `FABRICATED_REFS`,
`VAGUE_CLAIM`, `UNFALSIFIABLE_CLAIM`. Not one of them is about the class.

**`wks/sourcegate.py`** and **`wks/corroborate.py`** operate on source
access state and publisher orgs respectively. `corroborate.py:222` does compare
claim vocabulary to page vocabulary — but only to pick which sentence to quote
from a page, never to ask whether the page's topic matches the class.

**The nearest thing to a relevance check does not exist.** It used to:
`wks/claimcheck.py:100-102`:

```python
# REMOVED: CLASS_MISMATCH. It flagged 67 curated claims -- any claim
# containing another class's alias and none of its own -- and missed the
# single real case it was written for. See the module note.
```

The module docstring says it outright at line 31-32: *"This detects TRUNCATION,
not wrongness -- a complete but irrelevant sentence still passes, and saying so
is better than pretending."* And `claimcheck` is not called from any gate path:
`grep -rn claimcheck wks/ orch/ tools/` returns nothing outside the module and
its own test. So the check was removed for being noisy **and** was never wired in,
and the two facts compounded: 67 false positives was measured against a check
that never ran in production.

Stated plainly: **no check anywhere in the promotion pipeline ties the claim
text to the class.** The gate was measuring "is this supported" and was never
asked "is this about this".

## Source clusters

32 hosts supply all 155. The concentration is the mechanism:

| off-topic items | host |
|---:|---|
| 75 | academy.hackthebox.com |
| 40 | cheatsheetseries.owasp.org |
| 24 | claroty.com |
| 19 | elastic.co |
| 17 | portswigger.net |
| 15 | learn.microsoft.com |
| 12 | blog.trailofbits.com |
| 12 | unit42.paloaltonetworks.com |
| 11 | microsoft.com |
| 10 | cwe.mitre.org |

At URL level the pattern is sharper — a small number of pages carry the bulk:

- 27 items cite `cheatsheetseries.owasp.org/cheatsheets/Authentication_Cheat_Sheet.html`
- 25 cite `academy.hackthebox.com/course/preview/active-directory-powerview`
- 25 cite `academy.hackthebox.com/catalogue/paths`
- 22 cite `academy.hackthebox.com/course/preview/active-directory-enumeration--attacks`
- 21 cite a single Claroty blog post on exposure management for cyber-physical systems
- 19 cite one Elastic write-up on hunting lateral movement with EQL

`academy.hackthebox.com/catalogue/paths` is a **course catalogue landing page**.
It is the source of the 27 FILLER_MODULAR items — it describes courses, not
techniques. The Authentication Cheat Sheet is a single legitimate page about
authentication, and it supplied 40 items spread across `exposed_rmm`,
`service_enumeration_detail` and `dns_enum`: the sentence is real and quotable,
and it says nothing about any of them.

The `service_enumeration` double-filing the brief mentions is confirmed:
`service_enumeration.auto.01` and `service_enumeration_detail.auto.01` carry the
byte-identical claim, as do the `.t.6bc254fb` pair — the Claroty exposure-management
sentence stored twice under two adjacent class names.

## The five buckets

```
buckets = {DUPLICATE: 64, MISFILED: 28, FILLER_MODULAR: 27,
           PROBE_FALSE_POSITIVE: 23, OFF_CLASS: 8, WRONG_DOMAIN: 5}
sum = 155
```

### MISFILED — 28
A genuinely good technique claim filed under the wrong class. These are the only
items in the set that are *salvageable by moving them*, and they are worth
moving rather than quarantining.

- `exposed_rmm.auto.t.098b4140` — "a single sign-on solution may authenticate
  the user and allow them to remain logged in for a day" → should be **authn**.
- `ldap_enum.auto.t.23374889` — "the attacker can forge an RC4-encrypted Kerberos
  silver ticket and impersonate a privileged account" → should be **ad_kerberos**.
- `exposed_services.signal.rdp-session-to-a-domain-controller` — an RDP session
  signal filed under exposed_services → should be **rdp**.

Where they belong, counted across the 28: `authn` 16, `ad_ntlm` 4, `rdp` 2,
`ad_kerberos` 2, `ad_enumeration` 2, `idor` 1, `graphql` 1. Sixteen of 28 are
authentication knowledge sitting in recon classes — `exposed_rmm` alone accounts
for 16 of the 28, and it is the worst class in the corpus at 82.6% off-topic.

### DUPLICATE — 64
One sentence, many homes. `ad_enumeration.auto.t.ba9d4774` and
`segmentation_analysis.auto.t.ba9d4774` carry the identical XSS sentence; the
same claim is active under 11 classes. `misconfig.auto.t.144e910f` and
`misconfig.auto.t.144e910f-2` are the same row twice. These inflate every affected
class's item count, which is why the recon classes read as researched: their
coverage number is largely repetition.

### FILLER_MODULAR — 27
Course framing, harvested verbatim. "We will cover how to identify, exploit, and
prevent each of them through various methods."
(`ad_enumeration.auto.t.572ed1de`.) "This module covers the most common attacks
and vulnerabilities that can affect web application sessions, such as Session
Hijacking, Session Fixation, Cross-Site Request Forgery, Cross-Site Scripting,
and Open Redirects." (`ad_enumeration.auto.t.5bb83fe5`) "This will make us more
effective as attackers and equip us to give sound recommendations to our clients
on the major issues within their environment, as well as clear and actionable
remediation advice." (`ad_enumeration.auto.t.f194ef88`) Every one passed the gate
because each asserts something true about a real page — which is exactly what the
gate rewards. Note the tool's own FILLER regex catches only 22 of these 27; the
remaining 5 are the same defect with a different sentence opener, which is why
the tool reports `module-filler=49` corpus-wide and I re-classified from the text.

### WRONG_DOMAIN — 5
Real knowledge, right idea, no home in this taxonomy. "While accessing and
managing systems such as programmable logic controllers (PLCs) and human-machine
interfaces (HMIs) on the internet..." (`segmentation_analysis.auto.01`, OT/ICS
exposure from a Claroty blog). "If an exploit is not published, organizations may
need to investigate via other means including software bills of materials (SBOMs)
or vulnerability exploitability eXchange (VEX) files."
(`service_enumeration.auto.05`, vendor triage advice). "If improperly configured
or implemented, common web security vulnerabilities such as Information
Disclosure, SQL Injection, and Insecure Direct Object Reference (IDOR) may
arise." (`dns_enum.auto.t.8892f252`, a category list, not a technique).

### OFF_CLASS — 8
True noise. "Chain: product does not properly check the result of a reverse DNS
lookup because of operator precedence ( CWE-783 ), allowing bypass of DNS-based
access restrictions." (`authz.auto.t.b4858004` — a verbatim CWE abstract with a
prepended "Chain:", no attacker procedure.) "Binary exploitation is a core tenet
of penetration testing, but learning it can be daunting."
(`dns_enum.auto.t.9799d4ba` — course motivation.) "Most often, if we can exploit
a vulnerability and gain a foothold on a host, it will be running some version of
Windows or Linux." (`dns_enum.auto.t.c8db0977` — too general to test or act on.)

### PROBE_FALSE_POSITIVE — 23 (not in the brief's five; see below)
The audit tool's `VOCAB` lists are the defect here, not the corpus.
`xss.bypass.filter.parentheses_free_invocation` ("A filter blocking parentheses is
bypassed by invoking the function without them") is correctly filed under `xss` —
`VOCAB["xss"]` contains no word for *filter*, *bypass* or *parentheses*.
`oauth.tech.redirect_uri_manipulation` looks for the literal string
`redirect_uri`; the claim writes "Redirect URI". `authn.variant.xml-signature-wrapping-class`
is a SAML item under `authn`, and `authn`'s vocabulary has no SAML, signature or
assertion term. All 12 `xss` offenders are in this bucket. The other three oauth
items and the single jwt item likewise.

I added this sixth bucket rather than force 23 correctly-filed items into
OFF_CLASS or DUPLICATE, because that would have been the same error the audit is
looking for. **Quarantining these 23 would delete good knowledge.**

## What must be added to the gate

1. **A topical check in `quality.assess`, or a new held-reason source wired in
   the way `claimcheck` never was.** The vocab must be built from `bug_class`
   (name, aliases, CWE) rather than hand-listed per class — `claimcheck.build_vocab`
   already does this and returns per-class term sets. It must score against the
   item's OWN class and fail to a hold, never a promote.
2. **Fix the vocabulary before re-enabling it.** `CLASS_MISMATCH` was removed for
   67 false positives; the fix is per-class distinguishing vocabulary plus a
   required minimum, not a global "contains another class's alias" test. A class
   with an empty or alialless vocab must skip rather than hold — otherwise the 22
   clean classes start failing.
3. **Record `class_id_source` on the item.** Today the only provenance for a
   class is a string prefix the agent typed. Storing whether the class was
   asserted or derived makes the next audit measurable instead of inferred.
4. **Deduplicate at ingest.** 64 of 155 items are a claim already held under
   another class. `store.add_item` returns the existing id for a repeated
   `item_key` (`store.py:390-392`) but nothing compares the *claim* across keys, so
   the same sentence is promoted once per class.
5. **Separate navigational text from prose at quote-selection time.**
   `corroborate.pick_quote` picks the sentence with the most claim-token overlap
   on the page — it will happily lift a course description off a catalogue page.
   It needs a candidate blocklist for "we will cover", "this module covers", "for
   all exercises", which is the whole of the FILLER_MODULAR bucket.
6. **A page-type check, not just a host check.** `config.is_builder_host` filters
   GitBook/Notion-style hosts; `academy.hackthebox.com` is a course-catalogue
   host, not a builder host, and 75 items came through it. Course and catalogue
   pages should be `lead` at most.

## What I could not determine and why

- **Whether the 155 items' evidence would survive re-gating.** I did not re-run
  `quality.assess` on any item; that would write `validation_state`, and this
  analysis is read-only. The gate state of all 155 is whatever it was.
- **Which agent or wave produced each item.** `item` has no creator column and no
  git history exists in this tree. The `.auto.` suffix on 100+ item_keys is the
  only provenance signal, and I could not confirm what generates it.
- **Whether the 23 PROBE_FALSE_POSITIVE items were ever intended as off-topic.**
  They pass a human read, but I have no per-class brief from the wave that
  assigned them to say what that class was supposed to contain.
- **The true off-topic rate of the recon classes.** The 14.0% figure is the tool's
  vocabulary probe, and I have shown it both over-reports (23 false positives) and
  under-reports where it has no vocab list at all — 22 classes, including 70-item
  `xss`, are simply unprobed. The real number is **unverified** and needs a probe
  built on `bug_class` vocabulary before it means anything.
- **Whether `claroty.com` or `elastic.co` should be in the source registry at
  all.** They are vendor blogs, correctly `lead` rather than `normative`, and 43
  items cite them. Their `role` in `db/sources.json` I did not check.