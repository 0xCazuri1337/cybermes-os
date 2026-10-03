# WKS — Web & API Hunting Knowledge System

A research, curation and retrieval system for practical web/API security hunting
knowledge. It fetches published documentation, gates every claim on evidence,
and generates per-class hunting skills.

**It performs no active testing against any target.** There is deliberately no
scanning, fuzzing or exploitation code in `wks/`. `config.RESEARCH_ONLY` is
`True`. Active testing is a separate activity that requires explicit,
user-provided authorization.

---

## The tree

```
domains/                    THE organising boundary. One home per bug class.
  web/                      Browser- and API-mediated HTTP surfaces
    <class_id>/             a SELF-CONTAINED bug-class unit:
      knowledge/              CLASS.md   canonical map, 16-section schema (generated)
                              DIGEST.md  evidence digest from the db (generated)
      skills/                 SKILL.md + HISTORY.md — the hunting skill
      assessment/             COMPETENCY.md — what this class's evidence covers
      chains/  mastery/  labs/
    chains/                 in-domain chains spanning classes
    areas/  topics/         sub-topic pages owned by no single class
    methodology/            how to approach a web class (hand-authored)
  network/                  internal network + infrastructure
    active-directory/         AD specializations, one folder per class
    internal-network/
    infrastructure/
    chains/  methodology/
learning/         the learning loop: plans · tasks · sessions · proposals · gaps · progress
research/pending/ pre-gate material — subagent output, NOT knowledge
runtime/state/    execution state: cycle journals, verification caches
validation/       the gates, the evidence a report needs, FP discipline
reporting/        report structure and severity
tools/taxonomy/   the generator + spec that RENDER domains/ (never hand-edited)
db/wks.db         CANONICAL store — SQLite + FTS5, the only source of truth
quarantine/       material that could not be safely classified, including
                  `pre-domains-refactor-20261002/` (the pre-refactor tree)
```

**Active Directory is a specialization under `network`, not a third domain.**
Every AD attack path is reached through network access to a protocol, so
`domains.py` keeps AD under `NETWORK_SPECIALIZATIONS` and files it at
`domains/network/active-directory/<class_id>/`. This is a deliberate deviation
from a flat four-domain reading of the brief, and `eval/test_domains.py` (66
assertions) enforces it.

**`knowledge/CLASS.md` and `knowledge/DIGEST.md` are not duplicates.** The
class page is the canonical map; the digest is a machine-generated rendering of
the db rows behind it. The mapping between a db class id and its canonical page
is `CLASS_HOME` in `tools/taxonomy/build_taxonomy.py`, and it is the only place
that relationship is written down.

**Every path is owned by one function.** `wks/domains.py::class_rel` is the
single authority for where a class lives; the generator, the skill writer, the
digest writer and the chain writer all call it. A second spelling of a class
directory is a second answer, and the two eventually disagree — which is how
six evidence-backed sub-documents once got silently overwritten by skeletons.

**Nothing regenerates into a retired root.** `tools/audit_architecture.py`
fails if `bug-classes/`, `classes/`, `chains/`, `attack-chains/`, `state/` or a
flat `skills/*-hunting/` reappears, and `python tools/audit_architecture.py
--selftest` proves the checker can still fire.

## Taxonomy

The tree is **generated**, not hand-written — one structure (rule 5) and
extensibility without restructuring (rule 8) are only true if something checks
them:

```bash
python tools/taxonomy/taxonomy_write.py           # render from spec + db
python tools/taxonomy/taxonomy_write.py --check   # drift, exit 1
python tools/taxonomy/audit_taxonomy.py           # rule 9, exit 1 on findings
```

**One canonical home per class.** A concept that appears to belong in two places
gets one page and a pointer stub that carries a link and a reason — never a
second copy. `web/authorization/idor.md` is canonical for IDOR;
`api/rest/idor-bola.md` exists so the name "BOLA" is findable and points there.
LFI, RFI and arbitrary file read/write are Variations of `path-traversal.md`,
not separate classes. Resolved duplicates and classes added beyond the initial
taxonomy are recorded with their reasons in `bug-classes/README.md`.

## Quick start

```bash
cd ~/.hermes/cyber

python -m wks.cli selftest          # 33 assertions on the quality gate
python -m wks.cli seed              # register the 15-class taxonomy
python -m wks.cli verify-seeds      # every seed URL live, every class >= 2 hosts
python -m wks.cli gaps              # weakest classes first
python -m wks.cli search "coupon redemption" 
python -m wks.cli show idor         # full class digest as JSON
python -m wks.cli metrics           # 13 quality metrics
python -m wks.cli probe             # retrieval relevance probes
python -m wks.cli cycle             # one autonomous improvement cycle
python -m wks.cli overnight --cycles 6 --sleep 300
python -m wks.cli report            # last run summary
python -m wks.reconcile             # detect items orphaned by file revisions
```

Research intake and learning:

```bash
python -m wks.cli sources --list                    # research-source registry, by tier
python -m wks.cli sources --register               # register it into the source table
python -m wks.ingest research/incoming/idor.json   # verifies quotes, then gates
python -m wks.reconcile --apply      # supersede orphans after an agent rewrites a file
python -m wks.verify_quotes --file research/incoming/idor.json
python -m wks.fp log --class idor --hypothesis ... --test ... \
    --invalidated-by ... --rule ...                 # false-positive learning
python -m wks.fp list --class idor
python -m wks.cli audit-legacy                     # triage the old corpus
```

## Two source registries, and why they are not merged

| | `taxonomy._SEED` | `wks/research_sources.py` |
|---|---|---|
| role | **normative** — defines what a class *is* | **lead list** — technique, intel, tooling |
| typical entries | OWASP, PortSwigger, MITRE CWE, RFC | Medium writeups, community GitBooks, cvebase, tool repos |
| may satisfy the ≥2-host corroboration gate | yes | **no** (R20) |
| tier | T2 primary/normative | T3 practitioner · T4 CVE intel · T5 tooling |

Merging them would let two blog posts corroborate each other and promote a
claim with no normative backing — the precise failure this system exists to
prevent. Registry sources are registered so they can be **cited and
quote-verified**, never so they can define a class. Adding a normative source
still means editing `taxonomy._SEED`.

Registry entries carry a measured `access` tier, because "HTTP 200" is not
evidence that content arrived:

| access | meaning |
|---|---|
| `open` | plain fetch returns content |
| `json` | machine endpoint returns structured data (may be rate-limited) |
| `key` | free tier, but an API key is required |
| `js` | HTTP returns only a loader; needs a script (the 3 Notion pages) |
| `walled` | bot wall or paywall — **a 200 here is a lie** (HackerOne returns `browser-not-supported.html`) |

## Why it is built this way

The system this replaces promoted **1,380 knowledge items to `validated`**, of
which **1,378 had no usable source** and carried invented cross-references
(`Ref1`, `Ref2`). Measured over the quarantined corpus:

| defect | count |
|---|---|
| no source refs at all | 1,234 / 1,380 |
| content under 200 chars (truncated teaser) | 1,311 / 1,380 |
| fabricated cross-check references | 1,048 / 1,380 |
| title "RAG Test 0" / "CLI Validate Test" (test fixtures) | 641+ |
| substantial content AND a real citation | **0** |

So the design principle is: **a citation is not proof**, and a fluent, short,
confident-sounding claim must not be promotable by averaging. Every structural
decision below follows from that.

## Architecture

```
                      ┌────────────────────────────────────────┐
   delegated research │        wks/ingest.py                  │
   (subagents) ──────▶│  shape → LIVE quote check → gate      │
                      └───────────────┬────────────────────────┘
                                      │ only verified items enter
                                      ▼
   ┌──────────────────────────────────────────────────────────────┐
   │  db/wks.db   (canonical — SQLite + FTS5, no other store)    │
   │                                                              │
   │   source ──< item_source >── item ──< quality               │
   │                              │                               │
   │              bug_class ──────┤── chain_step >── chain       │
   │                                fp_case · task · conflict · run│
   └───────────┬──────────────────────────────┬───────────────────┘
               │ projections                  │ retrieval
               ▼                              ▼
   classes/*.md  chains/*.md            BM25 (FTS5) + trust prior
   skills/<id>-hunting/SKILL.md         + metadata filters
   skills/<id>-hunting/HISTORY.md       + chain expansion
```

The database is canonical. Everything else is a disposable projection that can
be deleted and rebuilt. `CONTROL/` is hand-authored and is **not** a
projection.

### Modules

| module | responsibility |
|---|---|
| `config.py` | paths (resolved **per call**), thresholds, weights |
| `store.py` | persistence; the only writer of `validation_state` calls |
| `quality.py` | **the gate** — 10-dimension vector + 4 hard gates |
| `retrieval.py` | BM25 + trust-prior blending, class digests, chains |
| `pipeline.py` | ingest, prompt-injection sanitiser, seed verification, markdown |
| `verify_quotes.py` | fetches each cited page, confirms the quote is really there |
| `reconcile.py` | supersedes items orphaned when an agent rewrites its file |
| `ingest.py` | the boundary: agent output → verified, gated rows |
| `skillgen.py` | per-class skill generation with version history |
| `chains.py` | first-class attack chains, each step justified |
| `fp.py` | false-positive capture → rejection rules → skill update |
| `evalm.py` | 13 metrics + 8 retrieval probes |
| `cycle.py` | the 12-step autonomous improvement cycle |
| `overnight.py` | bounded, resumable, breadth-preserving unattended loop |
| `taxonomy.py` | 15 seeded classes with GET-verified seed URLs |
| `seed.py` | registers the taxonomy; refuses un-corroborable classes |

Dependencies: **Python 3.14 standard library only.** No embeddings are
available on this host, and FTS5 with a trust prior is the better shape anyway:
a hunter can see which sources back a claim, which cosine similarity over a
mixed corpus of stubs and evidence cannot.

## The quality gate

Ten dimensions, weighted (`config.QUALITY_WEIGHTS`): source credibility,
technical specificity, evidence strength, reproducibility, corroboration,
practical usefulness, recency, internal consistency, real-world demonstration,
limitations documented.

A weighted mean alone is not enough, because a short confident stub can score
well. Four **hard gates** are necessary conditions, not inputs to the average:

| gate | reason |
|---|---|
| `NO_SOURCES` / `INSUFFICIENT_SOURCES` | no provenance, no claim |
| `INSUFFICIENT_PUBLISHER_HOSTS` | two pages on one host is one publisher, not corroboration |
| `DISCOVERY_ONLY_SOURCE` | social media is a lead, never knowledge |
| `FABRICATED_REFS` | invented citations → **rejected**, not merely held |
| `UNFALSIFIABLE_CLAIM` | "this may be vulnerable" is not a testable claim |

Plus one condition outside the database: **every cited quote must actually
appear on the cited page.** A subagent claiming it read a source is a
self-report. `wks/verify_quotes.py` fetches the page and checks.

**That check must be tested in both directions.** Its first implementation
rejected 11 of 56 genuine quotes (markdown emphasis, table pipes, tag-strip
artefacts before punctuation, undecoded HTML entities) — a 19% false-positive
rate, all of it my bug and none of it agent misconduct. A verifier that cries
wolf gets switched off, and then it protects nothing. `eval/test_wks.py` T13
pins both directions: real markup must match, and a single substituted word must
still fail.

States: `discovered · under_review · supported · high_confidence · disputed ·
outdated · rejected · unresolved`. Unresolved is legitimate; it is never
presented as established knowledge.

## Attack chains

Chains are rows, not prose, and **every step must reference an item that exists
and has passed the gate** — `chains.py` refuses to build a step on a missing or
unpromoted item. Each step carries a `why` and, where the underlying item has
one, its `disproof`. An unjustified chain is a story, and a story in a knowledge
base is worse than no chain.

## Maturity

`quality.maturity()` computes §29's definition of done rather than asserting
it: taxonomy placement, methodology, ≥12 items, ≥4 supported, ≥2 FP rules,
≥1 chain, an independently usable skill. A class missing any of these reports
`researching` and names exactly what is missing. `gaps` orders the work queue
by a cost model, so an unstarted class outranks a nearly-finished one.

## Operating rules

See `CONTROL/rules.md` — 19 rules, each with how it is checked. The short form:

```bash
python -m wks.cli selftest      # R1 R2 R3 R7 R8  — enforced in code
python -m wks.cli verify-seeds  # R5
python -m wks.cli gaps          # R6
python -m wks.cli metrics       # R4 + unsupported-claim rate
python -m wks.cli report        # R10
```

## Known limitations

Stated plainly, because a knowledge system that hides its gaps is worse than
one that reports them:

1. **Retrieval is lexical.** A paraphrase sharing no vocabulary will not match.
   There is no semantic fallback.
2. **Research coverage is 8 of 15 registered classes.** `authz`, `bizlogic`,
   `csrf`, `deser`, `mass_assign`, `ssti`, `path_traversal` are registered and
   seeded but have no gated items yet. The *taxonomy* covers all 57 classes, but
   a class page with no evidence behind it says `Not yet researched.` — which is
   an honest gap, not knowledge. `wks.cli gaps` names what is missing.
3. **The gate measures evidence structure, not technical truth.** Two credible
   sources can still both be wrong. `conflict` rows exist for this: 21 were
   raised, all as `fabricated-evidence`, and all have been settled — 7 resolved
   after re-cutting and re-ingesting, 14 dismissed because the claim never
   entered the corpus. `metrics.open_conflicts` is **0**. Nothing auto-detects
   semantic conflicts yet, so a conflict is only ever found when a quote fails
   verification.
4. **No automatic staleness re-review.** `outdated` is a state the system can
   hold but does not yet apply by itself.
5. **The 1,380 quarantined items were not migrated** — 0 passed the gate. The
   verdict per record is in `state/legacy-audit.json`; the corpus itself is
   untouched.
