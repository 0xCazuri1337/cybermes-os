# Adversarial review of the Cyber process: every place it can certify mastery it has not earned

Reviewer note, stated up front because it changes how the numbers below should be read:
**another process was editing this tree while I measured it.** Between 21:11 and 21:35
local, `wks/relevance.py` was created, deleted, and rewritten; `wks/quality.py` changed
size and mtime; `db/wks.db` was written at 21:11:44; `tools/recon_audit_offtopic.py` was
rewritten so that a probe which had reported 155 offenders began reporting 0. Every
measurement below was re-taken against the tree as it stood, and where a finding was
about code that changed under me I say so and re-verified rather than reporting the
first result. All mutation tests ran in throwaway copies under
`%TEMP%\fm_sb2`, never against the corpus.

Snapshot used for the live numbers: `items_total 1106`, `promotion_rate_pct 100.0`,
`duplicate_rate_pct 10.13`, `stale_rate_pct 0.0`, `classes_mature 61`.

---

## Method

Reading, then running. For every claim below I either show a command and its real
output, or I have labelled it `asserted, unverified`. Six probes were written to
answer "can this checker fail?" by making it fail — in a temp copy, never in the
corpus. They are preserved in `research/recon/fm/` so they can be re-run:

| script | question it answers |
|---|---|
| `fm08_tagblock.py` | does the relevance gate block, or only annotate? |
| `fm04_fillmaturity.py` | can a class read `mature` on off-topic prose alone? |
| `fm05_mastery_gates.py` | can 10 of the 12 mastery gates be closed by junk? |
| `fm06_runexam_bypass.py` | does the documented exam path enforce the guards? |
| `fm07b_offtopic_split.py` | how many items are misfiled, split by whether the measurement is trustworthy |
| `fm09_rules_deadfilter.py` | which rules are enforced vs procedural; which filters are dead |

Two of my own errors, corrected rather than carried forward: my first
off-topic probe reported 38.8% off-topic, which was wrong — it counted `graphql`
items that are plainly on-topic, because vocabulary *absence* is not misfiling, exactly
the false-negative mode `relevance.py` documents. FM-07b splits the count by
measurement trustworthiness and reports 2.1% as the defensible misfiling figure. Second,
I reported `audit_taxonomy.py` exiting 0 on 262 findings; that was `tail`'s exit code,
not the script's. Real exit is 1.

---

# Findings, ranked by the false confidence each can produce

## FM-01 — The relevance gate records its verdict and does not act on it

**What it is.** `quality.assess()` appends the relevance verdict to `reasons` and then
decides on `tags & _BLOCKING_TAGS`. The two vocabularies do not match.

**Where.** `wks/quality.py:235` calls `relevance.assess(...)` and appends `rel.state`.
`wks/quality.py:49` `_BLOCKING_TAGS` contains `"OFF_CLASS_TOPIC"` — a string
`relevance.py` never emits as a state. Its states are `ON_TOPIC, SIBLING, AMBIGUOUS,
MISFILED, ORPHAN, MODULE_FILLER`. The mismatch is a naming drift between two files that
were edited minutes apart by different hands.

**Reproducing command and real output.**

```
cd $WKS_ROOT && python -m wks.cli metrics
```
```
items_total                      1106
promotion_rate_pct               100.0
unsupported_claim_rate_pct       0.0
```

```
cd <sandbox_root> && python research/recon/fm/fm08_tagblock.py <sandbox_root>
```
```
relevance TERMINAL_STATES: ('MISFILED', 'MODULE_FILLER')
quality._BLOCKING_TAGS   : ['DISCOVERY_ONLY_SOURCE', 'INSUFFICIENT_PUBLISHER_HOSTS',
                             'INSUFFICIENT_SOURCES', 'MODULE_FILLER', 'NO_SOURCES',
                             'OFF_CLASS_TOPIC']
terminal states that BLOCK: ['MODULE_FILLER']
terminal states MISSING from the blocking sets: ['MISFILED']

  [exposed_rmm]
     claim        : 'Screening passwords against blocklists helps prevent users from selecting passwords that are commonly used'
     rel.state    : MISFILED
     rel.holds    : True
     tag recorded : reasons.append('MISFILED')
     tag BLOCKS?  : False   <-- ANNOTATES ONLY, ITEM STILL PROMOTES
```

End-to-end, on the live corpus:
```
LIVE active promoted items: 1106
relevance.assess() HOLDS      : 221 (20.0%)
  ...verdict MISFILED         : 170 (15.4%)
  ...verdict MODULE_FILLER    : 51
_BLOCKING_TAGS contains MISFILED?  False
_BLOCKING_TAGS contains OFF_CLASS_TOPIC? True
=> items whose tag is recorded but NOT blocking: 170

  graphql.validation.idor_two_accounts     rel=MISFILED -> state=high_confidence tags=['MISFILED']
  idor.technique.method_override_and_conte rel=MISFILED -> state=high_confidence tags=['MISFILED']
  xss.validation.httponly_blocks_cookie_th  rel=MISFILED -> state=high_confidence tags=['MISFILED']
```

**Why it inflates confidence.** 170 items — 15.4% of everything the corpus calls
knowledge — are detected as misfiled, written into `gate_reasons` where an auditor can
find them, and then promoted anyway. The failure is worse than a missing check, because
the evidence of the defect is *in the database and looks like a successful check*.
`metrics` reports 100% promotion and 0% unsupported. The worst classes:
`exposed_rmm` 13 misfiled of 23, `pass_the_hash` 9 of 26, `dns_enum` 8 of 22,
`tunneling_pivoting` 7 of 24, `ad_acl_abuse` 6 of 20.

**Smallest fix.** Add `"MISFILED"` to `_BLOCKING_TAGS` — one line — or append the
blocking vocabulary instead of the raw state. Then add a test asserting every member of
`relevance.TERMINAL_STATES` is in `_BLOCKING_TAGS | _REJECT_TAGS`, so the two lists
cannot drift apart again. This is the single highest-value one-line change in the tree.

---

## FM-02 — A class made entirely of off-topic prose reports `mature`

**What it is.** `maturity()` counts rows. It never inspects what the rows say.

**Where.** `wks/quality.py:279` `maturity()`, thresholds at `wks/config.py:163-166`
(`MATURITY_MIN_ITEMS=12`, `MATURITY_MIN_HIGH_CONF=4`, `MATURITY_MIN_FP_RULES=2`,
`MATURITY_MIN_CHAINS=1`).

**Reproducing command and real output.**

```
cd <sandbox_root> && python research/recon/fm/fm04_fillmaturity.py <sandbox_root>
```
Built 12 items for `idor` from four sentences that are about XSS, session cookies, SQL
injection and buffer overflows. Each cites two real publisher orgs. Result:
```
promoted idor items: 12
their gate_reasons: [('["MISFILED"]',)]

maturity(): mature | missing: []
checks: {'taxonomy_placed': True, 'methodology': True, 'items': True,
         'supported_items': True, 'fp_rules': True, 'chain': True, 'skill': True}
n_items: 12 n_supported: 12 n_fp: 8 n_chains: 5

RESULT: >>> OFF-TOPIC CLASS REPORTS MATURE <<<
```

**Why it inflates confidence.** `maturity: mature, missing: []` is the single string a
reader takes away from this system. It is reachable with zero correct knowledge about
the class, provided the prose is corroborated by two publishers — which filler off
OWASP cheat sheets always is. `metrics` reports `class_maturity_pct: 100.0` across 62
classes. Every one of those 62 is a count, not a judgement.

**Smallest fix.** In the `n_high` query at `wks/quality.py:278`, add
`AND coalesce(q.gate_reasons,'[]') NOT LIKE '%MISFILED%'`. A class whose knowledge
sits in the wrong class is not mature.

---

## FM-03 — Ten of the twelve mastery gates close on a file whose content proves nothing

**What it is.** `_validate_evidence` inspects artifact content only for `EXAM_GATES`,
a two-element set. The other ten gates require only that a path exists.

**Where.** `wks/mastery.py:146` `_validate_evidence`, with `EXAM_GATES` at
`wks/mastery.py:143`.

**Reproducing command and real output.**

```
cd <sandbox_root> && python research/recon/fm/fm05_mastery_gates.py <sandbox_root>
```
```
NON-EXAM GATES CLOSED BY EMPTY/TRIVIAL ARTIFACTS: 10/10

  [CLOSED] explain           evidence=explain.md     -> 1/12 state=RESEARCHING
           (gate requires a mechanism chain: attacker input -> parser -> normalisation
            -> validation -> trust decision -> internal operation -> observable result.
            Content is the single word TODO.)
  [CLOSED] hypothesize       evidence=hypo.txt       -> 3/12
           (gate requires a falsifiable hypothesis set. Content is ZERO BYTES.)
  [CLOSED] validate          evidence=validate.md    -> 10/12 state=TRANSFER_TESTING
           (gate requires an exploit request + response PAIR. Content is one word.)

  [CLOSED] black_box  evidence=examdir/GRADE.json -> 11/12
  [CLOSED] transfer   evidence=examdir/GRADE.json -> 12/12 state=MASTERED
           (THE SAME ARTIFACT closes transfer as black_box -- nothing ties a transfer
            gate to a DIFFERENT architecture than the black_box run)

FINAL: fm_probe_class -> 12/12 gates, state=MASTERED, score=1.0
```

**Why it inflates confidence.** The module docstring says "the state machine cannot be
talked into MASTERED by writing a sentence in a markdown file." It can: I wrote a
zero-byte file and reached 12/12 MASTERED in one command. The `transfer` gate is
supposed to prove the same class in a *different architecture*; nothing records the
architecture, so one run satisfies both. Note the guard that *does* work —
`_refuse_disqualified` correctly refused a `failure_analysis` gate inside a
disqualified exam — so this module is not uniformly decorative; the ten non-exam gates
simply have no artifact contract.

**Is the gate engine load-bearing?** Barely. `mastery/` holds exactly one record
(`idor.json`, 2/12). It is not consulted by `metrics`, by `maturity()`, by the
class pages, or by any cycle. It is a projection nobody projects. That is defensible
for an honest 2/12 — but it means the system has *no* mechanism that could currently
distinguish a class with capability from a class with notes, which is the brief's
central demand.

**Smallest fix.** Give each non-exam gate a per-gate content contract in
`_validate_evidence`: minimum bytes plus the specific structural elements the gate
names (`validate` must contain an HTTP request line and a status code;
`failure_analysis` must contain expected/actual/assumption; `reject_fp` must contain at
least one disproof test). Require `transfer` to cite an exam whose `card.json` differs
from the `black_box` exam's card.

---

## FM-04 — The documented exam path closes gates the guard refuses to close

**What it is.** `eval/run_exam.py grade_and_record()` — the command
`eval/exams/README.md` tells the operator to run — assigns `rec.gates` directly and
calls `mastery.save()`. `record_gate()`, and therefore both guards, never execute.

**Where.** `eval/run_exam.py:123` (assignment), `:129` (`mastery.save(rec)`).
Guards that are skipped: `wks/mastery.py:146` `_validate_evidence`,
`wks/mastery.py:182` `_refuse_disqualified`.

**Reproducing command and real output.**

```
cd <sandbox_root> && python research/recon/fm/fm06_runexam_bypass.py <sandbox_root> <sandbox_root>/eval
```
```
STAGE 1 -- the guard itself, called directly (control):
  record_gate REFUSED: evidence ...idor-9999 does not exist ...

STAGE 2 -- the documented exam path, run_exam.grade_and_record():
  { "verdict": "PASS", ... "score": { "detected": true, "evidence_present": true,
    "trap_correctly_ignored": true, "no_fabricated_evidence": true,
    "exam_not_contaminated": true }, ... }

gate black_box closed for idor: 2/12 state=VALIDATING
  grade_and_record returned 0
  RESULT: THE EXAM PATH CLOSED A GATE INSIDE A DISQUALIFIED EXAM.
          _refuse_disqualified never ran on this path.
```

And with the same exam directory, the guard and the path disagree directly:
```
record_gate chain REFUSED: idor-9999 is DISQUALIFIED: solver read eval/labforge.py;
  the run measures nothing about skill -- a disqualified run may never close a gate
gate chain closed for idor: 3/12 state=VALIDATING
```

**Why it inflates confidence.** `CONTROL/rules.md` R25 names
`_validate_evidence / _refuse_disqualified` as the check for the exam rule, and
`eval/exams/README.md` names `python eval/run_exam.py grade` as the way to close a
gate. The guard the rule points at is not on the path the rule documents. The
`mastery/idor.json` history shows this guard was added *because* a disqualified run had
already closed a gate once — the fix was made in the wrong place. Re-invoking with an
arbitrary `gate` argument also closes non-exam gates, so `chain` closed on an exam
grade.

**Smallest fix.** Replace the four lines in `grade_and_record` with
`mastery.record_gate(cid, gate, exam_dir / "GRADE.json")`. Both guards then run, and
`record_gate` is already the single writer the rules document names.

---

## FM-05 — `wks/claimcheck.py` flags six promoted items and is wired to nothing

**Reproducing command and real output.**

```
cd $WKS_ROOT && python -m wks.claimcheck
```
```
promoted items examined : 1111
flagged as not-a-claim  : 6 (6 auto-generated)
  csrf.auto.02       TRUNCATED(no terminal punctuation)
      'CMS allows modification of configuration via CSRF attack against the administrator'
  nosql.auto.t.7372380b  SENTENCE_FRAGMENT(starts with 'but')
      'But it still allows for more flexibility when exploiting this injection.'
  xxe.auto.t.62e2257e    SENTENCE_FRAGMENT(starts with 'and')
      'And, if an attacker does breach security, they should only encounter encrypted data and a network of'
```
```
grep -rn 'claimcheck' --include=*.py wks/ | grep -v '^wks/claimcheck.py'
(no output)
```
**Why it inflates confidence.** Six promoted items are sentence fragments. Its own
module note records the more important fact: *"a SQL-injection sentence was filed under
`ad_kerberos`"*, and that `CLASS_MISMATCH` — the one check that would have caught
misfiling — was **removed** after producing 67 false positives. So the module that was
written to close the subject gap closed it by deleting the subject check.

**Smallest fix.** Call `claimcheck.reasons(claim)` from `quality.assess` and add its
tags to `_BLOCKING_TAGS`. Its design guarantees over-holding rather than
over-promoting, which is the safe direction.

---

## FM-06 — Duplicate accounting understates redundancy 2×, and the gap is exactly cross-class

**Where.** `wks/evalm.py:79`; `wks/integrity.py:77` `pick_canonical`.

**Reproducing command and real output.**
```
groups reported by evalm._metrics (duplicate_rate_pct) : 112  -> 10.08%
groups actually covering                               : 112 groups, 355 rows
REDUNDANT ROWS                                         : 243  -> 21.87%
CROSS-CLASS groups                                    : 62   (253 rows)
```
```
  n=13 nc=11  ['ad_acl_abuse','ad_enumeration','ad_ldap','ad_ntlm','authn','dns_enum',
               'exposed_services','lateral_movement','segmentation_analysis','smb',
               'tunneling_pivoting']
      an xss vulnerability may allow an attacker to execute arbitrary javascript code ...
```
`duplicate_rate_pct` divides *groups* by items. One XSS sentence filed under eleven
different classes is counted as **one** duplicate. Then `integrity.pick_canonical`
picks one home by citation count and marks the rest `dedup_of` — which would erase the
record that eleven classes were padded by the same sentence, the precise signature of
systematic mis-filing. Twelve rows already carry `dedup_of` and are still counted by
`evalm`, which filters only `status='active'`.

**Smallest fix.** Report both `duplicate_groups` and
`redundant_item_rate_pct = (rows_in_groups − groups)/total`. In `mark_duplicates`,
refuse to collapse a group spanning more than one class; report it as MISFILED instead.

---

## FM-07 — `stale_rate_pct 0.0` measures fetch recency, not knowledge age

**Where.** `wks/evalm.py:86`.

```
select min(retrieved_at), max(retrieved_at), count(*) from source
-> ('2026-10-02T00:08:46+00:00', '2026-10-02T18:11:44+00:00', 513)
select count(*) from source where retrieved_at >= date('now','-3 years')  -> 513
```
Every one of 513 sources was fetched on one day, because the whole corpus was ingested
in one day. The filter is `NOT EXISTS(... retrieved_at >= date('now','-3 years'))`, so
zero is a structural consequence of a fresh ingest, not a health signal. It will read
`0.0` again after every ingest — which is precisely when a maintainer is least
interested in being told nothing is stale. The module that *does* measure staleness,
`wks/staleness.py`, re-fetches and diffs `content_hash`; it is called by no production
path (only `eval/test_wks_infra.py` T28). `metrics` reports `without_content_hash: 1`
and its own note already says the 0 means "not checked".

**Smallest fix.** Stop publishing the number under that name. Publish the sweep's
result (`candidates / STALE / CHANGED / unmeasured`) or rename it
`freshness_of_retrieval_rate_pct` and say what it measures. Wire `staleness.sweep`
into the cycle so the number has a producer.

---

## FM-08 — `blocked_on_single_host: 0` and `open_conflicts: 0` are empty results, not clean bills

**Where.** `wks/evalm.py:166`.

```
select gate_reasons, count(*) from quality group by 1 order by 2 desc limit 5
-> [('[]', 1097), ('["MISFILED"]', 12)]
```
The filter is `WHERE gate_reasons LIKE '%INSUFFICIENT_PUBLISHER_HOSTS%'`. The column
exists and is written; the string simply never appears, because the writer only emits
blocking tags for items that were blocked when last gated, and nothing has been blocked
since. The `0` is indistinguishable from "no item is blocked on a single publisher".

**A correction to the brief's hypothesis.** The hypothesised failure — a `WHERE` on
`item.status` when the state lives in `quality.validation_state`, so a wrong-column
filter matches nothing and looks like health — **does not exist in this tree**. I
swept every metric-style filter against the live schema (FM-09 output) and all sixteen
resolve to existing columns. And sqlite *raises* on an unknown column rather than
returning empty:
```
select count(*) from item where validation_status=1
-> OperationalError: no such column: validation_status
```
So a misspelled column crashes loudly. The genuine empty-result mode requires a column
that exists and is written only with non-matching values — which is what FM-01 and FM-08
are. **Stated because the brief asked me to find it and it is not there; a brief's
hypothesis is not a finding.**

**Smallest fix.** Derive `blocked_on_single_host` from the blocking decision itself
rather than `LIKE`-matching a string, and publish the count of items carrying a
*non-blocking* gate reason — currently 170 — which is the number that actually describes
this corpus.

---

## FM-09 — R28's checkers do not exist

```
grep -o 'tools/audit_[a-z_]*\.py' CONTROL/rules.md | sort -u | while read f; do
  [ -f "$f" ] && echo "EXISTS $f" || echo "MISSING $f"; done
-> MISSING tools/audit_rfc_subjects.py
-> MISSING tools/audit_seed_subjects.py
```
R28 is the rule that *a seed URL must be about the thing the class claims* — the rule
most directly about relevance. Its defect was real and was fixed
(`wks/network_taxonomy.py:209` records the measurement and the replacement seeds), but
the checker is gone. The footer block instructs the reader to run both before claiming
a cycle improved anything, so following the documented procedure yields "No such file or
directory" — noise an operator learns to skip. R28 also carries the sharpest warning in
the document: *"a checker here must be shown to fail."*

**Smallest fix.** Restore the checkers, or amend R28 to state plainly that the subject
audit was a one-time measurement with no standing check.

---

## FM-10 — Three rule IDs collide in CONTROL/rules.md

```
RULE IDS FOUND: ['R1'...'R28', 'R23', 'R24', 'R25']
DUPLICATE RULE IDS: ['R23', 'R24', 'R25']   rows=31  unique=28
```
The trailing three rows are real, enforced, and distinct: the second R23 is the
builder-page rule (`eval/test_wks.py` T20), the second R24 is labforge validation, the
second R25 is the exam-evidence rule — which is *this review's* R25-equivalent (FM-04).
The "What checked by means" footer summarises R23–R24 as the domain router and silently
drops all three. A control document whose ids collide cannot be cited unambiguously,
which is the property it exists to provide.

**Smallest fix.** Renumber to R29/R30/R31, update the footer, add a test asserting rule
ids are unique.

---

## FM-11 — Generator drift: measured clean (negative finding)

I expected to find drift here and did not. Recording it so nobody re-opens it:
```
SKILL.md files MISSING on disk for a registered class: 0
SKILL.md files DRIFTED from render():                 0
COMPETENCY.md MISSING: 0        COMPETENCY.md DRIFTED: 0
tools/taxonomy/taxonomy_write.py --check -> OK — 142 files match the spec and the canonical db
```
The structural gap is real — neither `skillgen.write_skill` nor
`methodgen.generate_all` re-reads what it just wrote, so a partial write is silent —
but measured drift is zero and no number is inflated today. **Low priority.**

---

## FM-12 — The quote matcher *is* validated in both directions (negative finding)

R17 holds. `eval/test_wks.py` T13 asserts both directions:
```
[PASS] verbatim matches itself
[PASS] backticks match
[PASS] space-before-comma artefact handled
[PASS] word substitution REJECTED
[PASS] invented sentence REJECTED
[PASS] short non-quote REJECTED
[PASS] GET-for-POST substitution REJECTED
```
`eval/test_wks.py` finishes `ALL WKS GATE TESTS PASS`. One asymmetry worth recording,
not a defect: `_contained`'s token fallback is unreachable for `n < 4` because of its
own guard, so short quotes verify only via the direct substring path. Nine corpus
citations have ≤5-word quotes, and `evidence_strength` (`wks/quality.py:131`) counts
any non-empty quote identically — a three-word span earns the same 0.25 bonus as a
sentence. Not worth a gate change.

---

# Rules: enforced in code vs procedural

Measured by checking whether each named artifact exists, whether the named symbol is
present, and whether it runs.

**Enforced in code, covered by a suite that fails loudly.** R1, R2, R3, R7, R8, R17, R19
(`eval/test_wks.py` — currently green). R14, R15 (`tools/taxonomy/`, exit 1 on findings).
R16, R18, R20, R22, R26 (`tools/`, `wks/verify_quotes.py`). R23, R24 (first pair —
`eval/test_domains.py`). R23, R24, R25 (second trio — `eval/test_labforge.py`,
`eval/run_exam.py`) — **with the caveat that the R25 guard is not on the path the rule
documents (FM-04).**

**Procedural — audited by a command a human must remember to run.** R5, R6, R9, R10,
R11, R12, R13, R27. These are the ones a reasonable agent skips without noticing
anything was lost, because skipping them produces no error, only absence:

- **R9** (no secrets in the corpus) — grep before commit. Skipped silently.
- **R11** (generated docs never hand-edited) — enforced only by a header comment.
- **R12** (legacy quarantine never imported on trust) — `eval/audit_legacy.py` exists.
- **R27** (a class with no gated items is a map, not knowledge) — currently *satisfied
  vacuously*: every class has items, so it reports nothing.
- **R13** (no active testing) — greppable by intent, not by test.

**Named but absent.** R28 — both checkers missing (FM-09).

**Undocumented as a rule.** The relevance gate itself. `wks/relevance.py` exists, is
built to a high standard (a validity contract, a two-direction selftest, a documented
refusal to gate on vocabulary *absence*), and was wired into `quality.assess` at 21:35
while I was auditing. It is not in `rules.md`, has no rule id, and — per FM-01 — does
not currently block. **The most important gate in this system is the only one with no
rule, no id, and (at measurement time) no effect.** That is the finding I would put in
front of the mission owner first.

---

# What I could not verify, and why

- **`wks/relevance.py` as it stands now.** The file was deleted at 21:11 and rewritten
  by 21:35 while I worked; I measured a version with 39 selftest cases (29/39 passing),
  then a version with 53 cases (36/53 passing). Both revisions' selftests **fail**.
  Whoever wired the module did not run its own validity contract first. FM-01's numbers
  were taken against the final revision and hold; do not trust my transcription of the
  selftest case count.
- **The corpus numbers are a moving target.** `items_total` was 1111 when I started and
  1106 when I finished, without my writing anything to it. Any headline figure here is
  only as good as the snapshot line.
- **Whether the concurrent process intended the FM-01 mismatch.** The
  `OFF_CLASS_TOPIC` string looks like a deliberate intent to name the blocking tag, and
  the wiring looks deliberate. It is more likely an unfinished edit than a design
  decision. I did not assume either way.
- **`orch/`, `wks/corroborate.py`, `wks/reconcile.py`, `wks/migrate.py`** — zero
  external callers each (measured). I did not establish whether they are dead or
  CLI-invoked; `corroborate.py` is a one-shot builder script by its own docstring.
- **R5's live seed verification and R16's live quote re-verification** — both require
  network. Prohibited on this host and not run.
- **`audit_refs.py --selftest` and `test_domains.py`** — not run; I read the code and
  confirmed the files and symbols exist, which is a weaker claim than running them.

# What I would NOT change, and why

- **`quality.assess`'s hard gates (R1/R2).** MIN_PUBLISHER_HOSTS=2 with org-collapsing,
  builder-host exclusion, `SOURCE_AUTHORITY` — these are genuinely load-bearing, they
  are fingerprinted by `orch/gate_guard` (verified `ok: true`, 6 files, no settings
  changed), and they are the reason no item in this corpus was promoted on a citation.
  They are not the problem.
- **`relevance.py`'s refusal to gate on vocabulary absence.** It is right, and it is
  measured right: making `ORPHAN` terminal held 117 items of which ~70% were false
  positives. Gating on absence would reject correct SQLi, XSS and IDOR knowledge and
  train the operator to ignore the gate — the same failure mode as R17. Keep the
  asymmetry; fix only the vocabulary mismatch (FM-01).
- **`integrity`'s "mark, never delete" policy for duplicates.** Retaining the
  mis-filed row and recording `dedup_of` is the right instinct. FM-06 asks only that it
  not collapse *across* classes.
- **`mastery`'s separation from `quality`.** The docstring's claim — a class can be
  MASTERED holding zero items, and an item can be `high_confidence` while the class is
  WEAK — is a correct and unusual design position. FM-03 criticises the gates' content
  contracts, not the separation.
- **The duplicate `continue` at `tools/taxonomy/audit_taxonomy.py:135-136`.** Dead but
  provably harmless — the second is unreachable and the first is correct. Cosmetic.
- **`wks.cli selftest` timing out at 180s.** Not a defect: the suite makes live network
  calls and completes green given ~400s. Noted so nobody reports it as a failure.

---

## Regression suite

`research/recon/false_mastery_tests.json` — 12 entries, one per finding, each naming a
real file and a real symbol, each with a command a script can run. Severities: 4
critical, 3 high, 3 medium, 2 low. Kinds: 4 missing_check, 2 dead_filter,
2 unused_component, 1 each unchecked_threshold, double_counting, unmeasured_as_zero,
generator_drift.