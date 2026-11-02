# W11 — Per-class hunting skill regeneration & projection verification

Store: `C:/Users/Administrator/.hermes/cyber` (`WKS_ROOT` exported, cwd = store root)
Host: Windows 11, bash (MSYS), `python` 3.14
Date: 2026-10-02 ~20:30–20:40 +0300
Scope: regenerate generated per-class skills, verify projection consistency, report drift.

---

## WHAT I RAN

### 1. `python -m wks.skillgen --help`

**`--help` is not implemented. It was silently ignored and a full regeneration ran anyway.**

`wks/skillgen.py` `main()` (line 206) takes no arguments and never parses `sys.argv`:

```python
def main() -> int:
    con = store.open_db(create=True)
    res = generate_all(con)
    for r in res:
        print(f"  {r['class_id']:16} {'UPDATED' if r['changed'] else 'unchanged'}"
              + (f" ({r['diff_lines']} diff lines)" if r['changed'] else ""))
```

There is no `argparse`, no `--help` string, no usage text anywhere in the module. So
`python -m wks.skillgen --help` == `python -m wks.skillgen`. Exit code 0, 62 lines of output,
all `unchanged`. **This means "learning the real options" is impossible via `--help`; the
only supported invocation is the bare command.** Real options: none.

### 2. `python -m wks.skillgen` (no arguments — the canonical regeneration)

Ran 4 times total across this session. Every run identical:

```
$ python -m wks.skillgen
  ad_acl_abuse     unchanged
  ad_delegation    unchanged
  ad_enumeration   unchanged
  ad_group_policy  unchanged
  ad_kerberos      unchanged
  ad_ldap          unchanged
  ad_ntlm          unchanged
  ad_trust_abuse   unchanged
  adcs_abuse       unchanged
  api_trust        unchanged
  authn            unchanged
  authz            unchanged
  bizlogic         unchanged
  cache_deception  unchanged
  cache_poisoning  unchanged
  clickjacking     unchanged
  cmd              unchanged
  cors             unchanged
  credential_access unchanged
  crlf             unchanged
  csrf             unchanged
  deser            unchanged
  dns_enum         unchanged
  exposed_rmm      unchanged
  exposed_services unchanged
  file_upload      unchanged
  graphql          unchanged
  host_header      unchanged
  idor             unchanged
  info_disclosure  unchanged
  internal_recon   unchanged
  jwt              unchanged
  lateral_movement unchanged
  ldap             unchanged
  ldap_enum        unchanged
  mass_assign      unchanged
  misconfig        unchanged
  nosql            unchanged
  oauth            unchanged
  open_redirect    unchanged
  pass_the_hash    unchanged
  password_attacks unchanged
  path_traversal   unchanged
  prototype_pollution unchanged
  race             unchanged
  rdp              unchanged
  segmentation_analysis unchanged
  service_enumeration unchanged
  service_enumeration_detail unchanged
  session          unchanged
  smb              unchanged
  smuggling        unchanged
  sqli             unchanged
  ssrf             unchanged
  ssti             unchanged
  subdomain_takeover unchanged
  supply_chain     unchanged
  tunneling_pivoting unchanged
  websocket        unchanged
  winrm            unchanged
  xss              unchanged
  xxe              unchanged
```

`UPDATED count: 0` · `unchanged count: 62` · exit 0.

**The regenerated projections were already byte-identical to what is on disk.** No skill
needed rewriting. This is the generator's designed behaviour (`skillgen.py:159-162`): a skill
is only rewritten when rendered content differs, so an unchanged class produces no spurious
version bump.

### 3. `python tools/taxonomy/taxonomy_write.py --check`

```
$ python tools/taxonomy/taxonomy_write.py --check
OK — 142 files match the spec and the canonical db
EXIT=0
```

(Corrected path confirmed: `tools/taxonomy/`. The old `methodology/scripts/` path no longer exists.)

### 4. `python tools/taxonomy/audit_taxonomy.py`

```
audited 166 bug-class files (6 declared sub-docs), 113 canonical classes, 78 chain files

262 finding(s):
```
EXIT=1. Full 265-line output captured; 63,362 chars. Findings by type:

| Finding type | Count |
|---|---|
| SECTION DRIFT | 91 |
| CHAIN SCHEMA DRIFT | 71 |
| CLASS_HOME MISSING FILE | 62 |
| DUPLICATE CANONICAL | 38 |
| **Total** | **262** |

---

## WHAT CHANGED

**Generated skill files written or updated: 0.**

The regeneration is a verified no-op at the file level. All 62 `SKILL.md` already matched
their database projection exactly.

**The generator is NOT file-level idempotent, however — it writes to `db/wks.db` on every run.**
This is the one real side effect I found, and it contradicts a plain reading of "do not modify
db/wks.db". I did not pass `--apply` to anything and made no deliberate DB edit; this is
`skillgen.py`'s own behaviour:

`skillgen.py:152-155` runs unconditionally for every class, *before* the content comparison:

```python
row = store.get_class(con, class_id)
store.upsert_class(con, class_id, row["name"], row["surface"],
                   status=row["status"], skill_path=str(skill))
con.commit()
```

Measured effect, isolating which rows actually change:

```
$ md5sum db/wks.db   (before) 182a951a993ad36fdd635a28c7ae63a9
$ python -m wks.skillgen
$ md5sum db/wks.db   (after)  cb0364abc2c82071492e1ce797f0f198   <- bytes changed
```

Row-level diff across 7 content tables, before vs after one run:

```
item:        identical (1112 rows)
bug_class:   DIFFERS (62 -> 62 rows)
   row 0 key: ad_acl_abuse
     col last_reviewed: '2026-10-02T17:33:57+00:00' -> '2026-10-02T17:34:06+00:00'
chain:       identical (71 rows)
quality:     identical (1112 rows)
chain_step:  identical (237 rows)
fp_case:     identical (70 rows)
item_source: identical (2341 rows)
```

**Only `bug_class.last_reviewed` changes — a UTC timestamp bumped on all 62 class rows.
Zero knowledge content is altered.** No `item`, `quality`, `chain`, `chain_step`, `fp_case`
or `item_source` row differs. So the store's *knowledge* is untouched; only a review-date
column churns. Worth flagging to whoever owns `skillgen.py`: an unconditional
`upsert_class`+`commit` in the projection path means "regenerate" is never a pure read,
and it makes the DB file hash unstable for anyone diffing it.

Corpus totals confirmed directly from the DB (not from notes):
`bug_class`=62, `item`=1112 (1111 `active`, 1 `superseded`), `chain`=71, `chain_edge`=94,
`chain_step`=237, `fp_case`=70, `item_source`=2341, `source`=513, `quality`=1112.
(Note: the task brief says "1111 promoted items" — the real status vocabulary is
`active`/`superseded`, not `promoted`; 1111 is the `active` count.)

### Generated skills are non-empty and carry real knowledge

```
$ find domains -name SKILL.md -printf '%s\t%p\n' | sort -n
count=62
total bytes=836930
min=8165   max=63748   mean=13498
empty (0 byte) files: 0
files under 200 bytes: 0
```

Every one of the 62 is substantial. Smallest / largest:

```
 8165  domains/web/ssti/skills/SKILL.md
 8754  domains/web/mass_assign/skills/SKILL.md
 8945  domains/web/misconfig/skills/SKILL.md
 ...
27755  domains/web/open_redirect/skills/SKILL.md
63748  domains/web/xss/skills/SKILL.md
```

62 `HISTORY.md` files accompany them (version history present, append-only).

**Note on layout:** the brief says generated skills live at `skills/idor-hunting`. That is
stale. `wks/skillgen.py:141-145` writes each skill **inside its own class directory**,
resolved via `wks.domains`:

```
domains/network/active-directory/adcs_abuse/skills/SKILL.md
domains/web/idor/skills/SKILL.md
```

The flat `skills/` root exists but is **empty** (`find skills -type f | wc -l` → 0). The old
`<id>-hunting/` layout survives only in quarantine:
`quarantine/pre-domains-refactor-20261002/skills-flat/<id>-hunting/SKILL.md` (62 files).
That reconciles the `find -name SKILL.md` total of 124 = 62 live + 62 quarantined.

#### Evidence A — `domains/web/idor/skills/SKILL.md`

```
---
name: idor-hunting
description: Use when hunting IDOR / BOLA (Object-Level Authorization) in a api target.
  Ordered prerequisites, signals, techniques, validation bar and false-positive rules.
---

# IDOR / BOLA (Object-Level Authorization) — hunting skill

<!-- GENERATED from db/wks.db by wks/skillgen.py. DO NOT HAND-EDIT.
     Edit the rows (or ingest better research) and re-run:
     python -m wks.skillgen -->

> surface `api` · CWE CWE-639 · OWASP API1:2023
> evidence: 14 items, 14 supported, 3 FP rules, 2 chains
> maturity: **mature**

A server fails to verify that the authenticated caller is entitled to the specific
object identified by the request, so one user reaches another's data.

**Also called:** broken object level authorization, bola, insecure direct object reference,
object level authorization failure, horizontal privilege escalation via id

## Prerequisites (do not start without these)

- IDOR/BOLA is only possible where a client-supplied identifier selects the object the
  server acts on, in the path, query string, header or body.
  - **Disproof:** Every request either carries no object identifier at all, or the
    identifier is server-generated/signed and cannot be altered without invalidating
    the request.
  - Sources: <https://owasp.org/API-Security/editions/2023/en/0xa1-broken-object-level-authorization/>
    · <https://cheatsheetseries.owasp.org/cheatsheets/Insecure_Direct_Object_Reference_Prevention_Cheat_Sheet.html>
    · <https://portswigger.net/web-security/access-control/idor>
```

Real CWE/OWASP mapping, real aliases, per-item disproof, cited sources — not a placeholder.

#### Evidence B — `domains/network/active-directory/pass_the_hash/skills/SKILL.md`

```
> surface `ad` · CWE CWE-294 · OWASP —
> evidence: 26 items, 26 supported, 3 FP rules, 1 chains
> maturity: **mature**

## Validation bar (how to prove it)

- A pass-the-hash finding requires a successful authentication made with the obtained
  hash, and recovering the hash alone - by replication or by capture - is not pass-the-hash.
  - **Disproof:** If every attempt to authenticate with the recovered NT hash against any
    target service fails and the target logs no NTLM authentication for that account from
    the operator's host, then no hash was used and the pass-the-hash claim is false even
    though credential recovery is real.
  - Sources: <https://academy.hackthebox.com/course/preview/active-directory-powerview>
    · <https://securelist.com/tr/nighteagle-apt-ghostcontainer-and-tunneling/121323/>
```

Operationally useful validation bar with a genuine falsification condition.

---

## PROJECTION DRIFT

### A. `taxonomy_write.py --check` — clean

```
OK — 142 files match the spec and the canonical db
```

No drift. 142 taxonomy files agree with the canonical DB.

### B. `audit_taxonomy.py` — 262 findings, exit 1

The `--check` gate passing while the audit reports 262 findings is not a contradiction:
they test different things. `--check` covers 142 taxonomy-scaffold files; the audit also
walks digests, competency pages, chain pages and class-home links, which `--check` does not govern.

#### B1. CHAIN SCHEMA DRIFT — 71 files, all `1/11 sections extra=['Sequence']`

Every chain page carries an extra `## Sequence` section not in the 11-section chain schema.
`extra=['Sequence']` is identical on all 71 — one systemic generator/spec disagreement, not
71 independent defects. Fix belongs in the chain writer or the schema, not in the pages.

*Brief correction:* the brief said this affects "roughly 22 chain pages under
`domains/network/chains/`". That undercounts by 3×. Actual split: **22 under
`domains/network/chains/`, 49 under `domains/web/chains/`.** All 71 listed below.*

`domains/web/chains/` (49):
```
ad-delegation-replay-to-dcsync-domain-admin.md
bizlogic-intermediate-credit-to-realised-loss.md
chain.authz.auto.01.md
chain.cache_deception.auto.01.md
chain.cache_poisoning.auto.01.md
chain.clickjacking.auto.01.md
chain.cmd.auto.01.md
chain.cors.auto.01.md
chain.crlf.auto.01.md
chain.deser.auto.01.md
chain.host_header.auto.01.md
chain.ldap.auto.01.md
chain.mass_assign.auto.01.md
chain.misconfig.auto.01.md
chain.nosql.auto.01.md
chain.open_redirect.auto.01.md
chain.path_traversal.auto.01.md
chain.prototype_pollution.auto.01.md
chain.session.auto.01.md
chain.smuggling.auto.01.md
chain.ssti.auto.01.md
chain.subdomain_takeover.auto.01.md
chain.websocket.auto.01.md
chain.xxe.auto.01.md
constrained-delegation-to-admin-service-ticket.md
csrf-same-site-xss-to-state-change.md
dangling-dns-to-session-cookie-theft.md
dangling-ns-to-transitive-zone-compromise.md
dns-zone-transfer-to-subdomain-takeover.md
graphql-exposure-to-enumeration.md
host-header-poisoning-to-password-reset-takeover.md
idor-to-account-takeover.md
jwt-weak-verification-to-impersonation.md
limit-overrun-to-quantified-financial-loss.md
machine-account-hash-to-group-derived-authority.md
oauth-consent-scope-to-persistent-app-principal.md
oauth-open-redirect-to-ato.md
oauth-state-missing-to-login-csrf-binding.md
preauth-disabled-account-to-plaintext-password.md
race-to-financial-impact.md
saml-assertion-signature-wrapping-to-session-identity-substitution.md
spn-enumeration-to-offline-service-hash-crack.md
sqli-boolean-oracle-to-row-count-enumeration.md
ssrf-metadata-to-application-identity-scope.md
ssrf-to-cloud-metadata-credential-theft.md
upload-traversal-to-interpreter-execution.md
user-consented-scope-to-durable-refresh-principal.md
web-cache-deception-to-cross-user-session-takeover.md
xss-reflected-to-privileged-action.md
```
`domains/network/chains/` (22):
```
ad-enum-to-kerberoast-to-lateral-execution.md
ad-gpo-delegated-write-to-domain-wide-execution.md
chain.ad_acl_abuse.auto.01.md
chain.ad_delegation.auto.01.md
chain.ad_kerberos.auto.01.md
chain.ad_ldap.auto.01.md
chain.ad_ntlm.auto.01.md
chain.ad_trust_abuse.auto.01.md
chain.adcs_abuse.auto.01.md
chain.credential_access.auto.01.md
chain.dns_enum.auto.01.md
chain.ldap_enum.auto.01.md
chain.pass_the_hash.auto.01.md
chain.password_attacks.auto.01.md
chain.segmentation_analysis.auto.01.md
chain.service_enumeration.auto.01.md
chain.service_enumeration_detail.auto.01.md
chain.tunneling_pivoting.auto.01.md
chain.winrm.auto.01.md
ci-credential-to-self-propagating-poisoned-artifact.md
rdp-valid-account-to-clipboard-exfiltration.md
reachable-admin-service-to-relayed-credential-to-lateral.md
```

#### B2. CLASS_HOME MISSING FILE — 62 (one per class, 100% of classes)

Every class's declared class-home markdown is absent, e.g.:
```
CLASS_HOME MISSING FILE  ad_acl_abuse  -> network/active-directory/ad-acl-abuse.md
CLASS_HOME MISSING FILE  api_trust     -> api/api-to-api/api-to-api-trust.md
CLASS_HOME MISSING FILE  idor          -> web/authorization/idor.md
CLASS_HOME MISSING FILE  sqli          -> web/injection/sql-injection.md
CLASS_HOME MISSING FILE  xss           -> web/xss/xss.md
```
Full list of all 62 is in the captured audit output; every one of the 62 `bug_class` rows is
affected. This is a total, not a sample.

#### B3. DUPLICATE CANONICAL — 38

Two documents claim the same canonical title. 37 are the uniform
`knowledge/CLASS.md` + `knowledge/DIGEST.md` pair per web class, e.g.:
```
DUPLICATE CANONICAL  IDOR / BOLA (Object-Level Authorization):
  ['domains/web/idor/knowledge/CLASS.md', 'domains/web/idor/knowledge/DIGEST.md']
```
(affects api_trust, authn, bizlogic, cors, crlf, clickjacking, csrf, xss, supply_chain,
graphql, host_header, idor, info_disclosure, deser, jwt, ldap, mass_assign, nosql, oauth,
cmd, open_redirect, path_traversal, prototype_pollution, race, smuggling, sqli, misconfig,
ssrf, ssti, session, subdomain_takeover, file_upload, cache_deception, cache_poisoning,
websocket, xxe — 37 classes)

One is a different shape — a methodology page colliding with a competency page:
```
DUPLICATE CANONICAL  Methodology — IDOR / BOLA (Object-Level Authorization):
  ['domains/web/methodology/idor.md', 'domains/web/idor/assessment/COMPETENCY.md']
```
One has visibly corrupted output — the leading `**` of "NoSQL / Operator Injection" was
consumed by the report's own bold formatting, so the captured line reads
`DUPLICATE CANONICAL  ***'domains/web/nosql/knowledge/CLASS.md', ...]`. Almost certainly a
cosmetic artifact of the audit tool's own formatting rather than data corruption, but it is
in the real output and I am reporting it as seen rather than silently cleaning it.

#### B4. SECTION DRIFT — 91

Two distinct populations:
- **37 `domains/web/<class>/knowledge/DIGEST.md`** — generated digests carry `Prerequisite`,
  `Signal`, `Technique`, `Fp Rule`, `Chain Link`, `Bypass`, `Variant`, `Test`,
  `Evidence`, `False-positive rules`, `Related classes (via chains)` instead of the expected
  16-section class schema (`Definition`, `Root Cause`, `Preconditions`, …). Many show
  `order_ok=False`.
- **37 `domains/web/<class>/assessment/COMPETENCY.md`** — same class, expected 16 sections.
- **17 `domains/web/methodology/*.md`** — methodology pages with bespoke sections
  (`Order`, `Procedure`, `What this establishes`, `The evidence rule`, …).
  Files: api-hunting, authentication-testing, authentication, authorization-testing,
  authorization, business-logic-testing, business-logic, csrf, idor, INDEX, injection-testing,
  METHODOLOGY, recon, ssrf, web-hunting, xss.

The DIGEST.md population is notable: **the digests are the generator's own projection of the
same DB rows that produce the SKILL.md files.** So `taxonomy_write --check` calls the tree
conforming while the audit says the generated digests don't match the class-page schema —
the two tools disagree about what a generated digest should look like.

### Step 5 — "Not yet researched" silent-knowledge-hiding check

**Result: no such defect exists. Zero occurrences, corpus-wide.**

```
$ grep -rn "Not yet researched" --include=SKILL.md domains/
---COUNT---
0
```
Broader placeholder sweep over all 62 generated skills for
`Not yet researched` / `TODO` / `TBD` / `placeholder` / `no digest generated yet` / `unmapped`:
```
domains/web/path_traversal/skills/SKILL.md   'placeholder' x1
domains/web/ssrf/skills/SKILL.md              'placeholder' x1
total hits: 2
```
Both inspected in context — **both are ordinary English inside false-positive disproof rules,
not template placeholders:**

`domains/web/path_traversal/skills/SKILL.md:123`
```
- **Disproof:** If the same route serves a fixed placeholder body for every nonexistent path
  including your traversal form, the identical-response rule applies and the report is a false
  positive...
```
`domains/web/ssrf/skills/SKILL.md:96`
```
- Killed by: An unresolvable domain and a malformed URL also returned HTTP 200 with the same
  non-empty placeholder body, so the 200 is the endpoint accepting the parameter, not a
  successful outbound fetch
```

**Directly checked the more dangerous variant — a skill whose header under-reports the DB.**
Parsed the `> evidence: N items` header of all 62 skills and compared against
`SELECT class_id, COUNT(*) FROM item` per class. One apparent mismatch:

```
MISMATCH idor  claims=14  db=15
```

**Investigated and it is not a defect.** The 15th row is item id 18,
`idor.technique.nested_child_refs_and_path_matching`, `status='superseded'`. The header is
computed by `wks/quality.py:274-277`, which filters `AND i.status='active'`:

```sql
SELECT count(*) n FROM item i JOIN quality q ON q.item_id=i.id
 WHERE i.class_id=? AND i.status='active'
```
Correctly excludes the superseded item. Corpus-wide there is exactly 1 superseded item, so
`idor` is the only class where the counts can differ. **Zero skills claim `0 items` while the
DB holds items, and zero classes have zero items** (`classes_with_items=62/62`). Nothing is
being silently hidden.

### Content-quality defect found in passing (not a projection mismatch, but worth flagging)

591 boilerplate disproof lines across the 62 skills — a single templated sentence:
`"This is refuted if an authoritative source shows the described behaviour does not occur,
does not grant access, or is already prevented by default framework configuration: \"<first
60 chars of the claim>\"."`

Worst offenders: `open_redirect` 36, `path_traversal` 28, `adcs_abuse` 21,
`tunneling_pivoting` 19, `pass_the_hash` 19, `xxe` 18, `exposed_rmm` 18,
`password_attacks` 18.

This is **in the DB rows, not the generator** — `skillgen.py` faithfully projects a
low-quality `disproof` field. It is not silent knowledge hiding (the claims and sources are
real), but it is near-zero hunting value: a disproof that just truncates the claim and says
"an authoritative source may refute this" rejects nothing. Worse, in `pass_the_hash` the
projected items include course-preamble text, e.g. item rendered as a hunting *technique*:
> "For all exercises, we will assume that the target company Inlanefreight has hired us to
> perform an in-depth penetration test with a heavy focus on AD security..."

and "Second point: MFA is largely ineffective against this technique…". That is instructional
scaffolding from a training source ingested as domain knowledge. Fix belongs upstream in
ingestion/claim-extraction, not in `skillgen.py`.

---

## WHAT I COULD NOT VERIFY

- **I could not verify the regeneration is correct against a fresh baseline**, because the
  generator reported `unchanged` for all 62 classes on every run. That proves the on-disk
  skills equal *the generator's current output* — it does not prove the generator's
  interpretation of the DB is right. `unchanged` is self-consistency, not correctness.
  A true from-scratch test would require deleting skills and rebuilding, which the hard rules
  and the "regenerate, never hand-edit" rule make out of scope here.
- **I did not verify `HISTORY.md` correctness.** I confirmed 62 files exist and that no
  spurious version bump was appended by my runs (the idor history's newest entries predate
  this session at 15:57/16:07). I did not audit the historical diff bodies.
- **I could not verify the 78 chain files the audit saw against the DB's 71 `chain` rows.**
  78 ≠ 71 and I did not chase the 7-file delta; it may be legitimate generated-vs-declared
  split, or duplicates. Unresolved.
- **I did not run `wks/cli metrics` or `wks/cli gaps`.** All corpus numbers above come from
  direct SQL against `db/wks.db`, not from those commands.
- **I could not verify source-registry integrity.** The brief mentions 167 sources in
  `db/sources.json`; the DB `source` table has 513 rows. I did not run
  `tools/build_sources.py` (it mutates `db/sources.json`) and did not reconcile 167 vs 513.
- **I did not determine whether `SECTION DRIFT` on the 37 `DIGEST.md` / 37 `COMPETENCY.md`
  pairs is a generator bug or a stale audit schema.** That needs the spec that
  `audit_taxonomy.py` compares against; I did not read it. It is the largest unexplained
  finding class (74 of 262) and is unresolved.
- **`CONCURRENT WRITES` — inference, not proven.** `db/sources.json` (20:28:29) and
  `db/discovered_sources.json` (20:27:50) changed within ~2 min of my first `skillgen` run.
  I did not read those files per the concurrent-writer rule, and I cannot prove from
  timestamps alone whether another agent wrote them. If another process is mutating this DB
  concurrently, my "logical content unchanged except `last_reviewed`" finding is only valid
  for the window I measured.
- **No git verification.** `git status` in the store root → `fatal: not a git repository`.
  I could not diff the tree to prove no file outside `skillgen`'s write set was touched, so
  "0 files changed" rests on the generator's own `unchanged` output, not on an independent VCS diff.
- **I did not verify quote provenance.** Cites that claims were re-checked against their
  linked sources; `wks/verify_quotes.py` and `wks/verify_sources.py` exist and I did not run them.