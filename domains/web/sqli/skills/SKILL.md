---
name: sqli-hunting
description: Use when hunting SQL Injection in a web target. Ordered prerequisites, signals, techniques, validation bar and false-positive rules.
---

# SQL Injection — hunting skill

<!-- GENERATED from db/wks.db by wks/skillgen.py. DO NOT HAND-EDIT.
     Edit the rows (or ingest better research) and re-run:
     python -m wks.skillgen -->

> surface `web` · CWE — · OWASP —
> evidence: 1 items, 0 supported, 0 FP rules, 0 chains
> maturity: **researching** — missing: methodology, items, supported_items, fp_rules, chain


## Techniques (what to change)

- The endpoint returned a different number of rows for a true predicate than for the corresponding false predicate. The difference was stable across repeated requests, which proves the boolean condition is evaluated by the database rather than by the application. This confirmed a blind SQL injection vulnerability.  _(merged 1 duplicate row(s))_ _(unverified)_
  - Sources: <https://example.com/advisories/blind-sqli-search>


## Hunt procedure

1. Baseline the endpoint, then append a single quote and compare the response or status against the baseline; a 500 or syntax error is a signal, not proof.
2. Confirm boolean pairs (' AND 1=1-- vs ' AND 1=2--) differ in body or length.
3. Enumerate with UNION SELECT NULL,NULL... until the column count matches; use sqlmap -u <url> --batch only to corroborate a hand-proven injection.
4. Never prove blind injection with a timeout alone; use a time-based payload repeated several times to separate jitter from a real delay.

### What counts as proof

- Two responses that differ in a way the CONTROL did not, produced by a single changed variable.
- An invariant the application is supposed to hold, observed broken.
- A second independent confirmation, or an explicit statement that this is single-account evidence only.

> Ordered prerequisites, the validation bar and the false-positive rules below are the authority: this block is the mechanics, those are the standard.
---
Full class document: `domains/web/sqli/knowledge/DIGEST.md` · retrieve more with `python -m wks.cli search "<query>" --class-id sqli`

---
Runbook: [`HUNT.md`](HUNT.md) — every promoted technique mapped to an executable procedure with the observables to record.
