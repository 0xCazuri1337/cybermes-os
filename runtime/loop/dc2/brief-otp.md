# Research task — otp

The `otp` class is BELOW the maturity threshold and needs
**1 more gate-passing item(s)**. It currently has
11 active items and 11 supported.

## Your job
Produce **1 NEW items** for class `otp`.
Each must be independently verifiable and cite TWO INDEPENDENT PUBLISHER ORGS.

Do NOT:
- re-state claims the corpus already holds (read the digest first)
- paraphrase one mechanism into several items
- write a claim you cannot cite a verbatim quote for
- add course-catalogue prose ("In this module we will cover...") — that is
  `BOILERPLATE_DISPROOF` and is held

## Read these before writing (they define the contract)
- `runtime/loop/WORKER_BRIEF.md` — the item schema and hard rules
- `domains/*/otp/knowledge/DIGEST.md` — what is ALREADY known

## Kind
Prefer `technique`, `test`, `variant` or `signal` items — those are what feed the
hunting runbooks. An `fp_rule` does NOT help this class: it already passes the
fp_rules check.

## Output
Write ONE file: `research/incoming/dc2-otp.json`
Last line: `// COMPLETE <n>`

Then run the acceptance test yourself and report the verdict verbatim:
    cd C:/Users/Administrator/.hermes/cyber
    python -m wks.ingest research/incoming/dc2-otp.json --dry
A rejection is information — report it, do not hide it. Never pass `--no-verify`.
