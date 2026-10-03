# cybermes

**Cyber Security knowledge + Hermes agent runtime.**

An evidence-gated knowledge store for offensive-security research, plus the orchestration
layer that runs learning loops over it. Every claim is bound to a verbatim quote from a
real source; claims that cannot be verified never enter the store.

> **Scope.** This repository contains research infrastructure and knowledge only. It
> performs **no active testing against any target** — there is deliberately no scanning,
> fuzzing, or exploitation code (`config.RESEARCH_ONLY = True`). Active testing is a
> separate activity that requires explicit, user-provided authorization.

---

## What's in here

| Path | What it is |
|---|---|
| `wks/` | Knowledge system core: ingest, gating, retrieval, FTS5, migrations |
| `orch/` | Orchestration: DAG scheduler, agent workers, gates, final gate |
| `tools/` | Generators and utilities (incl. `tools/taxonomy/` which renders `domains/`) |
| `domains/` | The organising boundary — one self-contained folder per bug class |
| `eval/` | Exam harness + graders (`eval/exams/*/GRADE.json`) |
| `db/wks.db` | **Canonical store.** SQLite + FTS5. The single source of truth |
| `research/pending/` `incoming/` | Pre-gate synthesized knowledge (subagent output, *not* yet knowledge) |
| `CONTROL/` | The constitution: invariants, enforceable rules, operator grammar |
| `validation/` `reporting/` `learning/` | Gates, severity, the learning loop |

At commit: **~67k lines of Python** across `wks/`, `orch/`, `tools/`, `eval/`, and
**625 Markdown knowledge documents** across `domains/` and `CONTROL/`.

## Knowledge at a glance

| Metric | Count |
|---|---|
| Knowledge items | 1,803 |
| Bug classes | 70 |
| Sources | 808 |
| Attack chains | 79 |

## Quick start

```bash
git clone <this-repo> cybermes
cd cybermes

# Point the system at its own tree
export WKS_ROOT="$(pwd)"          # native Windows: C:/path/to/cybermes

# Verify the store is healthy
python -m wks.cli selftest
python -m wks.cli metrics
python -m wks.cli gaps

# Apply any pending migrations (idempotent)
python -m wks.migrate
```

Run the orchestration gates:

```bash
python -m orch.cli gate
python -m orch.cli stats
```

> Both `wks` and `orch` read their root from `WKS_ROOT` (native path on Windows).
> If `metrics`/`gaps` return empty results, `WKS_ROOT` is almost certainly wrong.

## How the knowledge gate works

1. A source is fetched and pinned.
2. Claims are extracted; each must carry a **verbatim quote** from that source.
3. The quote is re-verified against the live page. A **404 means the page moved or was
   rewritten — it is never treated as fabrication**; the resolver searches successors and
   pinned release tags.
4. Corroboration and conflict resolution run before an item is admitted.
5. Items failing any gate stay in `research/pending/` and never enter `db/wks.db`.

## Documentation

- [`CONTROL/CONTROL.md`](CONTROL/CONTROL.md) — the constitution (invariants I1–I10)
- [`CONTROL/rules.md`](CONTROL/rules.md) — enforceable rules, each with how it is checked
- [`CONTROL/OPERATOR.md`](CONTROL/OPERATOR.md) — the command grammar
- [`CONTROL/state.md`](CONTROL/state.md) — live state and next work
- [`RAG_ARCHITECTURE.md`](RAG_ARCHITECTURE.md) — retrieval architecture
- [`docs/WKS-README.md`](docs/WKS-README.md) — the knowledge system's own original README

## Regenerating derived content

`domains/` is **generated** by `tools/taxonomy/` — never hand-edited. After an ingest,
re-run the projection and re-check the tree:

```bash
python -m wks.domains --check    # must print: tree check: 0 problem(s)
python -m wks.skillgen            # regenerates SKILL.md
```

## What is deliberately **not** in this repository

Third-party and licensed material is mirrored locally but never committed:

- `research/corpus/` — HTB / TryHackMe writeups and official PDFs (others' IP)
- `research/tmp/` — raw mirrors of third-party specs (OpenID Connect Core, cheat sheets)
- `cache/` — fetched page cache (NVD, Notion, reference sites)
- `quarantine/` — quarantined pre-refactor material, retained offline
- `db/wks-pre-*.db` — 21 historical DB snapshots (118 MB); superseded by `db/wks.db`

## License

Private repository. No license is granted for redistribution. Third-party material
mirrored locally remains the property of its original authors.