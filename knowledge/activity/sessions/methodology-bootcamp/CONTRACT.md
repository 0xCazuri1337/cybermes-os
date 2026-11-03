# Shared contract for mastery-artifact children

You are producing **competence artifacts** for ONE vulnerability class, from the
local corpus only. Read this file first; it is the same for every child.

## Environment

```bash
export WKS_ROOT="C:/Users/Administrator/.hermes/cyber"
export PYTHONPATH="$WKS_ROOT"
cd "$WKS_ROOT"
python -m wks.cli show <class_id>        # the class's items
python -m wks.cli metrics                # corpus totals
python -m wks.mastery gates              # the 12 gate definitions
```

Use `C:/Users/...` forward-slash native paths for python. Never hardcode an
absolute path in your output; paths resolve relative to WKS_ROOT.

## The 10 gates you may close (2 are forbidden to you)

You may close these 10 gates: `explain`, `recognize`, `hypothesize`, `test`,
`interpret`, `validate`, `reject_fp`, `generalize`, `chain`, `failure_analysis`.

You may **NOT** close `black_box` or `transfer`. Those are `EXAM_GATES` and the
engine raises `SystemExit` unless the evidence file is literally named
`GRADE.json` produced by grading a real solver report against a lab. Attempting
them wastes a cycle. Do not create GRADE.json files.

## Byte floors — a gate REFUSES below these

| gate | min bytes | gate | min bytes |
|---|---|---|---|
| explain | 200 | validate | 200 |
| recognize | 150 | reject_fp | 150 |
| hypothesize | 200 | generalize | 200 |
| test | 200 | chain | 250 |
| interpret | 200 | failure_analysis | 250 |

Padding does NOT defeat the check: the engine also rejects a file whose 3-letter+
tokens number 2 or fewer distinct words, and rejects one opening with `TODO`,
`TBD`, `stub`, `placeholder`, `N/A`, `...`. Write real reasoning prose.

## Record the gates yourself

```bash
python -m wks.mastery record <class_id> <gate> --evidence learning/sessions/methodology-bootcamp/<class>/<gate>.md
```

Write your artifacts into `learning/sessions/methodology-bootcamp/<class_id>/`.
Each gate is its own file. Then record each gate.

## THE INTEGRITY REQUIREMENT — this is what makes the artifact real

Every technical claim in your artifact must be traceable to a corpus item.
For each mechanism, signal, technique, test, disproof and FP rule you write,
name the `item_key` it came from in an inline citation like `[sqli.technique.
union-select]`.

**Before you finish, verify every cited item_key exists in the db and is
promoted.** Write and run this checker — it is the acceptance test. It is
maintained centrally, so prefer running the central one:

```bash
python tools/w13_citation_audit.py <class_id>     # canonical; exit 1 on any problem
```

It prints `problems=0` on a clean artifact and exits 1 on any fabricated,
cross-class or unpromoted citation. It matches ANY item-key-shaped token and
resolves it against the db, so a citation with the wrong class prefix is
REPORTED rather than silently ignored.

The regex used to be scoped to your own class prefix and a citation with a
foreign prefix was never matched — a clean report that had simply never looked
at it. The central audit fixes that. **Its three defect classes were each
proven live** against a tampered copy: fabricated key, cross-class key, and
unpromoted key all exit 1.

Note `validation_state` lives in the `quality` table, and `item`'s PK is `id`,
not `item_id` — the original template joined `quality.item_id = item.item_id`,
which raises `OperationalError` rather than reporting. The central audit uses
`quality.item_id = item.id`.

## The 10 gates, and what each artifact must contain

Read the definitions from `python -m wks.mastery gates` and honour them
literally. In particular:

- **explain** — the chain: attacker input -> parser -> normalisation ->
  validation -> trust decision -> internal operation -> observable result, and
  **the exact invariant that fails**. A class name is not an explanation.
- **recognize** — the OBSERVATIONS that justify investigating this class. Not
  the class description: what do you SEE.
- **hypothesize** — each hypothesis keyed to a signal you actually observed, and
  each **falsifiable** (name the observation that would refute it). A claim is
  not a hypothesis.
- **test** — an ORDERED plan, each step with its **expected information gain**.
- **interpret** — a table: result -> meaning -> next action. Include the
  ambiguous and negative results, which are where hunts actually die.
- **validate** — the request/response pair shape that proves impact, and what
  does NOT count as proof.
- **reject_fp** — the misleading cases and **the disproof test for each**. Every
  curated item carries a disproof; surface them.
- **generalize** — common, uncommon and defensive variants.
- **chain** — prerequisites, transition, escalation, and the **blocker** at each
  step.
- **failure_analysis** — expected vs actual vs the wrong assumption vs the next
  test, from a real failure mode of this class.

## Rules you must not break

- **Write your artifact files in ONE `write_file` call each.** A stub first
  write poisons the path for later writes. Use `patch` to revise after.
- Refining your draft after seeing it is GOOD — report it if you do. The cost of
  a second write to an EXISTING file is zero.
- Your summary is a self-report and carries no weight. The db and the bytes on
  disk are the evidence.
- Finish by printing `// COMPLETE <class> <gates_closed>` as the last line.
  Do not rely on file existence as the completion signal.
- Do not modify any file outside your own class directory. Do not run
  `wks.ingest`, `wks.cli gate`, or anything that writes the corpus.