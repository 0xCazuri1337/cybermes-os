# derived/

One generated page per registered class, produced by `python -m wks.methodgen`
from `db/wks.db`. **Do not hand-edit** — edit the db rows and regenerate
(rule R11 in [`CONTROL/rules.md`](../../CONTROL/rules.md)).

The registry is the `bug_class` table in `db/wks.db`, not a JSON file. An
earlier revision of this README named `competency_registry.json`; that file was
removed in the Selection-C rework and the registry moved into the canonical db.
Paths recorded in `bug_class.methodology` are **repo-relative**
(`methodology/derived/<id>.md`), so the tree can be relocated; they resolve
against `config.root()`, which honours `HERMES_CYBER_ROOT`.

These are class-aligned views. The canonical vulnerability pages live in
[`bug-classes/`](../../bug-classes/README.md).

## Two pages per class

`methodology/` also holds hand-authored procedure pages (`idor.md`,
`authorization.md`, `recon.md`, …) that describe the ordered approach for a
class. Where both exist for one class, the hand-authored page is the
**canonical** one and the generated view is its evidence-linked derivative.
`check_methodology_coverage.py` prints every such overlap as `DUPLICATED` so it
stays a visible decision rather than a silent second source of truth.

## Coverage

```bash
python methodology/scripts/check_methodology_coverage.py
```

Maps class id → procedure by reading `bug_class.methodology`, and reports
`covered / gaps / broken mappings / DUPLICATED / NON-PORTABLE`. An unreadable
registry exits non-zero rather than printing "all clear" — a silent zero is the
failure the check exists to catch.

There is deliberately **no mapping literal** in that script: the edge is
derived from the canonical db on every run, because a hand-maintained mirror of
database state goes stale silently.