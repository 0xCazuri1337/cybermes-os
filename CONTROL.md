# CONTROL.md → moved

The control surface is now a directory: [`CONTROL/`](CONTROL/).

    CONTROL/README.md     provenance map, precedence, superseded material
    CONTROL/CONTROL.md    constitution (invariants I1-I32)
    CONTROL/rules.md      45 enforceable rule rows (42 unique ids), each with how it is checked
    CONTROL/state.md      live state: phase, architecture, defects, next work
    CONTROL/OPERATOR.md   the command grammar

This file previously held a second, conflicting control surface. Both previous
versions are preserved verbatim under `CONTROL/superseded/`.

It also pointed at a `CONTROL/` directory that did not exist: the pointer was
written on 2026-10-01T18:38:51Z and the directory it named was never created,
so the control surface was unreachable from the only file advertising it.

Repaired 2026-10-02; the previous version is preserved verbatim at
`CONTROL/superseded/CONTROL.md.e2317629.md`.

That repair created the directory but left one dangling promise: this file
listed a `CONTROL/README.md` provenance map that was never written, so the map
a new engineer is told to read first did not exist. It is written now
(2026-10-02), along with this correction: the rules count was stated as 13
while `CONTROL/rules.md` had grown to R19 without this pointer being updated.

The count drifted again afterwards and was corrected a second time
(2026-10-31): `CONTROL/rules.md` now carries 40 rows, and three ids (R23, R24,
R25) each name two genuinely distinct rules, so there are 37 unique ids. The
pointer above now states both numbers, because "40 rules" would be as
misleading as "19 rules" was — a rule that cannot be cited unambiguously is
not usable, and the id collision is a live defect tracked as FM-10 in
`research/recon/process_review.md`.

Corrected a third time (2026-11-01, Goal-chain audit): two rules were added —
R39 (the source registry is read from one file by every reader) and R40 (the
ownership authorizer is installed when the database is opened). The table now
carries 45 rows and 42 unique ids. The three colliding ids are unchanged: the
collision is FM-10, and renumbering it here would have broken the citations
that already name the second R23/R24/R25 (for example `CONTROL/OPERATOR.md`
cites R23 for the builder-page rule).