# CONTROL.md → moved

The control surface is now a directory: [`CONTROL/`](CONTROL/).

    CONTROL/README.md     provenance map, precedence, superseded material
    CONTROL/CONTROL.md    constitution (invariants I1-I10)
    CONTROL/rules.md      19 enforceable rules, each with how it is checked
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