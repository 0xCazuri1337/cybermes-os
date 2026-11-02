# Miscellaneous — real classes with no better home

## What this directory represents

Genuine vulnerability classes that do not belong to any domain directory above.
This is a small directory by design: it is a staging position, not a dumping
ground.

## What belongs inside it

`cors.md`, `cache-deception.md`, `information-disclosure.md` — and **pointer
stubs only** for classes that already have a canonical home:

- `clickjacking.md` → `../client-side/clickjacking.md`
- `open-redirect.md` → `../client-side/open-redirect.md`

## What does NOT belong inside it

A second copy of anything. If a class is listed here **and** has a canonical
home, the file here must be a stub that links. Duplicated vulnerability
knowledge is the specific failure this taxonomy is built to prevent.

## How children are organised

Canonical files and stubs are visually distinct: a stub contains only a
canonical-path line and a one-line reason.

## Related bug classes

`information-disclosure.md` is the sink most chains terminate in; see
`../authorization/idor.md` for the case where the disclosure is the finding.

## How new entries should be added

Only after checking all nine domain directories. Record here why no domain fit.
A class that fits a domain moves there and its stub is deleted.
