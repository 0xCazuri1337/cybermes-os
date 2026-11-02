# scripts/

The checkers and generators that make claims about this tree falsifiable.
Nothing here is hunting knowledge — these are the tools that decide whether the
knowledge base is telling the truth about itself.

| Script | Purpose |
|---|---|
| `check_methodology_coverage.py` | competency id → procedure coverage; reports `covered / gaps / broken` |
| `taxonomy_spec.py` | **the tree definition** — add a class here |
| `build_taxonomy.py` | schemas, the db→page renderer, `CLASS_HOME` |
| `taxonomy_write.py` | writes the tree; `--check` verifies without writing |
| `audit_taxonomy.py` | rule 9 audit: one canonical home, no dead pointers, no orphaned evidence |

## The pattern

A generator, not hand-written files. Rule 5 (one structure) and rule 8
(extensible without restructuring) are both claims that only stay true if
something checks them:

```bash
python tools/taxonomy/taxonomy_write.py           # write
python tools/taxonomy/taxonomy_write.py --check   # drift, exit 1
python tools/taxonomy/audit_taxonomy.py           # rule 9, exit 1 on findings
```

## Two lessons encoded here

**A hand-maintained mirror of database state goes stale silently.** Both
`RESEARCHED` (which classes render from the db) and `STEM_TO_CLASS` (filename →
class id) were literals that duplicated information already in `CLASS_HOME`. A
background cycle ingested 51 items mid-session and three researched classes
rendered as empty skeletons while their evidence sat in the corpus. Both are now
derived from the db and from `CLASS_HOME` at run time.

**The renderer asserts its own coverage.** `taxonomy_write.py` refuses to write
when a researched class has no canonical page, and `audit_taxonomy.py` fails on a
dead pointer, a duplicate canonical page, or schema drift. A checker that only
ever passes protects nothing — both were tested by injecting a duplicate, a dead
pointer and a deleted section, and all three were caught.