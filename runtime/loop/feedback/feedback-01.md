# Feedback to worker — after rounds 1-3 (2026-10-04)

This file is the loop's memory. The NEXT round's prompt is built from it, not
from the template. Every point below is measured, not assumed.

## R1 — silent no-op (exit 0, zero work)
The multi-line brief passed as an argv argument arrived as **only its first
line**. The worker replied "Your message arrived as just the title", ran `ls`,
and exited 0. The driver nearly recorded this as a successful round.
- LESSON: an exit code is not evidence. The driver now asserts the expected
  ARTIFACT exists before recording anything.
- LESSON: on this host, pass the brief as a FILE and send a one-line
  instruction naming it.

## R2 — real research, killed by a permission wall
The worker read the brief, probed live URLs (correctly finding
`cheatsheetseries.owasp.org/cheatsheets/Path_Traversal.html` = **404** and
`portswigger.net/web-security/request-smuggling` = **200**), read the gate
source to understand the rules, and then died on
`Write .../AppData/Local/Temp/opencode/fc.py failed`.
- 87 seconds of genuinely useful work, discarded, because of a write outside
  the project tree.
- LESSON: the worker writes ONLY inside the project root. Stated in the brief
  now, before the assignment rather than after the failure.

## R3 — in flight at the time of writing
No verdict yet. If it also fails, the fallback is §1 of
`runtime/loop/HANDOFF-PROTOCOL.md`: the in-process executor
(`python -m orch.cli run --execute`) already produces gated evidence without any
external CLI, and the loop keeps working with OpenCode as a supplement.

## WHAT THE WORKER IS GOOD AT (keep doing)
- Probing URL status before planning an item. It found a real 404 unprompted.
- Reading the gate source to learn the actual rules instead of guessing them.

## WHAT TO WATCH
- Budget its time. R2 spent most of its budget reading `wks/*.py`. Reading
  `quality.py` is enough; the rules are also in the brief.
- Write the intake file EARLY and append to it, so a crash mid-research still
  leaves partial evidence. A file with 2 valid items beats no file.

## RECURRING GATE REJECTION REASONS (from the corpus, for the worker to avoid)
| Reason | How to avoid it |
|---|---|
| `INSUFFICIENT_PUBLISHER_HOSTS` | 2 distinct publisher ORGS, not 2 pages |
| `QUOTE_NOT_FOUND_ON_CITED_PAGE` | copy the span character-for-character; a paraphrase is a rejection |
| `BOILERPLATE_DISPROOF` | the disproof must name a specific failing condition |
| `OFF_CLASS_TOPIC` | the item must genuinely belong to the class it is filed under |
| `INSUFFICIENT_SOURCES` | >= 2 source entries, each a real fetched URL |