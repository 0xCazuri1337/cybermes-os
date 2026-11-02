# XSS — attacker data interpreted as script

## What this directory represents

Attacker-controlled data reaching an execution context in another user's
browser without neutralisation.

## What belongs inside it

`../../../xss/topics/reflected-xss.md`, `../../../xss/topics/stored-xss.md`,
`../../../xss/topics/dom-xss.md`, `../../../xss/topics/blind-xss.md`,
`../../../xss/topics/mutation-xss.md`, `../../../xss/topics/framework-xss.md`.

(These are the XSS sub-documents. Under the merged tree they live in the `xss`
bundle's `topics/`, not beside this README — the generator renders them there
from `SUBDOCS`, and `tools/fill_subdocs.py` fills them from gated db items.)

## What does NOT belong inside it

- Script execution on the *server* → `../server-side/`
- DOM clobbering and postMessage → `../client-side/` (they change behaviour,
  not parsing)
- XSS chained into session theft or CSRF-token exfiltration →
  `../../attack-chains/xss-chains.md` — **not** a new class

## How children are organised

By **how the payload arrives and where it lands**: reflected vs stored vs DOM
sink, plus the two variants that break naive filters (mutation) and naive
escaping (framework-specific contexts).

## Related bug classes

`../client-side/open-redirect.md` and `../request-forgery/csrf.md` are the two
standard chain partners.

## How new entries should be added

By sink and delivery. A new framework context is a section in
`../../../xss/topics/framework-xss.md` unless it changes the detection method.
