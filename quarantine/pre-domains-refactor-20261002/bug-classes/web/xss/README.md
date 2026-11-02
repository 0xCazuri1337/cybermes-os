# XSS — attacker data interpreted as script

## What this directory represents

Attacker-controlled data reaching an execution context in another user's
browser without neutralisation.

## What belongs inside it

`reflected-xss.md`, `stored-xss.md`, `dom-xss.md`, `blind-xss.md`,
`mutation-xss.md`, `framework-xss.md`.

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
`framework-xss.md` unless it changes the detection method.
