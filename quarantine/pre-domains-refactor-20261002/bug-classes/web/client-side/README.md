# Client-side — browser behaviour the server does not control

## What this directory represents

Flaws in state and navigation that live in the browser: what the page does with
data it already trusts, and where it is willing to send the user.

## What belongs inside it

`dom-clobbering.md`, `postmessage.md`, `clickjacking.md` (**canonical**),
`open-redirect.md` (**canonical**), `client-side-prototype-pollution.md`.

## What does NOT belong inside it

- `clickjacking.md` and `open-redirect.md` **also** appearing under
  `../miscellaneous/` — those are pointer stubs back to this directory
- Script injection into markup → `../xss/`
- CORS and cache-deception → `../miscellaneous/`

## How children are organised

By what the attacker manipulates: the **DOM namespace** (`dom-clobbering.md`),
the **message channel** (`postmessage.md`), the **rendered UI layer**
(`clickjacking.md`), the **navigation target** (`open-redirect.md`), or the
**object model** (`client-side-prototype-pollution.md`).

## Related bug classes

`../request-forgery/csrf.md` (the origin is assumed),
`../xss/` (code runs rather than state being confused).

## How new entries should be added

Ask what browser mechanism is abused. If the server response is wrong, it is not
client-side.
