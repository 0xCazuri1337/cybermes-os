# Client-side — browser behaviour the server does not control

## What this directory represents

Flaws in state and navigation that live in the browser: what the page does with
data it already trusts, and where it is willing to send the user.

## What belongs inside it

`../../../topics/client-side/dom-clobbering.md`, `../../../topics/client-side/postmessage.md`, `../../../clickjacking/CLASS.md` (**canonical**),
`../../../open_redirect/CLASS.md` (**canonical**), `../../../topics/client-side/client-side-prototype-pollution.md`.

## What does NOT belong inside it

- `../../../clickjacking/CLASS.md` and `../../../open_redirect/CLASS.md` **also** appearing under
  `../miscellaneous/` — those are pointer stubs back to this directory
- Script injection into markup → `../xss/`
- CORS and cache-deception → `../miscellaneous/`

## How children are organised

By what the attacker manipulates: the **DOM namespace** (`../../../topics/client-side/dom-clobbering.md`),
the **message channel** (`../../../topics/client-side/postmessage.md`), the **rendered UI layer**
(`../../../clickjacking/CLASS.md`), the **navigation target** (`../../../open_redirect/CLASS.md`), or the
**object model** (`../../../topics/client-side/client-side-prototype-pollution.md`).

## Related bug classes

`../request-forgery/csrf.md` (the origin is assumed),
`../xss/` (code runs rather than state being confused).

## How new entries should be added

Ask what browser mechanism is abused. If the server response is wrong, it is not
client-side.
