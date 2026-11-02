# Authorization testing

Procedure for the authorization boundary — the highest-yield web finding and
the most frequently mis-validated. Classes live in
[`bug-classes/web/authorization/`](../bug-classes/web/authorization/README.md).

## Order

1. **Enumerate identifiers from responses**, not from arithmetic. Every id
   echoed in a payload is a wordlist. Gaps in an otherwise sequential sequence
   reveal a deleted record you can still query.
2. **Object-level** — substitute one id at a time, in every carrier (path,
   query, body, header), holding everything else fixed. Vary nested references
   by fixing one leg and moving the other.
3. **Function-level** — the same check at the endpoint rather than the object:
   authenticated but not permitted.
4. **Vertical** — can a low-privilege subject reach an administrative capability,
   directly or by writing a privilege field onto their own record?
5. **Tenant boundary** — verify the ownership field in the returned payload
   actually differs before reporting cross-tenant impact.

## The evidence rule

Two accounts you control, fully separated. Reading your own second account
proves the boundary is missing without involving anyone else.

A `200` without a second-identity comparison is not a finding. Diff on more
than status: content length, JSON keys, the presence of the other user's
identifiers.

## Common false positives

Public-by-design objects, and own-tenant reads where you and the other user
share an `org_id`. See [false-positives.md](../validation/false-positives.md)
and the *Common False Positives* section of each class page.

## Related

- [idor.md](idor.md)
- [authorization-chains.md](../attack-chains/authorization-chains.md)
- [evidence-requirements.md](../validation/evidence-requirements.md)