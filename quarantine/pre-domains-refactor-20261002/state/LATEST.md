# WKS cycle run-20261002T000903460595Z

## Inspected
- classes: 15, items: 104
- weakest: `authz` (priority 215, missing items, supported_items, fp_rules, chain, skill)

## Selected task
- `seed.authz.research` — Research and gate the first evidence-backed items for authz
  - expected artifact: >=5 items with >=2 publisher hosts each
  - evidence required: None

## Open conflicts (unresolved, surfaced)
- `race` fabricated-evidence: A: A discount, coupon or promo parameter in a request body is a / B: cited quote not present on page: ['https://portswigger.net/w
- `race` fabricated-evidence: A: Reject the finding if a single-threaded baseline reproduces  / B: cited quote not present on page: ['https://portswigger.net/w
- `idor` fabricated-evidence: A: Platform or gateway authorization keyed on method and conten / B: cited quote not present on page: ['https://portswigger.net/w
- `idor` fabricated-evidence: A: The same object is often reachable through an unvalidated al / B: cited quote not present on page: ['https://docs.github.com/e
- `idor` fabricated-evidence: A: A 404 for a foreign id is a pass, not a near-miss; and an id / B: cited quote not present on page: ['https://cheatsheetseries.

## Quality metrics
- items: 103 | promoted: 103 (100.0%)
- unsupported-claim rate: 0.0%
- duplicate rate: 0.0% | stale rate: 0.0%
- items with a disproof clause: 100.0%
- blocked on single host: 0
- classes mature: 0/15 (0.0%)
- FP rules: 4 | chains: 4 | open conflicts: 21
- retrieval probe hit rate: 87.5% (7/8)

## Changed this cycle
- re-gated corpus: 103 promoted, 0 rejected
- updated class documents: ssrf, jwt, sqli, xss
- updated skills: jwt, sqli, ssrf, xss
- regenerated methodology: 4 file(s)
- generated 10 follow-up tasks

## Remaining gaps
- not mature: authz, bizlogic, csrf, deser, mass_assign, path_traversal, ssti, ssrf, jwt, sqli, xss, graphql, idor, oauth, race