# Hunt card — password_attacks

1 promoted technique/test items, each mapped to an executable procedure derived from its shape.

## password_attacks.technique.spray_across_accounts_to_avoid_lockout

**Claim.** Password spraying succeeds where password brute force fails because it inverts the two axes — one password against many accounts — so per-account lockout thresholds never trigger while the total attempt count stays high.

**Procedure — Race / TOCTOU attempt** (shapes: race_condition)

1. Identify the check and the use as TWO separate operations, and measure the gap between them.
2. Fire many parallel attempts (tens to hundreds) so at least one lands inside the window.
3. Vary ONLY the timing; the payload and session stay fixed.
4. Report a rate, not a single success: N successes in M attempts both proves the window and tells the reader whether it is practical to exploit.

**Record:** attempts, successes, success rate, window size if measurable
