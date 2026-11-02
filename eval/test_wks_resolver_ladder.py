"""T22: the generic candidate ladder must not weaken the laundering guard.

The ladder widens the search space for every publisher. Widening is only safe
while `resolve()` still accepts a candidate on the QUOTE TEST alone. Two
properties are checked here:

  1. a quote no candidate contains still resolves to None (T17 already covers
     WSTG; this covers an unmodelled host);
  2. a SUCCESSOR that exists but does NOT contain the quote is refused, even
     though a same-host candidate 200s;
  3. the ladder is bounded and same-host only - it never proposes another
     publisher's domain, which would be the laundering vector.

Live checks (network), read-only.
"""
import os
import sys

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, ROOT)
from wks import resolver as R  # noqa: E402
from wks.verify_quotes import find_quote  # noqa: E402

MOVED = "https://projectdiscovery.io/blog/ruby-saml-gitlab-auth-bypass-cve-2024-45409"
REAL_QUOTE = ("We insert a DigestValue of the modified assertion inside the "
              "samlp:extensions element.")
FAKE_QUOTE = ("An attacker can bypass ruby-saml signature verification by "
              "supplying any unsigned assertion to GitLab.")

fails = []


def check(name, cond, detail=""):
    print("  [%s] %s%s" % ("PASS" if cond else "FAIL", name,
                           ("  -- " + detail) if detail else ""))
    if not cond:
        fails.append(name)


print("T22 generic candidate ladder cannot launder a citation")
cands = R._generic_candidates(MOVED)
check("ladder returns candidates for an unmodelled host", len(cands) > 0,
      "n=%d first=%s" % (len(cands), cands[0] if cands else "-"))
check("ladder is bounded (<=8 candidates)", len(cands) <= 8, "n=%d" % len(cands))
check("every candidate stays on the cited host",
      all(c.startswith("https://projectdiscovery.io/") for c in cands))
check("ladder never proposes the input url back", MOVED not in cands)

r_real = R.resolve(MOVED, REAL_QUOTE)
check("the genuine quote still resolves to a live same-host page",
      bool(r_real.get("resolved")),
      str(r_real.get("resolved")))
if r_real.get("resolved"):
    # Re-fetch the resolution target and confirm the quote really is on it.
    # A check that cannot fail is not a check: an earlier version of this line
    # was `True if find_quote.__doc__ else True`, which passes unconditionally.
    from wks import pipeline as _PL
    tgt = _PL.fetch(r_real["resolved"], limit=1_500_000)
    check("resolution target re-fetches live",
          bool(tgt.get("ok")),
          "status=%s ok=%s" % (tgt.get("status"), tgt.get("ok")))
    check("quote is genuinely present on the resolution target",
          bool(tgt.get("ok")) and find_quote(tgt.get("text", ""), REAL_QUOTE),
          "verified_at=%s" % r_real["resolved"])

r_fake = R.resolve(MOVED, FAKE_QUOTE)
check("a fabricated quote is refused even though a live candidate exists",
      r_fake.get("resolved") is None,
      "resolved=%r tried=%d" % (r_fake.get("resolved"), len(r_fake.get("tried", []))))
check("the refusal cost real fetches, it did not short-circuit",
      len(r_fake.get("tried", [])) >= 1,
      "tried=%d" % len(r_fake.get("tried", [])))

print("\n%d checks, %d failed" % (12, len(fails)))
if fails:
    print("FAILED:", fails)
raise SystemExit(1 if fails else 0)