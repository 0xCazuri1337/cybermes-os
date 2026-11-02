# Quantifying hunt coverage before claiming anything is exhausted

Use when you are about to say a hunt is complete, or when a "resume / don't stop"
pushback arrives. The technique that resolves both: **compare discovered inventory
against probed inventory, per root.**

## The coverage assertion

```bash
# discovered vs actually probed, grouped by the in-scope root
python - <<'PY'
import collections
probed = {l.strip().lower() for l in open("evidence/probed.txt") if l.strip()}
allh   = {l.strip().lower() for l in open("recon/passive_hosts.txt") if l.strip()}
roots  = ("af.mil","disa.mil","health.mil","socom.mil","yellowribbon.mil",
          "dcma.mil","dla.mil","dtic.mil","dau.mil","dtra.mil","army.mil",
          "navy.mil","marines.mil","uscg.mil","ng.mil","osd.mil","dds.mil",
          "pentagon.mil","spaceforce.mil")
def root(h):
    p = h.split(".")
    for i in range(len(p)-1, 0, -1):
        cand = ".".join(p[i-1:])
        if cand in roots: return cand
    return "(other)"
d, p_ = collections.Counter(map(root, allh)), collections.Counter(map(root, probed))
print(f"{'root':<22}{'discovered':>11}{'probed':>8}")
for r in sorted(d, key=lambda x: -d[x]):
    print(f"{r:<22}{d[r]:>11}{p_.get(r,0):>8}")
print(f"{'TOTAL':<22}{sum(d.values()):>11}{len(probed):>8}")
PY
```

## Reading the result

A root with `discovered >> probed` is the whole ballgame. On a real engagement the
first pass enumerated 5 of 17 in-scope roots; re-running passive enumeration over the
remaining 12 returned **more than four times** the original inventory and produced the
session's only reportable finding. The "exhausted" verdict was an artifact of never
having measured the denominator.

**Passive enumeration is free** — CT logs and DNS recursion cost the target zero
requests — so an un-enumerated root is never an acceptable reason to stop. Enumerate
every in-scope root before any coverage claim.

## Keep the denominator honest

- Count **per root**, never a single pooled number. A pooled number hides an untouched
  root behind a large tested one.
- Distinguish `UNREACHABLE` from `not vulnerable`. A hostname that does not resolve
  from your egress is **inconclusive**, and recording it as a negative finding
  inflates your coverage and deflates your honesty at the same time.
- Count `BLOCKED_EDGE` separately from `REFUSED_AUTH`. A CDN/WAF block on your egress
  is a fact about your network, not about the application.
- State the fraction: `400 / 1,296 hosts triaged (31%), ranked by signal, not random`
  is honest; "1,296 hosts triaged" when 400 were is not.

## When a pushback arrives

Recompute this table first, in the same turn, before proposing any next step. It
converts "you're stopping early" from an assertion into a specific list of untouched
roots — and the specific list is what you can go hunt immediately.