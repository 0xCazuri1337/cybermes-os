# Network security classes

The second offensive domain. Reached when the attacker is inside a network, or
when a web foothold becomes one.

## Why this is a DOMAIN and not a third category

The tree has exactly two top-level domains: `web/` and `network/`. Active
Directory is a **sub-specialization of `network/`**, not a domain of its own,
because every AD attack path is reached by network access to a protocol — you
cannot forge a ticket without reaching a KDC. Splitting AD out would give the
same knowledge two homes and force the router to guess which one an objective
meant.

## Structure

```
internal-network/   what is reachable, what answers, what carries you sideways
infrastructure/     the services themselves and the privileges they concede
active-directory/   the directory as a graph: objects, ACLs, and the
                    authentication protocols (Kerberos, NTLM, LDAP) that
                    carry a foothold to domain control
```

## What belongs here

A weakness reachable through network reachability or through a service on a
host: SMB signing, WinRM remoting, DNS zone disclosure, Kerberos delegation,
AD ACL abuse, certificate-template enrollment abuse.

## What does NOT belong here

| Not here | Where it goes instead |
|---|---|
| An HTTP application flaw | `../web/` |
| Cloud identity (Entra ID, AWS IAM, Okta) | out of scope for this version — see `../../../CONTROL/CONTROL.md` |
| A single technique's step-by-step procedure | `methodology/` |
| Relationships BETWEEN classes | `../../attack-chains/` |
| Unverified claims | nowhere — they are rejected, not filed |

## The AD graph

Active Directory is modelled as a graph rather than a list of techniques
(brief §5). The questions that matter are relational:

```
OBJECT → RELATIONSHIP → PERMISSION → WEAKNESS → ACCESS → ESCALATION
```

Who can modify this object? Who can authenticate where? Which permission
creates a path? Every `active-directory/` page is written to answer one of
those, and the cross-page chains live in `../../attack-chains/`.

## Evidence status

Every page here currently renders `Not yet researched.` in its body. The class
definitions below are seeded and their sources are GET-verified across
independent publisher hosts, but **no gated evidence items exist yet**. That is
an honest gap, not knowledge:

```bash
python -m wks.cli domain-health      # declared vs. evidenced, per domain
python -m wks.cli gaps               # what to research next
```

A class page that reads `Not yet researched.` says exactly what it knows. A
page filled with plausible technique prose and no citations is the defect this
whole system exists to prevent.

## Related

- `../../web/` — the other domain; cross-domain chains link the two
- `../../attack-chains/` — how classes combine, including web → internal → AD
- `../../methodology/` — the ordered approach per specialization
- `../../validation/` — what counts as proven
- `../../../CONTROL/rules.md` — the enforceable rules
