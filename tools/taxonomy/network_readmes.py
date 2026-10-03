"""README bodies for the NETWORK branch of the taxonomy tree.

Added for the same reason `web` and `api` have one: `tools/audit_refs.py`
(R22) reports every canonical page that nothing links to as an ORPHAN. The WEB
branch was referenced from its parent README; the NETWORK branch had no such
entry, so all 25 new pages were reported as unreachable. That is a real
navigability defect, not a checker artefact — a 25-page branch nothing points
at is a map no one can walk.

These are NAVIGATIONAL only, exactly like their WEB counterparts: what the
directory is, what belongs in it, what does not, and how it relates to the rest
of the tree. They state no technical claim, so they need no evidence and cannot
go stale the way a prose claim does.
"""

NETWORK_README = """# Network security classes

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
"""

SPEC_READMES = {
    "internal-network": """# Internal Network classes

**Specialization of `../` — Internal Network.**

What is reachable, what answers, and which protocol carries you from one host
to the next. Classes here are about *reachability and movement*, not about the
configuration of the service itself.

| Class | What it covers |
|---|---|
| [`internal-recon.md`](internal-recon.md) | host and service discovery inside a network; naming and addressing as inference |
| [`service-enumeration.md`](service-enumeration.md) | banner/version discovery and what it selects |
| [`lateral-movement.md`](lateral-movement.md) | the choice among protocols available between two hosts |
| [`tunneling-pivoting.md`](tunneling-pivoting.md) | carrying one protocol inside another to reintroduce forbidden reachability |
| [`segmentation-analysis.md`](segmentation-analysis.md) | whether the claimed trust boundaries are real |

Service *configuration* lives one level up in [`../infrastructure/`](../infrastructure/),
which asks a different question: not "can I reach it" but "what does its own
configuration concede".
""",
    "infrastructure": """# Infrastructure & Host Service classes

**Specialization of `../` — Infrastructure.**

The services themselves, and the privileges their own configuration concedes.
These classes assume reachability and ask what the service does about it.

| Class | What it covers |
|---|---|
| [`exposed-services.md`](exposed-services.md) | administrative protocols reachable from where they should not be |
| [`exposed-rmm.md`](exposed-rmm.md) | RMM agents installed to bypass network controls |
| [`smb.md`](smb.md) | signing, null/guest sessions, named pipe coercion |
| [`winrm.md`](winrm.md) | WSMan and PowerShell remoting as movement *and* privilege |
| [`rdp.md`](rdp.md) | NLA, session hijacking, credential reuse |
| [`ldap-enumeration.md`](../../active-directory/ad_ldap/knowledge/CLASS.md) | directory structure as extraction |
| [`dns-enumeration.md`](../../infrastructure/dns_enum/knowledge/CLASS.md) | zones that enumerate the network without touching it |
| [`service-configuration.md`](../../infrastructure/service_enumeration_detail/knowledge/CLASS.md) | protocol configuration as the root cause behind the rest |

Windows and Linux host-level privilege escalation belongs here when the
mechanism is host configuration rather than a network protocol.
""",
    "active-directory": """# On-Premises Active Directory classes

**Specialization of `../` — Active Directory.** Not a domain: see
[`../README.md`](../../README.md) for why.

Cloud identity (Entra ID, Azure AD, AWS IAM, Okta) is **out of scope** for this
version (brief §4). These pages cover on-premises directory services only.

## AD is modelled as a graph

The capability that matters is not memorizing techniques. It is reading
relationships (brief §5):

```
OBJECT → RELATIONSHIP → PERMISSION → WEAKNESS → ACCESS → ESCALATION
```

- Who controls this object?
- Who can modify it?
- Who can authenticate where?
- Which permission creates an escalation path?
- Which trusts matter?
- What credentials provide access?

## Authentication & identity

| Class | What it covers |
|---|---|
| [`ad-kerberos.md`](ad-kerberos.md) | tickets requested offline and cracked, or forged outright |
| [`ad-ntlm.md`](ad-ntlm.md) | relay of a challenge, replay of a captured hash |
| [`ad-ldap.md`](ad-ldap.md) | filters as query structure; signing of the bind |
| [`ad-enumeration.md`](ad-enumeration.md) | the directory disclosing its own map |

## Privilege & attack paths

| Class | What it covers |
|---|---|
| [`ad-acl-abuse.md`](ad-acl-abuse.md) | permissions on objects that grant control |
| [`ad-delegation.md`](ad-delegation.md) | unconstrained, constrained, and resource-based delegation |
| [`adcs-abuse.md`](adcs-abuse.md) | certificate templates that will authenticate a low-privilege principal |
| [`ad-group-policy.md`](ad-group-policy.md) | SYSVOL-served policy files writable by admins |
| [`ad-trust-abuse.md`](ad-trust-abuse.md) | cross-forest and external trusts, SID filtering |
| [`credential-access.md`](credential-access.md) | LSASS, NTDS.dit, SAM, credential stores |
| [`pass-the-hash.md`](pass-the-hash.md) | protocols that authenticate the hash, not the secret |
| [`password-attacks.md`](password-attacks.md) | spraying against per-account online authentication |

Forests, external trusts and SID history are recorded here; the attack-path
*narratives* that cross these classes live in `../../../attack-chains/`.
""",
}
