# On-Premises Active Directory classes

**Specialization of `../` — Active Directory.** Not a domain: see
[`../README.md`](../README.md) for why.

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
