# On-Premises Active Directory classes

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
| [`../../active-directory/ad_kerberos/CLASS.md`](../../active-directory/ad_kerberos/CLASS.md) | tickets requested offline and cracked, or forged outright |
| [`../../active-directory/ad_ntlm/CLASS.md`](../../active-directory/ad_ntlm/CLASS.md) | relay of a challenge, replay of a captured hash |
| [`../../active-directory/ad_ldap/CLASS.md`](../../active-directory/ad_ldap/CLASS.md) | filters as query structure; signing of the bind |
| [`../../active-directory/ad_enumeration/CLASS.md`](../../active-directory/ad_enumeration/CLASS.md) | the directory disclosing its own map |

## Privilege & attack paths

| Class | What it covers |
|---|---|
| [`../../active-directory/ad_acl_abuse/CLASS.md`](../../active-directory/ad_acl_abuse/CLASS.md) | permissions on objects that grant control |
| [`../../active-directory/ad_delegation/CLASS.md`](../../active-directory/ad_delegation/CLASS.md) | unconstrained, constrained, and resource-based delegation |
| [`../../active-directory/adcs_abuse/CLASS.md`](../../active-directory/adcs_abuse/CLASS.md) | certificate templates that will authenticate a low-privilege principal |
| [`../../active-directory/ad_group_policy/CLASS.md`](../../active-directory/ad_group_policy/CLASS.md) | SYSVOL-served policy files writable by admins |
| [`../../active-directory/ad_trust_abuse/CLASS.md`](../../active-directory/ad_trust_abuse/CLASS.md) | cross-forest and external trusts, SID filtering |
| [`../../active-directory/credential_access/CLASS.md`](../../active-directory/credential_access/CLASS.md) | LSASS, NTDS.dit, SAM, credential stores |
| [`../../active-directory/pass_the_hash/CLASS.md`](../../active-directory/pass_the_hash/CLASS.md) | protocols that authenticate the hash, not the secret |
| [`../../active-directory/password_attacks/CLASS.md`](../../active-directory/password_attacks/CLASS.md) | spraying against per-account online authentication |

Forests, external trusts and SID history are recorded here; the attack-path
*narratives* that cross these classes live in `../../../attack-chains/`.
