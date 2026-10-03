"""The authored half of the NETWORK wave: claim, body, disproof per item.

Separated from build_items.py on purpose. That file owns the anti-fabrication
mechanics (quotes come out of cached page text). This file owns the reasoning:
what is actually true, what to test, and what observation would kill the claim.
A quote cannot be invented here; a claim can only be as good as the author.

Sources per item are (url_key, needle). The needle must appear verbatim on the
live page — build_items.pick() aborts the whole build if it does not, so this
file cannot smuggle in an unsupported citation.

`hv` is hunting_value (1..5) — demonstrated usefulness to a practitioner, which
the quality model scores explicitly.
"""
from __future__ import annotations

from build_items import CWE, IETF, MS, OWASP, cwe, item, rfc, t

S = {  # source shorthands
    "mitre": "https://attack.mitre.org/techniques/",
    "rfc": "https://www.rfc-editor.org/rfc/rfc",
}


def _src(url: str, stype: str, needle: str, locator: str | None = None, **kw):
    from build_items import src
    return src(url, stype, needle, locator=locator, **kw)


ITEMS: list[dict] = [

    # ======================= ACTIVE DIRECTORY =============================
    item(
        "ad_kerberos.technique.kerberoast_rc4_tgs_offline_crack", "technique",
        claim="A Kerberos service ticket whose SPN is issued to an account with "
              "no interactive login (a service principal) is an offline "
              "password-cracking oracle when the KDC still protects it with RC4, "
              "because the ticket's encrypted part is keyed on the account "
              "password hash.",
        body="Kerberoasting needs no privilege at all: any domain principal can "
             "request a TGS ticket for any SPN it names, and the KDC will return "
             "one encrypted with that SPN's account key. When that key is RC4 "
             "(etype 23), the returned ciphertext is crackable offline with no "
             "further interaction with the domain — the whole attack happens "
             "locally after a single request. Test procedure: request a service "
             "ticket for a target SPN with any low-privilege domain credential, "
             "record the etype and cipher, then attempt to crack the ticket "
             "offline. A domain that has globally disabled RC4 for service "
             "tickets makes this untestable in the classic form, which is "
             "exactly the mitigation ATT&CK names. The interesting hunting "
             "signal is not the crack but the request pattern: many distinct "
             "SPNs requested by one principal in a short window is a request "
             "shape that legitimate administration does not produce.",
        disproof="If the KDC refuses to issue service tickets to requesting "
                 "users' RC4 (etype 23 is globally disabled), or every "
                 "crackable ticket offline fails to recover the account "
                 "password, then this class is not exploitable in this "
                 "environment and the finding is a false positive.",
        sources=[
            _src(t("T1558/003"), "taxonomy", "vulnerable to offline Brute Force attacks",
                 locator="Detection/Description"),
            _src(cwe(294), "cwe", "Capture-replay attacks are common",
                 locator="Extended Description"),
        ],
        surface="ad", severity="high", hunting_value=5,
    ),
    item(
        "ad_kerberos.technique.asrep_roast_preauth_disabled", "technique",
        claim="A domain account configured with 'do not require Kerberos "
              "preauthentication' will return an AS-REP containing "
              "ticket-granting data to an unauthenticated AS-REQ, turning the "
              "authentication service into an offline password-cracking oracle "
              "for that account.",
        body="Kerberos preauthentication exists so that a wrong password "
             "produces an encrypted timestamp the client cannot produce — the "
             "KDC proves the client knows the key. Disable it and the AS-REP "
             "comes back regardless of whether the supplied credential is "
             "valid, and the reply is encrypted with the account password hash. "
             "The attack is: enumerate accounts with preauthentication disabled "
             "(an ordinary domain account is enough), send an AS-REQ without the "
             "encrypted timestamp to each, collect the AS-REPs, crack them "
             "offline. Because the enumeration step is LDAP and the cracking "
             "step is local, both halves leave different traces — an LDAP query "
             "sweeping the userAccountControl bit, then a burst of offline work "
             "on the one host. Check the userAccountControl flag as a baseline "
             "control: preauthentication is on by default, so any account with "
             "it off is a deliberate exception and worth its own ticket.",
        disproof="If enumeration returns no accounts with preauthentication "
                 "disabled, or an AS-REQ without an encrypted timestamp is "
                 "rejected with KDC_ERR_PREAUTH_REQUIRED for every account "
                 "tested, then no AS-REP material exists and the attack has no "
                 "precondition.",
        sources=[
            _src(t("T1558/004"), "taxonomy", "An account registered to a domain, with or without special privileges",
                 locator="Description"),
            _src(rfc(4120), "standard",
                 "the authentication server does not know  whether the client is actually the principal",
                 locator="3.1.3.1 Initial Request"),
        ],
        surface="ad", severity="high", hunting_value=5,
    ),
    item(
        "ad_kerberos.technique.krbtgt_hash_ticket_forgery", "technique",
        claim="Possession of the KRBTGT account password hash is sufficient to "
              "forge arbitrary Kerberos ticket-granting tickets for any principal "
              "in the forest, because KRBTGT is the key that signs and encrypts "
              "every TGT in that domain.",
        body="KRBTGT is a single account whose key is shared by every TGT the "
             "KDC issues, so it converts a single-credential compromise into "
             "domain-wide ticket forgery: any identity, any ticket lifetime, any "
             "group membership, forged at will. This is why rotating KRBTGT "
             "twice is the accepted containment step — one rotation does not "
             "invalidate tickets already in circulation because the previously "
             "active key still validates them. Obtain the hash via credential "
             "dumping on a domain controller, then mint a ticket for a target "
             "user. The forensic asymmetry worth hunting for: forged tickets can "
             "carry lifetimes no KDC would ever issue, because the forger picks "
             "the ticket times rather than having them negotiated. Correlating "
             "ticket lifetime against issuance time catches tickets that no "
             "legitimate AS exchange could have produced.",
        disproof="If KRBTGT cannot be dumped (credential protection intact, "
                 "PAW/Protected Users enforced) or a ticket minted from the hash "
                 "is rejected by a domain controller, then no forged TGT is "
                 "usable and the class does not apply here.",
        sources=[
            _src(t("T1558/001"), "taxonomy", "KRBTGT is the Kerberos Key Distribution Center",
                 locator="Description"),
            # Second publisher must be an INDEPENDENT host: two ATT&CK pages are
            # one publisher and can never satisfy MIN_PUBLISHER_HOSTS=2. RFC 4120
            # supplies the normative statement that the AS-REP encrypted part is
            # keyed on the principal's long-term key.
            _src(rfc(4120), "standard",
                 "using the client's long-term key or another key selected",
                 locator="5.2.7.1 Flags / 3.5.3 Key Usage"),
        ],
        surface="ad", severity="critical", hunting_value=5,
    ),

    item(
        "ad_ntlm.technique.ntlm_relay_authenticated_session_reuse", "technique",
        claim="An NTLM authentication exchange can be relayed rather than "
              "cracked: because NTLM authenticates the connection and not the "
              "channel to it, a captured challenge-response from one service is "
              "replayable against a second service that accepts NTLM.",
        body="The relay primitive is that NTLM's proof is possession of a "
             "response keyed on a shared secret and a server challenge — not a "
             "property of the TLS channel the client believes it is on. A client "
             "induced to authenticate to an attacker-controlled listener produces "
             "a response for a challenge the attacker chose; that response is "
             "then presented to a victim service, which validates it because it "
             "cannot tell the request did not arrive over the intended channel. "
             "Two ways this works in practice: capture-and-relay, where the "
             "adversary sits in the authentication path; and coercion, where the "
             "adversary induces the outbound authentication. Both are "
             "independent of hash cracking. The bound on the whole class is "
             "channel binding plus mandatory signing on the target service: if "
             "every service that accepts NTLM also requires signing, the "
             "relayed response has no valid signature and the exchange fails.",
        disproof="If the target service rejects the relayed exchange because "
                 "message signing or channel binding is mandatory, or if no "
                 "adversary-controlled authentication can be induced on the "
                 "path, then NTLM relay cannot succeed and any such report is a "
                 "false positive.",
        sources=[
            _src(t("T1557/001"), "taxonomy", "the NTLMv1/v2 hashes can be intercepted and relayed",
                 locator="Description"),
            _src("https://learn.microsoft.com/en-us/openspecs/windows_protocols/ms-nlmp/",
                 "docs", "NTLM is used by application protocols to authenticate remote users",
                 locator="Summary"),
        ],
        surface="ad", severity="high", hunting_value=5,
    ),

    item(
        "ad_ldap.technique.filter_syntax_is_attacker_reachable_structure", "technique",
        claim="An LDAP search filter is a structured query supplied by the "
              "client, so any code path that concatenates unescaped user input "
              "into a filter lets the input redefine the query rather than "
              "narrow it.",
        body="The LDAP filter is not a value the server looks up — it is the "
             "predicate that decides which entries match, and RFC 4511 defines "
             "it as a full expression language with and/or/not and comparison "
             "matchers. That means the escaping requirements are structural, not "
             "cosmetic: an unescaped ')' closes the component the application "
             "intended to be a literal, and everything after it is parsed as "
             "further filter structure. The test is a differential one — submit "
             "a value containing ')' and '*' and compare the entry set returned "
             "against the set returned by the same query with those characters "
             "escaped. If the response changes shape rather than failing, the "
             "filter is being built by concatenation. Related but distinct: "
             "unsigned LDAP binds let a response be forged rather than a query "
             "be widened, and the two remediations (escaping, and "
             "authenticated+integrity-protected binds) do not substitute for "
             "each other.",
        disproof="If a filter containing ')' and '*' returns the identical "
                 "entry set as the escaped form, or the server rejects "
                 "unbalanced filter syntax outright, then filter injection is "
                 "not reachable on this path.",
        sources=[
            _src(rfc(4511), "standard", "A filter that defines the conditions that must be fulfilled",
                 locator="4.5.1.7 SearchRequest.filter"),
            _src(cwe(90), "cwe",
                 "does not properly escape LDAP queries",
                 locator="Weakness Ordinalities / CVE-2005-2301"),
        ],
        surface="ad", severity="high", hunting_value=4,
    ),

    item(
        "pass_the_hash.technique.replay_hash_as_credential", "technique",
        claim="NTLM and Kerberos protocols accept a key as the credential "
              "rather than a secret the user holds, so a captured NTLM hash or "
              "service ticket is itself a replayable authentication artifact and "
              "needs no password recovery.",
        body="Pass-the-hash removes the cracking step entirely. Where the "
             "protocol's proof is keyed on the NTLM hash, possessing the hash is "
             "possession of the credential, and it can be presented directly to "
             "any service accepting that hash. Pass-the-ticket is the same "
             "property one layer up: a valid Kerberos service ticket is already "
             "a bearer artifact for that service, so capturing and injecting it "
             "is a credential use, not a forgery. The practical consequence for "
             "hunting is that both techniques leave authentication SUCCESS "
             "events with no matching interactive logon — the tell is the "
             "absence of a preceding interactive session for that principal, "
             "not the presence of anything unusual in the logon itself. This "
             "also sets the boundary of the class: a protocol that requires a "
             "secret not derivable from the hash (smartcard/PIN, or a key the "
             "user holds) is outside it.",
        disproof="If the hash or ticket is rejected by the target because "
                 "channel binding, signing, or an authentication level "
                 "requirement is enforced, then replay does not authenticate and "
                 "the finding collapses to a failed logon.",
        sources=[
            _src(t("T1550/003"), "taxonomy", "valid Kerberos tickets for Valid Accounts are captured",
                 locator="Description"),
            _src(cwe(294), "cwe", "Capture-replay attacks are common",
                 locator="Extended Description"),
        ],
        surface="ad", severity="high", hunting_value=5,
    ),

    item(
        "ad_enumeration.technique.ldap_domain_account_discovery", "technique",
        claim="Domain account names, group memberships and privilege are "
              "discoverable through LDAP with an ordinary domain credential, "
              "so a single low-privilege login yields the target list that every "
              "later password attack or lateral move is aimed at.",
        body="Account enumeration is the cheapest step in an attack chain and "
             "the one most often assumed to be blocked. It is not: an ordinary "
             "domain account can run an LDAP query against the directory and "
             "receive the distinguished name, SAM account name and display name "
             "for domain users, and can separately enumerate group membership "
             "to find who is actually privileged. The useful hunting insight is "
             "that enumeration and privilege lookup are DIFFERENT queries with "
             "different blast radius — a host enumerating the domain user list "
             "at volume is reconnaissance, while a query against a specific "
             "privileged group is targeting. Practically, establish a baseline "
             "of which hosts perform LDAP queries and at what rate; a single "
             "interactive workstation should not be issuing LDAP searches at "
             "all. Anonymous or unauthenticated enumeration where the domain "
             "controller permits it removes even the credential requirement.",
        disproof="If the domain controller refuses LDAP binds without a valid "
                 "credential AND denies all enumeration to a standard user "
                 "account, then this technique has no foothold; an empty result "
                 "set from a genuinely authenticated query disproves it.",
        sources=[
            _src(t("T1087/002"), "taxonomy", "Brute Ratel C4 can use LDAP queries",
                 locator="Software S1063"),
            _src(rfc(4511), "standard", "If the filter evaluates to TRUE for  a particular entry",
                 locator="4.5.1.7 SearchRequest.filter"),
        ],
        surface="ad", severity="medium", hunting_value=5,
    ),

    item(
        "ad_acl_abuse.technique.writable_dacl_grants_control", "technique",
        claim="An object whose DACL grants a low-privilege principal WRITE_DAC, "
              "WRITE_OWNER or a generic write right lets that principal rewrite "
              "the permissions on the object, converting read access into "
              "control of whatever the object governs.",
        body="This is a privilege-escalation primitive, not a data leak. Because "
             "access control is itself an object whose access is controlled by "
             "the DACL, granting a principal the right to modify the DACL (or to "
             "take ownership, which lets you then rewrite it) means the "
             "principal can grant itself any right it likes. On a domain object "
             "that governs replication or password reset, that is domain "
             "compromise. The enumeration approach: for each interesting object, "
             "read the access control entries and ask not 'can I write this "
             "object' but 'can I rewrite this object's permissions' — the two "
             "are different rights and only the second compounds. The Windows "
             "utilities that expose this are the same ones an adversary would "
             "use (icacls, cacls, takeown), which is useful for validation: "
             "confirm with the built-in tool rather than by asserting the "
             "permission model from the DACL dump alone.",
        disproof="If no principal in the low-privilege set holds WRITE_DAC, "
                 "WRITE_OWNER, GenericWrite, or an equivalent that permits "
                 "rewriting the DACL, and the object is not writable by anyone "
                 "outside its administrators, then no ACL path to control "
                 "exists.",
        sources=[
            _src(t("T1222/001"), "taxonomy", "DACLs identifies the accounts that are allowed or denied access",
                 locator="Description"),
            _src("https://learn.microsoft.com/en-us/windows/win32/secauthz/access-control",
                 "docs", "Access control refers to security features that control who can access",
                 locator="Introduction"),
        ],
        surface="ad", severity="high", hunting_value=5,
    ),

    item(
        "ad_delegation.technique.delegated_ticket_replay", "technique",
        claim="Kerberos delegation lets a service present a client's ticket to a "
              "downstream service as that client, so a service holding delegated "
              "credentials can act as the user against a third system the user "
              "could reach.",
        body="Delegation is the protocol feature that lets a middle tier hold "
             "forwardable credentials on a user's behalf. RFC 4120 makes the "
             "client's decision explicit: the OK-AS-DELEGATE flag in the ticket "
             "flags is set when the realm considers the named server a suitable "
             "recipient, and the flag exists so the client can decide whether to "
             "forward. The security weight is entirely in which servers are "
             "marked delegable: where delegation is configured unconstrained, or "
             "where resource-based constrained delegation lets a service obtain "
             "forwardable tickets to arbitrary SPNs, the service can authenticate "
             "as the user to systems the user never intended. The test is to "
             "enumerate which SPNs are configured for delegation, then confirm "
             "whether the constraint is to a single target or open. A service "
             "that is delegable to anything is a credential-forwarding open "
             "door, not a hardening question.",
        disproof="If no SPN in the domain is configured for unconstrained "
                 "delegation and all resource-based constrained delegation is "
                 "bound to a specific target service, then no delegable ticket "
                 "can be redirected and the primitive is closed.",
        sources=[
            _src(rfc(4120), "standard", "OK-AS-DELEGATE",
                 locator="5.2.7.1 Flags"),
            _src(t("T1134/003"), "taxonomy", "Adversaries may make new tokens and impersonate users",
                 locator="Description"),        ],
        surface="ad", severity="high", hunting_value=4,
    ),

    item(
        "adcs_abuse.technique.template_issuance_grants_domain_credential", "technique",
        claim="A certificate template that authenticates and can be enrolled by "
              "a low-privilege principal issues a credential whose subject name "
              "is attacker-chosen, so enrollment becomes domain authentication "
              "with no password involved.",
        body="AD CS turns certificate issuance into an authentication path. If a "
             "template's extended key usage permits authentication and its "
             "subject alternative name is supplied by the enrolling principal, "
             "the issued certificate is a credential for whatever identity the "
             "requester named. Enrollment is often gated only by an 'Authenticated "
             "Users' or low-privilege group membership rather than by enrollment "
             "rights on the template, which means ordinary domain users qualify. "
             "The enumeration procedure is specific: list templates, check "
             "eku for client authentication, check who holds Enroll rights, and "
             "check whether the SAN comes from the request. All three conditions "
             "must hold; any one of them failing breaks the chain. The persisted "
             "consequence is what makes this class worth the hunt: a forged or "
             "over-privileged certificate survives a password reset for its "
             "validity period, so containment has to include revocation rather "
             "than relying on credential rotation.",
        disproof="If no enrolled template combines an authentication EKU with "
                 "requester-controlled subject names and enrollment open to a "
                 "low-privilege principal, then no certificate can be obtained "
                 "that authenticates as another identity.",
        sources=[
            _src(t("T1649"), "taxonomy", "bind to an identity and can be used as credentials for domain accounts",
                 locator="Description"),
            _src("https://learn.microsoft.com/en-us/openspecs/windows_protocols/ms-wcce/",
                 "docs", "X.509 (as specified in [X509]) digital certificate enrollment",
                 locator="Summary"),
        ],
        surface="ad", severity="critical", hunting_value=5,
    ),

    item(
        "ad_trust_abuse.technique.trust_rewrite_forges_cross_forest_token", "technique",
        claim="Changing a domain's trust configuration to include an "
              "adversary-controlled domain lets an identity from that domain "
              "forge access tokens that victim-domain resources will accept.",
        body="A trust is a statement that identities in one forest may "
             "authenticate to resources in another. That makes the trust "
             "configuration itself an authorization control, and modifying it is "
             "a privilege action rather than a configuration cleanup: adding an "
             "adversary-controlled domain produces a trusted path whose tokens "
             "the victim forest will accept. The detection problem is that the "
             "change is made through ordinary administrative APIs, so it looks "
             "like administration unless you are watching the specific object. "
             "The specific objects matter: domain trust configuration, "
             "federation settings and Group Policy Objects are the three that "
             "ATT&CK groups as domain/tenant policy modification, and all three "
             "are directory-object changes rather than file writes. Watch for "
             "trust and GPO objects being modified — not for who modified them, "
             "since a legitimate administrator is the expected actor in both the "
             "benign and the malicious case.",
        disproof="If the domain's trust objects cannot be modified by any "
                 "principal outside Domain Admins and no trust exists with an "
                 "uncontrolled or unexpected partner, then no cross-forest "
                 "token forgery is available to a lower-privilege actor.",
        sources=[
            _src(t("T1484"), "taxonomy", "changing trust settings for domains",
                 locator="Description"),
            # RFC 4120 cross-realm is the normative half: a cross-realm TGT is
            # accepted on the strength of the transited-realm check, so trust
            # configuration IS an authorization control, not a convenience.
            _src(rfc(4120), "standard",
                 "intermediate realms may be bypassed to achieve cross-realm authentication",
                 locator="3.2.3 Cross-Realm Authentication"),
        ],
        surface="ad", severity="critical", hunting_value=4,
    ),

    item(
        "ad_group_policy.technique.sysvol_gpo_write_changes_every_host", "technique",
        claim="Group Policy Objects are file sets in the SYSVOL network path, "
              "so write access to SYSVOL lets one write change the behaviour of "
              "every machine and user the policy applies to.",
        body="GPO abuse is a file-write problem wearing an Active Directory "
             "costume. The settings are stored as files under a predictable "
             "network path, and the client applies whatever it finds there at "
             "refresh. That means the escalation is not 'modify an object' but "
             "'write a file that a privileged client will execute', and the "
             "blast radius is every host the policy applies to — a single write "
             "can create a scheduled task, change a security setting, or push a "
             "binary. The control is therefore filesystem permission on SYSVOL, "
             "not GPO ACLs in the abstract: confirm that only Domain Admins have "
             "write on the SYSVOL share and its underlying files, and treat any "
             "write to the Policies tree as an incident regardless of the "
             "authenticated identity. Because scheduled tasks and software "
             "installation are legitimate GPO features, the written content is "
             "indistinguishable from policy at the protocol level; the file "
             "write is the signal.",
        disproof="If SYSVOL and the Policies tree are writable only by Domain "
                 "Admins and machine accounts, and no lower-privilege principal "
                 "can create or modify a GPO file, then no GPO-based code "
                 "execution path exists from that account.",
        sources=[
            _src(t("T1484/001"), "taxonomy", "GPOs are containers for group policy settings",
                 locator="Description"),
            _src("https://learn.microsoft.com/en-us/windows/client-management/enroll-a-windows-10-device-automatically-using-group-policy",
                 "docs", "You can use a Group Policy to trigger autoenrollment",
                 locator="Introduction"),
        ],
        surface="ad", severity="critical", hunting_value=5,
    ),

    item(
        "credential_access.technique.dcsync_replication_rights_password_dump", "technique",
        claim="The directory replication request right (DCSync) lets a "
              "principal pull password hashes including KRBTGT from a domain "
              "controller without ever touching the NTDS.dit file, so a single "
              "misconfigured principal yields the whole domain's credentials.",
        body="DCSync abuses directory replication: a principal that holds the "
             "replication-related rights can request a full credential payload "
             "from a domain controller and receive current and historical hashes "
             "of accounts including KRBTGT and the Administrators group. The "
             "significance is that this is a permission, not an exploit — no "
             "memory scraping, no file access, no privileged session on the "
             "controller required beyond whatever the right is granted to. The "
             "hunt is therefore an ACL review of replication rights across the "
             "domain, checked against the specific rights DCSync requires "
             "(DS-Replication-Get-Changes, DS-Replication-Get-Changes-All and "
             "DS-Replication-Get-Changes-In-Filtered-Set). Detection is on the "
             "replication API invocation rather than on credential access, "
             "because by the time a hash is dumped the session looks like any "
             "other authenticated one.",
        disproof="If no non-Domain-Admin principal holds the three replication "
                 "rights, and a replication request from a standard account is "
                 "denied, then no DCSync path exists and the finding is a false "
                 "positive.",
        sources=[
            _src(t("T1003/006"), "taxonomy", "able to run DCSync to pull password data",
                 locator="Description"),
            # Second publisher: MS-NLMP (Microsoft) states the normative property
            # the attack depends on — a protocol authenticates the CLIENT, and
            # session security is only provided when the application asks for it.
            # A CWE page was the first choice here and was rejected: CWE-522 is
            # about credentials in transit/at rest in code, which is not what
            # DCSync abuses, so pairing it would have been gate-satisfying
            # padding rather than corroboration.
            _src("https://learn.microsoft.com/en-us/openspecs/windows_protocols/ms-nlmp/",
                 "docs", "NTLM is used by application protocols to authenticate remote users",
                 locator="Summary"),
        ],
        surface="ad", severity="critical", hunting_value=5,
    ),

    item(
        "password_attacks.technique.spray_across_accounts_to_avoid_lockout", "technique",
        claim="Password spraying succeeds where password brute force fails "
              "because it inverts the two axes — one password against many "
              "accounts — so per-account lockout thresholds never trigger while "
              "the total attempt count stays high.",
        body="The reason spraying works is arithmetic about how the control is "
             "written. Account lockout counts failed attempts per account, so "
             "trying many passwords against one account trips it and trying one "
             "password against many accounts does not. A spray run is therefore "
             "invisible to a per-account threshold and visible only as a "
             "many-accounts-one-password pattern, or as a low per-account rate "
             "sustained for days — which is why throttling to avoid alerting "
             "thresholds is part of the technique rather than an afterthought. "
             "Two operational consequences: lockout is not an effective control "
             "against spraying at all, and alerting must be built on the "
             "cross-account view (distinct accounts failing from one source in a "
             "window) rather than the per-account view. Defence in depth is "
             "multi-factor, which defeats the technique because the sprayed "
             "password is only one of the required factors.",
        disproof="If a spray-shaped run (one password, many distinct accounts, "
                 "below per-account lockout) produces no successful "
                 "authentication and every account still enforces multi-factor, "
                 "then the technique found nothing and must not be reported as a "
                 "compromise.",
        sources=[
            _src(t("T1110/003"), "taxonomy", "avoid account lockouts that would normally occur",
                 locator="Description"),
            _src("https://cheatsheetseries.owasp.org/cheatsheets/Authentication_Cheat_Sheet.html",
                 "cheatsheet", "The most common protection against these attacks is to implement account lockout",
                 locator="Account Lockout"),
        ],
        surface="ad", severity="high", hunting_value=5,
    ),

    # ======================= INFRASTRUCTURE ===============================
    item(
        "smb.technique.authenticated_smb_is_execution_channel", "technique",
        claim="SMB is not only file transfer: an authenticated SMB session is a "
              "remote execution channel, which is why administrative shares are "
              "worth more to an adversary than the data on them.",
        body="Because SMB carries file access, remote procedure calls and remote "
             "execution over one authenticated session, a share write is a "
             "staging step rather than an endpoint — the file lands and something "
             "else runs it. ATT&CK names the executions that ride the same "
             "authenticated SMB/RPC session: scheduled task, service execution "
             "and WMI. That changes the priority order for hunting: a host that "
             "writes a file to a remote administrative share and a host that then "
             "connects to create a service on that target are one incident, not "
             "two. NetBIOS is the naming and transport layer underneath, which "
             "is why the original NetBIOS-over-TCP specification still matters "
             "for understanding why a name resolution answer can direct a client "
             "to the adversary's listener. The practical control is signing: "
             "where SMB signing is not required, an intercepted or coerced "
             "authentication is reusable; where it is required, the relay and "
             "coercion variants close even though the file transfer does not.",
        disproof="If the target host requires SMB signing and has no "
                 "administrator shares exposed, then a captured or coerced SMB "
                 "authentication cannot be relayed or used for remote execution "
                 "and only ordinary file access is possible.",
        sources=[
            _src(t("T1021/002"), "taxonomy", "Example execution techniques that rely on authenticated sessions over SMB/RPC",
                 locator="Description"),
            _src(rfc(1002), "standard", "This RFC gives the detailed specifications of the NetBIOS-over-TCP",
                 locator="1. INTRODUCTION"),
        ],
        surface="infra", severity="high", hunting_value=5,
    ),

    item(
        "winrm.technique.winrm_session_is_remote_execution", "technique",
        claim="WinRM establishes a SOAP-over-HTTP session to a remote computer "
              "that runs commands as the authenticated user, so an exposed "
              "WinRM listener is a remote execution surface rather than only a "
              "management interface.",
        body="WinRM is the Microsoft implementation of WS-Management, "
             "SOAP-based and firewall-friendly, and Microsoft documents it as "
             "establishing a session with a remote computer over that protocol "
             "rather than over DCOM. That distinction has a security reading: "
             "because it is HTTP, it is reachable wherever HTTP is allowed, and "
             "because it runs commands rather than only querying, it is an "
             "execution surface. Microsoft's own guidance on the protocol notes "
             "it supports management data from both Windows and non-Windows "
             "implementations, so a permissive listener is not confined to the "
             "Windows estate. The detection baseline is the TrustedHosts list "
             "plus listener configuration: WinRM configured to accept "
             "connections from hosts that should not reach it is the finding. "
             "MITRE's mitigations for the technique are correspondingly blunt — "
             "disable the service, or confine it to specific enclaves with "
             "host firewall rules and separate accounts.",
        disproof="If the WinRM listener is disabled, or requires HTTPS with "
                 "certificate-based authentication and is restricted to an "
                 "explicit TrustedHosts list that excludes untrusted hosts, then "
                 "remote command execution over WinRM is not reachable.",
        sources=[
            _src("https://learn.microsoft.com/en-us/windows/win32/winrm/portal",
                 "docs", "WinRM establishes a session with a remote computer",
                 locator="Where can I use WinRM?"),
            _src(t("T1021/006"), "taxonomy", "Disable the WinRM service",
                 locator="Mitigations"),
        ],
        surface="infra", severity="high", hunting_value=5,
    ),

    item(
        "rdp.technique.rdp_reachable_is_access_reachable", "technique",
        claim="RDP provides remote display and input over a network connection "
              "and is designed for multiple topologies and LAN protocols, so "
              "reachability of an RDP listener is reachability of an interactive "
              "session on that host.",
        body="RDP is a multi-channel protocol carrying presentation data, device "
             "channels and encrypted input events, with the server rendering "
             "output into packets and the client turning them back into graphics "
             "calls. The hunting consequence is that this is not a metadata "
             "service: an RDP listener reachable from an unexpected segment is "
             "an interactive session reachable from there. Microsoft documents "
             "the protocol as designed to support different network topologies "
             "and multiple LAN protocols, which is precisely why the reachability "
             "question is a network-topology question rather than a port "
             "question. Pair it with the credential question: ATT&CK notes that "
             "adversaries expand access over RDP when the service is enabled and "
             "permits accounts with known credentials, so an enabled-but-"
             "restricted listener and an enabled-and-open listener are different "
             "findings. Recorded sessions are also a persistence surface in "
             "their own right, which is why RDP shows up outside movement.",
        disproof="If the RDP listener requires network-level authentication "
                 "and is firewalled to jump hosts only, so that no unauthorized "
                 "host can reach the port, then RDP reachability does not imply "
                 "session reachability.",
        sources=[
            _src("https://learn.microsoft.com/en-us/windows/win32/termserv/remote-desktop-protocol",
                 "docs", "RDP is designed to support different types of network topologies",
                 locator="Introduction"),
            _src(t("T1021/001"), "taxonomy", "if the service is enabled and allows access to accounts with known credentials",
                 locator="Description"),
        ],
        surface="infra", severity="high", hunting_value=5,
    ),

    item(
        "dns_enum.technique.zone_transfer_enumerates_the_network", "technique",
        claim="A DNS zone enumerates every host in a namespace without touching "
              "it, and an AXFR zone transfer returns the entire zone, so one "
              "query against a misconfigured server replaces host discovery.",
        body="DNS is a name-to-address mapping in which the zone is the complete "
             "inventory of a namespace, and RFC 1035 defines AXFR as a request "
             "for a transfer of an entire zone. That is the whole attack: query "
             "the server for a transfer and read the record set. In Windows "
             "environments DNS carries additional weight because the DNS Client "
             "service uses it to discover domain controllers before "
             "authentication even begins — the domain controller location "
             "mechanism is a DNS query, so zone contents describe the "
             "authentication topology as well as the host list. The control is "
             "therefore narrow and checkable: a zone transfer should only be "
             "accepted from the secondary servers that need it, and any AXFR "
             "answered to an unexpected source is a finding on its own. Note "
             "also that SRV records carry service locations, so a zone dump "
             "enumerates services, not merely hosts.",
        disproof="If an AXFR request from an unauthorized source is refused, or "
                 "the server only answers transfers to configured secondaries, "
                 "then the zone cannot be enumerated this way and discovery "
                 "requires per-host probing.",
        sources=[
            _src(rfc(1035), "standard", "A request for a transfer of an entire zone",
                 locator="3.4.2.2 AXFR"),
            _src("https://learn.microsoft.com/en-us/windows-server/networking/dns/dns-top",
                 "docs", "It discovers domain controllers",
                 locator="How DNS works"),
        ],
        surface="infra", severity="medium", hunting_value=5,
    ),

    item(
        "ldap_enum.technique.filter_tree_walk_returns_directory_structure", "technique",
        claim="LDAP returns directory entries selected by a client-supplied "
              "filter, so a permissive base scope lets a client walk the tree "
              "and receive attributes without any per-object authorization "
              "decision being visible in the protocol.",
        body="The LDAP search operation is defined by the filter the client "
             "sends and the attributes it asks for; when the filter evaluates "
             "true for an entry, that entry's attributes come back subject to "
             "applicable access control. So the enumeration surface is the "
             "product of three server-side settings — base scope, subtree depth, "
             "and which attributes may be returned anonymously — and each is "
             "independently misconfigurable. A permissive filter such as "
             "(objectClass=*) returns every entry in scope, which converts one "
             "query into a directory dump and, in a directory where computer "
             "accounts live, into a host inventory. The validation is "
             "differential: request the same subtree with a narrow filter and "
             "with (objectClass=*), and if the broad form returns entries the "
             "narrow one cannot, the broad filter is authorized when it should "
             "not be. This is the same structural property that makes filter "
             "injection dangerous, viewed from the read side rather than the "
             "write side.",
        disproof="If an (objectClass=*) subtree query from an unprivileged bind "
                 "returns no entries, or the server rejects it with an "
                 "insufficient-access error, then the directory structure is "
                 "not enumerable through that path.",
        sources=[
            _src(rfc(4511), "standard", "then the attributes of that entry are returned as part of the Search result",
                 locator="4.5.1.7 SearchRequest.filter"),
            _src(t("T1087/002"), "taxonomy", "execute an LDAP query to enumerate",
                 locator="Software S0635"),
        ],
        surface="infra", severity="medium", hunting_value=5,
    ),

    item(
        "service_enumeration.technique.banner_selects_the_applicable_technique", "technique",
        claim="Port and service scanning is used to acquire the list of open "
              "services and their banners, and that list is what determines "
              "which technique is even applicable to a host.",
        body="Enumeration is a selection step, not an end. The scan output — open "
             "ports, service banners, OS fingerprints — is what tells you "
             "whether NTLM relay, SMB signing, WinRM or an exposed RDP listener "
             "is a candidate at all, so a scan that produces only port numbers "
             "has not yet produced anything actionable. ATT&CK describes the "
             "acquisition step as port, vulnerability and wordlist scans, and "
             "the vendors listed show both halves in practice (host scanners, "
             "and malware that scans to enumerate active services). The "
             "operational discipline: record the banner, not just the open port, "
             "because the technique that applies is a property of the service "
             "implementation and version. Also correlate with the assigned "
             "function of the host — an unexpected high-value service on a host "
             "whose role does not need it is the finding, not the scan itself. "
             "IANA service names are the reference for what a port is supposed "
             "to be, which makes an unexpected name a concrete observation "
             "rather than a judgement call.",
        disproof="If the scan is run inside an authorized scope and the banners "
                 "collected match the documented services for every host in "
                 "that scope, then no unexpected service surface was found and "
                 "there is nothing to report.",
        sources=[
            _src(t("T1046"), "taxonomy", "Common methods to acquire this information include port, vulnerability",
                 locator="Description"),
            _src(rfc(6335), "standard", "IANA is the authority for assigning service names and port numbers",
                 locator="1. Introduction"),
        ],
        surface="net", severity="medium", hunting_value=5,
    ),

    item(
        "exposed_services.technique.external_remote_service_is_initial_access", "technique",
        claim="An administrative or remote service reachable from where policy "
              "forbids it is an initial-access or persistence surface, because "
              "attacker leverage is bounded by reachability rather than by the "
              "service's own authentication.",
        body="Reachability is the whole variable here. A management interface "
             "that is authenticated and patched changes character completely "
             "depending on who can reach it, because every control downstream of "
             "the listener is unreachable to an adversary who cannot complete a "
             "TCP handshake to it. The correct test is therefore not 'is this "
             "service exposed' but 'is this service reachable from a segment that "
             "policy says should not reach it' — an SMTP relay reachable from the "
             "DMZ and the same relay reachable from a laptop are different "
             "findings with the same banner. Where the service is required for "
             "administration, the mitigation pattern ATT&CK recommends for the "
             "comparable WinRM case is the general one: lock down critical "
             "enclaves with separate infrastructure and restrict access with host "
             "firewall rules to specific destinations, rather than trying to "
             "harden a listener that should never have been reachable.",
        disproof="If every exposed administrative service is reachable only from "
                 "an explicitly authorized management segment and enforced at "
                 "the network layer rather than by application configuration, "
                 "then the reachability that creates the risk is not present.",
        sources=[
            _src(t("T1133"), "taxonomy", "leverage external-facing remote services to initially access",
                 locator="Description"),
            # Second publisher is Microsoft Learn (RDP), independent of ATT&CK:
            # it supplies the reachability half of the claim — that the listener
            # is a network endpoint over multiple topologies, so exposure is a
            # network-path property rather than a property of the service.
            _src("https://learn.microsoft.com/en-us/windows/win32/termserv/remote-desktop-protocol",
                 "docs", "RDP is designed to support different types of network topologies",
                 locator="Introduction"),
        ],
        surface="net", severity="high", hunting_value=4,
    ),

    item(
        "exposed_rmm.technique.rmm_inherits_the_operator_session", "technique",
        claim="Remote monitoring and management agents control a host as if "
              "local, inheriting the user or software permissions of the session "
              "they run in, so an RMM console is a privileged interface whose "
              "exposure is governed by its own authentication.",
        body="The defining property of an RMM tool is exactly the security "
             "problem: it grants remote control of a computer as if the operator "
             "were sitting at it, inheriting that user or software's permissions. "
             "So the RMM agent is a privileged access path by design, installed "
             "to operate across network controls — which is why it is a "
             "high-value target rather than a utility. The two questions to ask "
             "are therefore about the console, not the endpoint: is the RMM "
             "management interface reachable from where it should not be, and is "
             "its authentication strong enough to resist the credential attacks "
             "documented as common against remote management surfaces. Vendor and "
             "group reporting in ATT&CK (tooling used to deploy malware from an "
             "already-compromised host) confirms the operational reality that "
             "these consoles are used as distribution and access infrastructure. "
             "Multi-factor authentication on the console is the specific control "
             "that changes the exposure.",
        disproof="If the RMM management interface is reachable only from an "
                 "authorized administrative segment and enforces multi-factor "
                 "authentication, then console compromise requires a "
                 "pre-existing privileged foothold and the exposure is "
                 "correspondingly reduced.",
        sources=[
            _src(t("T1219"), "taxonomy", "allow a user to control a computer remotely as if they are a local user",
                 locator="Description"),
            _src("https://cheatsheetseries.owasp.org/cheatsheets/Authentication_Cheat_Sheet.html",
                 "cheatsheet", "Multi-factor authentication (MFA) is by far the best defense",
                 locator="Multi-Factor Authentication"),
        ],
        surface="net", severity="high", hunting_value=4,
    ),

    item(
        "internal_recon.technique.private_address_space_predicts_host_role", "technique",
        claim="Private address space is only unique within an enterprise, so "
              "addresses observed on an internal network carry local rather than "
              "global meaning and inference about host role is drawn from naming "
              "and addressing conventions rather than from any global registry.",
        body="RFC 1918 states the consequence directly: addresses in private "
             "space are unique only within the enterprise, or among cooperating "
             "enterprises, so a private address identifies a host only relative to "
             "a vantage point inside the same space. That is the reason internal "
             "recon is inference: a DHCP-assigned address in a segment that "
             "conventionally serves a particular role is evidence about what runs "
             "there, and the reverse mapping — the address you can reach, the "
             "name you can resolve — is what turns reachability into a map. Two "
             "operational rules follow. First, private addresses must not be "
             "propagated across inter-enterprise links, so a private address "
             "appearing in external DNS records or leaked logs is itself an "
             "information disclosure. Second, because renumbering is costly, "
             "address-to-role mappings are stable, which is exactly what makes "
             "them predictive and worth enumerating deliberately rather than by "
             "opportunistic scanning.",
        disproof="If the internal network assigns addresses with no role "
                 "convention and no name service correlates them, then there is "
                 "no predictive mapping to exploit and host role must be "
                 "determined by direct service identification instead.",
        sources=[
            _src(rfc(1918), "standard", "will  only be unique within the enterprise",
                 locator="3. Private Address Space"),
            _src(t("T1018"), "taxonomy", "get a listing of other systems by IP address",
                 locator="Description"),
        ],
        surface="net", severity="info", hunting_value=4,
    ),

    item(
        "lateral_movement.technique.remote_service_choice_is_protocol_selection", "technique",
        claim="Lateral movement is a selection among the remote access protocols "
              "actually reachable between two hosts, so the movement choice is "
              "determined by reachability and each protocol's authentication "
              "model rather than by attacker preference.",
        body="With a set of valid domain credentials, the set of hosts reachable "
             "and the protocols each one offers is what defines the movement "
             "surface — remote services including SSH and RDP are the standard "
             "carriers. Two properties make the choice non-arbitrary. First, "
             "legitimate administrative tooling already uses these same "
             "protocols, so a lateral move over SMB, WinRM or SSH is "
             "indistinguishable from software deployment at the protocol layer; "
             "MITRE notes that using legitimate credentials with native network "
             "and OS tools may be stealthier than installing an adversary tool. "
             "Second, some remote services also carry execution (WinRM, SMB), "
             "which collapses movement and execution into one step. That makes "
             "reachability inventory the prerequisite for assessing the whole "
             "class, and it makes an unexpected management protocol on a host "
             "the finding worth escalating.",
        disproof="If no remote access protocol is reachable between the "
                 "credentialed host and any other host in scope, then there is no "
                 "lateral movement surface and credential reuse cannot extend "
                 "beyond the current session.",
        sources=[
            _src(t("T1021"), "taxonomy", "remote access protocols such as secure shell (SSH) or remote desktop protocol (RDP)",
                 locator="Description"),
            # Second publisher: RFC 4251 (IETF). ATT&CK names SSH as a movement
            # carrier but says nothing about WHY one host's exposure to another
            # is a protocol-level property; the SSH architecture spec does, by
            # separating server authentication (transport) from client
            # authentication (user auth) — the reachability split the claim rests
            # on. TA0008 was rejected as the second source: it is ATT&CK again,
            # i.e. one publisher.
            _src(rfc(4251), "standard",
                 "authenticates the client to the server",
                 locator="1.5 Authentication"),
        ],
        surface="net", severity="high", hunting_value=5,
    ),

    item(
        "tunneling_pivoting.technique.encapsulation_reintroduces_forbidden_reachability", "technique",
        claim="A tunnel carries one protocol inside another, so a reachability "
              "that policy forbids directly can be reintroduced through a host "
              "both sides accept — the boundary that matters is the tunnel "
              "endpoint, not the inner protocol.",
        body="Proxies and port forwarding tools are the mechanism; the security "
             "consequence is that the enforcement point moves. Where a policy "
             "denies a path, an attacker with two footholds and a permitted "
             "connection between them can carry the denied traffic as a payload "
             "of the permitted one. RFC 4459 makes the same point from the "
             "networking side: tunnels are commonly run as multiple layers of "
             "encapsulation with a distinct inner and outer path, and the tunnel "
             "endpoints may be the same or different hosts. For hunting, the "
             "useful observation is at the endpoint — a host that both accepts "
             "inbound connections from one segment and originates them to another "
             "is the structural precondition, and legitimate tools like remote "
             "proxy utilities are indistinguishable from adversary ones by name. "
             "Detection therefore looks for the traffic pattern (an established "
             "session carrying an unexpected protocol on a permitted port) "
             "rather than for the tool.",
        disproof="If egress from the compromised segment is filtered such that "
                 "no permitted-protocol channel to an attacker-controlled or "
                 "third host can carry an inner session, and no dual-homed host "
                 "bridges the segments, then the tunnel cannot reintroduce the "
                 "forbidden reachability.",
        sources=[
            _src(t("T1090"), "taxonomy", "Many tools exist that enable traffic redirection through proxies",
                 locator="Description"),
            _src(rfc(4459), "standard", "multiple layers of encapsulation",
                 locator="1. Introduction"),
        ],
        surface="net", severity="high", hunting_value=4,
    ),

    item(
        "segmentation_analysis.technique.private_addressing_marks_the_boundary", "technique",
        claim="Private address space defines the internal boundary as a routing "
              "property — private addresses must not be propagated across "
              "inter-enterprise links — so segmentation claims are testable "
              "against forwarding behaviour rather than against policy documents.",
        body="The measurable form of network segmentation is whether packets with "
             "private source or destination addresses cross a boundary. RFC 1918 "
             "requires that routing information about private networks not be "
             "propagated on inter-enterprise links and that packets with private "
             "addresses not be forwarded across them, and expects routers not "
             "using private space to filter such routing information. That gives "
             "a test rather than an assertion: attempt a connection from one "
             "segment to a private address in another and observe whether a "
             "route exists. A segmentation control that is documented but not "
             "enforced at the forwarding layer is not a control — the same "
             "applies to NAT and to inter-enterprise links, which is why a "
             "private address visible in external DNS or leaked logs is a "
             "boundary finding. Note also that private hosts can still reach "
             "external services through mediating gateways, so 'cannot route "
             "out' and 'cannot be routed to' are two different claims and both "
             "need testing.",
        disproof="If forwarding between segments is verifiably blocked at the "
                 "routing layer and no dual-homed host bridges the boundary, "
                 "then the segmentation control holds for the paths tested and "
                 "the claim of a segmentation gap is not supported.",
        sources=[
            _src(rfc(1918), "standard", "should not be forwarded across such links",
                 locator="3. Private Address Space"),
            # Second publisher must not be another RFC: rfc-editor.org is ONE
            # publisher no matter how many documents it serves, so RFC 3704 here
            # was one host and could never satisfy MIN_PUBLISHER_HOSTS. ATT&CK
            # T1018 is the independent host and carries the operational half —
            # listing reachable systems is the act the boundary is meant to stop.
            _src(t("T1018"), "taxonomy", "get a listing of other systems by IP address",
                 locator="Description"),
        ],
        surface="net", severity="medium", hunting_value=4,
    ),

    item(
        "service_enumeration_detail.technique.service_configuration_determines_reachability", "technique",
        claim="Whether a service's protocol weaknesses are reachable is decided "
              "by that service's own configuration — signing requirements, "
              "binding, authentication method and lockout policy — so service "
              "identification must be followed by configuration assessment "
              "before any weakness is asserted.",
        body="This is the step that separates an enumeration report from a "
             "finding. The same open port with the same banner is a different "
             "risk depending on whether the protocol requires signing, whether "
             "the authentication method is replayable, and whether failed "
             "attempts are locked out — and the configuration values that decide "
             "it are precisely the ones an attacker must get right for their "
             "technique to work. The two exemplar controls are authentication "
             "policy (multi-factor defeats replayable credential attacks; "
             "account lockout is the common protection against brute force but "
             "must be balanced so it cannot itself be used to deny service by "
             "locking other users out) and the protocol configuration of the "
             "service itself. So the assessment procedure is: identify the "
             "service, read its authentication and signing configuration, then "
             "evaluate the specific weakness against that configuration. A "
             "weakness reported without the configuration step is a hypothesis, "
             "and its disproof lives in the configuration.",
        disproof="If the service enforces signing and strong authentication "
                 "with lockout applied, then the protocol weaknesses that "
                 "enumeration would suggest are not reachable and the class "
                 "yields no finding for that service.",
        sources=[
            _src(t("T1046"), "taxonomy", "port, vulnerability, and/or wordlist scans",
                 locator="Description"),
            _src("https://cheatsheetseries.owasp.org/cheatsheets/Authentication_Cheat_Sheet.html",
                 "cheatsheet", "care must be taken to prevent it from being used to cause a denial of service",
                 locator="Account Lockout"),
        ],
        surface="net", severity="medium", hunting_value=5,
    ),
]
