"""NETWORK domain taxonomy — the second offensive domain (brief §4, §5).

This is the additive half of the dual-domain system. The WEB taxonomy in this
module has 15 seeded classes; this adds 20 for NETWORK, which the brief
specifies as three specializations:

    NETWORK
      ├── INTERNAL_NETWORK      discovery, reachability, lateral movement
      ├── INFRASTRUCTURE        the services and the hosts they run on
      └── ACTIVE_DIRECTORY      on-premises directory + its protocols

Active Directory is deliberately NOT a top-level domain. Every AD attack path
is reached by network access to a protocol, so splitting it out would create
two homes for the same knowledge and force the routing layer to guess.

WHY A SEPARATE `_NET_SEED` AND NOT A MERGE INTO `_SEED`. The WEB `_SEED` is
already referenced by name from `seed.py`, `taxonomy.py::SEEDS`, the CLI and the
class generators. Merging 20 rows into that tuple would put NETWORK classes
into every WEB-only code path and silently change existing `verify-seeds` and
`gaps` output. Two registries, one gate, one db: the domain is an attribute of a
class, not a separate corpus.

EVERY URL BELOW IS GET-VERIFIED. Measured, not guessed: of the 34
`learn.microsoft.com` URLs proposed in the first research pass, 13 were dead
(38%), and 4 classes could not corroborate until a second probe pass found them
real hosts. `runtime/state/network-seed-verified.json` records the merged, live set and
`runtime/state/network-seed-probe.json` the per-URL status. `wks.cli verify-seeds`
re-checks all of it and is the authority — this table is not evidence of its own
liveness.
"""
from __future__ import annotations

from dataclasses import dataclass, field


@dataclass(frozen=True)
class ClassSeed:
    id: str
    name: str
    surface: str
    specialization: str = ""
    cwe: str = ""
    mitre_attack: tuple[str, ...] = ()
    aliases: tuple[str, ...] = ()
    summary: str = ""
    sources: tuple[tuple[str, str], ...] = field(default_factory=tuple)
    # (url, source_type) — type sets the authority tier in config.py

    @property
    def hosts(self) -> set[str]:
        from urllib.parse import urlparse
        return {urlparse(u).netloc for u, _ in self.sources}


# Specialization keys. These are the brief's three NETWORK sub-domains (§2, §4).
INTERNAL_NETWORK = "internal_network"
INFRASTRUCTURE = "infrastructure"
ACTIVE_DIRECTORY = "active_directory"

SPECIALIZATIONS = {
    INTERNAL_NETWORK: {
        "label": "Internal Network",
        "statement": (
            "Discovering what is reachable, what answers, and which protocol "
            "carries you from one host to the next."
        ),
    },
    INFRASTRUCTURE: {
        "label": "Infrastructure & Host Services",
        "statement": (
            "The services themselves and the privileges their configuration "
            "concedes: SMB, WinRM, RDP, DNS, SSH, and host-level escalation on "
            "Windows and Linux."
        ),
    },
    ACTIVE_DIRECTORY: {
        "label": "On-Premises Active Directory",
        "statement": (
            "The directory as a GRAPH: objects, the permissions that connect "
            "them, and the authentication protocols (Kerberos, NTLM, LDAP) "
            "that carry a foothold to domain control."
        ),
    },
}

# Publisher hosts deliberately spread across independent authorities. A
# taxonomy page (attack.mitre.org, cwe.mitre.org) plus a protocol specification
# (rfc-editor.org, learn.microsoft.com) is a real pair. Two pages on one host is
# one publisher and can never satisfy MIN_PUBLISHER_HOSTS.
_NET_SEED = (
    # ================= ACTIVE DIRECTORY =================================
    ClassSeed(
        "ad_kerberos", "Kerberos Authentication Weaknesses", "ad", ACTIVE_DIRECTORY,
        cwe="CWE-287",
        mitre_attack=("T1558/003", "T1558/004", "T1550/003"),
        aliases=("kerberoasting", "kerberoast", "asrep roasting", "as-rep roasting",
                 "asreproasting", "golden ticket", "silver ticket", "spn",
                 "service principal name", "ticket forgery", "tgs request",
                 "service ticket", "krbtgt"),
        summary="Kerberos issues tickets that can be requested offline and cracked, "
                "or forged outright when the relevant key material is reachable.",
        sources=(
            ("https://www.rfc-editor.org/rfc/rfc4120.html", "standard"),
            ("https://attack.mitre.org/techniques/T1558/", "taxonomy"),
            ("https://cwe.mitre.org/data/definitions/287.html", "cwe"),
        ),
    ),
    ClassSeed(
        "ad_ntlm", "NTLM Authentication Weaknesses", "ad", ACTIVE_DIRECTORY,
        cwe="CWE-294",
        mitre_attack=("T1557/001", "T1550/002"),
        aliases=("ntlm", "ntlmv1", "relay", "ntlm relay", "name piping",
                 "named pipe", "nbns spoofing", "smb relay", "responder"),
        summary="An NTLM challenge can be relayed to a second service, or a captured "
                "hash replayed, because NTLM authenticates the connection rather "
                "than the channel to it.",
        sources=(
            ("https://attack.mitre.org/techniques/T1557/001/", "taxonomy"),
            ("https://cwe.mitre.org/data/definitions/294.html", "cwe"),
            ("https://learn.microsoft.com/en-us/openspecs/windows_protocols/ms-nlmp/", "docs"),
            ("https://learn.microsoft.com/en-us/openspecs/windows_protocols/ms-adts/", "docs"),
        ),
    ),
    ClassSeed(
        "ad_ldap", "LDAP as an Attack Surface", "ad", ACTIVE_DIRECTORY,
        cwe="CWE-90",
        mitre_attack=("T1087/002",),
        aliases=("ldap", "ldap injection", "ldap filter injection", "null bind",
                 "anonymous bind", "ldap signing", "channel binding"),
        summary="Directory queries are attacker-reachable structure: an unescaped "
                "filter changes the query, and an unsigned bind lets the response "
                "be forged.",
        sources=(
            ("https://www.rfc-editor.org/rfc/rfc4511.html", "standard"),
            ("https://cwe.mitre.org/data/definitions/90.html", "cwe"),
        ),
    ),
    ClassSeed(
        "ad_acl_abuse", "Active Directory ACL Abuse", "ad", ACTIVE_DIRECTORY,
        cwe="CWE-269",
        mitre_attack=("T1222/001", "T1003/006"),
        aliases=("acl abuse", "genericwrite", "genericall", "writedacl",
                 "writeowner", "dcsync", "dcsync rights", "object access abuse",
                 "privilege escalation rights", "acl misconfiguration"),
        summary="A principal holds a permission on an object that permits changing "
                "what that object grants, so read access becomes control of the "
                "domain.",
        sources=(
            ("https://attack.mitre.org/techniques/T1222/001/", "taxonomy"),
            ("https://cwe.mitre.org/data/definitions/269.html", "cwe"),
            ("https://learn.microsoft.com/en-us/windows/win32/secauthz/access-control", "docs"),
        ),
    ),
    ClassSeed(
        "ad_delegation", "Kerberos Delegation Abuse", "ad", ACTIVE_DIRECTORY,
        cwe="CWE-863",
        mitre_attack=("T1134/003",),
        aliases=("delegation abuse", "unconstrained delegation",
                 "constrained delegation", "resource based constrained delegation",
                 "rbcd", "s4u2self", "s4u2proxy", "ms-was"),
        summary="Delegation lets one identity authenticate as another to a third "
                "service, so the ticket a server holds can be replayed as the "
                "client it was issued for.",
        sources=(
            ("https://attack.mitre.org/techniques/T1134/003/", "taxonomy"),
            ("https://cwe.mitre.org/data/definitions/863.html", "cwe"),
            ("https://learn.microsoft.com/en-us/windows-server/security/kerberos/kerberos-authentication-overview", "docs"),
            ("https://learn.microsoft.com/en-us/openspecs/windows_protocols/ms-adts/", "docs"),
        ),
    ),
    ClassSeed(
        "adcs_abuse", "Active Directory Certificate Services Abuse", "ad", ACTIVE_DIRECTORY,
        cwe="CWE-295",
        mitre_attack=("T1649",),
        aliases=("ad cs", "adcs", "certificate template", "certificate enrollment",
                 "cert template", "esc1", "esc4", "esc6", "enrollment agent"),
        summary="A certificate template that will issue an authenticating certificate "
                "to a low-privilege principal converts domain public key into a "
                "credential.",
        sources=(
            ("https://attack.mitre.org/techniques/T1649/", "taxonomy"),
            ("https://learn.microsoft.com/en-us/openspecs/windows_protocols/ms-wcce/", "docs"),
            ("https://www.rfc-editor.org/rfc/rfc5280.html", "standard"),
        ),
    ),
    ClassSeed(
        "ad_trust_abuse", "Active Directory Trust Abuse", "ad", ACTIVE_DIRECTORY,
        cwe="CWE-863",
        mitre_attack=("T1484",),
        aliases=("trust abuse", "trust relationship", "forest trust", "external trust",
                 "sid filtering", "trust direction", "cross forest", "transitive trust"),
        summary="A trust lets an identity authenticate across a boundary, so a "
                "principal in one forest may reach an object in another.",
        sources=(
            ("https://attack.mitre.org/techniques/T1484/", "taxonomy"),
            ("https://learn.microsoft.com/en-us/openspecs/windows_protocols/ms-adts/", "docs"),
        ),
    ),
    ClassSeed(
        "ad_group_policy", "Group Policy Abuse", "ad", ACTIVE_DIRECTORY,
        cwe="CWE-269",
        mitre_attack=("T1484/001",),
        aliases=("gpo", "group policy", "group policy preference", "sysvol",
                 "netlogon", "gpt.ini", "scheduled tasks via gpo"),
        summary="Group Policy is applied as files in a share that authenticated "
                "administrators may write, so editing the policy changes what every "
                "affected machine does.",
        sources=(
            # MEASURED SUBJECT AUDIT (tools/audit_rfc_subjects.py, R28): RFC 4459
            # is "MTU and Fragmentation Issues with In-the-Network Tunneling" and
            # RFC 4124 is "Protocol Extensions for Support of Diffserv-aware MPLS
            # Traffic Engineering" — NEITHER has anything to do with Group Policy.
            # Both URLs returned 200 and passed every liveness check, which is
            # precisely why a 200 is not evidence of relevance. Replaced with
            # ATT&CK T1484/001 (Group Policy Modification) + MS Learn on Group
            # Policy client deployment + CWE-269 (Improper Privilege Management),
            # which is the weakness a writable SYSVOL actually instantiates.
            # All three verified 200 AND confirmed on-subject by title; MS-GPDEF
            # was tried first and is 404, so it was not used.
            ("https://attack.mitre.org/techniques/T1484/001/", "taxonomy"),
            ("https://learn.microsoft.com/en-us/windows/client-management/enroll-a-windows-10-device-automatically-using-group-policy", "docs"),
            ("https://cwe.mitre.org/data/definitions/269.html", "cwe"),
        ),
    ),
    ClassSeed(
        "credential_access", "Windows Credential Access", "ad", ACTIVE_DIRECTORY,
        cwe="CWE-522",
        mitre_attack=("T1003",),
        aliases=("credential access", "lsass", "ntds.dit", "sam", "sam hive",
                 "credential dumping", "mimikatz", "dpapi", "vault"),
        summary="Credential material exists in reachable files and process memory, "
                "and recovering it converts one authenticated session into many.",
        sources=(
            ("https://attack.mitre.org/tactics/TA0006/", "taxonomy"),
            ("https://cwe.mitre.org/data/definitions/522.html", "cwe"),
            ("https://learn.microsoft.com/en-us/openspecs/windows_protocols/ms-nlmp/", "docs"),
            ("https://learn.microsoft.com/en-us/openspecs/windows_protocols/ms-adts/", "docs"),
        ),
    ),
    ClassSeed(
        "pass_the_hash", "Pass-the-Hash and Ticket Replay", "ad", ACTIVE_DIRECTORY,
        cwe="CWE-294",
        mitre_attack=("T1550/002", "T1550/003"),
        aliases=("pass the hash", "pass-the-hash", "pth", "pass the ticket",
                 "ticket replay", "overpass the hash"),
        summary="A protocol that authenticates the NTLM hash or a service ticket "
                "rather than a secret the user holds lets that artefact be "
                "replayed verbatim as a credential.",
        sources=(
            ("https://attack.mitre.org/techniques/T1550/002/", "taxonomy"),
            ("https://cwe.mitre.org/data/definitions/294.html", "cwe"),
            ("https://learn.microsoft.com/en-us/openspecs/windows_protocols/ms-nlmp/", "docs"),
            ("https://learn.microsoft.com/en-us/openspecs/windows_protocols/ms-adts/", "docs"),
        ),
    ),
    ClassSeed(
        "password_attacks", "Password Attacks against Active Directory", "ad", ACTIVE_DIRECTORY,
        cwe="CWE-521",
        mitre_attack=("T1110/003",),
        aliases=("password spraying", "spray", "password attack", "password quality",
                 "credential stuffing", "password reuse", "lockout evasion"),
        summary="Directory authentication is online and per-account, so many "
                "accounts against one password succeeds where many passwords "
                "against one account triggers lockout.",
        sources=(
            ("https://attack.mitre.org/techniques/T1110/003/", "taxonomy"),
            ("https://cwe.mitre.org/data/definitions/521.html", "cwe"),
            ("https://learn.microsoft.com/en-us/openspecs/windows_protocols/ms-nlmp/", "docs"),
            ("https://learn.microsoft.com/en-us/openspecs/windows_protocols/ms-adts/", "docs"),
        ),
    ),
    ClassSeed(
        "ad_enumeration", "Active Directory Enumeration", "ad", ACTIVE_DIRECTORY,
        cwe="CWE-200",
        mitre_attack=("T1087/002", "T1018"),
        aliases=("ad enumeration", "domain enumeration", "ldap enumeration of ad",
                 "cldap", "trust enumeration", "domain trust enumeration"),
        summary="Domain membership is queryable without authentication on common "
                "paths, so the directory's own structure discloses the map needed "
                "to attack it.",
        sources=(
            ("https://www.rfc-editor.org/rfc/rfc4511.html", "standard"),
            ("https://attack.mitre.org/techniques/T1087/002/", "taxonomy"),
            ("https://cwe.mitre.org/data/definitions/200.html", "cwe"),
        ),
    ),

    # ================= INTERNAL NETWORK =================================
    ClassSeed(
        "internal_recon", "Internal Network Reconnaissance", "net", INTERNAL_NETWORK,
        cwe="CWE-200",
        mitre_attack=("TA0043",),
        aliases=("internal recon", "internal reconnaissance", "internal enumeration",
                 "host discovery", "network mapping", "subnet discovery",
                 "service enumeration", "port scan"),
        summary="An internal network is not uniform: naming and addressing patterns "
                "predict what a host runs, so enumeration is inference as much as "
                "probing.",
        sources=(
            ("https://attack.mitre.org/tactics/TA0043/", "taxonomy"),
            ("https://www.rfc-editor.org/rfc/rfc1918.html", "standard"),
            ("https://cwe.mitre.org/data/definitions/200.html", "cwe"),
        ),
    ),
    ClassSeed(
        "service_enumeration", "Service Enumeration and Fingerprinting", "net", INTERNAL_NETWORK,
        cwe="CWE-200",
        mitre_attack=("T1046", "T1595"),
        aliases=("service enumeration", "banner grabbing", "service fingerprinting",
                 "version detection", "fingerprinting"),
        summary="A service's announcement identifies its implementation and often its "
                "version, which selects the technique that applies to it.",
        sources=(
            ("https://attack.mitre.org/techniques/T1046/", "taxonomy"),
            ("https://cwe.mitre.org/data/definitions/200.html", "cwe"),
            ("https://learn.microsoft.com/en-us/openspecs/windows_protocols/ms-nlmp/", "docs"),
            ("https://learn.microsoft.com/en-us/windows-server/storage/file-server/smb-signing", "docs"),
        ),
    ),
    ClassSeed(
        "exposed_services", "Exposed Remote Services", "net", INFRASTRUCTURE,
        cwe="CWE-200",
        mitre_attack=("TA0001", "T1133"),
        aliases=("exposed service", "exposed services", "remote services",
                 "internet facing service", "management interface exposure"),
        summary="An administrative protocol reachable from where it should not be "
                "concedes its authentication surface to that reachability.",
        sources=(
            ("https://attack.mitre.org/tactics/TA0001/", "taxonomy"),
            ("https://learn.microsoft.com/en-us/windows-server/networking/", "docs"),
            ("https://cwe.mitre.org/data/definitions/200.html", "cwe"),
        ),
    ),
    ClassSeed(
        "exposed_rmm", "Remote Monitoring and Management Abuse", "net", INFRASTRUCTURE,
        cwe="CWE-200",
        mitre_attack=("T1219",),
        aliases=("rmm", "remote monitoring", "teamviewer", "anydesk", "screenconnect",
                 "remote management tool", "vnc"),
        summary="RMM agents are installed to bypass network controls, so their "
                "reachability and credential handling determine their risk.",
        sources=(
            ("https://attack.mitre.org/techniques/T1219/", "taxonomy"),
            ("https://cheatsheetseries.owasp.org/cheatsheets/Authentication_Cheat_Sheet.html", "cheatsheet"),
        ),
    ),
    ClassSeed(
        "smb", "SMB/CIFS Abuse", "net", INFRASTRUCTURE,
        cwe="CWE-732",
        mitre_attack=("T1021/002",),
        aliases=("smb", "cifs", "null session", "guest session", "smb signing",
                 "smb1", "named pipe coercion", "share enumeration", "psexec"),
        summary="SMB carries authentication, file access and remote execution, and "
                "its signing configuration decides whether a captured authentication "
                "can be relayed.",
        sources=(
            # MEASURED SUBJECT AUDIT (tools/audit_rfc_subjects.py, R28): RFC 4459
            # is "MTU and Fragmentation Issues with In-the-Network Tunneling", not
            # SMB. It passed every liveness check while proving nothing. RFC 1002
            # ("PROTOCOL STANDARD FOR A NetBIOS SERVICE ON A TCP/UDP TRANSPORT")
            # is the correct standards reference for SMB's transport.
            ("https://attack.mitre.org/techniques/T1021/002/", "taxonomy"),
            ("https://www.rfc-editor.org/rfc/rfc1002.html", "standard"),
            ("https://cwe.mitre.org/data/definitions/732.html", "cwe"),
            ("https://learn.microsoft.com/en-us/openspecs/windows_protocols/ms-smb2/", "docs"),
        ),
    ),
    ClassSeed(
        "winrm", "WinRM and PowerShell Remoting", "net", INFRASTRUCTURE,
        cwe="CWE-200",
        mitre_attack=("T1021/006",),
        aliases=("winrm", "wsman", "powershell remoting", "powershell remote",
                 "invoke command", "constrained endpoint"),
        summary="PowerShell remoting authenticates over WinRM and commonly runs as the "
                "target's local context, so it is both a movement and a privilege "
                "mechanism.",
        sources=(
            ("https://attack.mitre.org/techniques/T1021/006/", "taxonomy"),
            ("https://learn.microsoft.com/en-us/windows/win32/winrm/portal", "docs"),
        ),
    ),
    ClassSeed(
        "rdp", "RDP Abuse", "net", INFRASTRUCTURE,
        cwe="CWE-200",
        mitre_attack=("T1021/001",),
        aliases=("rdp", "remote desktop", "nla", "network level authentication",
                 "session hijacking", "terminal services"),
        summary="RDP authenticates the session and, without network level "
                "authentication, authenticates the client to the server as well, so "
                "reachable RDP is reachable access.",
        sources=(
            ("https://attack.mitre.org/techniques/T1021/001/", "taxonomy"),
            ("https://learn.microsoft.com/en-us/windows/win32/termserv/remote-desktop-protocol", "docs"),
        ),
    ),
    ClassSeed(
        "ldap_enum", "LDAP Enumeration", "net", INFRASTRUCTURE,
        cwe="CWE-200",
        mitre_attack=("T1087/002",),
        aliases=("ldap enumeration", "ldap search", "directory tree walk",
                 "anonymous ldap", "ldap tree"),
        summary="LDAP returns directory structure to a client, so filter syntax that "
                "reaches the query shape turns enumeration into extraction.",
        sources=(
            ("https://attack.mitre.org/techniques/T1087/002/", "taxonomy"),
            ("https://www.rfc-editor.org/rfc/rfc4511.html", "standard"),
        ),
    ),
    ClassSeed(
        "dns_enum", "DNS Enumeration", "net", INFRASTRUCTURE,
        cwe="CWE-200",
        mitre_attack=("T1016/001",),
        aliases=("dns enumeration", "zone transfer", "axfr", "dns zone",
                 "zone walking", "ad integrated dns", "srv record", "dns records"),
        summary="DNS names hosts and services, so a zone disclosure enumerates the "
                "network without touching it.",
        sources=(
            ("https://www.rfc-editor.org/rfc/rfc1035.html", "standard"),
            ("https://attack.mitre.org/techniques/T1016/001/", "taxonomy"),
            ("https://learn.microsoft.com/en-us/windows-server/networking/dns/dns-top", "docs"),
        ),
    ),
    ClassSeed(
        "lateral_movement", "Lateral Movement", "net", INTERNAL_NETWORK,
        cwe="CWE-284",
        mitre_attack=("TA0008",),
        aliases=("lateral movement", "move laterally", "pivot", "pivoting",
                 "east west movement", "internal movement"),
        summary="Movement is a choice among protocols available between two hosts, so "
                "the choice depends on what is reachable and what each protocol "
                "authenticates.",
        sources=(
            ("https://attack.mitre.org/tactics/TA0008/", "taxonomy"),
            ("https://cwe.mitre.org/data/definitions/284.html", "cwe"),
            ("https://learn.microsoft.com/en-us/openspecs/windows_protocols/ms-nlmp/", "docs"),
            ("https://learn.microsoft.com/en-us/windows-server/security/kerberos/kerberos-authentication-overview", "docs"),
        ),
    ),
    ClassSeed(
        "tunneling_pivoting", "Tunneling and Pivoting", "net", INTERNAL_NETWORK,
        cwe="CWE-200",
        mitre_attack=("T1090",),
        aliases=("tunneling", "tunnelling", "pivoting", "socks", "socks proxy",
                 "port forwarding", "proxy", "chisel", "reverse tunnel"),
        summary="A tunnel carries one protocol inside another, so reachability that "
                "policy forbids directly can be reintroduced by a host that both "
                "sides accept.",
        sources=(
            ("https://attack.mitre.org/techniques/T1090/", "taxonomy"),
            ("https://cwe.mitre.org/data/definitions/200.html", "cwe"),
            ("https://learn.microsoft.com/en-us/openspecs/windows_protocols/ms-nlmp/", "docs"),
            ("https://learn.microsoft.com/en-us/openspecs/windows_protocols/ms-adts/", "docs"),
        ),
    ),
    # ------------------------------------------------------------------
    # Privilege escalation. Registered in `bug_class` by a research effort on
    # 2026-10-03 but never declared here, which left five classes in the db
    # with no page anywhere ("resolves to ... which is absent"). Declaring them
    # is the repair: the class is real, its vocabulary is mechanism-shaped, and
    # with zero gated items it renders `Not yet researched.` — an honest gap
    # (I11) rather than a row that lies about existing knowledge.
    ClassSeed(
        "windows_privesc_token", "Windows Privilege Escalation via Token "
        "Manipulation", "ad", ACTIVE_DIRECTORY,
        cwe="CWE-269",
        mitre_attack=("T1134",),
        aliases=("token manipulation", "rogue process token", "token "
                 "impersonation", "duplicate token", "steal token",
                 "token privileges", "adjust token privileges",
                 "potato family", "rotten potato", "print spooler potato",
                 "juicy potato", "sweet potato", "rotten potato"),
        summary="A low-privilege token is exchanged for a token acting as a more "
                "privileged principal, so the escalation happens in the token the "
                "process holds rather than in code execution.",
        sources=(
            ("https://attack.mitre.org/techniques/T1134/", "taxonomy"),
            ("https://cwe.mitre.org/data/definitions/269.html", "cwe"),
            ("https://learn.microsoft.com/en-us/windows/win32/api/securitybaseapi/"
             "nf-securitybaseapi-adjusttokenprivileges", "docs"),
        ),
    ),
    ClassSeed(
        "windows_privesc_service", "Windows Privilege Escalation via Service "
        "Abuse", "ad", ACTIVE_DIRECTORY,
        cwe="CWE-269",
        mitre_attack=("T1543",),
        aliases=("unquoted service path", "weak service permissions",
                 "service binary path", "writable service binary",
                 "service dll hijack", "sc.exe", "service configuration",
                 "always install elevated", "msc file hijack",
                 "juicy potato", "privileged service abuse"),
        summary="A service the host starts with more privilege than the account "
                "controlling it can supply, so editing the service definition "
                "becomes code execution at the service's own level.",
        sources=(
            ("https://attack.mitre.org/techniques/T1543/003/", "taxonomy"),
            ("https://cwe.mitre.org/data/definitions/269.html", "cwe"),
            ("https://learn.microsoft.com/en-us/windows/win32/services/services",
             "docs"),
        ),
    ),
    ClassSeed(
        "windows_privesc_hijack", "Windows Privilege Escalation via Access "
        "Token Hijacking", "ad", ACTIVE_DIRECTORY,
        cwe="CWE-269",
        mitre_attack=("T1134",),
        aliases=("access token hijack", "token hijacking", "named pipe "
                 "impersonation", "createprocesswithtoken", "impersonate a "
                 "privileged token", "privilege escalation via token",
                 "privilege escalation via access token"),
        summary="A privileged process is made to act on a request the attacker "
                "supplies, so the elevated token is used without it ever being "
                "stolen from its owner.",
        sources=(
            ("https://attack.mitre.org/techniques/T1134/001/", "taxonomy"),
            ("https://cwe.mitre.org/data/definitions/269.html", "cwe"),
            ("https://learn.microsoft.com/en-us/windows/win32/api/processthreadsapi/"
             "nf-processthreadsapi-createprocessasuserw", "docs"),
        ),
    ),
    ClassSeed(
        "linux_privesc", "Linux Privilege Escalation", "net", INTERNAL_NETWORK,
        cwe="CWE-269",
        aliases=("linux privesc", "privilege escalation", "sudo misconfig",
                 "suid binary", "sgid binary", "writable /etc/passwd",
                 "cron privilege escalation", "path variable hijack",
                 "ld preload", "ld_library_path", "kernel exploit",
                 "capability abuse", "docker escape", "namespace escape",
                 "unprivileged user namespace", "gtfobins"),
        summary="A local user reaches root without a remote foothold: a permissive "
                "sudo rule, a writable binary that a privileged path runs, a "
                "preloadable library, or a kernel bug.",
        sources=(
            ("https://attack.mitre.org/tactics/TA0004/", "taxonomy"),
            ("https://cwe.mitre.org/data/definitions/269.html", "cwe"),
            ("https://gtfobins.github.io/", "research"),
        ),
    ),
    ClassSeed(
        "container_escape", "Container Escape", "net", INTERNAL_NETWORK,
        cwe="CWE-269",
        mitre_attack=("T1611",),
        aliases=("container escape", "docker escape", "container breakout",
                 "break out of container", "privileged container",
                 "host mount", "docker socket", "cgroup escape",
                 "nsenter", "escape the namespace", "mount namespace escape",
                 "shared pid namespace", "release agent"),
        summary="Code inside a container reaches the host: a privileged "
                "capability, a writable host mount, the docker socket, or a "
                "namespace the runtime failed to isolate.",
        sources=(
            ("https://attack.mitre.org/techniques/T1611/", "taxonomy"),
            ("https://cwe.mitre.org/data/definitions/269.html", "cwe"),
            ("https://docs.docker.com/engine/security/", "docs"),
        ),
    ),
    ClassSeed(
        "segmentation_analysis", "Network Segmentation Analysis", "net", INTERNAL_NETWORK,
        cwe="CWE-1188",
        mitre_attack=("TA0005",),
        aliases=("segmentation", "network segmentation", "segmentation analysis",
                 "trust boundary", "firewall analysis", "security boundary",
                 "vlan segmentation"),
        summary="Segmentation is a claim about which pairs of hosts may communicate; "
                "the claim is only as good as the paths actually available.",
        sources=(
            ("https://attack.mitre.org/tactics/TA0005/", "taxonomy"),
            ("https://cwe.mitre.org/data/definitions/1188.html", "cwe"),
            ("https://learn.microsoft.com/en-us/openspecs/windows_protocols/ms-nlmp/", "docs"),
            ("https://learn.microsoft.com/en-us/openspecs/windows_protocols/ms-adts/", "docs"),
        ),
    ),
    ClassSeed(
        "service_enumeration_detail", "Service-Specific Configuration Assessment", "net",
        INFRASTRUCTURE,
        cwe="CWE-16",
        mitre_attack=("T1046",),
        aliases=("service configuration", "configuration assessment", "service hardening",
                 "protocol configuration", "misconfigured service"),
        summary="A service's own configuration — signing, binding, authentication "
                "method — determines whether its protocol weaknesses are reachable.",
        sources=(
            ("https://attack.mitre.org/techniques/T1046/", "taxonomy"),
            ("https://cwe.mitre.org/data/definitions/16.html", "cwe"),
            ("https://cheatsheetseries.owasp.org/cheatsheets/Authentication_Cheat_Sheet.html", "cheatsheet"),
        ),
    ),
)

NET_CLASSES = {c.id: c for c in _NET_SEED}
NET_SEEDS: dict[str, list[str]] = {c.id: [u for u, _ in c.sources] for c in _NET_SEED}
NET_SEED_TYPES: dict[str, tuple[str, ...]] = {
    c.id: tuple(t for _, t in c.sources) for c in _NET_SEED
}

# Classes grouped by specialization, for the domain-health report and for the
# tree generator's per-directory rendering.
BY_SPECIALIZATION: dict[str, list[str]] = {
    INTERNAL_NETWORK: [],
    INFRASTRUCTURE: [],
    ACTIVE_DIRECTORY: [],
}
for _c in _NET_SEED:
    BY_SPECIALIZATION[_c.specialization].append(_c.id)


def corroboration_problems() -> list[str]:
    """Classes that CANNOT pass MIN_PUBLISHER_HOSTS, per the declared seeds.

    Computed from the table, not from a live fetch, so it is available offline
    and cannot be fooled by a fetch that happened to succeed. `verify-seeds` is
    the complementary check: this says "the DECLARATION is too thin", that one
    says "the URL is dead right now".
    """
    from wks import config
    bad = []
    for cid, c in NET_CLASSES.items():
        hosts = c.hosts
        if len(hosts) < config.MIN_PUBLISHER_HOSTS:
            bad.append(f"{cid}: {len(hosts)} host(s) {sorted(hosts)} "
                       f"< MIN_PUBLISHER_HOSTS={config.MIN_PUBLISHER_HOSTS}")
        for u, t in c.sources:
            if t not in config.SOURCE_AUTHORITY:
                bad.append(f"{cid}: source_type {t!r} not in config.SOURCE_AUTHORITY "
                           f"— authority would silently degrade to 3 (R21)")
    return bad


if __name__ == "__main__":
    import json
    import sys
    from urllib.parse import urlparse

    from wks import config

    problems = corroboration_problems()
    print(f"NETWORK classes: {len(NET_CLASSES)}")
    for spec, ids in BY_SPECIALIZATION.items():
        print(f"  {spec:<20} {len(ids):>2}  {', '.join(ids)}")
    all_hosts: dict[str, int] = {}
    for c in _NET_SEED:
        for h in c.hosts:
            all_hosts[h] = all_hosts.get(h, 0) + 1
    print("\nseed host spread:")
    for h, n in sorted(all_hosts.items(), key=lambda kv: -kv[1]):
        print(f"  {h:<28} {n} classes")
    if problems:
        print("\nPROBLEMS:")
        for p in problems:
            print("  " + p)
        sys.exit(1)
    print("\nall classes declare >= MIN_PUBLISHER_HOSTS distinct hosts")
