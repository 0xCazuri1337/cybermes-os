"""Classes that observation-driven selection deliberately does NOT name.

MEASURED (2026-10-03, bootcamp C3): `orch.hypothesis.SIGNATURES` selected 20
keys, 5 of which were not registered corpus classes, leaving only 15 of 70
reachable. The 55 unreachable classes were invisible in EVERY existing metric —
`metrics`, `gaps` and the masterprompt score all reported health — so a class
could be permanently unselectable and nothing would ever go red.

This module makes that set explicit and reviewed. Every entry states WHY the
class is not selected by behaviour classification, so the gap is a decision on
record rather than an omission nobody can see.

`eval/test_hunt_classification.py` T4 fails on any registered corpus class
that is neither in SIGNATURES nor listed here, so this file cannot rot: adding
a class to the corpus without adding it here fails the suite.

Two categories, and the distinction matters:

  OBSERVATION_GAP
      The class IS selectable in principle — a human recognises the signals
      immediately — but no signal vocabulary has been written for it yet. This
      is unfinished work and is prioritised by corpus size.

  NOT_A_BEHAVIOUR_CLASS
      The class is not identified by observed request/response behaviour. It is
      a property of DEPLOYMENT or ARCHITECTURE (a patch level, a configuration,
      an exposed service), so classifying it from behaviour would be wrong even
      if we could. It is reached by recon and assessment, not by classification.
"""

# --------------------------------------------------------------------------
# Selected by RECON or ASSESSMENT, not by observed behaviour. Naming these
# from a request/response pair would be a category error, so they stay out.
# --------------------------------------------------------------------------
NOT_A_BEHAVIOUR_CLASS = {
    "eol_software": "patch/version state; found by banner or asset inventory, not by behaviour",
    "exposed_services": "service inventory; found by port scan and banner, not by behaviour",
    "exposed_rmm": "management console exposure; found by recon, not by behaviour",
    "container_escape": "container boundary; an assessment property of the runtime",
    "internal_recon": "network position; a recon outcome rather than a class of request",
    "segmentation_analysis": "network topology; an assessment conclusion",
    "service_enumeration": "service inventory (recon)",
    "service_enumeration_detail": "service inventory (recon)",
    "dns_enum": "DNS zone data; recon",
    "ldap_enum": "LDAP directory content; recon",
    "ad_enumeration": "AD directory content; recon",
    "ad_ldap": "AD/LDAP directory content; recon",
    "windows_privesc_token": "token manipulation; reached via AD reconnaissance then a local test",
    "windows_privesc_service": "service misconfiguration; a local assessment property",
    "windows_privesc_hijack": "binary hijack path; a local assessment property",
    "linux_privesc": "local privilege boundary; assessed, not classified from a request",
}

# --------------------------------------------------------------------------
# OBSERVATION_GAP — a human recognises these signals, but no signal vocabulary
# has been written. Prioritised by corpus size; each is a named next subgoal.
# --------------------------------------------------------------------------
OBSERVATION_GAP = {
    "jwt": "token with unvalidated algorithm/claims; 30 items, highest-value gap",
    "oauth": "authorization-server misconfiguration; 33 items",
    "subdomain_takeover": "dangling DNS record; 35 items",
    "file_upload": "unrestricted upload reaching an executable sink; 32 items",
    "host_header": "host header trusted for routing/password reset; 24 items",
    "session": "session fixation/predictability in the session cookie; 21 items",
    "clickjacking": "missing or bypassable frame protection; 24 items",
    "cmd": "argument injection into a shell; 27 items",
    "crlf": "CRLF injection into a response header; 25 items",
    "cache_poisoning": "cache key does not include a varying input; 22 items",
    "cache_deception": "path-based cache confusion; 25 items",
    "prototype_pollution": "merge into Object.prototype via JSON; 37 items",
    "supply_chain": "dependency or build compromise; assessment property",
    "websocket": "cross-site WebSocket hijack; 26 items",
    "rate_limit": "missing or bypassable rate limit; 10 items",
    "otp": "one-time-code weakness; 11 items",
    "info_disclosure": "verbose error or metadata leak; 18 items",
    "misconfig": "exposed administrative configuration; 15 items",
    "api_trust": "API trust boundary; 19 items",
    "credential_access": "credential material exposure; recon/assessment",
    "password_attacks": "offline cracking feasibility; assessment property",
    "pass_the_hash": "NTLM relay/hash reuse; AD-specific technique",
    "lateral_movement": "pivot between hosts; an outcome, not a class",
    "tunneling_pivoting": "pivot transport; an outcome, not a class",
    "smb": "SMB share/service exposure; recon plus a protocol test",
    "ldap": "LDAP injection; 30 items — adjacent to nosql, needs its own vocabulary",
    "rdp": "RDP exposure/weakness; recon plus assessment",
    "winrm": "WinRM exposure; recon",
    "ad_ntlm": "NTLM authentication weakness; AD-specific",
    "ad_kerberos": "Kerberos protocol weakness; AD-specific",
    "ad_delegation": "delegation abuse; AD-specific",
    "ad_trust_abuse": "forest/domain trust abuse; AD-specific",
    "ad_acl_abuse": "ACL abuse; AD-specific",
    "ad_group_policy": "GPO abuse; AD-specific",
    "adcs_abuse": "ADCS abuse; AD-specific",
}

#: class_id -> stated reason. `eval/test_hunt_classification.py` T4 reads this.
ALLOWLIST: dict[str, str] = {**NOT_A_BEHAVIOUR_CLASS, **OBSERVATION_GAP}