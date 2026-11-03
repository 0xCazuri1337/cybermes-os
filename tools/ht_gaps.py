"""C7: turn the UNMAPPED HackTricks pages into ACTIONABLE gaps.

An unmapped page is not automatically a missing class. 378 of them are mostly
per-service protocol pages (one page per port), which is not 378 classes. This
groups them into gap FAMILIES and names, for each, the concrete decision:

  NEW CLASS   - a genuinely distinct vulnerability mechanism with no class today
  EXTEND      - a mechanism that belongs to an existing class as a VARIANT
  NOT A CLASS - per-service/per-tool detail that becomes an ITEM, not a class

Output: knowledge/materials/ht_gaps.json plus a readable table.
"""
import collections
import json
import os
import re
import sys

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
from wks import store  # noqa: E402

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))

# Per-service / per-tool pages: these are ITEMS for an existing network class,
# never new classes. Matched on the HackTricks filename shape "<port>-pentesting-x".
SERVICE_RE = re.compile(
    r"^(?:\d[\d,/\-\s]*-)?pentesting[- ](?:[a-z0-9]+)$|^\d+-pentesting-|"
    r"pentesting-[a-z0-9]+(?:-[a-z0-9]+)*$")

# Real mechanism families seen in the unmapped set, checked before the generic
# service shape. Key = (class it extends, human label).
EXTEND_TO = [
    (r"^\d+,\d+ - Pentesting TACACS\+|49 - Pentesting", "ad_ntlm",
     "TACACS+ is an alternative credential protocol to NTLM"),
    (r"Pentesting Kerberos|88 - Pentesting", "ad_kerberos", ""),
    (r"Pentesting NetBios|137,138,139", "smb", "NetBIOS session layer"),
    (r"Pentesting ISCSI|3260", "smb", "iSCSI sits on the same block-auth model"),
    (r"Pentesting LDAP|389 - ", "ad_ldap", ""),
    (r"RFC ?1918|Cisco SNMP|SNMP", "service_enumeration_detail", ""),
    (r"Pentesting VoIP|Basic VoIP|SIP", "exposed_rmm", "RMM/VoIP management exposure"),
    (r"Pentesting Modbus|Pentesting BACNet|OPC Unified|EthernetIP",
     "service_enumeration_detail", "OT/ICS protocol exposure"),
    (r"Pentesting Docker|44134|Pentesting Tiller|kubernetes",
     "misconfig", "container/orchestrator misconfiguration"),
    (r"Pentesting MongoDB|27017", "nosql", "NoSQL exposure surface"),
    (r"Pentesting MySQL|3306|Pentesting Postgresql|5432|MSSQL",
     "sqli", "database service exposure"),
    (r"Pentesting Redis|6379|Memcache|11211", "exposed_services",
     "unauthenticated datastore exposure"),
    (r"Pentesting Samba|SMB", "smb", ""),
    (r"Pentesting SSH|22 - |Pentesting Telnet|23 - ", "lateral_movement",
     "remote shell lateral movement"),
    (r"Pentesting FTP|21 - ", "exposed_rmm", ""),
    (r"Pentesting WinRM", "winrm", ""),
    (r"Pentesting IPsec|IKE VPN", "tunneling_pivoting", ""),
    (r"Pentesting Cisco|SAP|Veeam|GlusterFS|Hadoop|Cassandra|InfluxDB|"
     r"Elasticsearch|Kibana|Splunk|CouchDB|Neo4j|RabbitMQ|MQTT|NATS|AMQP",
     "exposed_rmm", "exposed management/data service"),
    (r"Steal postmessage|postmessage|PostMessage|Iframe Traps|SOP",
     "clickjacking", "framing / cross-origin UI redress"),
    (r"SAML Attacks|SAML Basics", "oauth", "SAML is the enterprise federation flow"),
    (r"Bypass Payment Process|Captcha Bypass|2FA", "authn", ""),
    (r"Timing Attacks", "race", "timing side channel"),
    (r"Email Injections|Phone Number Injections|formula.*injection",
     "cmd", "injection into a downstream sink"),
    (r"Dependency Confusion|supply|Supply", "supply_chain", ""),
    (r"Browser Extension", "xss", "extension-borne XSS"),
    (r"Client Side Template|CSTI", "ssti", "client-side variant"),
    (r"Evil Twin|Rogue AP|WPA|WEP|WPS|802\.1X|OWE|Passpoint|EasyMesh|"
     r"Client-Isolation|Protected Management|Hotspot|Roaming",
     "internal_recon", "wireless reconnaissance"),
    (r"Phishing|Anti-Forensic|Detecting Phishing", "exposed_rmm",
     "human-layer exposure"),
    (r"FreeIPA|Directory Services|adws", "ad_ldap", ""),
    (r"Harvesting tickets", "ad_kerberos", ""),
    (r"Interesting Groups - Linux Privesc|euid, ruid, suid|Linux Capabilities|"
     r"SELinux|ld\.so privesc|Containers|Escaping from Jails|Payloads to execute|"
     r"Bypass Linux Restrictions",
     "internal_recon", "linux privesc surface"),
    (r"Logstash|Splunk LPE", "internal_recon", "log platform exposure"),
    (r"Filesystem, Inodes|Payloads|Wildcards|Linux Environment|Useful Linux Commands",
     "internal_recon", "linux host triage"),
    (r"Fuzzing", "internal_recon", "input fuzzing surface"),
    (r"Threat Modeling", "internal_recon", "threat model surface"),
    (r"Forensic|Acquisition|Carving|Pcap|Anti-Forensic|Docker Forensics|"
     r"Ios Backup|Image Acquisition",
     "internal_recon", "host forensic surface"),
    (r"Lua Sandbox|Python sandbox|Bypass Python", "cmd",
     "sandbox escape leading to command execution"),
    (r"Cisco - vmanage|Cisco SNMP|Cisco Catalyst", "exposed_rmm",
     "network device management exposure"),
    (r"Pentesting Methodology|Pentesting Network", "internal_recon", ""),
    (r"H2 - Java SQL|DotNetNuke|WebSec", "misconfig", "product-specific exposure"),
]


def classify(p):
    """Return (decision, target, note) for one unmapped page."""
    hay = (p["title"] + " " + p["rel"]).lower()
    for rx, cid, note in EXTEND_TO:
        if re.search(rx.lower(), hay):
            return "EXTEND", cid, note
    base = os.path.basename(p["rel"])[:-3]
    if SERVICE_RE.match(base) or re.match(r"^\d+", base):
        return "NOT A CLASS", "exposed_services", "per-service page -> an item"
    return "NEW CLASS", None, "unrecognised mechanism"


def main():
    with open(os.path.join(ROOT, "research", "ht_crosswalk.json"),
              encoding="utf-8") as fh:
        xw = json.load(fh)
    con = store.connect()
    have = {r[0] for r in con.execute("SELECT id FROM bug_class")}
    dom = {r[0]: r[1] for r in con.execute(
        "SELECT class_id,domain FROM class_domain")}

    gaps = []
    for p in xw["UNMAPPED"]:
        decision, target, note = classify(p)
        gaps.append({"title": p["title"], "rel": p["rel"],
                     "section": p["section"], "depth": p["depth"],
                     "decision": decision, "target": target, "note": note,
                     "target_domain": dom.get(target) if target else None})

    with open(os.path.join(ROOT, "research", "ht_gaps.json"), "w",
              encoding="utf-8") as fh:
        json.dump(gaps, fh, indent=1)

    c = collections.Counter(g["decision"] for g in gaps)
    print("=" * 78)
    print("GAP TRIAGE: %d unmapped in-scope pages" % len(gaps))
    for k, v in c.most_common():
        print("  %-14s %d" % (k, v))
    print()

    print("=" * 78)
    print("A) PROPOSED NEW CLASSES (mechanisms with no class today)")
    newc = collections.defaultdict(list)
    for g in gaps:
        if g["decision"] == "NEW CLASS":
            newc[g["title"]].append(g)
    for title, gs in sorted(newc.items(), key=lambda kv: -len(kv[1])):
        doms = {g["section"] for g in gs}
        print("  %-52s (%d page(s))  %s" % (title[:52], len(gs), sorted(doms)))
    print()

    print("=" * 78)
    print("B) EXTEND AN EXISTING CLASS (grouped by target)")
    ext = collections.defaultdict(list)
    for g in gaps:
        if g["decision"] == "EXTEND" and g["target"] in have:
            ext[g["target"]].append(g)
    for cid, gs in sorted(ext.items(), key=lambda kv: -len(kv[1])):
        note = next((g["note"] for g in gs if g["note"]), "")
        print("  %-26s %-8s +%2d pages   %s" % (cid, dom.get(cid), len(gs), note))
        for g in sorted(gs, key=lambda g: g["title"])[:6]:
            print("        - %s" % g["title"][:74])
        if len(gs) > 6:
            print("        ... +%d more" % (len(gs) - 6))
    print()

    print("=" * 78)
    print("C) PER-SERVICE PAGES -> items for an existing network class, not classes")
    svc = [g for g in gaps if g["decision"] == "NOT A CLASS"]
    print("  %d pages. Highest-value ones (unique protocols):" % len(svc))
    seen = set()
    for g in sorted(svc, key=lambda g: g["title"]):
        k = g["title"].split("Pentesting")[-1].strip()
        if k in seen:
            continue
        seen.add(k)
        if len(seen) <= 30:
            print("     %s" % g["title"][:76])
    print("\nwrote knowledge/materials/ht_gaps.json (%d records)" % len(gaps))


if __name__ == "__main__":
    main()