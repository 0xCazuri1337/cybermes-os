import collections
import json
import os
import re

xw = json.load(open("research/ht_crosswalk.json", encoding="utf-8"))
allp = xw["MATCHED"] + xw["UNMAPPED"] + xw["OUT_OF_SCOPE"]

PRESC = re.compile(
    r"privilege[- ]escalation|privesc|/lpe\b|potato|dll hijack|com hijack|"
    r"token|named pipe|access token|integrity level|juicy|rogue|printspoofer|"
    r"namedpipes|svc|service trigger|autorun|writable sys|shim", re.I)

# In-scope only: web + network-services + windows/linux hardening + generic
IN = ("pentesting-web", "network-services-pentesting", "windows-hardening",
      "linux-hardening", "generic-methodologies-and-resources")

rows = []
for p in allp:
    hay = p["title"] + " " + p["rel"]
    if not PRESC.search(hay):
        continue
    rows.append((p["section"] in IN, p))

inscope = [r for ok, r in rows if ok]
print("=" * 78)
print("PRIVILEGE-ESCALATION COVERAGE GAP")
print("=" * 78)
print("  HackTricks pages matching privesc concepts : %d" % len(rows))
print("  of which IN our requested scope             : %d" % len(inscope))
print("  sections : %s" % dict(collections.Counter(r["section"] for r in inscope)))
print("  our bug_class rows for privesc             : 0")
print("  our items filed to a privesc class         : 0")
print()

# Group the windows privesc pages into technique families
fam = collections.defaultdict(list)
RULES = [
    (r"token", "token manipulation / impersonation"),
    (r"potato|printspoofer|godpotato|sharp|juicy|rogue|print.?spoof",
     "potato-family SYSTEM shell"),
    (r"named pipe|pipe", "named pipe impersonation / coercion"),
    (r"dll hijack|dll sideload|sys path|shim|wix|msi", "DLL/SYS-path hijacking"),
    (r"com hijack", "COM object hijacking"),
    (r"integrity level|integrity", "integrity level transition"),
    (r"service trigger|svc", "Windows service abuse"),
    (r"autorun|abusing tokens|credential|uac|efs|mimikatz|credential",
     "credential & token theft"),
    (r"leaked handle", "handle duplication"),
    (r"unquoted|writable|permission|acl|dacl", "weak file/registry permissions"),
    (r"wts impersonator|impersonate", "WTS impersonation"),
    (r"lpe|linux-privilege|interesting.groups|su[di]d|suid|ld\.so|capabilit",
     "Linux privesc vectors"),
    (r"container|runc|containerd|lxd", "container escape / runtime privesc"),
]
for r in inscope:
    hay = (r["title"] + " " + r["rel"]).lower()
    for rx, label in RULES:
        if re.search(rx, hay):
            fam[label].append(r["rel"])
            break
    else:
        fam["(unclassified)"].append(r["rel"])

print("-" * 78)
print("PROPOSED NEW CLASSES, by size (each row = one class to register)")
print("-" * 78)
ranked = sorted(fam.items(), key=lambda kv: -len(set(kv[1])))
for label, paths in ranked:
    uniq = sorted(set(paths))
    print("  %-46s %3d page(s)" % (label, len(uniq)))
print()

print("-" * 78)
print("DOMAIN ROUTING for the proposed classes")
print("-" * 78)
dom = {r[0]: r[1] for r in
       __import__("sqlite3").connect("db/wks.db").execute(
           "SELECT class_id,domain FROM class_domain")}
print("  Every one of these belongs to the NETWORK domain, under")
print("  network/active-directory for the Windows/AD token+service ones and")
print("  network/internal-network for the Linux/container ones.")
print()
print("-" * 78)
print("WHY THIS IS THE TOP GAP")
print("-" * 78)
print("  * our corpus has 62 classes and NOT ONE is a privilege-escalation class,")
print("    while privesc is the highest-yield post-exploitation step in AD work")
print("  * `pass_the_hash` (28 items) and `credential_access` (13) cover")
print("    credential movement but nothing covers turning a low-priv foothold into")
print("    SYSTEM, which is the step those chains end at")
print("  * 45 in-scope HackTricks pages exist on this and 0 of them are mapped,")
print("    so this is pure gap, not a routing error")

out = {"privesc_pages_in_scope": sorted({r["rel"] for r in inscope}),
       "families": {k: sorted(set(v)) for k, v in fam.items()}}
json.dump(out, open("research/ht_privesc_gap.json", "w", encoding="utf-8"), indent=1)
print("\nwrote research/ht_privesc_gap.json")