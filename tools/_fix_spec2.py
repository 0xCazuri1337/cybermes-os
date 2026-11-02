"""Move the 5 privesc rows from CHAINS into CLASSES, where they belong.

The first attempt anchored on "the last .md tuple in the file", which is in
CHAINS, so the rows were inserted into the wrong list: CHAINS gained five
class-shaped entries and CLASSES stayed at 86. A write that succeeds into the
wrong table is worse than a failed write -- `wks.domains --check` still reported
5 missing pages while the source looked updated.

This anchors on the CLASSES list's own bounds instead: from the line that opens
`CLASSES = [` to the line that closes it, then inserts before the close.
"""
import io
import re

P = "tools/taxonomy/taxonomy_spec.py"
src = io.open(P, encoding="utf-8").read()

PATHS = [
    "network/active-directory/windows-privesc-token.md",
    "network/active-directory/windows-privesc-hijack.md",
    "network/active-directory/windows-privesc-service.md",
    "network/internal-network/linux-privesc.md",
    "network/internal-network/container-escape.md",
]

# --- 1. remove the mis-placed copies wherever they landed -------------------
removed = 0
for path in PATHS:
    pat = re.compile(
        r'    \("%s",[^\n]*\n(?:     "[^\n]*\n)*?(?:     "[^\n]*",\n)?' % re.escape(path))
    # match the tuple through its closing paren, tolerating wrapped strings
    pat2 = re.compile(
        r'    \("%s", .*?\),\n(?:     ".*?"\),\n)?' % re.escape(path), re.S)
    new, n = pat2.subn("", src)
    if n:
        src = new
        removed += n
        print("removed mis-placed row: %s" % path)
print("removed %d row(s)" % removed)

# --- 2. insert into CLASSES, before its closing bracket ---------------------
open_m = re.search(r"(?m)^CLASSES = \[\n", src)
if not open_m:
    raise SystemExit("CLASSES list not found")
close = src.index("\n]\n", open_m.end())
block = src[open_m.end():close]

rows = [
    ("network/active-directory/windows-privesc-token.md",
     "Windows Privilege Escalation via Token Manipulation", "CWE-269", "A09:2021",
     "A low-privilege token is exchanged for a token acting as a more privileged principal, so the escalation happens in the token the process holds rather than in code execution."),
    ("network/active-directory/windows-privesc-hijack.md",
     "Windows Privilege Escalation via Load-Path Hijacking", "CWE-427", "A08:2021",
     "A writable directory on the executable search path lets an attacker-controlled binary load in place of a trusted one, so a normal program launch becomes privileged code execution."),
    ("network/active-directory/windows-privesc-service.md",
     "Windows Privilege Escalation via Service and Named-Pipe Abuse", "CWE-269", "A04:2021",
     "A privileged service is induced to load or impersonate an attacker-chosen identity, so the escalation runs with SYSTEM through a legitimate service entry point."),
    ("network/internal-network/linux-privesc.md",
     "Linux Privilege Escalation", "CWE-269", "A01:2021",
     "A local foothold becomes root through a misconfigured permission, a permissive interpreter path, or an over-privileged group membership, so the escalation needs no exploit at all."),
    ("network/internal-network/container-escape.md",
     "Container Escape and Runtime Privilege Escalation", "CWE-269", "A05:2021",
     "The boundary is the container runtime rather than the host kernel directly: an over-privileged socket, a writable mount, or a permissive runtime flag lets a container act on the host."),
]
added = 0
for path, title, cwe, owasp, summary in rows:
    if '"%s"' % path in block:
        print("already in CLASSES: %s" % path)
        continue
    block += '    ("%s", "%s", "%s", "%s",\n     "%s"),\n' % (
        path, title, cwe, owasp, summary)
    added += 1

src = src[:open_m.end()] + block + src[close:]
compile(src, P, "exec")
io.open(P, "w", encoding="utf-8").write(src)
print("inserted %d row(s) into CLASSES" % added)
print("lint ok")