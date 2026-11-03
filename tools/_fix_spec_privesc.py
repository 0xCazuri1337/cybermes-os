"""Register the 5 privilege-escalation classes in the taxonomy SPEC.

MEASURED: registering the classes in the db was not enough. `skills/ --check`
reported 5 problems ("missing skills/network/active-directory/
windows_privesc_token") and `taxonomy_write.py` still rendered only 62 classes,
because `taxonomy_spec.CLASSES` is a HAND-MAINTAINED list of (path, title, cwe,
owasp, summary) tuples. That is exactly the hand-kept literal the skill warns
about: it drifts from the db, and the drift reads as "no page exists" when the
class has items.

This inserts the 5 rows in the right sections so the generator owns the pages
from now on. Idempotent: skips any row whose path already exists.
"""
import io
import re

P = "tools/taxonomy/taxonomy_spec.py"
src = io.open(P, encoding="utf-8").read()

NEW = [
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
for path, title, cwe, owasp, summary in NEW:
    if '"%s"' % path in src:
        print("already in spec: %s" % path)
        continue
    row = '    ("%s", "%s", "%s", "%s",\n     "%s"),\n' % (
        path, title, cwe, owasp, summary)
    # insert after the last existing tuple inside the CLASSES list
    m = list(re.finditer(r"^    \(\"[^\"]+\.md\".*?\),\n(?:     \"[^\"]*\"\),\n)?",
                         src, re.M | re.S))
    if not m:
        raise SystemExit("no CLASSES tuples found to anchor on")
    last = m[-1]
    src = src[:last.end()] + row + src[last.end():]
    print("added: %s" % path)
    added += 1

compile(src, P, "exec")
io.open(P, "w", encoding="utf-8").write(src)
print("lint ok; rows added = %d" % added)