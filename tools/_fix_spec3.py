"""Insert the 5 privesc CLASS rows into taxonomy_spec.CLASSES by LINE INDEX.

Two earlier attempts failed, both instructive:

  attempt 1  anchored on "the last .md tuple in the file" -> that tuple is in
              CHAINS, so the rows landed in the wrong list while CLASSES stayed
              at 86 and `domains --check` still reported 5 missing pages.
  attempt 2  tried to remove the misplaced rows with a regex spanning wrapped
              string literals; it clipped a tuple's opening line, the result did
              not compile, and because the write came after the compile the file
              on disk was never touched -- which is the only reason it survived.

This version does neither. It finds the CLASSES list by line index, finds its
closing bracket by bracket depth, and inserts whole lines there. No regex spans
a string literal, and the write happens only after the result compiles.
"""
import io

P = "tools/taxonomy/taxonomy_spec.py"
lines = io.open(P, encoding="utf-8").read().split("\n")

ROWS = [
    ("network/active-directory/windows-privesc-token.md",
     "Windows Privilege Escalation via Token Manipulation", "CWE-269", "A09:2021",
     "A low-privilege token is exchanged for a token acting as a more privileged "
     "principal, so the escalation happens in the token the process holds rather "
     "than in code execution."),
    ("network/active-directory/windows-privesc-hijack.md",
     "Windows Privilege Escalation via Load-Path Hijacking", "CWE-427", "A08:2021",
     "A writable directory on the executable search path lets an "
     "attacker-controlled binary load in place of a trusted one, so a normal "
     "program launch becomes privileged code execution."),
    ("network/active-directory/windows-privesc-service.md",
     "Windows Privilege Escalation via Service and Named-Pipe Abuse", "CWE-269",
     "A04:2021",
     "A privileged service is induced to load or impersonate an attacker-chosen "
     "identity, so the escalation runs with SYSTEM through a legitimate service "
     "entry point."),
    ("network/internal-network/linux-privesc.md",
     "Linux Privilege Escalation", "CWE-269", "A01:2021",
     "A local foothold becomes root through a misconfigured permission, a "
     "permissive interpreter path, or an over-privileged group membership, so the "
     "escalation needs no exploit at all."),
    ("network/internal-network/container-escape.md",
     "Container Escape and Runtime Privilege Escalation", "CWE-269", "A05:2021",
     "The boundary is the container runtime rather than the host kernel directly: "
     "an over-privileged socket, a writable mount, or a permissive runtime flag "
     "lets a container act on the host."),
]

# --- locate CLASSES = [ and its matching close by depth ---------------------
start = None
for i, ln in enumerate(lines):
    if ln.strip() == "CLASSES = [":
        start = i
        break
if start is None:
    raise SystemExit("CLASSES = [ not found")

depth = 0
close = None
for i in range(start, len(lines)):
    depth += lines[i].count("[") - lines[i].count("]")
    if depth == 0 and i > start:
        close = i
        break
if close is None:
    raise SystemExit("CLASSES list close not found")
print("CLASSES spans lines %d..%d" % (start + 1, close + 1))

body = "\n".join(lines[start:close])
todo = [r for r in ROWS if '"%s"' % r[0] not in body]
if not todo:
    print("all rows already present; no change")
    raise SystemExit(0)

new_lines = []
for path, title, cwe, owasp, summary in todo:
    new_lines.append('    ("%s", "%s", "%s", "%s",' % (path, title, cwe, owasp))
    new_lines.append('     "%s"),' % summary)
    print("  + %s" % path)

out = lines[:close] + new_lines + lines[close:]
src = "\n".join(out)
compile(src, P, "exec")          # write ONLY after it compiles
io.open(P, "w", encoding="utf-8").write(src)
print("inserted %d row(s); lint ok" % len(todo))