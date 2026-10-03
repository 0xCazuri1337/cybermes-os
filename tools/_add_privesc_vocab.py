"""Add the 5 new privilege-escalation classes to relevance.CLASS_VOCAB.

MEASURED: the 5 classes were registered in `bug_class` but had no entry in
`wks/relevance.py:CLASS_VOCAB`, and `assess()` returns None for an unknown class
("the registry has no opinion"). A None means UNPROBEABLE and must never HOLD an
item — so every privesc item would have been staged with no topic check at all,
and the packet builder's `relevance.assess(...)` guard could not select sentences
for them. Vocabulary is what makes a class reviewable.

Terms are the mechanism words a pentester would actually write, not the class
name alone: a vocabulary of only "privilege escalation" would match every privesc
page equally and the margin test could not discriminate.
"""
import io

P = "wks/relevance.py"
src = io.open(P, encoding="utf-8").read()

NEW = '''    "windows_privesc_token": [
        "access token", "impersonate", "impersonation", "token theft",
        "primary token", "integrity level", "seimpersonate", "sedebug",
        "token duplication", "runas", "createprocesswithtoken",
        "privilege escalation", "system token", "privilege", "named pipe client",
    ],
    "windows_privesc_hijack": [
        "dll hijacking", "dll search order", "com hijacking", "com object",
        "sys path", "writable service path", "load path", "phantom dll",
        "side-loading", "sxs", "manifest", "privilege escalation",
        "writable directory", "binary planting", "program files",
    ],
    "windows_privesc_service": [
        "service trigger", "service abuse", "named pipe", "pipe impersonation",
        "scm", "service control manager", "unquoted service path", "wts",
        "impersonate client", "system service", "privilege escalation",
        "service binary", "alwaysinstallelevated", "coercion",
    ],
    "linux_privesc": [
        "sudo", "suid", "sgid", "capabilities", "cap_", "setcap",
        "interesting groups", "ld.so", "preload", "cron", "systemd",
        "writable service", "docker group", "privilege escalation", "root",
        "polkit", "sudoers", "nsenter", "capability", "shadow", "passwd",
    ],
    "container_escape": [
        "container escape", "runc", "containerd", "docker socket",
        "privileged container", "cgroup", "namespace", "mount namespace",
        "host filesystem", "escape the container", "kubernetes", "pod",
        "hostpath", "securitycontext", "privilege escalation", "escape",
    ],
'''

if '"windows_privesc_token"' in src:
    print("already present")
else:
    anchor = "CLASS_VOCAB: dict[str, list[str]] = {\n"
    i = src.index(anchor) + len(anchor)
    src = src[:i] + NEW + src[i:]
    compile(src, P, "exec")
    io.open(P, "w", encoding="utf-8").write(src)
    print("inserted 5 class vocabularies; lint ok")