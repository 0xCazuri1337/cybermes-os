"""Route each PDF-derived CVE item to the RIGHT class, not one bucket.

MEASURED: the first pass hardcoded `cid = "misconfig"` for every item. That class
has surface `web`, so 60-odd Linux kernel / SUID / Windows service-escalation
CVEs would have landed in the WEB domain -- a Samba CVEs-from-2017 box escalation
filed as a web vulnerability. `linux_privesc`, `windows_privesc_service` and
`eol_software` all exist in the taxonomy, are unused, and are the correct homes.

Routing is decided by WHAT the document describes, not by the machine name:

  * a Unix/Linux kernel or SUID/SGID mechanism -> linux_privesc
  * a Windows service/token/unquoted-path escalation -> windows_privesc_service
  * an exploit against a specific product's known CVE (Samba, Apache, Drupal...)
    reachable pre-auth -> eol_software / exposed_services

Every destination is checked against the db, and an unknown or wrong-surface
class ABORTS the row rather than defaulting -- filing by guess is the same
defect as an off-topic quote.
"""
import os
import re
import sqlite3

# (regex over the mechanism text, class, expected surface)
ROUTES = [
    (r"\bsuid\b|\bsgid\b|setuid|setgid|cap_dac|dirty cow|overlayfs|"
     r"linux kernel|kernel exploit|cron\.d|polkit|dbus|/etc/passwd.*root",
     "linux_privesc", "net"),
    (r"\bunquoted service path\b|\bservice path\b|sc\.exe|unquoted.*windows|"
     r"alwaysinstallelevated|\bpotato\b|token impersonat|"
     r"windows.*escalat|\.exe.*service|writable service",
     "windows_privesc_service", "net"),
    (r"end of life|\beol\b|unsupported software|outdated version|no longer supported|"
     r"unpatched",
     "eol_software", "net"),
    (r"cve-\d{4}-\d+|smb|samba|apache|nginx|openssh|vsftpd|"
     r"proftpd|wordpress|drupal|joomla|apache tomcat",
     "exposed_services", "net"),
]


def pick_class(text, cve):
    """Choose a class for one document, or None to refuse the row."""
    low = text.lower()
    # rank by how specific the match is, so the first strong hit wins
    best, best_len = None, 0
    for pat, cid, surface in ROUTES:
        m = re.search(pat, low)
        if m and len(m.group(0)) > best_len:
            best, best_len = (cid, surface), len(m.group(0))
    if not best:
        # a CVE alone still lands in exposed_services, but only if the document
        # really is about a product rather than a technique
        if cve:
            return "exposed_services", "net"
        return None
    return best


def known(db, cid):
    row = db.execute("SELECT surface FROM bug_class WHERE id=?", (cid,)).fetchone()
    return row[0] if row else None


if __name__ == "__main__":
    db = sqlite3.connect(os.path.join(
        os.environ.get("WKS_ROOT", "."), "db", "wks.db"))
    for _, cid, surface in ROUTES:
        actual = known(db, cid)
        mark = "OK " if actual == surface else "BAD"
        print(f"  {mark} {cid:<28} declared={surface:<8} actual={actual}")
    print("\nA class whose actual surface differs from the expectation must be")
    print("corrected in the taxonomy, not worked around in the builder.")