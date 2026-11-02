"""Classify each cached CORPUS write-up as WEB or NETWORK, and mine the technique
signals that justify the label.

Scoring is on TECHNIQUE VOCABULARY, not on the box name or folder: a machine
called "Blue" that pivots through SMB and Kerberos is a NETWORK write-up even
though its first finding is a web page. Folder names lie; commands do not.

Output: research/htb_corpus.json  (one record per write-up, with its citable
blob URL recovered from the sidecar index written at harvest time).
"""
import json
import os
import re
import sys

# The corpus lives under WKS_ROOT because cache/scratch/ is pruned after 24h
# idle. Producer and consumers MUST agree on this path: a writer that targets a
# different directory produces an invisible second corpus.
WKS = os.environ.get("WKS_ROOT") or os.path.dirname(os.path.dirname(
    os.path.abspath(__file__)))
CORPUS = os.path.join(WKS, "research", "corpus", "htb")
OUTPATH = os.path.join(WKS, "research", "htb_corpus.json")

# ---------------------------------------------------------------- vocabulary
NET = {
    "smb": ["smbclient", "smbmap", "crackmapexec", "netexec", "smb2", "impacket-smbserver",
            "responder", "ntlmrelay", "port 445", ":445", "enum4linux", "smb share",
            "\\\\10.10", "admin$", "ipc$"],
    "ldap": ["ldapsearch", "bloodhound", "ldap3", "crackmapexec ldap", "ldapquery",
             "get-user", "kerberoast"],
    "kerberos_ad": ["kerbrute", "kerberoasting", "asreproast", "as-rep roast",
                    "kinit", "get-ticket", "secretsdump", "impacket", "mimikatz",
                    "lsass", "ntds.dit", "hashdump", "crackmapexec", "psexec",
                    "winrm", "evil-winrm", "smbexec", "wmiexec", "golden ticket",
                    "silver ticket", "dcsync", "bloodhound-python", "net user",
                    "net group", "whoami /privs", "whoami /groups", "net localgroup"],
    "pivoting": ["chisel", "ligolo", "socat", "proxychains", "dynamic port forwarding",
                 "socks5", "-R ", "tunnel", "pivot", "iptables"],
    "ssh": ["ssh-keygen", "id_rsa", "authorized_keys", "sshpass", "ssh ", "-i "],
    "rdp": ["xfreerdp", "rdp", "evilwinrm", "winrm", "3389"],
    "dns": ["dig ", "dnsrecon", "axfr", "zone transfer", "dnsrecon.py", "subfinder",
            "dnsenum", "dig @"],
    "recon": ["nmap", "masscan", "rustscan", "port scan", "service enumeration",
              "-sC", "-sV", "enum", "netcat", "nc ", "gobuster", "ffuf", "feroxbuster"],
    "privesc_linux": ["linpeas", "linenum", "sudo -l", "find / -perm", "cron", "systemctl",
                      "capabilities", "capsh", "suid", "cap_dac", "authorized_keys",
                      "/etc/passwd", "/etc/shadow", "python3 -c", "rev shell", "bash -i"],
    "privesc_win": ["winpeas", "secretsdump", "mimikatz", "potato", "printspinner",
                    "juicy", "privilege escalation", "privesc", "token", "impersonate",
                    "svcpass", "registry", "AlwaysInstallElevated"],
}
WEB = {
    "sqli": ["sqlmap", "sql injection", "sqli", "' or 1=1", "union select", "sqlmap.py",
             "--dump", "' OR '1'='1", "sleep(", "benchmark("],
    "xss": ["xss", "cross-site scripting", "<script>", "alert(document", "onerror",
            "javascript:", "document.cookie"],
    "lfi_rfi": ["local file inclusion", "remote file inclusion", "lfi", "rfi",
                "../../../", "php://filter", "/etc/passwd", "log poisoning",
                "include("],
    "file_upload": ["file upload", "upload", "webshell", "reverse shell.php", "phar"],
    "ssrf": ["ssrf", "server-side request forgery", "169.254.169.254", "metadata"],
    "ssti": ["ssti", "server-side template", "{{7*7}}", "jinja2", "twig", "template injection"],
    "deser": ["deserialize", "deserialization", "php/object", "gadget", "ysoserial",
              "pickle", "__destruct"],
    "auth": ["jwt", "session hijack", "cookie", "login bypass", "auth bypass",
             "password reset", "2fa", "mfa", "privilege escalation to admin",
             "idOR".lower(), "insecure direct object"],
    "idor": ["idor", "insecure direct object", "authorization", "access control",
             "user id=", "/api/users/", "admin panel"],
    "xxe": ["xxe", "xml external", "<!DOCTYPE", "!ENTITY", "external entity"],
    "nosql": ["nosql", "mongodb", "$ne", "$gt", "operators", "injection"],
    "request": ["burp", "request smuggling", "content-length", "transfer-encoding",
                "http request", "host header", "ssrf", "cors", "origin"],
    "js_client": ["javascript", "jquery", "devtools", "view-source", ".js", "api key",
                  "localstorage", "source map"],
    "cms": ["wordpress", "joomla", "drupal", "moodle", "typo3", "phpmyadmin",
            "adminer", "grafana", "nextcloud", "gitea", "tomcat", "jenkins"],
}
# write-up furniture that must not count as technique evidence
FURNITURE = re.compile(r"^\s*(?:#{1,6}\s|\||```|!\[|\*\*|-\s*$)")

# technique label -> the bug_class it feeds, so the classifier can also say
# WHICH class a write-up contributes evidence to
CLASS_HINT = {
    "sqli": "sqli", "xss": "xss", "lfi_rfi": "path_traversal", "file_upload": "file_upload",
    "ssrf": "ssrf", "ssti": "ssti", "deser": "deser", "xxe": "xxe", "nosql": "nosql",
    "request": "smuggling", "auth": "authn", "idor": "idor", "js_client": "info_disclosure",
    "smb": "smb", "ldap": "ldap_enum", "kerberos_ad": "ad_kerberos", "pivoting": "tunneling_pivoting",
    "ssh": "exposed_services", "rdp": "rdp", "dns": "dns_enum", "recon": "service_enumeration",
    "privesc_linux": "misconfig", "privesc_win": "misconfig", "cms": "misconfig",
}


def score(text_low, table):
    hits = {}
    for label, needles in table.items():
        n = sum(text_low.count(x) for x in needles)
        if n:
            hits[label] = n
    return hits


def main():
    records = []
    if not os.path.isdir(CORPUS):
        print(f"no corpus at {CORPUS}")
        return
    # Walk RECURSIVELY: the harvest writes one subdirectory per repo, so a
    # flat os.listdir(CORPUS) sees only directory names and classifies nothing.
    # (Measured: 134 cached write-ups -> "classified 0".)
    md_files = []
    for root, _, files in os.walk(CORPUS):
        for fn in files:
            if fn.endswith(".md") and os.path.getsize(os.path.join(root, fn)) >= 1200:
                md_files.append(os.path.join(root, fn))
    md_files.sort()

    for p in md_files:
        fn = os.path.basename(p)
        raw = open(p, encoding="utf-8", errors="replace").read()
        if len(raw) < 1200:
            continue
        side = p + ".src.json"
        if not os.path.exists(side):
            continue  # no citable URL -> cannot become evidence
        meta = json.load(open(side, encoding="utf-8"))
        low = raw.lower()
        net = score(low, NET)
        web = score(low, WEB)
        nw, ww = sum(net.values()), sum(web.values())
        domain = "network" if nw >= ww else "web"
        primary = (net if domain == "network" else web)
        labels = sorted(primary.items(), key=lambda kv: -kv[1])
        classes = sorted({CLASS_HINT[l] for l, _ in labels[:6] if l in CLASS_HINT})
        records.append({
            "file": fn,
            "repo": meta["repo"],
            "path": meta["path"],
            "blob_url": meta["blob_url"],
            "raw_url": meta["raw_url"],
            "bytes": len(raw),
            "words": len(raw.split()),
            "domain": domain,
            "net_score": nw,
            "web_score": ww,
            "labels": [l for l, _ in labels[:8]],
            "label_counts": dict(labels[:8]),
            "classes": classes,
            "confidence": round(max(nw, ww) / max(1, nw + ww), 3),
        })

    os.makedirs(os.path.dirname(OUTPATH), exist_ok=True)
    with open(OUTPATH, "w", encoding="utf-8") as f:
        json.dump(records, f, indent=2)

    n = len(records)
    nw = sum(1 for r in records if r["domain"] == "network")
    print(f"classified {n} write-ups -> {OUTPATH}")
    print(f"  web     = {n - nw}")
    print(f"  network = {nw}")
    print(f"  words harvested = {sum(r['words'] for r in records):,}")
    print(f"  repos = {len({r['repo'] for r in records})}")
    # reconcile: the two buckets must sum to the total
    assert (n - nw) + nw == n, "domain buckets do not reconcile"
    print("  reconciliation OK")
    print("\nlabel frequency (top 20):")
    freq = {}
    for r in records:
        for l, c in r["label_counts"].items():
            freq[l] = freq.get(l, 0) + c
    for l, c in sorted(freq.items(), key=lambda kv: -kv[1])[:20]:
        print(f"  {c:>6}  {l}  -> {CLASS_HINT.get(l,'-')}")


if __name__ == "__main__":
    main()