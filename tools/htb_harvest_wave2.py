"""Second harvest wave: widen the repo set to close the 5 genuinely-missing classes.

MEASURED GAP: ssti, xxe, nosql, idor and request-smuggling have NO technique
module in the 512-writeup cache -- the only candidates found were index stubs
("Server-side Attacks" is a 4.9KB table of contents that merely names SSTI, and
"Active Directory LDAP" is a 1.8KB PowerShell cheatsheet), so the builder's
abort was CORRECT and must not be worked around by inventing a quote.

The standing order is that a gap becomes a NEW SUBGOAL, not a stop. So this
widens the source set rather than relaxing the gate: more repos, and the
larger previously-skipped repos (HackerOne, 0xdf mirrors, Ired/NetSPI-style
collections) which hold per-box walkthroughs covering exactly these classes.
"""
import hashlib
import json
import os
import re
import ssl
import sys
import time
import urllib.parse
import urllib.request

SCRATCH = os.path.dirname(os.path.abspath(__file__))
OUT = os.path.join(SCRATCH, "htb")
sys.path.insert(0, r"C:\Users\Administrator\.hermes\cyber")
from wks import config  # noqa: E402

ctx = ssl.create_default_context()
ctx.check_hostname = False
ctx.verify_mode = ssl.CERT_NONE
UA = {"User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) Chrome/120",
      "Accept": "application/vnd.github+json"}

# repos likely to carry per-box writeups for the missing classes
REPOS = [
    ("0xdf/htb-machines", "master"),
    ("0xdf/htb-writeups", "master"),
    ("HackerOne/hackthebox-machines-writeups", "main"),
    ("smashinggeek/HTB-Writeups", "main"),
    ("Bishiboosh/HTB-Writeups", "main"),
    ("Fickfick/HTB-Writeups", "main"),
    ("valeriali/HTB-Writeups", "main"),
    ("S41N/HTB-Writeups", "main"),
    ("danielmiessler/htb-writeups", "main"),
    ("hendriknielaender/htb-writeups", "main"),
    ("0xWizardOfHz/HTB-Writeups", "main"),
    ("AdmiralP/HTB-Writeups", "main"),
    ("jperezvu/HTB-writeups", "master"),
    ("AndreyMedvedev/HTB-Writeups", "main"),
    ("OffensiveSecurity/HTB", "main"),
    ("HackTheBox-Academy/HTB-Academy", "main"),
    ("Tyzva/HTB-Writeups", "main"),
    ("ignis-sec/HTB-Writeups", "main"),
    ("0xdeadb0b/HTB-Writeups", "main"),
    ("AlessandroC/HTB-Writeups", "main"),
]

# classes the second wave must serve, for the coverage report at the end
TARGETS = ["ssti", "xxe", "nosql", "idor", "smuggl", "smuggling", "ssrf"]


def get(url, tries=2):
    for i in range(tries):
        try:
            return urllib.request.urlopen(
                urllib.request.Request(url, headers=UA), timeout=40, context=ctx).read()
        except Exception:
            if i == tries - 1:
                raise
            time.sleep(1.5 * (i + 1))


def slug_for(path):
    base, ext = os.path.splitext(
        re.sub(r'[<>:"/\\|?*\x00-\x1f]', "_", path.replace(" ", "_")))
    return base[:170] + "-" + hashlib.sha1(path.encode()).hexdigest()[:8] + ext


def main():
    got_new = 0
    for repo, branch in REPOS:
        dest = os.path.join(OUT, repo.replace("/", "__"))
        try:
            tree = json.loads(get(
                f"https://api.github.com/repos/{repo}/git/trees/{branch}?recursive=1"))
        except Exception as e:
            print(f"  skip {repo}: {type(e).__name__}", flush=True)
            continue
        if "tree" not in tree:
            print(f"  skip {repo}: {str(tree)[:50]}", flush=True)
            continue
        blobs = [t for t in tree["tree"]
                 if t["type"] == "blob"
                 and t["path"].lower().endswith((".md", ".markdown"))
                 and 1500 < t.get("size", 0) < 400_000
                 and not re.search(r"readme|license|contribut|template",
                                   t["path"], re.I)]
        if not blobs:
            print(f"  {repo}: 0 candidates", flush=True)
            continue
        os.makedirs(dest, exist_ok=True)
        n = 0
        for t in blobs:
            sp = os.path.join(dest, slug_for(t["path"]))
            if os.path.exists(sp + ".src.json"):
                n += 1
                continue
            url = f"https://raw.githubusercontent.com/{repo}/{branch}/" \
                  + urllib.parse.quote(t["path"])
            try:
                data = get(url)
            except Exception:
                continue
            if len(data) < 1500:
                continue
            with open(sp, "wb") as f:
                f.write(data)
            with open(sp + ".src.json", "w", encoding="utf-8") as f:
                json.dump({"repo": repo, "branch": branch, "path": t["path"],
                           "blob_url": f"https://github.com/{repo}/blob/{branch}/"
                                       + urllib.parse.quote(t["path"]),
                           "raw_url": url, "bytes": len(data)}, f)
            n += 1
            got_new += 1
            time.sleep(0.1)
        print(f"  {repo}: {n}/{len(blobs)} writeups", flush=True)

    print(f"\nnew files this wave: {got_new}")
    total = 0
    for root, _, files in os.walk(OUT):
        total += sum(1 for f in files if f.endswith((".md", ".markdown")))
    print(f"total cached writeups now: {total}")

    # coverage check: does any cached file now teach the missing classes?
    KEY = {"ssti": ["ssti", "template injection", "{{7*7}}", "jinja", "twig"],
           "xxe": ["xxe", "xml external", "<!entity", "!doctype"],
           "nosql": ["nosql", "mongodb", "$ne", "$gt"],
           "idor": ["idor", "insecure direct object", "broken access control"],
           "smuggling": ["request smuggling", "smuggling", "transfer-encoding"]}
    print("\ncoverage after wave 2:")
    for cls, needles in KEY.items():
        hits = []
        for root, _, files in os.walk(OUT):
            for fn in files:
                if not fn.endswith((".md", ".markdown")):
                    continue
                try:
                    txt = open(os.path.join(root, fn), encoding="utf-8",
                               errors="replace").read().lower()
                except Exception:
                    continue
                if any(n.lower() in txt for n in needles):
                    hits.append(os.path.join(root, fn))
                    break
        print(f"  {cls:<12} {len(hits)} file(s)")


if __name__ == "__main__":
    main()