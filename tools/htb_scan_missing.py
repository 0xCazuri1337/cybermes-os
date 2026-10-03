"""Wave 2b: find the missing-class write-ups using the SEARCH api, not guesses.

Wave 2a failed completely: all 20 repos were names I INVENTED, and every one
404'd (R11 again — a guessed URL is not a source). Zero files harvested.

But its coverage scan reported the classes are already present in the 512-file
cache (ssti 2, xxe 5, nosql 4, idor 4, smuggling 4 files), so the real gap was
never the source set: it is that the builder's `TOPICAL` map has no entry for
those classes, and the anchors that DID appear were filtered out.

So: use api.github.com/search/code is auth-gated, but repository search is
not, and content search across the CACHE is local and free. This re-scans the
existing cache properly (whole-word, multi-variant needles) and reports exactly
which files can serve each missing class, so the next builder run can target
them instead of re-harvesting.
"""
import io
import json
import os
import re
import sys

# The corpus lives under WKS_ROOT because cache/scratch/ is pruned after 24h
# idle. Producer and consumers MUST agree on this path: a writer that targets a
# different directory produces an invisible second corpus.
_ROOT = os.environ.get("WKS_ROOT") or os.path.dirname(os.path.dirname(
    os.path.abspath(__file__)))
OUT = os.path.join(_ROOT, "research", "corpus", "htb")
HTB = os.path.join(SCRATCH, "htb")

# Whole-word / multi-variant needles. The wave-2a scan used naive substring
# matching on a few tokens; this matches the way the builder will.
NEEDLES = {
    "ssti": [r"server[- ]side template", r"\bSSTI\b", r"\{\{.*\}\}", r"jinja2",
             r"\btwig\b", r"template injection"],
    "xxe": [r"\bXXE\b", r"XML External Entity", r"<!ENTITY", r"<!DOCTYPE",
            r"external entit"],
    "nosql": [r"\bNoSQL\b", r"\bmongo", r"\$ne\b", r"\$gt\b", r"mongoDB"],
    "idor": [r"\bIDOR\b", r"Insecure Direct Object", r"Broken Access Control",
             r"access control.*(user|object).*id"],
    "smuggling": [r"request smuggling", r"\bsmuggl", r"Transfer-Encoding: chunked",
                  r"Content-Length.*Transfer-Encoding"],
    "ssrf": [r"\bSSRF\b", r"server[- ]side request forgery", r"169\.254\.169\.254"],
}


def scan():
    files = []
    for root, _, names in os.walk(HTB):
        for fn in names:
            if fn.endswith((".md", ".markdown")):
                p = os.path.join(root, fn)
                side = p + ".src.json"
                if os.path.exists(side):
                    files.append(p)
    return files


def main():
    files = scan()
    print(f"scanning {len(files)} cached write-ups\n")
    out = {}
    for cls, pats in NEEDLES.items():
        rx = re.compile("|".join(pats), re.I)
        hits = []
        for p in files:
            try:
                txt = io.open(p, encoding="utf-8", errors="replace").read()
            except Exception:
                continue
            m = rx.search(txt)
            if not m:
                continue
            meta = json.load(open(p + ".src.json", encoding="utf-8"))
            # the file must be ABOUT the class, not merely mention it once
            if len(rx.findall(txt)) < 2:
                continue
            hits.append({"file": p, "path": meta["path"], "repo": meta["repo"],
                         "raw_url": meta["raw_url"], "hits": len(rx.findall(txt))})
        hits.sort(key=lambda h: -h["hits"])
        out[cls] = hits
        print(f"{cls.upper()}: {len(hits)} usable file(s)")
        for h in hits[:4]:
            print(f"    x{h['hits']:<4} {h['path'][:66]}")
    with open("research/htb_missing_coverage.json", "w", encoding="utf-8") as f:
        json.dump(out, f, indent=2)
    print("\n-> research/htb_missing_coverage.json")


if __name__ == "__main__":
    main()