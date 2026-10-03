"""Harvest real HTB machine write-ups (.md) from GitHub repos into a local cache.

Discovery-only: this produces the PRACTICE corpus that shows which techniques
operators actually meet on boxes. It is NOT evidence for the gate -- every
write-up is one GitHub publisher. Technique items must corroborate against a
normative publisher (PortSwigger / OWASP / MITRE / vendor docs).

Cache layout:  cache/htb/<repo-owner>__<repo>/<slug>.md
Run twice-safe: an existing non-empty cached file is never refetched.
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

ssl_ctx = ssl.create_default_context()
ssl_ctx.check_hostname = False
ssl_ctx.verify_mode = ssl.CERT_NONE
UA = {"User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) Chrome/120",
      "Accept": "application/vnd.github+json"}

# The corpus lives under WKS_ROOT because cache/scratch/ is pruned after 24h
# idle. Producer and consumers MUST agree on this path: a writer that targets a
# different directory produces an invisible second corpus.
_ROOT = os.environ.get("WKS_ROOT") or os.path.dirname(os.path.dirname(
    os.path.abspath(__file__)))
OUT = os.path.join(_ROOT, "research", "corpus", "htb")
os.makedirs(OUT, exist_ok=True)

REPOS = [
    ("ajcriado/htb-writeups", "main", 200_000),
    ("Esther7171/HackTheBox-Writeups-Walkthroughs", "main", 200_000),
    ("Ch4os1/WriteUps-HTB", "main", 200_000),
    ("x00tex/hackTheBox", "main", 200_000),
    ("0xNirvana/Writeups", "master", 200_000),
    ("zweilosec/htb-writeups", "master", 200_000),
    ("Hackplayers/hackthebox-writeups", "master", 200_000),
]


def get(url, tries=3):
    for i in range(tries):
        try:
            req = urllib.request.Request(url, headers=UA)
            return urllib.request.urlopen(req, timeout=45, context=ssl_ctx).read()
        except Exception as e:
            if i == tries - 1:
                raise
            time.sleep(2 * (i + 1))


def main():
    manifest = []
    for repo, branch, maxsize in REPOS:
        dest = os.path.join(OUT, repo.replace("/", "__"))
        os.makedirs(dest, exist_ok=True)
        try:
            tree = json.loads(get(
                f"https://api.github.com/repos/{repo}/git/trees/{branch}?recursive=1"))
        except Exception as e:
            print(f"TREE-ERR {repo}: {str(e)[:70]}", flush=True)
            continue
        if "tree" not in tree:
            print(f"TREE-MISS {repo}: {str(tree)[:70]}", flush=True)
            continue
        blobs = [t for t in tree["tree"]
                 if t["type"] == "blob"
                 and t["path"].lower().endswith((".md", ".markdown"))
                 and 1200 < t.get("size", 0) < maxsize
                 and "template" not in t["path"].lower()
                 and not t["path"].lower().endswith(("readme.md", "license.md", "contributing.md"))]
        print(f"{repo}: {len(blobs)} candidate writeups", flush=True)
        ok = 0
        for t in blobs:
            # Windows-illegal filename chars appear in real repo paths (e.g. a
            # literal `*` in "10.10.11.12*172.16.228.11-FILES02.md"); without
            # this the OSError kills the whole harvest mid-run.
            # Keep the extension LAST: `name-<hash>.md`, never `name.md-<hash>`.
            # A hidden hash suffix after `.md` breaks every `*.md` glob (and
            # the classifier's own endswith check) -- the file becomes
            # uncountable while looking perfectly present on disk.
            base, ext = os.path.splitext(re.sub(r'[<>:"/\\|?*\x00-\x1f]', "_",
                                                t["path"].replace(" ", "_")))
            slug = base[:180] + "-" + hashlib.sha1(t["path"].encode()).hexdigest()[:8] + ext
            path = os.path.join(dest, slug)
            if os.path.exists(path) and os.path.getsize(path) > 500:
                ok += 1
                continue
            quoted = urllib.parse.quote(t["path"])
            url = f"https://raw.githubusercontent.com/{repo}/{branch}/{quoted}"
            try:
                data = get(url)
            except Exception:
                continue
            if len(data) < 500:
                continue
            with open(path, "wb") as f:
                f.write(data)
            # Sidecar index: filename -> (real repo path, citable blob URL).
            # The slug is sanitised and hashed, so the true URL is otherwise
            # unrecoverable -- and an item that cannot cite its source cannot
            # pass verify_quotes. Writing the index as we go means a crash
            # never orphans an already-downloaded file.
            with open(path + ".src.json", "w", encoding="utf-8") as f:
                json.dump({
                    "repo": repo, "branch": branch, "path": t["path"],
                    "blob_url": f"https://github.com/{repo}/blob/{branch}/"
                                + urllib.parse.quote(t["path"]),
                    "raw_url": url, "bytes": len(data),
                }, f)
            ok += 1
            time.sleep(0.12)
            if ok % 25 == 0:
                print(f"   {repo} {ok}/{len(blobs)}", flush=True)
        print(f"  -> cached {ok}", flush=True)
        manifest.append({"repo": repo, "branch": branch, "candidates": len(blobs), "cached": ok})

    with open(os.path.join(OUT, "manifest.json"), "w", encoding="utf-8") as f:
        json.dump(manifest, f, indent=2)

    total = 0
    size = 0
    for root, _, files in os.walk(OUT):
        for fn in files:
            if fn.endswith((".md", ".markdown")):
                total += 1
                size += os.path.getsize(os.path.join(root, fn))
    print(f"\nTOTAL cached writeups={total} bytes={size:,}", flush=True)


if __name__ == "__main__":
    main()