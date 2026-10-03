import re, sys
from pathlib import Path
CACHE = Path(sys.argv[1]) if len(sys.argv) > 1 and Path(sys.argv[1]).is_dir() else Path(__import__("os").environ.get("TMPDIR")) / "w10cache2"
idx = dict()
for line in (CACHE / "index.txt").read_text(encoding="utf-8").splitlines():
    u, p = line.split("\t")
    idx[u] = Path(p)

args = [a for a in sys.argv[1:] if not a.startswith("-")] + \
       [a for a in sys.argv[1:] if a.startswith("-")]
_ = sys.argv
needle = args[0] if len(args) > 0 else "Group Policy"
win = int(args[1]) if len(args) > 1 else 400
only = args[2] if len(args) > 2 else ""
for u, p in idx.items():
    if only and only not in u:
        continue
    t = p.read_text(encoding="utf-8")
    hits = list(re.finditer(re.escape(needle), t, re.I))
    if not hits:
        continue
    print(f"===== {u}  ({len(hits)} hits)")
    for m in hits[:8]:
        a = max(0, m.start() - win // 2); b = min(len(t), m.end() + win // 2)
        print("---")
        print(t[a:b].strip())
        print()