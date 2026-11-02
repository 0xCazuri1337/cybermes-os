"""Search primitives by class or keyword (index + by-class files)."""
import json, sys, os, glob

ROOT = os.path.dirname(os.path.abspath(__file__))
INDEX = os.path.join(ROOT, "index.json")
BYCLASS = os.path.join(ROOT, "by-class")

def main():
    q = " ".join(sys.argv[1:]).lower().strip()
    hits = 0
    try:
        with open(INDEX) as f:
            data = json.load(f)
    except Exception:
        data = {"primitives": []}
    for p in data.get("primitives", []):
        haystack = " ".join(str(v) for v in p.values()).lower()
        if not q or q in haystack:
            print(f"[index] {p.get('name')}  [{p.get('class')}]  {p.get('type')}")
            hits += 1
    for path in glob.glob(os.path.join(BYCLASS, "**", "*.md"), recursive=True):
        try:
            with open(path) as f:
                txt = f.read().lower()
        except Exception:
            continue
        if not q or q in txt or q in path.lower():
            rel = os.path.relpath(path, ROOT)
            print(f"[file] {rel}")
            hits += 1
    if hits == 0:
        print("no matches")

if __name__ == "__main__":
    main()

