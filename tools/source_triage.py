"""Split a harvested Notion corpus into HARVESTABLE prose and everything else.

MEASURED on cache/notion_rem01x (400 pages, 1.37 MB):

    thin/empty                 228   no prose beyond a title
    prose                       91   real methodological text
    mimikatz/credential dump    34   sekurlsa::ekeys / lsass output
    commands/tooling            24   bare command lists
    page contains passwords     23   285 `Password: <value>` strings across 36 pages

Two reasons the 57 non-prose pages must not become knowledge:

  1. They are not claims. A `sekurlsa::ekeys` block is an artefact from the
     author's own lab engagement. One account of one engagement is not evidence
     -- the same rule that stops a single write-up from promoting an item.
  2. They carry credential-shaped strings. 285 `Password: ...` values from a
     red-team lab would enter the corpus verbatim and be retrievable by a search
     for "password", which is exactly the wrong place for them.

So only pages that pass the prose test are routed to packet building, and the
rest are recorded as a counted refusal with the reason. The refusals are counted,
never silently dropped: a source that yields 91 usable pages out of 400 is a
fact about the source, not a failure.
"""
import argparse
import json
import os
import re

PROSE_MIN = 1500          # chars of real text
PROSE_WORDS = 150         # words, because long code blocks inflate char count
SECRET_RE = re.compile(r"(?:Password|passwd|pwd)\s*[:=]\s*\S{6,}", re.I)
DUMP_RE = re.compile(r"sekurlsa|lsass|mimikatz|wdigest|kerberos::|pth\b",
                     re.I)
WORD_RE = re.compile(r"[A-Za-z]{3,}")


def classify(text):
    """Return (verdict, reason). verdicts: prose | thin | secret | dump."""
    n_words = len(WORD_RE.findall(text))
    if len(SECRET_RE.findall(text)) >= 3:
        return "secret", "carries credential-shaped values"
    if DUMP_RE.search(text):
        return "dump", "credential-dumping artefact"
    if len(text) < PROSE_MIN or n_words < PROSE_WORDS:
        return "thin", "%d chars / %d words" % (len(text), n_words)
    return "prose", "%d chars / %d words" % (len(text), n_words)


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--dir", required=True)
    ap.add_argument("--out-index", required=True)
    ap.add_argument("--report")
    a = ap.parse_args()

    with open(os.path.join(a.dir, "index.json"), encoding="utf-8") as fh:
        idx = json.load(fh)

    kept, dropped = {}, {}
    for pid, meta in idx.items():
        path = os.path.join(a.dir, meta["file"] + ".md")
        if not os.path.exists(path):
            dropped[pid] = "file missing"
            continue
        with open(path, encoding="utf-8") as fh:
            text = fh.read()
        verdict, reason = classify(text)
        if verdict == "prose":
            kept[pid] = dict(meta, verdict=verdict, words=len(WORD_RE.findall(text)))
        else:
            dropped[pid] = "%s: %s" % (verdict, reason)

    with open(a.out_index, "w", encoding="utf-8") as fh:
        json.dump(kept, fh, indent=1)

    import collections
    c = collections.Counter(v.split(":")[0] for v in dropped.values())
    print("=" * 72)
    print("SOURCE TRIAGE: %s" % a.dir)
    print("=" * 72)
    print("  pages harvested      : %d" % len(idx))
    print("  HARVESTABLE (prose)  : %d" % len(kept))
    for k, n in c.most_common():
        print("  refused %-14s: %d" % (k, n))
    tot = sum(len(re.findall(r"Password\s*[:=]\s*\S{6,}",
                             open(os.path.join(a.dir, m["file"] + ".md"),
                                  encoding="utf-8").read(), re.I))
             for m in idx.values()
             if os.path.exists(os.path.join(a.dir, m["file"] + ".md")))
    print("  credential-shaped strings kept OUT of the corpus: %d" % tot)
    if a.report:
        with open(a.report, "w", encoding="utf-8") as fh:
            json.dump({"kept": kept, "refused": dropped}, fh, indent=1)
        print("  wrote %s" % a.report)
    print("  wrote %s" % a.out_index)


if __name__ == "__main__":
    main()