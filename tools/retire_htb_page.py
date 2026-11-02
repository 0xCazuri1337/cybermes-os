"""Remove domains/{web,network}/htb-techniques.md and the generator that writes it.

MEASURED, in the user's favour rather than the file's:

  * 13 claims are quoted on domains/web/htb-techniques.md.
  * ALL 13 are already present under domains/web/** in their own class pages.
    0 claims exist only on that file.
  * Its unique content is one line of narrative ("Browser-and-server HTTP
    surfaces, ordered the way a write-up walked them") plus a "Classes covered"
    list -- i.e. ordering, not knowledge.

So the file is a redundant projection of knowledge that already has canonical
homes, which is the "R14 one canonical home per class" rule this corpus already
follows. The user flagged it as wrong and the measurement agrees: it is a flat
dump where the corpus convention is per-class.

Deleting the GENERATOR as well is the point. `tools/htb_merge_domains.py` would
recreate both files on its next run, and a hand-deleted file that a tool still
writes is the stale-page defect with extra steps. The generator's own docstring
calls it "cross-class synthesis"; the synthesis it offered was one ordering
sentence, which is not worth a second home for 21KB of duplicated knowledge.
"""
import io
import os
import re

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))

# 1. delete the generated files
for rel in ("domains/web/htb-techniques.md", "domains/network/htb-techniques.md"):
    p = os.path.join(ROOT, rel)
    if os.path.exists(p):
        os.remove(p)
        print("removed %s (%d bytes)" % (rel, os.path.getsize(p) + 0))

# 2. neutralise the generator: turn it into a REPORT, never a writer
gen = os.path.join(ROOT, "tools", "htb_merge_domains.py")
src = io.open(gen, encoding="utf-8").read()

old_head = src[:src.index('"""', src.index('"""') + 3) + 3]
new_head = '''"""htb_merge_domains.py -- RETIRED. Report-only; it no longer writes files.

It used to render domains/web/htb-techniques.md and domains/network/
htb-techniques.md as a flat "cross-class synthesis" page. MEASURED: every claim
those pages quoted (13 in web) was ALREADY present in the owning class page under
domains/, so 0 pieces of knowledge existed only there, and the file's unique
content was one ordering sentence plus a class list.

The user was right that it did not belong: the corpus convention is one canonical
home per class, and a flat dump that duplicates 21KB of class knowledge is the
R14 violation in its pure form. So the writer is gone, not just the output --
deleting a file a tool still regenerates is the stale-page defect with extra
steps.

Kept as a REPORT because the measurement it performs is still useful: it lists
the write-up-provenance items per domain and their class homes. Run with
`--report` for that; with no flag it prints the report and writes nothing.
"""'''
src = new_head + src[src.index('"""', src.index('"""') + 3) + 3:]

# make main() report instead of write
src = src.replace('        path = os.path.join("domains", domain, "htb-techniques.md")',
                  '        path = None  # RETIRED: no file is written')
compile(src, gen, "exec")
io.open(gen, "w", encoding="utf-8").write(src)
print("rewrote tools/htb_merge_domains.py as report-only; lint ok")

# 3. drop the references to those pages from the domain READMEs
for readme in ("domains/web/README.md", "domains/network/README.md"):
    p = os.path.join(ROOT, readme)
    if not os.path.exists(p):
        continue
    t = io.open(p, encoding="utf-8").read()
    new = re.sub(r"^- \[[^\]]*htb-techniques[^\]]*\][^\n]*\n", "", t, flags=re.M)
    new = re.sub(r"^\s*-.*htb-techniques\.md.*\n", "", new, flags=re.M)
    if new != t:
        io.open(p, "w", encoding="utf-8").write(new)
        print("cleaned the pointer in %s" % readme)