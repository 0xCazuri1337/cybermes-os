"""Repair ht_stage.py after the patch tool spliced org_of() into read_page().

The patch replaced the `def org_of(url):` LINE but left that function's BODY
dangling inside read_page, so org_of no longer exists and the module cannot be
imported. Line surgery, by index, then compile before write.
"""
import io

P = "tools/ht_stage.py"
lines = io.open(P, encoding="utf-8").read().split("\n")

# find the orphaned body inside read_page: the two lines that used to be org_of
out = []
i = 0
fixed = False
while i < len(lines):
    ln = lines[i]
    if (not fixed and ln.strip() == "return local_page(rel)" and i + 2 < len(lines)
            and lines[i + 1].strip() == 'host = url.split("/")[2]'):
        out.append(ln)
        out.append("")
        out.append("")
        out.append("def org_of(url):")
        out.append('    host = url.split("/")[2]')
        out.append("    return config.publisher_org(host)")
        # skip the two orphaned lines plus any following return
        i += 1
        while i < len(lines) and ("url.split" in lines[i]
                                  or lines[i].strip().startswith("return config.publisher_org")):
            i += 1
        fixed = True
        print("repaired the org_of splice at line %d" % (i + 1))
        continue
    out.append(ln)
    i += 1

src = "\n".join(out)
compile(src, P, "exec")
io.open(P, "w", encoding="utf-8").write(src)
print("lint ok; org_of restored =", fixed)
assert fixed