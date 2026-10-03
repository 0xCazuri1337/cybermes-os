"""Replace ht_stage's acceptance block with the two-publisher version, by line.

Two measured problems with the earlier patches:
  * the acceptance block anchor did not match (the file had been re-indented),
    so the two-publisher logic was never installed while the `sources:` line WAS
    replaced -- leaving `sources` undefined.
  * `con` is opened AFTER this point in main(), so `twopart.two_part(con)` at
    line 116 raised NameError.

This edits by line index between two stable markers, and compiles before writing.
"""
import io

P = "tools/ht_stage.py"
lines = io.open(P, encoding="utf-8").read().split("\n")

NEW_BLOCK = '''        # A PRACTICE GUIDE IS NOT A PUBLISHER -- the gate says so itself
        # (BUILDER_PAGE_NOT_PUBLISHER). It therefore needs TWO independent
        # NORMATIVE publishers to reach MIN_PUBLISHER_HOSTS. A normative source
        # IS a publisher, which is why the HackTricks wave promoted 72 items on
        # this same path with a single partner.
        sources = [{
            "url": r["hacktricks_url"], "source_type": "reference",
            "host": r["hacktricks_url"].split("/")[2],
            "publisher": "source-guide", "quote": quote},
            {"url": r["partner_url"], "source_type": "research",
            "host": r["partner_url"].split("/")[2],
            "publisher": r.get("partner_org") or org_of(r["partner_url"]),
            "quote": part}]

        if is_guide(r["hacktricks_url"]):
            pool = tp.get(r["class_id"], [])
            if len(pool) < config.MIN_PUBLISHER_HOSTS:
                refused.append((r["class_id"], page,
                                "guide source needs %d independent normative "
                                "orgs, class has %d"
                                % (config.MIN_PUBLISHER_HOSTS, len(pool))))
                continue
            have = {org_of(r["partner_url"])}
            for cand in pool:
                if cand["org"] in have:
                    continue
                sources.append({
                    "url": cand["url"], "source_type": "research",
                    "host": cand["host"], "publisher": cand["org"],
                    "quote": cand["quote"]})
                have.add(cand["org"])
                if len(have) >= config.MIN_PUBLISHER_HOSTS:
                    break

        pubs = {s["publisher"] for s in sources
                if s["publisher"] not in ("source-guide", "")}
        if len(pubs) < config.MIN_PUBLISHER_HOSTS:
            refused.append((r["class_id"], page,
                            "only %d real publisher org(s): %s"
                            % (len(pubs), sorted(pubs))))
            continue'''.split("\n")

# --- 1. replace the acceptance block (from the "# Two REAL publishers" comment
#        through the "continue" that ends it) -------------------------------
start = None
for i, ln in enumerate(lines):
    if "Two REAL publishers are required" in ln:
        start = i
        break
if start is None:
    raise SystemExit("acceptance block marker not found")
end = start
while "continue" not in lines[end]:
    end += 1
print("replacing lines %d..%d" % (start + 1, end + 1))
lines[start:end + 1] = NEW_BLOCK

# --- 2. move the two_partner pool AFTER con is opened ----------------------
for i, ln in enumerate(lines):
    if "tp = twopart.two_part(con)" in ln:
        del lines[i - 2:i + 1]          # the comment lines + the call
        print("removed the misplaced twopart call at line %d" % (i + 1))
        break
for i, ln in enumerate(lines):
    if ln.strip() == "con = store.connect()":
        lines.insert(i + 1, "    # Two DISTINCT normative publishers per class, so a")
        lines.insert(i + 2, "    # guide-sourced item can still satisfy MIN_PUBLISHER_HOSTS.")
        lines.insert(i + 3, "    tp = twopart.two_part(con)")
        print("inserted twopart.two_part(con) after con = store.connect()")
        break
else:
    raise SystemExit("con = store.connect() not found")

src = "\n".join(lines)
compile(src, P, "exec")
io.open(P, "w", encoding="utf-8").write(src)
print("lint ok")