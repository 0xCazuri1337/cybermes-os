"""Install the two-publisher acceptance block by EXACT line range.

The previous attempt located the block by searching for the comment text
"Two REAL publishers are required", which no longer matched because an earlier
patch had re-indented the file. Result: the old single-publisher test survived,
`is_guide()` was never consulted, and every guide item was refused with
"only 1 real publisher org(s)" -- the two-partner logic existed in the file but
was dead code.

This version replaces lines 159..168 VERBATIM, having first asserted that those
lines are the block I think they are. If the assertion fails, nothing is written.
"""
import io

P = "tools/ht_stage.py"
lines = io.open(P, encoding="utf-8").read().split("\n")

START, END = 158, 167          # 0-based: lines 159..168 inclusive

expect_first = "        # Two REAL publishers are required, and the source page is not one"
expect_last = "            continue"
assert lines[START].rstrip() == expect_first, \
    "line %d is %r, expected the acceptance block" % (START + 1, lines[START])
assert lines[END].rstrip() == expect_last, \
    "line %d is %r, expected the block's closing continue" % (END + 1, lines[END])
print("assertion passed: lines %d..%d are the old block"
      % (START + 1, END + 1))

NEW = '''        # A PRACTICE GUIDE IS NOT A PUBLISHER -- the gate says so itself
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

lines[START:END + 1] = NEW
src = "\n".join(lines)
compile(src, P, "exec")
io.open(P, "w", encoding="utf-8").write(src)
print("replaced %d lines with the two-publisher block; lint ok" % len(NEW))