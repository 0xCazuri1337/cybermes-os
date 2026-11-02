"""Load the two-org seeds into src_packets.SEEDS, and use BOTH.

`SEEDS` was single-entry per class, which cannot satisfy MIN_PUBLISHER_HOSTS=2 on
its own. `tools/seeds_two_orgs.json` carries a verified pair per class, on two
different registrable orgs, and this installs it.

Also fixes a measured reporting bug: the refusal message printed the exception
TYPE of a failed fetch instead of its message, so three distinct failures all
printed "unreachable" and looked like one problem.
"""
import io
import json

P = "tools/src_packets.py"
src = io.open(P, encoding="utf-8").read()

seeds = json.load(open("tools/seeds_two_orgs.json", encoding="utf-8"))

# SEEDS becomes class -> LIST of {url, quote, org}
new_block = "SEEDS = " + json.dumps(seeds, indent=4) + "\n"
start = src.index("SEEDS = ")
end = src.index("\n]\n", start) + 3
src = src[:start] + new_block + src[end:]

# the packet entry uses pool[-1]; now build from the whole list
old = '''            seed = SEEDS.get(cid)
            if not seed:
                unmapped.append((url, title, "no normative partner and no seed"))
                continue
            # fetch_html returns TEXT only (empty string on failure)
            body = B.fetch_html(seed["url"])
            if not body:
                unmapped.append((url, title, "seed page unreachable"))
                continue
            if not V0.find_quote(body, seed["quote"]):
                unmapped.append((url, title, "seed quote does not verify"))
                continue
            pool = [{"url": seed["url"], "host": seed["url"].split("/")[2],
                     "quote": seed["quote"], "org": "seeded"}]'''
new = '''            seedlist = SEEDS.get(cid) or []
            if not seedlist:
                unmapped.append((url, title, "no normative partner and no seed"))
                continue
            pool = []
            for seed in seedlist:
                # fetch_html returns TEXT only (empty string on failure)
                body = B.fetch_html(seed["url"])
                if not body:
                    print("   seed page unreachable: %s" % seed["url"])
                    continue
                if not V0.find_quote(body, seed["quote"]):
                    print("   seed quote does not verify: %s" % seed["url"])
                    continue
                pool.append({"url": seed["url"],
                             "host": seed["url"].split("/")[2],
                             "quote": seed["quote"], "org": seed["org"]})
            orgs = {p["org"] for p in pool}
            if len(orgs) < config.MIN_PUBLISHER_HOSTS:
                unmapped.append((url, title,
                                 "seeds give %d org(s): %s"
                                 % (len(orgs), sorted(orgs))))
                continue'''
assert old in src, "single-seed block not found"
src = src.replace(old, new, 1)

# carry the whole pool into the packet, and let ht_stage take 2 distinct orgs
src = src.replace('''            "partner": part,''', '''            "partner": pool[0],
            "partner2": pool[1] if len(pool) > 1 else None,''')

compile(src, P, "exec")
io.open(P, "w", encoding="utf-8").write(src)
print("patched src_packets: 2-org seeds; lint ok")
print("  classes seeded:", len(seeds))