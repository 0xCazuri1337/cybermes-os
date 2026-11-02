"""Install the 2-org seeds into src_packets, by BRACE MATCHING.

The earlier attempt failed because `src.index("\n]\n")` did not find the close of
SEEDS: the dict closes with `}` then `)`, not `]`. Locating the block by counting
braces from the literal is not guessable by search string, so this counts.
"""
import io
import json

P = "tools/src_packets.py"
src = io.open(P, encoding="utf-8").read()

seeds = json.load(open("tools/seeds_two_orgs.json", encoding="utf-8"))
new_block = "SEEDS = " + json.dumps(seeds, indent=4) + "\n"

start = src.index("SEEDS = ")
# brace-match from the first { after the literal
i = src.index("{", start)
depth = 0
for j in range(i, len(src)):
    if src[j] == "{":
        depth += 1
    elif src[j] == "}":
        depth -= 1
        if depth == 0:
            end = j + 1
            break
else:
    raise SystemExit("could not brace-match SEEDS")

print("replacing SEEDS: chars %d..%d" % (start, end))
src = src[:start] + new_block + src[end:]

# use the whole pool, and report the real failure instead of the exception type
start = src.index("            seed = SEEDS.get(cid)")
end = src.index("        prose = B.to_text(md)")
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
                continue

'''
src = src[:start] + new + src[end:]

# carry partner2 into the packet
old = '''            "partner": part,'''
if old in src:
    src = src.replace(old, '''            "partner": pool[0],
            "partner2": pool[1] if len(pool) > 1 else None,''', 1)
    print("packet now carries partner2")

compile(src, P, "exec")
io.open(P, "w", encoding="utf-8").write(src)
print("lint ok; seeded classes:", len(seeds))