P = r'C:/Users/Administrator/.hermes/cyber/knowledge/materials/incoming'

# INDEPENDENT parent-side verification of wave 10.
#
# A child's "I verified all quotes" is a self-report, and so is the gate's own
# PASS -- the gate is the thing under test. This re-fetches each cited URL with
# a SEPARATE implementation (its own UA, its own tag-stripper, its own
# normaliser) and asserts the quote is present, so a bug shared with the gate
# cannot hide.
#
# Also asserts the two hard rules the briefs carried: >=2 DISTINCT publisher
# orgs per item, and no builder page (.notion.site / .gitbook.io / app.notion.com)
# satisfying the multi-publisher requirement.
import io
import json
import os
import random
import re
import sys
import urllib.request
from collections import Counter

sys.path.insert(0, r'C:/Users/Administrator/.hermes/cyber')
from wks import config  # noqa: E402

UA = {'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 '
                    '(KHTML, like Gecko) Chrome/124.0 Safari/537.36'}
TAG = re.compile(r'<[^>]+>')
SAMPLE = int(sys.argv[1]) if len(sys.argv) > 1 else 40
FILES = sorted(f for f in os.listdir(P) if f.startswith('w10-') and f.endswith('.json'))

cache = {}


def fetch(url, timeout=45):
    if url in cache:
        return cache[url]
    try:
        req = urllib.request.Request(url, headers=UA)
        with urllib.request.urlopen(req, timeout=timeout) as r:
            raw = r.read(1_500_000)
            ok = int(r.status) == 200
    except Exception as e:
        cache[url] = (False, '%s: %s' % (type(e).__name__, str(e)[:50]))
        return cache[url]
    import html as H
    s = raw.decode('utf-8', 'ignore')
    s = re.sub(r'(?is)<(script|style)[^>]*>.*?</\1>', ' ', s)
    s = TAG.sub(' ', s)
    s = H.unescape(H.unescape(s))
    s = s.replace('\u00a0', ' ').replace('\u200b', '')
    s = re.sub(r'\s+', ' ', s)
    cache[url] = (ok, s)
    return cache[url]


def norm(q):
    q = q.replace('\u00a0', ' ').replace('\u200b', '')
    q = re.sub(r'\s+', ' ', q).strip()
    # same normalisations the gate documents
    q = q.replace('\u2018', "'").replace('\u2019', "'")
    q = q.replace('\u201c', '"').replace('\u201d', '"')
    q = q.replace('\u2013', '-').replace('\u2014', '-').replace('\u2212', '-')
    q = re.sub(r'\s+([,.;:!?)\]}])', r'\1', q)
    q = re.sub(r'([(\[{])\s+', r'\1', q)
    return q


items = []
for f in FILES:
    raw = io.open(os.path.join(P, f), encoding='utf-8').read()
    raw = '\n'.join(l for l in raw.splitlines()
                    if not l.strip().startswith('// COMPLETE'))
    items.extend(json.loads(raw)['items'])
print('items across %d wave-10 files: %d' % (len(FILES), len(items)))

# --- structural rules, no network -------------------------------------------
bad_org, builder_only, no_disproof, single_src = [], [], [], []
for it in items:
    srcs = it.get('sources') or []
    orgs = {config.publisher_org(s.get('host') or '') for s in srcs}
    if len(orgs) < 2:
        bad_org.append((it['item_key'], sorted(orgs)))
    real = {o for o in orgs if not any(
        config.is_builder_host(s.get('host') or '') for s in srcs
        if config.publisher_org(s.get('host') or '') == o)}
    if len(real) < 2:
        builder_only.append((it['item_key'], sorted(orgs)))
    if len(srcs) < 2:
        single_src.append(it['item_key'])
    if not it.get('disproof'):
        no_disproof.append(it['item_key'])

print('\nitems with <2 distinct publisher ORGS: %d' % len(bad_org))
for k, o in bad_org[:10]:
    print('   ', k, o)
print('items where a BUILDER page is needed to reach 2 orgs: %d' % len(builder_only))
for k, o in builder_only[:10]:
    print('   ', k, o)
print('items with <2 sources: %d' % len(single_src))
print('items missing a disproof: %d' % len(no_disproof))

# --- verbatim quote check on a random sample ---------------------------------
cites = []
for it in items:
    for s in it.get('sources') or []:
        if s.get('quote') and s.get('url'):
            cites.append((it['item_key'], s['url'], s['quote']))
print('\ntotal citations in the wave: %d' % len(cites))
hosts = Counter(u.split('/')[2] for _, u, _ in cites)
print('cited hosts:')
for h, n in hosts.most_common():
    print('   %-40s %d' % (h, n))

random.seed(10)
sample = random.sample(cites, min(SAMPLE, len(cites)))
print('\nre-fetching %d sampled citations through an INDEPENDENT matcher...' % len(sample))
ok = miss = dead = 0
misses = []
for key, url, quote in sample:
    good, body = fetch(url)
    if not good:
        dead += 1
        misses.append((key, url, 'DEAD: %s' % body))
        continue
    if norm(quote) in norm(body):
        ok += 1
    else:
        # progressive relaxation, mirroring the documented matcher
        hay = body.replace('`', '').replace('|', ' ').replace('_', ' ')
        needle = norm(quote).replace('`', '').replace('|', ' ').replace('_', ' ')
        if needle in hay:
            ok += 1
        else:
            miss += 1
            misses.append((key, url, 'quote absent (len=%d)' % len(quote)))

print('  verbatim OK      : %d' % ok)
print('  quote ABSENT     : %d' % miss)
print('  page unreachable : %d' % dead)
for key, url, why in misses[:12]:
    print('   MISS %s\n        %s\n        %s' % (key, url, why))

print('\nSUMMARY: %d/%d citations verified verbatim; %d structural violations'
      % (ok, len(sample), len(bad_org) + len(builder_only) + len(no_disproof)))