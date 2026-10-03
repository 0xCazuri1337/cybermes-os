# One citation unreachable by my verifier: cors.technique.acao_null_on_a_sandboxed_
# document_surface_is_the_reachable_bypass -> https://www.w3.org/TR/cors/
#
# My checker got HTTP 403; tools/qget.py (the gate's own fetcher) got 200 with
# 597,902 chars. So the page IS live and the 403 was a User-Agent / bot-wall
# artefact of MY independent implementation, not a dead citation. That is the
# mirror image of the wave-9 finding, where 3 apparent misses were extraction
# artefacts rather than fabrications.
#
# This prints the item's actual quote and locates it on the real page, so the
# verdict rests on the text rather than on which fetcher answered.

import io
import json
import os
import sys

sys.path.insert(0, r'C:/Users/Administrator/.hermes/cyber')
from wks import pipeline, verify_quotes  # noqa: E402

P = r'C:/Users/Administrator/.hermes/cyber/research/incoming'
KEY = 'cors.technique.acao_null_on_a_sandboxed_document_surface_is_the_reachable_bypass'

for f in sorted(os.listdir(P)):
    if not (f.startswith('w10-') and f.endswith('.json')):
        continue
    raw = io.open(os.path.join(P, f), encoding='utf-8').read()
    raw = '\n'.join(l for l in raw.splitlines()
                    if not l.strip().startswith('// COMPLETE'))
    for it in json.loads(raw)['items']:
        if it['item_key'] == KEY:
            print('file: %s' % f)
            print('claim: %s' % it['claim'])
            for s in it['sources']:
                print('\nsource url  : %s' % s['url'])
                print('host        : %s' % s['host'])
                print('quote (%d ch): %s' % (len(s['quote'] or ''), s['quote']))
                page = pipeline.fetch(s['url'], limit=2_000_000)
                body = page.get('text') or ''
                print('fetch       : ok=%s chars=%d' % (page.get('ok'), len(body)))
                print('gate matcher: %s' % verify_quotes.find_quote(body, s['quote'] or ''))
                nq = (s['quote'] or '').replace('\u2019', "'").replace('\u2018', "'")
                print('straight-quote variant present: %s'
                      % (nq in body.replace('\u2019', "'").replace('\u2018', "'")))