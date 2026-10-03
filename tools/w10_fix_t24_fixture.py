P = r'C:/Users/Administrator/.hermes/cyber/eval/test_wks_conflict_idempotence.py'

# Rewrite the fixture so it actually reaches the conflict branch, and give each
# case its own filename.
#
# MEASURED: the fixture cited example.org, which FETCHES FAILED here -> the
# verdict is UNVERIFIED, not FABRICATED, and an unverified item never reaches
# the writer. The idempotence checks therefore passed by never exercising the
# code under test, while the "records a dispute" checks failed. example.com
# returns 200 with 427 chars, which is enough: the quote is absent either way.
import io
import py_compile

src = io.open(P, encoding='utf-8').read()

OLD_SIG = 'def failing_file(sb: Path, claim: str, url: str) -> Path:'
NEW_SIG = 'def failing_file(sb: Path, claim: str, fname: str) -> Path:'
assert OLD_SIG in src
src = src.replace(OLD_SIG, NEW_SIG, 1)

OLD_DOC = ('''    """One item whose quote cannot be on the cited page -> FABRICATED.''')
assert OLD_DOC in src

start = src.index(OLD_SIG)
end = src.index('def register_class(', start)
NEW_FN = '''def failing_file(sb: Path, claim: str, fname: str) -> Path:
    # One item whose quote cannot be on the cited page -> FABRICATED.
    #
    # The cited page MUST fetch. example.org failed here, which yields
    # FETCH_FAILED -> UNVERIFIED, and an unverified item never reaches the
    # conflict branch -- so the first version of this fixture passed the
    # idempotence checks by never exercising the writer at all. example.com
    # returns 200 with 427 chars and is enough: the quote is absent either way.
    p = sb / "research" / "incoming" / fname
    item = {
        "item_key": "t24cl.fp_rule.never_matches_the_page",
        "class_id": "t24cl",
        "kind": "fp_rule",
        "claim": claim,
        "body": "x" * 220,
        "disproof": "Refuted if the quoted span is present on the cited page.",
        "surface": "web",
        "severity_hint": "low",
        "hunting_value": 1,
        "sources": [
            {"url": "https://example.com/", "source_type": "docs",
             "host": "example.com",
             "quote": "a span deliberately absent from any live page zzzq"},
            {"url": "https://example.com/#two", "source_type": "docs",
             "host": "example.com",
             "quote": "another absent span qqqw"},
        ],
    }
    p.write_text(json.dumps({"items": [item]}, indent=1), encoding="utf-8")
    return p


'''
src = src[:start] + NEW_FN + src[end:]

# call sites: pass a filename instead of a url
for old, new in (
    ('f = failing_file(sb, "A claim whose quote is absent from the cited page.",\n                     "https://example.org/absent")',
     'f = failing_file(sb, "A claim whose quote is absent from the cited page.",\n                     "t24a.json")'),
    ('f1 = failing_file(sb, "First distinct absent-quote claim alpha.",\n                      "https://example.org/absent")',
     'f1 = failing_file(sb, "First distinct absent-quote claim alpha.",\n                      "t24b1.json")'),
    ('f2 = failing_file(sb, "Second distinct absent-quote claim beta.",\n                      "https://example.org/other")',
     'f2 = failing_file(sb, "Second distinct absent-quote claim beta.",\n                      "t24b2.json")'),
    ('f = failing_file(sb, "Dry run must not leave a dispute behind.",\n                     "https://example.org/absent")',
     'f = failing_file(sb, "Dry run must not leave a dispute behind.",\n                     "t24c.json")'),
    ('f = failing_file(sb, "Reported as rejected even though deduped.",\n                     "https://example.org/absent")',
     'f = failing_file(sb, "Reported as rejected even though deduped.",\n                     "t24d.json")'),
):
    assert old in src, 'call site not found: %r' % old[:60]
    src = src.replace(old, new, 1)

io.open(P, 'w', encoding='utf-8').write(src)
py_compile.compile(P, doraise=True)
print('COMPILES OK')
print('example.com refs:', src.count('https://example.com/'))
print('example.org refs:', src.count('example.org'))
print('fname call sites:', sum(src.count(x) for x in
                              ('"t24a.json"', '"t24b1.json"', '"t24b2.json"',
                               '"t24c.json"', '"t24d.json"')))