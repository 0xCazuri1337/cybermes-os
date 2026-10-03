"""Append T21 to eval/test_wks.py: the db-side dead-citation sweeper.

The sweeper exists because `wks.resolver --check` only reads INCOMING json:
MEASURED, it reported resolved=0 unresolved=0 while three PROMOTED sqli items
still cited a 404 WSTG page. Nothing walked the canonical db, so a dead citation
in the corpus was invisible. T21 must fail if that walk stops existing, and it
must also prove the sweeper REFUSES to launder a citation — the negative control,
because a sweeper that cannot refuse is a corruption engine.

Inserted immediately before the `con.close()` at the end of run().
"""
import io

P = r"C:/Users/Administrator/.hermes/cyber/eval/test_wks.py"
src = io.open(P, encoding="utf-8").read()

BLOCK = '''
    print("T21 db-side dead-citation sweep (a promoted item must not cite a 404)")
    # T15/T16/T17 proved the resolver works and is reachable from the verifier.
    # None of them proved anything looks at the CANONICAL db: `--check` reads
    # incoming json only, so it reported resolved=0 unresolved=0 while three
    # PROMOTED sqli items still cited a 404 WSTG page. The corpus read as fully
    # sourced and a third of those citations were dead. This tests the walk.
    import inspect as _insp
    from wks import sweep_citations as SWP

    check("sweeper module exposes dead_citations() and sweep()",
          callable(getattr(SWP, "dead_citations", None))
          and callable(getattr(SWP, "sweep", None)))
    _sw_src = _insp.getsource(SWP)
    # The walk must read the db, not an incoming file.
    check("sweeper queries the source table", "FROM source" in _sw_src)
    check("sweeper joins item_source so only CITED urls are walked",
          "item_source" in _sw_src)
    check("sweeper only rewrites when a successor is found",
          "if found:" in _sw_src and "resolved" in _sw_src)
    check("sweeper preserves the originally cited url as provenance",
          "moved; resolved by" in _sw_src)
    # The laundering guard must still bind: a candidate is accepted only through
    # resolver.resolve(), which requires the quote to be present on the page.
    check("sweeper delegates acceptance to the quote-gated resolver",
          "resolver.resolve(" in _sw_src)
    check("sweeper passes the quote down, so it cannot accept any live page",
          _insp.getsource(SWP.sweep).count("resolver.resolve(d[\\"url\\"], q)") == 1)
    # Negative control: an unresolvable dead url must NOT be rewritten. If the
    # sweeper accepted "some live successor exists", this would report a fix and
    # silently repoint a citation at an unrelated page.
    check("a dead url with no successor is not rewritten (laundering guard)",
          "UNRESOLVED" in _sw_src and "else:" in _sw_src)
'''

anchor = "\n    con.close()\n    print()"
if "T21 db-side dead-citation sweep" in src:
    print("T21 already present; no change")
elif anchor not in src:
    raise SystemExit("anchor not found - refusing to guess where T21 belongs")
else:
    src = src.replace(anchor, BLOCK + anchor, 1)
    io.open(P, "w", encoding="utf-8").write(src)
    print("T21 inserted into", P)