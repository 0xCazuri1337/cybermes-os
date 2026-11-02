"""Repair the duplicated closing docstring quote in T24.

The `patch` tool (fourth measured re-indent/duplication defect this session)
emitted the closing triple-quote twice, leaving the module with an
unterminated string.
Fix by script, then compile to prove it.
"""
import io
import py_compile

P = r"C:/Users/Administrator/.hermes/cyber/eval/test_wks_conflict_idempotence.py"
src = io.open(P, encoding="utf-8").read()
bad = 'Runs entirely inside a sandbox db; the canonical db is never touched.\n"""\n"""\n'
good = 'Runs entirely inside a sandbox db; the canonical db is never touched.\n"""\n'
assert bad in src, "expected the duplicated closing quote not found"
src = src.replace(bad, good, 1)
io.open(P, "w", encoding="utf-8").write(src)
py_compile.compile(P, doraise=True)
print("COMPILES OK")
for i, l in enumerate(src.split("\n")[:24], 1):
    print("%3d|%s" % (i, l))