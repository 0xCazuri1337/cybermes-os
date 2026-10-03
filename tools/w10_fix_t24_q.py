P = r'C:/Users/Administrator/.hermes/cyber/eval/test_wks_conflict_idempotence.py'

import io
import py_compile

# The patch tool emitted the closing triple-quote twice, leaving an unterminated
# string. Remove the stray pair. This script deliberately has NO docstring: a
# literal triple-quote inside one would terminate it early, which is exactly the
# error being repaired.
Q3 = chr(34) * 3

src = io.open(P, encoding='utf-8').read()
bad = ('Runs entirely inside a sandbox db; the canonical db is never touched.\n'
       + Q3 + '\n' + Q3 + '\n')
good = ('Runs entirely inside a sandbox db; the canonical db is never touched.\n'
        + Q3 + '\n')
assert bad in src, 'expected duplicated closing quote not found'
src = src.replace(bad, good, 1)
io.open(P, 'w', encoding='utf-8').write(src)
py_compile.compile(P, doraise=True)
print('COMPILES OK')
for i, line in enumerate(src.split('\n')[:24], 1):
    print('%3d|%s' % (i, line))