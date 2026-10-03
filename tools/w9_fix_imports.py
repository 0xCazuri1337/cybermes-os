import io
import re

P = r"C:/Users/Administrator/.hermes/cyber/tools/w9_parent_audit.py"
src = io.open(P, encoding="utf-8").read()

# 1. normalise the mangled import block: keep only top-level stdlib imports
head_end = src.index('ROOT = os.path.dirname')
head = '''"""Independent audit of PROMOTED items (parent-side, no child trust).

1. Re-fetch every cited URL of a sample and confirm each recorded quote is on the page,
   using the GATE'S OWN matcher (wks.verify_quotes.find_quote) after
   tools/w9_validate_checker.py proved it both ways.
2. Re-derive the publisher rule on what actually got promoted: builder hosts and
   same-organisation host pairs must not satisfy the >=2 publisher rule.

Usage: python tools/w9_parent_audit.py [sample_size]
"""
import html
import json
import os
import random
import re
import sqlite3
import sys
import urllib.request

'''
src = head + src[head_end:]

# 2. use find_quote instead of a naive substring test
src = src.replace(
    "    sys.path.insert(0, ROOT)\n    from wks.config import publisher_org, is_builder_host",
    "    sys.path.insert(0, ROOT)\n"
    "    from wks.config import publisher_org, is_builder_host\n"
    "    from wks.verify_quotes import find_quote")
src = src.replace("        if norm(quote) in page:",
                  "        if find_quote(page, quote):")

io.open(P, "w", encoding="utf-8").write(src)
print("rewrote", P)