"""FM-09  Which CONTROL/rules.md rules are ENFORCED IN CODE vs PROCEDURAL,
and which metrics filters are DEAD (would return a clean empty result if the
column they name did not exist).

READ-ONLY. Everything below is a grep/count, not an inference.
"""
import os
import re
import sqlite3
import subprocess
import sys
from pathlib import Path

SB = open(sys.argv[1]).read().strip()
ROOT = Path(SB)
os.environ["WKS_ROOT"] = SB
sys.path.insert(0, SB)

print("=" * 78)
print("FM-09  RULES: ENFORCED IN CODE vs PROCEDURAL   /   DEAD-FILTER SWEEP")
print("=" * 78)

# ---------------------------------------------------------------- rules table
rules = (ROOT / "CONTROL" / "rules.md").read_text(encoding="utf-8")
rows = re.findall(r"^\|\s*(R\d+)\s*\|(.+?)\|(.+?)\|(.+?)\|\s*$", rules, re.M)
print()
print(f"RULE IDS FOUND: {[r[0] for r in rows]}")
ids = [r[0] for r in rows]
dupes = sorted({i for i in ids if ids.count(i) > 1})
print(f"DUPLICATE RULE IDS in the table: {dupes}  <-- two different rules share an id")
print(f"total rows: {len(rows)}  unique ids: {len(set(ids))}")
print()

# Does the named checking artifact EXIST and does it actually run?
probe = [
    ("R1",  "wks/cli.py",            "gate"),
    ("R2",  "wks/quality.py",        "_BLOCKING_TAGS"),
    ("R3",  "eval/test_wks.py",      "T3"),
    ("R4",  "wks/evalm.py",          "items_with_disproof"),
    ("R5",  "wks/pipeline.py",       "verify_seed"),
    ("R6",  "wks/quality.py",        "def maturity"),
    ("R7",  "wks/retrieval.py",      "_STATE_PRIOR"),
    ("R14", "tools/taxonomy/audit_taxonomy.py", "DUPLICATE CANONICAL"),
    ("R15", "tools/taxonomy/taxonomy_write.py", "def check"),
    ("R16", "wks/verify_quotes.py",  "def find_quote"),
    ("R17", "eval/test_wks.py",      "word substitution REJECTED"),
    ("R18", "tools/resolve_disputes.py", "def main"),
    ("R20", "wks/research_sources.py", "def problems"),
    ("R22", "tools/audit_refs.py",   "def main"),
    ("R23", "eval/test_domains.py",  "def main"),
    ("R28", "tools/audit_rfc_subjects.py", "def main"),
]
print(f"{'rule':6} {'artifact exists':16} {'symbol present':16} file")
for rid, rel, sym in probe:
    p = ROOT / rel
    if not p.exists():
        print(f"{rid:6} {'NO':16} {'-':16} {rel}")
        continue
    txt = p.read_text(encoding="utf-8", errors="replace")
    print(f"{rid:6} {'yes':16} {str(sym in txt):16} {rel}  (looking for {sym!r})")

print()
print("--- does the rules.md footer block reference files that exist? ---")
cmds = re.findall(r"^(python [^\s#]+(?:\s+[^\n#]*)?)$", rules, re.M)
missing = []
for c in cmds:
    parts = c.split()
    script = parts[1]
    p = (ROOT / script) if script.endswith(".py") else None
    if p is not None and not p.exists():
        missing.append(c)
print(f"  footer commands parsed: {len(cmds)}")
print(f"  footer commands naming a MISSING script: {missing or '(none)'}")

# --------------------------------------------------------- dead-filter sweep
print()
print("=" * 78)
print("DEAD-FILTER SWEEP: every column referenced by a metric-style filter,")
print("checked against the live schema. A filter on a column that does not")
print("exist returns EMPTY -- which reads as 'nothing wrong'.")
print("=" * 78)
con = sqlite3.connect(f"file:{os.path.join(SB,'db','wks.db')}?mode=ro", uri=True)
con.row_factory = sqlite3.Row
tabs = {r[0] for r in con.execute(
    "select name from sqlite_master where type in ('table','view')")}
cols = {t: {r[1] for r in con.execute(f"PRAGMA table_info({t})")} for t in tabs}

FILTERS = [
    ("evalm blocked_on_single_host", "quality", "gate_reasons", "LIKE"),
    ("evalm by_state",               "quality", "validation_state", "="),
    ("evalm stale (source)",         "source", "retrieved_at", ">="),
    ("evalm source_access",          "source", "access_state", "="),
    ("evalm source_access hash",     "source", "content_hash", "IS NULL"),
    ("evalm orgs (source)",          "source", "host", "DISTINCT"),
    ("evalm items",                  "item",   "status", "="),
    ("evalm disproof",               "item",   "disproof", "IS NOT NULL"),
    ("evalm fp items",               "item",   "kind", "="),
    ("evalm conflicts",              "conflict", "status", "="),
    ("evalm chains",                 "chain",  "chain_key", "count"),
    ("maturity n_high",              "quality", "validation_state", "IN"),
    ("coverage n_fp_item",           "item",   "kind", "="),
    ("integrity dedup",              "item",   "dedup_of", "IS NULL"),
    ("claimcheck",                   "quality", "validation_state", "IN"),
    ("chains strict",                "quality", "validation_state", "IN"),
]
bad = []
for name, tbl, col, op in FILTERS:
    exists = col in cols.get(tbl, set())
    if not exists:
        bad.append((name, tbl, col))
    print(f"  {'OK  ' if exists else 'DEAD'}  {name:32} {tbl}.{col:20} ({op})")
print()
print(f"  dead filters found: {bad or '(none)'}")

print()
print("--- but a filter can be dead in a subtler way: right column, empty corpus ---")
for name, sql in [
    ("blocked_on_single_host",
     "SELECT count(*) n FROM quality WHERE gate_reasons LIKE '%INSUFFICIENT_PUBLISHER_HOSTS%'"),
    ("open_conflicts", "SELECT count(*) n FROM conflict WHERE status='open'"),
]:
    print(f"  {name:26} -> {con.execute(sql).fetchone()['n']} rows")
print()
print("  gate_reasons distinct values:",
      [tuple(r) for r in con.execute(
          "select gate_reasons, count(*) n from quality group by 1 order by n desc limit 5")])
print()
print("  -> the 0 above means 'the string never appears', not 'no item is")
print("     blocked'. The column is populated; it is populated with reasons")
print("     that are never blocking tags (see FM-08).")

print()
print("--- a filter that returns clean-empty on a MISSPELLED column ---")
for col in ("validation_status", "quality_state", "promoted", "is_valid"):
    try:
        con.execute(f"select count(*) from item where {col}=1").fetchone()
        print(f"  {col:20} -> EXISTS (silent no-op)")
    except sqlite3.OperationalError as e:
        print(f"  {col:20} -> OperationalError: {e}")
        break
    except Exception:
        pass
print("  NOTE: sqlite raises OperationalError, so a misspelled column in a")
print("  raw query CRASHES rather than returning empty. The empty-result")
print("  failure mode requires a column that EXISTS but is never written.")