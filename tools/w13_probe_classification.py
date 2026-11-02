"""MEASURED probe: the real class-selection path, exercised correctly.

The first version of this probe was WRONG and reported 0 hits for every target,
including text that plainly described an obvious class. Cause: `SIGNATURES` maps
OBSERVATION-KIND names (`object_reference`, `sequential_id`) — not free text —
so matching target prose against it matches nothing by construction. The probe
was measuring the wrong thing; the code was fine.

This version drives the actual API: it feeds observation kinds to
`classify_behaviour`, then measures the COVERAGE gap, which is the real finding:
SIGNATURES declares 20 of the 70 corpus classes, so 50 classes can never be
selected by observation no matter what is observed.

Read-only. Writes nothing.
"""
import os
import sys

WKS = os.environ.get("WKS_ROOT", ".")
sys.path.insert(0, WKS)
os.chdir(WKS)

from orch import hypothesis as hyp  # noqa: E402
from wks import store  # noqa: E402

TARGETS = [
    ("legacy-asp-dotnet-mssql", ["sql_error_or_behaviour", "boolean_differential"]),
    ("spa-node-postgres-idor", ["object_reference", "other_user_object", "sequential_id"]),
    ("mass-assign-admin", ["json_body_accepted", "privileged_field_accepted"]),
    ("ssrf-webhook", ["url_parameter_fetched_by_server", "internal_address_reachable"]),
    ("graphql-introspection", ["graphql_endpoint", "introspection_enabled"]),
    ("path-traversal-download", ["file_path_parameter", "dotdot_accepted"]),
    ("unknown-thing", ["novel_response_shape"]),
    ("noisy-target", ["user_input_reflected", "unexpected_status"]),
]

print("=" * 78)
print("A. classify_behaviour() on REAL observation kinds")
print("=" * 78)
for name, signals in TARGETS:
    r = hyp.classify_behaviour(signals)
    verdict = r["classification"]
    extra = ""
    if verdict == "UNKNOWN":
        extra = f"  <- {r.get('reason')}"
    print(f"  {name:28} -> {verdict:14} support={r.get('support', '-')}{extra}")

print()
print("=" * 78)
print("B. AMBIGUITY: two classes with equal support must NOT resolve by order")
print("=" * 78)
r = hyp.classify_behaviour(["state_changing_request", "no_csrf_token", "same_site_absent"])
print("  csrf vs csrf_bypass ->", r["classification"])
print("  reason:", r.get("reason", "(none)"))

print()
print("=" * 78)
print("C. COVERAGE: how many corpus classes can observation ever select?")
print("=" * 78)
con = store.connect()
# `bug_class` keys on `id`, not `class_id` — MEASURED: guessing `class_id`
# raises OperationalError, and an audit that returns nothing can always be
# mistaken for "no coverage problem".
rows = con.execute("SELECT id FROM bug_class ORDER BY id").fetchall()
corpus = [r["id"] for r in rows]
selectable = set(hyp.SIGNATURES)
missing = [c for c in corpus if c not in selectable]
print(f"  corpus classes            : {len(corpus)}")
print(f"  classes in SIGNATURES     : {len(selectable)}")
print(f"  UNSELECTABLE by observation: {len(missing)}")
print()
print("  " + ", ".join(missing))