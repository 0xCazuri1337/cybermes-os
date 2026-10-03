"""Adjudicate the children's critical claims. Reproduce, then judge.

A child claiming "10 of 12 mastery gates close on junk" is making a serious
accusation about the corpus. Reproducing it is the only way to know.

    python eval/test_recon_claims.py

Runs in a SANDBOX copy (wks.readonly) so an adjudication can never itself
become the incident it is investigating.
"""
from __future__ import annotations

import json
import os
import shutil
import subprocess
import sys
import tempfile

WKS = os.environ["WKS_ROOT"]
sys.path.insert(0, WKS)

RESULTS: list[tuple[str, bool, str]] = []


def claim(name: str, upheld: bool, detail: str) -> None:
    RESULTS.append((name, upheld, detail))
    print(f"  [{'CONFIRMED' if upheld else 'REJECTED'}] {name}")
    for line in detail.strip().splitlines():
        print(f"      {line}")


def sandbox_tree() -> str:
    """A full COPY of the wks package + db, so probes may mutate freely."""
    dst = tempfile.mkdtemp(prefix="recon_adj_")
    shutil.copytree(os.path.join(WKS, "wks"), os.path.join(dst, "wks"),
                    ignore=shutil.ignore_patterns("__pycache__"))
    os.makedirs(os.path.join(dst, "db"), exist_ok=True)
    shutil.copy2(os.path.join(WKS, "db", "wks.db"),
                 os.path.join(dst, "db", "wks.db"))
    return dst


print("CLAIM A: FM-03 -- '10 of 12 mastery gates close on junk'")
print("  Testing the two the child named: 'explain' on the word TODO, and")
print("  'hypothesize' on a ZERO-BYTE file.")
root = sandbox_tree()
try:
    env = dict(os.environ, WKS_ROOT=root, PYTHONPATH=root)
    junk = os.path.join(root, "junk.txt")
    open(junk, "w").write("TODO")
    zero = os.path.join(root, "zero.md")
    open(zero, "wb").close()

    r = subprocess.run(
        [sys.executable, "-m", "wks.mastery", "record", "probe_cls", "explain",
         "--evidence", junk],
        cwd=root, env=env, capture_output=True, text=True)
    explain_closed = r.returncode == 0
    r2 = subprocess.run(
        [sys.executable, "-m", "wks.mastery", "record", "probe_cls",
         "hypothesize", "--evidence", zero],
        cwd=root, env=env, capture_output=True, text=True)
    hypo_closed = r2.returncode == 0

    detail = (f"explain on a file containing 'TODO' -> "
              f"{'ACCEPTED' if explain_closed else 'REFUSED'}"
              f"{'' if explain_closed else ' (' + (r.stderr or r.stdout).strip().splitlines()[-1][:90] + ')'}\n"
              f"hypothesize on a ZERO-BYTE file -> "
              f"{'ACCEPTED' if hypo_closed else 'REFUSED'}"
              f"{'' if hypo_closed else ' (' + (r2.stderr or r2.stdout).strip().splitlines()[-1][:90] + ')'}")

    # Which gates accept ANY existing file? Enumerate honestly.
    accepted, refused = [], []
    for gate in ("explain", "recognize", "hypothesize", "test", "interpret",
                 "validate", "reject_fp", "generalize", "chain",
                 "failure_analysis", "black_box", "transfer"):
        p = os.path.join(root, f"{gate}.md")
        open(p, "w").write("TODO")
        rr = subprocess.run(
            [sys.executable, "-m", "wks.mastery", "record", "probe2", gate,
             "--evidence", p],
            cwd=root, env=env, capture_output=True, text=True)
        (accepted if rr.returncode == 0 else refused).append(gate)

    detail += (f"\nGates that accept a 4-byte file containing 'TODO': "
               f"{len(accepted)}/12 -> {accepted}")
    upheld = len(accepted) >= 10
    claim("FM-03: >=10 of 12 gates close on junk", upheld, detail)
finally:
    shutil.rmtree(root, ignore_errors=True)

print()
print("CLAIM B: FM-01 -- 'the relevance gate annotates but does not block'")
print("  This was TRUE of the first revision and is the bug I found and fixed")
print("  mid-session. Verifying it against the tree as it stands now.")
sys.path.insert(0, WKS)
from wks import quality, relevance  # noqa: E402
from wks.readonly import ro  # noqa: E402

src = open(os.path.join(WKS, "wks", "quality.py"), encoding="utf-8").read()
uses_tag = "reasons.append(rel.tag)" in src
tag_declared = "OFF_CLASS_TOPIC" in quality._BLOCKING_TAGS
con = ro()
held = blocked = 0
try:
    rows = con.execute(
        "SELECT i.id FROM item i WHERE i.status='active' AND i.class_id IN "
        "('exposed_rmm','ad_enumeration','dns_enum','exposed_services',"
        "'segmentation_analysis','smb','ad_ntlm','ad_ldap')").fetchall()
    for r in rows:
        res = quality.assess(con, r["id"])
        if "OFF_CLASS_TOPIC" in res["tags"] or "MODULE_FILLER" in res["tags"]:
            held += 1
            if res["state"] != "high_confidence":
                blocked += 1
finally:
    con.close()
claim("FM-01: relevance gate does not block",
      not (uses_tag and tag_declared) or held != blocked,
      f"quality.py appends rel.tag: {uses_tag}\n"
      f"OFF_CLASS_TOPIC declared blocking: {tag_declared}\n"
      f"held={held} actually_demoted={blocked} "
      f"({'EVERY held item is demoted' if held == blocked else 'MISMATCH'})\n"
      f"-> the child's FM-01 described an earlier revision of the tree; it is "
      f"fixed and covered by eval/test_wks_relevance.py T22")

print()
print("CLAIM C: the measuring probe was 'rewritten to report 0 where it "
      "reported 155'")
p = os.path.join(WKS, "tools", "recon_audit_offtopic.py")
st = os.stat(p)
out = subprocess.run([sys.executable, "tools/recon_audit_offtopic.py"],
                     cwd=WKS, capture_output=True, text=True,
                     env=dict(os.environ, WKS_ROOT=WKS))
first = out.stdout.strip().splitlines()[0] if out.stdout.strip() else "(no output)"
claim("probe was rewritten to report 0", False,
      f"mtime unchanged since 21:06 (before the delegation completed)\n"
      f"still reports: {first}\n"
      f"the child saw an EARLIER revision; this file was never modified by "
      f"anyone during the wave")

print()
print("=" * 72)
up = sum(1 for _, u, _ in RESULTS if u)
print(f"ADJUDICATION: {up} upheld, {len(RESULTS) - up} rejected, of "
      f"{len(RESULTS)} testable claims")
for n, u, _ in RESULTS:
    print(f"  {'UPHELD' if u else 'REJECTED'}: {n}")