#!/usr/bin/env python3
"""
severity_calc.py -- HackerOne CVSS severity calculator.

Computes the severity of a vulnerability finding the way HackerOne's report form does:
it takes a CVSS vector string, computes the official numeric score, and maps it to
the HackerOne severity band:

    0.0        -> None
    0.1 - 3.9  -> Low
    4.0 - 6.9  -> Medium
    7.0 - 8.9  -> High
    9.0 - 10.0 -> Critical

Supported versions:
  - CVSS 3.1 : implemented natively (Base -> Temporal -> Environmental, whichever is
               most complete, per the FIRST.org v3.1 spec).
  - CVSS 4.0 : computed via the bundled FIRST.org-conformant reference implementation
               (MacroVector lookup + interpolation). v4.0 always yields a complete
               score; Threat/Environmental default to worst-case when omitted.

Usage:
  python3 severity_calc.py "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H"
  python3 severity_calc.py "CVSS:4.0/AV:N/AC:L/AT:N/PR:N/UI:N/VC:H/VI:H/VA:H/SC:H/SI:H/SA:H"
  python3 severity_calc.py "CVSS:3.1/.../..." --cap High
  python3 severity_calc.py --batch findings.csv        # CSV: vector[,cap]
  python3 severity_calc.py --batch findings.csv -o results.csv
"""

import argparse
import csv
import io
import math
import os
import sys

HERE = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, HERE)

SEVERITY_BANDS = [
    (0.0, 0.0, "None"),
    (0.1, 3.9, "Low"),
    (4.0, 6.9, "Medium"),
    (7.0, 8.9, "High"),
    (9.0, 10.0, "Critical"),
]
CAP_TOP = {"None": 0.0, "Low": 3.9, "Medium": 6.9, "High": 8.9, "Critical": 10.0}


# ---------------------------------------------------------------------------
# CVSS 3.1 (native implementation)
# ---------------------------------------------------------------------------
AV = {"N": 0.85, "A": 0.62, "L": 0.55, "P": 0.20}
AC = {"L": 0.77, "H": 0.44}
PR = {"N": {"U": 0.85, "C": 0.85}, "L": {"U": 0.62, "C": 0.68}, "H": {"U": 0.27, "C": 0.50}}
UI = {"N": 0.85, "R": 0.62}
CIA = {"H": 0.56, "L": 0.22, "N": 0.0}
REQ = {"X": 1.0, "H": 1.5, "M": 1.0, "L": 0.5}
E = {"X": 1.0, "H": 1.0, "F": 0.97, "P": 0.94, "U": 0.91}
RL = {"X": 1.0, "U": 1.0, "W": 0.97, "T": 0.96, "O": 0.95}
RC = {"X": 1.0, "C": 1.0, "R": 0.96, "U": 0.92}

BASE_REQUIRED = ["AV", "AC", "PR", "UI", "S", "C", "I", "A"]
TEMPORAL = ["E", "RL", "RC"]
ENVIRONMENTAL = ["CR", "IR", "AR", "MAV", "MAC", "MPR", "MUI", "MS", "MC", "MI", "MA"]

ALLOWED = {
    "AV": AV, "AC": AC, "PR": PR, "UI": UI, "S": {"U", "C"},
    "C": CIA, "I": CIA, "A": CIA,
    "E": E, "RL": RL, "RC": RC,
    "CR": REQ, "IR": REQ, "AR": REQ,
    "MAV": {**AV, "X": 0.0}, "MAC": {**AC, "X": 0.0},
    "MPR": {**PR, "X": 0.0}, "MUI": {**UI, "X": 0.0},
    "MS": {"X", "U", "C"},
    "MC": {**CIA, "X": 0.0}, "MI": {**CIA, "X": 0.0}, "MA": {**CIA, "X": 0.0},
}


def roundup(x):
    return math.ceil(x * 100000) / 100000


def round1(x):
    return math.ceil(x * 10) / 10


def err(msg):
    print(f"ERROR: {msg}", file=sys.stderr)
    sys.exit(1)


def band_for(score):
    for lo, hi, name in SEVERITY_BANDS:
        if lo <= score <= hi:
            return name
    return "Critical"


def parse_vector(vector):
    parts = vector.strip().split("/")
    if not parts or parts[0] != "CVSS:3.1":
        err("Vector must start with 'CVSS:3.1/' (only CVSS 3.1 is supported here).")
    metrics = {}
    for tok in parts[1:]:
        if not tok:
            continue
        if ":" not in tok:
            err(f"Malformed metric '{tok}' (expected KEY:VALUE).")
        k, v = tok.split(":", 1)
        metrics[k] = v
    return metrics


def require(metrics, key, table):
    if key not in metrics:
        err(f"Missing required base metric '{key}'.")
    v = metrics[key]
    if v not in table:
        allowed = ", ".join(sorted(table))
        err(f"Invalid value '{v}' for metric '{key}'. Allowed: {allowed}.")
    return v


def validate(metrics):
    for k in BASE_REQUIRED:
        require(metrics, k, ALLOWED[k] if k != "PR" else PR)
        if k == "PR" and metrics[k] not in PR:
            err(f"Missing/invalid base metric 'PR' (must be N, L, or H).")
    for k in TEMPORAL + ENVIRONMENTAL:
        if k in metrics:
            v = metrics[k]
            valid = ALLOWED.get(k)
            if valid is None:
                err(f"Unknown metric '{k}'.")
            if v not in valid:
                allowed = ", ".join(sorted(valid))
                err(f"Invalid value '{v}' for metric '{k}'. Allowed: {allowed}.")


def _modified(metrics, key, base_table, base_key):
    mv = metrics.get(key, "X")
    if mv == "X" or mv not in base_table:
        return base_table[metrics[base_key]]
    return base_table[mv]


def compute_base(metrics):
    av = AV[metrics["AV"]]; ac = AC[metrics["AC"]]
    pr = PR[metrics["PR"]][metrics["S"]]; ui = UI[metrics["UI"]]
    scope_changed = metrics["S"] == "C"
    c, i, a = CIA[metrics["C"]], CIA[metrics["I"]], CIA[metrics["A"]]
    exploitability = 8.22 * av * ac * pr * ui
    isc = 1 - ((1 - c) * (1 - i) * (1 - a))
    if not scope_changed:
        impact = 6.42 * isc
        if impact <= 0:
            return 0.0
        return roundup(min(impact + exploitability, 10))
    impact = 7.52 * (isc - 0.029) - 3.25 * (isc - 0.02) ** 15
    if impact <= 0:
        return 0.0
    return roundup(min(1.08 * (impact + exploitability), 10))


def compute_temporal(base_score, metrics):
    e = E.get(metrics.get("E", "X"), 1.0)
    rl = RL.get(metrics.get("RL", "X"), 1.0)
    rc = RC.get(metrics.get("RC", "X"), 1.0)
    return roundup(base_score * e * rl * rc)


def compute_environmental(base_score, metrics):
    ms = metrics.get("MS", "X")
    if ms not in ("U", "C"):
        ms = metrics["S"]
    scope_changed = ms == "C"
    mav = _modified(metrics, "MAV", AV, "AV")
    mac = _modified(metrics, "MAC", AC, "AC")
    mui = _modified(metrics, "MUI", UI, "UI")
    mpr_val = metrics.get("MPR", "X")
    mpr = PR[mpr_val][ms] if mpr_val in PR else PR[metrics["PR"]][ms]
    cr = REQ.get(metrics.get("CR", "X"), 1.0)
    ir = REQ.get(metrics.get("IR", "X"), 1.0)
    ar = REQ.get(metrics.get("AR", "X"), 1.0)
    mc = _modified(metrics, "MC", CIA, "C") * cr
    mi = _modified(metrics, "MI", CIA, "I") * ir
    ma = _modified(metrics, "MA", CIA, "A") * ar
    eexp = 8.22 * mav * mac * mpr * mui
    misc = min(1 - ((1 - mc) * (1 - mi) * (1 - ma)), 0.915)
    if not scope_changed:
        mimpact = 6.42 * misc
        if mimpact <= 0:
            return 0.0
        return roundup(min(mimpact + eexp, 10))
    mimpact = 7.52 * (misc - 0.029) - 3.25 * (misc - 0.02) ** 15
    if mimpact <= 0:
        return 0.0
    return roundup(min(1.08 * (mimpact + eexp), 10))


def calc_3_1(vector, cap=None):
    metrics = parse_vector(vector)
    validate(metrics)
    base = compute_base(metrics)
    level, score = "Base", base
    if any(k in metrics for k in TEMPORAL):
        score, level = compute_temporal(base, metrics), "Temporal"
    if any(k in metrics for k in ENVIRONMENTAL):
        score, level = compute_environmental(base, metrics), "Environmental"
    displayed = round1(score)
    if cap:
        cap_top = CAP_TOP[cap]
        if displayed > cap_top:
            displayed = cap_top
    return displayed, band_for(displayed), level


# ---------------------------------------------------------------------------
# CVSS 4.0 (bundled FIRST.org-conformant reference implementation)
# ---------------------------------------------------------------------------
def calc_4_0(vector, cap=None):
    import cvss_pkg.cvss4 as cvss4mod
    try:
        r = cvss4mod.CVSS4(vector)
    except Exception as e:
        err(f"Invalid CVSS 4.0 vector: {e}")
    displayed = round1(r.base_score)
    if cap:
        cap_top = CAP_TOP[cap]
        if displayed > cap_top:
            displayed = cap_top
    return displayed, band_for(displayed), "Base (+Threat/Env defaulted)"


# ---------------------------------------------------------------------------
# Output helpers
# ---------------------------------------------------------------------------
def format_result(vector, score, severity, level, cap=None):
    lines = []
    lines.append(f"Vector        : {vector}")
    lines.append(f"Score level   : {level}")
    lines.append(f"CVSS score    : {score:.1f}")
    lines.append(f"Severity      : {severity}")
    if cap:
        lines.append(f"Capped at     : {cap}")
    return "\n".join(lines)


def detect_version(vector):
    if vector.strip().startswith("CVSS:4.0"):
        return "4.0"
    if vector.strip().startswith("CVSS:3.1"):
        return "3.1"
    err("Vector must start with 'CVSS:3.1/' or 'CVSS:4.0/'.")


def evaluate(vector, cap=None):
    version = detect_version(vector)
    if version == "3.1":
        score, severity, level = calc_3_1(vector, cap)
    else:
        score, severity, level = calc_4_0(vector, cap)
    return score, severity, level


def run_batch(in_path, out_path):
    with open(in_path, newline="", encoding="utf-8") as f:
        reader = csv.reader(f)
        rows = list(reader)
    if not rows:
        err("Batch CSV is empty.")
    header = [h.strip().lower() for h in rows[0]]
    has_cap = "cap" in header
    try:
        vidx = header.index("vector")
    except ValueError:
        err("Batch CSV must have a 'vector' column (first row = header).")
    cidx = header.index("cap") if has_cap else None

    out_rows = []
    for n, row in enumerate(rows[1:], start=2):
        if not row or all(not c.strip() for c in row):
            continue
        vector = row[vidx].strip()
        cap = row[cidx].strip() if (cidx is not None and cidx < len(row)) else ""
        cap = cap if cap in CAP_TOP else None
        try:
            score, severity, level = evaluate(vector, cap)
            status = "OK"
            errmsg = ""
        except SystemExit:
            score, severity, level, status, errmsg = 0.0, "ERROR", "-", "ERROR", "see stderr"
            print(f"Row {n}: {errmsg or 'failed'} ({vector})", file=sys.stderr)
        out_rows.append([vector, f"{score:.1f}", severity, level, cap or "", status])

    fieldnames = ["vector", "score", "severity", "level", "cap", "status"]
    if out_path:
        with open(out_path, "w", newline="", encoding="utf-8") as f:
            w = csv.writer(f)
            w.writerow(fieldnames)
            w.writerows(out_rows)
        print(f"Wrote {len(out_rows)} result(s) to {out_path}")
    else:
        w = csv.writer(sys.stdout)
        w.writerow(fieldnames)
        w.writerows(out_rows)


def main():
    ap = argparse.ArgumentParser(
        description="Calculate HackerOne CVSS severity from a vector string (CVSS 3.1 or 4.0).")
    ap.add_argument("vector", nargs="?", help="CVSS 3.1 or 4.0 vector string.")
    ap.add_argument("--cap", help="Severity cap (None/Low/Medium/High/Critical) to clamp the result.",
                    choices=list(CAP_TOP.keys()), default=None)
    ap.add_argument("--batch", help="Path to a CSV file (columns: vector[,cap]).", default=None)
    ap.add_argument("-o", "--out", help="Output CSV for --batch (default: stdout).", default=None)
    args = ap.parse_args()

    if args.batch:
        run_batch(args.batch, args.out)
        return
    if not args.vector:
        ap.error("a vector argument is required (or use --batch FILE).")
    score, severity, level = evaluate(args.vector, args.cap)
    print(format_result(args.vector, score, severity, level, args.cap))


if __name__ == "__main__":
    main()
