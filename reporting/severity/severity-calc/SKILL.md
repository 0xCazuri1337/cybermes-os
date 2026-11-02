---
name: severity-calc
description: Use when you need to calculate the severity of a security finding using the HackerOne CVSS calculator. Maps a CVSS 3.1 OR CVSS 4.0 vector string to the HackerOne severity band (None/Low/Medium/High/Critical).
---

# Severity Calc (HackerOne CVSS)

Calculates the severity of a vulnerability finding the way HackerOne's report form
does: it takes a **CVSS vector string**, computes the official numeric score, and
maps it to the HackerOne severity band.

Supports **both CVSS 3.1 and CVSS 4.0**:
- **CVSS 3.1** is implemented natively (Base → Temporal → Environmental, whichever is
  most complete per the FIRST.org v3.1 spec).
- **CVSS 4.0** is computed via the bundled FIRST.org-conformant reference
  implementation (`scripts/cvss_pkg/`, a verbatim vendored copy of
  RedHatProductSecurity/cvss `cvss4.py`). v4.0 always yields a complete score;
  Threat/Environmental metrics default to worst-case when omitted.

## When to use
- The user has (or you have produced) a CVSS vector for a finding and wants the
  resulting severity rating / numeric score.
- You are triaging findings and need to assign a HackerOne severity band.
- You want to sanity-check a severity the user or a program assigned.
- You have a list of findings (CSV) to score in bulk.

## How to use
Run the bundled calculator with a CVSS vector string:

```bash
python3 ~/.hermes/skills/severity-calc/scripts/severity_calc.py "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H"
python3 ~/.hermes/skills/severity-calc/scripts/severity_calc.py "CVSS:4.0/AV:N/AC:L/AT:N/PR:N/UI:N/VC:H/VI:H/VA:H/SC:H/SI:H/SA:H"
```

Optional per-asset severity cap (mimics HackerOne's maximum-severity clamp):

```bash
python3 ~/.hermes/skills/severity-calc/scripts/severity_calc.py "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H" --cap High
```

Batch scoring from a CSV (columns: `vector`[,`cap`]; a header row is required):

```bash
python3 ~/.hermes/skills/severity-calc/scripts/severity_calc.py --batch findings.csv
python3 ~/.hermes/skills/severity-calc/scripts/severity_calc.py --batch findings.csv -o results.csv
```

## Input format
A standard CVSS vector beginning with `CVSS:3.1/` or `CVSS:4.0/`, with `:`-separated
`KEY:VALUE` pairs. Metric sets differ by version:

- **CVSS 3.1** base metrics (required): AV, AC, PR, UI, S, C, I, A. Optional: Temporal
  (E, RL, RC), Environmental (CR, IR, AR, MAV, MAC, MPR, MUI, MS, MC, MI, MA).
- **CVSS 4.0** base metrics (required): AV, AC, AT, PR, UI, VC, VI, VA, SC, SI, SA.
  Optional: Threat (E), Environmental (CR, IR, AR, MAV, MAC, MPR, MUI, MSC, MSI, MSA),
  Supplemental (does not affect score). Note v4.0 renamed UI to N/P/A (None/Passive/
  Active) and requires the AT (Attack Requirements) metric.

The script auto-detects the version from the vector prefix.

## Severity band mapping (HackerOne)
| CVSS Score | Severity |
|------------|----------|
| 0.0        | None     |
| 0.1 – 3.9  | Low      |
| 4.0 – 6.9  | Medium   |
| 7.0 – 8.9  | High     |
| 9.0 – 10.0 | Critical |

## Output
Single-vector mode prints the original vector, the score level used (Base/Temporal/
Environmental), the rounded CVSS score, and the final severity band. With `--cap` it
clamps the displayed score to the top of the named band and notes the cap.

Batch mode prints (or writes to `-o`) a CSV with columns:
`vector,score,severity,level,cap,status`. Malformed rows are marked `status=ERROR`
and skipped, not fatal.

## Notes
- Only CVSS 3.1 and 4.0 are supported (these are what HackerOne offers).
- The numeric scores match the official FIRST.org calculators: 3.1 uses the closed
  form spec; 4.0 uses the MacroVector lookup + interpolation reference implementation.
- Verified against FIRST.org reference vectors (e.g. 3.1
  `AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H` → 9.8 Critical; 4.0
  `AV:N/AC:L/AT:N/PR:N/UI:N/VC:H/VI:H/VA:H/SC:H/SI:H/SA:H` → 9.3 Critical, and the
  published CVE examples 7.3 / 7.7 / 5.2 / 8.3 / 8.1 / 7.1).
