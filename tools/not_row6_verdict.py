import json
import re
import sys

d = json.load(open("research/ans_not2.json", encoding="utf-8"))
r = d[5]                                   # row #6
q = r["QUOTE_VERBATIM"]
claim = r.get("claim") or ""

print("row #6  class=%s  kind=%s" % (r["class_id"], r.get("kind")))
print()
print("QUOTE (%d chars):" % len(q))
print("   ", q[:260].replace("\n", " | "))
print()
print("CLAIM:")
print("   ", claim[:240])
print()

# The child's own flag: "mostly an exploit payload block, but states a real
# testable impact, so it was kept". Judge it on the same bar used everywhere
# else: is there a TESTABLE CONDITION, or only an artefact?
PAYLOAD = re.compile(r"<html>|<body>|<script|onerror|document\.|fetch\(|var\s+\w+\s*=")
CONDITION = re.compile(
    r"\borigin\b.*\bsubdomain\b|\bsubdomain\b.*\borigin\b|"
    r"\breflected\b.*\borigin\b|\borigin\b.*\breflect", re.I)

n_payload = len(PAYLOAD.findall(q))
has_condition = bool(CONDITION.search(q))
print("ASSESSMENT")
print("   payload markers in the quote : %d" % n_payload)
print("   states a testable condition  : %s" % has_condition)
print()
if has_condition and n_payload <= 3:
    print("   VERDICT: KEEP. The Origin-reflection-to-subdomain-origin chain is a")
    print("   condition, not an artefact; the payload that follows is context.")
elif not has_condition:
    print("   VERDICT: REJECT. No testable condition -- an artefact with a payload.")
else:
    print("   VERDICT: REJECT. Mostly payload with no separable condition.")
print()
print("Note: this row is MOOT for ingestion regardless. The whole Notion wave")
print("was rejected by the gate with QUOTE_NOT_FOUND_ON_CITED_PAGE because a")
print("Notion URL returns a 19,911-byte JS shell -- so this judgement only")
print("matters when the wave is re-sourced onto citable pages.")
print("Verdict recorded so the re-sourced run starts with a decision, not a")
print("re-litigation.")