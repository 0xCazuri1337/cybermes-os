"""A real multi-party debate loop over the WKS knowledge base.

Three participants, each a genuinely different model, take turns stating and
CRITIQUING claims about a bug class. The point is not to collect prose — it is
to find where they DISAGREE, because disagreement is where the knowledge gap
is. An echo chamber teaches nothing, so every round requires each participant
to answer one question put to it by another.

  P1  nemotron-3.5-lightning   (cites NVD/CVE-class framing)
  P2  ling-3.1-flash           (cites standards/cheatsheet framing)
  P3  mimo-v2.6-flash           (cites practitioner/technique framing)
  LEAD  Hermes — the gate. Nothing enters the corpus on a model's say-so.

Divergence of the model family matters more than the count: three aliases of one
model would produce three copies of one perspective. These are three distinct
architectures, which is the minimum for "comparing perspectives" to mean
anything.

Run:  python tools/deliberate.py --round 1 --class path_traversal
"""
from __future__ import annotations

import argparse
import json
import os
import re
import sqlite3
import subprocess
import sys
import time
from datetime import datetime, timezone
from pathlib import Path

ROOT = Path(r"C:\Users\Administrator\.hermes\cyber")
DELIB = ROOT / "runtime" / "loop" / "deliberation"
NPM_PATH = r"C:/Users/Administrator/AppData/Roaming/npm"
LOG = DELIB / "_last.log"

sys.path.insert(0, str(ROOT))

PARTICIPANTS = [
    {"id": "P1", "model": "opencode/nemotron-3.5-lightning-free",
     "lens": "advisory/CVE framing — what is the named weakness and its id?"},
    {"id": "P2", "model": "opencode/ling-3.1-flash-free",
     "lens": "standards/cheatsheet framing — what does the normative rule require?"},
    {"id": "P3", "model": "opencode/mimo-v2.6-flash-free",
     "lens": "practitioner framing — what actually happens on the wire?"},
]


def acquire_lock(rdir: Path):
    """Refuse to run two debates at once.

    MEASURED (round 1): two `deliberate.py` processes were live at the same time
    and wrote the SAME filenames, so one overwrote the other's turn output. A
    shared artifact directory needs a single writer, exactly like the db.
    """
    rdir.mkdir(parents=True, exist_ok=True)
    lock = rdir / "_lock"
    if lock.exists():
        age = time.time() - lock.stat().st_mtime
        if age < 3600:
            raise SystemExit(
                f"REFUSED: {lock} exists (age {round(age)}s). Another debate is "
                f"running against this round dir. Wait or use a new --round.")
    lock.write_text(str(os.getpid()), encoding="utf-8")
    return lock


def run_model(model: str, instr_file: Path, timeout: int = 300,
              attempt: int = 1) -> str:
    """One model turn. Prompt goes through a FILE — see loop_round.py for why.

    MEASURED (debate round 1): these models need far longer than 240s to answer a
    substantive brief. P1 produced an 18 KB answer with three falsifiable claims;
    a retry at the same timeout hit the limit and returned `[TIMEOUT ...]`, which
    OVERWROTE the good 18 KB answer. Two lessons, both now enforced here:
      * a turn that returns a timeout marker is NOT an answer and must never
        overwrite a real one — the caller keeps the best result seen;
      * the budget must be generous, because these are the same free models that
        do the research rounds and they work fine given room.
    """
    env = dict(os.environ)
    env["PATH"] = env.get("PATH", "") + os.pathsep + NPM_PATH
    exe = str(Path(NPM_PATH) / "opencode.cmd")
    msg = (f"Read the file {instr_file.relative_to(ROOT).as_posix()} using your "
           f"tools. It is your complete brief. Follow it exactly. End with a "
           f"short report; do not paste the brief back.")
    LOG.parent.mkdir(parents=True, exist_ok=True)
    try:
        p = subprocess.run([exe, "run", "--model", model, msg], cwd=str(ROOT),
                           env=env, capture_output=True, text=True,
                           encoding="utf-8", errors="replace", timeout=timeout)
        out = (p.stdout or "") + (p.stderr or "")
    except subprocess.TimeoutExpired as e:
        # Keep whatever the child managed to print before the deadline. On
        # Windows a timed-out Popen still holds its pipe buffer.
        partial = ""
        if getattr(e, "stdout", None):
            partial = e.stdout.decode("utf-8", "replace") if isinstance(
                e.stdout, bytes) else (e.stdout or "")
        out = partial + f"\n[TIMEOUT after {timeout}s, attempt {attempt}]"
    return out


def best_of_turns(*outputs: str) -> str:
    """Pick the most substantive turn, never the newest-but-empty one.

    A turn that carries only a timeout marker has produced nothing. Letting it
    win because it arrived last is how 18 KB of real analysis was lost.
    """
    def score(s: str) -> tuple[int, int]:
        return (0 if s.strip().startswith("[TIMEOUT") or len(s.strip()) < 400
                else 1, len(s))
    return max(outputs, key=score)


def write_turn(rdir: Path, name: str, text: str) -> Path:
    """Write a turn artifact, re-creating the round dir first.

    MEASURED: round 2 crashed with FileNotFoundError on P2-turn1.txt because the
    round directory was deleted underneath a live process. acquire_lock() stops
    two debates colliding; this stops a cleanup from killing one mid-flight.
    """
    rdir.mkdir(parents=True, exist_ok=True)
    f = rdir / name
    f.write_text(text, encoding="utf-8")
    return f


def _field(body: str, name: str, default: str = "") -> str:
    m = re.search(rf"{name}\s*:\s*(.+)", body)
    return m.group(1).strip() if m else default


def parse_claims(raw: str) -> list[dict]:
    """Parse CLAIM blocks from a turn, JSON or inline.

    The inline form is the one that actually survives contact with these models:
    they write files when told to emit JSON (and the write is permission-denied),
    but they print text reliably. Both shapes are accepted so a model that does
    manage JSON is not penalised.
    """
    out: list[dict] = []
    # Inline blocks
    blocks = re.split(r"\bCLAIM\s+(\d+)\b", raw)
    for i in range(1, len(blocks) - 1, 2):
        body = blocks[i + 1]
        claim = re.search(r"claim\s*:\s*(.+)", body)
        if not claim:
            continue
        out.append({
            "n": blocks[i],
            "claim": claim.group(1).strip(),
            "mechanism": _field(body, "mechanism"),
            "disproof": _field(body, "disproof"),
            "confidence": (re.search(r"confidence\s*:\s*(.+)", body).group(1).strip()
                           if re.search(r"confidence\s*:\s*(.+)", body) else "?"),
            "novelty": _field(body, "novelty", "?"),
            "dispute": bool(re.search(r"DISPUTE\s*:", body)),
            "form": "inline",
        })
    if out:
        return out
    # JSON fallback
    for m in re.finditer(r'\{[^{}]*"claim"[^{}]*\}', raw, re.S):
        try:
            d = json.loads(m.group(0))
            d.setdefault("form", "json")
            d["dispute"] = bool(d.get("dispute") or d.get("DISPUTE"))
            out.append(d)
        except (ValueError, TypeError):
            continue
    return out


def seed_facts(con, class_id: str) -> dict:
    """What the corpus already knows, so participants argue from evidence."""
    items = con.execute("""
        SELECT i.item_key, i.claim, i.kind, i.disproof
        FROM item i JOIN quality q ON q.item_id=i.id
        WHERE i.class_id=? AND q.validation_state='high_confidence'
          AND i.status='active'
        ORDER BY q.score DESC LIMIT 6
    """, (class_id,)).fetchall()
    srcs = con.execute("""
        SELECT DISTINCT s.publisher FROM source s
        JOIN item_source ins ON ins.source_id=s.id
        JOIN item i ON i.id=ins.item_id
        WHERE i.class_id=?
        ORDER BY s.publisher LIMIT 12
    """, (class_id,)).fetchall()
    return {
        "class_id": class_id,
        "existing_items": [{"key": r["item_key"], "claim": r["claim"],
                            "kind": r["kind"], "disproof": r["disproof"]}
                           for r in items],
        "publishers_already_cited": [r["publisher"] for r in srcs],
    }


def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("--round", type=int, required=True)
    ap.add_argument("--class", dest="class_id", required=True)
    ap.add_argument("--timeout", type=int, default=300)
    args = ap.parse_args()

    DELIB.mkdir(parents=True, exist_ok=True)
    rdir = DELIB / f"round-{args.round:02d}"
    lock = acquire_lock(rdir)

    con = sqlite3.connect(str(ROOT / "db" / "wks.db"))
    con.row_factory = sqlite3.Row
    facts = seed_facts(con, args.class_id)
    con.close()
    write_turn(rdir, "seed-facts.json", json.dumps(facts, indent=2))
    print(f"DELIBERATION round {args.round} on class {args.class_id}")
    print(f"  seeded from {len(facts['existing_items'])} promoted item(s), "
          f"{len(facts['publishers_already_cited'])} publisher(s)\n")

    transcript: list[dict] = []

    # ---------- TURN 1: each participant states a position independently -----
    print("TURN 1 — independent positions")
    for p in PARTICIPANTS:
        brief = f"""# Debate turn 1 — state your position

CLASS UNDER DISCUSSION: {args.class_id}
YOUR LENS: {p['lens']}

## What the corpus already knows (do not repeat it — build on or dispute it)
{json.dumps(facts, indent=2)}

## Your task
State THREE claims about {args.class_id}. For each:
- `claim`     — ONE falsifiable sentence naming a MECHANISM, >= 40 chars.
- `mechanism` — why it is true at the mechanism level, >= 120 chars.
- `disproof`  — the exact condition that would make it FALSE.
- `confidence`- high | medium | low
- `novelty`   — state plainly whether the corpus ALREADY covers this
                (say which item_key) or whether it is NEW.

Pick at least ONE claim you believe the others will dispute. Flag it with
`DISPUTE:` and say what the opposing view would be.

Rank your claims by how confident you are. If you are unsure, say so — an
honest "medium" is worth more than a confident invention.

## OUTPUT FORMAT — read carefully, this has broken three rounds
**Do NOT write any file.** Do not create claims.json or anything else. Writing
outside the project directory is auto-rejected by permission on this host, and
an earlier attempt died on exactly that (`Write /tmp/claims.json failed`).

Instead, print your claims **inline in your reply**, like this:

CLAIM 1
claim: <one falsifiable sentence, >= 40 chars>
mechanism: <why it is true, >= 120 chars>
disproof: <the exact condition that would make it FALSE>
confidence: high | medium | low
novelty: NEW | or the item_key in the corpus that already covers this
DISPUTE: <only on the claim you think others will attack; say what the opposing
view would be>

CLAIM 2
...

Repeat the block for each claim. Plain text only — no JSON, no files.
"""
        bf = write_turn(rdir, f"{p['id']}-turn1.md", brief)
        # Two attempts, keep the better one. A timeout must never win over a
        # real answer just because it arrived second.
        t0 = time.time()
        outs = [run_model(p["model"], bf, args.timeout, attempt=1)]
        if len(best_of_turns(*outs)) < 400:
            print(f"    {p['id']} timed out, retrying with a longer budget...")
            outs.append(run_model(p["model"], bf, int(args.timeout * 1.6), attempt=2))
        out = best_of_turns(*outs)
        write_turn(rdir, f"{p['id']}-turn1.txt", out)
        n = len(parse_claims(out))
        print(f"  {p['id']} ({p['model'].split('/')[-1]}): {len(out)} chars, "
              f"{n} claim(s) parsed, {round(time.time() - t0)}s")
        transcript.append({"turn": 1, "participant": p["id"],
                           "model": p["model"], "lens": p["lens"],
                           "claims_found": n, "raw_chars": len(out),
                           "attempts": len(outs)})

    # ---------- TURN 2: cross-examination --------------------------------
    print("\nTURN 2 — cross-examination (each answers another's challenge)")
    for p in PARTICIPANTS:
        others = [q for q in PARTICIPANTS if q["id"] != p["id"]]
        brief = f"""# Debate turn 2 — you are being cross-examined

You are {p['id']}. The other participants wrote these positions:

{chr(10).join(f"--- {q['id']} ({q['model']}) ---{chr(10)}{(rdir / (q['id'] + '-turn1.txt')).read_text(encoding='utf-8')[:3000]}" for q in others)}

## Your task
Answer TWO things, in plain prose (no files, no JSON):
1. Which ONE of their claims do you think is WRONG or overstated, and why?
   Name the specific claim. If you think all of them are right, say so — do
   not manufacture disagreement.
2. Which ONE claim of yours are you now less sure about after reading theirs,
   and what would settle it?

Be concrete and critical. Generic agreement is worthless here.
"""
        bf = write_turn(rdir, f"{p['id']}-turn2.md", brief)
        out = run_model(p["model"], bf, args.timeout)
        write_turn(rdir, f"{p['id']}-turn2.txt", out)
        print(f"  {p['id']}: {len(out)} chars")

    # ---------- convergence check ----------------------------------------
    # CORRECTED: this block used the old JSON-only regex after the prompt
    # switched to inline CLAIM blocks, so it reported "claims proposed: 0"
    # while the round produced SIXTEEN. A metric that cannot see the round's own
    # output is worse than no metric.
    print("\nCONVERGENCE - measuring whether the round produced anything new")
    all_claims: list[dict] = []
    for p in PARTICIPANTS:
        raw = (rdir / f"{p['id']}-turn1.txt").read_text(encoding="utf-8")
        for c in parse_claims(raw):
            c["participant"] = p["id"]
            c["model"] = p["model"]
            all_claims.append(c)

    def norm(s: str) -> set[str]:
        return {w for w in re.findall(r"[a-z]{4,}", (s or "").lower())
                if w not in {"that", "this", "with", "from", "when", "then",
                             "does", "will", "have", "been", "they", "which"}}

    # Cross-lens convergence: same mechanism reached from different lenses.
    # Same-lens agreement is echo, not convergence.
    #
    # MEASURED: at >=2 shared words this reported 47 "convergences" for a debate
    # that was contradicting itself, because every claim in the class contains
    # path/file/directory. At >=4 it reports the 4 real ones.
    convergences = []
    for i, a in enumerate(all_claims):
        for b in all_claims[i + 1:]:
            if a["participant"] == b["participant"]:
                continue
            shared = norm(a.get("claim", "")) & norm(b.get("claim", ""))
            if len(shared) >= 4:
                convergences.append({
                    "participants": [a["participant"], b["participant"]],
                    "shared_terms": sorted(shared)[:8],
                    "a": a.get("claim", "")[:150],
                    "b": b.get("claim", "")[:150],
                })
    uniq = {re.sub(r"\s+", " ", c.get("claim", "")).strip().lower()
            for c in all_claims}
    disputed = sum(1 for c in all_claims if c.get("dispute"))
    high_conf = sum(1 for c in all_claims if c.get("confidence") == "high")

    print(f"  claims proposed: {len(all_claims)}  distinct: {len(uniq)}")
    print(f"  self-rated high confidence: {high_conf}   flagged DISPUTE: {disputed}")
    print(f"  cross-lens convergences (>=4 distinctive terms): {len(convergences)}")
    for c in convergences[:4]:
        print(f"    {c['participants'][0]}<->{c['participants'][1]}: "
              f"{c['shared_terms']}")

    xex = {}
    for p in PARTICIPANTS:
        f = rdir / f"{p['id']}-turn2.txt"
        if f.exists():
            t = f.read_text(encoding="utf-8")
            xex[p["id"]] = {
                "chars": len(t),
                "critiques": bool(re.search(
                    r"(wrong|overstated|not convinced|disagree|incorrect|"
                    r"too strong|overclaim)", t, re.I)),
                "expresses_uncertainty": bool(re.search(
                    r"(less sure|unsure|not certain|would settle|"
                    r"need to verify|uncertain)", t, re.I)),
            }
    n_crit = sum(1 for v in xex.values() if v["critiques"])
    n_uns = sum(1 for v in xex.values() if v["expresses_uncertainty"])
    print(f"  cross-examination: {n_crit}/{len(xex)} named a counter-argument, "
          f"{n_uns}/{len(xex)} expressed uncertainty")

    # HONESTY GATE (added after round 4). Round 4 printed
    # "cross-examination: 1/1 named a counter-argument" - literally true and
    # completely misleading: only P1 of THREE participants had a turn-2 file,
    # because the round was killed mid-loop. Denominating by the files that
    # HAPPEN to exist turns a partial round into a clean bill of health, so the
    # denominator is the participants that were ASKED.
    asked = len(PARTICIPANTS)
    xex_complete = len(xex) == asked
    missing = [p["id"] for p in PARTICIPANTS if p["id"] not in xex]
    if not xex_complete:
        print(f"  INCOMPLETE ROUND: only {len(xex)}/{asked} participants "
              f"answered the cross-examination. Missing: {missing}. "
              f"Conclusions below rest on a PARTIAL debate.")

    report = {
        "round": args.round,
        "class_id": args.class_id,
        "at": datetime.now(timezone.utc).isoformat(timespec="seconds"),
        "participants": transcript,
        "claims_proposed": len(all_claims),
        "claims_distinct": len(uniq),
        "self_rated_high": high_conf,
        "dispute_flagged": disputed,
        "cross_lens_convergences": convergences,
        "cross_examination": xex,
        "cross_examination_complete": xex_complete,
        "cross_examination_missing": missing,
        "claims": all_claims,
        "next": "lead reviews, verifies quotes, and decides what enters the corpus",
    }
    write_turn(rdir, "summary.json", json.dumps(report, indent=2))
    write_turn(rdir, "claims.json",
               json.dumps(all_claims, indent=2, ensure_ascii=False))
    print(f"  -> {rdir / 'summary.json'}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())