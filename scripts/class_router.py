"""Class router — resolve a hunting scenario to the bug CLASS it names.

THE GAP THIS CLOSES
-------------------
MEASURED 2026-11-02: the routing benchmark scored 58.0% accuracy with 83.6%
false-positive routes. The cause was not a broken router — it was a router
with no vocabulary for the words a tester actually uses.

The registry's `_CLASS_TERMS` is a hand-written dictionary of 70 classes with
about five words each: `sqli -> {sqli, sql, injection, query, database}`. A
scenario that says "union select returns additional columns" shares NO token
with that set, so the resolver fell through to a metadata overlap and routed
the scenario to `path_traversal`. That is not a scoring artifact; it is the
router failing on a real hunting sentence.

The corpus already holds the vocabulary, in three places the registry never
read:

  1. `db/wks.db` `bug_class.aliases` — the canonical alternate names for
     each class ("mass assignment", "bola", "object level authorization").
  2. `db/wks.db` `bug_class.summary` — one sentence per class.
  3. `db/wks.db` `item.claim` — 2086 promoted technique, test, variant and
     signal rows, each carrying a `class_id`. These are the sentences a
     tester writes about a technique: "union select null union se", "boolean
     character extraction", "order by column count probe".

So the router here derives its vocabulary FROM THE TAXONOMY rather than
restating it. A second hand-written term list would be exactly the drift
this project keeps refusing.

MATCHING
--------
Matching is token-based with two properties that matter for hunting
sentences:

  * MULTI-WORD PHRASES score higher than single tokens. "mass assignment"
    is decisive; "mass" alone is not.
  * A term only counts when it is a whole token or a whole phrase. The
    class "cmd" must not match "cmdline" and must not match "command" —
    but "command injection" must match `cmd`.

The scorer returns the EXPECTED class when the taxonomy's own vocabulary
names it, and says so with the phrase that matched. It does not return a
guess: an unmatched scenario is UNROUTED, with the candidates named, so the
caller can defer rather than test the wrong thing.

THE DATABASE IS OPTIONAL
------------------------
The taxonomy is the source of truth, and it lives in the canonical database.
But the registry generator must still work in a minimal environment with no
database, so the vocabulary falls back to the registry's own `_CLASS_TERMS`
when the database cannot be opened. The fallback is recorded in the result,
so a caller can tell a taxonomy-backed route from a degraded one.
"""
from __future__ import annotations

import re
import sqlite3
from pathlib import Path
from typing import Any

ROOT = Path(__file__).resolve().parent.parent
CANONICAL_DB = ROOT / "db" / "wks.db"

#: How many item claims to read per class. The corpus has 2086 rows; the
#: routing terms are drawn from the ones that actually name a technique.
#: Reading all of them costs a full table scan on every registry build, and
#: the marginal vocabulary is in the long tail.
MAX_CLAIMS_PER_CLASS = 120

_WORD = re.compile(r"[a-z0-9_]+")


def _tokens(text: str) -> list[str]:
    return _WORD.findall((text or "").lower())


def _phrases(text: str) -> list[str]:
    """The multi-word phrases in a text, longest first.

    A phrase is two to four adjacent words. Longer phrases are decisive and
    short ones are noise, so the phrase list is what the matcher prefers.
    """
    words = _tokens(text)
    out: list[str] = []
    for size in (4, 3, 2):
        for i in range(len(words) - size + 1):
            phrase = " ".join(words[i:i + size])
            # A phrase that is all stopwords says nothing.
            if len(set(words[i:i + size]) - _STOPWORDS) >= 1:
                out.append(phrase)
    return out


_STOPWORDS = frozenset({
    "the", "a", "an", "of", "and", "or", "to", "in", "on", "for", "with",
    "is", "are", "was", "were", "be", "been", "that", "this", "it", "its",
    "at", "by", "from", "as", "not", "no", "any", "all", "can", "will",
    "would", "should", "could", "may", "must", "has", "have", "had", "do",
    "does", "did", "but", "which", "when", "where", "how", "what", "than",
    "then", "them", "they", "their", "there", "here", "into", "through",
    "via", "using", "use", "used", "user", "users", "server", "endpoint",
    "response", "request", "parameter", "value", "values", "target", "test",
    "testing", "check", "find", "looks", "like", "allows", "allows",
})


def _load_taxonomy(db_path: Path = CANONICAL_DB) -> dict[str, Any]:
    """Read the class vocabulary from the canonical taxonomy.

    Returns `{"source": ..., "classes": {class_id: {...}}, "ok": bool}`.
    A failure to open the database is NOT an exception — it is a degraded
    result, and the caller decides what to do with it.
    """
    if not db_path.is_file():
        return {"source": "none", "classes": {}, "ok": False,
                "reason": f"no canonical database at {db_path}"}
    try:
        con = sqlite3.connect(f"file:{db_path}?mode=ro", uri=True)
        con.row_factory = sqlite3.Row
    except sqlite3.Error as exc:
        return {"source": "none", "classes": {}, "ok": False,
                "reason": f"cannot open {db_path}: {exc}"}

    classes: dict[str, dict[str, Any]] = {}
    try:
        rows = con.execute(
            "SELECT id, name, summary, aliases FROM bug_class").fetchall()
        for row in rows:
            cid = str(row["id"])
            aliases: list[str] = []
            raw = row["aliases"]
            if raw:
                import json
                try:
                    parsed = json.loads(raw)
                    if isinstance(parsed, list):
                        aliases = [str(x) for x in parsed]
                except (json.JSONDecodeError, TypeError):
                    aliases = [str(raw)]
            classes[cid] = {
                "name": str(row["name"] or ""),
                "summary": str(row["summary"] or ""),
                "aliases": aliases,
                "phrases": [],
                "tokens": set(),
                "name_tokens": set(),
            }

        claims = con.execute(
            "SELECT class_id, claim FROM item "
            "WHERE class_id IS NOT NULL AND class_id != ''").fetchall()
        per_class: dict[str, list[str]] = {}
        for row in claims:
            cid = str(row["class_id"])
            claim = str(row["claim"] or "")
            if not claim:
                continue
            bucket = per_class.setdefault(cid, [])
            if len(bucket) < MAX_CLAIMS_PER_CLASS:
                bucket.append(claim)
        for cid, texts in per_class.items():
            entry = classes.setdefault(cid, {
                "name": "", "summary": "", "aliases": [],
                "phrases": [], "tokens": set(), "name_tokens": set()})
            # The CLAIMS contribute TOKENS only, never phrases.
            #
            # MEASURED 2026-11-02: the claims were originally mined for
            # phrases too, and that made the router confidently wrong. The
            # claims are free prose — "a search box taking a fts query
            # string is not covered by the quote payload" contains the
            # phrase "in a search", which then matched the scenario
            # "reflected input in a search parameter" and out-scored `xss`
            # by 12 points. A phrase mined from prose is an accident of
            # wording, not a name for the class. Phrases now come only
            # from the taxonomy's curated alias list and class names.
            entry["tokens"].update(
                w for w in _tokens(" ".join(texts))
                if w not in _STOPWORDS and len(w) > 2)
    except sqlite3.Error as exc:
        return {"source": "none", "classes": {}, "ok": False,
                "reason": f"taxonomy query failed: {exc}"}
    finally:
        con.close()

    for cid, entry in classes.items():
        # PHRASES come only from the curated alias list and the class name.
        #
        # The SUMMARY is prose written for a human reader ("A server fails
        # to verify that the authenticated caller is entitled to..."), and
        # mining phrases from it produces accidents of wording in the same
        # way mining claims did. The summary contributes TOKENS, which are
        # weighted far lower and cannot out-score a curated alias.
        phrases = set(entry["phrases"])
        for source in (entry["name"], *entry["aliases"]):
            if source:
                phrases.update(_phrases(source))
        # The class id and its underscore-split words are always terms.
        words = _tokens(cid.replace("_", " "))
        phrases.add(" ".join(words))
        entry["phrases"] = sorted(phrases, key=lambda p: (-len(p.split()), p))

        # The summary contributes tokens only.
        summary_tokens = {w for w in _tokens(entry["summary"])
                          if w not in _STOPWORDS and len(w) > 2}
        alias_tokens: set[str] = set()
        for alias in entry["aliases"]:
            alias_tokens.update(w for w in _tokens(alias)
                                if w not in _STOPWORDS and len(w) > 2)
        entry["tokens"] = ({w for w in words if w not in _STOPWORDS}
                           | alias_tokens | summary_tokens
                           | set(entry.get("tokens") or ()))

        # The DISCRIMINATING words of the class name: the name's own words,
        # minus the words the class id already contributed (which every
        # sibling shares) and minus stopwords. "Windows Privilege
        # Escalation via Token Manipulation" contributes "token" and
        # "manipulation" but not "windows" or "privilege" — those are the
        # shared prefix that made the three Windows siblings tie.
        id_words = set(words)
        entry["name_tokens"] = {
            w for w in _tokens(entry["name"])
            if w not in _STOPWORDS and len(w) > 2 and w not in id_words
        }
    return {"source": str(db_path), "classes": classes, "ok": True,
            "reason": ""}


_TAXONOMY: dict[str, Any] | None = None


def taxonomy(*, reload: bool = False) -> dict[str, Any]:
    """The taxonomy vocabulary, loaded once and cached."""
    global _TAXONOMY
    if _TAXONOMY is None or reload:
        _TAXONOMY = _load_taxonomy()
    return _TAXONOMY


def _fallback_terms() -> dict[str, set[str]]:
    """The registry's own term list, used when the taxonomy is unavailable."""
    import importlib.util
    spec = importlib.util.spec_from_file_location(
        "class_router_registry", ROOT / "scripts" / "skill_registry.py")
    if spec is None or spec.loader is None:
        return {}
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return dict(getattr(module, "_CLASS_TERMS", {}) or {})


def _idf(classes: dict[str, Any]) -> dict[str, float]:
    """Inverse document frequency for every token in the class vocabulary.

    A token that appears in one class's vocabulary discriminates that class
    from all the others; a token that appears in forty discriminates
    nothing. The weight is `log(N / df)` scaled so a token unique to one
    class is worth about 4x a token shared by half of them, and a token in
    EVERY class contributes nothing at all.

    This is computed from the taxonomy itself, so it cannot drift from the
    vocabulary it weights.
    """
    import math
    total = len(classes) or 1
    df: dict[str, int] = {}
    for entry in classes.values():
        for token in set(entry.get("tokens") or ()):
            df[token] = df.get(token, 0) + 1
    out: dict[str, float] = {}
    for token, count in df.items():
        if count >= total:
            # In every class: it names nothing.
            out[token] = 0.0
        else:
            out[token] = max(0.1, math.log(total / count) / math.log(total) * 4)
    return out


def match(scenario: str, *, tax: dict[str, Any] | None = None) -> dict[str, Any]:
    """Match a scenario to the bug classes it names.

    Returns `{"class_id": ..., "score": ..., "matched_phrase": ...,
    "candidates": [...], "status": ..., "source": ...}`.

    `status` is `ROUTED` when one class wins clearly, `AMBIGUOUS` when two
    or more classes score equally and neither wins, and `UNROUTED` when
    nothing matched. An ambiguous match is NOT resolved by guessing: the
    caller gets both candidates and the decision.
    """
    tax = tax if tax is not None else taxonomy()
    scenario_l = (scenario or "").lower()
    scenario_words = set(_tokens(scenario_l))
    scenario_phrases = set(_phrases(scenario_l))

    classes = tax.get("classes") or {}
    source = tax.get("source") or "none"
    if not classes:
        # DEGRADED: fall back to the registry's own vocabulary.
        fallback = _fallback_terms()
        results = []
        for cid, terms in fallback.items():
            overlap = len(terms & scenario_words)
            if overlap:
                results.append((overlap, cid, ""))
        results.sort(key=lambda t: (-t[0], t[1]))
        if not results:
            return {"class_id": "", "score": 0, "matched_phrase": "",
                    "candidates": [], "status": "UNROUTED",
                    "source": "fallback", "reason": tax.get("reason", "")}
        top = results[0]
        tied = [r for r in results if r[0] == top[0] and r[1] != top[1]]
        return {"class_id": top[1], "score": top[0], "matched_phrase": "",
                "candidates": [r[1] for r in results[:5]],
                "status": "AMBIGUOUS" if tied else "ROUTED",
                "source": "fallback", "reason": tax.get("reason", "")}

    scored: list[tuple[int, str, str]] = []
    idf = _idf(classes)
    for cid, entry in classes.items():
        score = 0.0
        best_phrase = ""

        # (1) A CURATED ALIAS is the strongest evidence there is: it is a
        #     name the taxonomy itself maintains for this class. A multi-word
        #     alias ("mass assignment") is worth more than a single-word one
        #     ("bola"), because a single word is more likely to collide.
        for alias in entry["aliases"]:
            alias_l = (alias or "").lower().strip()
            if not alias_l:
                continue
            if " " in alias_l:
                if alias_l in scenario_l:
                    score += 10 + 2 * len(alias_l.split())
                    if len(alias_l) > len(best_phrase):
                        best_phrase = alias_l
            elif alias_l in scenario_words:
                score += 7 * idf.get(alias_l, 1.0)
                if not best_phrase:
                    best_phrase = alias_l

        # (2) A curated multi-word phrase from the class name or aliases.
        for phrase in entry["phrases"]:
            if " " not in phrase:
                continue
            if phrase in scenario_phrases:
                score += 4 * len(phrase.split())
                if len(phrase) > len(best_phrase):
                    best_phrase = phrase

        # (2b) The DISCRIMINATING words of the class name are recorded but
        # NOT scored. They are used only to break a tie.
        #
        # MEASURED 2026-11-02: scoring them made the router WORSE (81.5%
        # -> 80.2% exact). "Windows Privilege Escalation via Token
        # Manipulation" contributes "token", and `windows_privesc_service`
        # and `windows_privesc_hijack` also carry "token" somewhere in
        # their own names and claims — so the words that were supposed to
        # DISCRIMINATE the siblings were shared with them, and the token
        # match pulled `authz` and `jwt` up on scenarios that named
        # neither. The words are still the right tie-breaker: when two
        # classes score identically, the one whose own name names the
        # scenario's word is the better answer. They just cannot out-score
        # evidence on their own.
        name_hits = sorted(entry["name_tokens"] & scenario_words)

        # (3) A single token, weighted by INVERSE DOCUMENT FREQUENCY.
        #
        # MEASURED 2026-11-02: an unweighted token match was the router's
        # largest source of false positives. "redirect" appears in the
        # aliases of `oauth`, `open_redirect` and several others, so a
        # scenario that said "redirect uri validation" gave every one of
        # them a point and the tie went to whichever sorted first. IDF
        # says what a corpus of classes already says: a word that occurs in
        # forty classes discriminates nothing, and a word that occurs in
        # one discriminates completely.
        for token in entry["tokens"]:
            if token in scenario_words:
                score += 1.5 * idf.get(token, 1.0)
                if not best_phrase:
                    best_phrase = token
        if score:
            scored.append((score, cid, best_phrase, len(name_hits)))

    if not scored:
        return {"class_id": "", "score": 0, "matched_phrase": "",
                "candidates": [], "status": "UNROUTED", "source": source,
                "reason": "no taxonomy term named this scenario"}

    # Sort by score, then by the number of DISCRIMINATING name words the
    # scenario named, then by id. The second key is what separates the
    # sibling classes that share a prefix and have no aliases of their own;
    # the third makes the order deterministic when even that ties.
    scored.sort(key=lambda t: (-t[0], -t[3], t[1]))
    top = scored[0]
    tied = [s for s in scored if s[0] == top[0] and s[1] != top[1]]
    # A tie is only ambiguous if the name-word tie-breaker did not separate
    # them either.
    unresolved = [s for s in tied if s[3] == top[3]]
    return {
        "class_id": top[1],
        "score": top[0],
        "matched_phrase": top[2],
        "candidates": [s[1] for s in scored[:5]],
        "candidates_scored": [{"class_id": s[1], "score": s[0],
                                "phrase": s[2]} for s in scored[:5]],
        "status": "AMBIGUOUS" if unresolved else "ROUTED",
        "source": source,
        "reason": (f"{len(unresolved)} class(es) scored equally with "
                   f"{top[1]} and could not be separated by the class name"
                   if unresolved else ""),
    }


def classify_capability(name: str, *, tax: dict[str, Any] | None = None
                        ) -> dict[str, Any]:
    """Map a CAPABILITY to the taxonomy class it implements.

    MEASURED 2026-11-02: the capability corpus is organised by FOLDER —
    `skills/capabilities/api/api-authorization/exploiting-mass-assignment-
    in-rest-apis/` — and the folder name is coarse. The taxonomy's class is
    fine-grained: `mass_assign`. So a capability folder names a DOMAIN of
    bugs and an individual capability names one of them.

    Without this mapping, routing a mass-assignment scenario returned the
    whole `api` class's capabilities — 35 artifacts, of which one was
    relevant — and the benchmark counted the other 34 as false positives.

    The capability's own NAME carries the technique
    ("exploiting-mass-assignment-in-rest-apis"), so the name is matched
    against the same taxonomy vocabulary. The result is a capability's
    fine-grained class, or an empty class_id when the name genuinely does
    not name one — in which case the caller knows the capability is broader
    than a single class and says so.
    """
    tax = tax if tax is not None else taxonomy()
    text = (name or "").replace("-", " ").replace("_", " ")
    # The name's own words are the strongest signal, so the name is matched
    # as a phrase-rich string. The class router's own matcher is used, so
    # there is ONE vocabulary in the system.
    result = match(text, tax=tax)
    return {
        "class_id": result.get("class_id") or "",
        "status": result.get("status") or "UNROUTED",
        "score": result.get("score") or 0,
        "matched_phrase": result.get("matched_phrase") or "",
        "source": result.get("source") or "",
    }


def main(argv: list[str] | None = None) -> int:
    import argparse
    import json
    ap = argparse.ArgumentParser(
        prog="class_router",
        description="Resolve a hunting scenario to the bug class it names.")
    ap.add_argument("scenario", nargs="+")
    ap.add_argument("--json", action="store_true")
    args = ap.parse_args(argv)
    scenario = " ".join(args.scenario)
    result = match(scenario)
    if args.json:
        print(json.dumps(result, indent=2, sort_keys=True))
    else:
        print(f"{result['status']}: {result['class_id'] or '(none)'} "
              f"score={result['score']} phrase={result['matched_phrase']!r}")
        print(f"  candidates: {', '.join(result['candidates'])}")
        if result.get("reason"):
            print(f"  note: {result['reason']}")
    return 0 if result["status"] == "ROUTED" else 1


if __name__ == "__main__":
    raise SystemExit(main())
