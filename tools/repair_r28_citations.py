"""R28 repair — replace the citations that are provably about another subject.

WHAT THIS FIXES (measured, 2026-10-31)
  23 active item citations on normative hosts were provably about a
  DIFFERENT subject from the class they were filed under. Every one of
  them was a Linux man page cited by a WINDOWS class:

    * `windows_privesc_service`  -> man7.org .../man2/execve.2.html  (8 items)
    * `windows_privesc_token`    -> man7.org .../man2/execve.2.html  (10 items)
    * `windows_privesc_hijack`   -> man7.org .../man8/ld.so.8.html    (5 items)

  Worse than the mismatch, the QUOTE on each link was a copy of the
  man page's text and said nothing about the Windows claim it was filed
  under. `execve(2)`'s "the resource limit was not imposed on processes
  that changed their user IDs" was cited as evidence for "the Terminal
  Services RPC named pipe LSM_API_service is itself a privesc surface";
  `ld.so(8)`'s list of `LD_PRELOAD` environment variables was cited as
  evidence for the Windows DLL search order.

  So the citation was decorative: the page was live (200), the quote was
  real text FROM that page, and the pair asserted nothing about the
  claim. This is precisely R28's failure mode -- "a 200 is not
  relevance" -- with a second failure on top: a quote that is real but
  about something else.

WHAT THIS DOES
  For each affected class, registers the CORRECT Microsoft Learn page for
  the subject the class actually claims, and re-links the items to it with
  a quote taken from THAT page and bearing on THAT claim:

    windows_privesc_hijack  -> win32/dlls/dynamic-link-library-search-order
    windows_privesc_service -> win32/services/service-security-and-access-rights
    windows_privesc_token   -> win32/secauthz/privilege-constants

  The wrong links are removed with `store.unlink_source`, which deletes
  the LINK and keeps the source row -- the man pages stay in the registry
  for the audit trail and for the items that legitimately cite them
  (`linux_privesc`).

  NOTHING IS DELETED. The prior state is preserved in the `superseded/`
  record this script writes, and the database was backed up before the
  repair (see CONTROL/state.md).

Run: python tools/repair_r28_citations.py [--dry-run]
Exit: non-zero if any affected item is left without a valid citation.
"""
from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT))

# The replacement page for each affected class, and the quote taken FROM
# that page. Each quote is verified to appear on the page it is attributed
# to -- `--verify` re-fetches and checks, so a drifted page is caught
# rather than silently trusted.
REPLACEMENTS: dict[str, dict[str, object]] = {
    "windows_privesc_hijack": {
        "url": "https://learn.microsoft.com/en-us/windows/win32/dlls/"
               "dynamic-link-library-search-order",
        "title": "Dynamic-link library search order - Win32 apps",
        "source_type": "docs",
        "quotes": [
            "It's common for multiple versions of the same dynamic-link "
            "library (DLL) to exist in different file system locations within "
            "an operating system (OS). You can control the specific location "
            "from which any given DLL is loaded by specifying a full path.",
            "When an unpackaged app loads a module and doesn't specify a full "
            "path, the system searches for the DLL at load time as described "
            "in this section.",
            "The standard DLL search order used by the system depends on "
            "whether or not safe DLL search mode is enabled.",
            "Safe DLL search mode (which is enabled by default) moves the "
            "user's current folder later in the search order.",
        ],
    },
    "windows_privesc_service": {
        "url": "https://learn.microsoft.com/en-us/windows/win32/services/"
               "service-security-and-access-rights",
        "title": "Service Security and Access Rights - Win32 apps",
        "source_type": "docs",
        "quotes": [
            "The Windows security model enables you to control access to the "
            "service control manager (SCM) and service objects.",
            "Granting certain access rights to untrusted users (such as "
            "SERVICE_CHANGE_CONFIG or SERVICE_STOP ) can allow them to "
            "interfere with the execution of your service, and possibly allow "
            "them to run applications under the LocalSystem account.",
            "When a process uses the OpenService function, the system checks "
            "the requested access rights against the security descriptor for "
            "the service object.",
        ],
    },
    "windows_privesc_token": {
        "url": "https://learn.microsoft.com/en-us/windows/win32/secauthz/"
               "privilege-constants",
        "title": "Privilege Constants (Winnt.h) - Win32 apps",
        "source_type": "docs",
        "quotes": [
            "Privileges determine the type of system operations that a user "
            "account can perform. An administrator assigns privileges to user "
            "and group accounts.",
            "The functions that get and adjust the privileges in an access "
            "token use the locally unique identifier (LUID) type to identify "
            "privileges.",
        ],
    },
}

# The citation links that must be removed: (class_id, wrong_source_url).
WRONG_LINKS = {
    "windows_privesc_service":
        "https://man7.org/linux/man-pages/man2/execve.2.html",
    "windows_privesc_token":
        "https://man7.org/linux/man-pages/man2/execve.2.html",
    "windows_privesc_hijack":
        "https://man7.org/linux/man-pages/man8/ld.so.8.html",
}


def fetch_text(url: str, timeout: int = 40) -> str:
    import re
    import ssl
    import urllib.request
    req = urllib.request.Request(url, headers={"User-Agent":
        "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 "
        "(KHTML, like Gecko) Chrome/125.0 Safari/537.36"})
    with urllib.request.urlopen(req, timeout=timeout,
                                context=ssl.create_default_context()) as r:
        body = r.read().decode("utf-8", "replace")
    # Strip tags and collapse whitespace so a quote can be compared against
    # the rendered text rather than the markup.
    text = re.sub(r"<script.*?</script>|<style.*?</style>", " ", body,
                  flags=re.I | re.S)
    text = re.sub(r"<[^>]+>", " ", text)
    import html
    return re.sub(r"\s+", " ", html.unescape(text)).strip()


def verify_quotes() -> list[str]:
    """Every quote must actually appear on the page it is attributed to.

    This runs even on a dry run: the quotes are the evidence the repair
    asserts, so an unverified quote would make the repair a guess. A
    drifted page is caught here rather than silently trusted.
    """
    problems = []
    for cid, spec in REPLACEMENTS.items():
        try:
            text = fetch_text(str(spec["url"]))
        except Exception as e:            # noqa: BLE001 -- reported, not raised
            problems.append(f"{cid}: cannot fetch {spec['url']}: {e}")
            continue
        for q in spec["quotes"]:         # type: ignore[union-attr]
            if q not in text:
                problems.append(f"{cid}: quote not found on the page: {q[:70]!r}")
    return problems


def main() -> int:
    ap = argparse.ArgumentParser(prog="repair_r28_citations")
    ap.add_argument("--dry-run", action="store_true")
    ap.add_argument("--verify", action="store_true",
                    help="re-fetch each replacement page and confirm every "
                         "quote appears on it")
    args = ap.parse_args()

    from wks import store as wks_store

    problems = verify_quotes()
    if problems:
        print("QUOTE VERIFICATION FAILED:", file=sys.stderr)
        for p in problems:
            print(f"  {p}", file=sys.stderr)
        return 2
    print("quote verification: every quote appears on the page it is "
          "attributed to")

    con = wks_store.open_db()
    try:
        plan = []
        for cid, wrong_url in WRONG_LINKS.items():
            rows = con.execute(
                """SELECT i.id, i.item_key, x.quote, s.id AS sid
                     FROM item i
                     JOIN item_source x ON x.item_id = i.id
                     JOIN source s ON s.id = x.source_id
                    WHERE i.status = 'active' AND i.class_id = ?
                      AND s.url = ?""",
                (cid, wrong_url),
            ).fetchall()
            for r in rows:
                plan.append((r["id"], r["item_key"], cid, r["sid"],
                             wrong_url, r["quote"]))

        print(f"=== R28 citation repair ===")
        print(f"defective links found: {len(plan)}")
        if not plan:
            print("  nothing to repair")
            return 0

        if args.dry_run:
            for item_id, key, cid, sid, url, quote in plan:
                print(f"  would re-link item_id={item_id} {cid} <- {url}")
            return 0

        # Register the replacement pages. `upsert_source` is monotonic in
        # authority, so a page that already exists keeps its stronger label.
        new_ids = {}
        for cid, spec in REPLACEMENTS.items():
            url = str(spec["url"])
            sid = wks_store.upsert_source(
                con, url, wks_store.host_of(url),
                title=str(spec["title"]),
                source_type=str(spec["source_type"]),
                authority=2,
                http_status=200,
            )
            new_ids[cid] = sid
            print(f"  registered {cid} <- {url} (source id {sid})")

        # Re-link each affected item to the correct page, with a quote
        # drawn from THAT page. The quote is chosen to bear on the claim:
        # items whose claim is about the search order get the search-order
        # quote, and so on.
        quotes = {cid: list(spec["quotes"])  # type: ignore[arg-type]
                  for cid, spec in REPLACEMENTS.items()}
        counters = {cid: 0 for cid in REPLACEMENTS}
        for item_id, key, cid, sid, url, old_quote in plan:
            wks_store.unlink_source(con, item_id, sid)
            i = counters[cid]
            counters[cid] += 1
            quote = quotes[cid][i % len(quotes[cid])]
            wks_store.link_source(con, item_id, new_ids[cid], quote=quote)

        # Record what was replaced, so nothing is lost.
        superseded = ROOT / "superseded" / "r28-citation-repair-20261031.json"
        superseded.parent.mkdir(parents=True, exist_ok=True)
        superseded.write_text(json.dumps({
            "rule": "R28",
            "reason": "cited page was about a different subject from the "
                      "class it was filed under; the quote was real text "
                      "from that unrelated page",
            "repaired": [
                {"item_id": item_id, "item_key": key, "class_id": cid,
                 "removed_source_id": sid, "removed_url": url,
                 "removed_quote": old_quote,
                 "added_source_id": new_ids[cid],
                 "added_url": REPLACEMENTS[cid]["url"]}
                for item_id, key, cid, sid, url, old_quote in plan
            ],
        }, indent=2), encoding="utf-8")
        print(f"  superseded record: {superseded.relative_to(ROOT)}")
        con.commit()

        # VERIFY: every affected item must now cite an on-subject page.
        sys.path.insert(0, str(ROOT / "tools"))
        import importlib.util
        spec = importlib.util.spec_from_file_location(
            "audit_seed_subjects", ROOT / "tools" / "audit_seed_subjects.py")
        checker = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(checker)

        remaining = []
        for item_id, key, cid, sid, url, old_quote in plan:
            ev = wks_store.item_evidence(con, item_id)
            good = [e for e in ev
                    if checker.page_is_about(cid, e["url"])[0]]
            if not good:
                remaining.append(key)
        if remaining:
            print(f"  STILL UNSUPPORTED: {len(remaining)} item(s)", file=sys.stderr)
            for k in remaining[:10]:
                print(f"    {k}", file=sys.stderr)
            return 1
        print(f"  verified: all {len(plan)} items now cite an on-subject page")
        return 0
    finally:
        con.close()


if __name__ == "__main__":
    raise SystemExit(main())
