"""Verify every quote in an intake file against the LIVE page.

WHY THIS EXISTS. A child's claim that it verified its quotes is a self-report.
So is my own. This script does not care who wrote the item: it fetches each
cited URL and checks whether the quote string is actually on the page. That is
the only check that means anything before an item reaches the corpus.

WHAT IT REPORTS, and why each verdict is distinct:
  VERIFIED     the quote appears in the fetched body
  MISMATCH     the page is live but the quote is not there -> the item is
               wrong. Either paraphrased, or the claim is fabricated.
  FETCH_FAILED  the URL 404/403/times out. Per R16 a dead citation is usually a
               MOVED page, not a fabrication, so this is reported separately
               and routed to wks/resolver.py rather than being called a fake.

NORMALISATION matches `wks.verify_quotes.norm`, so a quote that passes here is
not then rejected by ingest. A verifier that disagrees with the gate about what
counts as a match is a second opinion nobody asked for.
"""
from __future__ import annotations

import json
import re
import ssl
import sys
import urllib.error
import urllib.request
from pathlib import Path
from urllib.parse import urlparse

from wks.verify_quotes import norm

UA = ("Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 "
      "(KHTML, like Gecko) Chrome/125.0 Safari/537.36")
CTX = ssl.create_default_context()

# Hosts that may never satisfy the corroboration gate (standing constraint).
from wks import config


def strip_html(b: str) -> str:
    b = re.sub(r"(?is)<(script|style|head)\b.*?</\1>", " ", b)
    b = re.sub(r"<[^>]+>", " ", b)
    for a, c in (("&nbsp;", " "), ("&amp;", "&"), ("&lt;", "<"), ("&gt;", ">"),
                 ("&quot;", '"'), ("&#39;", "'"), ("&mdash;", "-"),
                 ("&ndash;", "-")):
        b = b.replace(a, c)
    return re.sub(r"\s+", " ", b)


def fetch(url: str, timeout: int = 30) -> tuple[int, str]:
    req = urllib.request.Request(url, headers={"User-Agent": UA,
                                               "Accept": "text/html,*/*"})
    try:
        with urllib.request.urlopen(req, timeout=timeout, context=CTX) as r:
            ctype = r.headers.get("Content-Type", "")
            body = r.read(600_000).decode("utf-8", "replace")
            if "html" in ctype.lower() or "<" in body[:2000]:
                body = strip_html(body)
            return r.status, re.sub(r"\s+", " ", body)
    except urllib.error.HTTPError as e:
        return e.code, ""
    except Exception:  # noqa: BLE001
        return 0, ""


def main() -> int:
    path = sys.argv[1]
    data = json.loads(Path(path).read_text(encoding="utf-8"))
    items = data.get("items") or []
    print(f"verifying {len(items)} items from {path}\n")

    rows, n_ver, n_mis, n_dead = [], 0, 0, 0
    for it in items:
        iid = it.get("item_key", "?")
        refs = it.get("source_refs", [])
        hosts = set()
        item_bad = []
        for ref in refs:
            url = ref.get("url", "")
            quote = ref.get("quote", "")
            host = urlparse(url).netloc
            hosts.add(host)
            if len(quote) > 200:
                item_bad.append(f"{host}: quote {len(quote)} chars (>200)")
            status, body = fetch(url)
            if status != 200:
                verdict = "FETCH_FAILED"
                n_dead += 1
                note = f"HTTP {status}"
            elif norm(quote) and norm(quote) in norm(body):
                verdict = "VERIFIED"
                n_ver += 1
                note = ""
            else:
                verdict = "MISMATCH"
                n_mis += 1
                note = "quote absent from live page"
            item_bad.append(f"{host}: {verdict} {note}".strip())
            rows.append({"item_key": iid, "url": url, "host": host,
                         "status": status, "verdict": verdict, "note": note})
            print(f"  [{verdict:<13}] {host:<26} {iid}")

        ok_hosts = len({h for h in hosts if not config.is_builder_host(h)})
        gate = "OK" if ok_hosts >= config.MIN_PUBLISHER_HOSTS else "THIN"
        print(f"  -> {iid}: {len(hosts)} host(s), {ok_hosts} non-builder "
              f"[{gate}], disproof={'yes' if it.get('disproof') else 'MISSING'}")

    print(f"\n=== SUMMARY ===")
    print(f"  VERIFIED      : {n_ver}")
    print(f"  MISMATCH      : {n_mis}")
    print(f"  FETCH_FAILED  : {n_dead}  (moved page candidates, not fabrications)")
    out = Path("state") / (Path(path).stem + "-verify.json")
    out.write_text(json.dumps({"source": path, "rows": rows,
                               "verified": n_ver, "mismatch": n_mis,
                               "fetch_failed": n_dead}, indent=2), encoding="utf-8")
    print(f"wrote {out}")
    return 1 if (n_mis or n_dead) else 0


if __name__ == "__main__":
    raise SystemExit(main())