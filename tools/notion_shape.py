"""Inspect the real shape of Notion's loadCachedPageChunk record.

MEASURED: the call succeeds and returns `recordMap.block` with 7 entries, but the
generic walker I wrote read 0 blocks, because each entry is
    {"spaceId":..., "value": {"value": {...}, "role":..., "version":...}}
i.e. the block payload is TWO levels down under `value.value`, not one. A walker
written against the wrong shape reports "no content found" and looks like an
empty page.
"""
import json
import sys
import urllib.request

UA = {
    "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 "
                  "Chrome/120.0 Safari/537.36",
    "Content-Type": "application/json", "Accept": "*/*",
    "Origin": "https://www.notion.so", "Referer": "https://www.notion.so/",
}
PID = "52de3128-5d97-490f-a13d-b4567d7b3c4f"


def dashed(p):
    h = p.replace("-", "")
    return "%s-%s-%s-%s-%s" % (h[0:8], h[8:12], h[12:16], h[16:20], h[20:32])


def call(pid):
    url = "https://www.notion.so/api/v3/loadCachedPageChunk"
    payload = {"pageId": dashed(pid), "limit": 100,
               "cursor": {"stack": []}, "chunkNumber": 0,
               "verticalColumns": False}
    r = urllib.request.Request(url, data=json.dumps(payload).encode(), headers=UA)
    return json.loads(urllib.request.urlopen(r, timeout=45).read().decode())


d = call(PID)
blocks = d["recordMap"]["block"]
print("block records:", len(blocks))
print()
first = list(blocks.items())[0]
print("top-level keys of one record:", list(first[1].keys()))
inner = first[1].get("value", {})
print("record['value'] keys         :", list(inner.keys())[:14])
payload = inner.get("value", {})
print("record['value']['value'] keys:", list(payload.keys())[:24])
print()
print("type   :", payload.get("type"))
print("id     :", payload.get("id"))
props = payload.get("properties") or {}
print("properties keys:", list(props.keys())[:12])
tt = props.get("title")
print("title  :", json.dumps(tt)[:220])
print()
print("--- every record's type + title ---")
for k, v in blocks.items():
    p = (v.get("value") or {}).get("value") or {}
    props = p.get("properties") or {}
    t = props.get("title") or []
    txt = "".join(x.get("plain_text", "") for x in t)
    print("  %-22s %-46s %s" % (p.get("type"), txt[:46], k[:8]))