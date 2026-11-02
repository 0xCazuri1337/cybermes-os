import json, os

# Source: autogen-{class}.json which uses the "research corpus" schema
#   {id, title, cwe, owasp, description, attack_vector, detection, poc, remediation,
#    impact, hunting_value, bypass, chain_link, references[] {url, quote}}
# Target: ingest schema
#   {item_key, class_id, kind, claim, body, disproof, severity_hint, hunting_value, sources[]}
#
# Each item in the delivered file is mapped as:
#   id        -> item_key   (e.g. cors-001  -> cors.001)
#   title     -> claim     (headline)
#   description -> body     (main explanation)
#   impact    -> body2 (secondary) -> we prepend to body if present
#   hunting_value -> hunting_value
#   severity  -> severity_hint (High/Medium/Low)
#   type      -> kind       (bypass/technique/evidence/impact/chain_link)
#   references[] {url, quote} -> sources[] (one per reference), source_type: primary if host in portswigger/orf/w3/ietf else writeup

FILES = {
    "cache_poisoning": "autogen-cache_poisoning.json",
    "csrf": "autogen-csrf.json",
    "file_upload": "autogen-file_upload.json",
    "host_header": "autogen-host_header.json",
    "ldap": "autogen-ldap.json",
    "misconfig": "autogen-misconfig.json",
    "nosql": "autogen-nosql.json",
    "open_redirect": "autogen-open_redirect.json",
    "cmd": "autogen-cmd.json",
    "cache_deception": "autogen-cache_deception.json",
}

def conv(item, class_id):
    kind_map = {
        "bypass": "bypass", "technique": "technique", "evidence": "evidence",
        "impact": "impact", "chain_link": "chain_link", "pattern": "pattern",
        "remediation": "mitigation", "deception": "deception", "variant": "variant",
        "signal": "signal", "test": "test", "validation": "validation",
        "prerequisite": "prerequisite", "mitigation": "mitigation",
    }
    ref = item.get("references") or []
    sources = []
    for s in ref:
        host = s.get("url", "").split("/")[2] if s.get("url") else ""
        sources.append({
            "url": s.get("url", ""),
            "source_type": "primary" if host in ("portswigger.net", "owasp.org", "cwe.mitre.org", "httpwg.org", "w3.org", "rfc-editor.org", "nginx.org") else "writeup",
            "host": host,
            "publisher": host,
            "quote": s.get("quote", ""),
            "locator": "Reference",
            "title": item.get("title", ""),
        })
    kind = kind_map.get(item.get("type"), "evidence")
    lines = [item.get("description", ""), item.get("impact", "")]
    body = "\n\n".join([l for l in lines if l]) or item.get("description", "")
    claim = item.get("title", "")
    disproof = item.get("bypass") and f"A payload that does not reach the filtered boundary (already rejected, or the filter operates after the shell has consumed it) is inert." or None
    return {
        "class_id": class_id,
        "item_key": f"{class_id}.{item.get('id','')}".replace(".json",""),
        "kind": kind,
        "claim": claim,
        "body": body,
        "disproof": disproof,
        "severity_hint": {"high": "High", "medium": "Medium", "low": "Low", "critical": "Critical"}.get(str(item.get("severity","")).lower(), "Medium"),
        "hunting_value": item.get("hunting_value", 4),
        "sources": sources,
    }

for class_id, fname in FILES.items():
    path = f"research/pending/{fname}"
    try:
        data = json.load(open(path))
    except Exception as e:
        print(f"SKIP {fname}: {e}")
        continue
    items_in = data.get("items") or []
    out_items = [conv(i, class_id) for i in items_in]
    json.dump({"items": out_items}, open(f"research/pending/{class_id}.json", "w"), indent=2)
    print(f"converted {fname} -> {class_id}.json: {len(out_items)} items")
