import json, sqlite3, sys

WEB = {
    "cache_deception": "autogen-cache_deception.json",
    "cache_poisoning": "cache_poisoning.json",
    "cmd": "autogen-cmd.json",
    "cors": "autogen-cors.json",
    "crlf": "crlf.json",
    "csrf": "autogen-csrf.json",
    "deser": "deser.json",
    "file_upload": "autogen-file_upload.json",
    "host_header": "host_header.json",
    "info_disclosure": "info_disclosure.json",
    "ldap": "autogen-ldap.json",
    "misconfig": "autogen-misconfig.json",
    "nosql": "autogen-nosql.json",
    "open_redirect": "autogen-open_redirect.json",
    "path_traversal": "autogen-path_traversal.json",
    "prototype_pollution": "autogen-prototype_pollution.json",
    "smuggling": "smugg.json",
    "sqli": "sqli.json",
    "ssrf": "ssrf.json",
    "ssti": "autogen-ssti.json",
    "supply_chain": "autogen-supply_chain.json",
    "websocket": "autogen-websocket.json",
    "xss": "xss.json",
    "xxe": "xxe.json",
}

def slugify_class(cid):
    return cid

def prep(path, class_id):
    data = json.load(open(path))
    items = data.get("items")
    if not isinstance(items, list):
        return 0
    if not items or "class_id" not in items[0]:
        for it in items:
            it["class_id"] = class_id
    with open(path, "w") as f:
        json.dump(data, f, indent=2)
    return len(items)

def main():
    con = sqlite3.connect("db/wks.db")
    accepted = rejected = 0
    for cid, fname in WEB.items():
        path = f"knowledge/incoming/pending/{fname}"
        try:
            n = prep(path, cid)
        except Exception as e:
            print(f"  SKIP {fname}: {e}")
            continue
        if n == 0:
            print(f"  EMPTY {fname}")
            continue
        # ingest one file per class
        import subprocess
        r = subprocess.run(
            [sys.executable, "-m", "wks.cli", "ingest", path],
            capture_output=True, text=True
        )
        out = r.stdout + r.stderr
        # count promoted lines containing 'high_confidence' or 'supported'
        import re
        for line in out.splitlines():
            if "high_confidence" in line or "supported" in line or "rejected=" in line:
                pass
        # simple verdict
        if "ingested=" in out:
            accepted += 1
        else:
            rejected += 1
        print(f"  {fname:35s} {cid:22s} items={n:3d} ingest={'OK' if 'ingested=' in out else 'FAIL'}")
    con.close()
    print(f"\naccepted={accepted} rejected={rejected}")

if __name__ == "__main__":
    main()
