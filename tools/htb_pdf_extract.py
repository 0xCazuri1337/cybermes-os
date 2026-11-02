"""Extract the 291 official HTB write-up PDFs to text, and index what is in them.

DIFFERENT SOURCE SHAPE from the previous wave. Those were 512 community `.md`
files, mostly HTB Academy curriculum tables (technique + command + description).
These are HTB's OFFICIAL retired-machine write-ups: prose, one machine per
document, and the valuable part is the SPECIFIC exploit -- a CVE, a named
version, the exact module or payload. That is a different kind of evidence:
"vsftpd 2.3.4 has a backdoor" is a product fact, not a technique.

Consequence for the pipeline: the anti-laundering rule from the last wave still
applies and is even more important here, because these documents are HTB's own
and a single publisher could otherwise corroborate itself across 291 files.

Extraction notes:
  * `pdftotext -layout` is available natively (no python pdf lib on this host),
  * the largest files are ~28MB (image-heavy); a small text yield means a scan
    with no usable text layer, and those are reported rather than mined,
  * text is cached beside the corpus so re-runs never re-parse 1.1GB.
"""
import os
import re
import subprocess
import sys

SRC = r"D:\TeraBoxDownload\HackTheBox-write_ups"
ROOT = os.environ.get("WKS_ROOT", r"C:\Users\Administrator\.hermes\cyber")
DST = os.path.join(ROOT, "research", "corpus", "htb-official-pdf")

# HTB official write-ups are dated documents; this is their provenance.
PUBLISHER = "hackthebox.com"

# MSYS path translation is DISABLED for native binaries on this host, so the
# folder must be handed to `pdftotext` as a native `D:/...` path. The first run
# passed the folder as a literal `D:\...` string joined through os.path, which
# is fine, but the SHELL-facing `/d/...` form does not exist to python --
# measured: 291/291 failed with FileNotFoundError while the same file extracted
# fine when passed as `D:/TeraBoxDownload/...`.
SRC_NATIVE = SRC.replace("\\", "/")


def slug(fn):
    base = os.path.splitext(fn)[0]
    return re.sub(r'[<>:"/\\|?*\x00-\x1f]+', "_", base).strip() + ".txt"


def main():
    if not os.path.isdir(SRC):
        print(f"source folder not found: {SRC}")
        return 1
    os.makedirs(DST, exist_ok=True)
    pdfs = sorted(f for f in os.listdir(SRC) if f.lower().endswith(".pdf"))
    print(f"PDFs to extract: {len(pdfs)}")

    rows, scanned = [], []
    for i, fn in enumerate(pdfs, 1):
        out = os.path.join(DST, slug(fn))
        # machine name + id from "<id>-<Name>_HTB_Official_writeup_<Author>.pdf"
        m = re.match(r"(\d+)-(.+?)_HTB_Official_writeup_(.+)\.pdf$", fn)
        mid, machine, author = (m.group(1), m.group(2), m.group(3)) if m else ("", "", "")
        if os.path.exists(out) and os.path.getsize(out) > 400:
            txt = open(out, encoding="utf-8", errors="replace").read()
        else:
            try:
                r = subprocess.run(
                    ["pdftotext", "-layout",
                     SRC_NATIVE.rstrip("/") + "/" + fn.replace("\\", "/"), out],
                    capture_output=True, timeout=180)
                if r.returncode != 0 or not os.path.exists(out):
                    scanned.append((fn, "pdftotext rc=%d" % r.returncode))
                    continue
            except Exception as e:
                scanned.append((fn, type(e).__name__))
                continue
            txt = open(out, encoding="utf-8", errors="replace").read()
        low = txt.lower()
        cves = sorted(set(re.findall(r"cve-\d{4}-\d{4,7}", low)))
        # the technique signals that matter in a walkthrough
        sig = {k: low.count(k) for k in (
            "nmap", "smbclient", "kerberoast", "bloodhound", "ldapsearch",
            "john", "hashcat", "sqlmap", "union select", "php://filter",
            "gobuster", "ffuf", "chisel", "ligolo", "linpeas", "winpeas",
            "mimikatz", "certutil", "reverse shell", "privilege escalation",
            "sudo -l", "impacket", "psexec", "winrm", "jwt", "xxe", "ssti",
        ) if low.count(k)}
        rows.append({"file": fn, "txt": out, "id": mid, "machine": machine,
                     "author": author, "chars": len(txt), "cves": cves,
                     "sig": sig, "pages": txt.count("\f") + 1})
        if i % 40 == 0:
            print(f"  {i}/{len(pdfs)}", flush=True)

    import json
    with open(os.path.join(ROOT, "research", "htb_pdf_corpus.json"), "w",
              encoding="utf-8") as f:
        json.dump(rows, f, indent=2)

    ok = [r for r in rows if r["chars"] > 1200]
    thin = [r for r in rows if r["chars"] <= 1200]
    print(f"\nextracted with real text : {len(ok)}/{len(pdfs)}")
    print(f"thin / no text layer     : {len(thin)}")
    if thin:
        for r in thin[:8]:
            print(f"    {r['chars']:>6}b  {r['file'][:66]}")
    print(f"total chars              : {sum(r['chars'] for r in rows):,}")

    allcve = sorted({c for r in rows for c in r["cves"]})
    print(f"\ndistinct CVEs named      : {len(allcve)}")
    print("  ", ", ".join(allcve[:14]))

    freq = {}
    for r in rows:
        for k, v in r["sig"].items():
            freq[k] = freq.get(k, 0) + v
    print("\ntop technique signals:")
    for k, v in sorted(freq.items(), key=lambda kv: -kv[1])[:22]:
        docs = sum(1 for r in rows if k in r["sig"])
        print(f"  {v:>7} occurrences in {docs:>3} docs   {k}")
    if scanned:
        print(f"\n{len(scanned)} file(s) failed extraction:")
        for fn, why in scanned[:8]:
            print(f"    {why}  {fn[:60]}")
    return 0


if __name__ == "__main__":
    sys.exit(main())