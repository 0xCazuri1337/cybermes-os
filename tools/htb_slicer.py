"""Correct the two builder defects the post-write audit found.

D1 (8/19 quotes): `slice_sentence` walked back a fixed number of characters, so
   a quote could begin mid-token ("ient -U", "ic path traversal filter"). A
   quote is evidence; a mangled one verifies against the page and teaches
   nothing.

D3 (2/19): the slice landed on a markdown table separator or a column header
   ("**Potential Attack** | **File Types** | | ---"), which is page furniture
   rather than a statement about the technique.

D2: a `path_traversal` claim was satisfied by a SQL Injection module, because
   the write-up was chosen from a VOCABULARY-SCORE class list rather than by
   what the document is actually about.

The fix is structural, not cosmetic:
  * slice at a real markdown block boundary (row / bullet / heading / sentence)
    and require the window to look like a TABLE ROW that CONTAINS the anchor,
  * reject furniture outright,
  * require the chosen write-up's own TITLE to be topical for the claim,
  * assert the final quote with the gate's matcher AND a word-boundary check.
"""
import glob
import io
import json
import os
import re
import sys

sys.path.insert(0, ".")
from wks.verify_quotes import find_quote

# The harvested write-up corpus. It lives under WKS_ROOT because
# cache/scratch/ is pruned after 24h idle and this is the only local copy
# of the primary evidence behind the merged items.
_ROOT = os.environ.get("WKS_ROOT") or os.path.dirname(os.path.dirname(
    os.path.abspath(__file__)))
SCRATCH = os.path.join(_ROOT, "research", "corpus")
CORPUS = "knowledge/materials/htb_corpus.json"


def rows_containing(text, needle):
    """Return markdown BLOCKS (table rows, bullets, headings, paragraphs)
    that actually contain the needle. A whole row is a natural unit, so the
    quote starts and ends on clean boundaries by construction."""
    lines = text.splitlines()
    hits = []
    i = lines[:]
    low = needle.lower()
    for idx, line in enumerate(i):
        if low not in line.lower():
            continue
        stripped = line.strip()
        # skip pure furniture / separators / table headers
        if not stripped or set(stripped) <= set("-|: *"):
            continue
        if re.match(r"^\|[\s:\-|]+\|$", stripped):      # markdown table rule
            continue
        hits.append((idx, line))
    # Group contiguous hits into blocks. The window extends DOWNWARD only.
    #
    # MEASURED: `lines[idx-2:idx+3]` dragged the two rows ABOVE a match into the
    # quote, so `ldap_enum` returned "| `cat sqldev_tgs_hashcat` ... hashcat ..."
    # for a claim about AD enumeration -- the previous technique's rows. The
    # relevance gate still passed because the mechanism token sat further down
    # inside the same window. A table row and its continuation live BELOW the
    # match; the rows above belong to whatever technique preceded it.
    blocks = []
    for idx, _ in hits:
        block_lines = [lines[idx]]
        j = idx + 1
        while j < len(lines) and len(block_lines) < 4:
            nxt = lines[j]
            if not nxt.strip():
                break
            # stop at a different section heading
            if nxt.lstrip().startswith("#") and len(block_lines) > 1:
                break
            block_lines.append(nxt)
            j += 1
        block = "\n".join(x for x in block_lines if x.strip())
        if block:
            blocks.append(block)
    # prefer the block with the most prose, then the tightest
    def score(b):
        prose = len(re.findall(r"[a-z]{4,}", b))
        pipes = b.count("|")
        return (prose >= 8, prose, -abs(b.count("\n")))
    return sorted(blocks, key=score, reverse=True)


def is_furniture(b):
    """True when the block is page furniture, not a claim about a technique."""
    if re.match(r"^\s*\|[\s:\-|]+\|\s*$", b):
        return True
    letters = re.findall(r"[a-z]{4,}", b.lower())
    if len(letters) < 8:
        return True
    # a table header row with no payload after it
    if re.match(r"^\|?\s*\*\*[^*]+\*\*\s*(\|\s*\*\*[^*]+\*\*\s*)*\|?\s*$", b.strip()):
        return True
    return False


def starts_clean(b):
    """A block must BEGIN at a real token boundary.

    A markdown TABLE ROW legitimately begins with `|`, which is the cleanest
    possible boundary -- the first version rejected it and turned 8 on-topic
    modules into MISSes. The real defect (D1) was a quote beginning INSIDE a
    word ("ic path traversal filter"), so the test is "does the first
    character continue a preceding word", not "is the first char a letter".
    """
    s = b.lstrip()
    if not s:
        return False
    if re.match(r"^[|`(\[/#\-*\d]", s):
        return True
    return bool(re.match(r"^[A-Za-z0-9\"']", s))


def _norm(s):
    """lowercase and collapse separators so 'File Inclusion' == 'file_inclusion'."""
    return re.sub(r"[^a-z0-9]+", "_", (s or "").lower()).strip("_")


_STOP_CLAIM = {"which", "there", "their", "these", "those", "where", "while",
               "because", "before", "after", "under", "other", "being", "about",
               "using", "into", "when", "what", "with", "from", "that", "this",
               "than", "then", "they", "when", "does", "must", "only", "same",
               "such", "each", "over", "into", "without", "never", "every"}


def _relevant(block, claim_terms, min_hits=1):
    """True when the block evidences the CLAIM's mechanism, not merely its topic.

    claim_terms are ORDERED by strength: the first entry is the mechanism
    itself ("zone transfer", "axfr"), later entries are weaker synonyms. The
    first MUST be present. Requiring only *some* term shipped a dns_enum item
    whose quote said "receives a DNS query" for a claim about zone transfer --
    the vocabulary matched, the claim did not.

    A caller with no declared terms keeps the old permissive behaviour.
    """
    if not claim_terms:
        return True
    low = block.lower()
    primary = claim_terms[0]
    if primary.lower() not in low:
        return False
    return True


def pick_writeup(corpus, cls, needles, topical_terms, claim_terms=(), prefer_first=False):
    """Choose a write-up whose OWN TITLE is topical for this class, that really
    contains a needle, and whose block actually demonstrates the claim.

    Returns (record, path, text, needle, block) or None.
    """
    scored = []
    for r in corpus:
        p = os.path.join(SCRATCH, "htb", r["repo"].replace("/", "__"), r["file"])
        if not os.path.exists(p):
            continue
        # Normalise BOTH sides: the corpus path says "20. File Inclusion.md"
        # (spaces) while the topical terms say "file_inclusion" (underscore).
        path_l = _norm(r["path"])
        if not any(_norm(t) in path_l for t in topical_terms):
            continue          # the document must be ABOUT this thing
        try:
            txt = io.open(p, encoding="utf-8", errors="replace").read()
        except Exception:
            continue
        # `prefer_first`: this caller is one CLAIM, not the class. Several rows
        # of the same class share topical_terms but assert different mechanisms,
        # so scoring all needles together hands row A the evidence for row B.
        # Restrict to the row's own anchors in order and take the first that
        # yields a usable block.
        for nd in (needles[:1] if prefer_first else needles):
            blocks = [b for b in rows_containing(txt, nd) if not is_furniture(b)]
            for b in blocks:
                if not starts_clean(b):
                    continue
                # Bounded length: a block over ~900 chars is page furniture.
                if len(b) > 900:
                    continue
                if not find_quote(txt, b):
                    continue
                # THE CLAIM-RELEVANCE GATE (audit D4). A block was previously
                # accepted merely because it sat in a document ABOUT the class,
                # which let ad_kerberos cite "cat .\\ilfreight_tgs.csv" and
                # pass_the_hash cite "base64 -d" -- both verbatim, both
                # irrelevant. The quote must contain the claim's own vocabulary.
                if claim_terms and not _relevant(b, claim_terms):
                    continue
                prose = len(re.findall(r"[a-z]{4,}", b.lower()))
                scored.append((prose, -len(b), r, p, txt, nd, b))
                break
    scored.sort(key=lambda t: (t[0], t[1]), reverse=True)
    if not scored:
        return None
    _, _, r, p, txt, nd, b = scored[0]
    return r, p, txt, nd, b


# class -> (must-be-topical title terms, anchor needles)
TOPICAL = {
    "path_traversal": (["file_inclusion", "path_traversal", "lfi"],
                       ["Bypass filters with URL encoding", "php://filter",
                        "Basic LFI", "/etc/passwd"]),
    "sqli": (["sql_injection", "sqlmap"],
             ["SLEEP", "' OR", "UNION", "sqlmap"]),
    "file_upload": (["file_upload"],
                    ["webshell", "reverse shell", "msfvenom"]),
    "xss": (["xss", "cross-site"], ["<script>", "onerror", "alert("]),
    "ssrf": (["ssrf", "server_side_request"],
             ["SSRF", "169.254.169.254", "server-side request"]),
    "ssti": (["ssti", "template"], ["{{7*7}}", "SSTI"]),
    "xxe": (["xxe"], ["ENTITY", "<!DOCTYPE", "XXE"]),
    "nosql": (["nosql"], ["$ne", "$gt", "MongoDB"]),
    "idor": (["idor", "access_control"], ["IDOR", "Insecure Direct Object"]),
    "info_disclosure": (["information_gathering", "javascript", "footprint"],
                        ["JavaScript", ".js", "API"]),
    "smuggling": (["smuggl"], ["smuggling", "Transfer-Encoding"]),
    "service_enumeration": (["network_enumeration", "getting_started", "footprint"],
                            ["-sV", "-p-", "nmap"]),
    "smb": (["common_services", "getting_started", "footprint"], ["smbclient", "smbmap", "enum4linux"]),
    "ad_kerberos": (["active_directory", "kerberos", "ldap"],
                    ["kerberoast", "GetUserSPNs", "impacket", "Kerberoast"]),
    "ldap_enum": (["active_directory", "ldap", "_ad_", "ad_easy", "ad_hard",
                   "ad_medium", "bloodhound", "proving-grounds"],
                  ["bloodhound", "ldapsearch", "SharpHound", "Get-ADUser",
                   "Get-ADGroup", "Get-ADObject", "Get-DomainUser"]),
    "rdp": (["common_services", "footprint"], ["RDP", "3389", "xfreerdp"]),
    "tunneling_pivoting": (["pivot", "tunnel"], ["chisel", "ligolo", "socks"]),
    "misconfig": (["privilege", "getting_started", "common_services"],
                  ["sudo -l", "linpeas", "LinPEAS"]),
    "exposed_services": (["getting_started", "footprint"], ["listening", "port scan", "banner"]),
    "dns_enum": (["footprint", "information_gathering"], ["axfr", "dig", "zone transfer"]),
    "ssti": (["server_side_attacks", "web_exploitation", "ssti", "template",
              "gobax", "redpanda", "epsilon", "medium_unix"],
             ["{{7*7}}", "{{", "SSTI", "template injection", "jinja"]),
    "xxe": (["web_attacks", "web_application_attacks", "owasp_top_10", "xxe",
             "web_exploitation", "mix-oscp-cpts"],
            ["<!ENTITY", "ENTITY", "XXE", "DOCTYPE"]),
    "nosql": (["introduction_to_web_applications", "wombo", "nosql", "web_exploitation"],
              ["$ne", "$gt", "NoSQL", "MongoDB"]),
    "idor": (["owasp_top_10", "web_attacks", "web_application_attacks",
              "introduction_to_web_applications", "idor"],
             ["IDOR", "Insecure Direct Object", "access control"]),
    "smuggling": (["hacking_wordpress", "quick-write-up", "unbalanced",
                   "smuggl", "linux-machines"],
                  ["smuggl", "Transfer-Encoding", "Content-Length"]),
    "ssrf": (["server_side_attacks", "travel-write-up", "awkward", "oouch",
              "ssrf", "medium_unix", "linux-machines"],
             ["SSRF", "169.254.169.254", "server-side request"]),
    "pass_the_hash": (["active_directory"], ["pass the hash", "ntlm", "hash"]),
}

if __name__ == "__main__":
    corpus = json.load(open(CORPUS, encoding="utf-8"))
    good = bad = 0
    for cls, (terms, needles) in TOPICAL.items():
        pick = pick_writeup(corpus, cls, needles, terms)
        if not pick:
            print(f"  MISS {cls}")
            bad += 1
            continue
        r, p, txt, nd, block = pick
        ok = (find_quote(txt, block) and starts_clean(block)
              and not is_furniture(block) and len(block) < 1200)
        good += ok
        bad += (not ok)
        print(f"  {'OK ' if ok else 'BAD'} {cls:<22} {r['path'][:52]}")
        print(f"      anchor={nd!r}")
        print(f"      block={block[:150]!r}")
    print(f"\nusable blocks: {good}, unusable: {bad}")