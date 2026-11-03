# Sources harvest — before / after, and the gap check

Every number below was read from the db or from disk, never from a summary line
a tool printed. `research/baseline.json` was written BEFORE the harvest began and
`research/after.json` after, so the deltas are measurements.

## 1. What was in the corpus before, and after

| metric | before | after | delta |
|---|---|---|---|
| items_total | 1631 | 1734 | **+103** |
| items_active | 1507 | 1610 | **+103** |
| high_confidence | 985 | 1049 | **+64** |
| classes | 62 | **67** | **+5** |
| classes with a `class_domain` row | 62 | 67 | +5 |
| sources | 719 | 760 | +41 |

Per domain:

| domain | items | high_conf |
|---|---|---|
| web | 1131 → **1207** (+76) | 753 → **790** (+37) |
| network | 376 → **403** (+27) | 174 → **201** (+27) |

## 2. Sources: what each one actually yielded

| source | pages | harvested | notes |
|---|---|---|---|
| **hacktricks.wiki** | 1066 in scope | **72 items, 144/144 quotes live-verified** | the deepest source; 285 pages mapped, 378 gap |
| **kathan19 HowToHunt** (GitBook) | 85/85 fetched | **36 items promoted** | 1 rejected by the gate (genuine quote mismatch) |
| **oreobiscuit Playbook** (GitBook) | 116/116 fetched | **3 items** | the playbook is mostly link lists; 7 of 10 refused |
| **HackTricks privesc pages** | 21 fetched | **27 items across 5 new classes** | closes a year-old structural hole |
| **Notion Rem01x** | 400 harvested | 62 verified quotes pending | 102 prose pages of 400; see §5 |
| **pentester.land** | 6421 write-ups | frequency analysis only | not prose — see §4 |
| sploitus.com | — | not bulk-crawled | its own llms.txt asks for attribution + `/api`; refusing to scrape HTML is respecting its terms |
| cvebase.io | — | not fetched | no llms.txt, `/api` 404s |

## 3. The structural hole is closed

`bug_class` had **62 classes and not one privilege-escalation class**, while 9
chains *terminated* on privesc ("code execution as SYSTEM"). pentester.land
independently confirms the demand: **470 write-up instances** carry
`local privilege escalation` / `privilege escalation` as a tag.

Five classes registered, each with an explicit `class_domain` specialization and
its first promoted item:

| class | domain / home | items | hosts |
|---|---|---|---|
| `windows_privesc_token` | network / active-directory | 8 | 3 |
| `windows_privesc_service` | network / active-directory | 6 | 3 |
| `linux_privesc` | network / internal-network | 5 | 3 |
| `container_escape` | network / internal-network | 5 | 3 |
| `windows_privesc_hijack` | network / active-directory | 3 | 3 |

`domains --check`: **0 problems across 67 classes.**

## 4. pentester.land is an index, not prose — and it is the most useful thing here

`writeups.json` is 6421 entries with **664 distinct bug tags**. A tag is not a
claim; it is a frequency signal about where real findings land. The top of it,
against our coverage:

| class | write-up instances | our items |
|---|---|---|
| xss | 1303 | 109 |
| authn | 1079 | 44 |
| cmd | 1014 | 27 |
| info_disclosure | 686 | 18 |
| idor | 467 | 34 |
| bizlogic | 431 | 26 |
| path_traversal | 309 | 56 |
| ssrf | 298 | 50 |
| sqli | 239 | 38 |

That inverts the priority order: `authn` (1079 instances, 44 items),
`cmd` (1014, 27) and `info_disclosure` (686, 18) are where the ecosystem finds
things and our corpus is thinnest — not `xss`, where we are strongest.

## 5. The Notion source needed triage before it could be harvested

400 pages fetched, 1.37 MB. Classification by content:

| kind | pages | action |
|---|---|---|
| thin / no prose | 242 | refused |
| mimikatz / credential-dump artefact | 35 | refused |
| **carries credential-shaped values** | 21 | **refused** |
| real prose | **102** | routed to packet building |

**294 `Password: <value>` strings were kept out of the corpus.** The largest pages
are `sekurlsa::ekeys` output and hash dumps from the author's own lab. They are
not claims — one account of one engagement is not evidence — and they are the
worst possible thing to make retrievable by a search for "password".

## 6. `domains/web/htb-techniques.md` — you were right, and here is the proof

Measured before deleting:

- 13 claims were quoted on that page.
- **All 13 were already present in their class pages. 0 existed only there.**
- Its unique content was one ordering sentence plus a class list.

So it was a flat duplicate of knowledge that already had canonical homes — the
R14 "one canonical home per class" rule in its pure form. Removed:
`domains/web/htb-techniques.md` and `domains/network/htb-techniques.md`, plus
every README pointer to them.

The **generator** was retired too, because a hand-deleted file that a tool still
rewrites is the stale-page defect with extra steps.
`tools/htb_merge_domains.py` now prints its report and writes nothing.

After the deletion: **22 of 22** HTB claims still reachable in their class pages
(13 web, 9 network), `taxonomy_write --check` clean at 147 files.

## 7. Gap check — web, network, AD

Scored on four axes, because an item count alone reads healthy on a corpus that
cannot prove anything:

**WEB (37 classes)** — volume 0 gaps, proof 0 gaps, margin 0 gaps.
Variant gaps: 3 (`api_trust`, `bizlogic`, `supply_chain`).

**NETWORK (30 classes)** — this is where the work is:

| gap | count | classes |
|---|---|---|
| volume (<12 items or <4 high_conf) | **16** | internal_recon(5), exposed_rmm(6), service_enumeration(6), service_enumeration_detail(7), segmentation_analysis(8), exposed_services(9), ldap_enum(9), dns_enum(10), smb(10), ad_acl_abuse, password_attacks, + the 5 new privesc classes |
| proof (no `test`/`validation` item) | **14** | ad_kerberos, ad_delegation, credential_access, password_attacks, ad_acl_abuse, lateral_movement, winrm, exposed_services, internal_recon, ldap_enum, segmentation_analysis, service_enumeration_detail, + windows_privesc_token/service |
| variant | 27 | almost every network class |

**ACTIVE DIRECTORY (15 classes)** — 7 classes hold **no proof criteria at all**:
`ad_acl_abuse`, `ad_delegation`, `ad_kerberos`, `credential_access`,
`password_attacks`, `windows_privesc_token`, `windows_privesc_service`.

13 of 15 AD classes hold **no `variant` item** — we know the mechanism but not
its sub-forms, which is exactly what a scanner misses.

## 8. The single cheapest gap to close next

`proof` is the cheapest axis: it needs no new source, only `test`-kind items
authored from evidence already in the corpus, because the proof criterion is
usually already stated in an existing item's disproof.

Ranked by volume of existing knowledge to mine:

| class | items | high_conf | orgs | needs |
|---|---|---|---|---|
| `password_attacks` | 21 | 3 | 6 | `test` items |
| `ad_acl_abuse` | 20 | 3 | 6 | `test` items |
| `lateral_movement` | 17 | 5 | 8 | `test` items |
| `ad_kerberos` | 15 | 12 | 11 | `test` items |
| `winrm` | 14 | 5 | 4 | `test` items |

`ad_kerberos` is the best first target: 15 items and 11 publisher orgs, so the
evidence base is already strong and only the proof axis is empty.

## 9. Integrity state at the end of this phase

| check | result |
|---|---|
| full-corpus drift (promoted item → page) | **991 promoted, 0 unrendered** |
| `wks.domains --check` | 0 problems across 67 classes |
| `taxonomy_write.py --check` | 147 files match the canonical db |
| ingest results across all waves | 165 submitted, **162 promoted, 3 held, 0 fabricated** |
| live re-verification (HackTricks wave) | 144/144 quotes, 0 mismatch, 0 self-corroboration |
| packet verification (every source) | 0 quote mismatch, 0 heading furniture, 0 self-corroboration |

## 10. Nine defects found and fixed this phase

Each was measured, not assumed:

1. **`INSERT OR IGNORE` inserted nothing** (NOT NULL + explicit NULL) and reported
   success — 22 "registered" classes, 0 rows. Fixed by asserting the count.
2. **kind `test`, `variant` and `evidence` had no section route**, so **109
   promoted items** (17 of mine, 92 pre-existing) were rendered nowhere. The
   corpus held knowledge the page denied. Fixed in `build_taxonomy.py`; drift is
   now asserted at 0.
3. **The guide-as-publisher error**: all 37 HowToHunt items held, twice over.
   Fixed with two independent normative orgs, not a threshold move.
4. **`capec.mitre.org` is not a second registry** — same org as CWE.
5. **A fetcher recorded its failures and destroyed 21 valid cache pointers.**
6. **Absolute-url vs relative-path cache keys** — a lookup reported "not cached"
   for content it held.
7. **A hardcoded `ht_` item prefix** made four sources indistinguishable.
8. **The verifier reported misses it never tested** (twice: wrong cache dir, and
   no Notion resolution path).
9. **Two spec edits landed in the wrong list** — `CHAINS` instead of `CLASSES`,
   caught by asserting the count changed where expected.

The `patch` tool re-indented Python on this host repeatedly enough that the
repair scripts all moved to **line-index surgery with a compile-before-write
guard** — and two of those guards fired and prevented a silent bad write.