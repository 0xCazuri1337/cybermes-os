# GAP ANALYSIS — HackTricks (1066 pages) vs the WKS corpus (62 classes)

Measured, not estimated. Every number here came out of `tools/ht_xwalk4.py`,
`tools/ht_gaps.py` and `tools/ht_diag2.py` against the live corpus at
`C:/Users/Administrator/.hermes/cyber`. Reproduce with:

```bash
export WKS_ROOT=C:/Users/Administrator/.hermes/cyber
cd "$WKS_ROOT"
python tools/ht_xwalk4.py      # the crosswalk
python tools/ht_gaps.py        # gap triage
python tools/ht_diag2.py       # the privesc hole
```

## 1. The crosswalk

| bucket | pages | meaning |
|---|---|---|
| MATCHED | 285 | maps to a registered class (7 hand-verified anchors, 196 scored, 82 inherited from the SUMMARY.md tree) |
| UNMAPPED | 378 | in our scope but maps to no class — the gap list |
| OUT_OF_SCOPE | 403 | HackTricks sections you did not ask for (binary-exploitation, mobile, wifi, stego, hardware, blockchain, crypto, privacy, macOS, AI, todo) |
| **total** | **1066** | every page accounted for — criterion C1 |

Deterministic: two runs produce byte-identical JSON, and the tool is
path-independent now (the default is absolute, because this host keeps exporting
an MSYS `/tmp` path that native python cannot open).

## 2. Coverage of our existing classes

285 in-scope pages map onto 58 of our 62 classes. Four classes have **zero**
HackTricks pages — worth knowing, because it means for those four HackTricks is
not a source at all:

| class | our items | our publisher hosts |
|---|---|---|
| `ad_enumeration` | 17 | 9 |
| `ad_ldap` | 23 | 9 |
| `cache_deception` | 25 | 8 |
| `dns_enum` | 10 | 7 |

`ad_enumeration` and `dns_enum` DID get pages in the final mapping (25 and 3);
the zero list above is from an earlier run before the anchor table was added.

Where HackTricks is deepest for classes we already hold:

| class | HackTricks pages | our items | our hosts |
|---|---|---|---|
| `deser` | 33 | 17 | 15 |
| `xss` | 17 | 93 | 12 |
| `sqli` | 12 | 25 | 9 |
| `path_traversal` | 10 | 44 | 13 |
| `smuggling` | 8 | 25 | 10 |
| `ssti` | 7 | 25 | 10 |

Note the inverse relationship worth acting on: `xss`, `path_traversal` and
`open_redirect` are the classes where we have the MOST items, so marginal
HackTricks pages there add less than they do for a thin class.

## 3. The structural hole — no privilege-escalation class at all

This is the single most important finding and it is not a routing error.

- `bug_class` has 62 rows. **Zero** of them is a privilege-escalation class.
- **Zero** items are filed to one.
- HackTricks has **48 in-scope pages** on privesc (37 windows-hardening,
  8 linux-hardening, 2 pentesting-web, 1 generic-methodologies).
- Our 9 chains *end at* privesc — `ad-delegation-replay-to-dcsync-domain-admin`
  terminates at "impersonate the domain controller", `chain.ad_delegation.auto.01`
  at "code execution as SYSTEM" — and no class owns the step they terminate on.

So the corpus can take you to a low-privilege authenticated host and describe
credential movement, but it has nothing on converting a foothold into SYSTEM.
For AD work that is the highest-yield post-exploitation step.

Proposed classes, sized by the pages behind each (48 pages, grouped):

| proposed class | pages | target domain / home |
|---|---|---|
| token manipulation & impersonation | 6 | network → active-directory |
| Linux privesc vectors | 5 | network → internal-network |
| DLL / SYS-path hijacking | 5 | network → active-directory |
| potato-family SYSTEM shell (Juicy/Rogue/PrintSpoofer/GodPotato) | 3 | network → active-directory |
| weak file/registry permissions | 3 | network → active-directory |
| container escape / runtime privesc (runc, containerd, lxd) | 2 | network → internal-network |
| named pipe impersonation / coercion | 2 | network → active-directory |
| COM object hijacking | 1 | network → active-directory |
| integrity level transition | 1 | network → active-directory |
| handle duplication | 1 | network → active-directory |
| WTS impersonation | 1 | network → active-directory |
| Windows service abuse | 1 | network → active-directory |
| credential & token theft | 1 | network → active-directory |
| (unclassified, needs a human look) | 16 | — |

Recommendation: register 5 classes, not 14. `windows_privesc_token`,
`windows_privesc_hijack`, `windows_privesc_service`, `linux_privesc`,
`container_escape` — each with the mechanism families above as `variant` items.
A class per technique would fragment retrieval.

## 4. Gaps that are EXTEND, not new classes (171 pages)

These map onto classes we already have and should become items or variants:

| target class | pages | what they add | target domain |
|---|---|---|---|
| `internal_recon` | 87 | host forensics, fuzzing, wifi recon, linux privesc surface | network |
| `exposed_rmm` | 33 | exposed management interfaces (RabbitMQ, MQTT, SD-WAN, SAPRouter, GlusterFS, …) | network |
| `service_enumeration_detail` | 6 | OT/ICS protocols (Modbus, BACnet, EthernetIP, OPC-UA, SNMP) | network |
| `clickjacking` | 6 | framing / cross-origin UI redress, postMessage | web |
| `cmd` | 6 | sandbox escapes, downstream-sink injections | web |
| `misconfig` | 5 | Docker, Helm/Tiller, Docker Registry, DNN | web |
| `smb` | 5 | NetBIOS, iSCSI, rpcclient enumeration | network |
| `sqli` | 4 | MSSQL/MySQL/PostgreSQL service exposure + user models | web |
| `lateral_movement` | 3 | SSH, Telnet, PPTP as movement channels | network |
| `exposed_services` | 3 | unauthenticated datastores (Redis, Memcache) | network |

## 5. Gaps that are per-service detail, NOT classes (46 pages)

HackTricks has one page per protocol — `6379 - Pentesting Redis`,
`11211 - Memcache`, `502 - Pentesting Modbus`, `9100 - Raw Printing` and ~40
more. These are **items** for `exposed_services` / `service_enumeration_detail`,
never new classes. Turning 46 protocol pages into 46 classes would make
retrieval worse, not better.

## 6. Fixes applied to the corpus during this analysis

- **`class_domain` was under-populated**: 40 of 62 classes had no explicit row
  and resolved only through the surface fallback. Now 62/62 route from the
  table. `wks.domains --check` → `tree check: 0 problem(s) across 62 classes`.
- The first insert attempt silently wrote **nothing**: `class_domain.specialization`
  is `NOT NULL DEFAULT ''` and I passed explicit `NULL`, so `INSERT OR IGNORE`
  swallowed the violation and reported success. Inserted with `'-'` and
  **asserted the row count afterwards** — 22 rows, 62 total, 0 still missing.

## 7. What was NOT done, and why

- **No privesc classes registered yet.** They need `wks.cli add-class` plus a
  domain row, and a class with zero items reads as "researching" forever. They
  should be registered together with their first harvested item.
- **No fake coverage.** The 285 mapped pages are a *routing* result. Mapping a
  page to a class does not put that page's knowledge in the corpus; only a
  promoted item does.
- **The macOS privesc section (84 pages) is out of scope** as you specified. It
  is the largest single block of privesc material on the site, so if you ever
  want macOS, that is where it is.

## 8. Verified state at the end of this phase

| criterion | result |
|---|---|
| C1 mapping complete + deterministic | PASS — 1066 accounted for, two runs identical |
| C2 no HackTricks self-corroboration | PASS — 0 self-corroborating entries |
| C3 quotes verbatim | PASS — 80/80 quotes verify on their own page via the gate's own matcher |
| C4 real merge, counts from the db | PASS — 1 promoted, re-derived from the db, not from a child's report |
| C5 domain routing wired | PASS — 62/62 classes have a class_domain row; tree check clean |
| C6 projection not drifted | PASS — `taxonomy_write.py --check`: 142 files match |
| gate fingerprint unchanged | PASS — `orch.cli gate`: OK, 6 files fingerprinted, MIN_PUBLISHER_HOSTS still 2 |
| gate regression suite | PASS — `wks.cli selftest`: ALL WKS GATE TESTS PASS |