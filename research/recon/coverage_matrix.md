# Recon Competency Coverage Matrix

Generated for the recon mastery cycle from `db/wks.db` (read-only) and
`tools/recon_audit_offtopic.py`. Companion to `competencies.json`.

**Baseline, measured:** 62 `bug_class` rows · 1112 `item` rows (1111 `status='active'`, 1 `superseded`) ·
71 `chain` rows · 70 `fp_case` rows · 513 `source` rows · 100.0% of active items `high_confidence` ·
100.0% disproof rate. **Every count below is `status='active'` items.**

**Support levels:** `EVIDENCED` = class exists, items promoted, on-topic ·
`CONTAMINATED` = class exists but its items are largely off-topic ·
`ABSENT` = no class, no items.

`requires_target_contact: false` means the competency's depth is demonstrable from
published material or captured/certified output alone. `true` means depth needs a live
target response — assessable only from captured tool output, never by scanning.

---

## Matrix

| competency | domain | contact | support | items | on-topic | biggest gap |
|---|---|---|---|---|---|---|
| `certificate_tls_intelligence` | osint | no | **ABSENT** | 0 | 0 | No CT class at all; CA/Browser Forum absent from 513-row source table. Highest-value, lowest-cost hole in the registry. |
| `technology_fingerprinting` | web | yes | **ABSENT** | 0 | 0 | Nothing teaches reading a `Server` header, though dns_enum cites it as a risk. Largest web-side gap. |
| `web_application_discovery` | web | yes | **ABSENT** | 0 | 0 | Hub competency — five others depend on it and none of them can run without it. |
| `content_discovery` | web | yes | **ABSENT** | 0 | 0 | No path enumeration and no soft-404 discrimination. `path_traversal` (33/33) needs a path already known. |
| `parameter_discovery` | web | yes | **ABSENT** | 0 | 0 | `mass_assign` (14/14) and `nosql` (16/16) name the flaw, never the parameter set. |
| `api_endpoint_discovery` | web | yes | **ABSENT** | 0 | 0 | `api_trust` (14/14) covers trust *between* known endpoints. `areas/api/` dirs hold 0 items. |
| `virtual_host_discovery` | web | yes | **ABSENT** | 0 | 0 | 0 items match `virtual host` or `vhost`. `host_header` (12/12) is poisoning, a different observable. |
| `subdomain_discovery` | osint | no | **ABSENT** | 0 | 0 | Passive name sources unrepresented. The 1 CT-mentioning item is a dns_enum AXFR item. |
| `historical_asset_discovery` | osint | no | **ABSENT** | 0 | 0 | 0 items for `wayback`. Hardest seed in the set — no standards body specifies web archiving. |
| `ip_asn_attribution` | osint | no | **ABSENT** | 0 | 0 | The 9 `asn` hits are inside `reason`/`season`. No IANA or RIR publisher exists. |
| `registration_intel` | osint | no | **ABSENT** | 0 | 0 | No RDAP/WHOIS class. Nameserver sets seed every DNS competency downstream. |
| `public_code_intel` | osint | no | **ABSENT** | 0 | 0 | 21 `github` mentions are incidental prose. No GitHub/GitLab publisher in the source table. |
| `osint_identity_attribution` | osint | no | **ABSENT** | 0 | 0 | No OSINT domain at all. 0 items match `osint`. |
| `email_address_discovery` | osint | no | **ABSENT** | 0 | 0 | 41 `email` items are all authn/credential claims. No M3AAWG or email-RFC publisher. |
| `breach_correlation` | osint | no | **ABSENT** | 0 | 0 | 12 `breach` items are credential-*dumping* consequences, not corpus correlation. |
| `search_engine_mining` | osint | no | **ABSENT** | 0 | 0 | No search-engine publisher. Sole contact sub-step belongs to web_application_discovery. |
| `cloud_asset_discovery` | cloud | no | **ABSENT** | 0 | 0 | No `cloud` value in `class_domain`, no `domains/cloud`. 34 `cloud` + 45 `aws` items are exploitation claims. |
| `cloud_storage_exposure` | cloud | no | **ABSENT** | 0 | 0 | The 2 `s3 bucket` items are both HashiCorp Vault inside `host_header`. |
| `cloud_identity_discovery` | cloud | no | **ABSENT** | 0 | 0 | Two adjacent `info_disclosure` items are enumeration-*attribution* evasion, a different observable. |
| `attack_surface_prioritization` | cross_domain | no | **ABSENT** | 0 | 0 | 71 chains are per-class, not cross-asset. Nothing ranks recon output against exploitability. |
| `recon_scope_bounding` | cross_domain | no | **ABSENT** | 0 | 0 | Enforced as code (R13 `RESEARCH_ONLY=True`) but has zero evidence items. A competency whose failure mode is an unauthorised probe, with nothing assessed. |
| `rmm_admin_surface_discovery` | network | yes | **CONTAMINATED** | 23 | 4 | Worst ratio measured: 19/23 off-topic (82.6%). |
| `misconfiguration_recon` | cross_domain | yes | **CONTAMINATED** | 13 | 3 | 10/13 off-topic (76.9%). Only class on this list also missing a `class_domain` row. |
| `service_discovery` | network | yes | **CONTAMINATED** | 35 | 12 | 23/35 off-topic across `service_enumeration` (71.4%) + `exposed_services` (61.9%). |
| `service_version_fingerprinting` | network | yes | **CONTAMINATED** | 30 | 9 | 21/30 off-topic. Class page promises configuration profiling; items don't execute it. |
| `smb_share_discovery` | network | yes | **CONTAMINATED** | 13 | 7 | 6/13 off-topic — despite the widest publisher spread of any recon class (11 orgs). Item selection, not sourcing. |
| `dns_zone_recon` | network | yes | **CONTAMINATED** | 22 | 8 | 14/22 off-topic + 4 filler. Verified in the generated `SKILL.md`: XSS, SQLi, buffer-overflow and HTB module blurbs render as DNS techniques. |
| `network_topology_segmentation` | cross_domain | yes | **CONTAMINATED** | 20 | 7 | 13/20 off-topic. Was one of the 9 unpromotable classes; seed now spans 3 orgs, so only topicality remains. |
| `endpoint_discovery` | network | yes | **CONTAMINATED** | 12 | 5 | 7/12 off-topic. Sits exactly on `MATURITY_MIN_ITEMS=12`, so 5 usable items cannot mature. |
| `internal_ad_enumeration` | active_directory | yes | **CONTAMINATED** | 22 | 10 | 12/22 off-topic + 6 filler. Formerly unpromotable (mitre-only); seed now 2 orgs. Topicality unresolved. |
| `infrastructure_correlation` | cross_domain | yes | **CONTAMINATED** | 54 | 20 | 34/54 off-topic. 4 of its inputs are ABSENT — the graph cannot be built from corpus knowledge at all. |
| `ldap_service_enumeration` | active_directory | yes | **CONTAMINATED** | 37 | 29 | `ldap_enum` 8/16, but `ad_ldap` is **21/21 clean**. Salvageable: repair or demote `ldap_enum` to a stub under R14. |
| `winrm_service_assessment` | network | yes | **EVIDENCED** | 15 | 13 | 2/15 off-topic (13.3%), mildest contamination of any NETWORK recon class. `fp_cases=0`. |
| `rdp_service_assessment` | network | yes | **EVIDENCED** | 15 | 15 | Fully clean, 2 named chains. `fp_cases=0`. |
| `subdomain_takeover_validation` | web | yes | **EVIDENCED** | 14 | 14 | Clean — but its upstream input `subdomain_discovery` is ABSENT, so the class assumes sources the corpus lacks. |
| `graphql_schema_discovery` | web | yes | **EVIDENCED** | 13 | 13 | Strongest recon-supporting class: 3 `fp_case` rows + a named chain. |
| `ad_replication_topology_discovery` | active_directory | yes | **EVIDENCED** | 27 | 27 | `ad_trust_abuse` 14/14 + `ad_kerberos` 13/13, 4 named chains. The only fully clean AD recon pair. |
| `ad_group_policy_discovery` | active_directory | yes | **EVIDENCED** | 13 | 13 | 13/13 clean. `fp_cases=0` — the highest-value gap per OPERATOR.md cycle priority. |

**Tally (machine-verified by `acceptance.py`): 21 ABSENT · 11 CONTAMINATED · 6 EVIDENCED · 38 competencies total.**
15 of 38 require no target contact.

---

## Competencies with no corpus support at all

Twenty-one of thirty-eight — more than half the registry. No class, no items,
no chain.

**osint (10)** — `certificate_tls_intelligence`, `historical_asset_discovery`,
`ip_asn_attribution`, `registration_intel`, `public_code_intel`,
`osint_identity_attribution`, `email_address_discovery`, `breach_correlation`,
`search_engine_mining`, `subdomain_discovery`

There is no OSINT domain anywhere in the tree. `class_domain` holds only
`web` and `network` (four specialisations). The 39 `domains/` files matching
`osint` are all the substring inside `talosintelligence.com`; the corpus has
**zero** items containing the word.

**cloud (3)** — `cloud_asset_discovery`, `cloud_storage_exposure`, `cloud_identity_discovery`

No `domains/cloud/` directory, no `cloud` value in `class_domain`, no CSA or
NIST publisher in 513 source rows. The 34 `cloud` and 45 `aws` item hits are
metadata-service exploitation and disclosure claims inside `ssrf`,
`info_disclosure` and `credential_access`.

**web surface mapping (5)** — `web_application_discovery`,
`technology_fingerprinting`, `content_discovery`, `parameter_discovery`,
`api_endpoint_discovery`

`domains/web/` has 34 class directories and every one is a *flaw*. Not one
performs discovery. Substring probes for `endpoint discovery`,
`parameter discovery`, `content discovery`, `virtual host`, `vhost` and
`source map` all return **0 items** across 1111 active items.

**cross_domain (2)** — `attack_surface_prioritization`, `recon_scope_bounding`

Neither exists as a class. `recon_scope_bounding` is enforced in code
(`config.RESEARCH_ONLY=True`, R13) but carries no evidence items — the one
competency whose failure mode is an unauthorised probe is the one with nothing
assessed.

---

## Competencies whose support is contaminated

Eleven. **The brief's predicted list is confirmed almost exactly** — and two more
join it.

Predicted and confirmed CONTAMINATED (off-topic counts measured):
`ad_enumeration` 12/22 · `dns_enum` 14/22 · `exposed_rmm` 19/23 ·
`exposed_services` 13/21 · `internal_recon` 7/12 · `ldap_enum` 8/16 ·
`segmentation_analysis` 13/20 · `service_enumeration` 10/14 ·
`service_enumeration_detail` 11/16 · `misconfig` 10/13 · `smb` 6/13 ·
`info_disclosure` 6/15.

Also contaminated: **`infrastructure_correlation`** (34/54 off-topic, because
aggregation compounds filler across the three classes it draws on).

**Two corrections to the prediction:**

1. **`ldap_service_enumeration` is NOT uniformly contaminated.** `ldap_enum` is
   8/16, but `ad_ldap` — the class actually carrying LDAP discovery — is
   **21/21 clean**. Aggregate 29/37. The competency is salvageable by repairing
   or demoting `ldap_enum`; do not rebuild it.
2. **`info_disclosure` at 6/15 is the mildest of the predicted list** and is not
   what breaks web technology fingerprinting — that competency is ABSENT
   regardless, because disclosure and stack inference are different observables.

**Contamination is measured, not assumed.** Three data points worth carrying:

- Corpus-wide: **155/1111 off-topic (14.0%)**, 49 module-filler. But the
  distribution is not flat — the 12 recon classes absorb most of it while 34 of
  62 classes sit at 0%.
- **Cross-cutting competencies compound the defect.** `infrastructure_correlation`
  draws on three classes and lands at 20/54. The more classes aggregated, the
  worse the on-topic ratio.
- **It reaches the generated projections.** I read
  `domains/network/infrastructure/dns_enum/skills/SKILL.md` directly: it renders
  *"An XSS vulnerability may allow an attacker to execute arbitrary JavaScript
  code…"*, *"SQL injection is a code injection technique…"*, *"Buffer overflows
  are common vulnerabilities…"* and six Hack-The-Box module blurbs as
  `dns_enum` techniques — each with a disproof clause and two cited sources,
  therefore passing every gate. Contamination is not a cosmetic problem: it
  ships into the hunting skill as authoritative.

**A defect in the measuring tool itself:** `recon_audit_offtopic.py` probes only
23 of 62 classes. Its `on_topic()` returns `True` unconditionally for an unprobed
class, so `0.0% off-topic` means *not probed*, not *clean*. The four classes I
report as EVIDENCED on the AD side (`ad_ldap`, `ad_kerberos`, `ad_trust_abuse`,
`ad_group_policy`) are **unprobed** — I verified them on item counts, chains and
a read of `dns_enum`'s page, not on the probe. Extend `VOCAB` before relying on
those four verdicts.

---

## Why this matters

Recon is the only stage where the corpus both fails hardest and hides best: 21 of
38 competencies have zero support and 11 more have support that is measurably
about something else. Ten are purely passive — certificate transparency, IP/ASN
attribution, registration data, historical assets — and not one of them is
representable in a corpus with two domains and no OSINT domain, so the cheapest
competencies to assess are the ones entirely absent. Contamination compounds
downstream: the eleven dirty classes feed a hub competency
(`infrastructure_correlation`) whose four declared inputs are themselves absent
or dirty, so the graph cannot be built from corpus knowledge at all. Because
every item carries a disproof and two sources, the defect passes every gate and
lands in the hunting skill as authoritative — I confirmed XSS and SQLi prose
rendering as DNS enumeration techniques in `dns_enum/skills/SKILL.md`. The
ordering is therefore forced: repair or demote the eleven contaminated classes
(R14) before seeding the twenty absences, because a new class seeded on top of a
dirty base inherits the base's topicality failure. The cheapest possible win is
`certificate_tls_intelligence` — normative RFC 6962, a genuinely independent
second org in the CA/Browser Forum, zero classes and zero items today, and no
target contact required to assess.

---

## Measurement commands

```bash
export WKS_ROOT="C:/Users/Administrator/.hermes/cyber"
python tools/recon_audit_offtopic.py            # table: class, items, offtopic, %, filler
python tools/recon_audit_offtopic.py --json     # per_class off-topic counts used above
python -m wks.cli gaps                         # state, items, chains, missing kinds
python -m wks.cli metrics                      # items_total, disproof_rate, publisher orgs
python -c "import sqlite3;c=sqlite3.connect('db/wks.db');
  print(c.execute(\"select class_id,count(*) from item
    where class_id=? and status='active'\",('dns_enum',)).fetchone())"
python -c "import sqlite3;c=sqlite3.connect('db/wks.db');
  print(c.execute('select count(*) from fp_case where class_id=?',('dns_enum',)).fetchone())"
python -c "import sqlite3;c=sqlite3.connect('db/wks.db');
  print(c.execute(\"select count(distinct chain_id) from chain_step
    where class_id=?\",('dns_enum',)).fetchone())"
python -c "import wks.network_taxonomy as nt,wks.config as cfg;
  from urllib.parse import urlparse;
  print(sorted({cfg.publisher_org(urlparse(u).hostname or '') for u,_ in nt._NET_SEED[0].sources}))"
```

**Read-only:** no `wks.ingest`, no writes to `db/wks.db`. One caveat: `python -m
wks.seed --help` does not print help, it *runs the seeder*. I invoked it once; it
reported `registered 40 classes (0 new)`, and a diff against
`db/wks-pre-resynth-20261002-205254.db` across `bug_class`, `item`, `chain`,
`fp_case`, `source`, `quality`, `item_source`, `run` and `event` shows every
count identical. No mutation occurred.

**No URL was GET-verified this cycle** — search is bot-walled here. Every
publisher org named in `competencies.json` is from prior knowledge and every URL
is marked `unverified`. Resolve them through `db/sources.json` before seeding;
`OPERATOR.md` records that 34% of first-pass `learn.microsoft.com` guesses 404'd.