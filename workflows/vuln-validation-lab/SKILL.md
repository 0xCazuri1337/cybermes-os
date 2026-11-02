---
name: vuln-validation-lab
description: Stand up an isolated instance to confirm product-bug impact.
---

# vuln-validation-lab

Use when you must validate a suspected product/software vulnerability on your own instance — e.g. a bug-bounty program (Elastic, etc.) that explicitly permits testing on a deployment you control. Covers standing up a local copy of the target software when container tooling (Docker/compose) is unavailable, by fetching the vendor's official release tarballs and running them directly with security disabled. Also applies any time you need an isolated, reproducible environment to confirm exploit impact instead of guessing.

## When to use
- A disclosure policy / bug-bounty program allows or encourages reproducing on your own deployment. Example: Elastic HackerOne — "reproduce product bugs on a deployment that meets the minimum requirements... no less than 1 CPU and 2 GB of RAM." Stand up the instance yourself; do not test against other users' data or production.
- You have a source-review LEAD or a hypothesis about a product bug but cannot confirm runtime impact without a live instance you control.
- You need an isolated environment to chain / confirm exploit impact (e.g. prototype-pollution -> RCE, XSS + CSP-bypass) safely.

## Approach
1. Confirm the program permits own-deployment testing and note the minimum spec (CPU / RAM).
2. Prefer the program's recommended path. If Docker / compose is available and permitted, use it.
3. If container tooling is unavailable (no daemon, missing compose plugin, no passwordless sudo), fall back to **official vendor tarballs**:
   - Fetch the exact version under review from the vendor's artifact host. Probe reachability with a ranged request first: `curl -s -m 15 -r 0-1000 <url>` (expect `206`).
   - Extract with `tar xzf`.
   - Configure a single-node, security-disabled instance (see `templates/start_es_kb_lab.sh` for an ES+Kibana example).
   - Boot the datastore first; wait until it answers on its port (e.g. `http://127.0.0.1:9200`), then boot the app tier pointed at it.
4. Validate the finding against your own instance ONLY. Never point tests at other users' data or production.

## Pitfalls
- **Verify before claiming.** Extraction + startup must actually succeed and the service must answer on its port before you treat the lab as ready. A downloaded tarball is NOT a working lab. Confirm with a real request, not by assuming.
- Match versions EXACTLY to the one under review; behavior differs across releases.
- Keep it isolated (bind 127.0.0.1) — do not expose the lab to the network.
- Tarball downloads are large (ES/Kibana ~500 MB each); run in the background and watch file size grow. Sequential download (datastore first, app second) avoids partial-state confusion.
- Note the lab's role in the finding workflow: it produces VALIDATED (impact demonstrated) evidence. It does NOT replace the mandatory pre-report validation gate in the bug-bounty workflow.

## Support files
- `templates/start_es_kb_lab.sh` — starter script: download (with reachability probe) + extract + single-node ES + Kibana, security off, readiness waits. Adapt `ES_VER` / `LAB_DIR` / paths. Marked unverified-end-to-end in the originating session — confirm extraction + startup on first real run.

## Out of scope
This skill is about the *environment*, not the vuln class. Route the actual bug hunt through the bug-bounty master-skill model (web/xss, identity/authorization, web/ssrf, etc.) and the validation layer before any report.
