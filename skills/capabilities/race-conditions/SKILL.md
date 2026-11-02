---
name: race-conditions
description: "Canonical race-conditions capability: hunting and validating TOCTOU/concurrency vulnerabilities — coupon double-redemption, gift-card double-spend, MFA-OTP validate race, account-create race, faucet/crypto double-mint, email-activation race, vote/upvote inflation, password-reset token race, rate-limit bypass via concurrent requests, HTTP/2 single-packet attack. Consolidates 2 sub-skills: exploiting-race-condition-vulnerabilities, hunt-race-condition. Use when hunting or validating race-conditions-related vulnerabilities."
sources: consolidated
---

# RACE-CONDITIONS — Canonical Capability

## 1. Identity and purpose

This is the single primary executable capability for race condition (TOCTOU/concurrency) security testing across web applications, APIs, fintech, SaaS, social platforms, and e-commerce. It consolidates 2 previously separate sub-skills (`exploiting-race-condition-vulnerabilities`, `hunt-race-condition`) into one operational entry point while preserving all source content in `references/` and the original sub-skill directories for rollback.

Primary objectives:
- Discover one-time/limited-use state-changing endpoints (coupons, transfers, votes, MFA, registration, activation) and prove non-atomic check-then-act windows.
- Exploit limit overrun, partial construction, and rate-limit bypass using synchronized parallel requests (HTTP/2 single-packet attack, last-byte sync, first-sequence sync).
- Produce reproducible, impact-rated findings with remediation guidance (atomic DB operations, locking, idempotency keys, distributed locks).

## 2. Scope

In scope:
- One-time or limited-use actions: coupon/discount redemption, gift-card redemption, balance transfers/withdrawals, inventory purchase, votes/upvotes/likes, MFA/OTP validation, account registration/creation, email activation/verification, password reset token consumption, referral/invite acceptance, trial activation, API key generation, faucet/token minting.
- TOCTOU (Time-of-Check-to-Time-of-Use) gaps between state read and state write.
- Rate-limit / attempt-limit bypass via concurrent requests.
- Multi-endpoint races (partial construction): register-then-confirm, email-change + password-reset, MFA window races.
- HTTP/2 single-packet attack, last-byte sync, first-sequence sync (Flatt extension), h2.cl multi-frame variant.
- Distributed/microservice races (inter-service TOCTOU, cache invalidation windows, queue workers).

Out of scope (hand off):
- Business-logic flaws not rooted in concurrency -> `hunt-business-logic`.
- MFA bypass via logic/replay rather than timing -> `hunt-mfa-bypass`.
- Account takeover via password reset token theft (not race) -> `hunt-ato`.
- API authorization (BOLA/IDOR) not rooted in race -> `hunt-idor` / `hunt-authz`.
- HTTP request smuggling (transport desync) -> `hunt-http-smuggling` (but h2.cl variant pairs with it).

## 3. Invocation and routing

Use this capability when:
- A target has state-changing endpoints enforcing "once per user", "limited quantity", "deduct balance", or rate limits.
- You need to test concurrency/TOCTOU windows or attempt parallel submission.
- A finding involves double-spend, duplicate action, or rate-limit bypass via timing.

Routing notes:
- Turbo Intruder single-packet exploitation, scripts, Burp Repeater parallel send -> `references/exploiting-race-condition-vulnerabilities.md`.
- Hunting methodology, disclosed cases, HTTP/2 single-packet deep reference, operator playbook -> `references/hunt-race-condition.md`.

## 4. Inputs and outputs

Inputs:
- Target base URLs, authenticated test accounts (multiple tiers), session cookies/tokens.
- Captured clean baseline requests for one-time/limited actions.
- Tech stack signals (Rails, Node.js, PHP, microservices, Redis, message queues).
- HTTP/2 support confirmation (ALPN h2).

Outputs:
- Confirmed/refuted race findings with raw request/response proof.
- Race window estimation, success rate across repeated attempts.
- Forged/parallel request scripts (Turbo Intruder, curl, Python threading/asyncio).
- Defense matrix (atomic UPDATE, SELECT FOR UPDATE, idempotency keys, distributed locks, transaction isolation).
- Reproduction steps, impact assessment, remediation guidance.

## 5. Preconditions and authorization

- Confirm written authorization and scope before testing; include hosts, accounts, impact boundaries.
- Use only test accounts; never double-spend real money/credits without authorization.
- Avoid destructive actions on production balances/inventory unless explicitly authorized in a sandbox.
- Coordinate rate limits and concurrency with the owner; races can cause load.
- Treat captured sessions/tokens as secrets.

## 6. Reconnaissance

Recon steps:
1. Enumerate one-time/limited-use actions: grep JS for `button.disabled`, optimistic UI, sequential async calls; map endpoints (`/vote`, `/redeem`, `/checkout`, `/transfer`, `/invite`, `/activate`, `/delete`).
2. Identify state machine: what state is read, what is written, validation between read and write; find the gap (window).
3. Capture a clean baseline request; confirm single-use behavior.
4. Confirm HTTP/2 support: `curl -sI --http2 https://target.com | grep -i HTTP/2`.
5. Check response headers: `X-RateLimit-*`, `X-Request-Id`, cache-control; tech stack signals (Rails without `with_lock`, Node async, PHP without `FOR UPDATE`).
6. Map account types/tiers; determine which actions are race-prone.
7. Establish connection-warming feasibility; pre-connect for single-packet.

## 7. Detection methodology

Core detection flow:
1. Identify a one-time/limited action and capture its request.
2. Estimate race window: single request time vs two sequential vs two concurrent; determine if server serializes.
3. Choose shape: identical-copies race (limit overrun) or different-requests race (partial construction).
4. Set up parallel tooling: Burp Repeater "Send group in parallel", Turbo Intruder `Engine.BURP2`, curl backgrounding, Python threading/asyncio.
5. Send 10-50 identical requests simultaneously (single-packet when HTTP/2 available).
6. Analyze responses: multiple 2xx where only one should succeed, duplicate success messages, DB constraint errors, timing anomalies.
7. Verify actual state: credit applied twice, vote count +N, coupon still unused, etc.
8. Reduce parallelism (5, 3, 2) to characterize window and reliability.
9. Test across account types/tiers and server load conditions.
10. Require reproducibility: 3/5 successes from a 20-line script before reporting.

## 8. Technique selection

Select techniques by observed endpoint and defenses:
- Modern HTTPS, h2 ALPN, body < 1400 bytes, N <= 30 -> Turbo Intruder `Engine.BURP2` single-packet (default).
- Body > MTU -> multi-connection HTTP/2; widen window ~5 ms.
- HTTP/1.1 only -> curl parallel pipeline; wide window; viable on slow servers.
- N > 30 (PIN brute-force, OTP exhaustion) -> Flatt first-sequence-sync extension.
- Front-end h2, back-end h1 -> h2.cl smuggling variant (pairs with `hunt-http-smuggling`).
- Quick repro -> `curl --next` 4-shot parallel HTTP/1.1.
- Partial construction -> different-requests race over ~20 rounds with fresh CSRF.

See `references/hunt-race-condition.md` (HTTP/2 single-packet deep reference, operator playbook).

## 9. Execution steps

1. Enumerate one-time/limited actions and capture a clean baseline request.
2. Confirm HTTP/2 support and estimate race window (single/sequential/concurrent timing).
3. Build parallel request batch (identical copies or different-requests list).
4. Pre-connect/warm connections; buffer all but last byte; release in single TCP write.
5. Fire N requests; collect responses, status codes, lengths, timings.
6. Verify backend state changed more than once (balance, vote count, coupon status).
7. Reduce N and repeat to characterize reliability; run 5 independent attempts.
8. Test bypass of defenses (rate limits, idempotency keys, unique constraints, locks, queues).
9. Document timing, N, success rate; capture Wireshark proof for high-value claims.
10. Stop and document when not exploitable or out of scope.

## 10. Tool usage

- Burp Suite Repeater: "Send group in parallel" (HTTP/2 single-packet).
- Turbo Intruder: `Engine.BURP2`, gate sync, last-byte sync, up to ~30 streams (Flatt extension for more).
- Nuclei: race condition detection templates.
- curl: `--next` parallel pipeline, backgrounding with `&`.
- Python threading: `threading.Barrier` synchronized start.
- Python asyncio/aiohttp: concurrent request sending.
- racepwn: dedicated race condition testing framework.
- Wireshark/tcpdump: validate single-packet delivery (N END_STREAM frames in one TCP segment).
- openssl/curl: HTTP/2 ALPN check.

## 11. Payloads and test cases

Identical-copies race (Turbo Intruder):
```python
def queueRequests(target, wordlists):
    engine = RequestEngine(endpoint=target.endpoint,
                          concurrentConnections=1,
                          engine=Engine.BURP2)
    for i in range(20):
        engine.queue(target.req, gate='race1')
    engine.openGate('race1')

def handleResponse(req, interesting):
    if req.status == 200:
        table.add(req)
```

Different-requests race (partial construction, email-verification bypass):
```
Request A:  POST /register   body: csrf=<csrf>&username=hacker&email=anything@exploit.net&password=pw
Request B:  GET  /confirm    params: token=   (empty)
Fire A and B together, repeat ~20 rounds.
```

Python threading:
```python
import threading, requests
barrier = threading.Barrier(20)
def synchronized_request():
    barrier.wait()
    r = requests.post("http://target.com/api/redeem-coupon",
                      json={"coupon": "DISCOUNT50"},
                      headers={"Cookie": "session=abc123"}, timeout=10)
    print(f"Status: {r.status_code}")
threads = [threading.Thread(target=synchronized_request) for _ in range(20)]
for t in threads: t.start()
for t in threads: t.join()
```

curl parallel:
```bash
for i in $(seq 1 15); do
  curl -s -o /dev/null -w "%{http_code}\n" \
    -X POST "https://target.com/api/vote" \
    -H "Cookie: session=YOUR_SESSION" \
    -H "Content-Type: application/json" \
    -d '{"report_id": "12345", "vote": "up"}' &
done
wait
```

Python asyncio:
```python
import asyncio, aiohttp
async def race_request(session, url, payload, headers):
    async with session.post(url, json=payload, headers=headers) as r:
        return await r.text()
async def main():
    url = "https://target.com/redeem"
    payload = {"code": "GIFT50"}
    headers = {"Cookie": "session=XXXXX"}
    async with aiohttp.ClientSession() as session:
        tasks = [race_request(session, url, payload, headers) for _ in range(20)]
        results = await asyncio.gather(*tasks)
    for r in results: print(r[:100])
asyncio.run(main())
```

Grep patterns for source audit:
```bash
grep -rn "find_by\|where.*first" --include="*.rb" | grep -v "lock"
grep -rn "SELECT.*WHERE" --include="*.php" | grep -v "FOR UPDATE"
grep -rn "\.get(\|\.filter(" --include="*.py" | grep -v "select_for_update"
```

HTTP/2 single-packet check:
```bash
curl -sI --http2 https://target.com | grep -i "HTTP/2\|h2"
```

Additional variants, disclosed cases, and deep single-packet reference live in `references/`.

## 12. Evidence

Each finding must include:
- Exact request(s) and response(s) (raw HTTP or tool output) showing duplicate success.
- Number of concurrent requests, tool/technique, timing, success rate across attempts.
- Backend state proof (balance, coupon count, vote count, created accounts).
- Authentication context (test accounts, sessions).
- Tech stack and defense matrix (locking, atomicity, idempotency, transaction isolation).
- Impact assessment (financial loss, integrity manipulation, access beyond entitlement).
- Remediation guidance.

For high-value claims: PoC video + Wireshark capture showing N END_STREAM frames in one TCP segment.

## 13. Reproduction and validation

- Reproduce with a 20-line script against a fresh test account; demonstrate duplicate effect >=3/5 attempts.
- Confirm server actually processed in parallel (not serialized) via timing.
- Validate across account types/tiers and load conditions.
- For partial construction races, repeat ~20 rounds with fresh CSRF.
- Verify state via independent read (DB/API), not just response codes.
- Mark as refuted if only one success or no concrete impact.

## 14. False-positive rejection

Reject or downgrade when:
- Only one request succeeds (no race won).
- Server serializes requests (T_par2 ≈ T_par1 + T_single) and no duplicate state.
- Database unique constraint prevents duplicate (no partial fulfillment).
- Rate limit holds under concurrent load.
- Response 2xx returns only caller's own data (no impact).
- Single anomalous response (noise) without repeated demonstration.
- Tool output (Burp "Send group in parallel" over HTTP/1.1) without single-packet proof for high-value claims.
- Success requires perfect timing not reliably controllable.

## 15. Impact

Impact guidance:
- Critical: double-spend of real money/credits, balance overdraft, unauthorized resource creation at scale, auth bypass via race.
- High: coupon/gift-card multi-redemption, vote/reputation manipulation, rate-limit bypass enabling brute-force (OTP/PIN), quota bypass.
- Medium: duplicate non-financial actions with limited business impact, minor counter inflation.
- Low: theoretical race without measurable state change or reliable reproduction.

Always tie impact to concrete financial/integrity/security loss; "counter went up twice" is only valid if that counter has real-world value.

## 16. Reporting

Report template:
- Summary: endpoint, vulnerability type (race condition/TOCTOU), technique, impact.
- Scope/authorization: test accounts and window.
- Steps to reproduce: numbered, minimal, including script.
- Race parameters: N concurrent, tool, success rate, timing, window estimate.
- Evidence: responses, state proof, (for high-value) Wireshark single-packet proof.
- Defenses tested: locking, atomic UPDATE, idempotency keys, unique constraints, transaction isolation, queue serialization.
- Impact: financial/integrity/access scope.
- Remediation: atomic DB operations (`UPDATE ... WHERE used=false RETURNING id`), `SELECT ... FOR UPDATE`, optimistic concurrency with version checks, idempotency keys, distributed locks (Redis Redlock/DB advisory locks), transaction isolation (SERIALIZABLE where needed), eliminate client-side-only protection, cache invalidation.
- References: disclosed reports (GitLab CVE-2022-4037, Flatt 10k-req PIN brute-force, nopCommerce CVE-2024-58248), OWASP.

## 17. Failure modes

- Endpoint not race-prone (row-level locks/transactions) -> window estimation filters out; move on.
- HTTP/2 not supported -> fall back to HTTP/1.1 parallel (wider window); or h2.cl variant.
- WAF/gateway blocks parallel bursts -> try fewer requests, different delivery (cookie vs header), chunking.
- Rate limiting on endpoint -> coordinate throttling or use first-sequence-sync.
- Inconclusive state -> repeat with fresh sessions, independent state read; mark not confirmed if ambiguous.
- No test account -> request credentials; do not test without authorization.
- Distributed backends serialize -> try different CDN nodes/load-balanced servers for lock bypass.

## 18. References

All 2 sub-skill references are preserved and must resolve:

| Reference | Sub-capability | Load when |
|---|---|---|
| `references/exploiting-race-condition-vulnerabilities.md` | `exploiting-race-condition-vulnerabilities` | Turbo Intruder single-packet exploitation, scripts, Burp Repeater parallel send, limit overrun |
| `references/hunt-race-condition.md` | `hunt-race-condition` | Hunting methodology, disclosed cases, HTTP/2 single-packet deep reference, operator playbook, bypass techniques |
| `references/api-reference.md` | `exploiting-race-condition-vulnerabilities` | API details for the exploiting sub-skill (mirrored from the sub-skill) |

Original sub-skills remain intact under their directories (including each sub-skill's own content).

Cross-references:
- `hunt-business-logic` — coupon/wallet/promo state-machine races.
- `hunt-mfa-bypass` — OTP rate-limit window single-packet bypass.
- `hunt-ato` — password reset/email change races.
- `hunt-http-smuggling` — h2.cl multi-frame variant.
- `hunt-api-misconfig` — wallet/balance endpoints without atomic UPDATE.

## 19. Testing and mastery

- Validate with the capability tests in `tests/test_race_conditions_capability.py`.
- Confirm all referenced files resolve and are non-empty.
- Confirm migration map paths/hashes/status are accurate.
- Practice on authorized labs: PortSwigger race condition labs, OWASP WebGoat, HackTheBox.
- Mastery criteria: independently discover, validate, and report a race-condition finding with reproducible script, state proof, and impact.


## Knowledge sources

- WKS bug classes: race
- Domain knowledge: race
- WKS remains the structured source of truth; retrieve and validate items through WKS rather than duplicating the full corpus in this skill.
- Research and learning material is mapped in `stage-a/knowledge-source-map.json` and must be validated before promotion.
