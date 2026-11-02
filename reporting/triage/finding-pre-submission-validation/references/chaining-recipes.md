# Chaining Recipes + Escalation Ladders
Reference for `finding-pre-submission-validation`. Every recipe answers:
**which primitive does the first bug give, and which sink converts it to real impact?**

## How to use
1. Find your finding's class in the Chain Matrix (or its row in the ladders).
2. Check each listed sink against YOUR target (does the platform have that feature?).
3. Test the chain while you still have access — record the request/response of the CHAIN
   succeeding, not just the first link.
4. A chain you can't demonstrate = "Further impact possible:" footnote. A demonstrated
   chain = the finding's real severity.

---

## Chain Matrix (primitive → sink → impact)

| First bug (primitive) | Sink | Resulting impact |
|---|---|---|
| Open redirect (redirect-victim) | OAuth/SSO `redirect_uri` accepting wildcard/`#` | Token/code theft → ATO |
| Open redirect | password-reset email link | password reset poisoning → ATO |
| Open redirect | `Referer`-based secrets / postMessage origin | secret leakage → ATO |
| SSRF (fetch-internal-URL) | `http://169.254.169.254/latest/meta-data/` | IAM creds → cloud account takeover |
| SSRF | internal-only admin panel (port-scan via response diff) | admin actions as the server |
| SSRF | internal database / Redis / metadata service | RCE / cred theft |
| XSS (execute-JS-in-victim) | admin/staff-visible page | staff session → tenant takeover |
| XSS | page where victim is logged in | session/CSRF-token theft → ATO |
| XSS (DOM, on OAuth callback) | token in URL fragment | token theft → ATO |
| Self-XSS | + CSRF (auto-trigger) or open redirect (lure) | promoted to stored/reflected-XSS impact |
| IDOR-read (act-as-other-user) | same endpoint with PUT/PATCH/DELETE | data modification / destruction |
| IDOR | cross-tenant admin function | full tenant takeover |
| LFI (read-file-server-side) | `/proc/self/environ`, session file, log poison → include | RCE |
| LFI | app source/config read | hardcoded secrets, internal paths |
| File upload (write-file) | traversal in stored filename → webroot/cron dir | RCE / persistence |
| CRLF injection (inject-header) | proxy cache key pollution | stored XSS on cached route |
| Info disclosure | internal hostnames/IPs/ports | target list for SSRF |
| S3 bucket listing / exposed JS | JS bundles in the bucket | hardcoded API keys → account access |
| SQLi (UNION read) | `INTO OUTFILE` / admin creds in users table | RCE / auth bypass → full DB |
| SQLi | stacked queries on MSSQL/Postgres | `xp_cmdshell` / `COPY TO PROGRAM` → RCE |
| Subdomain takeover | wildcard cookie `Domain=.tld` on the dangling name | session capture → ATO |
| Host header injection | password-reset / cache-key | reset poisoning / cache poisoning |
| XXE (internal fetch) | internal services / cloud metadata | SSRF-class impact + file read |
| Race condition | redemption/withdrawal/transfer endpoints | direct financial fraud |
| JWT weak secret / alg:none | admin claims | auth bypass → privileged actions |
| Leaked API key (hardcoded-credentials) | its cloud/vendor console | enumerate → escalate → bill abuse |
| GraphQL introspection | hidden mutations / depth-DoS | undocumented admin ops |
| Email header injection | newsletter/SMTP relay | spam relay / phishing |
| Signup/verify race | email verification flow | account takeover of unverified users |
| 2nd-order SQLi / stored payload | any later-unsanitized consumer | RCE or data leak elsewhere |
| CORS misconfig (`*` + creds) | credentialed endpoint | full cross-origin read of victim data |

## Escalation ladders — test rung N+1 before submitting at rung N

### XSS
obscure reflection → high-value page (login/profile/admin) → stored → admin-visible stored →
session theft (document PoC cookie exfil) → tenant/account takeover. If you stop at
"alert(1)" you are submitting a medium when a critical was one step away.

### SSRF
single internal GET → read full response body → blind→semi-blind via error/timing diff →
metadata cred retrieval (demo: use the returned key) → authenticated cloud API call (list
buckets). Stop only when the IAM policy actually blocks further actions.

### IDOR
read one object → enumerate ALL (loop, count total records affected) → write → delete →
admin-function IDOR (invite/role change). Report the count — "all 1.2M records" beats "an
object".

### SQLi
error-based → UNION column read → auth bypass login → data dump → file write → RCE.
If program forbids RCE/dumps, prove read of minimal sample + state depth in impact.

### LFI
`/etc/passwd` (proof of class) → app source → config/secrets (DB creds, API keys) → log
poisoning / session ride → RCE. Never submit just the passwd read if config was reachable.

### Open redirect
any-URL reflection → OAuth `redirect_uri` flow (authorize URL redirect) → token in
fragment → login with stolen code. Standalone redirect = low/informative; OAuth-chained =
high.

### File upload
blocked `.php` → `.php5/.phtml/.phar` → content-type/extension confusion → null byte /
double ext → polyglot (GIF header + PHP) → traversal in filename (`../../webroot/x.php`) →
webshell. Then prove RCE, not just "file uploaded".

### SSRF → cloud (AWS ladder)
GET base metadata path → IAM role name → `iam/security-credentials/<role>` → AccessKeyId/
SecretAccessKey/Token → `aws sts get-caller-identity` → enumerate S3/EC2 → read/exfil proof.
IMDSv2 required? try hop-limit / `X-Forwarded-For` / response-info leak alternates.

### Authentication bugs
bypass on low-value endpoint → same flaw on password reset / 2FA / email-change →
full ATO on any account (demo on your second account).

### Race conditions
single duplicate → concurrency via Turbo Intruder single-packet (30 parallel) → financial
impact (N× credit) → wallet/withdrawal endpoints. Never submit "rate limit missing" alone.

## Chain-testing OPSEC & fairness rules
- Test chains on YOUR OWN accounts/data. Looping IDOR reads across real users to "count"
  = do it minimally, note aggregate, never exfiltrate content you don't need.
- Cloud cred chains: STOP at `get-caller-identity` + a read-only enumeration proof.
  Never actually exfiltrate or modify customer data. State in the report: "stopped at X."
- Program policy overrides curiosity: if RCE is out of policy, prove up to the boundary
  and describe the rest — don't fire the payload.
- A chain that needs an unrealistic precondition (victim must be on IE11 + click 3 times +
  have specific cookie) is honest as "chained but unlikely" — factor into severity.

## Pentest (multi-host) chain vocabulary
When the "platform" is a network, primitives are: cred-hash, shell, tunnel-reach,
admin-access. Sinks are: SMB signing off (relay), Kerberoastable SPNs, MS17-010, domain
admin sessions, unconstrained delegation, ADCS web enrollment. Chain them with
`attack_path_suggest` (K-shortest cost paths) and record each hop with
`add_attack_step` so the final report reads as one attack narrative.
