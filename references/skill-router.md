# references/skill-router.md — Trigger Mapping & Discovery

Version: 1.0
Last Updated: 2026-10-29
Purpose: route hunters to the correct skills based on the discovered attack surface.

AUTHORITY: runtime/registry.json + scripts/skill_registry.py are AUTHORITATIVE. This
table is a human-readable compatibility cross-check. Use the resolver before
testing so all matching skills load automatically:
`python scripts/skill_registry.py resolve --scenario "<surface>" --mode test --paths-only`.

## How to use

1. Find the surface in the left column.
2. Check the trigger surface description.
3. Load ALL skills in "Skills to Load".
4. Skip skills in "When NOT to Load" if conditions apply.
5. Reference links for exact file paths (skills/<name>.md or .agents/skills/<name>/SKILL.md).

## Master registry table by attack surface

### FOUNDATION (always first)
| Attack Surface | Trigger Surface | Skills to Load | When NOT to Load | Key Patterns |
|---|---|---|---|---|
| Every session | every hunt/scan/triage/report | master-bugbounty-rules, learning-engine-integration | NEVER | Foundation pair, always |

### Authentication & Identity
| Attack Surface | Trigger Surface | Skills to Load | When NOT to Load | Key Patterns |
|---|---|---|---|---|
| Login form | username/password | auth-bypass, csrf (csrf when token-less pure API) | csrf if no state change | brute force, default creds |
| Magic link / passwordless | email link, OTP | auth-bypass, jwt | jwt if no token | link reuse, expiry |
| Registration | signup flow | auth-bypass, csrf, business-logic | csrf if no state change | mass assignment, weak validation |
| OAuth / OIDC | redirect, code, token | oauth, jwt, open-redirect (open-redirect only if chaining) | open-redirect unless chaining | redirect_uri, scope |
| SAML | SSO assertion | oauth (nearest), jwt | — | XXE, signature wrap |
| 2FA / TOTP | OTP verification | auth-bypass | — | bypass, recovery |
| SMS / email OTP | code delivery | auth-bypass | — | brute, reuse |
| Backup codes | recovery code | auth-bypass | — | enumeration |
| WebAuthn / FIDO2 | passkey | auth-bypass | — | downgrade |
| Reset link | password reset | auth-bypass | — | token predictability |
| Reset code | OTP reset | auth-bypass | — | brute, reuse |
| Security questions | recovery Q&A | auth-bypass | — | guessing |
| Verification via old password | re-auth | auth-bypass | — | bypass |

### Authorization & Access Control
| Attack Surface | Trigger Surface | Skills to Load | When NOT to Load | Key Patterns |
|---|---|---|---|---|
| User / object IDs | numeric/UUID params | idor | — | BOLA |
| Tenant / org ID | multi-tenant | idor, auth-bypass | — | cross-tenant |
| Resource paths | file/object paths | idor, lfi (lfi only if file serving) | lfi if no file read-back | traversal |
| Filter / query params | search/filter | idor, business-logic | — | param pollution |
| RBAC roles | role checks | auth-bypass, idor | — | vertical priv-esc |
| Admin / support actions | privileged endpoints | auth-bypass, idor | — | function-level authz |
| Feature gates | plan/feature flags | business-logic | — | bypass |

### API & GraphQL
| Attack Surface | Trigger Surface | Skills to Load | When NOT to Load | Key Patterns |
|---|---|---|---|---|
| REST endpoints | /api/* | api-testing, idor (idor when no object refs) | idor if no object refs | method override |
| JSON bodies | POST/PUT/PATCH | api-testing, business-logic | — | mass assignment |
| GraphQL | /graphql | graphql, idor, auth-bypass | — | introspection, batch |
| Hidden methods | OPTIONS/TRACE | api-testing | — | method override |
| Webhooks | callback URL | ssrf (nearest), business-logic | — | SSRF, replay |

### Client-Side & JS
| Attack Surface | Trigger Surface | Skills to Load | When NOT to Load | Key Patterns |
|---|---|---|---|---|
| JS bundles | *.js | api-testing (nearest) | — | endpoint leak |
| Source maps | *.map | api-testing (nearest) | — | source disclosure |
| Client routes | SPA routes | api-testing (nearest) | — | hidden routes |
| Forms / reflected content | input fields | xss, csrf (csrf when no state change) | csrf if no state change | reflected XSS |
| Markdown / rich text | WYSIWYG | xss | — | stored XSS |
| postMessage | message events | xss | — | origin bypass |

### Injection & Parsing
| Attack Surface | Trigger Surface | Skills to Load | When NOT to Load | Key Patterns |
|---|---|---|---|---|
| SQL | DB queries | sqli | — | error/UNION/blind |
| XSS sinks | output points | xss | — | stored/reflected/DOM |
| SSTI | template render | ssti | — | engine-specific |
| SSRF / URL fetchers | URL params | ssrf | — | scheme/IP bypass |
| XXE / XML | XML input | ssrf (nearest) | — | classic/blind |
| File uploads | multipart | file-upload, lfi (lfi when no file read-back) | lfi if no read-back | bypass |
| Path traversal | file paths | lfi | — | encoding |
| Command injection | shell exec | sqli (nearest, partial) | — | ;, \|, && |

### Infrastructure & Perimeter
| Attack Surface | Trigger Surface | Skills to Load | When NOT to Load | Key Patterns |
|---|---|---|---|---|
| CORS | Origin header | idor (nearest) | — | origin reflection |
| Cache | cache keys | open-redirect (nearest) | — | poisoning |
| Host headers | Host header | open-redirect (nearest) | — | poisoning |
| CDN / WAF | edge | recon (nearest) | — | bypass |
| Subdomains | subdomain enum | subdomain-enumeration, subdomain-takeover | — | takeover |
| Appliances | VPN/vCenter/SharePoint | recon (nearest) | — | appliance CVEs |
| NTLM | auth protocol | auth-bypass (nearest) | — | info disclosure |

### Stateful & Realtime
| Attack Surface | Trigger Surface | Skills to Load | When NOT to Load | Key Patterns |
|---|---|---|---|---|
| WebSockets | ws:// | race-condition (nearest) | — | CSWSH |
| Race conditions | concurrent requests | race-condition, business-logic | — | TOCTOU |
| One-time actions | tokens/links | race-condition, business-logic | — | replay |
| Payments | billing flow | business-logic | — | price manipulation |

### Cloud / Mobile / AI / Web3
| Attack Surface | Trigger Surface | Skills to Load | When NOT to Load | Key Patterns |
|---|---|---|---|---|
| Buckets | S3/GCS/Azure | api-testing (nearest) | — | public listing |
| IAM | cloud roles | api-testing (nearest) | — | privilege escalation |
| LLM / AI | AI features | business-logic (nearest) | — | prompt injection |
| APK / mobile | mobile API | api-testing (nearest) | — | hardcoded secrets |
| Smart contracts | web3 | api-testing (nearest) | — | reentrancy |

### Workflow & Chain
| Attack Surface | Trigger Surface | Skills to Load | When NOT to Load | Key Patterns |
|---|---|---|---|---|
| Business logic | workflow abuse | business-logic, race-condition (race-condition when no concurrency) | race-condition if no concurrency | state machine |
| Exploit chains | multi-step | all matching skills for the chain | — | chain boost |

### Validation & Reporting
| Attack Surface | Trigger Surface | Skills to Load | When NOT to Load | Key Patterns |
|---|---|---|---|---|
| Response analysis | diff baseline vs attack | none (response-diff: references/VERIFICATION_CHECKLIST.md) | — | signal scoring |
| FP filtering | triage | none (memory/FALSE_POSITIVE_DB.md + AGENTS.md FP gate) | — | signature hash |
| Severity | classification | none (prioritization.md P1-P4) | — | CVSS |
| Summary / report | final writeup | none (.opencode/commands/report.md; report only when asked) | — | report-writer |

Rule: for any surface not listed, run the resolver — fuzzy matching covers the
long tail. No payload before the skill gate passes.
