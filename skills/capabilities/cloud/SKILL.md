---
name: cloud
description: "Canonical cloud security capability: AWS, Azure, GCP, and Kubernetes hardening, enumeration, exploitation, and remediation. Consolidates 26 sub-skills. Use when hunting or validating cloud-related vulnerabilities."
sources: consolidated
---

# CLOUD — Canonical Capability

## 1. Identity and purpose

This is the single primary executable capability for cloud security testing across AWS, Azure, GCP, and Kubernetes/container platforms. It consolidates 26 previously separate sub-skills into one operational entry point while preserving all source content in `references/` and the original sub-skill directories for rollback.

Primary objectives:
- Discover every cloud asset, identity, storage, network, and workload surface.
- Validate IAM, storage, network, and workload controls with proof.
- Exploit misconfigurations, privilege escalation, and credential abuse only with authorization and proof.
- Produce reproducible, impact-rated findings with remediation guidance.

## 2. Scope

In scope:
- AWS: S3, IAM, STS, CloudFront, Lambda, RDS, CloudTrail, Macie, Security Hub, Pacu/CloudFox/ScoutSuite/Cartography.
- Azure/Microsoft Entra ID: tenants, storage accounts, PIM, federation/AD FS, ROADrecon, AADInternals.
- GCP: IAM, storage buckets, VPC firewall rules, Binary Authorization, Org Policy, Cloud Run/GKE supply chain.
- Kubernetes and Docker: API server, kubelet, etcd, dashboard, RBAC, secrets, service accounts, container escape.
- Cloud asset inventory, CSPM, and misconfiguration hunting across providers.

Out of scope (hand off):
- Pure web application vulnerabilities reached through cloud-hosted apps -> relevant web capabilities (XSS, SQLi, SSRF, etc.).
- Network-only findings without a cloud exploit path -> network capability.
- CI/CD and supply-chain issues beyond container image trust -> supply-chain capability.

## 3. Invocation and routing

Use this capability when:
- A target includes cloud accounts, tenants, projects, subscriptions, or Kubernetes clusters.
- You need to enumerate, audit, or exploit cloud identities, storage, or workloads.
- A finding involves public buckets, over-permissive IAM, metadata exposure, container escape, or cluster takeover.

Routing notes:
- Start with `references/hunt-cloud-misconfig.md` and `references/conducting-cloud-penetration-testing.md` for general cloud posture.
- AWS work routes to AWS references (S3, IAM, Pacu, CloudFox, ScoutSuite, Macie, Security Hub, Cartography).
- Azure work routes to `references/attacking-entra-id-with-roadtools.md`, `references/auditing-azure-active-directory-configuration.md`, `references/auditing-entra-id-with-aadinternals.md`, `references/detecting-azure-storage-account-misconfigurations.md`, `references/implementing-azure-ad-privileged-identity-management.md`.
- GCP work routes to GCP references (IAM, Binary Authorization, Org Policy, VPC firewall, bucket brute).
- Kubernetes/Docker work routes to `references/hunt-k8s.md`.
- Deep IAM chaining across providers routes to `references/cloud-iam-deep.md`.

## 4. Inputs and outputs

Inputs:
- Cloud account/tenant/project identifiers, credentials or assumed roles, and scope/authorization.
- Target endpoints, storage URLs, cluster API endpoints, and workload artifacts.
- Optional: cloud CLIs (aws, az, gcloud, kubectl), tooling (Pacu, CloudFox, ScoutSuite, ROADrecon, AADInternals, GCPBucketBrute, Cartography), and proxy captures.

Outputs:
- Confirmed or refuted cloud findings with request/response or CLI proof.
- Asset/identity/storage inventory and misconfiguration list.
- Reproduction steps, impact assessment, and remediation guidance.
- False-positive rulings with disproof rationale.

## 5. Preconditions and authorization

- Confirm written authorization and scope before testing; include accounts, tenants, projects, regions, and clusters.
- Use only test accounts and non-production data unless explicitly authorized.
- Respect rate limits and avoid destructive operations on shared resources.
- Stop at account/tenant/project boundaries; do not access other tenants data beyond proof of control.
- Document any out-of-scope resource discovered and hand off rather than exploit.

## 6. Reconnaissance

Recon steps:
1. Enumerate accounts, tenants, projects, subscriptions, and regions.
2. Discover storage buckets/blobs, public endpoints, and workload surfaces.
3. Collect IAM principals, roles, policies, service accounts, and managed identities.
4. Identify Kubernetes API servers, kubelets, etcd, and dashboards.
5. Harvest credentials and metadata endpoints via SSRF or leaked secrets.
6. Fingerprint providers and tools to select the right references.

See `references/enumerating-cloud-with-cloudfox.md`, `references/performing-aws-account-enumeration-with-scout-suite.md`, `references/performing-cloud-asset-inventory-with-cartography.md`, `references/hunt-cloud-misconfig.md`, `references/hunt-k8s.md`.


## 7. Detection methodology

Core detection flow:
1. Inventory assets and identities; classify by exposure and sensitivity.
2. Test storage exposure (public read/write, permissive policies, exfiltration paths).
3. Test IAM and privilege escalation (over-permissive policies, AssumeRole chaining, managed identity abuse).
4. Test network exposure (security groups, firewall rules, metadata access).
5. Test workloads and containers (Kubernetes API, kubelet, etcd, dashboard, container escape).
6. Validate each candidate with a second, independent check and, where possible, a second account/role.

References by phase:
- Storage: `references/auditing-aws-s3-bucket-permissions.md`, `references/detecting-s3-data-exfiltration-attempts.md`, `references/detecting-azure-storage-account-misconfigurations.md`, `references/remediating-s3-bucket-misconfiguration.md`.
- IAM: `references/cloud-iam-deep.md`, `references/performing-aws-privilege-escalation-assessment.md`, `references/auditing-gcp-iam-permissions.md`, `references/auditing-azure-active-directory-configuration.md`, `references/auditing-entra-id-with-aadinternals.md`.
- Misconfig: `references/hunt-cloud-misconfig.md`, `references/hunt-k8s.md`, `references/conducting-cloud-penetration-testing.md`.
- Tooling: `references/exploiting-aws-with-pacu.md`, `references/enumerating-cloud-with-cloudfox.md`, `references/emulating-cloud-attacks-with-stratus-red-team.md`, `references/performing-cloud-penetration-testing-with-pacu.md`, `references/performing-gcp-penetration-testing-with-gcpbucketbrute.md`, `references/performing-aws-account-enumeration-with-scout-suite.md`.

## 8. Technique selection

Select techniques by surface and observed behavior:
- Unknown cloud posture -> misconfig hunting + asset inventory + account enumeration.
- AWS IAM/storage -> S3 audit, IAM privilege escalation, Pacu/CloudFox/ScoutSuite.
- Azure/Entra ID -> ROADrecon, AADInternals, storage audit, PIM review.
- GCP -> IAM audit, bucket brute, VPC firewall audit, Binary Authorization, Org Policy.
- Kubernetes/Docker -> API/kubelet/etcd/dashboard/RBAC/secrets/container escape.
- Deep IAM chaining -> `references/cloud-iam-deep.md`.

See `references/performing-cloud-asset-inventory-with-cartography.md`, `references/implementing-aws-security-hub.md`, `references/implementing-aws-macie-for-data-classification.md`.

## 9. Execution steps

1. Establish a baseline for each resource (identity, storage, network, workload).
2. Replay with one controlled change at a time; record status, output, and timing.
3. For authorization tests, use two accounts/roles/projects and compare results.
4. For storage, test anonymous read/write and policy changes with canaries.
5. For IAM, test role assumption and permission boundaries with least-privilege probes.
6. For Kubernetes, test API/kubelet/etcd/dashboard endpoints and RBAC with service account tokens.
7. For containers, test escape primitives only in authorized, isolated environments.
8. Confirm exploitability with a clean reproduction (CLI or raw HTTP).
9. Stop and document when a vector is not exploitable or out of scope.

## 10. Tool usage

- Cloud CLIs: `aws`, `az`, `gcloud`, `kubectl`, `docker`.
- AWS: Pacu, CloudFox, ScoutSuite, Cartography, Stratus Red Team, Macie, Security Hub.
- Azure: ROADrecon, AADInternals, Az PowerShell.
- GCP: GCPBucketBrute, gcloud, Terraform.
- Kubernetes: kubectl, kubeletctl, etcdctl, Trivy, Falco.
- Evidence: CLI output, saved requests/responses, canary values, screenshots.

See `references/conducting-cloud-penetration-testing.md`, `references/exploiting-aws-with-pacu.md`, `references/enumerating-cloud-with-cloudfox.md`.

## 11. Payloads and test cases

Representative test cases (adapt to target):
- Public S3 bucket: anonymous `s3:GetObject`, `s3:PutObject`, `s3:ListBucket`.
- Permissive bucket policy: `Principal: "*"`, `Action: "s3:*"`.
- IAM privilege escalation: `iam:PassRole` + `ec2:RunInstances`, `sts:AssumeRole` chaining.
- Metadata via SSRF: `http://169.254.169.254/latest/meta-data/`.
- Azure storage public access: anonymous blob/container read.
- Entra ID: federation backdoor, Golden SAML, PIM elevation.
- GCP: public bucket, over-permissive IAM binding, firewall `0.0.0.0/0` ingress, unattested image deploy.
- Kubernetes: anonymous API access, kubelet `/exec` and `/run`, etcd unauth, dashboard skip-login, secret/SA token abuse, docker.sock escape, container escape (Leaky Vessels).

Framework and variant details live in the corresponding references.

## 12. Evidence

Each finding must include:
- Exact command/request and response or CLI output.
- Account/tenant/project/role and resource identifiers used.
- Canary values or modified fields and server-side effect.
- For authorization: paired proof showing cross-account/cross-role access.
- For storage: proof of read/write and data scope.
- Impact assessment and affected data scope.


## 13. Reproduction and validation

- Reproduce with cloud CLIs or saved raw requests in a clean session.
- Validate with a second account/role/project where applicable.
- Confirm persistence for policy or configuration changes.
- For race/async issues, repeat multiple times and document success rate.
- Mark as refuted if unauthorized access cannot be demonstrated.

## 14. False-positive rejection

Reject or downgrade when:
- A resource is listed but not actually accessible anonymously.
- An IAM policy is broad but constrained by conditions or SCPs.
- A Kubernetes endpoint responds but requires authentication.
- A container escape primitive is not reachable in the deployed runtime.
- Response differences are due to caching, region, or benign metadata.
- Dev-only or test resources are not reachable in production.

## 15. Impact

Impact guidance:
- Critical: unauthenticated cluster/account takeover, global data exposure, RCE via container escape, payment/infra compromise.
- High: cross-tenant data access, privilege escalation to admin, public writable storage with sensitive data.
- Medium: limited data exposure, misconfiguration with partial exploit path, missing hardening.
- Low: non-sensitive metadata disclosure, best-practice gaps without exploit path.

Always tie impact to business risk and data scope; avoid severity inflation from configuration presence alone.

## 16. Reporting

Report template:
- Summary: resource, vulnerability type, action, impact.
- Scope/authorization: accounts, tenants, projects, test window.
- Steps to reproduce: numbered, minimal.
- Proof of concept: CLI output or raw request/response.
- Impact: business and data scope.
- Remediation: specific control (least privilege, bucket policy, firewall restriction, RBAC hardening, image signing, CSPM).
- References: relevant cloud security framework and provider docs.

## 17. Failure modes

- Surface not fully discovered -> expand recon, check regions, accounts, versions, and content types.
- Auth required but no test account -> request credentials or scope clarification; do not bypass without authorization.
- Rate limiting or guardrails stop testing -> coordinate throttling or use allowed test windows.
- Tooling unavailable -> fall back to native CLIs and manual verification.
- Inconclusive authorization result -> repeat with fresh sessions and diff; mark as not confirmed if ambiguous.

## 18. References

All 26 sub-skill references are preserved and must resolve:

| Reference | Sub-capability | Load when |
|---|---|---|
| `references/auditing-aws-s3-bucket-permissions.md` | `auditing-aws-s3-bucket-permissions` | S3 permission audit |
| `references/cloud-iam-deep.md` | `cloud-iam-deep` | Cross-provider IAM chaining |
| `references/conducting-cloud-penetration-testing.md` | `conducting-cloud-penetration-testing` | General cloud pentest methodology |
| `references/detecting-s3-data-exfiltration-attempts.md` | `detecting-s3-data-exfiltration-attempts` | S3 exfiltration detection |
| `references/emulating-cloud-attacks-with-stratus-red-team.md` | `emulating-cloud-attacks-with-stratus-red-team` | Stratus Red Team detonation |
| `references/enumerating-cloud-with-cloudfox.md` | `enumerating-cloud-with-cloudfox` | CloudFox enumeration |
| `references/exploiting-aws-with-pacu.md` | `exploiting-aws-with-pacu` | Pacu exploitation |
| `references/hunt-cloud-misconfig.md` | `hunt-cloud-misconfig` | Cloud misconfig hunting |
| `references/implementing-aws-macie-for-data-classification.md` | `implementing-aws-macie-for-data-classification` | Macie data classification |
| `references/implementing-aws-security-hub.md` | `implementing-aws-security-hub` | Security Hub CSPM |
| `references/performing-aws-account-enumeration-with-scout-suite.md` | `performing-aws-account-enumeration-with-scout-suite` | ScoutSuite enumeration |
| `references/performing-aws-privilege-escalation-assessment.md` | `performing-aws-privilege-escalation-assessment` | AWS privilege escalation |
| `references/performing-cloud-asset-inventory-with-cartography.md` | `performing-cloud-asset-inventory-with-cartography` | Cartography inventory |
| `references/performing-cloud-penetration-testing-with-pacu.md` | `performing-cloud-penetration-testing-with-pacu` | Pacu pentest |
| `references/remediating-s3-bucket-misconfiguration.md` | `remediating-s3-bucket-misconfiguration` | S3 remediation |
| `references/attacking-entra-id-with-roadtools.md` | `attacking-entra-id-with-roadtools` | ROADrecon Entra ID |
| `references/auditing-azure-active-directory-configuration.md` | `auditing-azure-active-directory-configuration` | Azure AD audit |
| `references/auditing-entra-id-with-aadinternals.md` | `auditing-entra-id-with-aadinternals` | AADInternals |
| `references/detecting-azure-storage-account-misconfigurations.md` | `detecting-azure-storage-account-misconfigurations` | Azure storage audit |
| `references/implementing-azure-ad-privileged-identity-management.md` | `implementing-azure-ad-privileged-identity-management` | Azure PIM |
| `references/auditing-gcp-iam-permissions.md` | `auditing-gcp-iam-permissions` | GCP IAM audit |
| `references/implementing-gcp-binary-authorization.md` | `implementing-gcp-binary-authorization` | Binary Authorization |
| `references/implementing-gcp-organization-policy-constraints.md` | `implementing-gcp-organization-policy-constraints` | Org Policy |
| `references/implementing-gcp-vpc-firewall-rules.md` | `implementing-gcp-vpc-firewall-rules` | VPC firewall rules |
| `references/performing-gcp-penetration-testing-with-gcpbucketbrute.md` | `performing-gcp-penetration-testing-with-gcpbucketbrute` | GCP bucket brute |
| `references/hunt-k8s.md` | `hunt-k8s` | Kubernetes/Docker hunting |

Original sub-skills remain intact under `aws/`, `azure/`, `gcp/`, and `k8s/`.

## 19. Testing and mastery

- Validate with the capability tests in `tests/test_cloud_capability.py`.
- Confirm all referenced files resolve and are non-empty.
- Confirm migration map paths/hashes/status are accurate.
- Practice on authorized labs: AWS (flAWS, CloudGoat), Azure (PurpleCloud), GCP (GCPGoat), Kubernetes (Kubernetes Goat, k8s-lab).
- Mastery criteria: independently discover, validate, and report a cloud finding with full reproduction and impact.

---

Original sub-skills remain intact for reversibility. See `migration_map.json`.


## Knowledge sources

- WKS bug classes: none mapped
- Domain knowledge: none mapped
- WKS remains the structured source of truth; retrieve and validate items through WKS rather than duplicating the full corpus in this skill.
- Research and learning material is mapped in `stage-a/knowledge-source-map.json` and must be validated before promotion.
