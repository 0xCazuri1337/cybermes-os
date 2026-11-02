# Burp Suite Validation — Reference

Source provenance: `testing-for-xss-vulnerabilities`, `testing-for-xss-vulnerabilities-with-burpsuite`.

## When to use
- Burp Suite available in the assessment environment.
- Need scanner/active scan, intruder payloads, or repeater-based PoC.

## Workflow
1. Crawl/scan target with Burp Scanner (XSS checks).
2. Use Intruder with XSS payload lists for parameter fuzzing.
3. Use Repeater to craft and verify minimal PoC.
4. Confirm execution in browser (not just scanner finding).
5. Document request/response and browser proof.

## Notes
- Scanner findings are candidates; validate manually.
- Use extensions (Active Scan++, XSS Validator) when available.
- For OWASP WSTG alignment, map tests to WSTG-INPV-01/02.
