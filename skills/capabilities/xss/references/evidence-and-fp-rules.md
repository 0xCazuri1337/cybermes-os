# Evidence and False-Positive Rules — Reference

Source provenance: `domains/web/xss/topics/*`, `hunt-xss`, WKS FP rules.

## Evidence standards
- Unique canary appears unescaped in response.
- Browser execution confirmed (not reflection alone).
- For stored: second-user render confirmed.
- For DOM: source-to-sink trace + execution.
- For CSP: policy verified on landing page.

## False-positive rules (representative)
- Reflection alone is not XSS.
- Reflection in a 302 body is not XSS.
- Proper contextual encoding (`&lt;script&gt;`) means safe.
- Source read without reaching an execution-capable sink is not DOM XSS.
- Store-only write with no second-user render is not stored XSS.
- Self-fired marker in own session is not reportable.
- JSON API endpoint returning unescaped payload is not XSS unless rendered in HTML context.

## Quote verification
- Baseline: `validation/quote_verification/xss.json`.

## Gate 0 Validation

Before writing the report, answer all three:

1. What can the attacker DO right now? Demonstrate concrete action: execute JS in victim's browser session on target domain, steal session cookies/tokens, perform actions as victim, exfiltrate sensitive data. "Alert box appears" is not sufficient.
2. What does the victim LOSE? Session control (ATO), sensitive data (cookies, CSRF tokens, PII), money, or trust (credential phishing). If unauthenticated user on public page, quantify exposure.
3. Can it be reproduced in 10 minutes from scratch? Self-contained PoC URL/step sequence any reviewer can follow; fires in current browser without special config.

## Advanced triage and reporting

- Severity: Critical requires stored XSS on sign-in or site-wide ATO via CSP bypass; High stored in admin dashboards/sensitive editors; Medium reflected with limited impact; Low self-XSS.
- Discipline: do not file XSS as Critical without demonstrating terminal impact (ATO/token exfil/privilege escalation); file as Medium otherwise.
- Report template: title "Stored XSS in [COMPONENT] via [TECHNIQUE]"; summary, description, payload, steps to reproduce, impact, reference to H1 report pattern.
- Real impact examples: cache poisoning on sign-in page (mass credential harvesting), stored XSS via diagram rendering in wiki (org-level ATO), sanitizer bypass via label color field with CSP bypass.
