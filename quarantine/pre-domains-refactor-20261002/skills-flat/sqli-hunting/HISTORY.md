# History

Append-only. Each entry records WHY the skill changed, not just that it did. Improvement means better hunting behaviour, not more text.

## 2026-10-02 00:09 — 1 diff lines
- items: 14 (supported 14), FP rules 0, chains 0, state researching
- still missing: fp_rules, chain

```diff
(initial generation, 2026-10-02)
```

## 2026-10-02 01:36 — 11 diff lines
- items: 14 (supported 14), FP rules 0, chains 0, state researching
- still missing: fp_rules, chain

```diff
--- sqli@current
+++ sqli@new
@@ -7,7 +7,7 @@
 
 <!-- GENERATED from db/wks.db by wks/skillgen.py. DO NOT HAND-EDIT.
      Edit the rows (or ingest better research) and re-run:
-     python -m wks.skillgen -->
+     python -m wks.skillgen -->
 
 > surface `web` · CWE CWE-89 · OWASP A03:2021
 > evidence: 14 items, 14 supported, 0 FP rules, 0 chains
```

## 2026-10-02 10:30 — 108 diff lines
- items: 14 (supported 14), FP rules 12, chains 1, state mature

```diff
--- sqli@current
+++ sqli@new
@@ -10,8 +10,8 @@
      python -m wks.skillgen -->
 
 > surface `web` · CWE CWE-89 · OWASP A03:2021
-> evidence: 14 items, 14 supported, 0 FP rules, 0 chains
-> maturity: **researching** — missing: fp_rules, chain
+> evidence: 14 items, 14 supported, 12 FP rules, 1 chains
+> maturity: **mature**
 
 Attacker-controlled input is concatenated into a SQL statement, so the query structure becomes attacker-controlled.
 
@@ -22,7 +22,7 @@
 
 - Any request-controllable value that reaches a SQL query is a candidate injection point, including JSON/XML bodies, cookies and headers, not just GET parameters.
   - **Disproof:** If a field's value is provably never used in any query (e.g. purely client-side sorting or CSRF tokens), it cannot be an injection point.
-  - Sources: <https://portswigger.net/web-security/sql-injection> · <https://raw.githubusercontent.com/OWASP/wstg/master/document/4-Web_Application_Security_Testing/07-Injection/05-SQL_Injection.md>
+  - Sources: <https://raw.githubusercontent.com/OWASP/wstg/master/document/4-Web_Application_Security_Testing/07-Injection/05-SQL_Injection.md> · <https://portswigger.net/web-security/sql-injection>
 - Prepared/parameterized statements force the DB to separate code from data, so bind-variable queries are the baseline you must establish before treating quote errors as SQLi.
   - **Disproof:** If the query string is built by concatenation at runtime even when a parameterized API exists elsewhere, the endpoint is not parameterized.
   - Sources: <https://cheatsheetseries.owasp.org/cheatsheets/SQL_Injection_Prevention_Cheat_Sheet.html> · <https://cwe.mitre.org/data/definitions/89.html>
@@ -31,28 +31,28 @@
 
 - If the app neither returns query results nor error differences nor timing changes, the query may run asynchronously; absence of in-band signal does not mean absence of SQLi.
   - **Disproof:** If an OAST payload produces no collaborator/DNS callback and conditional time delays stay within baseline jitter, the parameter is very likely not injectable.
-  - Sources: <https://owasp.org/www-project-web-security-testing-guide/stable/4-Web_Application_Security_Testing/07-Input_Validation_Testing/05-Testing_for_SQL_Injection.html> · <https://portswigger.net/web-security/sql-injection/blind>
+  - Sources: <https://raw.githubusercontent.com/OWASP/wstg/v4.2/document/4-Web_Application_Security_Testing/07-Input_Validation_Testing/05-Testing_for_SQL_Injection.md> · <https://portswigger.net/web-security/sql-injection/blind>
 - A single quote or a paired OR 1=1 / OR 1=2 pair producing a repeatable response difference is the primary first-order SQLi signal.
   - **Disproof:** If the quote and both boolean twins produce byte-identical responses, the field shows no first-order SQLi signal.
-  - Sources: <https://portswigger.net/web-security/sql-injection> · <https://raw.githubusercontent.com/OWASP/wstg/master/document/4-Web_Application_Security_Testing/07-Injection/05-SQL_Injection.md>
+  - Sources: <https://raw.githubusercontent.com/OWASP/wstg/master/document/4-Web_Application_Security_Testing/07-Injection/05-SQL_Injection.md> · <https://portswigger.net/web-security/sql-injection>
 
 ## Techniques (what to change)
 
 - Blind boolean injection extracts arbitrary values one character at a time by making the app's visible behaviour depend on a single condition.
   - **Disproof:** If the application's behaviour is identical whether the condition is true or false, boolean extraction is impossible and time-based or OAST is required.
-  - Sources: <https://owasp.org/www-project-web-security-testing-guide/stable/4-Web_Application_Security_Testing/07-Input_Validation_Testing/05-Testing_for_SQL_Injection.html> · <https://portswigger.net/web-security/sql-injection/blind>
+  - Sources: <https://raw.githubusercontent.com/OWASP/wstg/v4.2/document/4-Web_Application_Security_Testing/07-Input_Validation_Testing/05-Testing_for_SQL_Injection.md> · <https://portswigger.net/web-security/sql-injection/blind>
 - Incrementing ORDER BY <n> until a response change appears infers the column count of the original query even when errors are suppressed.
   - **Disproof:** If every index from 1 upward yields an identical response, ORDER BY cannot be used for column counting and you must rely on UNION NULL probing.
   - Sources: <https://cheatsheetseries.owasp.org/cheatsheets/SQL_Injection_Prevention_Cheat_Sheet.html> · <https://portswigger.net/web-security/sql-injection/union-attacks>
 - UNION SELECT NULL with increasing NULL counts finds the column count, then a string marker in each position finds a column type that can carry exfiltrated data.
   - **Disproof:** If the response is identical for wrong and correct NULL counts, the UNION column-count method is ineffective and you must use boolean or error-based inference.
-  - Sources: <https://portswigger.net/web-security/sql-injection/union-attacks> · <https://raw.githubusercontent.com/OWASP/wstg/master/document/4-Web_Application_Security_Testing/07-Injection/05-SQL_Injection.md>
+  - Sources: <https://raw.githubusercontent.com/OWASP/wstg/master/document/4-Web_Application_Security_Testing/07-Injection/05-SQL_Injection.md> · <https://portswigger.net/web-security/sql-injection/union-attacks>
 
 ## Validation bar (how to prove it)
 
 - A SQLi finding is only validated when one variable changes and the response difference is reproducible and explainable by query logic.
   - **Disproof:** If the difference is non-deterministic, cache- or session-driven, or does not reverse when the condition is inverted, it is not a validated SQLi.
-  - Sources: <https://owasp.org/www-project-web-security-testing-guide/stable/4-Web_Application_Security_Testing/07-Input_Validation_Testing/05-Testing_for_SQL_Injection.html> · <https://portswigger.net/web-security/sql-injection/blind>
+  - Sources: <https://raw.githubusercontent.com/OWASP/wstg/v4.2/document/4-Web_Application_Security_Testing/07-Input_Validation_Testing/05-Testing_for_SQL_Injection.md> · <https://portswigger.net/web-security/sql-injection/blind>
 - A verbose database error that echoes the constructed query turns blind injection visible and independently confirms the injection point's context.
   - **Disproof:** If the app returns a generic custom error page with no driver text and no reflected query fragment, error-based confirmation is unavailable.
   - Sources: <https://cwe.mitre.org/data/definitions/89.html> · <https://portswigger.net/web-security/sql-injection/blind>
@@ -61,7 +61,7 @@
 
 - A 500 or generic error page triggered by malformed input alone is not SQLi evidence; many apps error identically for any invalid value.
   - **Disproof:** If plain type-mismatch input produces the identical 500 response with no SQL-specific text, the 500 is an input-validation artefact, not SQLi.
-  - Sources: <https://portswigger.net/web-security/sql-injection/blind> · <https://raw.githubusercontent.com/OWASP/wstg/master/document/4-Web_Application_Security_Testing/07-Injection/05-SQL_Injection.md>
+  - Sources: <https://raw.githubusercontent.com/OWASP/wstg/master/document/4-Web_Application_Security_Testing/07-Injection/05-SQL_Injection.md> · <https://portswigger.net/web-security/sql-injection/blind>
 - Under a properly parameterized ORM/HQL query, quote and comment payloads are matched as literal data, so their failure to inject is a true negative, not a missed bug.
   - **Disproof:** If the ORM library has a known injection CVE for the deployed version, or raw concatenated queries appear in the code path, the negative result is invalid.
   - Sources: <https://cheatsheetseries.owasp.org/cheatsheets/SQL_Injection_Prevention_Cheat_Sheet.html> · <https://cwe.mitre.org/data/definitions/89.html> · <https://raw.githubusercontent.com/OWASP/wstg/master/document/4-Web_Application_Security_Testing/07-Injection/05.7-ORM_Injection.md>
@@ -84,5 +84,42 @@
   - **Disproof:** If the stored payload is only ever read back through parameterized queries and never concatenated, the flow is not second-order injectable.
   - Sources: <https://cwe.mitre.org/data/definitions/89.html> · <https://portswigger.net/web-security/sql-injection>
 
+## Rejected before you report
+
+- **The search parameter is injectable because a single quote produces a database syntax error**
+  - Killed by: The unquoted control request also returned HTTP 500, so the error is raised before the query is built - it comes from a missing query parameter or a template error, not from the quote reaching a parser
+  - Rule: A 500 on a metacharacter proves nothing until the same request without the metacharacter returns 200; always capture an unquoted control response before attributing an error to injection
+- **The ordering of results changes when a CASE expression is appended to the sort parameter**
+  - Killed by: The two orderings also differed between two identical repeat requests, so the ordering is unstable for reasons unrelated to the injected expression - the key was not reaching a query
+  - Rule: Ordering is only a valid injection signal when a repeated identical baseline request is byte-identical; unstable ordering means the parameter is not demonstrably reaching the query
+- **A UNION SELECT payload is accepted because the response returns a different column count**
+  - Killed by: The response differed for every column count including impossible ones, and the 'injected' values were already present in the page's own template - the difference was template rendering, not query execution
+  - Rule: Before claiming UNION injection, grep the baseline response for the literal values you injected; a value already present in the template proves the response difference came from rendering, not the query
+- **The endpoint is blind-injectable because a sleep payload measurably delays the response**
+  - Killed by: The delay was not correlated with the payload: alternating requests showed the delay appearing on baselines too, and an unresolvable host produced a comparable timeout, so the latency is the network path
+  - Rule: Timing-based injection requires repeated alternating samples showing the delay tracks the payload; one slow response against a network you have not baselined is a network event, not a finding
+- **The id parameter is injectable because numeric ids return different data than string ids**
+  - Killed by: Any out-of-range value returns the same 400 regardless of quoting, and the message is a fixed application validation string with no database wording - the quote is rejected by type validation before any query
+  - Rule: A validation error that is byte-identical for any invalid value indicates a type check, not a parser; a parser-specific error must name the construct that failed
+- **An error-based payload exfiltrated database version information**
+  - Killed by: The version string appears in the response headers of every page including ones with no injectable parameter, so it is server disclosure rather than something the injection returned
+  - Rule: Before calling a value 'extracted by injection', grep other responses for it; a value the server already emits is information disclosure, a different finding with a different fix
+- **The WAF is bypassable because the payload with a comment marker returned HTTP 200**
+  - Killed by: The 200 response contained no injected data and the same payload alternated between 200 and 403 across repeats, so the filter is probabilistic rather than bypassed
+  - Rule: A filter bypass requires the bypassed request to return attacker-chosen data consistently; a status code that alternates across identical requests is filter noise, not a bypass
+- **The comment-terminated payload proves the input is concatenated rather than parameterised**
+  - Killed by: A trailing '-- -' produced the same result as an empty value, which is the application's own trimming behaviour; the result change came from the value being empty, not from a comment being honoured
+  - Rule: A comment marker only demonstrates concatenation if its effect differs from an empty value; identical results mean the marker is ordinary input, not a comment
+- **A 500 or generic error page triggered by malformed input alone is not SQLi evidence; many apps error identically for any invalid value.**
+  - Killed by: If plain type-mismatch input produces the identical 500 response with no SQL-specific text, the 500 is an input-validation artefact, not SQLi.
+  - Rule: A 500 or generic error page triggered by malformed input alone is not SQLi evidence; many apps error identically for any invalid value.
+- **Under a properly parameterized ORM/HQL query, quote and comment payloads are matched as literal data, so their failure to inject is a true negative, not a missed bug.**
+  - Killed by: If the ORM library has a known injection CVE for the deployed version, or raw concatenated queries appear in the code path, the negative result is invalid.
+  - Rule: Under a properly parameterized ORM/HQL query, quote and comment payloads are matched as literal data, so their failure to inject is a true negative, not a missed bug.
+
+## Chains to
+
+- `info_disclosure` (3 shared chain(s))
+
 ---
 Full class document: `classes/sqli.md` · retrieve more with `python -m wks.cli search "<query>" --class-id sqli`
```

## 2026-10-02 10:50 — 29 diff lines
- items: 14 (supported 14), FP rules 12, chains 1, state mature

```diff
--- sqli@current
+++ sqli@new
@@ -31,7 +31,7 @@
 
 - If the app neither returns query results nor error differences nor timing changes, the query may run asynchronously; absence of in-band signal does not mean absence of SQLi.
   - **Disproof:** If an OAST payload produces no collaborator/DNS callback and conditional time delays stay within baseline jitter, the parameter is very likely not injectable.
-  - Sources: <https://raw.githubusercontent.com/OWASP/wstg/v4.2/document/4-Web_Application_Security_Testing/07-Input_Validation_Testing/05-Testing_for_SQL_Injection.md> · <https://portswigger.net/web-security/sql-injection/blind>
+  - Sources: <https://owasp.org/www-project-web-security-testing-guide/stable/4-Web_Application_Security_Testing/07-Input_Validation_Testing/05-Testing_for_SQL_Injection.html> · <https://raw.githubusercontent.com/OWASP/wstg/v4.2/document/4-Web_Application_Security_Testing/07-Input_Validation_Testing/05-Testing_for_SQL_Injection.md> · <https://portswigger.net/web-security/sql-injection/blind>
 - A single quote or a paired OR 1=1 / OR 1=2 pair producing a repeatable response difference is the primary first-order SQLi signal.
   - **Disproof:** If the quote and both boolean twins produce byte-identical responses, the field shows no first-order SQLi signal.
   - Sources: <https://raw.githubusercontent.com/OWASP/wstg/master/document/4-Web_Application_Security_Testing/07-Injection/05-SQL_Injection.md> · <https://portswigger.net/web-security/sql-injection>
@@ -40,7 +40,7 @@
 
 - Blind boolean injection extracts arbitrary values one character at a time by making the app's visible behaviour depend on a single condition.
   - **Disproof:** If the application's behaviour is identical whether the condition is true or false, boolean extraction is impossible and time-based or OAST is required.
-  - Sources: <https://raw.githubusercontent.com/OWASP/wstg/v4.2/document/4-Web_Application_Security_Testing/07-Input_Validation_Testing/05-Testing_for_SQL_Injection.md> · <https://portswigger.net/web-security/sql-injection/blind>
+  - Sources: <https://owasp.org/www-project-web-security-testing-guide/stable/4-Web_Application_Security_Testing/07-Input_Validation_Testing/05-Testing_for_SQL_Injection.html> · <https://raw.githubusercontent.com/OWASP/wstg/v4.2/document/4-Web_Application_Security_Testing/07-Input_Validation_Testing/05-Testing_for_SQL_Injection.md> · <https://portswigger.net/web-security/sql-injection/blind>
 - Incrementing ORDER BY <n> until a response change appears infers the column count of the original query even when errors are suppressed.
   - **Disproof:** If every index from 1 upward yields an identical response, ORDER BY cannot be used for column counting and you must rely on UNION NULL probing.
   - Sources: <https://cheatsheetseries.owasp.org/cheatsheets/SQL_Injection_Prevention_Cheat_Sheet.html> · <https://portswigger.net/web-security/sql-injection/union-attacks>
@@ -52,7 +52,7 @@
 
 - A SQLi finding is only validated when one variable changes and the response difference is reproducible and explainable by query logic.
   - **Disproof:** If the difference is non-deterministic, cache- or session-driven, or does not reverse when the condition is inverted, it is not a validated SQLi.
-  - Sources: <https://raw.githubusercontent.com/OWASP/wstg/v4.2/document/4-Web_Application_Security_Testing/07-Input_Validation_Testing/05-Testing_for_SQL_Injection.md> · <https://portswigger.net/web-security/sql-injection/blind>
+  - Sources: <https://owasp.org/www-project-web-security-testing-guide/stable/4-Web_Application_Security_Testing/07-Input_Validation_Testing/05-Testing_for_SQL_Injection.html> · <https://raw.githubusercontent.com/OWASP/wstg/v4.2/document/4-Web_Application_Security_Testing/07-Input_Validation_Testing/05-Testing_for_SQL_Injection.md> · <https://portswigger.net/web-security/sql-injection/blind>
 - A verbose database error that echoes the constructed query turns blind injection visible and independently confirms the injection point's context.
   - **Disproof:** If the app returns a generic custom error page with no driver text and no reflected query fragment, error-based confirmation is unavailable.
   - Sources: <https://cwe.mitre.org/data/definitions/89.html> · <https://portswigger.net/web-security/sql-injection/blind>
```

## 2026-10-02 13:38 — 33 diff lines
- items: 17 (supported 17), FP rules 12, chains 1, state mature

```diff
--- sqli@current
+++ sqli@new
@@ -10,7 +10,7 @@
      python -m wks.skillgen -->
 
 > surface `web` · CWE CWE-89 · OWASP A03:2021
-> evidence: 14 items, 14 supported, 12 FP rules, 1 chains
+> evidence: 17 items, 17 supported, 12 FP rules, 1 chains
 > maturity: **mature**
 
 Attacker-controlled input is concatenated into a SQL statement, so the query structure becomes attacker-controlled.
@@ -38,6 +38,15 @@
 
 ## Techniques (what to change)
 
+- If authorization information is held in a SQL database, it may be possible to change this information through the successful exploitation of a SQL injection vulnerability.
+  - **Disproof:** This is refuted if an authoritative source shows the described behaviour does not occur, does not grant access, or is already prevented by default framework configuration: "If authorization information is held in a SQL database, it may be possible to change this ".
+  - Sources: <https://cwe.mitre.org/data/definitions/89.html> · <https://owasp.org/www-community/attacks/SQL_Injection>
+- For example, consider using persistence layers such as Hibernate or Enterprise Java Beans, which can provide significant protection against SQL injection if used properly.
+  - **Disproof:** This is refuted if an authoritative source shows the described behaviour does not occur, does not grant access, or is already prevented by default framework configuration: "For example, consider using persistence layers such as Hibernate or Enterprise Java Beans,".
+  - Sources: <https://cwe.mitre.org/data/definitions/89.html> · <https://owasp.org/www-community/attacks/SQL_Injection>
+- Input validation will not always prevent SQL injection, especially if you are required to support free-form text fields that could contain arbitrary characters.
+  - **Disproof:** This is refuted if an authoritative source shows the described behaviour does not occur, does not grant access, or is already prevented by default framework configuration: "Input validation will not always prevent SQL injection, especially if you are required to ".
+  - Sources: <https://cwe.mitre.org/data/definitions/89.html> · <https://owasp.org/www-community/attacks/SQL_Injection>
 - Blind boolean injection extracts arbitrary values one character at a time by making the app's visible behaviour depend on a single condition.
   - **Disproof:** If the application's behaviour is identical whether the condition is true or false, boolean extraction is impossible and time-based or OAST is required.
   - Sources: <https://owasp.org/www-project-web-security-testing-guide/stable/4-Web_Application_Security_Testing/07-Input_Validation_Testing/05-Testing_for_SQL_Injection.html> · <https://raw.githubusercontent.com/OWASP/wstg/v4.2/document/4-Web_Application_Security_Testing/07-Input_Validation_Testing/05-Testing_for_SQL_Injection.md> · <https://portswigger.net/web-security/sql-injection/blind>
@@ -122,4 +131,4 @@
 - `info_disclosure` (3 shared chain(s))
 
 ---
-Full class document: `classes/sqli.md` · retrieve more with `python -m wks.cli search "<query>" --class-id sqli`
+Full class document: `skills/Web/sqli/EVIDENCE.md` · retrieve more with `python -m wks.cli search "<query>" --class-id sqli`
```
