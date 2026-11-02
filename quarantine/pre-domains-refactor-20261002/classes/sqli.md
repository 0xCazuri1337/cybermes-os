# SQL Injection

> surface: `web` · CWE: CWE-89 · OWASP: A03:2021
> maturity: **mature** — 17 items, 17 supported, 12 FP rules, 1 chains

Attacker-controlled input is concatenated into a SQL statement, so the query structure becomes attacker-controlled.

**Aliases:** sql injection, sqli, second order sql injection, nosql injection operator

## Prerequisite

- **Any request-controllable value that reaches a SQL query is a candidate injection point, including JSON/XML bodies, cookies and headers, not just GET parameters.**  
  `high_confidence` · score 0.908 · disproved by: If a field's value is provably never used in any query (e.g. purely client-side sorting or CSRF tokens), it cannot be an injection point.
  sources: <https://raw.githubusercontent.com/OWASP/wstg/master/document/4-Web_Application_Security_Testing/07-Injection/05-SQL_Injection.md> · <https://portswigger.net/web-security/sql-injection>
- **Prepared/parameterized statements force the DB to separate code from data, so bind-variable queries are the baseline you must establish before treating quote errors as SQLi.**  
  `high_confidence` · score 0.908 · disproved by: If the query string is built by concatenation at runtime even when a parameterized API exists elsewhere, the endpoint is not parameterized.
  sources: <https://cheatsheetseries.owasp.org/cheatsheets/SQL_Injection_Prevention_Cheat_Sheet.html> · <https://cwe.mitre.org/data/definitions/89.html>

## Signal

- **If the app neither returns query results nor error differences nor timing changes, the query may run asynchronously; absence of in-band signal does not mean absence of SQLi.**  
  `high_confidence` · score 0.8965 · disproved by: If an OAST payload produces no collaborator/DNS callback and conditional time delays stay within baseline jitter, the parameter is very likely not injectable.
  sources: <https://owasp.org/www-project-web-security-testing-guide/stable/4-Web_Application_Security_Testing/07-Input_Validation_Testing/05-Testing_for_SQL_Injection.html> · <https://raw.githubusercontent.com/OWASP/wstg/v4.2/document/4-Web_Application_Security_Testing/07-Input_Validation_Testing/05-Testing_for_SQL_Injection.md> · <https://portswigger.net/web-security/sql-injection/blind>
- **A single quote or a paired OR 1=1 / OR 1=2 pair producing a repeatable response difference is the primary first-order SQLi signal.**  
  `high_confidence` · score 0.8255 · disproved by: If the quote and both boolean twins produce byte-identical responses, the field shows no first-order SQLi signal.
  sources: <https://raw.githubusercontent.com/OWASP/wstg/master/document/4-Web_Application_Security_Testing/07-Injection/05-SQL_Injection.md> · <https://portswigger.net/web-security/sql-injection>

## Technique

- **Blind boolean injection extracts arbitrary values one character at a time by making the app's visible behaviour depend on a single condition.**  
  `high_confidence` · score 0.869 · disproved by: If the application's behaviour is identical whether the condition is true or false, boolean extraction is impossible and time-based or OAST is required.
  sources: <https://owasp.org/www-project-web-security-testing-guide/stable/4-Web_Application_Security_Testing/07-Input_Validation_Testing/05-Testing_for_SQL_Injection.html> · <https://raw.githubusercontent.com/OWASP/wstg/v4.2/document/4-Web_Application_Security_Testing/07-Input_Validation_Testing/05-Testing_for_SQL_Injection.md> · <https://portswigger.net/web-security/sql-injection/blind>
- **Incrementing ORDER BY <n> until a response change appears infers the column count of the original query even when errors are suppressed.**  
  `high_confidence` · score 0.853 · disproved by: If every index from 1 upward yields an identical response, ORDER BY cannot be used for column counting and you must rely on UNION NULL probing.
  sources: <https://cheatsheetseries.owasp.org/cheatsheets/SQL_Injection_Prevention_Cheat_Sheet.html> · <https://portswigger.net/web-security/sql-injection/union-attacks>
- **UNION SELECT NULL with increasing NULL counts finds the column count, then a string marker in each position finds a column type that can carry exfiltrated data.**  
  `high_confidence` · score 0.8255 · disproved by: If the response is identical for wrong and correct NULL counts, the UNION column-count method is ineffective and you must use boolean or error-based inference.
  sources: <https://raw.githubusercontent.com/OWASP/wstg/master/document/4-Web_Application_Security_Testing/07-Injection/05-SQL_Injection.md> · <https://portswigger.net/web-security/sql-injection/union-attacks>
- **For example, consider using persistence layers such as Hibernate or Enterprise Java Beans, which can provide significant protection against SQL injection if used properly.**  
  `high_confidence` · score 0.8055 · disproved by: This is refuted if an authoritative source shows the described behaviour does not occur, does not grant access, or is already prevented by default framework configuration: "For example, consider using persistence layers such as Hibernate or Enterprise Java Beans,".
  sources: <https://cwe.mitre.org/data/definitions/89.html> · <https://owasp.org/www-community/attacks/SQL_Injection>
- **Input validation will not always prevent SQL injection, especially if you are required to support free-form text fields that could contain arbitrary characters.**  
  `high_confidence` · score 0.8055 · disproved by: This is refuted if an authoritative source shows the described behaviour does not occur, does not grant access, or is already prevented by default framework configuration: "Input validation will not always prevent SQL injection, especially if you are required to ".
  sources: <https://cwe.mitre.org/data/definitions/89.html> · <https://owasp.org/www-community/attacks/SQL_Injection>
- **If authorization information is held in a SQL database, it may be possible to change this information through the successful exploitation of a SQL injection vulnerability.**  
  `high_confidence` · score 0.778 · disproved by: This is refuted if an authoritative source shows the described behaviour does not occur, does not grant access, or is already prevented by default framework configuration: "If authorization information is held in a SQL database, it may be possible to change this ".
  sources: <https://cwe.mitre.org/data/definitions/89.html> · <https://owasp.org/www-community/attacks/SQL_Injection>

## Validation

- **A SQLi finding is only validated when one variable changes and the response difference is reproducible and explainable by query logic.**  
  `high_confidence` · score 0.924 · disproved by: If the difference is non-deterministic, cache- or session-driven, or does not reverse when the condition is inverted, it is not a validated SQLi.
  sources: <https://owasp.org/www-project-web-security-testing-guide/stable/4-Web_Application_Security_Testing/07-Input_Validation_Testing/05-Testing_for_SQL_Injection.html> · <https://raw.githubusercontent.com/OWASP/wstg/v4.2/document/4-Web_Application_Security_Testing/07-Input_Validation_Testing/05-Testing_for_SQL_Injection.md> · <https://portswigger.net/web-security/sql-injection/blind>
- **A verbose database error that echoes the constructed query turns blind injection visible and independently confirms the injection point's context.**  
  `high_confidence` · score 0.853 · disproved by: If the app returns a generic custom error page with no driver text and no reflected query fragment, error-based confirmation is unavailable.
  sources: <https://cwe.mitre.org/data/definitions/89.html> · <https://portswigger.net/web-security/sql-injection/blind>

## Fp Rule

- **Under a properly parameterized ORM/HQL query, quote and comment payloads are matched as literal data, so their failure to inject is a true negative, not a missed bug.**  
  `high_confidence` · score 0.8965 · disproved by: If the ORM library has a known injection CVE for the deployed version, or raw concatenated queries appear in the code path, the negative result is invalid.
  sources: <https://cheatsheetseries.owasp.org/cheatsheets/SQL_Injection_Prevention_Cheat_Sheet.html> · <https://cwe.mitre.org/data/definitions/89.html> · <https://raw.githubusercontent.com/OWASP/wstg/master/document/4-Web_Application_Security_Testing/07-Injection/05.7-ORM_Injection.md>
- **A 500 or generic error page triggered by malformed input alone is not SQLi evidence; many apps error identically for any invalid value.**  
  `high_confidence` · score 0.853 · disproved by: If plain type-mismatch input produces the identical 500 response with no SQL-specific text, the 500 is an input-validation artefact, not SQLi.
  sources: <https://raw.githubusercontent.com/OWASP/wstg/master/document/4-Web_Application_Security_Testing/07-Injection/05-SQL_Injection.md> · <https://portswigger.net/web-security/sql-injection/blind>

## Impact

- **A confirmed SQLi typically yields bulk read of application data and can subvert authentication, not just a single leaked record.**  
  `high_confidence` · score 0.798 · disproved by: If the DB account is restricted to read-only access to a single view and auth cannot be subverted, impact is bounded to the data in that view.
  sources: <https://cwe.mitre.org/data/definitions/89.html> · <https://portswigger.net/web-security/sql-injection>

## Bypass

- **WAFs that normalize, case-filter or over-clean requests can be bypassed by comment-splitting, mixed case, encoding and parameter pollution.**  
  `high_confidence` · score 0.908 · disproved by: If every encoded, case-varied and split variant is rejected identically and no differential response appears, the block is likely enforced downstream of the WAF, not by it.
  sources: <https://community.owasp.org/attacks/SQL_Injection_Bypassing_WAF> · <https://portswigger.net/web-security/sql-injection>

## Chain Link

- **Data written safely by one request can become injectable when a later request concatenates the stored value into a new query.**  
  `high_confidence` · score 0.853 · disproved by: If the stored payload is only ever read back through parameterized queries and never concatenated, the flow is not second-order injectable.
  sources: <https://cwe.mitre.org/data/definitions/89.html> · <https://portswigger.net/web-security/sql-injection>

## False-positive rules

- **Hypothesis:** The search parameter is injectable because a single quote produces a database syntax error
  - **Invalidated by:** The unquoted control request also returned HTTP 500, so the error is raised before the query is built - it comes from a missing query parameter or a template error, not from the quote reaching a parser
  - **Rule:** A 500 on a metacharacter proves nothing until the same request without the metacharacter returns 200; always capture an unquoted control response before attributing an error to injection

- **Hypothesis:** The ordering of results changes when a CASE expression is appended to the sort parameter
  - **Invalidated by:** The two orderings also differed between two identical repeat requests, so the ordering is unstable for reasons unrelated to the injected expression - the key was not reaching a query
  - **Rule:** Ordering is only a valid injection signal when a repeated identical baseline request is byte-identical; unstable ordering means the parameter is not demonstrably reaching the query

- **Hypothesis:** A UNION SELECT payload is accepted because the response returns a different column count
  - **Invalidated by:** The response differed for every column count including impossible ones, and the 'injected' values were already present in the page's own template - the difference was template rendering, not query execution
  - **Rule:** Before claiming UNION injection, grep the baseline response for the literal values you injected; a value already present in the template proves the response difference came from rendering, not the query

- **Hypothesis:** The endpoint is blind-injectable because a sleep payload measurably delays the response
  - **Invalidated by:** The delay was not correlated with the payload: alternating requests showed the delay appearing on baselines too, and an unresolvable host produced a comparable timeout, so the latency is the network path
  - **Rule:** Timing-based injection requires repeated alternating samples showing the delay tracks the payload; one slow response against a network you have not baselined is a network event, not a finding

- **Hypothesis:** The id parameter is injectable because numeric ids return different data than string ids
  - **Invalidated by:** Any out-of-range value returns the same 400 regardless of quoting, and the message is a fixed application validation string with no database wording - the quote is rejected by type validation before any query
  - **Rule:** A validation error that is byte-identical for any invalid value indicates a type check, not a parser; a parser-specific error must name the construct that failed

- **Hypothesis:** An error-based payload exfiltrated database version information
  - **Invalidated by:** The version string appears in the response headers of every page including ones with no injectable parameter, so it is server disclosure rather than something the injection returned
  - **Rule:** Before calling a value 'extracted by injection', grep other responses for it; a value the server already emits is information disclosure, a different finding with a different fix

- **Hypothesis:** The WAF is bypassable because the payload with a comment marker returned HTTP 200
  - **Invalidated by:** The 200 response contained no injected data and the same payload alternated between 200 and 403 across repeats, so the filter is probabilistic rather than bypassed
  - **Rule:** A filter bypass requires the bypassed request to return attacker-chosen data consistently; a status code that alternates across identical requests is filter noise, not a bypass

- **Hypothesis:** The comment-terminated payload proves the input is concatenated rather than parameterised
  - **Invalidated by:** A trailing '-- -' produced the same result as an empty value, which is the application's own trimming behaviour; the result change came from the value being empty, not from a comment being honoured
  - **Rule:** A comment marker only demonstrates concatenation if its effect differs from an empty value; identical results mean the marker is ordinary input, not a comment

- **Hypothesis:** A 500 or generic error page triggered by malformed input alone is not SQLi evidence; many apps error identically for any invalid value.
  - **Invalidated by:** If plain type-mismatch input produces the identical 500 response with no SQL-specific text, the 500 is an input-validation artefact, not SQLi.
  - **Rule:** A 500 or generic error page triggered by malformed input alone is not SQLi evidence; many apps error identically for any invalid value.

- **Hypothesis:** Under a properly parameterized ORM/HQL query, quote and comment payloads are matched as literal data, so their failure to inject is a true negative, not a missed bug.
  - **Invalidated by:** If the ORM library has a known injection CVE for the deployed version, or raw concatenated queries appear in the code path, the negative result is invalid.
  - **Rule:** Under a properly parameterized ORM/HQL query, quote and comment payloads are matched as literal data, so their failure to inject is a true negative, not a missed bug.

## Related classes (via chains)

- `info_disclosure` Information Disclosure (3 chains)
