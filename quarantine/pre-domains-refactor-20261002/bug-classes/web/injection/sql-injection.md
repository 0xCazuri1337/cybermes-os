# SQL Injection

## Definition

Attacker-controlled input is concatenated into a SQL statement, so the query structure becomes attacker-controlled.

- **CWE:** CWE-89
- **OWASP:** A03:2021
- **Surface:** web
- **Aliases:** ["sql injection", "sqli", "second order sql injection", "nosql injection operator"]

Canonical home for `sqli`. Rendered from `db/wks.db` by `methodology/scripts/build_taxonomy.py` — edit the rows, not this file.

## Root Cause

Not yet researched.

## Preconditions

**Any request-controllable value that reaches a SQL query is a candidate injection point, including JSON/XML bodies, cookies and headers, not just GET parameters.**

Before probing, enumerate every input field including hidden POST fields, cookies and HTTP headers, then test each separately. For each field send a distinctive marker and observe whether it is reflected, stored, or changes database-driven output. Record which field maps to a quoted string vs a numeric context, since that determines the payload shape.

*Disproof:* If a field's value is provably never used in any query (e.g. purely client-side sorting or CSRF tokens), it cannot be an injection point.

**Prepared/parameterized statements force the DB to separate code from data, so bind-variable queries are the baseline you must establish before treating quote errors as SQLi.**

Identify per endpoint whether the framework uses bound parameters (JDBC PreparedStatement, ORM positional/named params) or string concatenation. Where a bind variable is used, inject metacharacters and expect them to be compared literally. Where concatenation is used, expect structural breakage. This distinction is what separates a real finding from a benign type-conversion error.

*Disproof:* If the query string is built by concatenation at runtime even when a parameterized API exists elsewhere, the endpoint is not parameterized.

## Attack Surface

Surface: **web**.

The entry points and enabling conditions for this surface are enumerated under **Preconditions**; the observable signals are under **Detection**.

## Detection

**If the app neither returns query results nor error differences nor timing changes, the query may run asynchronously; absence of in-band signal does not mean absence of SQLi.**

Test a cookie or header parameter that the app processes in a background thread. When in-band booleans, errors and timing all read flat, switch to OAST: send a payload that triggers a DNS lookup to a controlled domain and poll for the interaction. Also try a conditional time delay as a cross-check before concluding the parameter is clean.

*Disproof:* If an OAST payload produces no collaborator/DNS callback and conditional time delays stay within baseline jitter, the parameter is very likely not injectable.

**A single quote or a paired OR 1=1 / OR 1=2 pair producing a repeatable response difference is the primary first-order SQLi signal.**

Send a lone quote or semicolon to each field and note errors. Then send a condition that should be true (OR 1=1) and its near-identical false twin (OR 1=2) with everything else held constant. A repeatable difference between the twins, not merely an error, is the signal worth escalating; capture raw response length, status and body hashes for both.

*Disproof:* If the quote and both boolean twins produce byte-identical responses, the field shows no first-order SQLi signal.

## Exploitation

**Blind boolean injection extracts arbitrary values one character at a time by making the app's visible behaviour depend on a single condition.**

Find an endpoint whose behaviour changes with the row count (e.g. a welcome-back banner). Then send AND SUBSTRING((SELECT ...),1,1) > 'm' and binary-search the character, confirming with an equality test, repeating per position. Use this when results and errors are hidden but some response attribute still varies with query outcome.

*Disproof:* If the application's behaviour is identical whether the condition is true or false, boolean extraction is impossible and time-based or OAST is required.

**Incrementing ORDER BY <n> until a response change appears infers the column count of the original query even when errors are suppressed.**

At a confirmed injection point send ' ORDER BY 1--, then 2, 3 and so on, comparing status, body length and content each time. The first index that changes behaviour marks the boundary. Cross-check with UNION SELECT NULL,... increments. Remember ORDER BY cannot take bind variables, so a sort-indicator parameter is a natural unparameterized injection surface.

*Disproof:* If every index from 1 upward yields an identical response, ORDER BY cannot be used for column counting and you must rely on UNION NULL probing.

**UNION SELECT NULL with increasing NULL counts finds the column count, then a string marker in each position finds a column type that can carry exfiltrated data.**

Send ' UNION SELECT NULL-- then with two, three and more NULLs, comparing responses for any change. Because NULL converts to every common type it succeeds on any matching column count. Then substitute a literal string like 'a' one column at a time; a type-conversion error marks that column as non-string, silence plus visible marker marks it usable.

*Disproof:* If the response is identical for wrong and correct NULL counts, the UNION column-count method is ineffective and you must use boolean or error-based inference.

## Variations

**WAFs that normalize, case-filter or over-clean requests can be bypassed by comment-splitting, mixed case, encoding and parameter pollution.**

When a clean payload is blocked but the endpoint is otherwise injectable, try un/**/ion se/**/lect, UnIoN SeLeCt, inline MySQL comments /*!50000UNION*/, percent-encoding of keywords, XML entity escapes, and splitting the payload across duplicated or separate parameters. Compare which variant reaches the DB by observing boolean differential behaviour rather than the WAF's verdict.

*Disproof:* If every encoded, case-varied and split variant is rejected identically and no differential response appears, the block is likely enforced downstream of the WAF, not by it.

## Technology / Framework Considerations

Not yet researched.

## API Considerations

Not yet researched.

## Attack Chains

- `sqli-boolean-oracle-to-row-count-enumeration` — sqli-boolean-oracle-to-row-count-enumeration (goal: `data_disclosure`)

## Real-World Examples

Not yet researched.

## Common False Positives

**A 500 or generic error page triggered by malformed input alone is not SQLi evidence; many apps error identically for any invalid value.**

Do not file a finding because a quote or a stray character returned 500. Establish a baseline with clearly invalid input such as a string where a number is expected, and check whether that also 500s. Only when a structurally valid injected condition changes behaviour while ordinary invalid input does not should the endpoint be treated as injectable.

*Disproof:* If plain type-mismatch input produces the identical 500 response with no SQL-specific text, the 500 is an input-validation artefact, not SQLi.

**Under a properly parameterized ORM/HQL query, quote and comment payloads are matched as literal data, so their failure to inject is a true negative, not a missed bug.**

Confirm the endpoint routes through the ORM's bound-parameter API rather than concatenated HQL or native SQL. If so, payloads like tom' or '1'='1 are searched for verbatim and produce zero rows or a type error - expected behaviour. Only reclassify as a finding when the ORM layer itself is version-vulnerable or the developer bypassed binding with string concatenation.

*Disproof:* If the ORM library has a known injection CVE for the deployed version, or raw concatenated queries appear in the code path, the negative result is invalid.
**Hypothesis:** A UNION SELECT payload is accepted because the response returns a different column count
- Invalidated by: The response differed for every column count including impossible ones, and the 'injected' values were already present in the page's own template - the difference was template rendering, not query execution
- **Rejection rule:** Before claiming UNION injection, grep the baseline response for the literal values you injected; a value already present in the template proves the response difference came from rendering, not the query

**Hypothesis:** An error-based payload exfiltrated database version information
- Invalidated by: The version string appears in the response headers of every page including ones with no injectable parameter, so it is server disclosure rather than something the injection returned
- **Rejection rule:** Before calling a value 'extracted by injection', grep other responses for it; a value the server already emits is information disclosure, a different finding with a different fix

**Hypothesis:** The WAF is bypassable because the payload with a comment marker returned HTTP 200
- Invalidated by: The 200 response contained no injected data and the same payload alternated between 200 and 403 across repeats, so the filter is probabilistic rather than bypassed
- **Rejection rule:** A filter bypass requires the bypassed request to return attacker-chosen data consistently; a status code that alternates across identical requests is filter noise, not a bypass

**Hypothesis:** The comment-terminated payload proves the input is concatenated rather than parameterised
- Invalidated by: A trailing '-- -' produced the same result as an empty value, which is the application's own trimming behaviour; the result change came from the value being empty, not from a comment being honoured
- **Rejection rule:** A comment marker only demonstrates concatenation if its effect differs from an empty value; identical results mean the marker is ordinary input, not a comment

**Hypothesis:** The endpoint is blind-injectable because a sleep payload measurably delays the response
- Invalidated by: The delay was not correlated with the payload: alternating requests showed the delay appearing on baselines too, and an unresolvable host produced a comparable timeout, so the latency is the network path
- **Rejection rule:** Timing-based injection requires repeated alternating samples showing the delay tracks the payload; one slow response against a network you have not baselined is a network event, not a finding

**Hypothesis:** The id parameter is injectable because numeric ids return different data than string ids
- Invalidated by: Any out-of-range value returns the same 400 regardless of quoting, and the message is a fixed application validation string with no database wording - the quote is rejected by type validation before any query
- **Rejection rule:** A validation error that is byte-identical for any invalid value indicates a type check, not a parser; a parser-specific error must name the construct that failed

**Hypothesis:** The ordering of results changes when a CASE expression is appended to the sort parameter
- Invalidated by: The two orderings also differed between two identical repeat requests, so the ordering is unstable for reasons unrelated to the injected expression - the key was not reaching a query
- **Rejection rule:** Ordering is only a valid injection signal when a repeated identical baseline request is byte-identical; unstable ordering means the parameter is not demonstrably reaching the query

**Hypothesis:** The search parameter is injectable because a single quote produces a database syntax error
- Invalidated by: The unquoted control request also returned HTTP 500, so the error is raised before the query is built - it comes from a missing query parameter or a template error, not from the quote reaching a parser
- **Rejection rule:** A 500 on a metacharacter proves nothing until the same request without the metacharacter returns 200; always capture an unquoted control response before attributing an error to injection

**Hypothesis:** A 500 or generic error page triggered by malformed input alone is not SQLi evidence; many apps error identically for any invalid value.
- Invalidated by: If plain type-mismatch input produces the identical 500 response with no SQL-specific text, the 500 is an input-validation artefact, not SQLi.
- **Rejection rule:** A 500 or generic error page triggered by malformed input alone is not SQLi evidence; many apps error identically for any invalid value.

**Hypothesis:** Under a properly parameterized ORM/HQL query, quote and comment payloads are matched as literal data, so their failure to inject is a true negative, not a missed bug.
- Invalidated by: If the ORM library has a known injection CVE for the deployed version, or raw concatenated queries appear in the code path, the negative result is invalid.
- **Rejection rule:** Under a properly parameterized ORM/HQL query, quote and comment payloads are matched as literal data, so their failure to inject is a true negative, not a missed bug.

## Validation

**A SQLi finding is only validated when one variable changes and the response difference is reproducible and explainable by query logic.**

For each candidate field, replay the true/false pair three times with all other parameters identical and diff status code, headers and body. Then confirm the difference is attributable to SQL by making it depend on a known condition (e.g. flipping a comparison reverses the outcome). Record raw request/response pairs as the validation artifact.

*Disproof:* If the difference is non-deterministic, cache- or session-driven, or does not reverse when the condition is inverted, it is not a validated SQLi.

**A verbose database error that echoes the constructed query turns blind injection visible and independently confirms the injection point's context.**

Inject a single quote and inspect status, body, and any JS/HTML comment for driver error text. If the response quotes your input inside a reconstructed statement, note whether the context is quoted or unquoted, then craft a payload that returns data directly through the error channel (e.g. CAST-based conversion errors). Treat absence of such leakage as a signal to use blind techniques.

*Disproof:* If the app returns a generic custom error page with no driver text and no reflected query fragment, error-based confirmation is unavailable.

## Impact

**A confirmed SQLi typically yields bulk read of application data and can subvert authentication, not just a single leaked record.**

Scope impact by what the DB account can reach: enumerate tables and columns, then attempt read of credential and PII tables, and separately test whether an authentication query can be subverted to return any row. Rate conclusions by the CWE-89 consequence classes actually demonstrated - confidentiality, authentication bypass, integrity - rather than by the injection primitive alone.

*Disproof:* If the DB account is restricted to read-only access to a single view and auth cannot be subverted, impact is bounded to the data in that view.

## Related Bug Classes

Not yet researched.

## References

- **cheatsheetseries.owasp.org** (standards_body)
  - <https://cheatsheetseries.owasp.org/cheatsheets/SQL_Injection_Prevention_Cheat_Sheet.html>
- **community.owasp.org** (standards_body)
  - <https://community.owasp.org/attacks/SQL_Injection_Bypassing_WAF>
- **cwe.mitre.org** (standards_body)
  - <https://cwe.mitre.org/data/definitions/89.html>
- **owasp.org** (standards_body)
  - <https://owasp.org/www-project-web-security-testing-guide/stable/4-Web_Application_Security_Testing/07-Input_Validation_Testing/05-Testing_for_SQL_Injection.html>
- **portswigger.net** (vendor_docs)
  - <https://portswigger.net/web-security/sql-injection>
  - <https://portswigger.net/web-security/sql-injection/blind>
  - <https://portswigger.net/web-security/sql-injection/union-attacks>
- **raw.githubusercontent.com** (standards_body)
  - <https://raw.githubusercontent.com/OWASP/wstg/master/document/4-Web_Application_Security_Testing/07-Injection/05-SQL_Injection.md>
  - <https://raw.githubusercontent.com/OWASP/wstg/master/document/4-Web_Application_Security_Testing/07-Injection/05.7-ORM_Injection.md>
  - <https://raw.githubusercontent.com/OWASP/wstg/v4.2/document/4-Web_Application_Security_Testing/07-Input_Validation_Testing/05-Testing_for_SQL_Injection.md>

Every item above is gated on >= 2 distinct publisher hosts (`wks/quality.py`, rule R1). Publisher diversity, not citation count, is what makes these corroborated.
