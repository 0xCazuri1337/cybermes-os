# Methodology — SQL Injection

> Derived from 17 verified items. Regenerate with `python -m wks.methodgen --class sqli --apply`. Do not hand-edit: this file is a projection of the evidence, and edits are lost on the next cycle.

**Surface.** Attacker-controlled input is concatenated into a SQL statement, so the query structure becomes attacker-controlled.

**References.** CWE-89 · A03:2021

## 1. Preconditions

_Nothing below is reachable until these hold. Confirm each against the target before spending time on the technique._

**Any request-controllable value that reaches a SQL query is a candidate injection point, including JSON/XML bodies, cookies and headers, not just GET parameters.**

Before probing, enumerate every input field including hidden POST fields, cookies and HTTP headers, then test each separately. For each field send a distinctive marker and observe whether it is reflected, stored, or changes database-driven output. Record which field maps to a quoted string vs a numeric context, since that determines the payload shape.

- *Disproof:* If a field's value is provably never used in any query (e.g. purely client-side sorting or CSRF tokens), it cannot be an injection point.
- *Evidence:* high_confidence — [portswigger.net](https://portswigger.net/web-security/sql-injection); [raw.githubusercontent.com](https://raw.githubusercontent.com/OWASP/wstg/master/document/4-Web_Application_Security_Testing/07-Injection/05-SQL_Injection.md)

**Prepared/parameterized statements force the DB to separate code from data, so bind-variable queries are the baseline you must establish before treating quote errors as SQLi.**

Identify per endpoint whether the framework uses bound parameters (JDBC PreparedStatement, ORM positional/named params) or string concatenation. Where a bind variable is used, inject metacharacters and expect them to be compared literally. Where concatenation is used, expect structural breakage. This distinction is what separates a real finding from a benign type-conversion error.

- *Disproof:* If the query string is built by concatenation at runtime even when a parameterized API exists elsewhere, the endpoint is not parameterized.
- *Evidence:* high_confidence — [cheatsheetseries.owasp.org](https://cheatsheetseries.owasp.org/cheatsheets/SQL_Injection_Prevention_Cheat_Sheet.html); [cwe.mitre.org](https://cwe.mitre.org/data/definitions/89.html)

## 2. Reconnaissance signals

_What to look for while mapping the surface, and where each signal tells you the rest of the procedure is worth running._

**If the app neither returns query results nor error differences nor timing changes, the query may run asynchronously; absence of in-band signal does not mean absence of SQLi.**

Test a cookie or header parameter that the app processes in a background thread. When in-band booleans, errors and timing all read flat, switch to OAST: send a payload that triggers a DNS lookup to a controlled domain and poll for the interaction. Also try a conditional time delay as a cross-check before concluding the parameter is clean.

- *Disproof:* If an OAST payload produces no collaborator/DNS callback and conditional time delays stay within baseline jitter, the parameter is very likely not injectable.
- *Evidence:* high_confidence — [owasp.org](https://owasp.org/www-project-web-security-testing-guide/stable/4-Web_Application_Security_Testing/07-Input_Validation_Testing/05-Testing_for_SQL_Injection.html); [portswigger.net](https://portswigger.net/web-security/sql-injection/blind); [raw.githubusercontent.com](https://raw.githubusercontent.com/OWASP/wstg/v4.2/document/4-Web_Application_Security_Testing/07-Input_Validation_Testing/05-Testing_for_SQL_Injection.md)

**A single quote or a paired OR 1=1 / OR 1=2 pair producing a repeatable response difference is the primary first-order SQLi signal.**

Send a lone quote or semicolon to each field and note errors. Then send a condition that should be true (OR 1=1) and its near-identical false twin (OR 1=2) with everything else held constant. A repeatable difference between the twins, not merely an error, is the signal worth escalating; capture raw response length, status and body hashes for both.

- *Disproof:* If the quote and both boolean twins produce byte-identical responses, the field shows no first-order SQLi signal.
- *Evidence:* high_confidence — [portswigger.net](https://portswigger.net/web-security/sql-injection); [raw.githubusercontent.com](https://raw.githubusercontent.com/OWASP/wstg/master/document/4-Web_Application_Security_Testing/07-Injection/05-SQL_Injection.md)

## 3. Test sequence

_Concrete mutations to try. Each is written to be executable, not to be a description of the vulnerability._

**Blind boolean injection extracts arbitrary values one character at a time by making the app's visible behaviour depend on a single condition.**

Find an endpoint whose behaviour changes with the row count (e.g. a welcome-back banner). Then send AND SUBSTRING((SELECT ...),1,1) > 'm' and binary-search the character, confirming with an equality test, repeating per position. Use this when results and errors are hidden but some response attribute still varies with query outcome.

- *Disproof:* If the application's behaviour is identical whether the condition is true or false, boolean extraction is impossible and time-based or OAST is required.
- *Evidence:* high_confidence — [owasp.org](https://owasp.org/www-project-web-security-testing-guide/stable/4-Web_Application_Security_Testing/07-Input_Validation_Testing/05-Testing_for_SQL_Injection.html); [portswigger.net](https://portswigger.net/web-security/sql-injection/blind); [raw.githubusercontent.com](https://raw.githubusercontent.com/OWASP/wstg/v4.2/document/4-Web_Application_Security_Testing/07-Input_Validation_Testing/05-Testing_for_SQL_Injection.md)

**Incrementing ORDER BY <n> until a response change appears infers the column count of the original query even when errors are suppressed.**

At a confirmed injection point send ' ORDER BY 1--, then 2, 3 and so on, comparing status, body length and content each time. The first index that changes behaviour marks the boundary. Cross-check with UNION SELECT NULL,... increments. Remember ORDER BY cannot take bind variables, so a sort-indicator parameter is a natural unparameterized injection surface.

- *Disproof:* If every index from 1 upward yields an identical response, ORDER BY cannot be used for column counting and you must rely on UNION NULL probing.
- *Evidence:* high_confidence — [cheatsheetseries.owasp.org](https://cheatsheetseries.owasp.org/cheatsheets/SQL_Injection_Prevention_Cheat_Sheet.html); [portswigger.net](https://portswigger.net/web-security/sql-injection/union-attacks)

**UNION SELECT NULL with increasing NULL counts finds the column count, then a string marker in each position finds a column type that can carry exfiltrated data.**

Send ' UNION SELECT NULL-- then with two, three and more NULLs, comparing responses for any change. Because NULL converts to every common type it succeeds on any matching column count. Then substitute a literal string like 'a' one column at a time; a type-conversion error marks that column as non-string, silence plus visible marker marks it usable.

- *Disproof:* If the response is identical for wrong and correct NULL counts, the UNION column-count method is ineffective and you must use boolean or error-based inference.
- *Evidence:* high_confidence — [portswigger.net](https://portswigger.net/web-security/sql-injection/union-attacks); [raw.githubusercontent.com](https://raw.githubusercontent.com/OWASP/wstg/master/document/4-Web_Application_Security_Testing/07-Injection/05-SQL_Injection.md)

**For example, consider using persistence layers such as Hibernate or Enterprise Java Beans, which can provide significant protection against SQL injection if used properly.**

even delete this information with a SQL injection attack. 
 
 
 
 
 
 
 
 
 

 

 
 
 
 
 Potential Mitigations 
 
 
 
 
 
 
 Phase(s) 
 Mitigation 
 
 
 
 
 
 
 
 Architecture and Design 
 
 
 
 
 
 
 Strategy: Libraries or Frameworks 
 
 
 
 Use a vetted library or framework that does not allow this weakness to occur or provides constructs that make this weakness easier to avoid [ REF-1482 ]. 
 For example, consider using persistence layers such as Hibernate or Enterprise Java Beans, which can provide significant protection against SQL injection if used properly. 
 
 
 
 
 
 
 
 
 
 
 Architecture and Design 
 
 
 
 
 
 
 Strategy: Parameterization 
 
 
 
 If available, use structured mechanisms that automatically enforce the separation between data and code. These mechanisms may be able to provide the relevant quoting, encoding, and validation automatically, instead of relying on the developer to provide this capability at every point where output is gen

- *Disproof:* This is refuted if an authoritative source shows the described behaviour does not occur, does not grant access, or is already prevented by default framework configuration: "For example, consider using persistence layers such as Hibernate or Enterprise Java Beans,".
- *Evidence:* high_confidence — [cwe.mitre.org](https://cwe.mitre.org/data/definitions/89.html); [owasp.org](https://owasp.org/www-community/attacks/SQL_Injection)

**Input validation will not always prevent SQL injection, especially if you are required to support free-form text fields that could contain arbitrary characters.**

rameter in the request. This will indirectly limit the scope of an attack, but this technique is less important than proper output encoding and escaping. 
 Note that proper output encoding, escaping, and quoting is the most effective solution for preventing SQL injection, although input validation may provide some defense-in-depth. This is because it effectively limits what will appear in output. Input validation will not always prevent SQL injection, especially if you are required to support free-form text fields that could contain arbitrary characters. For example, the name "O'Reilly" would likely pass the validation step, since it is a common last name in the English language. However, it cannot be directly inserted into the database because it contains the "'" apostrophe character, which would need to be escaped or otherwise handled. In this case, stripping the apostrophe might reduce the risk of SQL injection, but it would produce incorrect

- *Disproof:* This is refuted if an authoritative source shows the described behaviour does not occur, does not grant access, or is already prevented by default framework configuration: "Input validation will not always prevent SQL injection, especially if you are required to ".
- *Evidence:* high_confidence — [cwe.mitre.org](https://cwe.mitre.org/data/definitions/89.html); [owasp.org](https://owasp.org/www-community/attacks/SQL_Injection)

**If authorization information is held in a SQL database, it may be possible to change this information through the successful exploitation of a SQL injection vulnerability.**

ileges or Assume Identity; Bypass Protection Mechanism 
 
 
 
 
 
 
 Scope: Authentication 
 
 
 
 If poor SQL commands are used to check user names and passwords or perform other kinds of authentication, it may be possible to connect to the product as another user with no previous knowledge of the password. 
 
 
 
 
 
 
 
 
 Bypass Protection Mechanism 
 
 
 
 
 
 
 Scope: Access Control 
 
 
 
 If authorization information is held in a SQL database, it may be possible to change this information through the successful exploitation of a SQL injection vulnerability. 
 
 
 
 
 
 
 
 
 Modify Application Data 
 
 
 
 
 
 
 Scope: Integrity 
 
 
 
 Just as it may be possible to read sensitive information, it is also possible to modify or even delete this information with a SQL injection attack. 
 
 
 
 
 
 
 
 
 

 

 
 
 
 
 Potential Mitigations 
 
 
 
 
 
 
 Phase(s) 
 Mitigation 
 
 
 
 
 
 
 
 Architecture and Design 
 
 
 
 
 
 
 Strategy: Libraries or Fr

- *Disproof:* This is refuted if an authoritative source shows the described behaviour does not occur, does not grant access, or is already prevented by default framework configuration: "If authorization information is held in a SQL database, it may be possible to change this ".
- *Evidence:* high_confidence — [cwe.mitre.org](https://cwe.mitre.org/data/definitions/89.html); [owasp.org](https://owasp.org/www-community/attacks/SQL_Injection)

## 4. Validation

_How to prove the finding rather than infer it. A technique that cannot be validated must not be reported._

**A SQLi finding is only validated when one variable changes and the response difference is reproducible and explainable by query logic.**

For each candidate field, replay the true/false pair three times with all other parameters identical and diff status code, headers and body. Then confirm the difference is attributable to SQL by making it depend on a known condition (e.g. flipping a comparison reverses the outcome). Record raw request/response pairs as the validation artifact.

- *Disproof:* If the difference is non-deterministic, cache- or session-driven, or does not reverse when the condition is inverted, it is not a validated SQLi.
- *Evidence:* high_confidence — [owasp.org](https://owasp.org/www-project-web-security-testing-guide/stable/4-Web_Application_Security_Testing/07-Input_Validation_Testing/05-Testing_for_SQL_Injection.html); [portswigger.net](https://portswigger.net/web-security/sql-injection/blind); [raw.githubusercontent.com](https://raw.githubusercontent.com/OWASP/wstg/v4.2/document/4-Web_Application_Security_Testing/07-Input_Validation_Testing/05-Testing_for_SQL_Injection.md)

**A verbose database error that echoes the constructed query turns blind injection visible and independently confirms the injection point's context.**

Inject a single quote and inspect status, body, and any JS/HTML comment for driver error text. If the response quotes your input inside a reconstructed statement, note whether the context is quoted or unquoted, then craft a payload that returns data directly through the error channel (e.g. CAST-based conversion errors). Treat absence of such leakage as a signal to use blind techniques.

- *Disproof:* If the app returns a generic custom error page with no driver text and no reflected query fragment, error-based confirmation is unavailable.
- *Evidence:* high_confidence — [cwe.mitre.org](https://cwe.mitre.org/data/definitions/89.html); [portswigger.net](https://portswigger.net/web-security/sql-injection/blind)

## 5. False-positive rejection

_The checks that eliminate the most common non-findings. Run these BEFORE reporting, not after a rejection._

**Under a properly parameterized ORM/HQL query, quote and comment payloads are matched as literal data, so their failure to inject is a true negative, not a missed bug.**

Confirm the endpoint routes through the ORM's bound-parameter API rather than concatenated HQL or native SQL. If so, payloads like tom' or '1'='1 are searched for verbatim and produce zero rows or a type error - expected behaviour. Only reclassify as a finding when the ORM layer itself is version-vulnerable or the developer bypassed binding with string concatenation.

- *Disproof:* If the ORM library has a known injection CVE for the deployed version, or raw concatenated queries appear in the code path, the negative result is invalid.
- *Evidence:* high_confidence — [cheatsheetseries.owasp.org](https://cheatsheetseries.owasp.org/cheatsheets/SQL_Injection_Prevention_Cheat_Sheet.html); [cwe.mitre.org](https://cwe.mitre.org/data/definitions/89.html); [raw.githubusercontent.com](https://raw.githubusercontent.com/OWASP/wstg/master/document/4-Web_Application_Security_Testing/07-Injection/05.7-ORM_Injection.md)

**A 500 or generic error page triggered by malformed input alone is not SQLi evidence; many apps error identically for any invalid value.**

Do not file a finding because a quote or a stray character returned 500. Establish a baseline with clearly invalid input such as a string where a number is expected, and check whether that also 500s. Only when a structurally valid injected condition changes behaviour while ordinary invalid input does not should the endpoint be treated as injectable.

- *Disproof:* If plain type-mismatch input produces the identical 500 response with no SQL-specific text, the 500 is an input-validation artefact, not SQLi.
- *Evidence:* high_confidence — [portswigger.net](https://portswigger.net/web-security/sql-injection/blind); [raw.githubusercontent.com](https://raw.githubusercontent.com/OWASP/wstg/master/document/4-Web_Application_Security_Testing/07-Injection/05-SQL_Injection.md)

## 6. Known bypasses

_Filters and controls that have defeated the techniques above. Treat these as the reason a naive test fails, not as proof of safety._

**WAFs that normalize, case-filter or over-clean requests can be bypassed by comment-splitting, mixed case, encoding and parameter pollution.**

When a clean payload is blocked but the endpoint is otherwise injectable, try un/**/ion se/**/lect, UnIoN SeLeCt, inline MySQL comments /*!50000UNION*/, percent-encoding of keywords, XML entity escapes, and splitting the payload across duplicated or separate parameters. Compare which variant reaches the DB by observing boolean differential behaviour rather than the WAF's verdict.

- *Disproof:* If every encoded, case-varied and split variant is rejected identically and no differential response appears, the block is likely enforced downstream of the WAF, not by it.
- *Evidence:* high_confidence — [community.owasp.org](https://community.owasp.org/attacks/SQL_Injection_Bypassing_WAF); [portswigger.net](https://portswigger.net/web-security/sql-injection)

## 7. Chaining

_How this class escalates when combined with others. Each step is anchored to a promoted item._

**Data written safely by one request can become injectable when a later request concatenates the stored value into a new query.**

Plant a payload in any user-writable field that persists (profile name, comment, uploaded filename, order note), then find every later screen or background job that reads that column into a query. Test by storing a unique marker per field and searching for it in downstream behaviour, especially ORDER BY/sort and report paths that cannot use bind variables.

- *Disproof:* If the stored payload is only ever read back through parameterized queries and never concatenated, the flow is not second-order injectable.
- *Evidence:* high_confidence — [cwe.mitre.org](https://cwe.mitre.org/data/definitions/89.html); [portswigger.net](https://portswigger.net/web-security/sql-injection)

## 8. Impact

_What is actually demonstrable, and what to stop claiming._

**A confirmed SQLi typically yields bulk read of application data and can subvert authentication, not just a single leaked record.**

Scope impact by what the DB account can reach: enumerate tables and columns, then attempt read of credential and PII tables, and separately test whether an authentication query can be subverted to return any row. Rate conclusions by the CWE-89 consequence classes actually demonstrated - confidentiality, authentication bypass, integrity - rather than by the injection primitive alone.

- *Disproof:* If the DB account is restricted to read-only access to a single view and auth cannot be subverted, impact is bounded to the data in that view.
- *Evidence:* high_confidence — [cwe.mitre.org](https://cwe.mitre.org/data/definitions/89.html); [portswigger.net](https://portswigger.net/web-security/sql-injection)

---

*Generated from the evidence base. Where this file and the database disagree, the database is correct.*
