<!-- GENERATED from db/wks.db — do not edit -->
# SQL Injection

> surface: `web` · CWE: CWE-89 · OWASP: A03:2021
> maturity: **mature** — 45 items, 34 supported, 12 FP rules, 1 chains

Attacker-controlled input is concatenated into a SQL statement, so the query structure becomes attacker-controlled.

**Aliases:** sql injection, sqli, second order sql injection, nosql injection operator

## Prerequisite

- **Any request-controllable value that reaches a SQL query is a candidate injection point, including JSON/XML bodies, cookies and headers, not just GET parameters.**  
  `high_confidence` · score 0.908 · disproved by: If a field's value is provably never used in any query (e.g. purely client-side sorting or CSRF tokens), it cannot be an injection point.
  sources: <https://raw.githubusercontent.com/OWASP/wstg/master/document/4-Web_Application_Security_Testing/07-Injection/05-SQL_Injection.md> · <https://portswigger.net/web-security/sql-injection>
- **Prepared/parameterized statements force the DB to separate code from data, so bind-variable queries are the baseline you must establish before treating quote errors as SQLi.**  
  `high_confidence` · score 0.908 · disproved by: If the query string is built by concatenation at runtime even when a parameterized API exists elsewhere, the endpoint is not parameterized.
  sources: <https://cheatsheetseries.owasp.org/cheatsheets/SQL_Injection_Prevention_Cheat_Sheet.html> · <https://cwe.mitre.org/data/definitions/89.html>
- **Extraction on MS Access is gated on naming a real column such as username, so the guess-and-check step on column names comes before any value can be pulled out of the database through the injection.**  
  `high_confidence` · score 0.808 · disproved by: Reading a value out of MS Access with no valid column name in the injected query, or a fabricated column name returning data, refutes this ordering.
  sources: <https://sqlite.org/lang_expr.html> · <https://raw.githubusercontent.com/HackTricks-wiki/hacktricks/master/src/pentesting-web/sql-injection/ms-access-sql-injection.md>

## Signal

- **If the app neither returns query results nor error differences nor timing changes, the query may run asynchronously; absence of in-band signal does not mean absence of SQLi.**  
  `high_confidence` · score 0.8965 · disproved by: If an OAST payload produces no collaborator/DNS callback and conditional time delays stay within baseline jitter, the parameter is very likely not injectable.
  sources: <https://owasp.org/www-project-web-security-testing-guide/stable/4-Web_Application_Security_Testing/07-Input_Validation_Testing/05-Testing_for_SQL_Injection.html> · <https://raw.githubusercontent.com/OWASP/wstg/v4.2/document/4-Web_Application_Security_Testing/07-Input_Validation_Testing/05-Testing_for_SQL_Injection.md> · <https://portswigger.net/web-security/sql-injection/blind>
- **A single quote or a paired OR 1=1 / OR 1=2 pair producing a repeatable response difference is the primary first-order SQLi signal.**  
  `high_confidence` · score 0.8255 · disproved by: If the quote and both boolean twins produce byte-identical responses, the field shows no first-order SQLi signal.
  sources: <https://raw.githubusercontent.com/OWASP/wstg/master/document/4-Web_Application_Security_Testing/07-Injection/05-SQL_Injection.md> · <https://portswigger.net/web-security/sql-injection>

## Technique

- **A UNION-based SQL injection is confirmed by matching the result-set column count through successively longer runs of NULL placeholders, and NULL is used as the filler because it type-checks in any column position and so maximises the chance the payload succeeds.**  
  `high_confidence` · score 0.8815 · disproved by: If no NULL-counted payload ever produces the extra result set or alters the response, the column count was never matched and the UNION injection is not demonstrated.
  sources: <https://cwe.mitre.org/data/definitions/89.html> · <https://docs.djangoproject.com/en/5.0/topics/db/sql/> · <https://kathan19.gitbook.io/howtohunt/sqli/sql_injection.md>
- **Blind boolean injection extracts arbitrary values one character at a time by making the app's visible behaviour depend on a single condition.**  
  `high_confidence` · score 0.869 · disproved by: If the application's behaviour is identical whether the condition is true or false, boolean extraction is impossible and time-based or OAST is required.
  sources: <https://owasp.org/www-project-web-security-testing-guide/stable/4-Web_Application_Security_Testing/07-Input_Validation_Testing/05-Testing_for_SQL_Injection.html> · <https://raw.githubusercontent.com/OWASP/wstg/v4.2/document/4-Web_Application_Security_Testing/07-Input_Validation_Testing/05-Testing_for_SQL_Injection.md> · <https://portswigger.net/web-security/sql-injection/blind>
- **Incrementing ORDER BY <n> until a response change appears infers the column count of the original query even when errors are suppressed.**  
  `high_confidence` · score 0.853 · disproved by: If every index from 1 upward yields an identical response, ORDER BY cannot be used for column counting and you must rely on UNION NULL probing.
  sources: <https://cheatsheetseries.owasp.org/cheatsheets/SQL_Injection_Prevention_Cheat_Sheet.html> · <https://portswigger.net/web-security/sql-injection/union-attacks>
- **SQL injection is confirmed by a boolean differential: a condition that is always true returns the normal row count while the same condition forced false returns a different one.**  
  `high_confidence` · score 0.843 · disproved by: Refuted when the application returns an identical response for true and false conditions, which indicates the value is escaped, parameterised, or never reaches a SQL parser.
  sources: <https://owasp.org/www-community/attacks/SQL_Injection> · <https://portswigger.net/web-security/sql-injection> · <https://raw.githubusercontent.com/Esther7171/HackTheBox-Writeups-Walkthroughs/main/Write-ups/Academy/05.%20Web%20Exploitation/25.%20SQL%20Injection%20Fundamentals/SQL%20Injection%20Fundamentals.md> · <https://raw.githubusercontent.com/ajcriado/htb-writeups/main/Academy/CPTS/Content%20Summary/17.%20SQL%20Injection%20Fundamentals.md>
- **A UNION-based SQL injection is confirmed by matching the number of columns in the injected result set against the original query using successive NULL placeholders, then selecting data from other tables.**  
  `high_confidence` · score 0.8305 · disproved by: The claim is false when the original query always returns a fixed number of columns unrelated to the injection point, when the database does not expose the metadata used (a closed source or heavily restricted RDBMS), or when the response is identical across every NULL-count probe, which proves no UNION result set reached the output.
  sources: <https://portswigger.net/web-security/sql-injection/union-based> · <https://www.w3schools.com/sql/sql_union.asp>
- **UNION SELECT NULL with increasing NULL counts finds the column count, then a string marker in each position finds a column type that can carry exfiltrated data.**  
  `high_confidence` · score 0.8255 · disproved by: If the response is identical for wrong and correct NULL counts, the UNION column-count method is ineffective and you must use boolean or error-based inference.
  sources: <https://raw.githubusercontent.com/OWASP/wstg/master/document/4-Web_Application_Security_Testing/07-Injection/05-SQL_Injection.md> · <https://portswigger.net/web-security/sql-injection/union-attacks>
- **Error-based SQL injection extracts data by triggering database error messages that echo the injected value or the attacked metadata, and is confirmed when an error response reveals a table, column, or value that was not present in the baseline.**  
  `high_confidence` · score 0.817 · disproved by: The claim is false when the error message only reports a syntax or constraint violation with no embedded target value, or when the same error appears before any injection is attempted, which means the message is a framework default rather than a data channel. If the value only ever appears in the application's own echoed input and never in a database error, the finding is verbose errors, not error-based injection.
  sources: <https://cheatsheetseries.owasp.org/cheatsheets/SQL_Injection_Prevention_Cheat_Sheet.html> · <https://portswigger.net/web-security/sql-injection/blind>
- **Inside an injected MS Access query, TOP and LAST act as row selectors, so the tester can cap or reverse the result set and page out a table's records instead of dumping it whole.**  
  `high_confidence` · score 0.808 · disproved by: TOP or LAST modifiers rejected as syntax by the same injection point, or accepted but leaving the returned rows unchanged, refute their use as row-selection controls.
  sources: <https://sqlite.org/lang_expr.html> · <https://raw.githubusercontent.com/HackTricks-wiki/hacktricks/master/src/pentesting-web/sql-injection/ms-access-sql-injection.md>
- **For example, consider using persistence layers such as Hibernate or Enterprise Java Beans, which can provide significant protection against SQL injection if used properly.**  
  `high_confidence` · score 0.8055 · disproved by: Refuted when: the value is bound as a parameter or written through the framework's own encoder, so the interpreter never sees attacker text as syntax. Settle it by running the identical request with and without that one control and diffing the response -- if the difference the claim predicts does not appear, the claim is false. Specifically, this is refuted if the behaviour described (“For example, consider using persistence layers such as Hibernate or Enterprise J”) does not occur under a test that isolates that control.
  sources: <https://cwe.mitre.org/data/definitions/89.html> · <https://owasp.org/www-community/attacks/SQL_Injection>
- **Input validation will not always prevent SQL injection, especially if you are required to support free-form text fields that could contain arbitrary characters.**  
  `high_confidence` · score 0.8055 · disproved by: Refuted when: the value is bound as a parameter or written through the framework's own encoder, so the interpreter never sees attacker text as syntax. Settle it by running the identical request with and without that one control and diffing the response -- if the difference the claim predicts does not appear, the claim is false. Specifically, this is refuted if the behaviour described (“Input validation will not always prevent SQL injection, especially if you are re”) does not occur under a test that isolates that control.
  sources: <https://cwe.mitre.org/data/definitions/89.html> · <https://owasp.org/www-community/attacks/SQL_Injection>
- **Once a UNION SELECT column count is aligned, the tester can read a chosen position out of a table with a wildcard select and never has to know the column's name, which is how data leaves the database once the injection point is confirmed.**  
  `high_confidence` · score 0.798 · disproved by: A wildcard select that returns nothing from a table known to be readable, or one that fails purely on a column-count mismatch, refutes the positional-access claim.
  sources: <https://cwe.mitre.org/data/definitions/89.html> · <https://raw.githubusercontent.com/HackTricks-wiki/hacktricks/master/src/pentesting-web/sql-injection/README.md>
- **MySQL schema and table names come out of a UNION SELECT with GROUP_CONCAT over information_schema, and the alternating letter case of the quoted keywords is the point: the enumeration has to be sent in mixed case so a filter matching keywords in one fixed case does not stop it.**  
  `high_confidence` · score 0.798 · disproved by: A filter that blocks the mixed-case spelling while letting the all-lowercase form through, or a UNION SELECT that returns no schema rows despite a working injection point, refutes this enumeration route.
  sources: <https://cheatsheetseries.owasp.org/cheatsheets/SQL_Injection_Prevention_Cheat_Sheet.html> · <https://raw.githubusercontent.com/HackTricks-wiki/hacktricks/master/src/pentesting-web/sql-injection/mysql-injection/README.md>
- **Naming a target table turns the same UNION SELECT pattern into a column dictionary, so the tester moves from which tables exist to exactly which attributes the injected query can reference.**  
  `high_confidence` · score 0.798 · disproved by: The column enumeration coming back empty for a table that the same injection point can already read rows from refutes this metadata route.
  sources: <https://cheatsheetseries.owasp.org/cheatsheets/SQL_Injection_Prevention_Cheat_Sheet.html> · <https://raw.githubusercontent.com/HackTricks-wiki/hacktricks/master/src/pentesting-web/sql-injection/mysql-injection/README.md>
- **An MSSQL injection point doubles as a privilege-reach probe: calling fn_my_permissions against the database and filtering on a named permission tells the tester which database-level grants the injected session actually holds before they plan any escalation.**  
  `high_confidence` · score 0.7955 · disproved by: fn_my_permissions returning no rows, or an empty grant set, for a login that demonstrably holds the named database permission refutes it as a reach check.
  sources: <https://portswigger.net/web-security/sql-injection> · <https://raw.githubusercontent.com/HackTricks-wiki/hacktricks/master/src/pentesting-web/sql-injection/mssql-injection.md>
- **If authorization information is held in a SQL database, it may be possible to change this information through the successful exploitation of a SQL injection vulnerability.**  
  `high_confidence` · score 0.778 · disproved by: Refuted when: the value is bound as a parameter or written through the framework's own encoder, so the interpreter never sees attacker text as syntax. Settle it by running the identical request with and without that one control and diffing the response -- if the difference the claim predicts does not appear, the claim is false. Specifically, this is refuted if the behaviour described (“If authorization information is held in a SQL database, it may be possible to ch”) does not occur under a test that isolates that control.
  sources: <https://cwe.mitre.org/data/definitions/89.html> · <https://owasp.org/www-community/attacks/SQL_Injection>
- **On MSSQL a single injected UNION SELECT over information_schema.columns hands back the schema, table and column names of the current database at once, and on error-based vectors every selected expression has to carry an alias or the query will not come back.**  
  `high_confidence` · score 0.768 · disproved by: An error-based injected select that errors purely because an expression lacks an alias, or a schema enumeration that returns no rows despite a working injection point, refutes these requirements.
  sources: <https://portswigger.net/web-security/sql-injection> · <https://raw.githubusercontent.com/HackTricks-wiki/hacktricks/master/src/pentesting-web/sql-injection/mssql-injection.md>

## Test

- **When a blind SQL injection returns no data, the proof is made of timing: concatenate a deliberately slow operation into the SQL query and look for a repeatable jump in page-load time that the unmodified request does not show.**  
  `high_confidence` · score 0.8255 · disproved by: A concatenated slow operation that leaves page-load time flat, or a delay that appears just as often on a control request carrying no injected syntax, refutes it as a blind SQL injection oracle.
  sources: <https://cwe.mitre.org/data/definitions/89.html> · <https://raw.githubusercontent.com/HackTricks-wiki/hacktricks/master/src/pentesting-web/sql-injection/README.md>
- **MS Access hands the tester a file-existence oracle from inside the injection: point the database reference at a local file and the invalid-database-format error appears only when that file is really there, so file enumeration is driven by comparing errors across candidate paths.**  
  `high_confidence` · score 0.808 · disproved by: The invalid-format error appearing identically for names that do not exist, or never appearing for one that does, refutes the existence oracle.
  sources: <https://sqlite.org/lang_expr.html> · <https://raw.githubusercontent.com/HackTricks-wiki/hacktricks/master/src/pentesting-web/sql-injection/ms-access-sql-injection.md>
- **On MSSQL the tester can read the live query text back through sys.dm_exec_requests joined to sys.dm_exec_sql_text, which is the way to confirm the injection really landed in the query and to see the surrounding SQL, with the server-level permission checked separately.**  
  `high_confidence` · score 0.7955 · disproved by: The DMVs returning nothing, or returning a query that does not contain the injected syntax, refutes their use for reading back the currently executing SQL query.
  sources: <https://portswigger.net/web-security/sql-injection> · <https://raw.githubusercontent.com/HackTricks-wiki/hacktricks/master/src/pentesting-web/sql-injection/mssql-injection.md>

## Validation

- **A boolean or time differential found while several parameters are being varied at once is not attributable to any of them, so the finding is only valid once the same differential reproduces with exactly one variable changed.**  
  `high_confidence` · score 0.918 · disproved by: The rule is a testing discipline, not a property of the vulnerability, so it is false as a statement about what constitutes a finding in cases where a different kind of evidence is available: an out-of-band callback from a payload that could only have been assembled by the database is attributable regardless of how many other parameters were in the request, because the callback proves the injected expression executed. It is also false where the endpoint exposes the generated SQL - a debug echo, a query log, an error page printing the statement - since the statement text itself settles where the value landed. And a differential can be attributable without single-variable isolation when the other parameters are held constant by construction, for example by fixing them from a captured baseline and varying only the target.
  sources: <https://docs.djangoproject.com/en/5.0/topics/db/sql/> · <https://sqlite.org/lang_expr.html>
- **In a full-text search parameter the attacker-controlled text is a query language, not a string literal, so single-quote and UNION payloads test nothing and the injection point is the operator's own grammar.**  
  `high_confidence` · score 0.893 · disproved by: The claim is false when the value is quoted or escaped before reaching the operator's parser - a driver or API that treats the operand as an opaque string and escapes the operator's metacharacters removes the grammar surface entirely, in which case the standard payload is again the right one. It is also false as a claim of vulnerability: the mere existence of a rich query language in a search box is not a finding, and FTS5's own syntax is deliberately non-SQL, so a payload that changes match results is a search-behaviour quirk rather than SQL injection. The finding needs the grammar surface to reach a SQL-executing construct - for example an FTS expression that a trigger, a view, or an auxiliary function expands into further SQL - and that chain has to be demonstrated.
  sources: <https://sqlite.org/fts5.html> · <https://www.postgresql.org/docs/current/sql-syntax-lexical.html>
- **A verbose database error that echoes the constructed query turns blind injection visible and independently confirms the injection point's context.**  
  `high_confidence` · score 0.853 · disproved by: If the app returns a generic custom error page with no driver text and no reflected query fragment, error-based confirmation is unavailable.
  sources: <https://cwe.mitre.org/data/definitions/89.html> · <https://portswigger.net/web-security/sql-injection/blind>

## Fp Rule

- **Under a properly parameterized ORM/HQL query, quote and comment payloads are matched as literal data, so their failure to inject is a true negative, not a missed bug.**  
  `high_confidence` · score 0.8965 · disproved by: If the ORM library has a known injection CVE for the deployed version, or raw concatenated queries appear in the code path, the negative result is invalid.
  sources: <https://cheatsheetseries.owasp.org/cheatsheets/SQL_Injection_Prevention_Cheat_Sheet.html> · <https://cwe.mitre.org/data/definitions/89.html> · <https://raw.githubusercontent.com/OWASP/wstg/master/document/4-Web_Application_Security_Testing/07-Injection/05.7-ORM_Injection.md>
- **A dollar-quoted string in PostgreSQL is a closed literal that ignores backslashes and dollar signs, so a payload containing $tag$ delimiters only becomes dangerous if the attacker can supply the tag the application's own quoting chose.**  
  `high_confidence` · score 0.8355 · disproved by: The claim is false when the tag is attacker-controlled or absent in a way that lets the payload close the literal - an unquoted dollar-quoted string in a function definition whose body is built from user input lets an attacker insert their own $q$...$q$ and terminate it, and PostgreSQL's own example of a nested $q$[\t\r\n\v\\]$q$ inside $function$ ... $function$ shows exactly that shape. It also fails if the payload is delivered outside the dollar-quoted region - a second statement concatenated after the function body, or a value reaching a non-dollar-quoted parameter such as a dynamic EXECUTE string, is ordinary SQL and the standard payloads apply.
  sources: <https://docs.djangoproject.com/en/5.0/topics/db/sql/> · <https://www.postgresql.org/docs/current/sql-syntax-lexical.html>

## Impact

- **A confirmed SQLi typically yields bulk read of application data and can subvert authentication, not just a single leaked record.**  
  `high_confidence` · score 0.798 · disproved by: If the DB account is restricted to read-only access to a single view and auth cannot be subverted, impact is bounded to the data in that view.
  sources: <https://cwe.mitre.org/data/definitions/89.html> · <https://portswigger.net/web-security/sql-injection>

## Variant

- **A search box wired into a full-text MATCH ... AGAINST clause in boolean mode is its own injection flavour: the search term is concatenated inside the quoted argument, so the tester should probe the quote and the boolean-mode operators rather than a plain WHERE value.**  
  `high_confidence` · score 0.8255 · disproved by: A search parameter concatenated into that MATCH clause that can neither break out of the quotes nor change the boolean-mode search, refutes it as an injection point.
  sources: <https://cheatsheetseries.owasp.org/cheatsheets/SQL_Injection_Prevention_Cheat_Sheet.html> · <https://raw.githubusercontent.com/HackTricks-wiki/hacktricks/master/src/pentesting-web/sql-injection/mysql-injection/README.md>

## Bypass

- **HTTP parameter pollution lets an attacker bypass a web application firewall or input filter by encoding separators or distributing the injection across multiple parameters, so the same value never reaches the filter.**  
  `high_confidence` · score 0.839 · disproved by: The claim is false when the application parses the request into a safe data structure, binds all values, and never concatenates user input into a SQL string, because in that case no parameter layout can produce injection. It is also false when the WAF or filter normalises the request in the same way the application does, so the same decoded token still appears.
  sources: <https://owasp.org/www-community/SQL_Injection_Prevention_Cheat_Sheet> · <https://portswigger.net/web-security/sql-injection/blind>

## Chain Link

- **Data written safely by one request can become injectable when a later request concatenates the stored value into a new query.**  
  `high_confidence` · score 0.853 · disproved by: If the stored payload is only ever read back through parameterized queries and never concatenated, the flow is not second-order injectable.
  sources: <https://cwe.mitre.org/data/definitions/89.html> · <https://portswigger.net/web-security/sql-injection>
- **SQL injection can escalate into remote code execution when a database that permits file writes or command execution is reachable, chaining the injection to a file write followed by an application-controlled file include.**  
  `high_confidence` · score 0.8475 · disproved by: The claim is false when the injectable query runs against a database user without file or command privileges, when the target directory is outside the web root or not writable by the database process, or when the written file can never be reached through an application-controlled path. It is also false when the injection point is parameterised, in which case the injected text never reaches the parser.
  sources: <https://owasp.org/www-community/attacks/SQL_Injection> · <https://portswigger.net/web-security/sql-injection/os-command-injection>

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
