---
name: sqli-hunting
description: Use when hunting SQL Injection in a web target. Ordered prerequisites, signals, techniques, validation bar and false-positive rules.
---

# SQL Injection — hunting skill

<!-- GENERATED from db/wks.db by wks/skillgen.py. DO NOT HAND-EDIT.
     Edit the rows (or ingest better research) and re-run:
     python -m wks.skillgen -->

> surface `web` · CWE CWE-89 · OWASP A03:2021
> evidence: 38 items, 34 supported, 14 FP rules, 1 chains
> maturity: **mature**

Attacker-controlled input is concatenated into a SQL statement, so the query structure becomes attacker-controlled.

**Also called:** sql injection, sqli, second order sql injection, nosql injection operator


## Prerequisites (do not start without these)

- Any request-controllable value that reaches a SQL query is a candidate injection point, including JSON/XML bodies, cookies and headers, not just GET parameters.  _(merged 1 duplicate row(s))_
  - **Disproof:** If a field's value is provably never used in any query (e.g. purely client-side sorting or CSRF tokens), it cannot be an injection point.
  - Sources: <https://raw.githubusercontent.com/OWASP/wstg/master/document/4-Web_Application_Security_Testing/07-Injection/05-SQL_Injection.md> · <https://portswigger.net/web-security/sql-injection>
- Extraction on MS Access is gated on naming a real column such as username, so the guess-and-check step on column names comes before any value can be pulled out of the database through the injection.  _(merged 1 duplicate row(s))_
  - **Disproof:** Reading a value out of MS Access with no valid column name in the injected query, or a fabricated column name returning data, refutes this ordering.
  - Sources: <https://sqlite.org/lang_expr.html> · <https://raw.githubusercontent.com/HackTricks-wiki/hacktricks/master/src/pentesting-web/sql-injection/ms-access-sql-injection.md>
- Prepared/parameterized statements force the DB to separate code from data, so bind-variable queries are the baseline you must establish before treating quote errors as SQLi.  _(merged 1 duplicate row(s))_
  - **Disproof:** If the query string is built by concatenation at runtime even when a parameterized API exists elsewhere, the endpoint is not parameterized.
  - Sources: <https://cheatsheetseries.owasp.org/cheatsheets/SQL_Injection_Prevention_Cheat_Sheet.html> · <https://cwe.mitre.org/data/definitions/89.html>

## Recon signals (where to look)

- A single quote or a paired OR 1=1 / OR 1=2 pair producing a repeatable response difference is the primary first-order SQLi signal.  _(merged 1 duplicate row(s))_
  - **Disproof:** If the quote and both boolean twins produce byte-identical responses, the field shows no first-order SQLi signal.
  - Sources: <https://raw.githubusercontent.com/OWASP/wstg/master/document/4-Web_Application_Security_Testing/07-Injection/05-SQL_Injection.md> · <https://portswigger.net/web-security/sql-injection>
- If the app neither returns query results nor error differences nor timing changes, the query may run asynchronously; absence of in-band signal does not mean absence of SQLi.  _(merged 1 duplicate row(s))_
  - **Disproof:** If an OAST payload produces no collaborator/DNS callback and conditional time delays stay within baseline jitter, the parameter is very likely not injectable.
  - Sources: <https://owasp.org/www-project-web-security-testing-guide/stable/4-Web_Application_Security_Testing/07-Input_Validation_Testing/05-Testing_for_SQL_Injection.html> · <https://raw.githubusercontent.com/OWASP/wstg/v4.2/document/4-Web_Application_Security_Testing/07-Input_Validation_Testing/05-Testing_for_SQL_Injection.md> · <https://portswigger.net/web-security/sql-injection/blind>

## Techniques (what to change)

- A UNION-based SQL injection is confirmed by matching the result-set column count through successively longer runs of NULL placeholders, and NULL is used as the filler because it type-checks in any column position and so maximises the chance the payload succeeds.  _(merged 2 duplicate row(s))_ _(unverified)_
  - **Disproof:** If no NULL-counted payload ever produces the extra result set or alters the response, the column count was never matched and the UNION injection is not demonstrated.
  - Sources: <https://cwe.mitre.org/data/definitions/89.html> · <https://docs.djangoproject.com/en/5.0/topics/db/sql/> · <https://kathan19.gitbook.io/howtohunt/sqli/sql_injection.md>
- An MSSQL injection point doubles as a privilege-reach probe: calling fn_my_permissions against the database and filtering on a named permission tells the tester which database-level grants the injected session actually holds before they plan any escalation.  _(merged 1 duplicate row(s))_
  - **Disproof:** fn_my_permissions returning no rows, or an empty grant set, for a login that demonstrably holds the named database permission refutes it as a reach check.
  - Sources: <https://portswigger.net/web-security/sql-injection> · <https://raw.githubusercontent.com/HackTricks-wiki/hacktricks/master/src/pentesting-web/sql-injection/mssql-injection.md>
- Blind boolean injection extracts arbitrary values one character at a time by making the app's visible behaviour depend on a single condition.  _(merged 1 duplicate row(s))_
  - **Disproof:** If the application's behaviour is identical whether the condition is true or false, boolean extraction is impossible and time-based or OAST is required.
  - Sources: <https://owasp.org/www-project-web-security-testing-guide/stable/4-Web_Application_Security_Testing/07-Input_Validation_Testing/05-Testing_for_SQL_Injection.html> · <https://raw.githubusercontent.com/OWASP/wstg/v4.2/document/4-Web_Application_Security_Testing/07-Input_Validation_Testing/05-Testing_for_SQL_Injection.md> · <https://portswigger.net/web-security/sql-injection/blind>
- For example, consider using persistence layers such as Hibernate or Enterprise Java Beans, which can provide significant protection against SQL injection if used properly.  _(merged 1 duplicate row(s))_ _(unverified)_
  - **Disproof:** This is refuted if an authoritative source shows the described behaviour does not occur, does not grant access, or is already prevented by default framework configuration: "For example, consider using persistence layers such as Hibernate or Enterprise Java Beans,".
  - Sources: <https://cwe.mitre.org/data/definitions/89.html> · <https://owasp.org/www-community/attacks/SQL_Injection>
- If authorization information is held in a SQL database, it may be possible to change this information through the successful exploitation of a SQL injection vulnerability.  _(merged 1 duplicate row(s))_ _(unverified)_
  - **Disproof:** This is refuted if an authoritative source shows the described behaviour does not occur, does not grant access, or is already prevented by default framework configuration: "If authorization information is held in a SQL database, it may be possible to change this ".
  - Sources: <https://cwe.mitre.org/data/definitions/89.html> · <https://owasp.org/www-community/attacks/SQL_Injection>
- Incrementing ORDER BY <n> until a response change appears infers the column count of the original query even when errors are suppressed.  _(merged 1 duplicate row(s))_
  - **Disproof:** If every index from 1 upward yields an identical response, ORDER BY cannot be used for column counting and you must rely on UNION NULL probing.
  - Sources: <https://cheatsheetseries.owasp.org/cheatsheets/SQL_Injection_Prevention_Cheat_Sheet.html> · <https://portswigger.net/web-security/sql-injection/union-attacks>
- Input validation will not always prevent SQL injection, especially if you are required to support free-form text fields that could contain arbitrary characters.  _(merged 1 duplicate row(s))_ _(unverified)_
  - **Disproof:** This is refuted if an authoritative source shows the described behaviour does not occur, does not grant access, or is already prevented by default framework configuration: "Input validation will not always prevent SQL injection, especially if you are required to ".
  - Sources: <https://cwe.mitre.org/data/definitions/89.html> · <https://owasp.org/www-community/attacks/SQL_Injection>
- Inside an injected MS Access query, TOP and LAST act as row selectors, so the tester can cap or reverse the result set and page out a table's records instead of dumping it whole.  _(merged 1 duplicate row(s))_
  - **Disproof:** TOP or LAST modifiers rejected as syntax by the same injection point, or accepted but leaving the returned rows unchanged, refute their use as row-selection controls.
  - Sources: <https://sqlite.org/lang_expr.html> · <https://raw.githubusercontent.com/HackTricks-wiki/hacktricks/master/src/pentesting-web/sql-injection/ms-access-sql-injection.md>
- MySQL schema and table names come out of a UNION SELECT with GROUP_CONCAT over information_schema, and the alternating letter case of the quoted keywords is the point: the enumeration has to be sent in mixed case so a filter matching keywords in one fixed case does not stop it.  _(merged 1 duplicate row(s))_
  - **Disproof:** A filter that blocks the mixed-case spelling while letting the all-lowercase form through, or a UNION SELECT that returns no schema rows despite a working injection point, refutes this enumeration route.
  - Sources: <https://cheatsheetseries.owasp.org/cheatsheets/SQL_Injection_Prevention_Cheat_Sheet.html> · <https://raw.githubusercontent.com/HackTricks-wiki/hacktricks/master/src/pentesting-web/sql-injection/mysql-injection/README.md>
- Naming a target table turns the same UNION SELECT pattern into a column dictionary, so the tester moves from which tables exist to exactly which attributes the injected query can reference.  _(merged 1 duplicate row(s))_
  - **Disproof:** The column enumeration coming back empty for a table that the same injection point can already read rows from refutes this metadata route.
  - Sources: <https://cheatsheetseries.owasp.org/cheatsheets/SQL_Injection_Prevention_Cheat_Sheet.html> · <https://raw.githubusercontent.com/HackTricks-wiki/hacktricks/master/src/pentesting-web/sql-injection/mysql-injection/README.md>
- On MSSQL a single injected UNION SELECT over information_schema.columns hands back the schema, table and column names of the current database at once, and on error-based vectors every selected expression has to carry an alias or the query will not come back.  _(merged 1 duplicate row(s))_
  - **Disproof:** An error-based injected select that errors purely because an expression lacks an alias, or a schema enumeration that returns no rows despite a working injection point, refutes these requirements.
  - Sources: <https://portswigger.net/web-security/sql-injection> · <https://raw.githubusercontent.com/HackTricks-wiki/hacktricks/master/src/pentesting-web/sql-injection/mssql-injection.md>
- Once a UNION SELECT column count is aligned, the tester can read a chosen position out of a table with a wildcard select and never has to know the column's name, which is how data leaves the database once the injection point is confirmed.  _(merged 1 duplicate row(s))_
  - **Disproof:** A wildcard select that returns nothing from a table known to be readable, or one that fails purely on a column-count mismatch, refutes the positional-access claim.
  - Sources: <https://cwe.mitre.org/data/definitions/89.html> · <https://raw.githubusercontent.com/HackTricks-wiki/hacktricks/master/src/pentesting-web/sql-injection/README.md>
- SQL injection is confirmed by a boolean differential: a condition that is always true returns the normal row count while the same condition forced false returns a different one.  _(merged 1 duplicate row(s))_
  - **Disproof:** Refuted when the application returns an identical response for true and false conditions, which indicates the value is escaped, parameterised, or never reaches a SQL parser.
  - Sources: <https://owasp.org/www-community/attacks/SQL_Injection> · <https://portswigger.net/web-security/sql-injection> · <https://raw.githubusercontent.com/Esther7171/HackTheBox-Writeups-Walkthroughs/main/Write-ups/Academy/05.%20Web%20Exploitation/25.%20SQL%20Injection%20Fundamentals/SQL%20Injection%20Fundamentals.md>
- UNION SELECT NULL with increasing NULL counts finds the column count, then a string marker in each position finds a column type that can carry exfiltrated data.  _(merged 1 duplicate row(s))_
  - **Disproof:** If the response is identical for wrong and correct NULL counts, the UNION column-count method is ineffective and you must use boolean or error-based inference.
  - Sources: <https://raw.githubusercontent.com/OWASP/wstg/master/document/4-Web_Application_Security_Testing/07-Injection/05-SQL_Injection.md> · <https://portswigger.net/web-security/sql-injection/union-attacks>

## Tests

- MS Access hands the tester a file-existence oracle from inside the injection: point the database reference at a local file and the invalid-database-format error appears only when that file is really there, so file enumeration is driven by comparing errors across candidate paths.  _(merged 1 duplicate row(s))_
  - **Disproof:** The invalid-format error appearing identically for names that do not exist, or never appearing for one that does, refutes the existence oracle.
  - Sources: <https://sqlite.org/lang_expr.html> · <https://raw.githubusercontent.com/HackTricks-wiki/hacktricks/master/src/pentesting-web/sql-injection/ms-access-sql-injection.md>
- On MSSQL the tester can read the live query text back through sys.dm_exec_requests joined to sys.dm_exec_sql_text, which is the way to confirm the injection really landed in the query and to see the surrounding SQL, with the server-level permission checked separately.  _(merged 1 duplicate row(s))_
  - **Disproof:** The DMVs returning nothing, or returning a query that does not contain the injected syntax, refutes their use for reading back the currently executing SQL query.
  - Sources: <https://portswigger.net/web-security/sql-injection> · <https://raw.githubusercontent.com/HackTricks-wiki/hacktricks/master/src/pentesting-web/sql-injection/mssql-injection.md>
- To decide this case, observe: Establish a baseline with clearly invalid input such as a string where a number is expected, and check whether that also 500s.  _(merged 1 duplicate row(s))_
  - **Disproof:** This test does not apply where the surrounding behaviour is unobservable -- for example when the response is identical in every case, or when the only evidence is server-side and not reflected to the requester. The originating rule (sqli.fp_rule.generic_500_not_sqli) states the full boundary.
  - Sources: <https://raw.githubusercontent.com/OWASP/wstg/master/document/4-Web_Application_Security_Testing/07-Injection/05-SQL_Injection.md> · <https://portswigger.net/web-security/sql-injection/blind>
- To decide this case, observe: For each candidate field, replay the true/false pair three times with all other parameters identical and diff status code, headers and body.  _(merged 1 duplicate row(s))_
  - **Disproof:** This test does not apply where the surrounding behaviour is unobservable -- for example when the response is identical in every case, or when the only evidence is server-side and not reflected to the requester. The originating rule (sqli.validation.single_variable_differential) states the full boundary.
  - Sources: <https://raw.githubusercontent.com/OWASP/wstg/v4.2/document/4-Web_Application_Security_Testing/07-Input_Validation_Testing/05-Testing_for_SQL_Injection.md> · <https://portswigger.net/web-security/sql-injection/blind>
- When a blind SQL injection returns no data, the proof is made of timing: concatenate a deliberately slow operation into the SQL query and look for a repeatable jump in page-load time that the unmodified request does not show.  _(merged 1 duplicate row(s))_
  - **Disproof:** A concatenated slow operation that leaves page-load time flat, or a delay that appears just as often on a control request carrying no injected syntax, refutes it as a blind SQL injection oracle.
  - Sources: <https://cwe.mitre.org/data/definitions/89.html> · <https://raw.githubusercontent.com/HackTricks-wiki/hacktricks/master/src/pentesting-web/sql-injection/README.md>

## Validation bar (how to prove it)

- A SQLi finding is only validated when one variable changes and the response difference is reproducible and explainable by query logic.  _(merged 1 duplicate row(s))_
  - **Disproof:** If the difference is non-deterministic, cache- or session-driven, or does not reverse when the condition is inverted, it is not a validated SQLi.
  - Sources: <https://owasp.org/www-project-web-security-testing-guide/stable/4-Web_Application_Security_Testing/07-Input_Validation_Testing/05-Testing_for_SQL_Injection.html> · <https://raw.githubusercontent.com/OWASP/wstg/v4.2/document/4-Web_Application_Security_Testing/07-Input_Validation_Testing/05-Testing_for_SQL_Injection.md> · <https://portswigger.net/web-security/sql-injection/blind>
- A boolean or time differential found while several parameters are being varied at once is not attributable to any of them, so the finding is only valid once the same differential reproduces with exactly one variable changed.  _(merged 1 duplicate row(s))_
  - **Disproof:** The rule is a testing discipline, not a property of the vulnerability, so it is false as a statement about what constitutes a finding in cases where a different kind of evidence is available: an out-of-band callback from a payload that could only have been assembled by the database is attributable regardless of how many other parameters were in the request, because the callback proves the injected expression executed. It is also false where the endpoint exposes the generated SQL - a debug echo, a query log, an error page printing the statement - since the statement text itself settles where the value landed. And a differential can be attributable without single-variable isolation when the other parameters are held constant by construction, for example by fixing them from a captured baseline and varying only the target.
  - Sources: <https://docs.djangoproject.com/en/5.0/topics/db/sql/> · <https://sqlite.org/lang_expr.html>
- A verbose database error that echoes the constructed query turns blind injection visible and independently confirms the injection point's context.  _(merged 1 duplicate row(s))_
  - **Disproof:** If the app returns a generic custom error page with no driver text and no reflected query fragment, error-based confirmation is unavailable.
  - Sources: <https://cwe.mitre.org/data/definitions/89.html> · <https://portswigger.net/web-security/sql-injection/blind>
- In a full-text search parameter the attacker-controlled text is a query language, not a string literal, so single-quote and UNION payloads test nothing and the injection point is the operator's own grammar.  _(merged 1 duplicate row(s))_
  - **Disproof:** The claim is false when the value is quoted or escaped before reaching the operator's parser - a driver or API that treats the operand as an opaque string and escapes the operator's metacharacters removes the grammar surface entirely, in which case the standard payload is again the right one. It is also false as a claim of vulnerability: the mere existence of a rich query language in a search box is not a finding, and FTS5's own syntax is deliberately non-SQL, so a payload that changes match results is a search-behaviour quirk rather than SQL injection. The finding needs the grammar surface to reach a SQL-executing construct - for example an FTS expression that a trigger, a view, or an auxiliary function expands into further SQL - and that chain has to be demonstrated.
  - Sources: <https://sqlite.org/fts5.html> · <https://www.postgresql.org/docs/current/sql-syntax-lexical.html>

## False-positive rules (when to reject it)

- A 500 or generic error page triggered by malformed input alone is not SQLi evidence; many apps error identically for any invalid value.  _(merged 1 duplicate row(s))_
  - **Disproof:** If plain type-mismatch input produces the identical 500 response with no SQL-specific text, the 500 is an input-validation artefact, not SQLi.
  - Sources: <https://raw.githubusercontent.com/OWASP/wstg/master/document/4-Web_Application_Security_Testing/07-Injection/05-SQL_Injection.md> · <https://portswigger.net/web-security/sql-injection/blind>
- A dollar-quoted string in PostgreSQL is a closed literal that ignores backslashes and dollar signs, so a payload containing $tag$ delimiters only becomes dangerous if the attacker can supply the tag the application's own quoting chose.  _(merged 1 duplicate row(s))_
  - **Disproof:** The claim is false when the tag is attacker-controlled or absent in a way that lets the payload close the literal - an unquoted dollar-quoted string in a function definition whose body is built from user input lets an attacker insert their own $q$...$q$ and terminate it, and PostgreSQL's own example of a nested $q$[\t\r\n\v\\]$q$ inside $function$ ... $function$ shows exactly that shape. It also fails if the payload is delivered outside the dollar-quoted region - a second statement concatenated after the function body, or a value reaching a non-dollar-quoted parameter such as a dynamic EXECUTE string, is ordinary SQL and the standard payloads apply.
  - Sources: <https://docs.djangoproject.com/en/5.0/topics/db/sql/> · <https://www.postgresql.org/docs/current/sql-syntax-lexical.html>
- A request that returns a database error echoing the caller's own input, on a code path that passes that input as a bound parameter, is a verbose-error disclosure and not SQL injection - the value never entered the statement text.  _(merged 1 duplicate row(s))_
  - **Disproof:** The claim is false when the same request also produces a behaviour change with the quote removed - a boolean differential, a time delta, or an OAST callback - because then the value is reaching the statement text by some other route even if this particular call site is parameterised. Parameterisation is per call site, and applications routinely have a safe read path and an unsafe report, export, or search path on the same endpoint. It is also false when the framework's own string escaping is being relied on rather than binding: a helper that quotes and doubles the value correctly still yields a value that will break the moment a second, unescaped layer concatenates it, so the presence of quotes in the output is not evidence of safety at the statement level.
  - Sources: <https://docs.djangoproject.com/en/5.0/topics/db/sql/> · <https://sqlite.org/lang_expr.html>
- Under a properly parameterized ORM/HQL query, quote and comment payloads are matched as literal data, so their failure to inject is a true negative, not a missed bug.  _(merged 1 duplicate row(s))_
  - **Disproof:** If the ORM library has a known injection CVE for the deployed version, or raw concatenated queries appear in the code path, the negative result is invalid.
  - Sources: <https://cheatsheetseries.owasp.org/cheatsheets/SQL_Injection_Prevention_Cheat_Sheet.html> · <https://cwe.mitre.org/data/definitions/89.html> · <https://raw.githubusercontent.com/OWASP/wstg/master/document/4-Web_Application_Security_Testing/07-Injection/05.7-ORM_Injection.md>

## Evidence requirements

- A convincing observation for this class is: For each candidate field, replay the true/false pair three times with all other parameters identical and diff status code, headers and body.  _(merged 1 duplicate row(s))_
  - **Disproof:** Not evidence when the observable cannot be produced at all -- blind, server-side-only, or identical-in-every-case behaviour leaves nothing to show. The originating rule (sqli.validation.single_variable_differential) states the full boundary.
  - Sources: <https://raw.githubusercontent.com/OWASP/wstg/v4.2/document/4-Web_Application_Security_Testing/07-Input_Validation_Testing/05-Testing_for_SQL_Injection.md> · <https://portswigger.net/web-security/sql-injection/blind>

## Impact framing

- A confirmed SQLi typically yields bulk read of application data and can subvert authentication, not just a single leaked record.  _(merged 1 duplicate row(s))_
  - **Disproof:** If the DB account is restricted to read-only access to a single view and auth cannot be subverted, impact is bounded to the data in that view.
  - Sources: <https://cwe.mitre.org/data/definitions/89.html> · <https://portswigger.net/web-security/sql-injection>

## Variants

- A search box wired into a full-text MATCH ... AGAINST clause in boolean mode is its own injection flavour: the search term is concatenated inside the quoted argument, so the tester should probe the quote and the boolean-mode operators rather than a plain WHERE value.  _(merged 1 duplicate row(s))_
  - **Disproof:** A search parameter concatenated into that MATCH clause that can neither break out of the quotes nor change the boolean-mode search, refutes it as an injection point.
  - Sources: <https://cheatsheetseries.owasp.org/cheatsheets/SQL_Injection_Prevention_Cheat_Sheet.html> · <https://raw.githubusercontent.com/HackTricks-wiki/hacktricks/master/src/pentesting-web/sql-injection/mysql-injection/README.md>

## Defence bypasses

- WAFs that normalize, case-filter or over-clean requests can be bypassed by comment-splitting, mixed case, encoding and parameter pollution.  _(merged 1 duplicate row(s))_
  - **Disproof:** If every encoded, case-varied and split variant is rejected identically and no differential response appears, the block is likely enforced downstream of the WAF, not by it.
  - Sources: <https://community.owasp.org/attacks/SQL_Injection_Bypassing_WAF> · <https://portswigger.net/web-security/sql-injection>

## Chaining opportunities

- Data written safely by one request can become injectable when a later request concatenates the stored value into a new query.  _(merged 1 duplicate row(s))_
  - **Disproof:** If the stored payload is only ever read back through parameterized queries and never concatenated, the flow is not second-order injectable.
  - Sources: <https://cwe.mitre.org/data/definitions/89.html> · <https://portswigger.net/web-security/sql-injection>

## Rejected before you report

- **The search parameter is injectable because a single quote produces a database syntax error**
  - Killed by: The unquoted control request also returned HTTP 500, so the error is raised before the query is built - it comes from a missing query parameter or a template error, not from the quote reaching a parser
  - Rule: A 500 on a metacharacter proves nothing until the same request without the metacharacter returns 200; always capture an unquoted control response before attributing an error to injection
- **The ordering of results changes when a CASE expression is appended to the sort parameter**
  - Killed by: The two orderings also differed between two identical repeat requests, so the ordering is unstable for reasons unrelated to the injected expression - the key was not reaching a query
  - Rule: Ordering is only a valid injection signal when a repeated identical baseline request is byte-identical; unstable ordering means the parameter is not demonstrably reaching the query
- **A UNION SELECT payload is accepted because the response returns a different column count**
  - Killed by: The response differed for every column count including impossible ones, and the 'injected' values were already present in the page's own template - the difference was template rendering, not query execution
  - Rule: Before claiming UNION injection, grep the baseline response for the literal values you injected; a value already present in the template proves the response difference came from rendering, not the query
- **The endpoint is blind-injectable because a sleep payload measurably delays the response**
  - Killed by: The delay was not correlated with the payload: alternating requests showed the delay appearing on baselines too, and an unresolvable host produced a comparable timeout, so the latency is the network path
  - Rule: Timing-based injection requires repeated alternating samples showing the delay tracks the payload; one slow response against a network you have not baselined is a network event, not a finding
- **The id parameter is injectable because numeric ids return different data than string ids**
  - Killed by: Any out-of-range value returns the same 400 regardless of quoting, and the message is a fixed application validation string with no database wording - the quote is rejected by type validation before any query
  - Rule: A validation error that is byte-identical for any invalid value indicates a type check, not a parser; a parser-specific error must name the construct that failed
- **An error-based payload exfiltrated database version information**
  - Killed by: The version string appears in the response headers of every page including ones with no injectable parameter, so it is server disclosure rather than something the injection returned
  - Rule: Before calling a value 'extracted by injection', grep other responses for it; a value the server already emits is information disclosure, a different finding with a different fix
- **The WAF is bypassable because the payload with a comment marker returned HTTP 200**
  - Killed by: The 200 response contained no injected data and the same payload alternated between 200 and 403 across repeats, so the filter is probabilistic rather than bypassed
  - Rule: A filter bypass requires the bypassed request to return attacker-chosen data consistently; a status code that alternates across identical requests is filter noise, not a bypass
- **The comment-terminated payload proves the input is concatenated rather than parameterised**
  - Killed by: A trailing '-- -' produced the same result as an empty value, which is the application's own trimming behaviour; the result change came from the value being empty, not from a comment being honoured
  - Rule: A comment marker only demonstrates concatenation if its effect differs from an empty value; identical results mean the marker is ordinary input, not a comment
- **A 500 or generic error page triggered by malformed input alone is not SQLi evidence; many apps error identically for any invalid value.**
  - Killed by: If plain type-mismatch input produces the identical 500 response with no SQL-specific text, the 500 is an input-validation artefact, not SQLi.
  - Rule: A 500 or generic error page triggered by malformed input alone is not SQLi evidence; many apps error identically for any invalid value.
- **Under a properly parameterized ORM/HQL query, quote and comment payloads are matched as literal data, so their failure to inject is a true negative, not a missed bug.**
  - Killed by: If the ORM library has a known injection CVE for the deployed version, or raw concatenated queries appear in the code path, the negative result is invalid.
  - Rule: Under a properly parameterized ORM/HQL query, quote and comment payloads are matched as literal data, so their failure to inject is a true negative, not a missed bug.

## Chains to

- `info_disclosure` (3 shared chain(s))


## Hunt procedure

1. Baseline the endpoint, then append a single quote and compare the response or status against the baseline; a 500 or syntax error is a signal, not proof.
2. Confirm boolean pairs (' AND 1=1-- vs ' AND 1=2--) differ in body or length.
3. Enumerate with UNION SELECT NULL,NULL... until the column count matches; use sqlmap -u <url> --batch only to corroborate a hand-proven injection.
4. Never prove blind injection with a timeout alone; use a time-based payload repeated several times to separate jitter from a real delay.

### What counts as proof

- Two responses that differ in a way the CONTROL did not, produced by a single changed variable.
- An invariant the application is supposed to hold, observed broken.
- A second independent confirmation, or an explicit statement that this is single-account evidence only.

> Ordered prerequisites, the validation bar and the false-positive rules below are the authority: this block is the mechanics, those are the standard.
---
Full class document: `domains/web/sqli/knowledge/DIGEST.md` · retrieve more with `python -m wks.cli search "<query>" --class-id sqli`
