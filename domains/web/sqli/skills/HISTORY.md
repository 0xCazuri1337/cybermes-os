# History

Append-only. Each entry records WHY the skill changed, not just that it did. Improvement means better hunting behaviour, not more text.

## 2026-10-02 15:57 — 1 diff lines
- items: 17 (supported 17), FP rules 12, chains 1, state mature

```diff
(initial generation, 2026-10-02)
```

## 2026-10-02 16:07 — 8 diff lines
- items: 17 (supported 17), FP rules 12, chains 1, state mature

```diff
--- sqli@current
+++ sqli@new
@@ -131,4 +131,4 @@
 - `info_disclosure` (3 shared chain(s))
 
 ---
-Full class document: `domains/web/sqli/EVIDENCE.md` · retrieve more with `python -m wks.cli search "<query>" --class-id sqli`
+Full class document: `domains/web/sqli/knowledge/DIGEST.md` · retrieve more with `python -m wks.cli search "<query>" --class-id sqli`
```

## 2026-10-02 19:37 — 44 diff lines
- items: 19 (supported 16), FP rules 12, chains 1, state mature

```diff
--- sqli@current
+++ sqli@new
@@ -10,7 +10,7 @@
      python -m wks.skillgen -->
 
 > surface `web` · CWE CWE-89 · OWASP A03:2021
-> evidence: 17 items, 17 supported, 12 FP rules, 1 chains
+> evidence: 19 items, 16 supported, 12 FP rules, 1 chains
 > maturity: **mature**
 
 Attacker-controlled input is concatenated into a SQL statement, so the query structure becomes attacker-controlled.
@@ -38,13 +38,13 @@
 
 ## Techniques (what to change)
 
-- If authorization information is held in a SQL database, it may be possible to change this information through the successful exploitation of a SQL injection vulnerability.
+- If authorization information is held in a SQL database, it may be possible to change this information through the successful exploitation of a SQL injection vulnerability. _(unverified)_
   - **Disproof:** This is refuted if an authoritative source shows the described behaviour does not occur, does not grant access, or is already prevented by default framework configuration: "If authorization information is held in a SQL database, it may be possible to change this ".
   - Sources: <https://cwe.mitre.org/data/definitions/89.html> · <https://owasp.org/www-community/attacks/SQL_Injection>
-- For example, consider using persistence layers such as Hibernate or Enterprise Java Beans, which can provide significant protection against SQL injection if used properly.
+- For example, consider using persistence layers such as Hibernate or Enterprise Java Beans, which can provide significant protection against SQL injection if used properly. _(unverified)_
   - **Disproof:** This is refuted if an authoritative source shows the described behaviour does not occur, does not grant access, or is already prevented by default framework configuration: "For example, consider using persistence layers such as Hibernate or Enterprise Java Beans,".
   - Sources: <https://cwe.mitre.org/data/definitions/89.html> · <https://owasp.org/www-community/attacks/SQL_Injection>
-- Input validation will not always prevent SQL injection, especially if you are required to support free-form text fields that could contain arbitrary characters.
+- Input validation will not always prevent SQL injection, especially if you are required to support free-form text fields that could contain arbitrary characters. _(unverified)_
   - **Disproof:** This is refuted if an authoritative source shows the described behaviour does not occur, does not grant access, or is already prevented by default framework configuration: "Input validation will not always prevent SQL injection, especially if you are required to ".
   - Sources: <https://cwe.mitre.org/data/definitions/89.html> · <https://owasp.org/www-community/attacks/SQL_Injection>
 - Blind boolean injection extracts arbitrary values one character at a time by making the app's visible behaviour depend on a single condition.
@@ -56,6 +56,15 @@
 - UNION SELECT NULL with increasing NULL counts finds the column count, then a string marker in each position finds a column type that can carry exfiltrated data.
   - **Disproof:** If the response is identical for wrong and correct NULL counts, the UNION column-count method is ineffective and you must use boolean or error-based inference.
   - Sources: <https://raw.githubusercontent.com/OWASP/wstg/master/document/4-Web_Application_Security_Testing/07-Injection/05-SQL_Injection.md> · <https://portswigger.net/web-security/sql-injection/union-attacks>
+
+## Tests
+
+- To decide this case, observe: sh a baseline with clearly invalid input such as a string where a number is expected, and check whether that also 500s. Only when a structurally valid injected condition changes behaviour while ordinary invalid input does not should the endpoint be treated as injectable.
+  - **Disproof:** This test does not apply where the surrounding behaviour is unobservable -- for example when the response is identical in every case, or when the only evidence is server-side and not reflected to the requester. The originating rule (sqli.fp_rule.generic_500_not_sqli) states the full boundary.
+  - Sources: <https://raw.githubusercontent.com/OWASP/wstg/master/document/4-Web_Application_Security_Testing/07-Injection/05-SQL_Injection.md> · <https://portswigger.net/web-security/sql-injection/blind>
+- To decide this case, observe: For each candidate field, replay the true/false pair three times with all other parameters identical and diff status code, headers and body. Then confirm the difference is attributable to SQL by making it depend on a known condition (e.g. flipping a comparison reverses the outcome). Record raw request/response pairs as the validation artifact.
+  - **Disproof:** This test does not apply where the surrounding behaviour is unobservable -- for example when the response is identical in every case, or when the only evidence is server-side and not reflected to the requester. The originating rule (sqli.validation.single_variable_differential) states the full boundary.
+  - Sources: <https://raw.githubusercontent.com/OWASP/wstg/v4.2/document/4-Web_Application_Security_Testing/07-Input_Validation_Testing/05-Testing_for_SQL_Injection.md> · <https://portswigger.net/web-security/sql-injection/blind>
 
 ## Validation bar (how to prove it)
 
```

## 2026-10-03 01:46 — 127 diff lines
- items: 38 (supported 34), FP rules 14, chains 1, state mature

```diff
--- sqli@current
+++ sqli@new
@@ -10,7 +10,7 @@
      python -m wks.skillgen -->
 
 > surface `web` · CWE CWE-89 · OWASP A03:2021
-> evidence: 19 items, 16 supported, 12 FP rules, 1 chains
+> evidence: 38 items, 34 supported, 14 FP rules, 1 chains
 > maturity: **mature**
 
 Attacker-controlled input is concatenated into a SQL statement, so the query structure becomes attacker-controlled.
@@ -23,6 +23,9 @@
 - Any request-controllable value that reaches a SQL query is a candidate injection point, including JSON/XML bodies, cookies and headers, not just GET parameters.
   - **Disproof:** If a field's value is provably never used in any query (e.g. purely client-side sorting or CSRF tokens), it cannot be an injection point.
   - Sources: <https://raw.githubusercontent.com/OWASP/wstg/master/document/4-Web_Application_Security_Testing/07-Injection/05-SQL_Injection.md> · <https://portswigger.net/web-security/sql-injection>
+- Extraction on MS Access is gated on naming a real column such as username, so the guess-and-check step on column names comes before any value can be pulled out of the database through the injection.
+  - **Disproof:** Reading a value out of MS Access with no valid column name in the injected query, or a fabricated column name returning data, refutes this ordering.
+  - Sources: <https://sqlite.org/lang_expr.html> · <https://raw.githubusercontent.com/HackTricks-wiki/hacktricks/master/src/pentesting-web/sql-injection/ms-access-sql-injection.md>
 - Prepared/parameterized statements force the DB to separate code from data, so bind-variable queries are the baseline you must establish before treating quote errors as SQLi.
   - **Disproof:** If the query string is built by concatenation at runtime even when a parameterized API exists elsewhere, the endpoint is not parameterized.
   - Sources: <https://cheatsheetseries.owasp.org/cheatsheets/SQL_Injection_Prevention_Cheat_Sheet.html> · <https://cwe.mitre.org/data/definitions/89.html>
@@ -50,24 +53,66 @@
 - Blind boolean injection extracts arbitrary values one character at a time by making the app's visible behaviour depend on a single condition.
   - **Disproof:** If the application's behaviour is identical whether the condition is true or false, boolean extraction is impossible and time-based or OAST is required.
   - Sources: <https://owasp.org/www-project-web-security-testing-guide/stable/4-Web_Application_Security_Testing/07-Input_Validation_Testing/05-Testing_for_SQL_Injection.html> · <https://raw.githubusercontent.com/OWASP/wstg/v4.2/document/4-Web_Application_Security_Testing/07-Input_Validation_Testing/05-Testing_for_SQL_Injection.md> · <https://portswigger.net/web-security/sql-injection/blind>
+- Once a UNION SELECT column count is aligned, the tester can read a chosen position out of a table with a wildcard select and never has to know the column's name, which is how data leaves the database once the injection point is confirmed.
+  - **Disproof:** A wildcard select that returns nothing from a table known to be readable, or one that fails purely on a column-count mismatch, refutes the positional-access claim.
+  - Sources: <https://cwe.mitre.org/data/definitions/89.html> · <https://raw.githubusercontent.com/HackTricks-wiki/hacktricks/master/src/pentesting-web/sql-injection/README.md>
+- On MSSQL a single injected UNION SELECT over information_schema.columns hands back the schema, table and column names of the current database at once, and on error-based vectors every selected expression has to carry an alias or the query will not come back.
+  - **Disproof:** An error-based injected select that errors purely because an expression lacks an alias, or a schema enumeration that returns no rows despite a working injection point, refutes these requirements.
+  - Sources: <https://portswigger.net/web-security/sql-injection> · <https://raw.githubusercontent.com/HackTricks-wiki/hacktricks/master/src/pentesting-web/sql-injection/mssql-injection.md>
+- MySQL schema and table names come out of a UNION SELECT with GROUP_CONCAT over information_schema, and the alternating letter case of the quoted keywords is the point: the enumeration has to be sent in mixed case so a filter matching keywords in one fixed case does not stop it.
+  - **Disproof:** A filter that blocks the mixed-case spelling while letting the all-lowercase form through, or a UNION SELECT that returns no schema rows despite a working injection point, refutes this enumeration route.
+  - Sources: <https://cheatsheetseries.owasp.org/cheatsheets/SQL_Injection_Prevention_Cheat_Sheet.html> · <https://raw.githubusercontent.com/HackTricks-wiki/hacktricks/master/src/pentesting-web/sql-injection/mysql-injection/README.md>
+- An MSSQL injection point doubles as a privilege-reach probe: calling fn_my_permissions against the database and filtering on a named permission tells the tester which database-level grants the injected session actually holds before they plan any escalation.
+  - **Disproof:** fn_my_permissions returning no rows, or an empty grant set, for a login that demonstrably holds the named database permission refutes it as a reach check.
+  - Sources: <https://portswigger.net/web-security/sql-injection> · <https://raw.githubusercontent.com/HackTricks-wiki/hacktricks/master/src/pentesting-web/sql-injection/mssql-injection.md>
+- Inside an injected MS Access query, TOP and LAST act as row selectors, so the tester can cap or reverse the result set and page out a table's records instead of dumping it whole.
+  - **Disproof:** TOP or LAST modifiers rejected as syntax by the same injection point, or accepted but leaving the returned rows unchanged, refute their use as row-selection controls.
+  - Sources: <https://sqlite.org/lang_expr.html> · <https://raw.githubusercontent.com/HackTricks-wiki/hacktricks/master/src/pentesting-web/sql-injection/ms-access-sql-injection.md>
+- Naming a target table turns the same UNION SELECT pattern into a column dictionary, so the tester moves from which tables exist to exactly which attributes the injected query can reference.
+  - **Disproof:** The column enumeration coming back empty for a table that the same injection point can already read rows from refutes this metadata route.
+  - Sources: <https://cheatsheetseries.owasp.org/cheatsheets/SQL_Injection_Prevention_Cheat_Sheet.html> · <https://raw.githubusercontent.com/HackTricks-wiki/hacktricks/master/src/pentesting-web/sql-injection/mysql-injection/README.md>
+- A UNION-based SQL injection is confirmed by matching the result-set column count through successively longer runs of NULL placeholders, and NULL is used as the filler because it type-checks in any column position and so maximises the chance the payload succeeds. _(unverified)_
+  - **Disproof:** If no NULL-counted payload ever produces the extra result set or alters the response, the column count was never matched and the UNION injection is not demonstrated.
+  - Sources: <https://cwe.mitre.org/data/definitions/89.html> · <https://kathan19.gitbook.io/howtohunt/sqli/sql_injection.md>
+- A UNION-based SQL injection is confirmed by matching the result-set column count through successively longer runs of NULL placeholders, and NULL is used as the filler because it type-checks in any column position and so maximises the chance the payload succeeds.
+  - **Disproof:** If no NULL-counted payload ever produces the extra result set or alters the response, the column count was never matched and the UNION injection is not demonstrated.
+  - Sources: <https://cwe.mitre.org/data/definitions/89.html> · <https://docs.djangoproject.com/en/5.0/topics/db/sql/> · <https://kathan19.gitbook.io/howtohunt/sqli/sql_injection.md>
 - Incrementing ORDER BY <n> until a response change appears infers the column count of the original query even when errors are suppressed.
   - **Disproof:** If every index from 1 upward yields an identical response, ORDER BY cannot be used for column counting and you must rely on UNION NULL probing.
   - Sources: <https://cheatsheetseries.owasp.org/cheatsheets/SQL_Injection_Prevention_Cheat_Sheet.html> · <https://portswigger.net/web-security/sql-injection/union-attacks>
+- SQL injection is confirmed by a boolean differential: a condition that is always true returns the normal row count while the same condition forced false returns a different one.
+  - **Disproof:** Refuted when the application returns an identical response for true and false conditions, which indicates the value is escaped, parameterised, or never reaches a SQL parser.
+  - Sources: <https://owasp.org/www-community/attacks/SQL_Injection> · <https://portswigger.net/web-security/sql-injection> · <https://raw.githubusercontent.com/Esther7171/HackTheBox-Writeups-Walkthroughs/main/Write-ups/Academy/05.%20Web%20Exploitation/25.%20SQL%20Injection%20Fundamentals/SQL%20Injection%20Fundamentals.md>
 - UNION SELECT NULL with increasing NULL counts finds the column count, then a string marker in each position finds a column type that can carry exfiltrated data.
   - **Disproof:** If the response is identical for wrong and correct NULL counts, the UNION column-count method is ineffective and you must use boolean or error-based inference.
   - Sources: <https://raw.githubusercontent.com/OWASP/wstg/master/document/4-Web_Application_Security_Testing/07-Injection/05-SQL_Injection.md> · <https://portswigger.net/web-security/sql-injection/union-attacks>
 
 ## Tests
 
-- To decide this case, observe: sh a baseline with clearly invalid input such as a string where a number is expected, and check whether that also 500s. Only when a structurally valid injected condition changes behaviour while ordinary invalid input does not should the endpoint be treated as injectable.
+- To decide this case, observe: Establish a baseline with clearly invalid input such as a string where a number is expected, and check whether that also 500s.
   - **Disproof:** This test does not apply where the surrounding behaviour is unobservable -- for example when the response is identical in every case, or when the only evidence is server-side and not reflected to the requester. The originating rule (sqli.fp_rule.generic_500_not_sqli) states the full boundary.
   - Sources: <https://raw.githubusercontent.com/OWASP/wstg/master/document/4-Web_Application_Security_Testing/07-Injection/05-SQL_Injection.md> · <https://portswigger.net/web-security/sql-injection/blind>
-- To decide this case, observe: For each candidate field, replay the true/false pair three times with all other parameters identical and diff status code, headers and body. Then confirm the difference is attributable to SQL by making it depend on a known condition (e.g. flipping a comparison reverses the outcome). Record raw request/response pairs as the validation artifact.
+- To decide this case, observe: For each candidate field, replay the true/false pair three times with all other parameters identical and diff status code, headers and body.
   - **Disproof:** This test does not apply where the surrounding behaviour is unobservable -- for example when the response is identical in every case, or when the only evidence is server-side and not reflected to the requester. The originating rule (sqli.validation.single_variable_differential) states the full boundary.
   - Sources: <https://raw.githubusercontent.com/OWASP/wstg/v4.2/document/4-Web_Application_Security_Testing/07-Input_Validation_Testing/05-Testing_for_SQL_Injection.md> · <https://portswigger.net/web-security/sql-injection/blind>
+- MS Access hands the tester a file-existence oracle from inside the injection: point the database reference at a local file and the invalid-database-format error appears only when that file is really there, so file enumeration is driven by comparing errors across candidate paths.
+  - **Disproof:** The invalid-format error appearing identically for names that do not exist, or never appearing for one that does, refutes the existence oracle.
+  - Sources: <https://sqlite.org/lang_expr.html> · <https://raw.githubusercontent.com/HackTricks-wiki/hacktricks/master/src/pentesting-web/sql-injection/ms-access-sql-injection.md>
+- On MSSQL the tester can read the live query text back through sys.dm_exec_requests joined to sys.dm_exec_sql_text, which is the way to confirm the injection really landed in the query and to see the surrounding SQL, with the server-level permission checked separately.
+  - **Disproof:** The DMVs returning nothing, or returning a query that does not contain the injected syntax, refutes their use for reading back the currently executing SQL query.
+  - Sources: <https://portswigger.net/web-security/sql-injection> · <https://raw.githubusercontent.com/HackTricks-wiki/hacktricks/master/src/pentesting-web/sql-injection/mssql-injection.md>
+- When a blind SQL injection returns no data, the proof is made of timing: concatenate a deliberately slow operation into the SQL query and look for a repeatable jump in page-load time that the unmodified request does not show.
+  - **Disproof:** A concatenated slow operation that leaves page-load time flat, or a delay that appears just as often on a control request carrying no injected syntax, refutes it as a blind SQL injection oracle.
+  - Sources: <https://cwe.mitre.org/data/definitions/89.html> · <https://raw.githubusercontent.com/HackTricks-wiki/hacktricks/master/src/pentesting-web/sql-injection/README.md>
 
 ## Validation bar (how to prove it)
 
+- In a full-text search parameter the attacker-controlled text is a query language, not a string literal, so single-quote and UNION payloads test nothing and the injection point is the operator's own grammar.
+  - **Disproof:** The claim is false when the value is quoted or escaped before reaching the operator's parser - a driver or API that treats the operand as an opaque string and escapes the operator's metacharacters removes the grammar surface entirely, in which case the standard payload is again the right one. It is also false as a claim of vulnerability: the mere existence of a rich query language in a search box is not a finding, and FTS5's own syntax is deliberately non-SQL, so a payload that changes match results is a search-behaviour quirk rather than SQL injection. The finding needs the grammar surface to reach a SQL-executing construct - for example an FTS expression that a trigger, a view, or an auxiliary function expands into further SQL - and that chain has to be demonstrated.
+  - Sources: <https://sqlite.org/fts5.html> · <https://www.postgresql.org/docs/current/sql-syntax-lexical.html>
+- A boolean or time differential found while several parameters are being varied at once is not attributable to any of them, so the finding is only valid once the same differential reproduces with exactly one variable changed.
+  - **Disproof:** The rule is a testing discipline, not a property of the vulnerability, so it is false as a statement about what constitutes a finding in cases where a different kind of evidence is available: an out-of-band callback from a payload that could only have been assembled by the database is attributable regardless of how many other parameters were in the request, because the callback proves the injected expression executed. It is also false where the endpoint exposes the generated SQL - a debug echo, a query log, an error page printing the statement - since the statement text itself settles where the value landed. And a differential can be attributable without single-variable isolation when the other parameters are held constant by construction, for example by fixing them from a captured baseline and varying only the target.
+  - Sources: <https://docs.djangoproject.com/en/5.0/topics/db/sql/> · <https://sqlite.org/lang_expr.html>
 - A SQLi finding is only validated when one variable changes and the response difference is reproducible and explainable by query logic.
   - **Disproof:** If the difference is non-deterministic, cache- or session-driven, or does not reverse when the condition is inverted, it is not a validated SQLi.
   - Sources: <https://owasp.org/www-project-web-security-testing-guide/stable/4-Web_Application_Security_Testing/07-Input_Validation_Testing/05-Testing_for_SQL_Injection.html> · <https://raw.githubusercontent.com/OWASP/wstg/v4.2/document/4-Web_Application_Security_Testing/07-Input_Validation_Testing/05-Testing_for_SQL_Injection.md> · <https://portswigger.net/web-security/sql-injection/blind>
@@ -77,6 +122,12 @@
 
 ## False-positive rules (when to reject it)
 
+- A request that returns a database error echoing the caller's own input, on a code path that passes that input as a bound parameter, is a verbose-error disclosure and not SQL injection - the value never entered the statement text.
+  - **Disproof:** The claim is false when the same request also produces a behaviour change with the quote removed - a boolean differential, a time delta, or an OAST callback - because then the value is reaching the statement text by some other route even if this particular call site is parameterised. Parameterisation is per call site, and applications routinely have a safe read path and an unsafe report, export, or search path on the same endpoint. It is also false when the framework's own string escaping is being relied on rather than binding: a helper that quotes and doubles the value correctly still yields a value that will break the moment a second, unescaped layer concatenates it, so the presence of quotes in the output is not evidence of safety at the statement level.
+  - Sources: <https://docs.djangoproject.com/en/5.0/topics/db/sql/> · <https://sqlite.org/lang_expr.html>
+- A dollar-quoted string in PostgreSQL is a closed literal that ignores backslashes and dollar signs, so a payload containing $tag$ delimiters only becomes dangerous if the attacker can supply the tag the application's own quoting chose.
+  - **Disproof:** The claim is false when the tag is attacker-controlled or absent in a way that lets the payload close the literal - an unquoted dollar-quoted string in a function definition whose body is built from user input lets an attacker insert their own $q$...$q$ and terminate it, and PostgreSQL's own example of a nested $q$[\t\r\n\v\\]$q$ inside $function$ ... $function$ shows exactly that shape. It also fails if the payload is delivered outside the dollar-quoted region - a second statement concatenated after the function body, or a value reaching a non-dollar-quoted parameter such as a dynamic EXECUTE string, is ordinary SQL and the standard payloads apply.
+  - Sources: <https://docs.djangoproject.com/en/5.0/topics/db/sql/> · <https://www.postgresql.org/docs/current/sql-syntax-lexical.html>
 - A 500 or generic error page triggered by malformed input alone is not SQLi evidence; many apps error identically for any invalid value.
   - **Disproof:** If plain type-mismatch input produces the identical 500 response with no SQL-specific text, the 500 is an input-validation artefact, not SQLi.
   - Sources: <https://raw.githubusercontent.com/OWASP/wstg/master/document/4-Web_Application_Security_Testing/07-Injection/05-SQL_Injection.md> · <https://portswigger.net/web-security/sql-injection/blind>
@@ -84,11 +135,23 @@
   - **Disproof:** If the ORM library has a known injection CVE for the deployed version, or raw concatenated queries appear in the code path, the negative result is invalid.
   - Sources: <https://cheatsheetseries.owasp.org/cheatsheets/SQL_Injection_Prevention_Cheat_Sheet.html> · <https://cwe.mitre.org/data/definitions/89.html> · <https://raw.githubusercontent.com/OWASP/wstg/master/document/4-Web_Application_Security_Testing/07-Injection/05.7-ORM_Injection.md>
 
+## Evidence requirements
+
+- A convincing observation for this class is: For each candidate field, replay the true/false pair three times with all other parameters identical and diff status code, headers and body.
+  - **Disproof:** Not evidence when the observable cannot be produced at all -- blind, server-side-only, or identical-in-every-case behaviour leaves nothing to show. The originating rule (sqli.validation.single_variable_differential) states the full boundary.
+  - Sources: <https://raw.githubusercontent.com/OWASP/wstg/v4.2/document/4-Web_Application_Security_Testing/07-Input_Validation_Testing/05-Testing_for_SQL_Injection.md> · <https://portswigger.net/web-security/sql-injection/blind>
+
 ## Impact framing
 
 - A confirmed SQLi typically yields bulk read of application data and can subvert authentication, not just a single leaked record.
   - **Disproof:** If the DB account is restricted to read-only access to a single view and auth cannot be subverted, impact is bounded to the data in that view.
   - Sources: <https://cwe.mitre.org/data/definitions/89.html> · <https://portswigger.net/web-security/sql-injection>
+
+## Variants
... (truncated)
```

## 2026-10-04 00:43 — 243 diff lines
- items: 38 (supported 34), FP rules 14, chains 1, state mature

```diff
--- sqli@current
+++ sqli@new
@@ -20,148 +20,145 @@
 
 ## Prerequisites (do not start without these)
 
-- Any request-controllable value that reaches a SQL query is a candidate injection point, including JSON/XML bodies, cookies and headers, not just GET parameters.
+- Any request-controllable value that reaches a SQL query is a candidate injection point, including JSON/XML bodies, cookies and headers, not just GET parameters.  _(merged 1 duplicate row(s))_
   - **Disproof:** If a field's value is provably never used in any query (e.g. purely client-side sorting or CSRF tokens), it cannot be an injection point.
   - Sources: <https://raw.githubusercontent.com/OWASP/wstg/master/document/4-Web_Application_Security_Testing/07-Injection/05-SQL_Injection.md> · <https://portswigger.net/web-security/sql-injection>
-- Extraction on MS Access is gated on naming a real column such as username, so the guess-and-check step on column names comes before any value can be pulled out of the database through the injection.
+- Extraction on MS Access is gated on naming a real column such as username, so the guess-and-check step on column names comes before any value can be pulled out of the database through the injection.  _(merged 1 duplicate row(s))_
   - **Disproof:** Reading a value out of MS Access with no valid column name in the injected query, or a fabricated column name returning data, refutes this ordering.
   - Sources: <https://sqlite.org/lang_expr.html> · <https://raw.githubusercontent.com/HackTricks-wiki/hacktricks/master/src/pentesting-web/sql-injection/ms-access-sql-injection.md>
-- Prepared/parameterized statements force the DB to separate code from data, so bind-variable queries are the baseline you must establish before treating quote errors as SQLi.
+- Prepared/parameterized statements force the DB to separate code from data, so bind-variable queries are the baseline you must establish before treating quote errors as SQLi.  _(merged 1 duplicate row(s))_
   - **Disproof:** If the query string is built by concatenation at runtime even when a parameterized API exists elsewhere, the endpoint is not parameterized.
   - Sources: <https://cheatsheetseries.owasp.org/cheatsheets/SQL_Injection_Prevention_Cheat_Sheet.html> · <https://cwe.mitre.org/data/definitions/89.html>
 
 ## Recon signals (where to look)
 
-- If the app neither returns query results nor error differences nor timing changes, the query may run asynchronously; absence of in-band signal does not mean absence of SQLi.
+- A single quote or a paired OR 1=1 / OR 1=2 pair producing a repeatable response difference is the primary first-order SQLi signal.  _(merged 1 duplicate row(s))_
+  - **Disproof:** If the quote and both boolean twins produce byte-identical responses, the field shows no first-order SQLi signal.
+  - Sources: <https://raw.githubusercontent.com/OWASP/wstg/master/document/4-Web_Application_Security_Testing/07-Injection/05-SQL_Injection.md> · <https://portswigger.net/web-security/sql-injection>
+- If the app neither returns query results nor error differences nor timing changes, the query may run asynchronously; absence of in-band signal does not mean absence of SQLi.  _(merged 1 duplicate row(s))_
   - **Disproof:** If an OAST payload produces no collaborator/DNS callback and conditional time delays stay within baseline jitter, the parameter is very likely not injectable.
   - Sources: <https://owasp.org/www-project-web-security-testing-guide/stable/4-Web_Application_Security_Testing/07-Input_Validation_Testing/05-Testing_for_SQL_Injection.html> · <https://raw.githubusercontent.com/OWASP/wstg/v4.2/document/4-Web_Application_Security_Testing/07-Input_Validation_Testing/05-Testing_for_SQL_Injection.md> · <https://portswigger.net/web-security/sql-injection/blind>
-- A single quote or a paired OR 1=1 / OR 1=2 pair producing a repeatable response difference is the primary first-order SQLi signal.
-  - **Disproof:** If the quote and both boolean twins produce byte-identical responses, the field shows no first-order SQLi signal.
-  - Sources: <https://raw.githubusercontent.com/OWASP/wstg/master/document/4-Web_Application_Security_Testing/07-Injection/05-SQL_Injection.md> · <https://portswigger.net/web-security/sql-injection>
 
 ## Techniques (what to change)
 
-- If authorization information is held in a SQL database, it may be possible to change this information through the successful exploitation of a SQL injection vulnerability. _(unverified)_
+- A UNION-based SQL injection is confirmed by matching the result-set column count through successively longer runs of NULL placeholders, and NULL is used as the filler because it type-checks in any column position and so maximises the chance the payload succeeds.  _(merged 2 duplicate row(s))_ _(unverified)_
+  - **Disproof:** If no NULL-counted payload ever produces the extra result set or alters the response, the column count was never matched and the UNION injection is not demonstrated.
+  - Sources: <https://cwe.mitre.org/data/definitions/89.html> · <https://docs.djangoproject.com/en/5.0/topics/db/sql/> · <https://kathan19.gitbook.io/howtohunt/sqli/sql_injection.md>
+- An MSSQL injection point doubles as a privilege-reach probe: calling fn_my_permissions against the database and filtering on a named permission tells the tester which database-level grants the injected session actually holds before they plan any escalation.  _(merged 1 duplicate row(s))_
+  - **Disproof:** fn_my_permissions returning no rows, or an empty grant set, for a login that demonstrably holds the named database permission refutes it as a reach check.
+  - Sources: <https://portswigger.net/web-security/sql-injection> · <https://raw.githubusercontent.com/HackTricks-wiki/hacktricks/master/src/pentesting-web/sql-injection/mssql-injection.md>
+- Blind boolean injection extracts arbitrary values one character at a time by making the app's visible behaviour depend on a single condition.  _(merged 1 duplicate row(s))_
+  - **Disproof:** If the application's behaviour is identical whether the condition is true or false, boolean extraction is impossible and time-based or OAST is required.
+  - Sources: <https://owasp.org/www-project-web-security-testing-guide/stable/4-Web_Application_Security_Testing/07-Input_Validation_Testing/05-Testing_for_SQL_Injection.html> · <https://raw.githubusercontent.com/OWASP/wstg/v4.2/document/4-Web_Application_Security_Testing/07-Input_Validation_Testing/05-Testing_for_SQL_Injection.md> · <https://portswigger.net/web-security/sql-injection/blind>
+- For example, consider using persistence layers such as Hibernate or Enterprise Java Beans, which can provide significant protection against SQL injection if used properly.  _(merged 1 duplicate row(s))_ _(unverified)_
+  - **Disproof:** This is refuted if an authoritative source shows the described behaviour does not occur, does not grant access, or is already prevented by default framework configuration: "For example, consider using persistence layers such as Hibernate or Enterprise Java Beans,".
+  - Sources: <https://cwe.mitre.org/data/definitions/89.html> · <https://owasp.org/www-community/attacks/SQL_Injection>
+- If authorization information is held in a SQL database, it may be possible to change this information through the successful exploitation of a SQL injection vulnerability.  _(merged 1 duplicate row(s))_ _(unverified)_
   - **Disproof:** This is refuted if an authoritative source shows the described behaviour does not occur, does not grant access, or is already prevented by default framework configuration: "If authorization information is held in a SQL database, it may be possible to change this ".
   - Sources: <https://cwe.mitre.org/data/definitions/89.html> · <https://owasp.org/www-community/attacks/SQL_Injection>
-- For example, consider using persistence layers such as Hibernate or Enterprise Java Beans, which can provide significant protection against SQL injection if used properly. _(unverified)_
-  - **Disproof:** This is refuted if an authoritative source shows the described behaviour does not occur, does not grant access, or is already prevented by default framework configuration: "For example, consider using persistence layers such as Hibernate or Enterprise Java Beans,".
-  - Sources: <https://cwe.mitre.org/data/definitions/89.html> · <https://owasp.org/www-community/attacks/SQL_Injection>
-- Input validation will not always prevent SQL injection, especially if you are required to support free-form text fields that could contain arbitrary characters. _(unverified)_
+- Incrementing ORDER BY <n> until a response change appears infers the column count of the original query even when errors are suppressed.  _(merged 1 duplicate row(s))_
+  - **Disproof:** If every index from 1 upward yields an identical response, ORDER BY cannot be used for column counting and you must rely on UNION NULL probing.
+  - Sources: <https://cheatsheetseries.owasp.org/cheatsheets/SQL_Injection_Prevention_Cheat_Sheet.html> · <https://portswigger.net/web-security/sql-injection/union-attacks>
+- Input validation will not always prevent SQL injection, especially if you are required to support free-form text fields that could contain arbitrary characters.  _(merged 1 duplicate row(s))_ _(unverified)_
   - **Disproof:** This is refuted if an authoritative source shows the described behaviour does not occur, does not grant access, or is already prevented by default framework configuration: "Input validation will not always prevent SQL injection, especially if you are required to ".
   - Sources: <https://cwe.mitre.org/data/definitions/89.html> · <https://owasp.org/www-community/attacks/SQL_Injection>
-- Blind boolean injection extracts arbitrary values one character at a time by making the app's visible behaviour depend on a single condition.
-  - **Disproof:** If the application's behaviour is identical whether the condition is true or false, boolean extraction is impossible and time-based or OAST is required.
-  - Sources: <https://owasp.org/www-project-web-security-testing-guide/stable/4-Web_Application_Security_Testing/07-Input_Validation_Testing/05-Testing_for_SQL_Injection.html> · <https://raw.githubusercontent.com/OWASP/wstg/v4.2/document/4-Web_Application_Security_Testing/07-Input_Validation_Testing/05-Testing_for_SQL_Injection.md> · <https://portswigger.net/web-security/sql-injection/blind>
-- Once a UNION SELECT column count is aligned, the tester can read a chosen position out of a table with a wildcard select and never has to know the column's name, which is how data leaves the database once the injection point is confirmed.
+- Inside an injected MS Access query, TOP and LAST act as row selectors, so the tester can cap or reverse the result set and page out a table's records instead of dumping it whole.  _(merged 1 duplicate row(s))_
+  - **Disproof:** TOP or LAST modifiers rejected as syntax by the same injection point, or accepted but leaving the returned rows unchanged, refute their use as row-selection controls.
+  - Sources: <https://sqlite.org/lang_expr.html> · <https://raw.githubusercontent.com/HackTricks-wiki/hacktricks/master/src/pentesting-web/sql-injection/ms-access-sql-injection.md>
+- MySQL schema and table names come out of a UNION SELECT with GROUP_CONCAT over information_schema, and the alternating letter case of the quoted keywords is the point: the enumeration has to be sent in mixed case so a filter matching keywords in one fixed case does not stop it.  _(merged 1 duplicate row(s))_
+  - **Disproof:** A filter that blocks the mixed-case spelling while letting the all-lowercase form through, or a UNION SELECT that returns no schema rows despite a working injection point, refutes this enumeration route.
+  - Sources: <https://cheatsheetseries.owasp.org/cheatsheets/SQL_Injection_Prevention_Cheat_Sheet.html> · <https://raw.githubusercontent.com/HackTricks-wiki/hacktricks/master/src/pentesting-web/sql-injection/mysql-injection/README.md>
+- Naming a target table turns the same UNION SELECT pattern into a column dictionary, so the tester moves from which tables exist to exactly which attributes the injected query can reference.  _(merged 1 duplicate row(s))_
+  - **Disproof:** The column enumeration coming back empty for a table that the same injection point can already read rows from refutes this metadata route.
+  - Sources: <https://cheatsheetseries.owasp.org/cheatsheets/SQL_Injection_Prevention_Cheat_Sheet.html> · <https://raw.githubusercontent.com/HackTricks-wiki/hacktricks/master/src/pentesting-web/sql-injection/mysql-injection/README.md>
+- On MSSQL a single injected UNION SELECT over information_schema.columns hands back the schema, table and column names of the current database at once, and on error-based vectors every selected expression has to carry an alias or the query will not come back.  _(merged 1 duplicate row(s))_
+  - **Disproof:** An error-based injected select that errors purely because an expression lacks an alias, or a schema enumeration that returns no rows despite a working injection point, refutes these requirements.
+  - Sources: <https://portswigger.net/web-security/sql-injection> · <https://raw.githubusercontent.com/HackTricks-wiki/hacktricks/master/src/pentesting-web/sql-injection/mssql-injection.md>
+- Once a UNION SELECT column count is aligned, the tester can read a chosen position out of a table with a wildcard select and never has to know the column's name, which is how data leaves the database once the injection point is confirmed.  _(merged 1 duplicate row(s))_
   - **Disproof:** A wildcard select that returns nothing from a table known to be readable, or one that fails purely on a column-count mismatch, refutes the positional-access claim.
   - Sources: <https://cwe.mitre.org/data/definitions/89.html> · <https://raw.githubusercontent.com/HackTricks-wiki/hacktricks/master/src/pentesting-web/sql-injection/README.md>
-- On MSSQL a single injected UNION SELECT over information_schema.columns hands back the schema, table and column names of the current database at once, and on error-based vectors every selected expression has to carry an alias or the query will not come back.
-  - **Disproof:** An error-based injected select that errors purely because an expression lacks an alias, or a schema enumeration that returns no rows despite a working injection point, refutes these requirements.
-  - Sources: <https://portswigger.net/web-security/sql-injection> · <https://raw.githubusercontent.com/HackTricks-wiki/hacktricks/master/src/pentesting-web/sql-injection/mssql-injection.md>
-- MySQL schema and table names come out of a UNION SELECT with GROUP_CONCAT over information_schema, and the alternating letter case of the quoted keywords is the point: the enumeration has to be sent in mixed case so a filter matching keywords in one fixed case does not stop it.
-  - **Disproof:** A filter that blocks the mixed-case spelling while letting the all-lowercase form through, or a UNION SELECT that returns no schema rows despite a working injection point, refutes this enumeration route.
-  - Sources: <https://cheatsheetseries.owasp.org/cheatsheets/SQL_Injection_Prevention_Cheat_Sheet.html> · <https://raw.githubusercontent.com/HackTricks-wiki/hacktricks/master/src/pentesting-web/sql-injection/mysql-injection/README.md>
-- An MSSQL injection point doubles as a privilege-reach probe: calling fn_my_permissions against the database and filtering on a named permission tells the tester which database-level grants the injected session actually holds before they plan any escalation.
-  - **Disproof:** fn_my_permissions returning no rows, or an empty grant set, for a login that demonstrably holds the named database permission refutes it as a reach check.
-  - Sources: <https://portswigger.net/web-security/sql-injection> · <https://raw.githubusercontent.com/HackTricks-wiki/hacktricks/master/src/pentesting-web/sql-injection/mssql-injection.md>
-- Inside an injected MS Access query, TOP and LAST act as row selectors, so the tester can cap or reverse the result set and page out a table's records instead of dumping it whole.
-  - **Disproof:** TOP or LAST modifiers rejected as syntax by the same injection point, or accepted but leaving the returned rows unchanged, refute their use as row-selection controls.
-  - Sources: <https://sqlite.org/lang_expr.html> · <https://raw.githubusercontent.com/HackTricks-wiki/hacktricks/master/src/pentesting-web/sql-injection/ms-access-sql-injection.md>
-- Naming a target table turns the same UNION SELECT pattern into a column dictionary, so the tester moves from which tables exist to exactly which attributes the injected query can reference.
-  - **Disproof:** The column enumeration coming back empty for a table that the same injection point can already read rows from refutes this metadata route.
-  - Sources: <https://cheatsheetseries.owasp.org/cheatsheets/SQL_Injection_Prevention_Cheat_Sheet.html> · <https://raw.githubusercontent.com/HackTricks-wiki/hacktricks/master/src/pentesting-web/sql-injection/mysql-injection/README.md>
-- A UNION-based SQL injection is confirmed by matching the result-set column count through successively longer runs of NULL placeholders, and NULL is used as the filler because it type-checks in any column position and so maximises the chance the payload succeeds. _(unverified)_
-  - **Disproof:** If no NULL-counted payload ever produces the extra result set or alters the response, the column count was never matched and the UNION injection is not demonstrated.
-  - Sources: <https://cwe.mitre.org/data/definitions/89.html> · <https://kathan19.gitbook.io/howtohunt/sqli/sql_injection.md>
-- A UNION-based SQL injection is confirmed by matching the result-set column count through successively longer runs of NULL placeholders, and NULL is used as the filler because it type-checks in any column position and so maximises the chance the payload succeeds.
-  - **Disproof:** If no NULL-counted payload ever produces the extra result set or alters the response, the column count was never matched and the UNION injection is not demonstrated.
-  - Sources: <https://cwe.mitre.org/data/definitions/89.html> · <https://docs.djangoproject.com/en/5.0/topics/db/sql/> · <https://kathan19.gitbook.io/howtohunt/sqli/sql_injection.md>
-- Incrementing ORDER BY <n> until a response change appears infers the column count of the original query even when errors are suppressed.
-  - **Disproof:** If every index from 1 upward yields an identical response, ORDER BY cannot be used for column counting and you must rely on UNION NULL probing.
-  - Sources: <https://cheatsheetseries.owasp.org/cheatsheets/SQL_Injection_Prevention_Cheat_Sheet.html> · <https://portswigger.net/web-security/sql-injection/union-attacks>
-- SQL injection is confirmed by a boolean differential: a condition that is always true returns the normal row count while the same condition forced false returns a different one.
+- SQL injection is confirmed by a boolean differential: a condition that is always true returns the normal row count while the same condition forced false returns a different one.  _(merged 1 duplicate row(s))_
   - **Disproof:** Refuted when the application returns an identical response for true and false conditions, which indicates the value is escaped, parameterised, or never reaches a SQL parser.
   - Sources: <https://owasp.org/www-community/attacks/SQL_Injection> · <https://portswigger.net/web-security/sql-injection> · <https://raw.githubusercontent.com/Esther7171/HackTheBox-Writeups-Walkthroughs/main/Write-ups/Academy/05.%20Web%20Exploitation/25.%20SQL%20Injection%20Fundamentals/SQL%20Injection%20Fundamentals.md>
-- UNION SELECT NULL with increasing NULL counts finds the column count, then a string marker in each position finds a column type that can carry exfiltrated data.
+- UNION SELECT NULL with increasing NULL counts finds the column count, then a string marker in each position finds a column type that can carry exfiltrated data.  _(merged 1 duplicate row(s))_
   - **Disproof:** If the response is identical for wrong and correct NULL counts, the UNION column-count method is ineffective and you must use boolean or error-based inference.
   - Sources: <https://raw.githubusercontent.com/OWASP/wstg/master/document/4-Web_Application_Security_Testing/07-Injection/05-SQL_Injection.md> · <https://portswigger.net/web-security/sql-injection/union-attacks>
 
 ## Tests
 
-- To decide this case, observe: Establish a baseline with clearly invalid input such as a string where a number is expected, and check whether that also 500s.
+- MS Access hands the tester a file-existence oracle from inside the injection: point the database reference at a local file and the invalid-database-format error appears only when that file is really there, so file enumeration is driven by comparing errors across candidate paths.  _(merged 1 duplicate row(s))_
+  - **Disproof:** The invalid-format error appearing identically for names that do not exist, or never appearing for one that does, refutes the existence oracle.
+  - Sources: <https://sqlite.org/lang_expr.html> · <https://raw.githubusercontent.com/HackTricks-wiki/hacktricks/master/src/pentesting-web/sql-injection/ms-access-sql-injection.md>
+- On MSSQL the tester can read the live query text back through sys.dm_exec_requests joined to sys.dm_exec_sql_text, which is the way to confirm the injection really landed in the query and to see the surrounding SQL, with the server-level permission checked separately.  _(merged 1 duplicate row(s))_
+  - **Disproof:** The DMVs returning nothing, or returning a query that does not contain the injected syntax, refutes their use for reading back the currently executing SQL query.
... (truncated)
```

## 2026-10-04 00:50 — 17 diff lines
- items: 38 (supported 34), FP rules 14, chains 1, state mature

```diff
--- sqli@current
+++ sqli@new
@@ -202,10 +202,10 @@
 
 ## Hunt procedure
 
-1. Enumerate the surface before probing: collect every endpoint, parameter and object id the class could plausibly sit on.
-2. Establish a CONTROLLED BASELINE first — one unauthenticated and one authenticated low-privilege request per candidate — and diff against the probe. A difference with no baseline proves nothing.
-3. Change exactly ONE variable per probe. Two changes produce a difference you cannot attribute.
-4. Record raw request and response pairs verbatim, including headers, before you interpret anything.
+1. Baseline the endpoint, then append a single quote and compare the response or status against the baseline; a 500 or syntax error is a signal, not proof.
+2. Confirm boolean pairs (' AND 1=1-- vs ' AND 1=2--) differ in body or length.
+3. Enumerate with UNION SELECT NULL,NULL... until the column count matches; use sqlmap -u <url> --batch only to corroborate a hand-proven injection.
+4. Never prove blind injection with a timeout alone; use a time-based payload repeated several times to separate jitter from a real delay.
 
 ### What counts as proof
 
```

## 2026-10-04 19:46 — 9 diff lines
- items: 38 (supported 34), FP rules 14, chains 1, state mature

```diff
--- sqli@current
+++ sqli@new
@@ -216,6 +216,3 @@
 > Ordered prerequisites, the validation bar and the false-positive rules below are the authority: this block is the mechanics, those are the standard.
 ---
 Full class document: `domains/web/sqli/knowledge/DIGEST.md` · retrieve more with `python -m wks.cli search "<query>" --class-id sqli`
-
----
-Runbook: [`HUNT.md`](HUNT.md) — every promoted technique mapped to an executable procedure with the observables to record.
```

## 2026-10-04 21:29 — 35 diff lines
- items: 38 (supported 37), FP rules 14, chains 1, state mature

```diff
--- sqli@current
+++ sqli@new
@@ -10,7 +10,7 @@
      python -m wks.skillgen -->
 
 > surface `web` · CWE CWE-89 · OWASP A03:2021
-> evidence: 38 items, 34 supported, 14 FP rules, 1 chains
+> evidence: 38 items, 37 supported, 14 FP rules, 1 chains
 > maturity: **mature**
 
 Attacker-controlled input is concatenated into a SQL statement, so the query structure becomes attacker-controlled.
@@ -50,17 +50,17 @@
 - Blind boolean injection extracts arbitrary values one character at a time by making the app's visible behaviour depend on a single condition.  _(merged 1 duplicate row(s))_
   - **Disproof:** If the application's behaviour is identical whether the condition is true or false, boolean extraction is impossible and time-based or OAST is required.
   - Sources: <https://owasp.org/www-project-web-security-testing-guide/stable/4-Web_Application_Security_Testing/07-Input_Validation_Testing/05-Testing_for_SQL_Injection.html> · <https://raw.githubusercontent.com/OWASP/wstg/v4.2/document/4-Web_Application_Security_Testing/07-Input_Validation_Testing/05-Testing_for_SQL_Injection.md> · <https://portswigger.net/web-security/sql-injection/blind>
-- For example, consider using persistence layers such as Hibernate or Enterprise Java Beans, which can provide significant protection against SQL injection if used properly.  _(merged 1 duplicate row(s))_ _(unverified)_
-  - **Disproof:** This is refuted if an authoritative source shows the described behaviour does not occur, does not grant access, or is already prevented by default framework configuration: "For example, consider using persistence layers such as Hibernate or Enterprise Java Beans,".
+- For example, consider using persistence layers such as Hibernate or Enterprise Java Beans, which can provide significant protection against SQL injection if used properly.  _(merged 1 duplicate row(s))_
+  - **Disproof:** Refuted when: the value is bound as a parameter or written through the framework's own encoder, so the interpreter never sees attacker text as syntax. Settle it by running the identical request with and without that one control and diffing the response -- if the difference the claim predicts does not appear, the claim is false. Specifically, this is refuted if the behaviour described (“For example, consider using persistence layers such as Hibernate or Enterprise J”) does not occur under a test that isolates that control.
   - Sources: <https://cwe.mitre.org/data/definitions/89.html> · <https://owasp.org/www-community/attacks/SQL_Injection>
-- If authorization information is held in a SQL database, it may be possible to change this information through the successful exploitation of a SQL injection vulnerability.  _(merged 1 duplicate row(s))_ _(unverified)_
-  - **Disproof:** This is refuted if an authoritative source shows the described behaviour does not occur, does not grant access, or is already prevented by default framework configuration: "If authorization information is held in a SQL database, it may be possible to change this ".
+- If authorization information is held in a SQL database, it may be possible to change this information through the successful exploitation of a SQL injection vulnerability.  _(merged 1 duplicate row(s))_
+  - **Disproof:** Refuted when: the value is bound as a parameter or written through the framework's own encoder, so the interpreter never sees attacker text as syntax. Settle it by running the identical request with and without that one control and diffing the response -- if the difference the claim predicts does not appear, the claim is false. Specifically, this is refuted if the behaviour described (“If authorization information is held in a SQL database, it may be possible to ch”) does not occur under a test that isolates that control.
   - Sources: <https://cwe.mitre.org/data/definitions/89.html> · <https://owasp.org/www-community/attacks/SQL_Injection>
 - Incrementing ORDER BY <n> until a response change appears infers the column count of the original query even when errors are suppressed.  _(merged 1 duplicate row(s))_
   - **Disproof:** If every index from 1 upward yields an identical response, ORDER BY cannot be used for column counting and you must rely on UNION NULL probing.
   - Sources: <https://cheatsheetseries.owasp.org/cheatsheets/SQL_Injection_Prevention_Cheat_Sheet.html> · <https://portswigger.net/web-security/sql-injection/union-attacks>
-- Input validation will not always prevent SQL injection, especially if you are required to support free-form text fields that could contain arbitrary characters.  _(merged 1 duplicate row(s))_ _(unverified)_
-  - **Disproof:** This is refuted if an authoritative source shows the described behaviour does not occur, does not grant access, or is already prevented by default framework configuration: "Input validation will not always prevent SQL injection, especially if you are required to ".
+- Input validation will not always prevent SQL injection, especially if you are required to support free-form text fields that could contain arbitrary characters.  _(merged 1 duplicate row(s))_
+  - **Disproof:** Refuted when: the value is bound as a parameter or written through the framework's own encoder, so the interpreter never sees attacker text as syntax. Settle it by running the identical request with and without that one control and diffing the response -- if the difference the claim predicts does not appear, the claim is false. Specifically, this is refuted if the behaviour described (“Input validation will not always prevent SQL injection, especially if you are re”) does not occur under a test that isolates that control.
   - Sources: <https://cwe.mitre.org/data/definitions/89.html> · <https://owasp.org/www-community/attacks/SQL_Injection>
 - Inside an injected MS Access query, TOP and LAST act as row selectors, so the tester can cap or reverse the result set and page out a table's records instead of dumping it whole.  _(merged 1 duplicate row(s))_
   - **Disproof:** TOP or LAST modifiers rejected as syntax by the same injection point, or accepted but leaving the returned rows unchanged, refute their use as row-selection controls.
```

## 2026-10-28 14:45 — 20 diff lines
- items: 37 (supported 37), FP rules 14, chains 1, state mature

```diff
--- sqli@current
+++ sqli@new
@@ -10,7 +10,7 @@
      python -m wks.skillgen -->
 
 > surface `web` · CWE CWE-89 · OWASP A03:2021
-> evidence: 38 items, 37 supported, 14 FP rules, 1 chains
+> evidence: 37 items, 37 supported, 14 FP rules, 1 chains
 > maturity: **mature**
 
 Attacker-controlled input is concatenated into a SQL statement, so the query structure becomes attacker-controlled.
@@ -41,7 +41,7 @@
 
 ## Techniques (what to change)
 
-- A UNION-based SQL injection is confirmed by matching the result-set column count through successively longer runs of NULL placeholders, and NULL is used as the filler because it type-checks in any column position and so maximises the chance the payload succeeds.  _(merged 2 duplicate row(s))_ _(unverified)_
+- A UNION-based SQL injection is confirmed by matching the result-set column count through successively longer runs of NULL placeholders, and NULL is used as the filler because it type-checks in any column position and so maximises the chance the payload succeeds.  _(merged 1 duplicate row(s))_
   - **Disproof:** If no NULL-counted payload ever produces the extra result set or alters the response, the column count was never matched and the UNION injection is not demonstrated.
   - Sources: <https://cwe.mitre.org/data/definitions/89.html> · <https://docs.djangoproject.com/en/5.0/topics/db/sql/> · <https://kathan19.gitbook.io/howtohunt/sqli/sql_injection.md>
 - An MSSQL injection point doubles as a privilege-reach probe: calling fn_my_permissions against the database and filtering on a named permission tells the tester which database-level grants the injected session actually holds before they plan any escalation.  _(merged 1 duplicate row(s))_
```

## 2026-10-28 21:00 — 72 diff lines
- items: 45 (supported 45), FP rules 14, chains 1, state mature

```diff
--- sqli@current
+++ sqli@new
@@ -10,7 +10,7 @@
      python -m wks.skillgen -->
 
 > surface `web` · CWE CWE-89 · OWASP A03:2021
-> evidence: 37 items, 37 supported, 14 FP rules, 1 chains
+> evidence: 45 items, 45 supported, 14 FP rules, 1 chains
 > maturity: **mature**
 
 Attacker-controlled input is concatenated into a SQL statement, so the query structure becomes attacker-controlled.
@@ -41,15 +41,27 @@
 
 ## Techniques (what to change)
 
+- A UNION-based SQL injection is confirmed by matching the number of columns in the injected result set against the original query using successive NULL placeholders, then selecting data from other tables.  _(merged 1 duplicate row(s))_
+  - **Disproof:** The claim is false when the original query always returns a fixed number of columns unrelated to the injection point, when the database does not expose the metadata used (a closed source or heavily restricted RDBMS), or when the response is identical across every NULL-count probe, which proves no UNION result set reached the output.
+  - Sources: <https://portswigger.net/web-security/sql-injection/union-based> · <https://www.w3schools.com/sql/sql_union.asp>
 - A UNION-based SQL injection is confirmed by matching the result-set column count through successively longer runs of NULL placeholders, and NULL is used as the filler because it type-checks in any column position and so maximises the chance the payload succeeds.  _(merged 1 duplicate row(s))_
   - **Disproof:** If no NULL-counted payload ever produces the extra result set or alters the response, the column count was never matched and the UNION injection is not demonstrated.
   - Sources: <https://cwe.mitre.org/data/definitions/89.html> · <https://docs.djangoproject.com/en/5.0/topics/db/sql/> · <https://kathan19.gitbook.io/howtohunt/sqli/sql_injection.md>
+- A boolean-based blind SQL injection is confirmed when the application's response changes based on a injected condition that is true versus one that is false, with no error or data returned.  _(merged 1 duplicate row(s))_
+  - **Disproof:** The claim is false when the same request produces no behavioural change when the query is rewritten so the value is bound rather than concatenated, because then the condition was never evaluated by the database. It also fails if the observed difference is reproducible with the payload removed or with a syntactically identical but semantically neutral value, which points at response timing, caching, or application logic rather than injection.
+  - Sources: <https://owasp.org/www-community/attacks/SQL_Injection> · <https://portswigger.net/web-security/sql-injection/blind>
+- A time-based blind SQL injection is confirmed when the response delay produced by injecting a SLEEP() predicate is measurable and reproducible, and stops when the condition is made false or when the value is bound.  _(merged 1 duplicate row(s))_
+  - **Disproof:** The claim is false when the observed delay is identical regardless of the condition, which means the database never evaluated the predicate, or when the delay is caused by the endpoint's own behaviour (slow query, saturation, upstream dependency) rather than by the injected predicate. It also fails when the payload is bound, since the function then receives a literal string and never sleeps.
+  - Sources: <https://owasp.org/www-community/attacks/SQL_Injection> · <https://portswigger.net/web-security/sql-injection/blind>
 - An MSSQL injection point doubles as a privilege-reach probe: calling fn_my_permissions against the database and filtering on a named permission tells the tester which database-level grants the injected session actually holds before they plan any escalation.  _(merged 1 duplicate row(s))_
   - **Disproof:** fn_my_permissions returning no rows, or an empty grant set, for a login that demonstrably holds the named database permission refutes it as a reach check.
   - Sources: <https://portswigger.net/web-security/sql-injection> · <https://raw.githubusercontent.com/HackTricks-wiki/hacktricks/master/src/pentesting-web/sql-injection/mssql-injection.md>
 - Blind boolean injection extracts arbitrary values one character at a time by making the app's visible behaviour depend on a single condition.  _(merged 1 duplicate row(s))_
   - **Disproof:** If the application's behaviour is identical whether the condition is true or false, boolean extraction is impossible and time-based or OAST is required.
   - Sources: <https://owasp.org/www-project-web-security-testing-guide/stable/4-Web_Application_Security_Testing/07-Input_Validation_Testing/05-Testing_for_SQL_Injection.html> · <https://raw.githubusercontent.com/OWASP/wstg/v4.2/document/4-Web_Application_Security_Testing/07-Input_Validation_Testing/05-Testing_for_SQL_Injection.md> · <https://portswigger.net/web-security/sql-injection/blind>
+- Error-based SQL injection extracts data by triggering database error messages that echo the injected value or the attacked metadata, and is confirmed when an error response reveals a table, column, or value that was not present in the baseline.  _(merged 1 duplicate row(s))_
+  - **Disproof:** The claim is false when the error message only reports a syntax or constraint violation with no embedded target value, or when the same error appears before any injection is attempted, which means the message is a framework default rather than a data channel. If the value only ever appears in the application's own echoed input and never in a database error, the finding is verbose errors, not error-based injection.
+  - Sources: <https://cheatsheetseries.owasp.org/cheatsheets/SQL_Injection_Prevention_Cheat_Sheet.html> · <https://portswigger.net/web-security/sql-injection/blind>
 - For example, consider using persistence layers such as Hibernate or Enterprise Java Beans, which can provide significant protection against SQL injection if used properly.  _(merged 1 duplicate row(s))_
   - **Disproof:** Refuted when: the value is bound as a parameter or written through the framework's own encoder, so the interpreter never sees attacker text as syntax. Settle it by running the identical request with and without that one control and diffing the response -- if the difference the claim predicts does not appear, the claim is false. Specifically, this is refuted if the behaviour described (“For example, consider using persistence layers such as Hibernate or Enterprise J”) does not occur under a test that isolates that control.
   - Sources: <https://cwe.mitre.org/data/definitions/89.html> · <https://owasp.org/www-community/attacks/SQL_Injection>
@@ -110,6 +122,9 @@
 - A boolean or time differential found while several parameters are being varied at once is not attributable to any of them, so the finding is only valid once the same differential reproduces with exactly one variable changed.  _(merged 1 duplicate row(s))_
   - **Disproof:** The rule is a testing discipline, not a property of the vulnerability, so it is false as a statement about what constitutes a finding in cases where a different kind of evidence is available: an out-of-band callback from a payload that could only have been assembled by the database is attributable regardless of how many other parameters were in the request, because the callback proves the injected expression executed. It is also false where the endpoint exposes the generated SQL - a debug echo, a query log, an error page printing the statement - since the statement text itself settles where the value landed. And a differential can be attributable without single-variable isolation when the other parameters are held constant by construction, for example by fixing them from a captured baseline and varying only the target.
   - Sources: <https://docs.djangoproject.com/en/5.0/topics/db/sql/> · <https://sqlite.org/lang_expr.html>
+- A second-order SQL injection is confirmed when attacker-controlled data is safely stored after one query and later reaches a second, differently-constructed query where it is concatenated unescaped, producing an injection only on the second access.  _(merged 1 duplicate row(s))_
+  - **Disproof:** The claim is false when the second query also binds the value or applies escaping at the point of use, because then the stored data never becomes statement text. It is also false when the stored value is not actually read by the second query, or when any transformation (escaping, type casting, query rewriting) applied to the value at read time neutralises the payload.
+  - Sources: <https://owasp.org/www-community/attacks/SQL_Injection> · <https://portswigger.net/web-security/sql-injection/blind>
 - A verbose database error that echoes the constructed query turns blind injection visible and independently confirms the injection point's context.  _(merged 1 duplicate row(s))_
   - **Disproof:** If the app returns a generic custom error page with no driver text and no reflected query fragment, error-based confirmation is unavailable.
   - Sources: <https://cwe.mitre.org/data/definitions/89.html> · <https://portswigger.net/web-security/sql-injection/blind>
@@ -152,6 +167,12 @@
 
 ## Defence bypasses
 
+- A SQL injection in an authentication query can bypass login entirely, including two-factor authentication, by changing the logic so a true condition is always returned.  _(merged 1 duplicate row(s))_
+  - **Disproof:** The claim is refuted when the application re-queries the database with the username and password as distinct bound parameters, or when a second, independent verification step (password hash comparison, TOTP check) is performed outside the injectable statement. A login that returns the raw SQL error instead of an authenticated page does not demonstrate bypass.
+  - Sources: <https://owasp.org/www-community/attacks/SQL_Injection> · <https://portswigger.net/web-security/sql-injection/blind>
+- HTTP parameter pollution lets an attacker bypass a web application firewall or input filter by encoding separators or distributing the injection across multiple parameters, so the same value never reaches the filter.  _(merged 1 duplicate row(s))_
+  - **Disproof:** The claim is false when the application parses the request into a safe data structure, binds all values, and never concatenates user input into a SQL string, because in that case no parameter layout can produce injection. It is also false when the WAF or filter normalises the request in the same way the application does, so the same decoded token still appears.
+  - Sources: <https://owasp.org/www-community/SQL_Injection_Prevention_Cheat_Sheet> · <https://portswigger.net/web-security/sql-injection/blind>
 - WAFs that normalize, case-filter or over-clean requests can be bypassed by comment-splitting, mixed case, encoding and parameter pollution.  _(merged 1 duplicate row(s))_
   - **Disproof:** If every encoded, case-varied and split variant is rejected identically and no differential response appears, the block is likely enforced downstream of the WAF, not by it.
   - Sources: <https://community.owasp.org/attacks/SQL_Injection_Bypassing_WAF> · <https://portswigger.net/web-security/sql-injection>
@@ -161,6 +182,9 @@
 - Data written safely by one request can become injectable when a later request concatenates the stored value into a new query.  _(merged 1 duplicate row(s))_
   - **Disproof:** If the stored payload is only ever read back through parameterized queries and never concatenated, the flow is not second-order injectable.
   - Sources: <https://cwe.mitre.org/data/definitions/89.html> · <https://portswigger.net/web-security/sql-injection>
+- SQL injection can escalate into remote code execution when a database that permits file writes or command execution is reachable, chaining the injection to a file write followed by an application-controlled file include.  _(merged 1 duplicate row(s))_
+  - **Disproof:** The claim is false when the injectable query runs against a database user without file or command privileges, when the target directory is outside the web root or not writable by the database process, or when the written file can never be reached through an application-controlled path. It is also false when the injection point is parameterised, in which case the injected text never reaches the parser.
+  - Sources: <https://owasp.org/www-community/attacks/SQL_Injection> · <https://portswigger.net/web-security/sql-injection/os-command-injection>
 
 ## Rejected before you report
 
```

## 2026-10-31 00:41 — 223 diff lines
- items: 0 (supported 0), FP rules 0, chains 0, state planned
- still missing: items, supported_items, fp_rules, chain

```diff
--- sqli@current
+++ sqli@new
@@ -10,218 +10,9 @@
      python -m wks.skillgen -->
 
 > surface `web` · CWE CWE-89 · OWASP A03:2021
-> evidence: 45 items, 45 supported, 14 FP rules, 1 chains
-> maturity: **mature**
+> evidence: 0 items, 0 supported, 0 FP rules, 0 chains
+> maturity: **planned** — missing: items, supported_items, fp_rules, chain
 
-Attacker-controlled input is concatenated into a SQL statement, so the query structure becomes attacker-controlled.
-
-**Also called:** sql injection, sqli, second order sql injection, nosql injection operator
-
-
-## Prerequisites (do not start without these)
-
-- Any request-controllable value that reaches a SQL query is a candidate injection point, including JSON/XML bodies, cookies and headers, not just GET parameters.  _(merged 1 duplicate row(s))_
-  - **Disproof:** If a field's value is provably never used in any query (e.g. purely client-side sorting or CSRF tokens), it cannot be an injection point.
-  - Sources: <https://raw.githubusercontent.com/OWASP/wstg/master/document/4-Web_Application_Security_Testing/07-Injection/05-SQL_Injection.md> · <https://portswigger.net/web-security/sql-injection>
-- Extraction on MS Access is gated on naming a real column such as username, so the guess-and-check step on column names comes before any value can be pulled out of the database through the injection.  _(merged 1 duplicate row(s))_
-  - **Disproof:** Reading a value out of MS Access with no valid column name in the injected query, or a fabricated column name returning data, refutes this ordering.
-  - Sources: <https://sqlite.org/lang_expr.html> · <https://raw.githubusercontent.com/HackTricks-wiki/hacktricks/master/src/pentesting-web/sql-injection/ms-access-sql-injection.md>
-- Prepared/parameterized statements force the DB to separate code from data, so bind-variable queries are the baseline you must establish before treating quote errors as SQLi.  _(merged 1 duplicate row(s))_
-  - **Disproof:** If the query string is built by concatenation at runtime even when a parameterized API exists elsewhere, the endpoint is not parameterized.
-  - Sources: <https://cheatsheetseries.owasp.org/cheatsheets/SQL_Injection_Prevention_Cheat_Sheet.html> · <https://cwe.mitre.org/data/definitions/89.html>
-
-## Recon signals (where to look)
-
-- A single quote or a paired OR 1=1 / OR 1=2 pair producing a repeatable response difference is the primary first-order SQLi signal.  _(merged 1 duplicate row(s))_
-  - **Disproof:** If the quote and both boolean twins produce byte-identical responses, the field shows no first-order SQLi signal.
-  - Sources: <https://raw.githubusercontent.com/OWASP/wstg/master/document/4-Web_Application_Security_Testing/07-Injection/05-SQL_Injection.md> · <https://portswigger.net/web-security/sql-injection>
-- If the app neither returns query results nor error differences nor timing changes, the query may run asynchronously; absence of in-band signal does not mean absence of SQLi.  _(merged 1 duplicate row(s))_
-  - **Disproof:** If an OAST payload produces no collaborator/DNS callback and conditional time delays stay within baseline jitter, the parameter is very likely not injectable.
-  - Sources: <https://owasp.org/www-project-web-security-testing-guide/stable/4-Web_Application_Security_Testing/07-Input_Validation_Testing/05-Testing_for_SQL_Injection.html> · <https://raw.githubusercontent.com/OWASP/wstg/v4.2/document/4-Web_Application_Security_Testing/07-Input_Validation_Testing/05-Testing_for_SQL_Injection.md> · <https://portswigger.net/web-security/sql-injection/blind>
-
-## Techniques (what to change)
-
-- A UNION-based SQL injection is confirmed by matching the number of columns in the injected result set against the original query using successive NULL placeholders, then selecting data from other tables.  _(merged 1 duplicate row(s))_
-  - **Disproof:** The claim is false when the original query always returns a fixed number of columns unrelated to the injection point, when the database does not expose the metadata used (a closed source or heavily restricted RDBMS), or when the response is identical across every NULL-count probe, which proves no UNION result set reached the output.
-  - Sources: <https://portswigger.net/web-security/sql-injection/union-based> · <https://www.w3schools.com/sql/sql_union.asp>
-- A UNION-based SQL injection is confirmed by matching the result-set column count through successively longer runs of NULL placeholders, and NULL is used as the filler because it type-checks in any column position and so maximises the chance the payload succeeds.  _(merged 1 duplicate row(s))_
-  - **Disproof:** If no NULL-counted payload ever produces the extra result set or alters the response, the column count was never matched and the UNION injection is not demonstrated.
-  - Sources: <https://cwe.mitre.org/data/definitions/89.html> · <https://docs.djangoproject.com/en/5.0/topics/db/sql/> · <https://kathan19.gitbook.io/howtohunt/sqli/sql_injection.md>
-- A boolean-based blind SQL injection is confirmed when the application's response changes based on a injected condition that is true versus one that is false, with no error or data returned.  _(merged 1 duplicate row(s))_
-  - **Disproof:** The claim is false when the same request produces no behavioural change when the query is rewritten so the value is bound rather than concatenated, because then the condition was never evaluated by the database. It also fails if the observed difference is reproducible with the payload removed or with a syntactically identical but semantically neutral value, which points at response timing, caching, or application logic rather than injection.
-  - Sources: <https://owasp.org/www-community/attacks/SQL_Injection> · <https://portswigger.net/web-security/sql-injection/blind>
-- A time-based blind SQL injection is confirmed when the response delay produced by injecting a SLEEP() predicate is measurable and reproducible, and stops when the condition is made false or when the value is bound.  _(merged 1 duplicate row(s))_
-  - **Disproof:** The claim is false when the observed delay is identical regardless of the condition, which means the database never evaluated the predicate, or when the delay is caused by the endpoint's own behaviour (slow query, saturation, upstream dependency) rather than by the injected predicate. It also fails when the payload is bound, since the function then receives a literal string and never sleeps.
-  - Sources: <https://owasp.org/www-community/attacks/SQL_Injection> · <https://portswigger.net/web-security/sql-injection/blind>
-- An MSSQL injection point doubles as a privilege-reach probe: calling fn_my_permissions against the database and filtering on a named permission tells the tester which database-level grants the injected session actually holds before they plan any escalation.  _(merged 1 duplicate row(s))_
-  - **Disproof:** fn_my_permissions returning no rows, or an empty grant set, for a login that demonstrably holds the named database permission refutes it as a reach check.
-  - Sources: <https://portswigger.net/web-security/sql-injection> · <https://raw.githubusercontent.com/HackTricks-wiki/hacktricks/master/src/pentesting-web/sql-injection/mssql-injection.md>
-- Blind boolean injection extracts arbitrary values one character at a time by making the app's visible behaviour depend on a single condition.  _(merged 1 duplicate row(s))_
-  - **Disproof:** If the application's behaviour is identical whether the condition is true or false, boolean extraction is impossible and time-based or OAST is required.
-  - Sources: <https://owasp.org/www-project-web-security-testing-guide/stable/4-Web_Application_Security_Testing/07-Input_Validation_Testing/05-Testing_for_SQL_Injection.html> · <https://raw.githubusercontent.com/OWASP/wstg/v4.2/document/4-Web_Application_Security_Testing/07-Input_Validation_Testing/05-Testing_for_SQL_Injection.md> · <https://portswigger.net/web-security/sql-injection/blind>
-- Error-based SQL injection extracts data by triggering database error messages that echo the injected value or the attacked metadata, and is confirmed when an error response reveals a table, column, or value that was not present in the baseline.  _(merged 1 duplicate row(s))_
-  - **Disproof:** The claim is false when the error message only reports a syntax or constraint violation with no embedded target value, or when the same error appears before any injection is attempted, which means the message is a framework default rather than a data channel. If the value only ever appears in the application's own echoed input and never in a database error, the finding is verbose errors, not error-based injection.
-  - Sources: <https://cheatsheetseries.owasp.org/cheatsheets/SQL_Injection_Prevention_Cheat_Sheet.html> · <https://portswigger.net/web-security/sql-injection/blind>
-- For example, consider using persistence layers such as Hibernate or Enterprise Java Beans, which can provide significant protection against SQL injection if used properly.  _(merged 1 duplicate row(s))_
-  - **Disproof:** Refuted when: the value is bound as a parameter or written through the framework's own encoder, so the interpreter never sees attacker text as syntax. Settle it by running the identical request with and without that one control and diffing the response -- if the difference the claim predicts does not appear, the claim is false. Specifically, this is refuted if the behaviour described (“For example, consider using persistence layers such as Hibernate or Enterprise J”) does not occur under a test that isolates that control.
-  - Sources: <https://cwe.mitre.org/data/definitions/89.html> · <https://owasp.org/www-community/attacks/SQL_Injection>
-- If authorization information is held in a SQL database, it may be possible to change this information through the successful exploitation of a SQL injection vulnerability.  _(merged 1 duplicate row(s))_
-  - **Disproof:** Refuted when: the value is bound as a parameter or written through the framework's own encoder, so the interpreter never sees attacker text as syntax. Settle it by running the identical request with and without that one control and diffing the response -- if the difference the claim predicts does not appear, the claim is false. Specifically, this is refuted if the behaviour described (“If authorization information is held in a SQL database, it may be possible to ch”) does not occur under a test that isolates that control.
-  - Sources: <https://cwe.mitre.org/data/definitions/89.html> · <https://owasp.org/www-community/attacks/SQL_Injection>
-- Incrementing ORDER BY <n> until a response change appears infers the column count of the original query even when errors are suppressed.  _(merged 1 duplicate row(s))_
-  - **Disproof:** If every index from 1 upward yields an identical response, ORDER BY cannot be used for column counting and you must rely on UNION NULL probing.
-  - Sources: <https://cheatsheetseries.owasp.org/cheatsheets/SQL_Injection_Prevention_Cheat_Sheet.html> · <https://portswigger.net/web-security/sql-injection/union-attacks>
-- Input validation will not always prevent SQL injection, especially if you are required to support free-form text fields that could contain arbitrary characters.  _(merged 1 duplicate row(s))_
-  - **Disproof:** Refuted when: the value is bound as a parameter or written through the framework's own encoder, so the interpreter never sees attacker text as syntax. Settle it by running the identical request with and without that one control and diffing the response -- if the difference the claim predicts does not appear, the claim is false. Specifically, this is refuted if the behaviour described (“Input validation will not always prevent SQL injection, especially if you are re”) does not occur under a test that isolates that control.
-  - Sources: <https://cwe.mitre.org/data/definitions/89.html> · <https://owasp.org/www-community/attacks/SQL_Injection>
-- Inside an injected MS Access query, TOP and LAST act as row selectors, so the tester can cap or reverse the result set and page out a table's records instead of dumping it whole.  _(merged 1 duplicate row(s))_
-  - **Disproof:** TOP or LAST modifiers rejected as syntax by the same injection point, or accepted but leaving the returned rows unchanged, refute their use as row-selection controls.
-  - Sources: <https://sqlite.org/lang_expr.html> · <https://raw.githubusercontent.com/HackTricks-wiki/hacktricks/master/src/pentesting-web/sql-injection/ms-access-sql-injection.md>
-- MySQL schema and table names come out of a UNION SELECT with GROUP_CONCAT over information_schema, and the alternating letter case of the quoted keywords is the point: the enumeration has to be sent in mixed case so a filter matching keywords in one fixed case does not stop it.  _(merged 1 duplicate row(s))_
-  - **Disproof:** A filter that blocks the mixed-case spelling while letting the all-lowercase form through, or a UNION SELECT that returns no schema rows despite a working injection point, refutes this enumeration route.
-  - Sources: <https://cheatsheetseries.owasp.org/cheatsheets/SQL_Injection_Prevention_Cheat_Sheet.html> · <https://raw.githubusercontent.com/HackTricks-wiki/hacktricks/master/src/pentesting-web/sql-injection/mysql-injection/README.md>
-- Naming a target table turns the same UNION SELECT pattern into a column dictionary, so the tester moves from which tables exist to exactly which attributes the injected query can reference.  _(merged 1 duplicate row(s))_
-  - **Disproof:** The column enumeration coming back empty for a table that the same injection point can already read rows from refutes this metadata route.
-  - Sources: <https://cheatsheetseries.owasp.org/cheatsheets/SQL_Injection_Prevention_Cheat_Sheet.html> · <https://raw.githubusercontent.com/HackTricks-wiki/hacktricks/master/src/pentesting-web/sql-injection/mysql-injection/README.md>
-- On MSSQL a single injected UNION SELECT over information_schema.columns hands back the schema, table and column names of the current database at once, and on error-based vectors every selected expression has to carry an alias or the query will not come back.  _(merged 1 duplicate row(s))_
-  - **Disproof:** An error-based injected select that errors purely because an expression lacks an alias, or a schema enumeration that returns no rows despite a working injection point, refutes these requirements.
-  - Sources: <https://portswigger.net/web-security/sql-injection> · <https://raw.githubusercontent.com/HackTricks-wiki/hacktricks/master/src/pentesting-web/sql-injection/mssql-injection.md>
-- Once a UNION SELECT column count is aligned, the tester can read a chosen position out of a table with a wildcard select and never has to know the column's name, which is how data leaves the database once the injection point is confirmed.  _(merged 1 duplicate row(s))_
-  - **Disproof:** A wildcard select that returns nothing from a table known to be readable, or one that fails purely on a column-count mismatch, refutes the positional-access claim.
-  - Sources: <https://cwe.mitre.org/data/definitions/89.html> · <https://raw.githubusercontent.com/HackTricks-wiki/hacktricks/master/src/pentesting-web/sql-injection/README.md>
-- SQL injection is confirmed by a boolean differential: a condition that is always true returns the normal row count while the same condition forced false returns a different one.  _(merged 1 duplicate row(s))_
-  - **Disproof:** Refuted when the application returns an identical response for true and false conditions, which indicates the value is escaped, parameterised, or never reaches a SQL parser.
-  - Sources: <https://owasp.org/www-community/attacks/SQL_Injection> · <https://portswigger.net/web-security/sql-injection> · <https://raw.githubusercontent.com/Esther7171/HackTheBox-Writeups-Walkthroughs/main/Write-ups/Academy/05.%20Web%20Exploitation/25.%20SQL%20Injection%20Fundamentals/SQL%20Injection%20Fundamentals.md>
-- UNION SELECT NULL with increasing NULL counts finds the column count, then a string marker in each position finds a column type that can carry exfiltrated data.  _(merged 1 duplicate row(s))_
-  - **Disproof:** If the response is identical for wrong and correct NULL counts, the UNION column-count method is ineffective and you must use boolean or error-based inference.
-  - Sources: <https://raw.githubusercontent.com/OWASP/wstg/master/document/4-Web_Application_Security_Testing/07-Injection/05-SQL_Injection.md> · <https://portswigger.net/web-security/sql-injection/union-attacks>
-
-## Tests
-
-- MS Access hands the tester a file-existence oracle from inside the injection: point the database reference at a local file and the invalid-database-format error appears only when that file is really there, so file enumeration is driven by comparing errors across candidate paths.  _(merged 1 duplicate row(s))_
-  - **Disproof:** The invalid-format error appearing identically for names that do not exist, or never appearing for one that does, refutes the existence oracle.
-  - Sources: <https://sqlite.org/lang_expr.html> · <https://raw.githubusercontent.com/HackTricks-wiki/hacktricks/master/src/pentesting-web/sql-injection/ms-access-sql-injection.md>
-- On MSSQL the tester can read the live query text back through sys.dm_exec_requests joined to sys.dm_exec_sql_text, which is the way to confirm the injection really landed in the query and to see the surrounding SQL, with the server-level permission checked separately.  _(merged 1 duplicate row(s))_
-  - **Disproof:** The DMVs returning nothing, or returning a query that does not contain the injected syntax, refutes their use for reading back the currently executing SQL query.
-  - Sources: <https://portswigger.net/web-security/sql-injection> · <https://raw.githubusercontent.com/HackTricks-wiki/hacktricks/master/src/pentesting-web/sql-injection/mssql-injection.md>
-- To decide this case, observe: Establish a baseline with clearly invalid input such as a string where a number is expected, and check whether that also 500s.  _(merged 1 duplicate row(s))_
-  - **Disproof:** This test does not apply where the surrounding behaviour is unobservable -- for example when the response is identical in every case, or when the only evidence is server-side and not reflected to the requester. The originating rule (sqli.fp_rule.generic_500_not_sqli) states the full boundary.
-  - Sources: <https://raw.githubusercontent.com/OWASP/wstg/master/document/4-Web_Application_Security_Testing/07-Injection/05-SQL_Injection.md> · <https://portswigger.net/web-security/sql-injection/blind>
-- To decide this case, observe: For each candidate field, replay the true/false pair three times with all other parameters identical and diff status code, headers and body.  _(merged 1 duplicate row(s))_
-  - **Disproof:** This test does not apply where the surrounding behaviour is unobservable -- for example when the response is identical in every case, or when the only evidence is server-side and not reflected to the requester. The originating rule (sqli.validation.single_variable_differential) states the full boundary.
-  - Sources: <https://raw.githubusercontent.com/OWASP/wstg/v4.2/document/4-Web_Application_Security_Testing/07-Input_Validation_Testing/05-Testing_for_SQL_Injection.md> · <https://portswigger.net/web-security/sql-injection/blind>
-- When a blind SQL injection returns no data, the proof is made of timing: concatenate a deliberately slow operation into the SQL query and look for a repeatable jump in page-load time that the unmodified request does not show.  _(merged 1 duplicate row(s))_
-  - **Disproof:** A concatenated slow operation that leaves page-load time flat, or a delay that appears just as often on a control request carrying no injected syntax, refutes it as a blind SQL injection oracle.
-  - Sources: <https://cwe.mitre.org/data/definitions/89.html> · <https://raw.githubusercontent.com/HackTricks-wiki/hacktricks/master/src/pentesting-web/sql-injection/README.md>
-
-## Validation bar (how to prove it)
-
-- A SQLi finding is only validated when one variable changes and the response difference is reproducible and explainable by query logic.  _(merged 1 duplicate row(s))_
-  - **Disproof:** If the difference is non-deterministic, cache- or session-driven, or does not reverse when the condition is inverted, it is not a validated SQLi.
-  - Sources: <https://owasp.org/www-project-web-security-testing-guide/stable/4-Web_Application_Security_Testing/07-Input_Validation_Testing/05-Testing_for_SQL_Injection.html> · <https://raw.githubusercontent.com/OWASP/wstg/v4.2/document/4-Web_Application_Security_Testing/07-Input_Validation_Testing/05-Testing_for_SQL_Injection.md> · <https://portswigger.net/web-security/sql-injection/blind>
-- A boolean or time differential found while several parameters are being varied at once is not attributable to any of them, so the finding is only valid once the same differential reproduces with exactly one variable changed.  _(merged 1 duplicate row(s))_
-  - **Disproof:** The rule is a testing discipline, not a property of the vulnerability, so it is false as a statement about what constitutes a finding in cases where a different kind of evidence is available: an out-of-band callback from a payload that could only have been assembled by the database is attributable regardless of how many other parameters were in the request, because the callback proves the injected expression executed. It is also false where the endpoint exposes the generated SQL - a debug echo, a query log, an error page printing the statement - since the statement text itself settles where the value landed. And a differential can be attributable without single-variable isolation when the other parameters are held constant by construction, for example by fixing them from a captured baseline and varying only the target.
-  - Sources: <https://docs.djangoproject.com/en/5.0/topics/db/sql/> · <https://sqlite.org/lang_expr.html>
... (truncated)
```

## 2026-10-31 01:33 — 11 diff lines
- items: 0 (supported 0), FP rules 0, chains 0, state planned
- still missing: methodology, items, supported_items, fp_rules, chain

```diff
--- sqli@current
+++ sqli@new
@@ -11,7 +11,7 @@
 
 > surface `web` · CWE CWE-89 · OWASP A03:2021
 > evidence: 0 items, 0 supported, 0 FP rules, 0 chains
-> maturity: **planned** — missing: items, supported_items, fp_rules, chain
+> maturity: **planned** — missing: methodology, items, supported_items, fp_rules, chain
 
 
 
```

## 2026-10-31 06:41 — 94 diff lines
- items: 45 (supported 34), FP rules 12, chains 1, state mature

```diff
--- sqli@current
+++ sqli@new
@@ -10,7 +10,7 @@
      python -m wks.skillgen -->
 
 > surface `web` · CWE CWE-89 · OWASP A03:2021
-> evidence: 45 items, 45 supported, 14 FP rules, 1 chains
+> evidence: 45 items, 34 supported, 12 FP rules, 1 chains
 > maturity: **mature**
 
 Attacker-controlled input is concatenated into a SQL statement, so the query structure becomes attacker-controlled.
@@ -47,10 +47,10 @@
 - A UNION-based SQL injection is confirmed by matching the result-set column count through successively longer runs of NULL placeholders, and NULL is used as the filler because it type-checks in any column position and so maximises the chance the payload succeeds.  _(merged 1 duplicate row(s))_
   - **Disproof:** If no NULL-counted payload ever produces the extra result set or alters the response, the column count was never matched and the UNION injection is not demonstrated.
   - Sources: <https://cwe.mitre.org/data/definitions/89.html> · <https://docs.djangoproject.com/en/5.0/topics/db/sql/> · <https://kathan19.gitbook.io/howtohunt/sqli/sql_injection.md>
-- A boolean-based blind SQL injection is confirmed when the application's response changes based on a injected condition that is true versus one that is false, with no error or data returned.  _(merged 1 duplicate row(s))_
+- A boolean-based blind SQL injection is confirmed when the application's response changes based on a injected condition that is true versus one that is false, with no error or data returned.  _(merged 1 duplicate row(s))_ _(unverified)_
   - **Disproof:** The claim is false when the same request produces no behavioural change when the query is rewritten so the value is bound rather than concatenated, because then the condition was never evaluated by the database. It also fails if the observed difference is reproducible with the payload removed or with a syntactically identical but semantically neutral value, which points at response timing, caching, or application logic rather than injection.
   - Sources: <https://owasp.org/www-community/attacks/SQL_Injection> · <https://portswigger.net/web-security/sql-injection/blind>
-- A time-based blind SQL injection is confirmed when the response delay produced by injecting a SLEEP() predicate is measurable and reproducible, and stops when the condition is made false or when the value is bound.  _(merged 1 duplicate row(s))_
+- A time-based blind SQL injection is confirmed when the response delay produced by injecting a SLEEP() predicate is measurable and reproducible, and stops when the condition is made false or when the value is bound.  _(merged 1 duplicate row(s))_ _(unverified)_
   - **Disproof:** The claim is false when the observed delay is identical regardless of the condition, which means the database never evaluated the predicate, or when the delay is caused by the endpoint's own behaviour (slow query, saturation, upstream dependency) rather than by the injected predicate. It also fails when the payload is bound, since the function then receives a literal string and never sleeps.
   - Sources: <https://owasp.org/www-community/attacks/SQL_Injection> · <https://portswigger.net/web-security/sql-injection/blind>
 - An MSSQL injection point doubles as a privilege-reach probe: calling fn_my_permissions against the database and filtering on a named permission tells the tester which database-level grants the injected session actually holds before they plan any escalation.  _(merged 1 duplicate row(s))_
@@ -104,10 +104,10 @@
 - On MSSQL the tester can read the live query text back through sys.dm_exec_requests joined to sys.dm_exec_sql_text, which is the way to confirm the injection really landed in the query and to see the surrounding SQL, with the server-level permission checked separately.  _(merged 1 duplicate row(s))_
   - **Disproof:** The DMVs returning nothing, or returning a query that does not contain the injected syntax, refutes their use for reading back the currently executing SQL query.
   - Sources: <https://portswigger.net/web-security/sql-injection> · <https://raw.githubusercontent.com/HackTricks-wiki/hacktricks/master/src/pentesting-web/sql-injection/mssql-injection.md>
-- To decide this case, observe: Establish a baseline with clearly invalid input such as a string where a number is expected, and check whether that also 500s.  _(merged 1 duplicate row(s))_
+- To decide this case, observe: Establish a baseline with clearly invalid input such as a string where a number is expected, and check whether that also 500s.  _(merged 1 duplicate row(s))_ _(unverified)_
   - **Disproof:** This test does not apply where the surrounding behaviour is unobservable -- for example when the response is identical in every case, or when the only evidence is server-side and not reflected to the requester. The originating rule (sqli.fp_rule.generic_500_not_sqli) states the full boundary.
   - Sources: <https://raw.githubusercontent.com/OWASP/wstg/master/document/4-Web_Application_Security_Testing/07-Injection/05-SQL_Injection.md> · <https://portswigger.net/web-security/sql-injection/blind>
-- To decide this case, observe: For each candidate field, replay the true/false pair three times with all other parameters identical and diff status code, headers and body.  _(merged 1 duplicate row(s))_
+- To decide this case, observe: For each candidate field, replay the true/false pair three times with all other parameters identical and diff status code, headers and body.  _(merged 1 duplicate row(s))_ _(unverified)_
   - **Disproof:** This test does not apply where the surrounding behaviour is unobservable -- for example when the response is identical in every case, or when the only evidence is server-side and not reflected to the requester. The originating rule (sqli.validation.single_variable_differential) states the full boundary.
   - Sources: <https://raw.githubusercontent.com/OWASP/wstg/v4.2/document/4-Web_Application_Security_Testing/07-Input_Validation_Testing/05-Testing_for_SQL_Injection.md> · <https://portswigger.net/web-security/sql-injection/blind>
 - When a blind SQL injection returns no data, the proof is made of timing: concatenate a deliberately slow operation into the SQL query and look for a repeatable jump in page-load time that the unmodified request does not show.  _(merged 1 duplicate row(s))_
@@ -116,13 +116,13 @@
 
 ## Validation bar (how to prove it)
 
-- A SQLi finding is only validated when one variable changes and the response difference is reproducible and explainable by query logic.  _(merged 1 duplicate row(s))_
+- A SQLi finding is only validated when one variable changes and the response difference is reproducible and explainable by query logic.  _(merged 1 duplicate row(s))_ _(unverified)_
   - **Disproof:** If the difference is non-deterministic, cache- or session-driven, or does not reverse when the condition is inverted, it is not a validated SQLi.
   - Sources: <https://owasp.org/www-project-web-security-testing-guide/stable/4-Web_Application_Security_Testing/07-Input_Validation_Testing/05-Testing_for_SQL_Injection.html> · <https://raw.githubusercontent.com/OWASP/wstg/v4.2/document/4-Web_Application_Security_Testing/07-Input_Validation_Testing/05-Testing_for_SQL_Injection.md> · <https://portswigger.net/web-security/sql-injection/blind>
 - A boolean or time differential found while several parameters are being varied at once is not attributable to any of them, so the finding is only valid once the same differential reproduces with exactly one variable changed.  _(merged 1 duplicate row(s))_
   - **Disproof:** The rule is a testing discipline, not a property of the vulnerability, so it is false as a statement about what constitutes a finding in cases where a different kind of evidence is available: an out-of-band callback from a payload that could only have been assembled by the database is attributable regardless of how many other parameters were in the request, because the callback proves the injected expression executed. It is also false where the endpoint exposes the generated SQL - a debug echo, a query log, an error page printing the statement - since the statement text itself settles where the value landed. And a differential can be attributable without single-variable isolation when the other parameters are held constant by construction, for example by fixing them from a captured baseline and varying only the target.
   - Sources: <https://docs.djangoproject.com/en/5.0/topics/db/sql/> · <https://sqlite.org/lang_expr.html>
-- A second-order SQL injection is confirmed when attacker-controlled data is safely stored after one query and later reaches a second, differently-constructed query where it is concatenated unescaped, producing an injection only on the second access.  _(merged 1 duplicate row(s))_
+- A second-order SQL injection is confirmed when attacker-controlled data is safely stored after one query and later reaches a second, differently-constructed query where it is concatenated unescaped, producing an injection only on the second access.  _(merged 1 duplicate row(s))_ _(unverified)_
   - **Disproof:** The claim is false when the second query also binds the value or applies escaping at the point of use, because then the stored data never becomes statement text. It is also false when the stored value is not actually read by the second query, or when any transformation (escaping, type casting, query rewriting) applied to the value at read time neutralises the payload.
   - Sources: <https://owasp.org/www-community/attacks/SQL_Injection> · <https://portswigger.net/web-security/sql-injection/blind>
 - A verbose database error that echoes the constructed query turns blind injection visible and independently confirms the injection point's context.  _(merged 1 duplicate row(s))_
@@ -134,13 +134,13 @@
 
 ## False-positive rules (when to reject it)
 
-- A 500 or generic error page triggered by malformed input alone is not SQLi evidence; many apps error identically for any invalid value.  _(merged 1 duplicate row(s))_
+- A 500 or generic error page triggered by malformed input alone is not SQLi evidence; many apps error identically for any invalid value.  _(merged 1 duplicate row(s))_ _(unverified)_
   - **Disproof:** If plain type-mismatch input produces the identical 500 response with no SQL-specific text, the 500 is an input-validation artefact, not SQLi.
   - Sources: <https://raw.githubusercontent.com/OWASP/wstg/master/document/4-Web_Application_Security_Testing/07-Injection/05-SQL_Injection.md> · <https://portswigger.net/web-security/sql-injection/blind>
 - A dollar-quoted string in PostgreSQL is a closed literal that ignores backslashes and dollar signs, so a payload containing $tag$ delimiters only becomes dangerous if the attacker can supply the tag the application's own quoting chose.  _(merged 1 duplicate row(s))_
   - **Disproof:** The claim is false when the tag is attacker-controlled or absent in a way that lets the payload close the literal - an unquoted dollar-quoted string in a function definition whose body is built from user input lets an attacker insert their own $q$...$q$ and terminate it, and PostgreSQL's own example of a nested $q$[\t\r\n\v\\]$q$ inside $function$ ... $function$ shows exactly that shape. It also fails if the payload is delivered outside the dollar-quoted region - a second statement concatenated after the function body, or a value reaching a non-dollar-quoted parameter such as a dynamic EXECUTE string, is ordinary SQL and the standard payloads apply.
   - Sources: <https://docs.djangoproject.com/en/5.0/topics/db/sql/> · <https://www.postgresql.org/docs/current/sql-syntax-lexical.html>
-- A request that returns a database error echoing the caller's own input, on a code path that passes that input as a bound parameter, is a verbose-error disclosure and not SQL injection - the value never entered the statement text.  _(merged 1 duplicate row(s))_
+- A request that returns a database error echoing the caller's own input, on a code path that passes that input as a bound parameter, is a verbose-error disclosure and not SQL injection - the value never entered the statement text.  _(merged 1 duplicate row(s))_ _(unverified)_
   - **Disproof:** The claim is false when the same request also produces a behaviour change with the quote removed - a boolean differential, a time delta, or an OAST callback - because then the value is reaching the statement text by some other route even if this particular call site is parameterised. Parameterisation is per call site, and applications routinely have a safe read path and an unsafe report, export, or search path on the same endpoint. It is also false when the framework's own string escaping is being relied on rather than binding: a helper that quotes and doubles the value correctly still yields a value that will break the moment a second, unescaped layer concatenates it, so the presence of quotes in the output is not evidence of safety at the statement level.
   - Sources: <https://docs.djangoproject.com/en/5.0/topics/db/sql/> · <https://sqlite.org/lang_expr.html>
 - Under a properly parameterized ORM/HQL query, quote and comment payloads are matched as literal data, so their failure to inject is a true negative, not a missed bug.  _(merged 1 duplicate row(s))_
@@ -149,7 +149,7 @@
 
 ## Evidence requirements
 
-- A convincing observation for this class is: For each candidate field, replay the true/false pair three times with all other parameters identical and diff status code, headers and body.  _(merged 1 duplicate row(s))_
+- A convincing observation for this class is: For each candidate field, replay the true/false pair three times with all other parameters identical and diff status code, headers and body.  _(merged 1 duplicate row(s))_ _(unverified)_
   - **Disproof:** Not evidence when the observable cannot be produced at all -- blind, server-side-only, or identical-in-every-case behaviour leaves nothing to show. The originating rule (sqli.validation.single_variable_differential) states the full boundary.
   - Sources: <https://raw.githubusercontent.com/OWASP/wstg/v4.2/document/4-Web_Application_Security_Testing/07-Input_Validation_Testing/05-Testing_for_SQL_Injection.md> · <https://portswigger.net/web-security/sql-injection/blind>
 
@@ -167,13 +167,13 @@
 
 ## Defence bypasses
 
-- A SQL injection in an authentication query can bypass login entirely, including two-factor authentication, by changing the logic so a true condition is always returned.  _(merged 1 duplicate row(s))_
+- A SQL injection in an authentication query can bypass login entirely, including two-factor authentication, by changing the logic so a true condition is always returned.  _(merged 1 duplicate row(s))_ _(unverified)_
   - **Disproof:** The claim is refuted when the application re-queries the database with the username and password as distinct bound parameters, or when a second, independent verification step (password hash comparison, TOTP check) is performed outside the injectable statement. A login that returns the raw SQL error instead of an authenticated page does not demonstrate bypass.
   - Sources: <https://owasp.org/www-community/attacks/SQL_Injection> · <https://portswigger.net/web-security/sql-injection/blind>
 - HTTP parameter pollution lets an attacker bypass a web application firewall or input filter by encoding separators or distributing the injection across multiple parameters, so the same value never reaches the filter.  _(merged 1 duplicate row(s))_
   - **Disproof:** The claim is false when the application parses the request into a safe data structure, binds all values, and never concatenates user input into a SQL string, because in that case no parameter layout can produce injection. It is also false when the WAF or filter normalises the request in the same way the application does, so the same decoded token still appears.
   - Sources: <https://owasp.org/www-community/SQL_Injection_Prevention_Cheat_Sheet> · <https://portswigger.net/web-security/sql-injection/blind>
-- WAFs that normalize, case-filter or over-clean requests can be bypassed by comment-splitting, mixed case, encoding and parameter pollution.  _(merged 1 duplicate row(s))_
+- WAFs that normalize, case-filter or over-clean requests can be bypassed by comment-splitting, mixed case, encoding and parameter pollution.  _(merged 1 duplicate row(s))_ _(unverified)_
   - **Disproof:** If every encoded, case-varied and split variant is rejected identically and no differential response appears, the block is likely enforced downstream of the WAF, not by it.
   - Sources: <https://community.owasp.org/attacks/SQL_Injection_Bypassing_WAF> · <https://portswigger.net/web-security/sql-injection>
 
```

## 2026-11-01 06:10 — 227 diff lines
- items: 1 (supported 0), FP rules 0, chains 0, state researching
- still missing: methodology, items, supported_items, fp_rules, chain

```diff
--- sqli@current
+++ sqli@new
@@ -9,219 +9,15 @@
      Edit the rows (or ingest better research) and re-run:
      python -m wks.skillgen -->
 
-> surface `web` · CWE CWE-89 · OWASP A03:2021
-> evidence: 45 items, 34 supported, 12 FP rules, 1 chains
-> maturity: **mature**
+> surface `web` · CWE — · OWASP —
+> evidence: 1 items, 0 supported, 0 FP rules, 0 chains
+> maturity: **researching** — missing: methodology, items, supported_items, fp_rules, chain
 
-Attacker-controlled input is concatenated into a SQL statement, so the query structure becomes attacker-controlled.
-
-**Also called:** sql injection, sqli, second order sql injection, nosql injection operator
-
-
-## Prerequisites (do not start without these)
-
-- Any request-controllable value that reaches a SQL query is a candidate injection point, including JSON/XML bodies, cookies and headers, not just GET parameters.  _(merged 1 duplicate row(s))_
-  - **Disproof:** If a field's value is provably never used in any query (e.g. purely client-side sorting or CSRF tokens), it cannot be an injection point.
-  - Sources: <https://raw.githubusercontent.com/OWASP/wstg/master/document/4-Web_Application_Security_Testing/07-Injection/05-SQL_Injection.md> · <https://portswigger.net/web-security/sql-injection>
-- Extraction on MS Access is gated on naming a real column such as username, so the guess-and-check step on column names comes before any value can be pulled out of the database through the injection.  _(merged 1 duplicate row(s))_
-  - **Disproof:** Reading a value out of MS Access with no valid column name in the injected query, or a fabricated column name returning data, refutes this ordering.
-  - Sources: <https://sqlite.org/lang_expr.html> · <https://raw.githubusercontent.com/HackTricks-wiki/hacktricks/master/src/pentesting-web/sql-injection/ms-access-sql-injection.md>
-- Prepared/parameterized statements force the DB to separate code from data, so bind-variable queries are the baseline you must establish before treating quote errors as SQLi.  _(merged 1 duplicate row(s))_
-  - **Disproof:** If the query string is built by concatenation at runtime even when a parameterized API exists elsewhere, the endpoint is not parameterized.
-  - Sources: <https://cheatsheetseries.owasp.org/cheatsheets/SQL_Injection_Prevention_Cheat_Sheet.html> · <https://cwe.mitre.org/data/definitions/89.html>
-
-## Recon signals (where to look)
-
-- A single quote or a paired OR 1=1 / OR 1=2 pair producing a repeatable response difference is the primary first-order SQLi signal.  _(merged 1 duplicate row(s))_
-  - **Disproof:** If the quote and both boolean twins produce byte-identical responses, the field shows no first-order SQLi signal.
-  - Sources: <https://raw.githubusercontent.com/OWASP/wstg/master/document/4-Web_Application_Security_Testing/07-Injection/05-SQL_Injection.md> · <https://portswigger.net/web-security/sql-injection>
-- If the app neither returns query results nor error differences nor timing changes, the query may run asynchronously; absence of in-band signal does not mean absence of SQLi.  _(merged 1 duplicate row(s))_
-  - **Disproof:** If an OAST payload produces no collaborator/DNS callback and conditional time delays stay within baseline jitter, the parameter is very likely not injectable.
-  - Sources: <https://owasp.org/www-project-web-security-testing-guide/stable/4-Web_Application_Security_Testing/07-Input_Validation_Testing/05-Testing_for_SQL_Injection.html> · <https://raw.githubusercontent.com/OWASP/wstg/v4.2/document/4-Web_Application_Security_Testing/07-Input_Validation_Testing/05-Testing_for_SQL_Injection.md> · <https://portswigger.net/web-security/sql-injection/blind>
 
 ## Techniques (what to change)
 
-- A UNION-based SQL injection is confirmed by matching the number of columns in the injected result set against the original query using successive NULL placeholders, then selecting data from other tables.  _(merged 1 duplicate row(s))_
-  - **Disproof:** The claim is false when the original query always returns a fixed number of columns unrelated to the injection point, when the database does not expose the metadata used (a closed source or heavily restricted RDBMS), or when the response is identical across every NULL-count probe, which proves no UNION result set reached the output.
-  - Sources: <https://portswigger.net/web-security/sql-injection/union-based> · <https://www.w3schools.com/sql/sql_union.asp>
-- A UNION-based SQL injection is confirmed by matching the result-set column count through successively longer runs of NULL placeholders, and NULL is used as the filler because it type-checks in any column position and so maximises the chance the payload succeeds.  _(merged 1 duplicate row(s))_
-  - **Disproof:** If no NULL-counted payload ever produces the extra result set or alters the response, the column count was never matched and the UNION injection is not demonstrated.
-  - Sources: <https://cwe.mitre.org/data/definitions/89.html> · <https://docs.djangoproject.com/en/5.0/topics/db/sql/> · <https://kathan19.gitbook.io/howtohunt/sqli/sql_injection.md>
-- A boolean-based blind SQL injection is confirmed when the application's response changes based on a injected condition that is true versus one that is false, with no error or data returned.  _(merged 1 duplicate row(s))_ _(unverified)_
-  - **Disproof:** The claim is false when the same request produces no behavioural change when the query is rewritten so the value is bound rather than concatenated, because then the condition was never evaluated by the database. It also fails if the observed difference is reproducible with the payload removed or with a syntactically identical but semantically neutral value, which points at response timing, caching, or application logic rather than injection.
-  - Sources: <https://owasp.org/www-community/attacks/SQL_Injection> · <https://portswigger.net/web-security/sql-injection/blind>
-- A time-based blind SQL injection is confirmed when the response delay produced by injecting a SLEEP() predicate is measurable and reproducible, and stops when the condition is made false or when the value is bound.  _(merged 1 duplicate row(s))_ _(unverified)_
-  - **Disproof:** The claim is false when the observed delay is identical regardless of the condition, which means the database never evaluated the predicate, or when the delay is caused by the endpoint's own behaviour (slow query, saturation, upstream dependency) rather than by the injected predicate. It also fails when the payload is bound, since the function then receives a literal string and never sleeps.
-  - Sources: <https://owasp.org/www-community/attacks/SQL_Injection> · <https://portswigger.net/web-security/sql-injection/blind>
-- An MSSQL injection point doubles as a privilege-reach probe: calling fn_my_permissions against the database and filtering on a named permission tells the tester which database-level grants the injected session actually holds before they plan any escalation.  _(merged 1 duplicate row(s))_
-  - **Disproof:** fn_my_permissions returning no rows, or an empty grant set, for a login that demonstrably holds the named database permission refutes it as a reach check.
-  - Sources: <https://portswigger.net/web-security/sql-injection> · <https://raw.githubusercontent.com/HackTricks-wiki/hacktricks/master/src/pentesting-web/sql-injection/mssql-injection.md>
-- Blind boolean injection extracts arbitrary values one character at a time by making the app's visible behaviour depend on a single condition.  _(merged 1 duplicate row(s))_
-  - **Disproof:** If the application's behaviour is identical whether the condition is true or false, boolean extraction is impossible and time-based or OAST is required.
-  - Sources: <https://owasp.org/www-project-web-security-testing-guide/stable/4-Web_Application_Security_Testing/07-Input_Validation_Testing/05-Testing_for_SQL_Injection.html> · <https://raw.githubusercontent.com/OWASP/wstg/v4.2/document/4-Web_Application_Security_Testing/07-Input_Validation_Testing/05-Testing_for_SQL_Injection.md> · <https://portswigger.net/web-security/sql-injection/blind>
-- Error-based SQL injection extracts data by triggering database error messages that echo the injected value or the attacked metadata, and is confirmed when an error response reveals a table, column, or value that was not present in the baseline.  _(merged 1 duplicate row(s))_
-  - **Disproof:** The claim is false when the error message only reports a syntax or constraint violation with no embedded target value, or when the same error appears before any injection is attempted, which means the message is a framework default rather than a data channel. If the value only ever appears in the application's own echoed input and never in a database error, the finding is verbose errors, not error-based injection.
-  - Sources: <https://cheatsheetseries.owasp.org/cheatsheets/SQL_Injection_Prevention_Cheat_Sheet.html> · <https://portswigger.net/web-security/sql-injection/blind>
-- For example, consider using persistence layers such as Hibernate or Enterprise Java Beans, which can provide significant protection against SQL injection if used properly.  _(merged 1 duplicate row(s))_
-  - **Disproof:** Refuted when: the value is bound as a parameter or written through the framework's own encoder, so the interpreter never sees attacker text as syntax. Settle it by running the identical request with and without that one control and diffing the response -- if the difference the claim predicts does not appear, the claim is false. Specifically, this is refuted if the behaviour described (“For example, consider using persistence layers such as Hibernate or Enterprise J”) does not occur under a test that isolates that control.
-  - Sources: <https://cwe.mitre.org/data/definitions/89.html> · <https://owasp.org/www-community/attacks/SQL_Injection>
-- If authorization information is held in a SQL database, it may be possible to change this information through the successful exploitation of a SQL injection vulnerability.  _(merged 1 duplicate row(s))_
-  - **Disproof:** Refuted when: the value is bound as a parameter or written through the framework's own encoder, so the interpreter never sees attacker text as syntax. Settle it by running the identical request with and without that one control and diffing the response -- if the difference the claim predicts does not appear, the claim is false. Specifically, this is refuted if the behaviour described (“If authorization information is held in a SQL database, it may be possible to ch”) does not occur under a test that isolates that control.
-  - Sources: <https://cwe.mitre.org/data/definitions/89.html> · <https://owasp.org/www-community/attacks/SQL_Injection>
-- Incrementing ORDER BY <n> until a response change appears infers the column count of the original query even when errors are suppressed.  _(merged 1 duplicate row(s))_
-  - **Disproof:** If every index from 1 upward yields an identical response, ORDER BY cannot be used for column counting and you must rely on UNION NULL probing.
-  - Sources: <https://cheatsheetseries.owasp.org/cheatsheets/SQL_Injection_Prevention_Cheat_Sheet.html> · <https://portswigger.net/web-security/sql-injection/union-attacks>
-- Input validation will not always prevent SQL injection, especially if you are required to support free-form text fields that could contain arbitrary characters.  _(merged 1 duplicate row(s))_
-  - **Disproof:** Refuted when: the value is bound as a parameter or written through the framework's own encoder, so the interpreter never sees attacker text as syntax. Settle it by running the identical request with and without that one control and diffing the response -- if the difference the claim predicts does not appear, the claim is false. Specifically, this is refuted if the behaviour described (“Input validation will not always prevent SQL injection, especially if you are re”) does not occur under a test that isolates that control.
-  - Sources: <https://cwe.mitre.org/data/definitions/89.html> · <https://owasp.org/www-community/attacks/SQL_Injection>
-- Inside an injected MS Access query, TOP and LAST act as row selectors, so the tester can cap or reverse the result set and page out a table's records instead of dumping it whole.  _(merged 1 duplicate row(s))_
-  - **Disproof:** TOP or LAST modifiers rejected as syntax by the same injection point, or accepted but leaving the returned rows unchanged, refute their use as row-selection controls.
-  - Sources: <https://sqlite.org/lang_expr.html> · <https://raw.githubusercontent.com/HackTricks-wiki/hacktricks/master/src/pentesting-web/sql-injection/ms-access-sql-injection.md>
-- MySQL schema and table names come out of a UNION SELECT with GROUP_CONCAT over information_schema, and the alternating letter case of the quoted keywords is the point: the enumeration has to be sent in mixed case so a filter matching keywords in one fixed case does not stop it.  _(merged 1 duplicate row(s))_
-  - **Disproof:** A filter that blocks the mixed-case spelling while letting the all-lowercase form through, or a UNION SELECT that returns no schema rows despite a working injection point, refutes this enumeration route.
-  - Sources: <https://cheatsheetseries.owasp.org/cheatsheets/SQL_Injection_Prevention_Cheat_Sheet.html> · <https://raw.githubusercontent.com/HackTricks-wiki/hacktricks/master/src/pentesting-web/sql-injection/mysql-injection/README.md>
-- Naming a target table turns the same UNION SELECT pattern into a column dictionary, so the tester moves from which tables exist to exactly which attributes the injected query can reference.  _(merged 1 duplicate row(s))_
-  - **Disproof:** The column enumeration coming back empty for a table that the same injection point can already read rows from refutes this metadata route.
-  - Sources: <https://cheatsheetseries.owasp.org/cheatsheets/SQL_Injection_Prevention_Cheat_Sheet.html> · <https://raw.githubusercontent.com/HackTricks-wiki/hacktricks/master/src/pentesting-web/sql-injection/mysql-injection/README.md>
-- On MSSQL a single injected UNION SELECT over information_schema.columns hands back the schema, table and column names of the current database at once, and on error-based vectors every selected expression has to carry an alias or the query will not come back.  _(merged 1 duplicate row(s))_
-  - **Disproof:** An error-based injected select that errors purely because an expression lacks an alias, or a schema enumeration that returns no rows despite a working injection point, refutes these requirements.
-  - Sources: <https://portswigger.net/web-security/sql-injection> · <https://raw.githubusercontent.com/HackTricks-wiki/hacktricks/master/src/pentesting-web/sql-injection/mssql-injection.md>
-- Once a UNION SELECT column count is aligned, the tester can read a chosen position out of a table with a wildcard select and never has to know the column's name, which is how data leaves the database once the injection point is confirmed.  _(merged 1 duplicate row(s))_
-  - **Disproof:** A wildcard select that returns nothing from a table known to be readable, or one that fails purely on a column-count mismatch, refutes the positional-access claim.
-  - Sources: <https://cwe.mitre.org/data/definitions/89.html> · <https://raw.githubusercontent.com/HackTricks-wiki/hacktricks/master/src/pentesting-web/sql-injection/README.md>
-- SQL injection is confirmed by a boolean differential: a condition that is always true returns the normal row count while the same condition forced false returns a different one.  _(merged 1 duplicate row(s))_
-  - **Disproof:** Refuted when the application returns an identical response for true and false conditions, which indicates the value is escaped, parameterised, or never reaches a SQL parser.
-  - Sources: <https://owasp.org/www-community/attacks/SQL_Injection> · <https://portswigger.net/web-security/sql-injection> · <https://raw.githubusercontent.com/Esther7171/HackTheBox-Writeups-Walkthroughs/main/Write-ups/Academy/05.%20Web%20Exploitation/25.%20SQL%20Injection%20Fundamentals/SQL%20Injection%20Fundamentals.md>
-- UNION SELECT NULL with increasing NULL counts finds the column count, then a string marker in each position finds a column type that can carry exfiltrated data.  _(merged 1 duplicate row(s))_
-  - **Disproof:** If the response is identical for wrong and correct NULL counts, the UNION column-count method is ineffective and you must use boolean or error-based inference.
-  - Sources: <https://raw.githubusercontent.com/OWASP/wstg/master/document/4-Web_Application_Security_Testing/07-Injection/05-SQL_Injection.md> · <https://portswigger.net/web-security/sql-injection/union-attacks>
-
-## Tests
-
-- MS Access hands the tester a file-existence oracle from inside the injection: point the database reference at a local file and the invalid-database-format error appears only when that file is really there, so file enumeration is driven by comparing errors across candidate paths.  _(merged 1 duplicate row(s))_
-  - **Disproof:** The invalid-format error appearing identically for names that do not exist, or never appearing for one that does, refutes the existence oracle.
-  - Sources: <https://sqlite.org/lang_expr.html> · <https://raw.githubusercontent.com/HackTricks-wiki/hacktricks/master/src/pentesting-web/sql-injection/ms-access-sql-injection.md>
-- On MSSQL the tester can read the live query text back through sys.dm_exec_requests joined to sys.dm_exec_sql_text, which is the way to confirm the injection really landed in the query and to see the surrounding SQL, with the server-level permission checked separately.  _(merged 1 duplicate row(s))_
-  - **Disproof:** The DMVs returning nothing, or returning a query that does not contain the injected syntax, refutes their use for reading back the currently executing SQL query.
-  - Sources: <https://portswigger.net/web-security/sql-injection> · <https://raw.githubusercontent.com/HackTricks-wiki/hacktricks/master/src/pentesting-web/sql-injection/mssql-injection.md>
-- To decide this case, observe: Establish a baseline with clearly invalid input such as a string where a number is expected, and check whether that also 500s.  _(merged 1 duplicate row(s))_ _(unverified)_
-  - **Disproof:** This test does not apply where the surrounding behaviour is unobservable -- for example when the response is identical in every case, or when the only evidence is server-side and not reflected to the requester. The originating rule (sqli.fp_rule.generic_500_not_sqli) states the full boundary.
-  - Sources: <https://raw.githubusercontent.com/OWASP/wstg/master/document/4-Web_Application_Security_Testing/07-Injection/05-SQL_Injection.md> · <https://portswigger.net/web-security/sql-injection/blind>
-- To decide this case, observe: For each candidate field, replay the true/false pair three times with all other parameters identical and diff status code, headers and body.  _(merged 1 duplicate row(s))_ _(unverified)_
-  - **Disproof:** This test does not apply where the surrounding behaviour is unobservable -- for example when the response is identical in every case, or when the only evidence is server-side and not reflected to the requester. The originating rule (sqli.validation.single_variable_differential) states the full boundary.
-  - Sources: <https://raw.githubusercontent.com/OWASP/wstg/v4.2/document/4-Web_Application_Security_Testing/07-Input_Validation_Testing/05-Testing_for_SQL_Injection.md> · <https://portswigger.net/web-security/sql-injection/blind>
-- When a blind SQL injection returns no data, the proof is made of timing: concatenate a deliberately slow operation into the SQL query and look for a repeatable jump in page-load time that the unmodified request does not show.  _(merged 1 duplicate row(s))_
-  - **Disproof:** A concatenated slow operation that leaves page-load time flat, or a delay that appears just as often on a control request carrying no injected syntax, refutes it as a blind SQL injection oracle.
-  - Sources: <https://cwe.mitre.org/data/definitions/89.html> · <https://raw.githubusercontent.com/HackTricks-wiki/hacktricks/master/src/pentesting-web/sql-injection/README.md>
-
-## Validation bar (how to prove it)
-
-- A SQLi finding is only validated when one variable changes and the response difference is reproducible and explainable by query logic.  _(merged 1 duplicate row(s))_ _(unverified)_
-  - **Disproof:** If the difference is non-deterministic, cache- or session-driven, or does not reverse when the condition is inverted, it is not a validated SQLi.
-  - Sources: <https://owasp.org/www-project-web-security-testing-guide/stable/4-Web_Application_Security_Testing/07-Input_Validation_Testing/05-Testing_for_SQL_Injection.html> · <https://raw.githubusercontent.com/OWASP/wstg/v4.2/document/4-Web_Application_Security_Testing/07-Input_Validation_Testing/05-Testing_for_SQL_Injection.md> · <https://portswigger.net/web-security/sql-injection/blind>
-- A boolean or time differential found while several parameters are being varied at once is not attributable to any of them, so the finding is only valid once the same differential reproduces with exactly one variable changed.  _(merged 1 duplicate row(s))_
... (truncated)
```

## 2026-11-01 06:12 — 13 diff lines
- items: 1 (supported 0), FP rules 0, chains 0, state researching
- still missing: methodology, items, supported_items, fp_rules, chain

```diff
--- sqli@current
+++ sqli@new
@@ -16,8 +16,8 @@
 
 ## Techniques (what to change)
 
-- A true predicate returns more rows than a false one.  _(merged 1 duplicate row(s))_ _(unverified)_
-  - Sources: <https://example.com/a>
+- The endpoint returned a different number of rows for a true predicate than for the corresponding false predicate. The difference was stable across repeated requests, which proves the boolean condition is evaluated by the database rather than by the application. This confirmed a blind SQL injection vulnerability.  _(merged 1 duplicate row(s))_ _(unverified)_
+  - Sources: <https://example.com/advisories/blind-sqli-search>
 
 
 ## Hunt procedure
```

## 2026-11-01 06:22 — 228 diff lines
- items: 45 (supported 34), FP rules 12, chains 1, state mature

```diff
--- sqli@current
+++ sqli@new
@@ -9,15 +9,219 @@
      Edit the rows (or ingest better research) and re-run:
      python -m wks.skillgen -->
 
-> surface `web` · CWE — · OWASP —
-> evidence: 1 items, 0 supported, 0 FP rules, 0 chains
-> maturity: **researching** — missing: methodology, items, supported_items, fp_rules, chain
-
+> surface `web` · CWE CWE-89 · OWASP A03:2021
+> evidence: 45 items, 34 supported, 12 FP rules, 1 chains
+> maturity: **mature**
+
+Attacker-controlled input is concatenated into a SQL statement, so the query structure becomes attacker-controlled.
+
+**Also called:** sql injection, sqli, second order sql injection, nosql injection operator
+
+
+## Prerequisites (do not start without these)
+
+- Any request-controllable value that reaches a SQL query is a candidate injection point, including JSON/XML bodies, cookies and headers, not just GET parameters.  _(merged 1 duplicate row(s))_
+  - **Disproof:** If a field's value is provably never used in any query (e.g. purely client-side sorting or CSRF tokens), it cannot be an injection point.
+  - Sources: <https://raw.githubusercontent.com/OWASP/wstg/master/document/4-Web_Application_Security_Testing/07-Injection/05-SQL_Injection.md> · <https://portswigger.net/web-security/sql-injection>
+- Extraction on MS Access is gated on naming a real column such as username, so the guess-and-check step on column names comes before any value can be pulled out of the database through the injection.  _(merged 1 duplicate row(s))_
+  - **Disproof:** Reading a value out of MS Access with no valid column name in the injected query, or a fabricated column name returning data, refutes this ordering.
+  - Sources: <https://sqlite.org/lang_expr.html> · <https://raw.githubusercontent.com/HackTricks-wiki/hacktricks/master/src/pentesting-web/sql-injection/ms-access-sql-injection.md>
+- Prepared/parameterized statements force the DB to separate code from data, so bind-variable queries are the baseline you must establish before treating quote errors as SQLi.  _(merged 1 duplicate row(s))_
+  - **Disproof:** If the query string is built by concatenation at runtime even when a parameterized API exists elsewhere, the endpoint is not parameterized.
+  - Sources: <https://cheatsheetseries.owasp.org/cheatsheets/SQL_Injection_Prevention_Cheat_Sheet.html> · <https://cwe.mitre.org/data/definitions/89.html>
+
+## Recon signals (where to look)
+
+- A single quote or a paired OR 1=1 / OR 1=2 pair producing a repeatable response difference is the primary first-order SQLi signal.  _(merged 1 duplicate row(s))_
+  - **Disproof:** If the quote and both boolean twins produce byte-identical responses, the field shows no first-order SQLi signal.
+  - Sources: <https://raw.githubusercontent.com/OWASP/wstg/master/document/4-Web_Application_Security_Testing/07-Injection/05-SQL_Injection.md> · <https://portswigger.net/web-security/sql-injection>
+- If the app neither returns query results nor error differences nor timing changes, the query may run asynchronously; absence of in-band signal does not mean absence of SQLi.  _(merged 1 duplicate row(s))_
+  - **Disproof:** If an OAST payload produces no collaborator/DNS callback and conditional time delays stay within baseline jitter, the parameter is very likely not injectable.
+  - Sources: <https://owasp.org/www-project-web-security-testing-guide/stable/4-Web_Application_Security_Testing/07-Input_Validation_Testing/05-Testing_for_SQL_Injection.html> · <https://raw.githubusercontent.com/OWASP/wstg/v4.2/document/4-Web_Application_Security_Testing/07-Input_Validation_Testing/05-Testing_for_SQL_Injection.md> · <https://portswigger.net/web-security/sql-injection/blind>
 
 ## Techniques (what to change)
 
-- The endpoint returned a different number of rows for a true predicate than for the corresponding false predicate. The difference was stable across repeated requests, which proves the boolean condition is evaluated by the database rather than by the application. This confirmed a blind SQL injection vulnerability.  _(merged 1 duplicate row(s))_ _(unverified)_
-  - Sources: <https://example.com/advisories/blind-sqli-search>
+- A UNION-based SQL injection is confirmed by matching the number of columns in the injected result set against the original query using successive NULL placeholders, then selecting data from other tables.  _(merged 1 duplicate row(s))_
+  - **Disproof:** The claim is false when the original query always returns a fixed number of columns unrelated to the injection point, when the database does not expose the metadata used (a closed source or heavily restricted RDBMS), or when the response is identical across every NULL-count probe, which proves no UNION result set reached the output.
+  - Sources: <https://portswigger.net/web-security/sql-injection/union-based> · <https://www.w3schools.com/sql/sql_union.asp>
+- A UNION-based SQL injection is confirmed by matching the result-set column count through successively longer runs of NULL placeholders, and NULL is used as the filler because it type-checks in any column position and so maximises the chance the payload succeeds.  _(merged 1 duplicate row(s))_
+  - **Disproof:** If no NULL-counted payload ever produces the extra result set or alters the response, the column count was never matched and the UNION injection is not demonstrated.
+  - Sources: <https://cwe.mitre.org/data/definitions/89.html> · <https://docs.djangoproject.com/en/5.0/topics/db/sql/> · <https://kathan19.gitbook.io/howtohunt/sqli/sql_injection.md>
+- A boolean-based blind SQL injection is confirmed when the application's response changes based on a injected condition that is true versus one that is false, with no error or data returned.  _(merged 1 duplicate row(s))_ _(unverified)_
+  - **Disproof:** The claim is false when the same request produces no behavioural change when the query is rewritten so the value is bound rather than concatenated, because then the condition was never evaluated by the database. It also fails if the observed difference is reproducible with the payload removed or with a syntactically identical but semantically neutral value, which points at response timing, caching, or application logic rather than injection.
+  - Sources: <https://owasp.org/www-community/attacks/SQL_Injection> · <https://portswigger.net/web-security/sql-injection/blind>
+- A time-based blind SQL injection is confirmed when the response delay produced by injecting a SLEEP() predicate is measurable and reproducible, and stops when the condition is made false or when the value is bound.  _(merged 1 duplicate row(s))_ _(unverified)_
+  - **Disproof:** The claim is false when the observed delay is identical regardless of the condition, which means the database never evaluated the predicate, or when the delay is caused by the endpoint's own behaviour (slow query, saturation, upstream dependency) rather than by the injected predicate. It also fails when the payload is bound, since the function then receives a literal string and never sleeps.
+  - Sources: <https://owasp.org/www-community/attacks/SQL_Injection> · <https://portswigger.net/web-security/sql-injection/blind>
+- An MSSQL injection point doubles as a privilege-reach probe: calling fn_my_permissions against the database and filtering on a named permission tells the tester which database-level grants the injected session actually holds before they plan any escalation.  _(merged 1 duplicate row(s))_
+  - **Disproof:** fn_my_permissions returning no rows, or an empty grant set, for a login that demonstrably holds the named database permission refutes it as a reach check.
+  - Sources: <https://portswigger.net/web-security/sql-injection> · <https://raw.githubusercontent.com/HackTricks-wiki/hacktricks/master/src/pentesting-web/sql-injection/mssql-injection.md>
+- Blind boolean injection extracts arbitrary values one character at a time by making the app's visible behaviour depend on a single condition.  _(merged 1 duplicate row(s))_
+  - **Disproof:** If the application's behaviour is identical whether the condition is true or false, boolean extraction is impossible and time-based or OAST is required.
+  - Sources: <https://owasp.org/www-project-web-security-testing-guide/stable/4-Web_Application_Security_Testing/07-Input_Validation_Testing/05-Testing_for_SQL_Injection.html> · <https://raw.githubusercontent.com/OWASP/wstg/v4.2/document/4-Web_Application_Security_Testing/07-Input_Validation_Testing/05-Testing_for_SQL_Injection.md> · <https://portswigger.net/web-security/sql-injection/blind>
+- Error-based SQL injection extracts data by triggering database error messages that echo the injected value or the attacked metadata, and is confirmed when an error response reveals a table, column, or value that was not present in the baseline.  _(merged 1 duplicate row(s))_
+  - **Disproof:** The claim is false when the error message only reports a syntax or constraint violation with no embedded target value, or when the same error appears before any injection is attempted, which means the message is a framework default rather than a data channel. If the value only ever appears in the application's own echoed input and never in a database error, the finding is verbose errors, not error-based injection.
+  - Sources: <https://cheatsheetseries.owasp.org/cheatsheets/SQL_Injection_Prevention_Cheat_Sheet.html> · <https://portswigger.net/web-security/sql-injection/blind>
+- For example, consider using persistence layers such as Hibernate or Enterprise Java Beans, which can provide significant protection against SQL injection if used properly.  _(merged 1 duplicate row(s))_
+  - **Disproof:** Refuted when: the value is bound as a parameter or written through the framework's own encoder, so the interpreter never sees attacker text as syntax. Settle it by running the identical request with and without that one control and diffing the response -- if the difference the claim predicts does not appear, the claim is false. Specifically, this is refuted if the behaviour described (“For example, consider using persistence layers such as Hibernate or Enterprise J”) does not occur under a test that isolates that control.
+  - Sources: <https://cwe.mitre.org/data/definitions/89.html> · <https://owasp.org/www-community/attacks/SQL_Injection>
+- If authorization information is held in a SQL database, it may be possible to change this information through the successful exploitation of a SQL injection vulnerability.  _(merged 1 duplicate row(s))_
+  - **Disproof:** Refuted when: the value is bound as a parameter or written through the framework's own encoder, so the interpreter never sees attacker text as syntax. Settle it by running the identical request with and without that one control and diffing the response -- if the difference the claim predicts does not appear, the claim is false. Specifically, this is refuted if the behaviour described (“If authorization information is held in a SQL database, it may be possible to ch”) does not occur under a test that isolates that control.
+  - Sources: <https://cwe.mitre.org/data/definitions/89.html> · <https://owasp.org/www-community/attacks/SQL_Injection>
+- Incrementing ORDER BY <n> until a response change appears infers the column count of the original query even when errors are suppressed.  _(merged 1 duplicate row(s))_
+  - **Disproof:** If every index from 1 upward yields an identical response, ORDER BY cannot be used for column counting and you must rely on UNION NULL probing.
+  - Sources: <https://cheatsheetseries.owasp.org/cheatsheets/SQL_Injection_Prevention_Cheat_Sheet.html> · <https://portswigger.net/web-security/sql-injection/union-attacks>
+- Input validation will not always prevent SQL injection, especially if you are required to support free-form text fields that could contain arbitrary characters.  _(merged 1 duplicate row(s))_
+  - **Disproof:** Refuted when: the value is bound as a parameter or written through the framework's own encoder, so the interpreter never sees attacker text as syntax. Settle it by running the identical request with and without that one control and diffing the response -- if the difference the claim predicts does not appear, the claim is false. Specifically, this is refuted if the behaviour described (“Input validation will not always prevent SQL injection, especially if you are re”) does not occur under a test that isolates that control.
+  - Sources: <https://cwe.mitre.org/data/definitions/89.html> · <https://owasp.org/www-community/attacks/SQL_Injection>
+- Inside an injected MS Access query, TOP and LAST act as row selectors, so the tester can cap or reverse the result set and page out a table's records instead of dumping it whole.  _(merged 1 duplicate row(s))_
+  - **Disproof:** TOP or LAST modifiers rejected as syntax by the same injection point, or accepted but leaving the returned rows unchanged, refute their use as row-selection controls.
+  - Sources: <https://sqlite.org/lang_expr.html> · <https://raw.githubusercontent.com/HackTricks-wiki/hacktricks/master/src/pentesting-web/sql-injection/ms-access-sql-injection.md>
+- MySQL schema and table names come out of a UNION SELECT with GROUP_CONCAT over information_schema, and the alternating letter case of the quoted keywords is the point: the enumeration has to be sent in mixed case so a filter matching keywords in one fixed case does not stop it.  _(merged 1 duplicate row(s))_
+  - **Disproof:** A filter that blocks the mixed-case spelling while letting the all-lowercase form through, or a UNION SELECT that returns no schema rows despite a working injection point, refutes this enumeration route.
+  - Sources: <https://cheatsheetseries.owasp.org/cheatsheets/SQL_Injection_Prevention_Cheat_Sheet.html> · <https://raw.githubusercontent.com/HackTricks-wiki/hacktricks/master/src/pentesting-web/sql-injection/mysql-injection/README.md>
+- Naming a target table turns the same UNION SELECT pattern into a column dictionary, so the tester moves from which tables exist to exactly which attributes the injected query can reference.  _(merged 1 duplicate row(s))_
+  - **Disproof:** The column enumeration coming back empty for a table that the same injection point can already read rows from refutes this metadata route.
+  - Sources: <https://cheatsheetseries.owasp.org/cheatsheets/SQL_Injection_Prevention_Cheat_Sheet.html> · <https://raw.githubusercontent.com/HackTricks-wiki/hacktricks/master/src/pentesting-web/sql-injection/mysql-injection/README.md>
+- On MSSQL a single injected UNION SELECT over information_schema.columns hands back the schema, table and column names of the current database at once, and on error-based vectors every selected expression has to carry an alias or the query will not come back.  _(merged 1 duplicate row(s))_
+  - **Disproof:** An error-based injected select that errors purely because an expression lacks an alias, or a schema enumeration that returns no rows despite a working injection point, refutes these requirements.
+  - Sources: <https://portswigger.net/web-security/sql-injection> · <https://raw.githubusercontent.com/HackTricks-wiki/hacktricks/master/src/pentesting-web/sql-injection/mssql-injection.md>
+- Once a UNION SELECT column count is aligned, the tester can read a chosen position out of a table with a wildcard select and never has to know the column's name, which is how data leaves the database once the injection point is confirmed.  _(merged 1 duplicate row(s))_
+  - **Disproof:** A wildcard select that returns nothing from a table known to be readable, or one that fails purely on a column-count mismatch, refutes the positional-access claim.
+  - Sources: <https://cwe.mitre.org/data/definitions/89.html> · <https://raw.githubusercontent.com/HackTricks-wiki/hacktricks/master/src/pentesting-web/sql-injection/README.md>
+- SQL injection is confirmed by a boolean differential: a condition that is always true returns the normal row count while the same condition forced false returns a different one.  _(merged 1 duplicate row(s))_
+  - **Disproof:** Refuted when the application returns an identical response for true and false conditions, which indicates the value is escaped, parameterised, or never reaches a SQL parser.
+  - Sources: <https://owasp.org/www-community/attacks/SQL_Injection> · <https://portswigger.net/web-security/sql-injection> · <https://raw.githubusercontent.com/Esther7171/HackTheBox-Writeups-Walkthroughs/main/Write-ups/Academy/05.%20Web%20Exploitation/25.%20SQL%20Injection%20Fundamentals/SQL%20Injection%20Fundamentals.md>
+- UNION SELECT NULL with increasing NULL counts finds the column count, then a string marker in each position finds a column type that can carry exfiltrated data.  _(merged 1 duplicate row(s))_
+  - **Disproof:** If the response is identical for wrong and correct NULL counts, the UNION column-count method is ineffective and you must use boolean or error-based inference.
+  - Sources: <https://raw.githubusercontent.com/OWASP/wstg/master/document/4-Web_Application_Security_Testing/07-Injection/05-SQL_Injection.md> · <https://portswigger.net/web-security/sql-injection/union-attacks>
+
+## Tests
+
+- MS Access hands the tester a file-existence oracle from inside the injection: point the database reference at a local file and the invalid-database-format error appears only when that file is really there, so file enumeration is driven by comparing errors across candidate paths.  _(merged 1 duplicate row(s))_
+  - **Disproof:** The invalid-format error appearing identically for names that do not exist, or never appearing for one that does, refutes the existence oracle.
+  - Sources: <https://sqlite.org/lang_expr.html> · <https://raw.githubusercontent.com/HackTricks-wiki/hacktricks/master/src/pentesting-web/sql-injection/ms-access-sql-injection.md>
+- On MSSQL the tester can read the live query text back through sys.dm_exec_requests joined to sys.dm_exec_sql_text, which is the way to confirm the injection really landed in the query and to see the surrounding SQL, with the server-level permission checked separately.  _(merged 1 duplicate row(s))_
+  - **Disproof:** The DMVs returning nothing, or returning a query that does not contain the injected syntax, refutes their use for reading back the currently executing SQL query.
+  - Sources: <https://portswigger.net/web-security/sql-injection> · <https://raw.githubusercontent.com/HackTricks-wiki/hacktricks/master/src/pentesting-web/sql-injection/mssql-injection.md>
+- To decide this case, observe: Establish a baseline with clearly invalid input such as a string where a number is expected, and check whether that also 500s.  _(merged 1 duplicate row(s))_ _(unverified)_
+  - **Disproof:** This test does not apply where the surrounding behaviour is unobservable -- for example when the response is identical in every case, or when the only evidence is server-side and not reflected to the requester. The originating rule (sqli.fp_rule.generic_500_not_sqli) states the full boundary.
+  - Sources: <https://raw.githubusercontent.com/OWASP/wstg/master/document/4-Web_Application_Security_Testing/07-Injection/05-SQL_Injection.md> · <https://portswigger.net/web-security/sql-injection/blind>
+- To decide this case, observe: For each candidate field, replay the true/false pair three times with all other parameters identical and diff status code, headers and body.  _(merged 1 duplicate row(s))_ _(unverified)_
+  - **Disproof:** This test does not apply where the surrounding behaviour is unobservable -- for example when the response is identical in every case, or when the only evidence is server-side and not reflected to the requester. The originating rule (sqli.validation.single_variable_differential) states the full boundary.
+  - Sources: <https://raw.githubusercontent.com/OWASP/wstg/v4.2/document/4-Web_Application_Security_Testing/07-Input_Validation_Testing/05-Testing_for_SQL_Injection.md> · <https://portswigger.net/web-security/sql-injection/blind>
+- When a blind SQL injection returns no data, the proof is made of timing: concatenate a deliberately slow operation into the SQL query and look for a repeatable jump in page-load time that the unmodified request does not show.  _(merged 1 duplicate row(s))_
+  - **Disproof:** A concatenated slow operation that leaves page-load time flat, or a delay that appears just as often on a control request carrying no injected syntax, refutes it as a blind SQL injection oracle.
+  - Sources: <https://cwe.mitre.org/data/definitions/89.html> · <https://raw.githubusercontent.com/HackTricks-wiki/hacktricks/master/src/pentesting-web/sql-injection/README.md>
+
+## Validation bar (how to prove it)
+
+- A SQLi finding is only validated when one variable changes and the response difference is reproducible and explainable by query logic.  _(merged 1 duplicate row(s))_ _(unverified)_
... (truncated)
```

## 2026-11-01 06:35 — 227 diff lines
- items: 1 (supported 0), FP rules 0, chains 0, state researching
- still missing: items, supported_items, fp_rules, chain

```diff
--- sqli@current
+++ sqli@new
@@ -9,219 +9,15 @@
      Edit the rows (or ingest better research) and re-run:
      python -m wks.skillgen -->
 
-> surface `web` · CWE CWE-89 · OWASP A03:2021
-> evidence: 45 items, 34 supported, 12 FP rules, 1 chains
-> maturity: **mature**
+> surface `web` · CWE — · OWASP —
+> evidence: 1 items, 0 supported, 0 FP rules, 0 chains
+> maturity: **researching** — missing: items, supported_items, fp_rules, chain
 
-Attacker-controlled input is concatenated into a SQL statement, so the query structure becomes attacker-controlled.
-
-**Also called:** sql injection, sqli, second order sql injection, nosql injection operator
-
-
-## Prerequisites (do not start without these)
-
-- Any request-controllable value that reaches a SQL query is a candidate injection point, including JSON/XML bodies, cookies and headers, not just GET parameters.  _(merged 1 duplicate row(s))_
-  - **Disproof:** If a field's value is provably never used in any query (e.g. purely client-side sorting or CSRF tokens), it cannot be an injection point.
-  - Sources: <https://raw.githubusercontent.com/OWASP/wstg/master/document/4-Web_Application_Security_Testing/07-Injection/05-SQL_Injection.md> · <https://portswigger.net/web-security/sql-injection>
-- Extraction on MS Access is gated on naming a real column such as username, so the guess-and-check step on column names comes before any value can be pulled out of the database through the injection.  _(merged 1 duplicate row(s))_
-  - **Disproof:** Reading a value out of MS Access with no valid column name in the injected query, or a fabricated column name returning data, refutes this ordering.
-  - Sources: <https://sqlite.org/lang_expr.html> · <https://raw.githubusercontent.com/HackTricks-wiki/hacktricks/master/src/pentesting-web/sql-injection/ms-access-sql-injection.md>
-- Prepared/parameterized statements force the DB to separate code from data, so bind-variable queries are the baseline you must establish before treating quote errors as SQLi.  _(merged 1 duplicate row(s))_
-  - **Disproof:** If the query string is built by concatenation at runtime even when a parameterized API exists elsewhere, the endpoint is not parameterized.
-  - Sources: <https://cheatsheetseries.owasp.org/cheatsheets/SQL_Injection_Prevention_Cheat_Sheet.html> · <https://cwe.mitre.org/data/definitions/89.html>
-
-## Recon signals (where to look)
-
-- A single quote or a paired OR 1=1 / OR 1=2 pair producing a repeatable response difference is the primary first-order SQLi signal.  _(merged 1 duplicate row(s))_
-  - **Disproof:** If the quote and both boolean twins produce byte-identical responses, the field shows no first-order SQLi signal.
-  - Sources: <https://raw.githubusercontent.com/OWASP/wstg/master/document/4-Web_Application_Security_Testing/07-Injection/05-SQL_Injection.md> · <https://portswigger.net/web-security/sql-injection>
-- If the app neither returns query results nor error differences nor timing changes, the query may run asynchronously; absence of in-band signal does not mean absence of SQLi.  _(merged 1 duplicate row(s))_
-  - **Disproof:** If an OAST payload produces no collaborator/DNS callback and conditional time delays stay within baseline jitter, the parameter is very likely not injectable.
-  - Sources: <https://owasp.org/www-project-web-security-testing-guide/stable/4-Web_Application_Security_Testing/07-Input_Validation_Testing/05-Testing_for_SQL_Injection.html> · <https://raw.githubusercontent.com/OWASP/wstg/v4.2/document/4-Web_Application_Security_Testing/07-Input_Validation_Testing/05-Testing_for_SQL_Injection.md> · <https://portswigger.net/web-security/sql-injection/blind>
 
 ## Techniques (what to change)
 
-- A UNION-based SQL injection is confirmed by matching the number of columns in the injected result set against the original query using successive NULL placeholders, then selecting data from other tables.  _(merged 1 duplicate row(s))_
-  - **Disproof:** The claim is false when the original query always returns a fixed number of columns unrelated to the injection point, when the database does not expose the metadata used (a closed source or heavily restricted RDBMS), or when the response is identical across every NULL-count probe, which proves no UNION result set reached the output.
-  - Sources: <https://portswigger.net/web-security/sql-injection/union-based> · <https://www.w3schools.com/sql/sql_union.asp>
-- A UNION-based SQL injection is confirmed by matching the result-set column count through successively longer runs of NULL placeholders, and NULL is used as the filler because it type-checks in any column position and so maximises the chance the payload succeeds.  _(merged 1 duplicate row(s))_
-  - **Disproof:** If no NULL-counted payload ever produces the extra result set or alters the response, the column count was never matched and the UNION injection is not demonstrated.
-  - Sources: <https://cwe.mitre.org/data/definitions/89.html> · <https://docs.djangoproject.com/en/5.0/topics/db/sql/> · <https://kathan19.gitbook.io/howtohunt/sqli/sql_injection.md>
-- A boolean-based blind SQL injection is confirmed when the application's response changes based on a injected condition that is true versus one that is false, with no error or data returned.  _(merged 1 duplicate row(s))_ _(unverified)_
-  - **Disproof:** The claim is false when the same request produces no behavioural change when the query is rewritten so the value is bound rather than concatenated, because then the condition was never evaluated by the database. It also fails if the observed difference is reproducible with the payload removed or with a syntactically identical but semantically neutral value, which points at response timing, caching, or application logic rather than injection.
-  - Sources: <https://owasp.org/www-community/attacks/SQL_Injection> · <https://portswigger.net/web-security/sql-injection/blind>
-- A time-based blind SQL injection is confirmed when the response delay produced by injecting a SLEEP() predicate is measurable and reproducible, and stops when the condition is made false or when the value is bound.  _(merged 1 duplicate row(s))_ _(unverified)_
-  - **Disproof:** The claim is false when the observed delay is identical regardless of the condition, which means the database never evaluated the predicate, or when the delay is caused by the endpoint's own behaviour (slow query, saturation, upstream dependency) rather than by the injected predicate. It also fails when the payload is bound, since the function then receives a literal string and never sleeps.
-  - Sources: <https://owasp.org/www-community/attacks/SQL_Injection> · <https://portswigger.net/web-security/sql-injection/blind>
-- An MSSQL injection point doubles as a privilege-reach probe: calling fn_my_permissions against the database and filtering on a named permission tells the tester which database-level grants the injected session actually holds before they plan any escalation.  _(merged 1 duplicate row(s))_
-  - **Disproof:** fn_my_permissions returning no rows, or an empty grant set, for a login that demonstrably holds the named database permission refutes it as a reach check.
-  - Sources: <https://portswigger.net/web-security/sql-injection> · <https://raw.githubusercontent.com/HackTricks-wiki/hacktricks/master/src/pentesting-web/sql-injection/mssql-injection.md>
-- Blind boolean injection extracts arbitrary values one character at a time by making the app's visible behaviour depend on a single condition.  _(merged 1 duplicate row(s))_
-  - **Disproof:** If the application's behaviour is identical whether the condition is true or false, boolean extraction is impossible and time-based or OAST is required.
-  - Sources: <https://owasp.org/www-project-web-security-testing-guide/stable/4-Web_Application_Security_Testing/07-Input_Validation_Testing/05-Testing_for_SQL_Injection.html> · <https://raw.githubusercontent.com/OWASP/wstg/v4.2/document/4-Web_Application_Security_Testing/07-Input_Validation_Testing/05-Testing_for_SQL_Injection.md> · <https://portswigger.net/web-security/sql-injection/blind>
-- Error-based SQL injection extracts data by triggering database error messages that echo the injected value or the attacked metadata, and is confirmed when an error response reveals a table, column, or value that was not present in the baseline.  _(merged 1 duplicate row(s))_
-  - **Disproof:** The claim is false when the error message only reports a syntax or constraint violation with no embedded target value, or when the same error appears before any injection is attempted, which means the message is a framework default rather than a data channel. If the value only ever appears in the application's own echoed input and never in a database error, the finding is verbose errors, not error-based injection.
-  - Sources: <https://cheatsheetseries.owasp.org/cheatsheets/SQL_Injection_Prevention_Cheat_Sheet.html> · <https://portswigger.net/web-security/sql-injection/blind>
-- For example, consider using persistence layers such as Hibernate or Enterprise Java Beans, which can provide significant protection against SQL injection if used properly.  _(merged 1 duplicate row(s))_
-  - **Disproof:** Refuted when: the value is bound as a parameter or written through the framework's own encoder, so the interpreter never sees attacker text as syntax. Settle it by running the identical request with and without that one control and diffing the response -- if the difference the claim predicts does not appear, the claim is false. Specifically, this is refuted if the behaviour described (“For example, consider using persistence layers such as Hibernate or Enterprise J”) does not occur under a test that isolates that control.
-  - Sources: <https://cwe.mitre.org/data/definitions/89.html> · <https://owasp.org/www-community/attacks/SQL_Injection>
-- If authorization information is held in a SQL database, it may be possible to change this information through the successful exploitation of a SQL injection vulnerability.  _(merged 1 duplicate row(s))_
-  - **Disproof:** Refuted when: the value is bound as a parameter or written through the framework's own encoder, so the interpreter never sees attacker text as syntax. Settle it by running the identical request with and without that one control and diffing the response -- if the difference the claim predicts does not appear, the claim is false. Specifically, this is refuted if the behaviour described (“If authorization information is held in a SQL database, it may be possible to ch”) does not occur under a test that isolates that control.
-  - Sources: <https://cwe.mitre.org/data/definitions/89.html> · <https://owasp.org/www-community/attacks/SQL_Injection>
-- Incrementing ORDER BY <n> until a response change appears infers the column count of the original query even when errors are suppressed.  _(merged 1 duplicate row(s))_
-  - **Disproof:** If every index from 1 upward yields an identical response, ORDER BY cannot be used for column counting and you must rely on UNION NULL probing.
-  - Sources: <https://cheatsheetseries.owasp.org/cheatsheets/SQL_Injection_Prevention_Cheat_Sheet.html> · <https://portswigger.net/web-security/sql-injection/union-attacks>
-- Input validation will not always prevent SQL injection, especially if you are required to support free-form text fields that could contain arbitrary characters.  _(merged 1 duplicate row(s))_
-  - **Disproof:** Refuted when: the value is bound as a parameter or written through the framework's own encoder, so the interpreter never sees attacker text as syntax. Settle it by running the identical request with and without that one control and diffing the response -- if the difference the claim predicts does not appear, the claim is false. Specifically, this is refuted if the behaviour described (“Input validation will not always prevent SQL injection, especially if you are re”) does not occur under a test that isolates that control.
-  - Sources: <https://cwe.mitre.org/data/definitions/89.html> · <https://owasp.org/www-community/attacks/SQL_Injection>
-- Inside an injected MS Access query, TOP and LAST act as row selectors, so the tester can cap or reverse the result set and page out a table's records instead of dumping it whole.  _(merged 1 duplicate row(s))_
-  - **Disproof:** TOP or LAST modifiers rejected as syntax by the same injection point, or accepted but leaving the returned rows unchanged, refute their use as row-selection controls.
-  - Sources: <https://sqlite.org/lang_expr.html> · <https://raw.githubusercontent.com/HackTricks-wiki/hacktricks/master/src/pentesting-web/sql-injection/ms-access-sql-injection.md>
-- MySQL schema and table names come out of a UNION SELECT with GROUP_CONCAT over information_schema, and the alternating letter case of the quoted keywords is the point: the enumeration has to be sent in mixed case so a filter matching keywords in one fixed case does not stop it.  _(merged 1 duplicate row(s))_
-  - **Disproof:** A filter that blocks the mixed-case spelling while letting the all-lowercase form through, or a UNION SELECT that returns no schema rows despite a working injection point, refutes this enumeration route.
-  - Sources: <https://cheatsheetseries.owasp.org/cheatsheets/SQL_Injection_Prevention_Cheat_Sheet.html> · <https://raw.githubusercontent.com/HackTricks-wiki/hacktricks/master/src/pentesting-web/sql-injection/mysql-injection/README.md>
-- Naming a target table turns the same UNION SELECT pattern into a column dictionary, so the tester moves from which tables exist to exactly which attributes the injected query can reference.  _(merged 1 duplicate row(s))_
-  - **Disproof:** The column enumeration coming back empty for a table that the same injection point can already read rows from refutes this metadata route.
-  - Sources: <https://cheatsheetseries.owasp.org/cheatsheets/SQL_Injection_Prevention_Cheat_Sheet.html> · <https://raw.githubusercontent.com/HackTricks-wiki/hacktricks/master/src/pentesting-web/sql-injection/mysql-injection/README.md>
-- On MSSQL a single injected UNION SELECT over information_schema.columns hands back the schema, table and column names of the current database at once, and on error-based vectors every selected expression has to carry an alias or the query will not come back.  _(merged 1 duplicate row(s))_
-  - **Disproof:** An error-based injected select that errors purely because an expression lacks an alias, or a schema enumeration that returns no rows despite a working injection point, refutes these requirements.
-  - Sources: <https://portswigger.net/web-security/sql-injection> · <https://raw.githubusercontent.com/HackTricks-wiki/hacktricks/master/src/pentesting-web/sql-injection/mssql-injection.md>
-- Once a UNION SELECT column count is aligned, the tester can read a chosen position out of a table with a wildcard select and never has to know the column's name, which is how data leaves the database once the injection point is confirmed.  _(merged 1 duplicate row(s))_
-  - **Disproof:** A wildcard select that returns nothing from a table known to be readable, or one that fails purely on a column-count mismatch, refutes the positional-access claim.
-  - Sources: <https://cwe.mitre.org/data/definitions/89.html> · <https://raw.githubusercontent.com/HackTricks-wiki/hacktricks/master/src/pentesting-web/sql-injection/README.md>
-- SQL injection is confirmed by a boolean differential: a condition that is always true returns the normal row count while the same condition forced false returns a different one.  _(merged 1 duplicate row(s))_
-  - **Disproof:** Refuted when the application returns an identical response for true and false conditions, which indicates the value is escaped, parameterised, or never reaches a SQL parser.
-  - Sources: <https://owasp.org/www-community/attacks/SQL_Injection> · <https://portswigger.net/web-security/sql-injection> · <https://raw.githubusercontent.com/Esther7171/HackTheBox-Writeups-Walkthroughs/main/Write-ups/Academy/05.%20Web%20Exploitation/25.%20SQL%20Injection%20Fundamentals/SQL%20Injection%20Fundamentals.md>
-- UNION SELECT NULL with increasing NULL counts finds the column count, then a string marker in each position finds a column type that can carry exfiltrated data.  _(merged 1 duplicate row(s))_
-  - **Disproof:** If the response is identical for wrong and correct NULL counts, the UNION column-count method is ineffective and you must use boolean or error-based inference.
-  - Sources: <https://raw.githubusercontent.com/OWASP/wstg/master/document/4-Web_Application_Security_Testing/07-Injection/05-SQL_Injection.md> · <https://portswigger.net/web-security/sql-injection/union-attacks>
-
-## Tests
-
-- MS Access hands the tester a file-existence oracle from inside the injection: point the database reference at a local file and the invalid-database-format error appears only when that file is really there, so file enumeration is driven by comparing errors across candidate paths.  _(merged 1 duplicate row(s))_
-  - **Disproof:** The invalid-format error appearing identically for names that do not exist, or never appearing for one that does, refutes the existence oracle.
-  - Sources: <https://sqlite.org/lang_expr.html> · <https://raw.githubusercontent.com/HackTricks-wiki/hacktricks/master/src/pentesting-web/sql-injection/ms-access-sql-injection.md>
-- On MSSQL the tester can read the live query text back through sys.dm_exec_requests joined to sys.dm_exec_sql_text, which is the way to confirm the injection really landed in the query and to see the surrounding SQL, with the server-level permission checked separately.  _(merged 1 duplicate row(s))_
-  - **Disproof:** The DMVs returning nothing, or returning a query that does not contain the injected syntax, refutes their use for reading back the currently executing SQL query.
-  - Sources: <https://portswigger.net/web-security/sql-injection> · <https://raw.githubusercontent.com/HackTricks-wiki/hacktricks/master/src/pentesting-web/sql-injection/mssql-injection.md>
-- To decide this case, observe: Establish a baseline with clearly invalid input such as a string where a number is expected, and check whether that also 500s.  _(merged 1 duplicate row(s))_ _(unverified)_
-  - **Disproof:** This test does not apply where the surrounding behaviour is unobservable -- for example when the response is identical in every case, or when the only evidence is server-side and not reflected to the requester. The originating rule (sqli.fp_rule.generic_500_not_sqli) states the full boundary.
-  - Sources: <https://raw.githubusercontent.com/OWASP/wstg/master/document/4-Web_Application_Security_Testing/07-Injection/05-SQL_Injection.md> · <https://portswigger.net/web-security/sql-injection/blind>
-- To decide this case, observe: For each candidate field, replay the true/false pair three times with all other parameters identical and diff status code, headers and body.  _(merged 1 duplicate row(s))_ _(unverified)_
-  - **Disproof:** This test does not apply where the surrounding behaviour is unobservable -- for example when the response is identical in every case, or when the only evidence is server-side and not reflected to the requester. The originating rule (sqli.validation.single_variable_differential) states the full boundary.
-  - Sources: <https://raw.githubusercontent.com/OWASP/wstg/v4.2/document/4-Web_Application_Security_Testing/07-Input_Validation_Testing/05-Testing_for_SQL_Injection.md> · <https://portswigger.net/web-security/sql-injection/blind>
-- When a blind SQL injection returns no data, the proof is made of timing: concatenate a deliberately slow operation into the SQL query and look for a repeatable jump in page-load time that the unmodified request does not show.  _(merged 1 duplicate row(s))_
-  - **Disproof:** A concatenated slow operation that leaves page-load time flat, or a delay that appears just as often on a control request carrying no injected syntax, refutes it as a blind SQL injection oracle.
-  - Sources: <https://cwe.mitre.org/data/definitions/89.html> · <https://raw.githubusercontent.com/HackTricks-wiki/hacktricks/master/src/pentesting-web/sql-injection/README.md>
-
-## Validation bar (how to prove it)
-
-- A SQLi finding is only validated when one variable changes and the response difference is reproducible and explainable by query logic.  _(merged 1 duplicate row(s))_ _(unverified)_
-  - **Disproof:** If the difference is non-deterministic, cache- or session-driven, or does not reverse when the condition is inverted, it is not a validated SQLi.
-  - Sources: <https://owasp.org/www-project-web-security-testing-guide/stable/4-Web_Application_Security_Testing/07-Input_Validation_Testing/05-Testing_for_SQL_Injection.html> · <https://raw.githubusercontent.com/OWASP/wstg/v4.2/document/4-Web_Application_Security_Testing/07-Input_Validation_Testing/05-Testing_for_SQL_Injection.md> · <https://portswigger.net/web-security/sql-injection/blind>
-- A boolean or time differential found while several parameters are being varied at once is not attributable to any of them, so the finding is only valid once the same differential reproduces with exactly one variable changed.  _(merged 1 duplicate row(s))_
... (truncated)
```

## 2026-11-01 06:44 — 11 diff lines
- items: 1 (supported 0), FP rules 0, chains 0, state researching
- still missing: methodology, items, supported_items, fp_rules, chain

```diff
--- sqli@current
+++ sqli@new
@@ -11,7 +11,7 @@
 
 > surface `web` · CWE — · OWASP —
 > evidence: 1 items, 0 supported, 0 FP rules, 0 chains
-> maturity: **researching** — missing: items, supported_items, fp_rules, chain
+> maturity: **researching** — missing: methodology, items, supported_items, fp_rules, chain
 
 
 ## Techniques (what to change)
```

## 2026-11-01 07:27 — 228 diff lines
- items: 45 (supported 34), FP rules 12, chains 1, state mature

```diff
--- sqli@current
+++ sqli@new
@@ -9,15 +9,219 @@
      Edit the rows (or ingest better research) and re-run:
      python -m wks.skillgen -->
 
-> surface `web` · CWE — · OWASP —
-> evidence: 1 items, 0 supported, 0 FP rules, 0 chains
-> maturity: **researching** — missing: methodology, items, supported_items, fp_rules, chain
-
+> surface `web` · CWE CWE-89 · OWASP A03:2021
+> evidence: 45 items, 34 supported, 12 FP rules, 1 chains
+> maturity: **mature**
+
+Attacker-controlled input is concatenated into a SQL statement, so the query structure becomes attacker-controlled.
+
+**Also called:** sql injection, sqli, second order sql injection, nosql injection operator
+
+
+## Prerequisites (do not start without these)
+
+- Any request-controllable value that reaches a SQL query is a candidate injection point, including JSON/XML bodies, cookies and headers, not just GET parameters.  _(merged 1 duplicate row(s))_
+  - **Disproof:** If a field's value is provably never used in any query (e.g. purely client-side sorting or CSRF tokens), it cannot be an injection point.
+  - Sources: <https://raw.githubusercontent.com/OWASP/wstg/master/document/4-Web_Application_Security_Testing/07-Injection/05-SQL_Injection.md> · <https://portswigger.net/web-security/sql-injection>
+- Extraction on MS Access is gated on naming a real column such as username, so the guess-and-check step on column names comes before any value can be pulled out of the database through the injection.  _(merged 1 duplicate row(s))_
+  - **Disproof:** Reading a value out of MS Access with no valid column name in the injected query, or a fabricated column name returning data, refutes this ordering.
+  - Sources: <https://sqlite.org/lang_expr.html> · <https://raw.githubusercontent.com/HackTricks-wiki/hacktricks/master/src/pentesting-web/sql-injection/ms-access-sql-injection.md>
+- Prepared/parameterized statements force the DB to separate code from data, so bind-variable queries are the baseline you must establish before treating quote errors as SQLi.  _(merged 1 duplicate row(s))_
+  - **Disproof:** If the query string is built by concatenation at runtime even when a parameterized API exists elsewhere, the endpoint is not parameterized.
+  - Sources: <https://cheatsheetseries.owasp.org/cheatsheets/SQL_Injection_Prevention_Cheat_Sheet.html> · <https://cwe.mitre.org/data/definitions/89.html>
+
+## Recon signals (where to look)
+
+- A single quote or a paired OR 1=1 / OR 1=2 pair producing a repeatable response difference is the primary first-order SQLi signal.  _(merged 1 duplicate row(s))_
+  - **Disproof:** If the quote and both boolean twins produce byte-identical responses, the field shows no first-order SQLi signal.
+  - Sources: <https://raw.githubusercontent.com/OWASP/wstg/master/document/4-Web_Application_Security_Testing/07-Injection/05-SQL_Injection.md> · <https://portswigger.net/web-security/sql-injection>
+- If the app neither returns query results nor error differences nor timing changes, the query may run asynchronously; absence of in-band signal does not mean absence of SQLi.  _(merged 1 duplicate row(s))_
+  - **Disproof:** If an OAST payload produces no collaborator/DNS callback and conditional time delays stay within baseline jitter, the parameter is very likely not injectable.
+  - Sources: <https://owasp.org/www-project-web-security-testing-guide/stable/4-Web_Application_Security_Testing/07-Input_Validation_Testing/05-Testing_for_SQL_Injection.html> · <https://raw.githubusercontent.com/OWASP/wstg/v4.2/document/4-Web_Application_Security_Testing/07-Input_Validation_Testing/05-Testing_for_SQL_Injection.md> · <https://portswigger.net/web-security/sql-injection/blind>
 
 ## Techniques (what to change)
 
-- The endpoint returned a different number of rows for a true predicate than for the corresponding false predicate. The difference was stable across repeated requests, which proves the boolean condition is evaluated by the database rather than by the application. This confirmed a blind SQL injection vulnerability.  _(merged 1 duplicate row(s))_ _(unverified)_
-  - Sources: <https://example.com/advisories/blind-sqli-search>
+- A UNION-based SQL injection is confirmed by matching the number of columns in the injected result set against the original query using successive NULL placeholders, then selecting data from other tables.  _(merged 1 duplicate row(s))_
+  - **Disproof:** The claim is false when the original query always returns a fixed number of columns unrelated to the injection point, when the database does not expose the metadata used (a closed source or heavily restricted RDBMS), or when the response is identical across every NULL-count probe, which proves no UNION result set reached the output.
+  - Sources: <https://portswigger.net/web-security/sql-injection/union-based> · <https://www.w3schools.com/sql/sql_union.asp>
+- A UNION-based SQL injection is confirmed by matching the result-set column count through successively longer runs of NULL placeholders, and NULL is used as the filler because it type-checks in any column position and so maximises the chance the payload succeeds.  _(merged 1 duplicate row(s))_
+  - **Disproof:** If no NULL-counted payload ever produces the extra result set or alters the response, the column count was never matched and the UNION injection is not demonstrated.
+  - Sources: <https://cwe.mitre.org/data/definitions/89.html> · <https://docs.djangoproject.com/en/5.0/topics/db/sql/> · <https://kathan19.gitbook.io/howtohunt/sqli/sql_injection.md>
+- A boolean-based blind SQL injection is confirmed when the application's response changes based on a injected condition that is true versus one that is false, with no error or data returned.  _(merged 1 duplicate row(s))_ _(unverified)_
+  - **Disproof:** The claim is false when the same request produces no behavioural change when the query is rewritten so the value is bound rather than concatenated, because then the condition was never evaluated by the database. It also fails if the observed difference is reproducible with the payload removed or with a syntactically identical but semantically neutral value, which points at response timing, caching, or application logic rather than injection.
+  - Sources: <https://owasp.org/www-community/attacks/SQL_Injection> · <https://portswigger.net/web-security/sql-injection/blind>
+- A time-based blind SQL injection is confirmed when the response delay produced by injecting a SLEEP() predicate is measurable and reproducible, and stops when the condition is made false or when the value is bound.  _(merged 1 duplicate row(s))_ _(unverified)_
+  - **Disproof:** The claim is false when the observed delay is identical regardless of the condition, which means the database never evaluated the predicate, or when the delay is caused by the endpoint's own behaviour (slow query, saturation, upstream dependency) rather than by the injected predicate. It also fails when the payload is bound, since the function then receives a literal string and never sleeps.
+  - Sources: <https://owasp.org/www-community/attacks/SQL_Injection> · <https://portswigger.net/web-security/sql-injection/blind>
+- An MSSQL injection point doubles as a privilege-reach probe: calling fn_my_permissions against the database and filtering on a named permission tells the tester which database-level grants the injected session actually holds before they plan any escalation.  _(merged 1 duplicate row(s))_
+  - **Disproof:** fn_my_permissions returning no rows, or an empty grant set, for a login that demonstrably holds the named database permission refutes it as a reach check.
+  - Sources: <https://portswigger.net/web-security/sql-injection> · <https://raw.githubusercontent.com/HackTricks-wiki/hacktricks/master/src/pentesting-web/sql-injection/mssql-injection.md>
+- Blind boolean injection extracts arbitrary values one character at a time by making the app's visible behaviour depend on a single condition.  _(merged 1 duplicate row(s))_
+  - **Disproof:** If the application's behaviour is identical whether the condition is true or false, boolean extraction is impossible and time-based or OAST is required.
+  - Sources: <https://owasp.org/www-project-web-security-testing-guide/stable/4-Web_Application_Security_Testing/07-Input_Validation_Testing/05-Testing_for_SQL_Injection.html> · <https://raw.githubusercontent.com/OWASP/wstg/v4.2/document/4-Web_Application_Security_Testing/07-Input_Validation_Testing/05-Testing_for_SQL_Injection.md> · <https://portswigger.net/web-security/sql-injection/blind>
+- Error-based SQL injection extracts data by triggering database error messages that echo the injected value or the attacked metadata, and is confirmed when an error response reveals a table, column, or value that was not present in the baseline.  _(merged 1 duplicate row(s))_
+  - **Disproof:** The claim is false when the error message only reports a syntax or constraint violation with no embedded target value, or when the same error appears before any injection is attempted, which means the message is a framework default rather than a data channel. If the value only ever appears in the application's own echoed input and never in a database error, the finding is verbose errors, not error-based injection.
+  - Sources: <https://cheatsheetseries.owasp.org/cheatsheets/SQL_Injection_Prevention_Cheat_Sheet.html> · <https://portswigger.net/web-security/sql-injection/blind>
+- For example, consider using persistence layers such as Hibernate or Enterprise Java Beans, which can provide significant protection against SQL injection if used properly.  _(merged 1 duplicate row(s))_
+  - **Disproof:** Refuted when: the value is bound as a parameter or written through the framework's own encoder, so the interpreter never sees attacker text as syntax. Settle it by running the identical request with and without that one control and diffing the response -- if the difference the claim predicts does not appear, the claim is false. Specifically, this is refuted if the behaviour described (“For example, consider using persistence layers such as Hibernate or Enterprise J”) does not occur under a test that isolates that control.
+  - Sources: <https://cwe.mitre.org/data/definitions/89.html> · <https://owasp.org/www-community/attacks/SQL_Injection>
+- If authorization information is held in a SQL database, it may be possible to change this information through the successful exploitation of a SQL injection vulnerability.  _(merged 1 duplicate row(s))_
+  - **Disproof:** Refuted when: the value is bound as a parameter or written through the framework's own encoder, so the interpreter never sees attacker text as syntax. Settle it by running the identical request with and without that one control and diffing the response -- if the difference the claim predicts does not appear, the claim is false. Specifically, this is refuted if the behaviour described (“If authorization information is held in a SQL database, it may be possible to ch”) does not occur under a test that isolates that control.
+  - Sources: <https://cwe.mitre.org/data/definitions/89.html> · <https://owasp.org/www-community/attacks/SQL_Injection>
+- Incrementing ORDER BY <n> until a response change appears infers the column count of the original query even when errors are suppressed.  _(merged 1 duplicate row(s))_
+  - **Disproof:** If every index from 1 upward yields an identical response, ORDER BY cannot be used for column counting and you must rely on UNION NULL probing.
+  - Sources: <https://cheatsheetseries.owasp.org/cheatsheets/SQL_Injection_Prevention_Cheat_Sheet.html> · <https://portswigger.net/web-security/sql-injection/union-attacks>
+- Input validation will not always prevent SQL injection, especially if you are required to support free-form text fields that could contain arbitrary characters.  _(merged 1 duplicate row(s))_
+  - **Disproof:** Refuted when: the value is bound as a parameter or written through the framework's own encoder, so the interpreter never sees attacker text as syntax. Settle it by running the identical request with and without that one control and diffing the response -- if the difference the claim predicts does not appear, the claim is false. Specifically, this is refuted if the behaviour described (“Input validation will not always prevent SQL injection, especially if you are re”) does not occur under a test that isolates that control.
+  - Sources: <https://cwe.mitre.org/data/definitions/89.html> · <https://owasp.org/www-community/attacks/SQL_Injection>
+- Inside an injected MS Access query, TOP and LAST act as row selectors, so the tester can cap or reverse the result set and page out a table's records instead of dumping it whole.  _(merged 1 duplicate row(s))_
+  - **Disproof:** TOP or LAST modifiers rejected as syntax by the same injection point, or accepted but leaving the returned rows unchanged, refute their use as row-selection controls.
+  - Sources: <https://sqlite.org/lang_expr.html> · <https://raw.githubusercontent.com/HackTricks-wiki/hacktricks/master/src/pentesting-web/sql-injection/ms-access-sql-injection.md>
+- MySQL schema and table names come out of a UNION SELECT with GROUP_CONCAT over information_schema, and the alternating letter case of the quoted keywords is the point: the enumeration has to be sent in mixed case so a filter matching keywords in one fixed case does not stop it.  _(merged 1 duplicate row(s))_
+  - **Disproof:** A filter that blocks the mixed-case spelling while letting the all-lowercase form through, or a UNION SELECT that returns no schema rows despite a working injection point, refutes this enumeration route.
+  - Sources: <https://cheatsheetseries.owasp.org/cheatsheets/SQL_Injection_Prevention_Cheat_Sheet.html> · <https://raw.githubusercontent.com/HackTricks-wiki/hacktricks/master/src/pentesting-web/sql-injection/mysql-injection/README.md>
+- Naming a target table turns the same UNION SELECT pattern into a column dictionary, so the tester moves from which tables exist to exactly which attributes the injected query can reference.  _(merged 1 duplicate row(s))_
+  - **Disproof:** The column enumeration coming back empty for a table that the same injection point can already read rows from refutes this metadata route.
+  - Sources: <https://cheatsheetseries.owasp.org/cheatsheets/SQL_Injection_Prevention_Cheat_Sheet.html> · <https://raw.githubusercontent.com/HackTricks-wiki/hacktricks/master/src/pentesting-web/sql-injection/mysql-injection/README.md>
+- On MSSQL a single injected UNION SELECT over information_schema.columns hands back the schema, table and column names of the current database at once, and on error-based vectors every selected expression has to carry an alias or the query will not come back.  _(merged 1 duplicate row(s))_
+  - **Disproof:** An error-based injected select that errors purely because an expression lacks an alias, or a schema enumeration that returns no rows despite a working injection point, refutes these requirements.
+  - Sources: <https://portswigger.net/web-security/sql-injection> · <https://raw.githubusercontent.com/HackTricks-wiki/hacktricks/master/src/pentesting-web/sql-injection/mssql-injection.md>
+- Once a UNION SELECT column count is aligned, the tester can read a chosen position out of a table with a wildcard select and never has to know the column's name, which is how data leaves the database once the injection point is confirmed.  _(merged 1 duplicate row(s))_
+  - **Disproof:** A wildcard select that returns nothing from a table known to be readable, or one that fails purely on a column-count mismatch, refutes the positional-access claim.
+  - Sources: <https://cwe.mitre.org/data/definitions/89.html> · <https://raw.githubusercontent.com/HackTricks-wiki/hacktricks/master/src/pentesting-web/sql-injection/README.md>
+- SQL injection is confirmed by a boolean differential: a condition that is always true returns the normal row count while the same condition forced false returns a different one.  _(merged 1 duplicate row(s))_
+  - **Disproof:** Refuted when the application returns an identical response for true and false conditions, which indicates the value is escaped, parameterised, or never reaches a SQL parser.
+  - Sources: <https://owasp.org/www-community/attacks/SQL_Injection> · <https://portswigger.net/web-security/sql-injection> · <https://raw.githubusercontent.com/Esther7171/HackTheBox-Writeups-Walkthroughs/main/Write-ups/Academy/05.%20Web%20Exploitation/25.%20SQL%20Injection%20Fundamentals/SQL%20Injection%20Fundamentals.md>
+- UNION SELECT NULL with increasing NULL counts finds the column count, then a string marker in each position finds a column type that can carry exfiltrated data.  _(merged 1 duplicate row(s))_
+  - **Disproof:** If the response is identical for wrong and correct NULL counts, the UNION column-count method is ineffective and you must use boolean or error-based inference.
+  - Sources: <https://raw.githubusercontent.com/OWASP/wstg/master/document/4-Web_Application_Security_Testing/07-Injection/05-SQL_Injection.md> · <https://portswigger.net/web-security/sql-injection/union-attacks>
+
+## Tests
+
+- MS Access hands the tester a file-existence oracle from inside the injection: point the database reference at a local file and the invalid-database-format error appears only when that file is really there, so file enumeration is driven by comparing errors across candidate paths.  _(merged 1 duplicate row(s))_
+  - **Disproof:** The invalid-format error appearing identically for names that do not exist, or never appearing for one that does, refutes the existence oracle.
+  - Sources: <https://sqlite.org/lang_expr.html> · <https://raw.githubusercontent.com/HackTricks-wiki/hacktricks/master/src/pentesting-web/sql-injection/ms-access-sql-injection.md>
+- On MSSQL the tester can read the live query text back through sys.dm_exec_requests joined to sys.dm_exec_sql_text, which is the way to confirm the injection really landed in the query and to see the surrounding SQL, with the server-level permission checked separately.  _(merged 1 duplicate row(s))_
+  - **Disproof:** The DMVs returning nothing, or returning a query that does not contain the injected syntax, refutes their use for reading back the currently executing SQL query.
+  - Sources: <https://portswigger.net/web-security/sql-injection> · <https://raw.githubusercontent.com/HackTricks-wiki/hacktricks/master/src/pentesting-web/sql-injection/mssql-injection.md>
+- To decide this case, observe: Establish a baseline with clearly invalid input such as a string where a number is expected, and check whether that also 500s.  _(merged 1 duplicate row(s))_ _(unverified)_
+  - **Disproof:** This test does not apply where the surrounding behaviour is unobservable -- for example when the response is identical in every case, or when the only evidence is server-side and not reflected to the requester. The originating rule (sqli.fp_rule.generic_500_not_sqli) states the full boundary.
+  - Sources: <https://raw.githubusercontent.com/OWASP/wstg/master/document/4-Web_Application_Security_Testing/07-Injection/05-SQL_Injection.md> · <https://portswigger.net/web-security/sql-injection/blind>
+- To decide this case, observe: For each candidate field, replay the true/false pair three times with all other parameters identical and diff status code, headers and body.  _(merged 1 duplicate row(s))_ _(unverified)_
+  - **Disproof:** This test does not apply where the surrounding behaviour is unobservable -- for example when the response is identical in every case, or when the only evidence is server-side and not reflected to the requester. The originating rule (sqli.validation.single_variable_differential) states the full boundary.
+  - Sources: <https://raw.githubusercontent.com/OWASP/wstg/v4.2/document/4-Web_Application_Security_Testing/07-Input_Validation_Testing/05-Testing_for_SQL_Injection.md> · <https://portswigger.net/web-security/sql-injection/blind>
+- When a blind SQL injection returns no data, the proof is made of timing: concatenate a deliberately slow operation into the SQL query and look for a repeatable jump in page-load time that the unmodified request does not show.  _(merged 1 duplicate row(s))_
+  - **Disproof:** A concatenated slow operation that leaves page-load time flat, or a delay that appears just as often on a control request carrying no injected syntax, refutes it as a blind SQL injection oracle.
+  - Sources: <https://cwe.mitre.org/data/definitions/89.html> · <https://raw.githubusercontent.com/HackTricks-wiki/hacktricks/master/src/pentesting-web/sql-injection/README.md>
+
+## Validation bar (how to prove it)
+
+- A SQLi finding is only validated when one variable changes and the response difference is reproducible and explainable by query logic.  _(merged 1 duplicate row(s))_ _(unverified)_
... (truncated)
```

## 2026-11-01 07:40 — 227 diff lines
- items: 1 (supported 0), FP rules 0, chains 0, state researching
- still missing: items, supported_items, fp_rules, chain

```diff
--- sqli@current
+++ sqli@new
@@ -9,219 +9,15 @@
      Edit the rows (or ingest better research) and re-run:
      python -m wks.skillgen -->
 
-> surface `web` · CWE CWE-89 · OWASP A03:2021
-> evidence: 45 items, 34 supported, 12 FP rules, 1 chains
-> maturity: **mature**
+> surface `web` · CWE — · OWASP —
+> evidence: 1 items, 0 supported, 0 FP rules, 0 chains
+> maturity: **researching** — missing: items, supported_items, fp_rules, chain
 
-Attacker-controlled input is concatenated into a SQL statement, so the query structure becomes attacker-controlled.
-
-**Also called:** sql injection, sqli, second order sql injection, nosql injection operator
-
-
-## Prerequisites (do not start without these)
-
-- Any request-controllable value that reaches a SQL query is a candidate injection point, including JSON/XML bodies, cookies and headers, not just GET parameters.  _(merged 1 duplicate row(s))_
-  - **Disproof:** If a field's value is provably never used in any query (e.g. purely client-side sorting or CSRF tokens), it cannot be an injection point.
-  - Sources: <https://raw.githubusercontent.com/OWASP/wstg/master/document/4-Web_Application_Security_Testing/07-Injection/05-SQL_Injection.md> · <https://portswigger.net/web-security/sql-injection>
-- Extraction on MS Access is gated on naming a real column such as username, so the guess-and-check step on column names comes before any value can be pulled out of the database through the injection.  _(merged 1 duplicate row(s))_
-  - **Disproof:** Reading a value out of MS Access with no valid column name in the injected query, or a fabricated column name returning data, refutes this ordering.
-  - Sources: <https://sqlite.org/lang_expr.html> · <https://raw.githubusercontent.com/HackTricks-wiki/hacktricks/master/src/pentesting-web/sql-injection/ms-access-sql-injection.md>
-- Prepared/parameterized statements force the DB to separate code from data, so bind-variable queries are the baseline you must establish before treating quote errors as SQLi.  _(merged 1 duplicate row(s))_
-  - **Disproof:** If the query string is built by concatenation at runtime even when a parameterized API exists elsewhere, the endpoint is not parameterized.
-  - Sources: <https://cheatsheetseries.owasp.org/cheatsheets/SQL_Injection_Prevention_Cheat_Sheet.html> · <https://cwe.mitre.org/data/definitions/89.html>
-
-## Recon signals (where to look)
-
-- A single quote or a paired OR 1=1 / OR 1=2 pair producing a repeatable response difference is the primary first-order SQLi signal.  _(merged 1 duplicate row(s))_
-  - **Disproof:** If the quote and both boolean twins produce byte-identical responses, the field shows no first-order SQLi signal.
-  - Sources: <https://raw.githubusercontent.com/OWASP/wstg/master/document/4-Web_Application_Security_Testing/07-Injection/05-SQL_Injection.md> · <https://portswigger.net/web-security/sql-injection>
-- If the app neither returns query results nor error differences nor timing changes, the query may run asynchronously; absence of in-band signal does not mean absence of SQLi.  _(merged 1 duplicate row(s))_
-  - **Disproof:** If an OAST payload produces no collaborator/DNS callback and conditional time delays stay within baseline jitter, the parameter is very likely not injectable.
-  - Sources: <https://owasp.org/www-project-web-security-testing-guide/stable/4-Web_Application_Security_Testing/07-Input_Validation_Testing/05-Testing_for_SQL_Injection.html> · <https://raw.githubusercontent.com/OWASP/wstg/v4.2/document/4-Web_Application_Security_Testing/07-Input_Validation_Testing/05-Testing_for_SQL_Injection.md> · <https://portswigger.net/web-security/sql-injection/blind>
 
 ## Techniques (what to change)
 
-- A UNION-based SQL injection is confirmed by matching the number of columns in the injected result set against the original query using successive NULL placeholders, then selecting data from other tables.  _(merged 1 duplicate row(s))_
-  - **Disproof:** The claim is false when the original query always returns a fixed number of columns unrelated to the injection point, when the database does not expose the metadata used (a closed source or heavily restricted RDBMS), or when the response is identical across every NULL-count probe, which proves no UNION result set reached the output.
-  - Sources: <https://portswigger.net/web-security/sql-injection/union-based> · <https://www.w3schools.com/sql/sql_union.asp>
-- A UNION-based SQL injection is confirmed by matching the result-set column count through successively longer runs of NULL placeholders, and NULL is used as the filler because it type-checks in any column position and so maximises the chance the payload succeeds.  _(merged 1 duplicate row(s))_
-  - **Disproof:** If no NULL-counted payload ever produces the extra result set or alters the response, the column count was never matched and the UNION injection is not demonstrated.
-  - Sources: <https://cwe.mitre.org/data/definitions/89.html> · <https://docs.djangoproject.com/en/5.0/topics/db/sql/> · <https://kathan19.gitbook.io/howtohunt/sqli/sql_injection.md>
-- A boolean-based blind SQL injection is confirmed when the application's response changes based on a injected condition that is true versus one that is false, with no error or data returned.  _(merged 1 duplicate row(s))_ _(unverified)_
-  - **Disproof:** The claim is false when the same request produces no behavioural change when the query is rewritten so the value is bound rather than concatenated, because then the condition was never evaluated by the database. It also fails if the observed difference is reproducible with the payload removed or with a syntactically identical but semantically neutral value, which points at response timing, caching, or application logic rather than injection.
-  - Sources: <https://owasp.org/www-community/attacks/SQL_Injection> · <https://portswigger.net/web-security/sql-injection/blind>
-- A time-based blind SQL injection is confirmed when the response delay produced by injecting a SLEEP() predicate is measurable and reproducible, and stops when the condition is made false or when the value is bound.  _(merged 1 duplicate row(s))_ _(unverified)_
-  - **Disproof:** The claim is false when the observed delay is identical regardless of the condition, which means the database never evaluated the predicate, or when the delay is caused by the endpoint's own behaviour (slow query, saturation, upstream dependency) rather than by the injected predicate. It also fails when the payload is bound, since the function then receives a literal string and never sleeps.
-  - Sources: <https://owasp.org/www-community/attacks/SQL_Injection> · <https://portswigger.net/web-security/sql-injection/blind>
-- An MSSQL injection point doubles as a privilege-reach probe: calling fn_my_permissions against the database and filtering on a named permission tells the tester which database-level grants the injected session actually holds before they plan any escalation.  _(merged 1 duplicate row(s))_
-  - **Disproof:** fn_my_permissions returning no rows, or an empty grant set, for a login that demonstrably holds the named database permission refutes it as a reach check.
-  - Sources: <https://portswigger.net/web-security/sql-injection> · <https://raw.githubusercontent.com/HackTricks-wiki/hacktricks/master/src/pentesting-web/sql-injection/mssql-injection.md>
-- Blind boolean injection extracts arbitrary values one character at a time by making the app's visible behaviour depend on a single condition.  _(merged 1 duplicate row(s))_
-  - **Disproof:** If the application's behaviour is identical whether the condition is true or false, boolean extraction is impossible and time-based or OAST is required.
-  - Sources: <https://owasp.org/www-project-web-security-testing-guide/stable/4-Web_Application_Security_Testing/07-Input_Validation_Testing/05-Testing_for_SQL_Injection.html> · <https://raw.githubusercontent.com/OWASP/wstg/v4.2/document/4-Web_Application_Security_Testing/07-Input_Validation_Testing/05-Testing_for_SQL_Injection.md> · <https://portswigger.net/web-security/sql-injection/blind>
-- Error-based SQL injection extracts data by triggering database error messages that echo the injected value or the attacked metadata, and is confirmed when an error response reveals a table, column, or value that was not present in the baseline.  _(merged 1 duplicate row(s))_
-  - **Disproof:** The claim is false when the error message only reports a syntax or constraint violation with no embedded target value, or when the same error appears before any injection is attempted, which means the message is a framework default rather than a data channel. If the value only ever appears in the application's own echoed input and never in a database error, the finding is verbose errors, not error-based injection.
-  - Sources: <https://cheatsheetseries.owasp.org/cheatsheets/SQL_Injection_Prevention_Cheat_Sheet.html> · <https://portswigger.net/web-security/sql-injection/blind>
-- For example, consider using persistence layers such as Hibernate or Enterprise Java Beans, which can provide significant protection against SQL injection if used properly.  _(merged 1 duplicate row(s))_
-  - **Disproof:** Refuted when: the value is bound as a parameter or written through the framework's own encoder, so the interpreter never sees attacker text as syntax. Settle it by running the identical request with and without that one control and diffing the response -- if the difference the claim predicts does not appear, the claim is false. Specifically, this is refuted if the behaviour described (“For example, consider using persistence layers such as Hibernate or Enterprise J”) does not occur under a test that isolates that control.
-  - Sources: <https://cwe.mitre.org/data/definitions/89.html> · <https://owasp.org/www-community/attacks/SQL_Injection>
-- If authorization information is held in a SQL database, it may be possible to change this information through the successful exploitation of a SQL injection vulnerability.  _(merged 1 duplicate row(s))_
-  - **Disproof:** Refuted when: the value is bound as a parameter or written through the framework's own encoder, so the interpreter never sees attacker text as syntax. Settle it by running the identical request with and without that one control and diffing the response -- if the difference the claim predicts does not appear, the claim is false. Specifically, this is refuted if the behaviour described (“If authorization information is held in a SQL database, it may be possible to ch”) does not occur under a test that isolates that control.
-  - Sources: <https://cwe.mitre.org/data/definitions/89.html> · <https://owasp.org/www-community/attacks/SQL_Injection>
-- Incrementing ORDER BY <n> until a response change appears infers the column count of the original query even when errors are suppressed.  _(merged 1 duplicate row(s))_
-  - **Disproof:** If every index from 1 upward yields an identical response, ORDER BY cannot be used for column counting and you must rely on UNION NULL probing.
-  - Sources: <https://cheatsheetseries.owasp.org/cheatsheets/SQL_Injection_Prevention_Cheat_Sheet.html> · <https://portswigger.net/web-security/sql-injection/union-attacks>
-- Input validation will not always prevent SQL injection, especially if you are required to support free-form text fields that could contain arbitrary characters.  _(merged 1 duplicate row(s))_
-  - **Disproof:** Refuted when: the value is bound as a parameter or written through the framework's own encoder, so the interpreter never sees attacker text as syntax. Settle it by running the identical request with and without that one control and diffing the response -- if the difference the claim predicts does not appear, the claim is false. Specifically, this is refuted if the behaviour described (“Input validation will not always prevent SQL injection, especially if you are re”) does not occur under a test that isolates that control.
-  - Sources: <https://cwe.mitre.org/data/definitions/89.html> · <https://owasp.org/www-community/attacks/SQL_Injection>
-- Inside an injected MS Access query, TOP and LAST act as row selectors, so the tester can cap or reverse the result set and page out a table's records instead of dumping it whole.  _(merged 1 duplicate row(s))_
-  - **Disproof:** TOP or LAST modifiers rejected as syntax by the same injection point, or accepted but leaving the returned rows unchanged, refute their use as row-selection controls.
-  - Sources: <https://sqlite.org/lang_expr.html> · <https://raw.githubusercontent.com/HackTricks-wiki/hacktricks/master/src/pentesting-web/sql-injection/ms-access-sql-injection.md>
-- MySQL schema and table names come out of a UNION SELECT with GROUP_CONCAT over information_schema, and the alternating letter case of the quoted keywords is the point: the enumeration has to be sent in mixed case so a filter matching keywords in one fixed case does not stop it.  _(merged 1 duplicate row(s))_
-  - **Disproof:** A filter that blocks the mixed-case spelling while letting the all-lowercase form through, or a UNION SELECT that returns no schema rows despite a working injection point, refutes this enumeration route.
-  - Sources: <https://cheatsheetseries.owasp.org/cheatsheets/SQL_Injection_Prevention_Cheat_Sheet.html> · <https://raw.githubusercontent.com/HackTricks-wiki/hacktricks/master/src/pentesting-web/sql-injection/mysql-injection/README.md>
-- Naming a target table turns the same UNION SELECT pattern into a column dictionary, so the tester moves from which tables exist to exactly which attributes the injected query can reference.  _(merged 1 duplicate row(s))_
-  - **Disproof:** The column enumeration coming back empty for a table that the same injection point can already read rows from refutes this metadata route.
-  - Sources: <https://cheatsheetseries.owasp.org/cheatsheets/SQL_Injection_Prevention_Cheat_Sheet.html> · <https://raw.githubusercontent.com/HackTricks-wiki/hacktricks/master/src/pentesting-web/sql-injection/mysql-injection/README.md>
-- On MSSQL a single injected UNION SELECT over information_schema.columns hands back the schema, table and column names of the current database at once, and on error-based vectors every selected expression has to carry an alias or the query will not come back.  _(merged 1 duplicate row(s))_
-  - **Disproof:** An error-based injected select that errors purely because an expression lacks an alias, or a schema enumeration that returns no rows despite a working injection point, refutes these requirements.
-  - Sources: <https://portswigger.net/web-security/sql-injection> · <https://raw.githubusercontent.com/HackTricks-wiki/hacktricks/master/src/pentesting-web/sql-injection/mssql-injection.md>
-- Once a UNION SELECT column count is aligned, the tester can read a chosen position out of a table with a wildcard select and never has to know the column's name, which is how data leaves the database once the injection point is confirmed.  _(merged 1 duplicate row(s))_
-  - **Disproof:** A wildcard select that returns nothing from a table known to be readable, or one that fails purely on a column-count mismatch, refutes the positional-access claim.
-  - Sources: <https://cwe.mitre.org/data/definitions/89.html> · <https://raw.githubusercontent.com/HackTricks-wiki/hacktricks/master/src/pentesting-web/sql-injection/README.md>
-- SQL injection is confirmed by a boolean differential: a condition that is always true returns the normal row count while the same condition forced false returns a different one.  _(merged 1 duplicate row(s))_
-  - **Disproof:** Refuted when the application returns an identical response for true and false conditions, which indicates the value is escaped, parameterised, or never reaches a SQL parser.
-  - Sources: <https://owasp.org/www-community/attacks/SQL_Injection> · <https://portswigger.net/web-security/sql-injection> · <https://raw.githubusercontent.com/Esther7171/HackTheBox-Writeups-Walkthroughs/main/Write-ups/Academy/05.%20Web%20Exploitation/25.%20SQL%20Injection%20Fundamentals/SQL%20Injection%20Fundamentals.md>
-- UNION SELECT NULL with increasing NULL counts finds the column count, then a string marker in each position finds a column type that can carry exfiltrated data.  _(merged 1 duplicate row(s))_
-  - **Disproof:** If the response is identical for wrong and correct NULL counts, the UNION column-count method is ineffective and you must use boolean or error-based inference.
-  - Sources: <https://raw.githubusercontent.com/OWASP/wstg/master/document/4-Web_Application_Security_Testing/07-Injection/05-SQL_Injection.md> · <https://portswigger.net/web-security/sql-injection/union-attacks>
-
-## Tests
-
-- MS Access hands the tester a file-existence oracle from inside the injection: point the database reference at a local file and the invalid-database-format error appears only when that file is really there, so file enumeration is driven by comparing errors across candidate paths.  _(merged 1 duplicate row(s))_
-  - **Disproof:** The invalid-format error appearing identically for names that do not exist, or never appearing for one that does, refutes the existence oracle.
-  - Sources: <https://sqlite.org/lang_expr.html> · <https://raw.githubusercontent.com/HackTricks-wiki/hacktricks/master/src/pentesting-web/sql-injection/ms-access-sql-injection.md>
-- On MSSQL the tester can read the live query text back through sys.dm_exec_requests joined to sys.dm_exec_sql_text, which is the way to confirm the injection really landed in the query and to see the surrounding SQL, with the server-level permission checked separately.  _(merged 1 duplicate row(s))_
-  - **Disproof:** The DMVs returning nothing, or returning a query that does not contain the injected syntax, refutes their use for reading back the currently executing SQL query.
-  - Sources: <https://portswigger.net/web-security/sql-injection> · <https://raw.githubusercontent.com/HackTricks-wiki/hacktricks/master/src/pentesting-web/sql-injection/mssql-injection.md>
-- To decide this case, observe: Establish a baseline with clearly invalid input such as a string where a number is expected, and check whether that also 500s.  _(merged 1 duplicate row(s))_ _(unverified)_
-  - **Disproof:** This test does not apply where the surrounding behaviour is unobservable -- for example when the response is identical in every case, or when the only evidence is server-side and not reflected to the requester. The originating rule (sqli.fp_rule.generic_500_not_sqli) states the full boundary.
-  - Sources: <https://raw.githubusercontent.com/OWASP/wstg/master/document/4-Web_Application_Security_Testing/07-Injection/05-SQL_Injection.md> · <https://portswigger.net/web-security/sql-injection/blind>
-- To decide this case, observe: For each candidate field, replay the true/false pair three times with all other parameters identical and diff status code, headers and body.  _(merged 1 duplicate row(s))_ _(unverified)_
-  - **Disproof:** This test does not apply where the surrounding behaviour is unobservable -- for example when the response is identical in every case, or when the only evidence is server-side and not reflected to the requester. The originating rule (sqli.validation.single_variable_differential) states the full boundary.
-  - Sources: <https://raw.githubusercontent.com/OWASP/wstg/v4.2/document/4-Web_Application_Security_Testing/07-Input_Validation_Testing/05-Testing_for_SQL_Injection.md> · <https://portswigger.net/web-security/sql-injection/blind>
-- When a blind SQL injection returns no data, the proof is made of timing: concatenate a deliberately slow operation into the SQL query and look for a repeatable jump in page-load time that the unmodified request does not show.  _(merged 1 duplicate row(s))_
-  - **Disproof:** A concatenated slow operation that leaves page-load time flat, or a delay that appears just as often on a control request carrying no injected syntax, refutes it as a blind SQL injection oracle.
-  - Sources: <https://cwe.mitre.org/data/definitions/89.html> · <https://raw.githubusercontent.com/HackTricks-wiki/hacktricks/master/src/pentesting-web/sql-injection/README.md>
-
-## Validation bar (how to prove it)
-
-- A SQLi finding is only validated when one variable changes and the response difference is reproducible and explainable by query logic.  _(merged 1 duplicate row(s))_ _(unverified)_
-  - **Disproof:** If the difference is non-deterministic, cache- or session-driven, or does not reverse when the condition is inverted, it is not a validated SQLi.
-  - Sources: <https://owasp.org/www-project-web-security-testing-guide/stable/4-Web_Application_Security_Testing/07-Input_Validation_Testing/05-Testing_for_SQL_Injection.html> · <https://raw.githubusercontent.com/OWASP/wstg/v4.2/document/4-Web_Application_Security_Testing/07-Input_Validation_Testing/05-Testing_for_SQL_Injection.md> · <https://portswigger.net/web-security/sql-injection/blind>
-- A boolean or time differential found while several parameters are being varied at once is not attributable to any of them, so the finding is only valid once the same differential reproduces with exactly one variable changed.  _(merged 1 duplicate row(s))_
... (truncated)
```

## 2026-11-01 08:04 — 11 diff lines
- items: 1 (supported 0), FP rules 0, chains 0, state researching
- still missing: methodology, items, supported_items, fp_rules, chain

```diff
--- sqli@current
+++ sqli@new
@@ -11,7 +11,7 @@
 
 > surface `web` · CWE — · OWASP —
 > evidence: 1 items, 0 supported, 0 FP rules, 0 chains
-> maturity: **researching** — missing: items, supported_items, fp_rules, chain
+> maturity: **researching** — missing: methodology, items, supported_items, fp_rules, chain
 
 
 ## Techniques (what to change)
```

## 2026-11-02 08:52 — 228 diff lines
- items: 45 (supported 34), FP rules 12, chains 1, state mature

```diff
--- sqli@current
+++ sqli@new
@@ -9,15 +9,219 @@
      Edit the rows (or ingest better research) and re-run:
      python -m wks.skillgen -->
 
-> surface `web` · CWE — · OWASP —
-> evidence: 1 items, 0 supported, 0 FP rules, 0 chains
-> maturity: **researching** — missing: methodology, items, supported_items, fp_rules, chain
-
+> surface `web` · CWE CWE-89 · OWASP A03:2021
+> evidence: 45 items, 34 supported, 12 FP rules, 1 chains
+> maturity: **mature**
+
+Attacker-controlled input is concatenated into a SQL statement, so the query structure becomes attacker-controlled.
+
+**Also called:** sql injection, sqli, second order sql injection, nosql injection operator
+
+
+## Prerequisites (do not start without these)
+
+- Any request-controllable value that reaches a SQL query is a candidate injection point, including JSON/XML bodies, cookies and headers, not just GET parameters.  _(merged 1 duplicate row(s))_
+  - **Disproof:** If a field's value is provably never used in any query (e.g. purely client-side sorting or CSRF tokens), it cannot be an injection point.
+  - Sources: <https://raw.githubusercontent.com/OWASP/wstg/master/document/4-Web_Application_Security_Testing/07-Injection/05-SQL_Injection.md> · <https://portswigger.net/web-security/sql-injection>
+- Extraction on MS Access is gated on naming a real column such as username, so the guess-and-check step on column names comes before any value can be pulled out of the database through the injection.  _(merged 1 duplicate row(s))_
+  - **Disproof:** Reading a value out of MS Access with no valid column name in the injected query, or a fabricated column name returning data, refutes this ordering.
+  - Sources: <https://sqlite.org/lang_expr.html> · <https://raw.githubusercontent.com/HackTricks-wiki/hacktricks/master/src/pentesting-web/sql-injection/ms-access-sql-injection.md>
+- Prepared/parameterized statements force the DB to separate code from data, so bind-variable queries are the baseline you must establish before treating quote errors as SQLi.  _(merged 1 duplicate row(s))_
+  - **Disproof:** If the query string is built by concatenation at runtime even when a parameterized API exists elsewhere, the endpoint is not parameterized.
+  - Sources: <https://cheatsheetseries.owasp.org/cheatsheets/SQL_Injection_Prevention_Cheat_Sheet.html> · <https://cwe.mitre.org/data/definitions/89.html>
+
+## Recon signals (where to look)
+
+- A single quote or a paired OR 1=1 / OR 1=2 pair producing a repeatable response difference is the primary first-order SQLi signal.  _(merged 1 duplicate row(s))_
+  - **Disproof:** If the quote and both boolean twins produce byte-identical responses, the field shows no first-order SQLi signal.
+  - Sources: <https://raw.githubusercontent.com/OWASP/wstg/master/document/4-Web_Application_Security_Testing/07-Injection/05-SQL_Injection.md> · <https://portswigger.net/web-security/sql-injection>
+- If the app neither returns query results nor error differences nor timing changes, the query may run asynchronously; absence of in-band signal does not mean absence of SQLi.  _(merged 1 duplicate row(s))_
+  - **Disproof:** If an OAST payload produces no collaborator/DNS callback and conditional time delays stay within baseline jitter, the parameter is very likely not injectable.
+  - Sources: <https://owasp.org/www-project-web-security-testing-guide/stable/4-Web_Application_Security_Testing/07-Input_Validation_Testing/05-Testing_for_SQL_Injection.html> · <https://raw.githubusercontent.com/OWASP/wstg/v4.2/document/4-Web_Application_Security_Testing/07-Input_Validation_Testing/05-Testing_for_SQL_Injection.md> · <https://portswigger.net/web-security/sql-injection/blind>
 
 ## Techniques (what to change)
 
-- The endpoint returned a different number of rows for a true predicate than for the corresponding false predicate. The difference was stable across repeated requests, which proves the boolean condition is evaluated by the database rather than by the application. This confirmed a blind SQL injection vulnerability.  _(merged 1 duplicate row(s))_ _(unverified)_
-  - Sources: <https://example.com/advisories/blind-sqli-search>
+- A UNION-based SQL injection is confirmed by matching the number of columns in the injected result set against the original query using successive NULL placeholders, then selecting data from other tables.  _(merged 1 duplicate row(s))_
+  - **Disproof:** The claim is false when the original query always returns a fixed number of columns unrelated to the injection point, when the database does not expose the metadata used (a closed source or heavily restricted RDBMS), or when the response is identical across every NULL-count probe, which proves no UNION result set reached the output.
+  - Sources: <https://portswigger.net/web-security/sql-injection/union-based> · <https://www.w3schools.com/sql/sql_union.asp>
+- A UNION-based SQL injection is confirmed by matching the result-set column count through successively longer runs of NULL placeholders, and NULL is used as the filler because it type-checks in any column position and so maximises the chance the payload succeeds.  _(merged 1 duplicate row(s))_
+  - **Disproof:** If no NULL-counted payload ever produces the extra result set or alters the response, the column count was never matched and the UNION injection is not demonstrated.
+  - Sources: <https://cwe.mitre.org/data/definitions/89.html> · <https://docs.djangoproject.com/en/5.0/topics/db/sql/> · <https://kathan19.gitbook.io/howtohunt/sqli/sql_injection.md>
+- A boolean-based blind SQL injection is confirmed when the application's response changes based on a injected condition that is true versus one that is false, with no error or data returned.  _(merged 1 duplicate row(s))_ _(unverified)_
+  - **Disproof:** The claim is false when the same request produces no behavioural change when the query is rewritten so the value is bound rather than concatenated, because then the condition was never evaluated by the database. It also fails if the observed difference is reproducible with the payload removed or with a syntactically identical but semantically neutral value, which points at response timing, caching, or application logic rather than injection.
+  - Sources: <https://owasp.org/www-community/attacks/SQL_Injection> · <https://portswigger.net/web-security/sql-injection/blind>
+- A time-based blind SQL injection is confirmed when the response delay produced by injecting a SLEEP() predicate is measurable and reproducible, and stops when the condition is made false or when the value is bound.  _(merged 1 duplicate row(s))_ _(unverified)_
+  - **Disproof:** The claim is false when the observed delay is identical regardless of the condition, which means the database never evaluated the predicate, or when the delay is caused by the endpoint's own behaviour (slow query, saturation, upstream dependency) rather than by the injected predicate. It also fails when the payload is bound, since the function then receives a literal string and never sleeps.
+  - Sources: <https://owasp.org/www-community/attacks/SQL_Injection> · <https://portswigger.net/web-security/sql-injection/blind>
+- An MSSQL injection point doubles as a privilege-reach probe: calling fn_my_permissions against the database and filtering on a named permission tells the tester which database-level grants the injected session actually holds before they plan any escalation.  _(merged 1 duplicate row(s))_
+  - **Disproof:** fn_my_permissions returning no rows, or an empty grant set, for a login that demonstrably holds the named database permission refutes it as a reach check.
+  - Sources: <https://portswigger.net/web-security/sql-injection> · <https://raw.githubusercontent.com/HackTricks-wiki/hacktricks/master/src/pentesting-web/sql-injection/mssql-injection.md>
+- Blind boolean injection extracts arbitrary values one character at a time by making the app's visible behaviour depend on a single condition.  _(merged 1 duplicate row(s))_
+  - **Disproof:** If the application's behaviour is identical whether the condition is true or false, boolean extraction is impossible and time-based or OAST is required.
+  - Sources: <https://owasp.org/www-project-web-security-testing-guide/stable/4-Web_Application_Security_Testing/07-Input_Validation_Testing/05-Testing_for_SQL_Injection.html> · <https://raw.githubusercontent.com/OWASP/wstg/v4.2/document/4-Web_Application_Security_Testing/07-Input_Validation_Testing/05-Testing_for_SQL_Injection.md> · <https://portswigger.net/web-security/sql-injection/blind>
+- Error-based SQL injection extracts data by triggering database error messages that echo the injected value or the attacked metadata, and is confirmed when an error response reveals a table, column, or value that was not present in the baseline.  _(merged 1 duplicate row(s))_
+  - **Disproof:** The claim is false when the error message only reports a syntax or constraint violation with no embedded target value, or when the same error appears before any injection is attempted, which means the message is a framework default rather than a data channel. If the value only ever appears in the application's own echoed input and never in a database error, the finding is verbose errors, not error-based injection.
+  - Sources: <https://cheatsheetseries.owasp.org/cheatsheets/SQL_Injection_Prevention_Cheat_Sheet.html> · <https://portswigger.net/web-security/sql-injection/blind>
+- For example, consider using persistence layers such as Hibernate or Enterprise Java Beans, which can provide significant protection against SQL injection if used properly.  _(merged 1 duplicate row(s))_
+  - **Disproof:** Refuted when: the value is bound as a parameter or written through the framework's own encoder, so the interpreter never sees attacker text as syntax. Settle it by running the identical request with and without that one control and diffing the response -- if the difference the claim predicts does not appear, the claim is false. Specifically, this is refuted if the behaviour described (“For example, consider using persistence layers such as Hibernate or Enterprise J”) does not occur under a test that isolates that control.
+  - Sources: <https://cwe.mitre.org/data/definitions/89.html> · <https://owasp.org/www-community/attacks/SQL_Injection>
+- If authorization information is held in a SQL database, it may be possible to change this information through the successful exploitation of a SQL injection vulnerability.  _(merged 1 duplicate row(s))_
+  - **Disproof:** Refuted when: the value is bound as a parameter or written through the framework's own encoder, so the interpreter never sees attacker text as syntax. Settle it by running the identical request with and without that one control and diffing the response -- if the difference the claim predicts does not appear, the claim is false. Specifically, this is refuted if the behaviour described (“If authorization information is held in a SQL database, it may be possible to ch”) does not occur under a test that isolates that control.
+  - Sources: <https://cwe.mitre.org/data/definitions/89.html> · <https://owasp.org/www-community/attacks/SQL_Injection>
+- Incrementing ORDER BY <n> until a response change appears infers the column count of the original query even when errors are suppressed.  _(merged 1 duplicate row(s))_
+  - **Disproof:** If every index from 1 upward yields an identical response, ORDER BY cannot be used for column counting and you must rely on UNION NULL probing.
+  - Sources: <https://cheatsheetseries.owasp.org/cheatsheets/SQL_Injection_Prevention_Cheat_Sheet.html> · <https://portswigger.net/web-security/sql-injection/union-attacks>
+- Input validation will not always prevent SQL injection, especially if you are required to support free-form text fields that could contain arbitrary characters.  _(merged 1 duplicate row(s))_
+  - **Disproof:** Refuted when: the value is bound as a parameter or written through the framework's own encoder, so the interpreter never sees attacker text as syntax. Settle it by running the identical request with and without that one control and diffing the response -- if the difference the claim predicts does not appear, the claim is false. Specifically, this is refuted if the behaviour described (“Input validation will not always prevent SQL injection, especially if you are re”) does not occur under a test that isolates that control.
+  - Sources: <https://cwe.mitre.org/data/definitions/89.html> · <https://owasp.org/www-community/attacks/SQL_Injection>
+- Inside an injected MS Access query, TOP and LAST act as row selectors, so the tester can cap or reverse the result set and page out a table's records instead of dumping it whole.  _(merged 1 duplicate row(s))_
+  - **Disproof:** TOP or LAST modifiers rejected as syntax by the same injection point, or accepted but leaving the returned rows unchanged, refute their use as row-selection controls.
+  - Sources: <https://sqlite.org/lang_expr.html> · <https://raw.githubusercontent.com/HackTricks-wiki/hacktricks/master/src/pentesting-web/sql-injection/ms-access-sql-injection.md>
+- MySQL schema and table names come out of a UNION SELECT with GROUP_CONCAT over information_schema, and the alternating letter case of the quoted keywords is the point: the enumeration has to be sent in mixed case so a filter matching keywords in one fixed case does not stop it.  _(merged 1 duplicate row(s))_
+  - **Disproof:** A filter that blocks the mixed-case spelling while letting the all-lowercase form through, or a UNION SELECT that returns no schema rows despite a working injection point, refutes this enumeration route.
+  - Sources: <https://cheatsheetseries.owasp.org/cheatsheets/SQL_Injection_Prevention_Cheat_Sheet.html> · <https://raw.githubusercontent.com/HackTricks-wiki/hacktricks/master/src/pentesting-web/sql-injection/mysql-injection/README.md>
+- Naming a target table turns the same UNION SELECT pattern into a column dictionary, so the tester moves from which tables exist to exactly which attributes the injected query can reference.  _(merged 1 duplicate row(s))_
+  - **Disproof:** The column enumeration coming back empty for a table that the same injection point can already read rows from refutes this metadata route.
+  - Sources: <https://cheatsheetseries.owasp.org/cheatsheets/SQL_Injection_Prevention_Cheat_Sheet.html> · <https://raw.githubusercontent.com/HackTricks-wiki/hacktricks/master/src/pentesting-web/sql-injection/mysql-injection/README.md>
+- On MSSQL a single injected UNION SELECT over information_schema.columns hands back the schema, table and column names of the current database at once, and on error-based vectors every selected expression has to carry an alias or the query will not come back.  _(merged 1 duplicate row(s))_
+  - **Disproof:** An error-based injected select that errors purely because an expression lacks an alias, or a schema enumeration that returns no rows despite a working injection point, refutes these requirements.
+  - Sources: <https://portswigger.net/web-security/sql-injection> · <https://raw.githubusercontent.com/HackTricks-wiki/hacktricks/master/src/pentesting-web/sql-injection/mssql-injection.md>
+- Once a UNION SELECT column count is aligned, the tester can read a chosen position out of a table with a wildcard select and never has to know the column's name, which is how data leaves the database once the injection point is confirmed.  _(merged 1 duplicate row(s))_
+  - **Disproof:** A wildcard select that returns nothing from a table known to be readable, or one that fails purely on a column-count mismatch, refutes the positional-access claim.
+  - Sources: <https://cwe.mitre.org/data/definitions/89.html> · <https://raw.githubusercontent.com/HackTricks-wiki/hacktricks/master/src/pentesting-web/sql-injection/README.md>
+- SQL injection is confirmed by a boolean differential: a condition that is always true returns the normal row count while the same condition forced false returns a different one.  _(merged 1 duplicate row(s))_
+  - **Disproof:** Refuted when the application returns an identical response for true and false conditions, which indicates the value is escaped, parameterised, or never reaches a SQL parser.
+  - Sources: <https://owasp.org/www-community/attacks/SQL_Injection> · <https://portswigger.net/web-security/sql-injection> · <https://raw.githubusercontent.com/Esther7171/HackTheBox-Writeups-Walkthroughs/main/Write-ups/Academy/05.%20Web%20Exploitation/25.%20SQL%20Injection%20Fundamentals/SQL%20Injection%20Fundamentals.md>
+- UNION SELECT NULL with increasing NULL counts finds the column count, then a string marker in each position finds a column type that can carry exfiltrated data.  _(merged 1 duplicate row(s))_
+  - **Disproof:** If the response is identical for wrong and correct NULL counts, the UNION column-count method is ineffective and you must use boolean or error-based inference.
+  - Sources: <https://raw.githubusercontent.com/OWASP/wstg/master/document/4-Web_Application_Security_Testing/07-Injection/05-SQL_Injection.md> · <https://portswigger.net/web-security/sql-injection/union-attacks>
+
+## Tests
+
+- MS Access hands the tester a file-existence oracle from inside the injection: point the database reference at a local file and the invalid-database-format error appears only when that file is really there, so file enumeration is driven by comparing errors across candidate paths.  _(merged 1 duplicate row(s))_
+  - **Disproof:** The invalid-format error appearing identically for names that do not exist, or never appearing for one that does, refutes the existence oracle.
+  - Sources: <https://sqlite.org/lang_expr.html> · <https://raw.githubusercontent.com/HackTricks-wiki/hacktricks/master/src/pentesting-web/sql-injection/ms-access-sql-injection.md>
+- On MSSQL the tester can read the live query text back through sys.dm_exec_requests joined to sys.dm_exec_sql_text, which is the way to confirm the injection really landed in the query and to see the surrounding SQL, with the server-level permission checked separately.  _(merged 1 duplicate row(s))_
+  - **Disproof:** The DMVs returning nothing, or returning a query that does not contain the injected syntax, refutes their use for reading back the currently executing SQL query.
+  - Sources: <https://portswigger.net/web-security/sql-injection> · <https://raw.githubusercontent.com/HackTricks-wiki/hacktricks/master/src/pentesting-web/sql-injection/mssql-injection.md>
+- To decide this case, observe: Establish a baseline with clearly invalid input such as a string where a number is expected, and check whether that also 500s.  _(merged 1 duplicate row(s))_ _(unverified)_
+  - **Disproof:** This test does not apply where the surrounding behaviour is unobservable -- for example when the response is identical in every case, or when the only evidence is server-side and not reflected to the requester. The originating rule (sqli.fp_rule.generic_500_not_sqli) states the full boundary.
+  - Sources: <https://raw.githubusercontent.com/OWASP/wstg/master/document/4-Web_Application_Security_Testing/07-Injection/05-SQL_Injection.md> · <https://portswigger.net/web-security/sql-injection/blind>
+- To decide this case, observe: For each candidate field, replay the true/false pair three times with all other parameters identical and diff status code, headers and body.  _(merged 1 duplicate row(s))_ _(unverified)_
+  - **Disproof:** This test does not apply where the surrounding behaviour is unobservable -- for example when the response is identical in every case, or when the only evidence is server-side and not reflected to the requester. The originating rule (sqli.validation.single_variable_differential) states the full boundary.
+  - Sources: <https://raw.githubusercontent.com/OWASP/wstg/v4.2/document/4-Web_Application_Security_Testing/07-Input_Validation_Testing/05-Testing_for_SQL_Injection.md> · <https://portswigger.net/web-security/sql-injection/blind>
+- When a blind SQL injection returns no data, the proof is made of timing: concatenate a deliberately slow operation into the SQL query and look for a repeatable jump in page-load time that the unmodified request does not show.  _(merged 1 duplicate row(s))_
+  - **Disproof:** A concatenated slow operation that leaves page-load time flat, or a delay that appears just as often on a control request carrying no injected syntax, refutes it as a blind SQL injection oracle.
+  - Sources: <https://cwe.mitre.org/data/definitions/89.html> · <https://raw.githubusercontent.com/HackTricks-wiki/hacktricks/master/src/pentesting-web/sql-injection/README.md>
+
+## Validation bar (how to prove it)
+
+- A SQLi finding is only validated when one variable changes and the response difference is reproducible and explainable by query logic.  _(merged 1 duplicate row(s))_ _(unverified)_
... (truncated)
```

## 2026-11-02 09:01 — 227 diff lines
- items: 1 (supported 0), FP rules 0, chains 0, state researching
- still missing: items, supported_items, fp_rules, chain

```diff
--- sqli@current
+++ sqli@new
@@ -9,219 +9,15 @@
      Edit the rows (or ingest better research) and re-run:
      python -m wks.skillgen -->
 
-> surface `web` · CWE CWE-89 · OWASP A03:2021
-> evidence: 45 items, 34 supported, 12 FP rules, 1 chains
-> maturity: **mature**
+> surface `web` · CWE — · OWASP —
+> evidence: 1 items, 0 supported, 0 FP rules, 0 chains
+> maturity: **researching** — missing: items, supported_items, fp_rules, chain
 
-Attacker-controlled input is concatenated into a SQL statement, so the query structure becomes attacker-controlled.
-
-**Also called:** sql injection, sqli, second order sql injection, nosql injection operator
-
-
-## Prerequisites (do not start without these)
-
-- Any request-controllable value that reaches a SQL query is a candidate injection point, including JSON/XML bodies, cookies and headers, not just GET parameters.  _(merged 1 duplicate row(s))_
-  - **Disproof:** If a field's value is provably never used in any query (e.g. purely client-side sorting or CSRF tokens), it cannot be an injection point.
-  - Sources: <https://raw.githubusercontent.com/OWASP/wstg/master/document/4-Web_Application_Security_Testing/07-Injection/05-SQL_Injection.md> · <https://portswigger.net/web-security/sql-injection>
-- Extraction on MS Access is gated on naming a real column such as username, so the guess-and-check step on column names comes before any value can be pulled out of the database through the injection.  _(merged 1 duplicate row(s))_
-  - **Disproof:** Reading a value out of MS Access with no valid column name in the injected query, or a fabricated column name returning data, refutes this ordering.
-  - Sources: <https://sqlite.org/lang_expr.html> · <https://raw.githubusercontent.com/HackTricks-wiki/hacktricks/master/src/pentesting-web/sql-injection/ms-access-sql-injection.md>
-- Prepared/parameterized statements force the DB to separate code from data, so bind-variable queries are the baseline you must establish before treating quote errors as SQLi.  _(merged 1 duplicate row(s))_
-  - **Disproof:** If the query string is built by concatenation at runtime even when a parameterized API exists elsewhere, the endpoint is not parameterized.
-  - Sources: <https://cheatsheetseries.owasp.org/cheatsheets/SQL_Injection_Prevention_Cheat_Sheet.html> · <https://cwe.mitre.org/data/definitions/89.html>
-
-## Recon signals (where to look)
-
-- A single quote or a paired OR 1=1 / OR 1=2 pair producing a repeatable response difference is the primary first-order SQLi signal.  _(merged 1 duplicate row(s))_
-  - **Disproof:** If the quote and both boolean twins produce byte-identical responses, the field shows no first-order SQLi signal.
-  - Sources: <https://raw.githubusercontent.com/OWASP/wstg/master/document/4-Web_Application_Security_Testing/07-Injection/05-SQL_Injection.md> · <https://portswigger.net/web-security/sql-injection>
-- If the app neither returns query results nor error differences nor timing changes, the query may run asynchronously; absence of in-band signal does not mean absence of SQLi.  _(merged 1 duplicate row(s))_
-  - **Disproof:** If an OAST payload produces no collaborator/DNS callback and conditional time delays stay within baseline jitter, the parameter is very likely not injectable.
-  - Sources: <https://owasp.org/www-project-web-security-testing-guide/stable/4-Web_Application_Security_Testing/07-Input_Validation_Testing/05-Testing_for_SQL_Injection.html> · <https://raw.githubusercontent.com/OWASP/wstg/v4.2/document/4-Web_Application_Security_Testing/07-Input_Validation_Testing/05-Testing_for_SQL_Injection.md> · <https://portswigger.net/web-security/sql-injection/blind>
 
 ## Techniques (what to change)
 
-- A UNION-based SQL injection is confirmed by matching the number of columns in the injected result set against the original query using successive NULL placeholders, then selecting data from other tables.  _(merged 1 duplicate row(s))_
-  - **Disproof:** The claim is false when the original query always returns a fixed number of columns unrelated to the injection point, when the database does not expose the metadata used (a closed source or heavily restricted RDBMS), or when the response is identical across every NULL-count probe, which proves no UNION result set reached the output.
-  - Sources: <https://portswigger.net/web-security/sql-injection/union-based> · <https://www.w3schools.com/sql/sql_union.asp>
-- A UNION-based SQL injection is confirmed by matching the result-set column count through successively longer runs of NULL placeholders, and NULL is used as the filler because it type-checks in any column position and so maximises the chance the payload succeeds.  _(merged 1 duplicate row(s))_
-  - **Disproof:** If no NULL-counted payload ever produces the extra result set or alters the response, the column count was never matched and the UNION injection is not demonstrated.
-  - Sources: <https://cwe.mitre.org/data/definitions/89.html> · <https://docs.djangoproject.com/en/5.0/topics/db/sql/> · <https://kathan19.gitbook.io/howtohunt/sqli/sql_injection.md>
-- A boolean-based blind SQL injection is confirmed when the application's response changes based on a injected condition that is true versus one that is false, with no error or data returned.  _(merged 1 duplicate row(s))_ _(unverified)_
-  - **Disproof:** The claim is false when the same request produces no behavioural change when the query is rewritten so the value is bound rather than concatenated, because then the condition was never evaluated by the database. It also fails if the observed difference is reproducible with the payload removed or with a syntactically identical but semantically neutral value, which points at response timing, caching, or application logic rather than injection.
-  - Sources: <https://owasp.org/www-community/attacks/SQL_Injection> · <https://portswigger.net/web-security/sql-injection/blind>
-- A time-based blind SQL injection is confirmed when the response delay produced by injecting a SLEEP() predicate is measurable and reproducible, and stops when the condition is made false or when the value is bound.  _(merged 1 duplicate row(s))_ _(unverified)_
-  - **Disproof:** The claim is false when the observed delay is identical regardless of the condition, which means the database never evaluated the predicate, or when the delay is caused by the endpoint's own behaviour (slow query, saturation, upstream dependency) rather than by the injected predicate. It also fails when the payload is bound, since the function then receives a literal string and never sleeps.
-  - Sources: <https://owasp.org/www-community/attacks/SQL_Injection> · <https://portswigger.net/web-security/sql-injection/blind>
-- An MSSQL injection point doubles as a privilege-reach probe: calling fn_my_permissions against the database and filtering on a named permission tells the tester which database-level grants the injected session actually holds before they plan any escalation.  _(merged 1 duplicate row(s))_
-  - **Disproof:** fn_my_permissions returning no rows, or an empty grant set, for a login that demonstrably holds the named database permission refutes it as a reach check.
-  - Sources: <https://portswigger.net/web-security/sql-injection> · <https://raw.githubusercontent.com/HackTricks-wiki/hacktricks/master/src/pentesting-web/sql-injection/mssql-injection.md>
-- Blind boolean injection extracts arbitrary values one character at a time by making the app's visible behaviour depend on a single condition.  _(merged 1 duplicate row(s))_
-  - **Disproof:** If the application's behaviour is identical whether the condition is true or false, boolean extraction is impossible and time-based or OAST is required.
-  - Sources: <https://owasp.org/www-project-web-security-testing-guide/stable/4-Web_Application_Security_Testing/07-Input_Validation_Testing/05-Testing_for_SQL_Injection.html> · <https://raw.githubusercontent.com/OWASP/wstg/v4.2/document/4-Web_Application_Security_Testing/07-Input_Validation_Testing/05-Testing_for_SQL_Injection.md> · <https://portswigger.net/web-security/sql-injection/blind>
-- Error-based SQL injection extracts data by triggering database error messages that echo the injected value or the attacked metadata, and is confirmed when an error response reveals a table, column, or value that was not present in the baseline.  _(merged 1 duplicate row(s))_
-  - **Disproof:** The claim is false when the error message only reports a syntax or constraint violation with no embedded target value, or when the same error appears before any injection is attempted, which means the message is a framework default rather than a data channel. If the value only ever appears in the application's own echoed input and never in a database error, the finding is verbose errors, not error-based injection.
-  - Sources: <https://cheatsheetseries.owasp.org/cheatsheets/SQL_Injection_Prevention_Cheat_Sheet.html> · <https://portswigger.net/web-security/sql-injection/blind>
-- For example, consider using persistence layers such as Hibernate or Enterprise Java Beans, which can provide significant protection against SQL injection if used properly.  _(merged 1 duplicate row(s))_
-  - **Disproof:** Refuted when: the value is bound as a parameter or written through the framework's own encoder, so the interpreter never sees attacker text as syntax. Settle it by running the identical request with and without that one control and diffing the response -- if the difference the claim predicts does not appear, the claim is false. Specifically, this is refuted if the behaviour described (“For example, consider using persistence layers such as Hibernate or Enterprise J”) does not occur under a test that isolates that control.
-  - Sources: <https://cwe.mitre.org/data/definitions/89.html> · <https://owasp.org/www-community/attacks/SQL_Injection>
-- If authorization information is held in a SQL database, it may be possible to change this information through the successful exploitation of a SQL injection vulnerability.  _(merged 1 duplicate row(s))_
-  - **Disproof:** Refuted when: the value is bound as a parameter or written through the framework's own encoder, so the interpreter never sees attacker text as syntax. Settle it by running the identical request with and without that one control and diffing the response -- if the difference the claim predicts does not appear, the claim is false. Specifically, this is refuted if the behaviour described (“If authorization information is held in a SQL database, it may be possible to ch”) does not occur under a test that isolates that control.
-  - Sources: <https://cwe.mitre.org/data/definitions/89.html> · <https://owasp.org/www-community/attacks/SQL_Injection>
-- Incrementing ORDER BY <n> until a response change appears infers the column count of the original query even when errors are suppressed.  _(merged 1 duplicate row(s))_
-  - **Disproof:** If every index from 1 upward yields an identical response, ORDER BY cannot be used for column counting and you must rely on UNION NULL probing.
-  - Sources: <https://cheatsheetseries.owasp.org/cheatsheets/SQL_Injection_Prevention_Cheat_Sheet.html> · <https://portswigger.net/web-security/sql-injection/union-attacks>
-- Input validation will not always prevent SQL injection, especially if you are required to support free-form text fields that could contain arbitrary characters.  _(merged 1 duplicate row(s))_
-  - **Disproof:** Refuted when: the value is bound as a parameter or written through the framework's own encoder, so the interpreter never sees attacker text as syntax. Settle it by running the identical request with and without that one control and diffing the response -- if the difference the claim predicts does not appear, the claim is false. Specifically, this is refuted if the behaviour described (“Input validation will not always prevent SQL injection, especially if you are re”) does not occur under a test that isolates that control.
-  - Sources: <https://cwe.mitre.org/data/definitions/89.html> · <https://owasp.org/www-community/attacks/SQL_Injection>
-- Inside an injected MS Access query, TOP and LAST act as row selectors, so the tester can cap or reverse the result set and page out a table's records instead of dumping it whole.  _(merged 1 duplicate row(s))_
-  - **Disproof:** TOP or LAST modifiers rejected as syntax by the same injection point, or accepted but leaving the returned rows unchanged, refute their use as row-selection controls.
-  - Sources: <https://sqlite.org/lang_expr.html> · <https://raw.githubusercontent.com/HackTricks-wiki/hacktricks/master/src/pentesting-web/sql-injection/ms-access-sql-injection.md>
-- MySQL schema and table names come out of a UNION SELECT with GROUP_CONCAT over information_schema, and the alternating letter case of the quoted keywords is the point: the enumeration has to be sent in mixed case so a filter matching keywords in one fixed case does not stop it.  _(merged 1 duplicate row(s))_
-  - **Disproof:** A filter that blocks the mixed-case spelling while letting the all-lowercase form through, or a UNION SELECT that returns no schema rows despite a working injection point, refutes this enumeration route.
-  - Sources: <https://cheatsheetseries.owasp.org/cheatsheets/SQL_Injection_Prevention_Cheat_Sheet.html> · <https://raw.githubusercontent.com/HackTricks-wiki/hacktricks/master/src/pentesting-web/sql-injection/mysql-injection/README.md>
-- Naming a target table turns the same UNION SELECT pattern into a column dictionary, so the tester moves from which tables exist to exactly which attributes the injected query can reference.  _(merged 1 duplicate row(s))_
-  - **Disproof:** The column enumeration coming back empty for a table that the same injection point can already read rows from refutes this metadata route.
-  - Sources: <https://cheatsheetseries.owasp.org/cheatsheets/SQL_Injection_Prevention_Cheat_Sheet.html> · <https://raw.githubusercontent.com/HackTricks-wiki/hacktricks/master/src/pentesting-web/sql-injection/mysql-injection/README.md>
-- On MSSQL a single injected UNION SELECT over information_schema.columns hands back the schema, table and column names of the current database at once, and on error-based vectors every selected expression has to carry an alias or the query will not come back.  _(merged 1 duplicate row(s))_
-  - **Disproof:** An error-based injected select that errors purely because an expression lacks an alias, or a schema enumeration that returns no rows despite a working injection point, refutes these requirements.
-  - Sources: <https://portswigger.net/web-security/sql-injection> · <https://raw.githubusercontent.com/HackTricks-wiki/hacktricks/master/src/pentesting-web/sql-injection/mssql-injection.md>
-- Once a UNION SELECT column count is aligned, the tester can read a chosen position out of a table with a wildcard select and never has to know the column's name, which is how data leaves the database once the injection point is confirmed.  _(merged 1 duplicate row(s))_
-  - **Disproof:** A wildcard select that returns nothing from a table known to be readable, or one that fails purely on a column-count mismatch, refutes the positional-access claim.
-  - Sources: <https://cwe.mitre.org/data/definitions/89.html> · <https://raw.githubusercontent.com/HackTricks-wiki/hacktricks/master/src/pentesting-web/sql-injection/README.md>
-- SQL injection is confirmed by a boolean differential: a condition that is always true returns the normal row count while the same condition forced false returns a different one.  _(merged 1 duplicate row(s))_
-  - **Disproof:** Refuted when the application returns an identical response for true and false conditions, which indicates the value is escaped, parameterised, or never reaches a SQL parser.
-  - Sources: <https://owasp.org/www-community/attacks/SQL_Injection> · <https://portswigger.net/web-security/sql-injection> · <https://raw.githubusercontent.com/Esther7171/HackTheBox-Writeups-Walkthroughs/main/Write-ups/Academy/05.%20Web%20Exploitation/25.%20SQL%20Injection%20Fundamentals/SQL%20Injection%20Fundamentals.md>
-- UNION SELECT NULL with increasing NULL counts finds the column count, then a string marker in each position finds a column type that can carry exfiltrated data.  _(merged 1 duplicate row(s))_
-  - **Disproof:** If the response is identical for wrong and correct NULL counts, the UNION column-count method is ineffective and you must use boolean or error-based inference.
-  - Sources: <https://raw.githubusercontent.com/OWASP/wstg/master/document/4-Web_Application_Security_Testing/07-Injection/05-SQL_Injection.md> · <https://portswigger.net/web-security/sql-injection/union-attacks>
-
-## Tests
-
-- MS Access hands the tester a file-existence oracle from inside the injection: point the database reference at a local file and the invalid-database-format error appears only when that file is really there, so file enumeration is driven by comparing errors across candidate paths.  _(merged 1 duplicate row(s))_
-  - **Disproof:** The invalid-format error appearing identically for names that do not exist, or never appearing for one that does, refutes the existence oracle.
-  - Sources: <https://sqlite.org/lang_expr.html> · <https://raw.githubusercontent.com/HackTricks-wiki/hacktricks/master/src/pentesting-web/sql-injection/ms-access-sql-injection.md>
-- On MSSQL the tester can read the live query text back through sys.dm_exec_requests joined to sys.dm_exec_sql_text, which is the way to confirm the injection really landed in the query and to see the surrounding SQL, with the server-level permission checked separately.  _(merged 1 duplicate row(s))_
-  - **Disproof:** The DMVs returning nothing, or returning a query that does not contain the injected syntax, refutes their use for reading back the currently executing SQL query.
-  - Sources: <https://portswigger.net/web-security/sql-injection> · <https://raw.githubusercontent.com/HackTricks-wiki/hacktricks/master/src/pentesting-web/sql-injection/mssql-injection.md>
-- To decide this case, observe: Establish a baseline with clearly invalid input such as a string where a number is expected, and check whether that also 500s.  _(merged 1 duplicate row(s))_ _(unverified)_
-  - **Disproof:** This test does not apply where the surrounding behaviour is unobservable -- for example when the response is identical in every case, or when the only evidence is server-side and not reflected to the requester. The originating rule (sqli.fp_rule.generic_500_not_sqli) states the full boundary.
-  - Sources: <https://raw.githubusercontent.com/OWASP/wstg/master/document/4-Web_Application_Security_Testing/07-Injection/05-SQL_Injection.md> · <https://portswigger.net/web-security/sql-injection/blind>
-- To decide this case, observe: For each candidate field, replay the true/false pair three times with all other parameters identical and diff status code, headers and body.  _(merged 1 duplicate row(s))_ _(unverified)_
-  - **Disproof:** This test does not apply where the surrounding behaviour is unobservable -- for example when the response is identical in every case, or when the only evidence is server-side and not reflected to the requester. The originating rule (sqli.validation.single_variable_differential) states the full boundary.
-  - Sources: <https://raw.githubusercontent.com/OWASP/wstg/v4.2/document/4-Web_Application_Security_Testing/07-Input_Validation_Testing/05-Testing_for_SQL_Injection.md> · <https://portswigger.net/web-security/sql-injection/blind>
-- When a blind SQL injection returns no data, the proof is made of timing: concatenate a deliberately slow operation into the SQL query and look for a repeatable jump in page-load time that the unmodified request does not show.  _(merged 1 duplicate row(s))_
-  - **Disproof:** A concatenated slow operation that leaves page-load time flat, or a delay that appears just as often on a control request carrying no injected syntax, refutes it as a blind SQL injection oracle.
-  - Sources: <https://cwe.mitre.org/data/definitions/89.html> · <https://raw.githubusercontent.com/HackTricks-wiki/hacktricks/master/src/pentesting-web/sql-injection/README.md>
-
-## Validation bar (how to prove it)
-
-- A SQLi finding is only validated when one variable changes and the response difference is reproducible and explainable by query logic.  _(merged 1 duplicate row(s))_ _(unverified)_
-  - **Disproof:** If the difference is non-deterministic, cache- or session-driven, or does not reverse when the condition is inverted, it is not a validated SQLi.
-  - Sources: <https://owasp.org/www-project-web-security-testing-guide/stable/4-Web_Application_Security_Testing/07-Input_Validation_Testing/05-Testing_for_SQL_Injection.html> · <https://raw.githubusercontent.com/OWASP/wstg/v4.2/document/4-Web_Application_Security_Testing/07-Input_Validation_Testing/05-Testing_for_SQL_Injection.md> · <https://portswigger.net/web-security/sql-injection/blind>
-- A boolean or time differential found while several parameters are being varied at once is not attributable to any of them, so the finding is only valid once the same differential reproduces with exactly one variable changed.  _(merged 1 duplicate row(s))_
... (truncated)
```

## 2026-11-02 09:16 — 11 diff lines
- items: 1 (supported 0), FP rules 0, chains 0, state researching
- still missing: methodology, items, supported_items, fp_rules, chain

```diff
--- sqli@current
+++ sqli@new
@@ -11,7 +11,7 @@
 
 > surface `web` · CWE — · OWASP —
 > evidence: 1 items, 0 supported, 0 FP rules, 0 chains
-> maturity: **researching** — missing: items, supported_items, fp_rules, chain
+> maturity: **researching** — missing: methodology, items, supported_items, fp_rules, chain
 
 
 ## Techniques (what to change)
```
