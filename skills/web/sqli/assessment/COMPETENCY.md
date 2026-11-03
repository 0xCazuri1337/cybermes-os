# Methodology — SQL Injection

> Derived from 34 verified items. Regenerate with `python -m wks.methodgen --class sqli --apply`. Do not hand-edit: this file is a projection of the evidence, and edits are lost on the next cycle.

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

**Extraction on MS Access is gated on naming a real column such as username, so the guess-and-check step on column names comes before any value can be pulled out of the database through the injection.**

Extraction on MS Access is gated on naming a real column such as username, so the guess-and-check step on column names comes before any value can be pulled out of the database through the injection.

HackTricks reference: MS Access SQL Injection (pentesting-web/sql-injection/ms-access-sql-injection.md)

- *Disproof:* Reading a value out of MS Access with no valid column name in the injected query, or a fabricated column name returning data, refutes this ordering.
- *Evidence:* high_confidence — [raw.githubusercontent.com](https://raw.githubusercontent.com/HackTricks-wiki/hacktricks/master/src/pentesting-web/sql-injection/ms-access-sql-injection.md); [sqlite.org](https://sqlite.org/lang_expr.html)

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

**A UNION-based SQL injection is confirmed by matching the result-set column count through successively longer runs of NULL placeholders, and NULL is used as the filler because it type-checks in any column position and so maximises the chance the payload succeeds.**

A UNION-based SQL injection is confirmed by matching the result-set column count through successively longer runs of NULL placeholders, and NULL is used as the filler because it type-checks in any column position and so maximises the chance the payload succeeds.

HackTricks reference: sql injection (https://kathan19.gitbook.io/howtohunt/sqli/sql_injection.md)

- *Disproof:* If no NULL-counted payload ever produces the extra result set or alters the response, the column count was never matched and the UNION injection is not demonstrated.
- *Evidence:* high_confidence — [cwe.mitre.org](https://cwe.mitre.org/data/definitions/89.html); [docs.djangoproject.com](https://docs.djangoproject.com/en/5.0/topics/db/sql/); [kathan19.gitbook.io](https://kathan19.gitbook.io/howtohunt/sqli/sql_injection.md)

**Blind boolean injection extracts arbitrary values one character at a time by making the app's visible behaviour depend on a single condition.**

Find an endpoint whose behaviour changes with the row count (e.g. a welcome-back banner). Then send AND SUBSTRING((SELECT ...),1,1) > 'm' and binary-search the character, confirming with an equality test, repeating per position. Use this when results and errors are hidden but some response attribute still varies with query outcome.

- *Disproof:* If the application's behaviour is identical whether the condition is true or false, boolean extraction is impossible and time-based or OAST is required.
- *Evidence:* high_confidence — [owasp.org](https://owasp.org/www-project-web-security-testing-guide/stable/4-Web_Application_Security_Testing/07-Input_Validation_Testing/05-Testing_for_SQL_Injection.html); [portswigger.net](https://portswigger.net/web-security/sql-injection/blind); [raw.githubusercontent.com](https://raw.githubusercontent.com/OWASP/wstg/v4.2/document/4-Web_Application_Security_Testing/07-Input_Validation_Testing/05-Testing_for_SQL_Injection.md)

**Incrementing ORDER BY <n> until a response change appears infers the column count of the original query even when errors are suppressed.**

At a confirmed injection point send ' ORDER BY 1--, then 2, 3 and so on, comparing status, body length and content each time. The first index that changes behaviour marks the boundary. Cross-check with UNION SELECT NULL,... increments. Remember ORDER BY cannot take bind variables, so a sort-indicator parameter is a natural unparameterized injection surface.

- *Disproof:* If every index from 1 upward yields an identical response, ORDER BY cannot be used for column counting and you must rely on UNION NULL probing.
- *Evidence:* high_confidence — [cheatsheetseries.owasp.org](https://cheatsheetseries.owasp.org/cheatsheets/SQL_Injection_Prevention_Cheat_Sheet.html); [portswigger.net](https://portswigger.net/web-security/sql-injection/union-attacks)

**SQL injection is confirmed by a boolean differential: a condition that is always true returns the normal row count while the same condition forced false returns a different one.**

In practice on HTB this shows up as: | [Auth Bypass Payloads](https://github.com/swisskyrepo/PayloadsAllTheThings/tree/master/SQL%20Injection#authentication-bypass) |
| **Union Injection** |
| `' order by 1-- -` | Detect number of columns using `order by` |
| `cn' UNION select 1,2,3-- -` | Detect number of columns using Union injection |
| `cn' UNION select 1,@@version,3,4-- -` | Basic Union injection |

Write-up provenance: Esther7171/HackTheBox-Writeups-Walkthroughs :: Write-ups/Academy/05. Web Exploitation/25. SQL Injection Fundamentals/SQL Injection Fundamentals.md (726 words, classified web).

- *Disproof:* Refuted when the application returns an identical response for true and false conditions, which indicates the value is escaped, parameterised, or never reaches a SQL parser.
- *Evidence:* high_confidence — [owasp.org](https://owasp.org/www-community/attacks/SQL_Injection); [portswigger.net](https://portswigger.net/web-security/sql-injection); [raw.githubusercontent.com](https://raw.githubusercontent.com/Esther7171/HackTheBox-Writeups-Walkthroughs/main/Write-ups/Academy/05.%20Web%20Exploitation/25.%20SQL%20Injection%20Fundamentals/SQL%20Injection%20Fundamentals.md)

**A UNION-based SQL injection is confirmed by matching the number of columns in the injected result set against the original query using successive NULL placeholders, then selecting data from other tables.**

UNION-based injection requires the injected SELECT to produce the same number of columns as the original query, so the tester probes column counts with ' UNION SELECT NULL --, then ' UNION SELECT NULL, NULL --, and so on, until the response changes. NULL is the preferred filler because it type-checks in any column position and therefore maximises the chance the payload is accepted. Once the column count is matched, the attacker substitutes with useful values: database version, current user, and table and column names drawn from information_schema or equivalent metadata tables, ending with full data extraction of the target schema.

- *Disproof:* The claim is false when the original query always returns a fixed number of columns unrelated to the injection point, when the database does not expose the metadata used (a closed source or heavily restricted RDBMS), or when the response is identical across every NULL-count probe, which proves no UNION result set reached the output.
- *Evidence:* high_confidence — [portswigger.net](https://portswigger.net/web-security/sql-injection/union-based); [w3schools.com](https://www.w3schools.com/sql/sql_union.asp)

**UNION SELECT NULL with increasing NULL counts finds the column count, then a string marker in each position finds a column type that can carry exfiltrated data.**

Send ' UNION SELECT NULL-- then with two, three and more NULLs, comparing responses for any change. Because NULL converts to every common type it succeeds on any matching column count. Then substitute a literal string like 'a' one column at a time; a type-conversion error marks that column as non-string, silence plus visible marker marks it usable.

- *Disproof:* If the response is identical for wrong and correct NULL counts, the UNION column-count method is ineffective and you must use boolean or error-based inference.
- *Evidence:* high_confidence — [portswigger.net](https://portswigger.net/web-security/sql-injection/union-attacks); [raw.githubusercontent.com](https://raw.githubusercontent.com/OWASP/wstg/master/document/4-Web_Application_Security_Testing/07-Injection/05-SQL_Injection.md)

**Error-based SQL injection extracts data by triggering database error messages that echo the injected value or the attacked metadata, and is confirmed when an error response reveals a table, column, or value that was not present in the baseline.**

Error-based injection relies on the database's own error reporting to disclose data. The tester injects an expression that forces the database to perform an operation it cannot complete, then read the error message for the value it prints - for example a CAST to an incompatible type, a subquery in a context that returns more than one row, or a CONCAT of a hidden column with a known value. In MySQL, extracting hidden columns via ERROR_FOR_DIVISION_BY_ZERO or using the information_schema in a GROUP BY context turns the error into a data channel. The key validation is that the error text contains the target value and that it disappears when the value is bound, proving the value came from the statement text rather than from the application's own rendering.

- *Disproof:* The claim is false when the error message only reports a syntax or constraint violation with no embedded target value, or when the same error appears before any injection is attempted, which means the message is a framework default rather than a data channel. If the value only ever appears in the application's own echoed input and never in a database error, the finding is verbose errors, not error-based injection.
- *Evidence:* high_confidence — [cheatsheetseries.owasp.org](https://cheatsheetseries.owasp.org/cheatsheets/SQL_Injection_Prevention_Cheat_Sheet.html); [portswigger.net](https://portswigger.net/web-security/sql-injection/blind)

**Inside an injected MS Access query, TOP and LAST act as row selectors, so the tester can cap or reverse the result set and page out a table's records instead of dumping it whole.**

Inside an injected MS Access query, TOP and LAST act as row selectors, so the tester can cap or reverse the result set and page out a table's records instead of dumping it whole.

HackTricks reference: MS Access SQL Injection (pentesting-web/sql-injection/ms-access-sql-injection.md)

- *Disproof:* TOP or LAST modifiers rejected as syntax by the same injection point, or accepted but leaving the returned rows unchanged, refute their use as row-selection controls.
- *Evidence:* high_confidence — [raw.githubusercontent.com](https://raw.githubusercontent.com/HackTricks-wiki/hacktricks/master/src/pentesting-web/sql-injection/ms-access-sql-injection.md); [sqlite.org](https://sqlite.org/lang_expr.html)

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

- *Disproof:* Refuted when: the value is bound as a parameter or written through the framework's own encoder, so the interpreter never sees attacker text as syntax. Settle it by running the identical request with and without that one control and diffing the response -- if the difference the claim predicts does not appear, the claim is false. Specifically, this is refuted if the behaviour described (“For example, consider using persistence layers such as Hibernate or Enterprise J”) does not occur under a test that isolates that control.
- *Evidence:* high_confidence — [cwe.mitre.org](https://cwe.mitre.org/data/definitions/89.html); [owasp.org](https://owasp.org/www-community/attacks/SQL_Injection)

**Input validation will not always prevent SQL injection, especially if you are required to support free-form text fields that could contain arbitrary characters.**

rameter in the request. This will indirectly limit the scope of an attack, but this technique is less important than proper output encoding and escaping. 
 Note that proper output encoding, escaping, and quoting is the most effective solution for preventing SQL injection, although input validation may provide some defense-in-depth. This is because it effectively limits what will appear in output. Input validation will not always prevent SQL injection, especially if you are required to support free-form text fields that could contain arbitrary characters. For example, the name "O'Reilly" would likely pass the validation step, since it is a common last name in the English language. However, it cannot be directly inserted into the database because it contains the "'" apostrophe character, which would need to be escaped or otherwise handled. In this case, stripping the apostrophe might reduce the risk of SQL injection, but it would produce incorrect

- *Disproof:* Refuted when: the value is bound as a parameter or written through the framework's own encoder, so the interpreter never sees attacker text as syntax. Settle it by running the identical request with and without that one control and diffing the response -- if the difference the claim predicts does not appear, the claim is false. Specifically, this is refuted if the behaviour described (“Input validation will not always prevent SQL injection, especially if you are re”) does not occur under a test that isolates that control.
- *Evidence:* high_confidence — [cwe.mitre.org](https://cwe.mitre.org/data/definitions/89.html); [owasp.org](https://owasp.org/www-community/attacks/SQL_Injection)

**Once a UNION SELECT column count is aligned, the tester can read a chosen position out of a table with a wildcard select and never has to know the column's name, which is how data leaves the database once the injection point is confirmed.**

Once a UNION SELECT column count is aligned, the tester can read a chosen position out of a table with a wildcard select and never has to know the column's name, which is how data leaves the database once the injection point is confirmed.

HackTricks reference: SQL Injection (pentesting-web/sql-injection/README.md)

- *Disproof:* A wildcard select that returns nothing from a table known to be readable, or one that fails purely on a column-count mismatch, refutes the positional-access claim.
- *Evidence:* high_confidence — [cwe.mitre.org](https://cwe.mitre.org/data/definitions/89.html); [raw.githubusercontent.com](https://raw.githubusercontent.com/HackTricks-wiki/hacktricks/master/src/pentesting-web/sql-injection/README.md)

**MySQL schema and table names come out of a UNION SELECT with GROUP_CONCAT over information_schema, and the alternating letter case of the quoted keywords is the point: the enumeration has to be sent in mixed case so a filter matching keywords in one fixed case does not stop it.**

MySQL schema and table names come out of a UNION SELECT with GROUP_CONCAT over information_schema, and the alternating letter case of the quoted keywords is the point: the enumeration has to be sent in mixed case so a filter matching keywords in one fixed case does not stop it.

HackTricks reference: MySQL injection (pentesting-web/sql-injection/mysql-injection/README.md)

- *Disproof:* A filter that blocks the mixed-case spelling while letting the all-lowercase form through, or a UNION SELECT that returns no schema rows despite a working injection point, refutes this enumeration route.
- *Evidence:* high_confidence — [cheatsheetseries.owasp.org](https://cheatsheetseries.owasp.org/cheatsheets/SQL_Injection_Prevention_Cheat_Sheet.html); [raw.githubusercontent.com](https://raw.githubusercontent.com/HackTricks-wiki/hacktricks/master/src/pentesting-web/sql-injection/mysql-injection/README.md)

**Naming a target table turns the same UNION SELECT pattern into a column dictionary, so the tester moves from which tables exist to exactly which attributes the injected query can reference.**

Naming a target table turns the same UNION SELECT pattern into a column dictionary, so the tester moves from which tables exist to exactly which attributes the injected query can reference.

HackTricks reference: MySQL injection (pentesting-web/sql-injection/mysql-injection/README.md)

- *Disproof:* The column enumeration coming back empty for a table that the same injection point can already read rows from refutes this metadata route.
- *Evidence:* high_confidence — [cheatsheetseries.owasp.org](https://cheatsheetseries.owasp.org/cheatsheets/SQL_Injection_Prevention_Cheat_Sheet.html); [raw.githubusercontent.com](https://raw.githubusercontent.com/HackTricks-wiki/hacktricks/master/src/pentesting-web/sql-injection/mysql-injection/README.md)

**An MSSQL injection point doubles as a privilege-reach probe: calling fn_my_permissions against the database and filtering on a named permission tells the tester which database-level grants the injected session actually holds before they plan any escalation.**

An MSSQL injection point doubles as a privilege-reach probe: calling fn_my_permissions against the database and filtering on a named permission tells the tester which database-level grants the injected session actually holds before they plan any escalation.

HackTricks reference: MSSQL Injection (pentesting-web/sql-injection/mssql-injection.md)

- *Disproof:* fn_my_permissions returning no rows, or an empty grant set, for a login that demonstrably holds the named database permission refutes it as a reach check.
- *Evidence:* high_confidence — [portswigger.net](https://portswigger.net/web-security/sql-injection); [raw.githubusercontent.com](https://raw.githubusercontent.com/HackTricks-wiki/hacktricks/master/src/pentesting-web/sql-injection/mssql-injection.md)

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

- *Disproof:* Refuted when: the value is bound as a parameter or written through the framework's own encoder, so the interpreter never sees attacker text as syntax. Settle it by running the identical request with and without that one control and diffing the response -- if the difference the claim predicts does not appear, the claim is false. Specifically, this is refuted if the behaviour described (“If authorization information is held in a SQL database, it may be possible to ch”) does not occur under a test that isolates that control.
- *Evidence:* high_confidence — [cwe.mitre.org](https://cwe.mitre.org/data/definitions/89.html); [owasp.org](https://owasp.org/www-community/attacks/SQL_Injection)

**On MSSQL a single injected UNION SELECT over information_schema.columns hands back the schema, table and column names of the current database at once, and on error-based vectors every selected expression has to carry an alias or the query will not come back.**

On MSSQL a single injected UNION SELECT over information_schema.columns hands back the schema, table and column names of the current database at once, and on error-based vectors every selected expression has to carry an alias or the query will not come back.

HackTricks reference: MSSQL Injection (pentesting-web/sql-injection/mssql-injection.md)

- *Disproof:* An error-based injected select that errors purely because an expression lacks an alias, or a schema enumeration that returns no rows despite a working injection point, refutes these requirements.
- *Evidence:* high_confidence — [portswigger.net](https://portswigger.net/web-security/sql-injection); [raw.githubusercontent.com](https://raw.githubusercontent.com/HackTricks-wiki/hacktricks/master/src/pentesting-web/sql-injection/mssql-injection.md)

## 4. Validation

_How to prove the finding rather than infer it. A technique that cannot be validated must not be reported._

**A boolean or time differential found while several parameters are being varied at once is not attributable to any of them, so the finding is only valid once the same differential reproduces with exactly one variable changed.**

SQL injection confirmation is a differential argument, and a differential needs a controlled comparison. The corpus's own rule is that a SQLi finding is only validated when one variable is in play, and that rule survives contact with real applications because almost every parameterised endpoint has one injectable parameter among several that also affect row counts, ordering, caching and timing. A tester who varies a page, a sort, a filter and a date together and sees 'true' return more rows will produce a report that cannot be reproduced by the triager. The reproducible form is a matched triple: same request with the value set to a true condition, the same request with a false condition, and the same request with the value restored - three responses, one variable, ideally with the boolean pair run twice to rule out cache warming. For time-based detection the same discipline applies with a baseline request that contains no delay, so the delta is attributable to the payload rather than to a slow endpoint.

- *Disproof:* The rule is a testing discipline, not a property of the vulnerability, so it is false as a statement about what constitutes a finding in cases where a different kind of evidence is available: an out-of-band callback from a payload that could only have been assembled by the database is attributable regardless of how many other parameters were in the request, because the callback proves the injected expression executed. It is also false where the endpoint exposes the generated SQL - a debug echo, a query log, an error page printing the statement - since the statement text itself settles where the value landed. And a differential can be attributable without single-variable isolation when the other parameters are held constant by construction, for example by fixing them from a captured baseline and varying only the target.
- *Evidence:* high_confidence — [docs.djangoproject.com](https://docs.djangoproject.com/en/5.0/topics/db/sql/); [sqlite.org](https://sqlite.org/lang_expr.html)

**In a full-text search parameter the attacker-controlled text is a query language, not a string literal, so single-quote and UNION payloads test nothing and the injection point is the operator's own grammar.**

Full-text search changes the payload vocabulary entirely, and testers who carry over a standard quote payload produce a false negative and then a false report. SQLite FTS5 is the clearest example: a query is issued with a MATCH operator whose right-hand expression must be a text value specifying the term to search for, and advanced searches are requested by providing a more complicated FTS5 query string as that text - the documented syntax includes bare terms, column filters like b : (uvw AND xyz), quoted phrases, NEAR and NOT, and brace alternation. An input reaching that operand is being parsed as FTS5, so the meaningful probes are FTS5 grammar abuse and the resulting error or row-count differentials, not SQL string termination. The same shape appears wherever a search parameter feeds MATCH, REGEXP, tsquery, a JSON path, an XPath, or a template - each is a query language with its own injection surface that the standard payload never touches.

- *Disproof:* The claim is false when the value is quoted or escaped before reaching the operator's parser - a driver or API that treats the operand as an opaque string and escapes the operator's metacharacters removes the grammar surface entirely, in which case the standard payload is again the right one. It is also false as a claim of vulnerability: the mere existence of a rich query language in a search box is not a finding, and FTS5's own syntax is deliberately non-SQL, so a payload that changes match results is a search-behaviour quirk rather than SQL injection. The finding needs the grammar surface to reach a SQL-executing construct - for example an FTS expression that a trigger, a view, or an auxiliary function expands into further SQL - and that chain has to be demonstrated.
- *Evidence:* high_confidence — [postgresql.org](https://www.postgresql.org/docs/current/sql-syntax-lexical.html); [sqlite.org](https://sqlite.org/fts5.html)

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

**A dollar-quoted string in PostgreSQL is a closed literal that ignores backslashes and dollar signs, so a payload containing $tag$ delimiters only becomes dangerous if the attacker can supply the tag the application's own quoting chose.**

PostgreSQL offers a second string form that defeats most of the payloads testers have memorised. A dollar-quoted string constant consists of a dollar sign, an optional tag of zero or more characters, another dollar sign, the content, a dollar sign, the same tag, and a dollar sign; no characters inside are ever escaped, so the string content is always written literally, backslashes are not special, and neither are dollar signs unless they are part of a sequence matching the opening tag. It is even possible to nest dollar-quoted constants by choosing different tags at each level, which is what makes it the natural choice for function bodies. The hunter's consequence is precise: quoting the payload with backslashes or doubled single quotes proves nothing in a dollar-quoted context, and the actual attack requires predicting or influencing the tag. Conversely, an application's use of a fixed $function$ wrapper is a genuine control that a doubled-quote payload will not defeat.

- *Disproof:* The claim is false when the tag is attacker-controlled or absent in a way that lets the payload close the literal - an unquoted dollar-quoted string in a function definition whose body is built from user input lets an attacker insert their own $q$...$q$ and terminate it, and PostgreSQL's own example of a nested $q$[\t\r\n\v\\]$q$ inside $function$ ... $function$ shows exactly that shape. It also fails if the payload is delivered outside the dollar-quoted region - a second statement concatenated after the function body, or a value reaching a non-dollar-quoted parameter such as a dynamic EXECUTE string, is ordinary SQL and the standard payloads apply.
- *Evidence:* high_confidence — [docs.djangoproject.com](https://docs.djangoproject.com/en/5.0/topics/db/sql/); [postgresql.org](https://www.postgresql.org/docs/current/sql-syntax-lexical.html)

## 6. Known bypasses

_Filters and controls that have defeated the techniques above. Treat these as the reason a naive test fails, not as proof of safety._

**HTTP parameter pollution lets an attacker bypass a web application firewall or input filter by encoding separators or distributing the injection across multiple parameters, so the same value never reaches the filter.**

Many SQLi filters look for dangerous tokens in a single decoded parameter. HTTP parameter pollution exploits the fact that an application and a downstream framework may read different parameters or merge repeated keys differently, so the payload that never appears in any one filtered parameter reaches the statement untouched. A classic route is encoding the quote or the comment delimiter so the filter's signature does not match, or splitting the payload across parameters that the ORM or template layer later concatenates, while the raw SQL parser sees the full statement. This is a filter bypass, not a separate injection class, and it is only effective where the application actually builds SQL from user input rather than from bound parameters.

- *Disproof:* The claim is false when the application parses the request into a safe data structure, binds all values, and never concatenates user input into a SQL string, because in that case no parameter layout can produce injection. It is also false when the WAF or filter normalises the request in the same way the application does, so the same decoded token still appears.
- *Evidence:* high_confidence — [owasp.org](https://owasp.org/www-community/SQL_Injection_Prevention_Cheat_Sheet); [portswigger.net](https://portswigger.net/web-security/sql-injection/blind)

## 7. Chaining

_How this class escalates when combined with others. Each step is anchored to a promoted item._

**Data written safely by one request can become injectable when a later request concatenates the stored value into a new query.**

Plant a payload in any user-writable field that persists (profile name, comment, uploaded filename, order note), then find every later screen or background job that reads that column into a query. Test by storing a unique marker per field and searching for it in downstream behaviour, especially ORDER BY/sort and report paths that cannot use bind variables.

- *Disproof:* If the stored payload is only ever read back through parameterized queries and never concatenated, the flow is not second-order injectable.
- *Evidence:* high_confidence — [cwe.mitre.org](https://cwe.mitre.org/data/definitions/89.html); [portswigger.net](https://portswigger.net/web-security/sql-injection)

**SQL injection can escalate into remote code execution when a database that permits file writes or command execution is reachable, chaining the injection to a file write followed by an application-controlled file include.**

The chain has three steps. First, an injectable query in a database that trusts file operations - MySQL with file_priv, PostgreSQL with COPY ... TO/FROM or pg_write_file, or any database with load_file / xp_cmdshell-style capabilities - is used to write a web shell or script into an application-writable directory, using INTO OUTFILE or an equivalent write primitive. Second, the attacker confirms the file is served by the web root. Third, the attacker invokes the file through a file-access or include path, converting data exfiltration into remote code execution. Each step requires a different predicate and different capabilities, so the chain only succeeds when the injected query is not parameterised and the database and application both grant the required privileges.

- *Disproof:* The claim is false when the injectable query runs against a database user without file or command privileges, when the target directory is outside the web root or not writable by the database process, or when the written file can never be reached through an application-controlled path. It is also false when the injection point is parameterised, in which case the injected text never reaches the parser.
- *Evidence:* high_confidence — [owasp.org](https://owasp.org/www-community/attacks/SQL_Injection); [portswigger.net](https://portswigger.net/web-security/sql-injection/os-command-injection)

## 8. Impact

_What is actually demonstrable, and what to stop claiming._

**A confirmed SQLi typically yields bulk read of application data and can subvert authentication, not just a single leaked record.**

Scope impact by what the DB account can reach: enumerate tables and columns, then attempt read of credential and PII tables, and separately test whether an authentication query can be subverted to return any row. Rate conclusions by the CWE-89 consequence classes actually demonstrated - confidentiality, authentication bypass, integrity - rather than by the injection primitive alone.

- *Disproof:* If the DB account is restricted to read-only access to a single view and auth cannot be subverted, impact is bounded to the data in that view.
- *Evidence:* high_confidence — [cwe.mitre.org](https://cwe.mitre.org/data/definitions/89.html); [portswigger.net](https://portswigger.net/web-security/sql-injection)

---

*Generated from the evidence base. Where this file and the database disagree, the database is correct.*
