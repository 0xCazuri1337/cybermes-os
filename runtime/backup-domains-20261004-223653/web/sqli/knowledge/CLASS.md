# SQL Injection

## Definition

Attacker-controlled input is concatenated into a SQL statement, so the query structure becomes attacker-controlled.

- **CWE:** CWE-89
- **OWASP:** A03:2021
- **Surface:** web
- **Aliases:** ["sql injection", "sqli", "second order sql injection", "nosql injection operator"]

Canonical home for `sqli`. Rendered from `db/wks.db` by `tools/taxonomy/build_taxonomy.py` — edit the rows, not this file.

## Root Cause

Not yet researched.

## Preconditions

**Any request-controllable value that reaches a SQL query is a candidate injection point, including JSON/XML bodies, cookies and headers, not just GET parameters.**

Before probing, enumerate every input field including hidden POST fields, cookies and HTTP headers, then test each separately. For each field send a distinctive marker and observe whether it is reflected, stored, or changes database-driven output. Record which field maps to a quoted string vs a numeric context, since that determines the payload shape.

*Disproof:* If a field's value is provably never used in any query (e.g. purely client-side sorting or CSRF tokens), it cannot be an injection point.

**Extraction on MS Access is gated on naming a real column such as username, so the guess-and-check step on column names comes before any value can be pulled out of the database through the injection.**

Extraction on MS Access is gated on naming a real column such as username, so the guess-and-check step on column names comes before any value can be pulled out of the database through the injection.

HackTricks reference: MS Access SQL Injection (pentesting-web/sql-injection/ms-access-sql-injection.md)

*Disproof:* Reading a value out of MS Access with no valid column name in the injected query, or a fabricated column name returning data, refutes this ordering.

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

**A convincing observation for this class is: For each candidate field, replay the true/false pair three times with all other parameters identical and diff status code, headers and body.**

Derived from sqli.validation.single_variable_differential, which states the boundary for this class. The observation above is what a report must contain to be believed: an artifact the reviewer can re-check, not a claim the hunter asserts. A finding without it is an assertion.

*Disproof:* Not evidence when the observable cannot be produced at all -- blind, server-side-only, or identical-in-every-case behaviour leaves nothing to show. The originating rule (sqli.validation.single_variable_differential) states the full boundary.

## Exploitation

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

*Disproof:* This is refuted if an authoritative source shows the described behaviour does not occur, does not grant access, or is already prevented by default framework configuration: "If authorization information is held in a SQL database, it may be possible to change this ".

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

*Disproof:* This is refuted if an authoritative source shows the described behaviour does not occur, does not grant access, or is already prevented by default framework configuration: "For example, consider using persistence layers such as Hibernate or Enterprise Java Beans,".

**Input validation will not always prevent SQL injection, especially if you are required to support free-form text fields that could contain arbitrary characters.**

rameter in the request. This will indirectly limit the scope of an attack, but this technique is less important than proper output encoding and escaping. 
 Note that proper output encoding, escaping, and quoting is the most effective solution for preventing SQL injection, although input validation may provide some defense-in-depth. This is because it effectively limits what will appear in output. Input validation will not always prevent SQL injection, especially if you are required to support free-form text fields that could contain arbitrary characters. For example, the name "O'Reilly" would likely pass the validation step, since it is a common last name in the English language. However, it cannot be directly inserted into the database because it contains the "'" apostrophe character, which would need to be escaped or otherwise handled. In this case, stripping the apostrophe might reduce the risk of SQL injection, but it would produce incorrect

*Disproof:* This is refuted if an authoritative source shows the described behaviour does not occur, does not grant access, or is already prevented by default framework configuration: "Input validation will not always prevent SQL injection, especially if you are required to ".

**Blind boolean injection extracts arbitrary values one character at a time by making the app's visible behaviour depend on a single condition.**

Find an endpoint whose behaviour changes with the row count (e.g. a welcome-back banner). Then send AND SUBSTRING((SELECT ...),1,1) > 'm' and binary-search the character, confirming with an equality test, repeating per position. Use this when results and errors are hidden but some response attribute still varies with query outcome.

*Disproof:* If the application's behaviour is identical whether the condition is true or false, boolean extraction is impossible and time-based or OAST is required.

**Once a UNION SELECT column count is aligned, the tester can read a chosen position out of a table with a wildcard select and never has to know the column's name, which is how data leaves the database once the injection point is confirmed.**

Once a UNION SELECT column count is aligned, the tester can read a chosen position out of a table with a wildcard select and never has to know the column's name, which is how data leaves the database once the injection point is confirmed.

HackTricks reference: SQL Injection (pentesting-web/sql-injection/README.md)

*Disproof:* A wildcard select that returns nothing from a table known to be readable, or one that fails purely on a column-count mismatch, refutes the positional-access claim.

**On MSSQL a single injected UNION SELECT over information_schema.columns hands back the schema, table and column names of the current database at once, and on error-based vectors every selected expression has to carry an alias or the query will not come back.**

On MSSQL a single injected UNION SELECT over information_schema.columns hands back the schema, table and column names of the current database at once, and on error-based vectors every selected expression has to carry an alias or the query will not come back.

HackTricks reference: MSSQL Injection (pentesting-web/sql-injection/mssql-injection.md)

*Disproof:* An error-based injected select that errors purely because an expression lacks an alias, or a schema enumeration that returns no rows despite a working injection point, refutes these requirements.

**MySQL schema and table names come out of a UNION SELECT with GROUP_CONCAT over information_schema, and the alternating letter case of the quoted keywords is the point: the enumeration has to be sent in mixed case so a filter matching keywords in one fixed case does not stop it.**

MySQL schema and table names come out of a UNION SELECT with GROUP_CONCAT over information_schema, and the alternating letter case of the quoted keywords is the point: the enumeration has to be sent in mixed case so a filter matching keywords in one fixed case does not stop it.

HackTricks reference: MySQL injection (pentesting-web/sql-injection/mysql-injection/README.md)

*Disproof:* A filter that blocks the mixed-case spelling while letting the all-lowercase form through, or a UNION SELECT that returns no schema rows despite a working injection point, refutes this enumeration route.

**An MSSQL injection point doubles as a privilege-reach probe: calling fn_my_permissions against the database and filtering on a named permission tells the tester which database-level grants the injected session actually holds before they plan any escalation.**

An MSSQL injection point doubles as a privilege-reach probe: calling fn_my_permissions against the database and filtering on a named permission tells the tester which database-level grants the injected session actually holds before they plan any escalation.

HackTricks reference: MSSQL Injection (pentesting-web/sql-injection/mssql-injection.md)

*Disproof:* fn_my_permissions returning no rows, or an empty grant set, for a login that demonstrably holds the named database permission refutes it as a reach check.

**Inside an injected MS Access query, TOP and LAST act as row selectors, so the tester can cap or reverse the result set and page out a table's records instead of dumping it whole.**

Inside an injected MS Access query, TOP and LAST act as row selectors, so the tester can cap or reverse the result set and page out a table's records instead of dumping it whole.

HackTricks reference: MS Access SQL Injection (pentesting-web/sql-injection/ms-access-sql-injection.md)

*Disproof:* TOP or LAST modifiers rejected as syntax by the same injection point, or accepted but leaving the returned rows unchanged, refute their use as row-selection controls.

**Naming a target table turns the same UNION SELECT pattern into a column dictionary, so the tester moves from which tables exist to exactly which attributes the injected query can reference.**

Naming a target table turns the same UNION SELECT pattern into a column dictionary, so the tester moves from which tables exist to exactly which attributes the injected query can reference.

HackTricks reference: MySQL injection (pentesting-web/sql-injection/mysql-injection/README.md)

*Disproof:* The column enumeration coming back empty for a table that the same injection point can already read rows from refutes this metadata route.

**A UNION-based SQL injection is confirmed by matching the result-set column count through successively longer runs of NULL placeholders, and NULL is used as the filler because it type-checks in any column position and so maximises the chance the payload succeeds.**

A UNION-based SQL injection is confirmed by matching the result-set column count through successively longer runs of NULL placeholders, and NULL is used as the filler because it type-checks in any column position and so maximises the chance the payload succeeds.

HackTricks reference: sql injection (https://kathan19.gitbook.io/howtohunt/sqli/sql_injection.md)

*Disproof:* If no NULL-counted payload ever produces the extra result set or alters the response, the column count was never matched and the UNION injection is not demonstrated.

**A UNION-based SQL injection is confirmed by matching the result-set column count through successively longer runs of NULL placeholders, and NULL is used as the filler because it type-checks in any column position and so maximises the chance the payload succeeds.**

A UNION-based SQL injection is confirmed by matching the result-set column count through successively longer runs of NULL placeholders, and NULL is used as the filler because it type-checks in any column position and so maximises the chance the payload succeeds.

HackTricks reference: sql injection (https://kathan19.gitbook.io/howtohunt/sqli/sql_injection.md)

*Disproof:* If no NULL-counted payload ever produces the extra result set or alters the response, the column count was never matched and the UNION injection is not demonstrated.

**Incrementing ORDER BY <n> until a response change appears infers the column count of the original query even when errors are suppressed.**

At a confirmed injection point send ' ORDER BY 1--, then 2, 3 and so on, comparing status, body length and content each time. The first index that changes behaviour marks the boundary. Cross-check with UNION SELECT NULL,... increments. Remember ORDER BY cannot take bind variables, so a sort-indicator parameter is a natural unparameterized injection surface.

*Disproof:* If every index from 1 upward yields an identical response, ORDER BY cannot be used for column counting and you must rely on UNION NULL probing.

**SQL injection is confirmed by a boolean differential: a condition that is always true returns the normal row count while the same condition forced false returns a different one.**

In practice on HTB this shows up as: | [Auth Bypass Payloads](https://github.com/swisskyrepo/PayloadsAllTheThings/tree/master/SQL%20Injection#authentication-bypass) |
| **Union Injection** |
| `' order by 1-- -` | Detect number of columns using `order by` |
| `cn' UNION select 1,2,3-- -` | Detect number of columns using Union injection |
| `cn' UNION select 1,@@version,3,4-- -` | Basic Union injection |

Write-up provenance: Esther7171/HackTheBox-Writeups-Walkthroughs :: Write-ups/Academy/05. Web Exploitation/25. SQL Injection Fundamentals/SQL Injection Fundamentals.md (726 words, classified web).

*Disproof:* Refuted when the application returns an identical response for true and false conditions, which indicates the value is escaped, parameterised, or never reaches a SQL parser.

**UNION SELECT NULL with increasing NULL counts finds the column count, then a string marker in each position finds a column type that can carry exfiltrated data.**

Send ' UNION SELECT NULL-- then with two, three and more NULLs, comparing responses for any change. Because NULL converts to every common type it succeeds on any matching column count. Then substitute a literal string like 'a' one column at a time; a type-conversion error marks that column as non-string, silence plus visible marker marks it usable.

*Disproof:* If the response is identical for wrong and correct NULL counts, the UNION column-count method is ineffective and you must use boolean or error-based inference.

## Variations

**WAFs that normalize, case-filter or over-clean requests can be bypassed by comment-splitting, mixed case, encoding and parameter pollution.**

When a clean payload is blocked but the endpoint is otherwise injectable, try un/**/ion se/**/lect, UnIoN SeLeCt, inline MySQL comments /*!50000UNION*/, percent-encoding of keywords, XML entity escapes, and splitting the payload across duplicated or separate parameters. Compare which variant reaches the DB by observing boolean differential behaviour rather than the WAF's verdict.

*Disproof:* If every encoded, case-varied and split variant is rejected identically and no differential response appears, the block is likely enforced downstream of the WAF, not by it.

**A search box wired into a full-text MATCH ... AGAINST clause in boolean mode is its own injection flavour: the search term is concatenated inside the quoted argument, so the tester should probe the quote and the boolean-mode operators rather than a plain WHERE value.**

A search box wired into a full-text MATCH ... AGAINST clause in boolean mode is its own injection flavour: the search term is concatenated inside the quoted argument, so the tester should probe the quote and the boolean-mode operators rather than a plain WHERE value.

HackTricks reference: MySQL injection (pentesting-web/sql-injection/mysql-injection/README.md)

*Disproof:* A search parameter concatenated into that MATCH clause that can neither break out of the quotes nor change the boolean-mode search, refutes it as an injection point.

## Technology / Framework Considerations

Not yet researched.

## API Considerations

Not yet researched.

## Attack Chains

- `sqli-boolean-oracle-to-row-count-enumeration` — sqli-boolean-oracle-to-row-count-enumeration (goal: `data_disclosure`)

## Real-World Examples

Not yet researched.

## Common False Positives

**A request that returns a database error echoing the caller's own input, on a code path that passes that input as a bound parameter, is a verbose-error disclosure and not SQL injection - the value never entered the statement text.**

Django's rule for its own escape hatch is the reference: every time you use raw SQL you should properly escape any parameters that the user can control by using params, in order to protect against SQL injection attacks. Parameterisation works by separating statement text from values - SQLite's documentation of the mechanism is that a variable or parameter token specifies a placeholder in the expression for a value that is filled in at runtime through the bind interface. So when you see your payload come back inside a database error, the question is not 'did my quote break out' but 'did my bytes become part of the statement'. If the driver bound the value, the quote is inert data, the error is about a type or constraint rather than a syntax error at your quote position, and the finding is verbose errors. The field tell is the error class: a syntax error adjacent to your injected token means the token was concatenated; a constraint or type error mentioning the whole value means it was bound and echoed.

*Disproof:* The claim is false when the same request also produces a behaviour change with the quote removed - a boolean differential, a time delta, or an OAST callback - because then the value is reaching the statement text by some other route even if this particular call site is parameterised. Parameterisation is per call site, and applications routinely have a safe read path and an unsafe report, export, or search path on the same endpoint. It is also false when the framework's own string escaping is being relied on rather than binding: a helper that quotes and doubles the value correctly still yields a value that will break the moment a second, unescaped layer concatenates it, so the presence of quotes in the output is not evidence of safety at the statement level.

**A dollar-quoted string in PostgreSQL is a closed literal that ignores backslashes and dollar signs, so a payload containing $tag$ delimiters only becomes dangerous if the attacker can supply the tag the application's own quoting chose.**

PostgreSQL offers a second string form that defeats most of the payloads testers have memorised. A dollar-quoted string constant consists of a dollar sign, an optional tag of zero or more characters, another dollar sign, the content, a dollar sign, the same tag, and a dollar sign; no characters inside are ever escaped, so the string content is always written literally, backslashes are not special, and neither are dollar signs unless they are part of a sequence matching the opening tag. It is even possible to nest dollar-quoted constants by choosing different tags at each level, which is what makes it the natural choice for function bodies. The hunter's consequence is precise: quoting the payload with backslashes or doubled single quotes proves nothing in a dollar-quoted context, and the actual attack requires predicting or influencing the tag. Conversely, an application's use of a fixed $function$ wrapper is a genuine control that a doubled-quote payload will not defeat.

*Disproof:* The claim is false when the tag is attacker-controlled or absent in a way that lets the payload close the literal - an unquoted dollar-quoted string in a function definition whose body is built from user input lets an attacker insert their own $q$...$q$ and terminate it, and PostgreSQL's own example of a nested $q$[\t\r\n\v\\]$q$ inside $function$ ... $function$ shows exactly that shape. It also fails if the payload is delivered outside the dollar-quoted region - a second statement concatenated after the function body, or a value reaching a non-dollar-quoted parameter such as a dynamic EXECUTE string, is ordinary SQL and the standard payloads apply.

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

**In a full-text search parameter the attacker-controlled text is a query language, not a string literal, so single-quote and UNION payloads test nothing and the injection point is the operator's own grammar.**

Full-text search changes the payload vocabulary entirely, and testers who carry over a standard quote payload produce a false negative and then a false report. SQLite FTS5 is the clearest example: a query is issued with a MATCH operator whose right-hand expression must be a text value specifying the term to search for, and advanced searches are requested by providing a more complicated FTS5 query string as that text - the documented syntax includes bare terms, column filters like b : (uvw AND xyz), quoted phrases, NEAR and NOT, and brace alternation. An input reaching that operand is being parsed as FTS5, so the meaningful probes are FTS5 grammar abuse and the resulting error or row-count differentials, not SQL string termination. The same shape appears wherever a search parameter feeds MATCH, REGEXP, tsquery, a JSON path, an XPath, or a template - each is a query language with its own injection surface that the standard payload never touches.

*Disproof:* The claim is false when the value is quoted or escaped before reaching the operator's parser - a driver or API that treats the operand as an opaque string and escapes the operator's metacharacters removes the grammar surface entirely, in which case the standard payload is again the right one. It is also false as a claim of vulnerability: the mere existence of a rich query language in a search box is not a finding, and FTS5's own syntax is deliberately non-SQL, so a payload that changes match results is a search-behaviour quirk rather than SQL injection. The finding needs the grammar surface to reach a SQL-executing construct - for example an FTS expression that a trigger, a view, or an auxiliary function expands into further SQL - and that chain has to be demonstrated.

**A boolean or time differential found while several parameters are being varied at once is not attributable to any of them, so the finding is only valid once the same differential reproduces with exactly one variable changed.**

SQL injection confirmation is a differential argument, and a differential needs a controlled comparison. The corpus's own rule is that a SQLi finding is only validated when one variable is in play, and that rule survives contact with real applications because almost every parameterised endpoint has one injectable parameter among several that also affect row counts, ordering, caching and timing. A tester who varies a page, a sort, a filter and a date together and sees 'true' return more rows will produce a report that cannot be reproduced by the triager. The reproducible form is a matched triple: same request with the value set to a true condition, the same request with a false condition, and the same request with the value restored - three responses, one variable, ideally with the boolean pair run twice to rule out cache warming. For time-based detection the same discipline applies with a baseline request that contains no delay, so the delta is attributable to the payload rather than to a slow endpoint.

*Disproof:* The rule is a testing discipline, not a property of the vulnerability, so it is false as a statement about what constitutes a finding in cases where a different kind of evidence is available: an out-of-band callback from a payload that could only have been assembled by the database is attributable regardless of how many other parameters were in the request, because the callback proves the injected expression executed. It is also false where the endpoint exposes the generated SQL - a debug echo, a query log, an error page printing the statement - since the statement text itself settles where the value landed. And a differential can be attributable without single-variable isolation when the other parameters are held constant by construction, for example by fixing them from a captured baseline and varying only the target.

**A SQLi finding is only validated when one variable changes and the response difference is reproducible and explainable by query logic.**

For each candidate field, replay the true/false pair three times with all other parameters identical and diff status code, headers and body. Then confirm the difference is attributable to SQL by making it depend on a known condition (e.g. flipping a comparison reverses the outcome). Record raw request/response pairs as the validation artifact.

*Disproof:* If the difference is non-deterministic, cache- or session-driven, or does not reverse when the condition is inverted, it is not a validated SQLi.

**A verbose database error that echoes the constructed query turns blind injection visible and independently confirms the injection point's context.**

Inject a single quote and inspect status, body, and any JS/HTML comment for driver error text. If the response quotes your input inside a reconstructed statement, note whether the context is quoted or unquoted, then craft a payload that returns data directly through the error channel (e.g. CAST-based conversion errors). Treat absence of such leakage as a signal to use blind techniques.

*Disproof:* If the app returns a generic custom error page with no driver text and no reflected query fragment, error-based confirmation is unavailable.

**To decide this case, observe: Establish a baseline with clearly invalid input such as a string where a number is expected, and check whether that also 500s.**

Derived from sqli.fp_rule.generic_500_not_sqli, which states the false-positive boundary for this class. The observable above is what separates a real finding from the pattern that only looks like one. A hunter who cannot produce this observation in a request/response pair does not have a finding yet.

*Disproof:* This test does not apply where the surrounding behaviour is unobservable -- for example when the response is identical in every case, or when the only evidence is server-side and not reflected to the requester. The originating rule (sqli.fp_rule.generic_500_not_sqli) states the full boundary.

**To decide this case, observe: For each candidate field, replay the true/false pair three times with all other parameters identical and diff status code, headers and body.**

Derived from sqli.validation.single_variable_differential, which states the false-positive boundary for this class. The observable above is what separates a real finding from the pattern that only looks like one. A hunter who cannot produce this observation in a request/response pair does not have a finding yet.

*Disproof:* This test does not apply where the surrounding behaviour is unobservable -- for example when the response is identical in every case, or when the only evidence is server-side and not reflected to the requester. The originating rule (sqli.validation.single_variable_differential) states the full boundary.

**MS Access hands the tester a file-existence oracle from inside the injection: point the database reference at a local file and the invalid-database-format error appears only when that file is really there, so file enumeration is driven by comparing errors across candidate paths.**

MS Access hands the tester a file-existence oracle from inside the injection: point the database reference at a local file and the invalid-database-format error appears only when that file is really there, so file enumeration is driven by comparing errors across candidate paths.

HackTricks reference: MS Access SQL Injection (pentesting-web/sql-injection/ms-access-sql-injection.md)

*Disproof:* The invalid-format error appearing identically for names that do not exist, or never appearing for one that does, refutes the existence oracle.

**On MSSQL the tester can read the live query text back through sys.dm_exec_requests joined to sys.dm_exec_sql_text, which is the way to confirm the injection really landed in the query and to see the surrounding SQL, with the server-level permission checked separately.**

On MSSQL the tester can read the live query text back through sys.dm_exec_requests joined to sys.dm_exec_sql_text, which is the way to confirm the injection really landed in the query and to see the surrounding SQL, with the server-level permission checked separately.

HackTricks reference: MSSQL Injection (pentesting-web/sql-injection/mssql-injection.md)

*Disproof:* The DMVs returning nothing, or returning a query that does not contain the injected syntax, refutes their use for reading back the currently executing SQL query.

**When a blind SQL injection returns no data, the proof is made of timing: concatenate a deliberately slow operation into the SQL query and look for a repeatable jump in page-load time that the unmodified request does not show.**

When a blind SQL injection returns no data, the proof is made of timing: concatenate a deliberately slow operation into the SQL query and look for a repeatable jump in page-load time that the unmodified request does not show.

HackTricks reference: SQL Injection (pentesting-web/sql-injection/README.md)

*Disproof:* A concatenated slow operation that leaves page-load time flat, or a delay that appears just as often on a control request carrying no injected syntax, refutes it as a blind SQL injection oracle.

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
- **docs.djangoproject.com** (research)
  - <https://docs.djangoproject.com/en/5.0/topics/db/sql/>
- **kathan19.gitbook.io** (reference)
  - <https://kathan19.gitbook.io/howtohunt/sqli/sql_injection.md>
- **owasp.org** (cheatsheet)
  - <https://owasp.org/www-community/attacks/SQL_Injection>
  - <https://owasp.org/www-project-web-security-testing-guide/stable/4-Web_Application_Security_Testing/07-Input_Validation_Testing/05-Testing_for_SQL_Injection.html>
- **portswigger.net** (vendor_docs)
  - <https://portswigger.net/web-security/sql-injection>
  - <https://portswigger.net/web-security/sql-injection/blind>
  - <https://portswigger.net/web-security/sql-injection/union-attacks>
- **postgresql.org** (writeup)
  - <https://www.postgresql.org/docs/current/sql-syntax-lexical.html>
- **raw.githubusercontent.com** (writeup)
  - <https://raw.githubusercontent.com/Esther7171/HackTheBox-Writeups-Walkthroughs/main/Write-ups/Academy/05.%20Web%20Exploitation/25.%20SQL%20Injection%20Fundamentals/SQL%20Injection%20Fundamentals.md>
  - <https://raw.githubusercontent.com/HackTricks-wiki/hacktricks/master/src/pentesting-web/sql-injection/README.md>
  - <https://raw.githubusercontent.com/HackTricks-wiki/hacktricks/master/src/pentesting-web/sql-injection/ms-access-sql-injection.md>
  - <https://raw.githubusercontent.com/HackTricks-wiki/hacktricks/master/src/pentesting-web/sql-injection/mssql-injection.md>
  - <https://raw.githubusercontent.com/HackTricks-wiki/hacktricks/master/src/pentesting-web/sql-injection/mysql-injection/README.md>
  - <https://raw.githubusercontent.com/OWASP/wstg/master/document/4-Web_Application_Security_Testing/07-Injection/05-SQL_Injection.md>
  - <https://raw.githubusercontent.com/OWASP/wstg/master/document/4-Web_Application_Security_Testing/07-Injection/05.7-ORM_Injection.md>
  - <https://raw.githubusercontent.com/OWASP/wstg/v4.2/document/4-Web_Application_Security_Testing/07-Input_Validation_Testing/05-Testing_for_SQL_Injection.md>
  - <https://raw.githubusercontent.com/ajcriado/htb-writeups/main/Academy/CPTS/Content%20Summary/17.%20SQL%20Injection%20Fundamentals.md>
- **sqlite.org** (writeup)
  - <https://sqlite.org/fts5.html>
  - <https://sqlite.org/lang_expr.html>

Every item above is gated on >= 2 distinct publisher hosts (`wks/quality.py`, rule R1). Publisher diversity, not citation count, is what makes these corroborated.
