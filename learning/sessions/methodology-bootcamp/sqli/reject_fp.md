# reject_fp — the misleading cases and the disproof test for each

Every row here is a real rejection path: a hypothesis that looked live, a
disproof test that killed it, and the durable rule. The eight field-observed
false positives plus the corpus fp_rules are the reason this class has a high
false-positive rate — each one looks exactly like a finding until a control
request is run.

---

## 1. "The search parameter is injectable because a single quote produces a database syntax error"

*Looked vulnerable:* `GET /search?q=test'` returned HTTP 500 with the body
containing `You have an error in your SQL syntax`.
*Disproof test:* request the same path with `q=test` (no quote) and `q=test''`
(doubled quote), then compare the **full response body of all three** rather than
the status code.
*Invalidated by:* the unquoted control also returned HTTP 500, so the error is
raised before the query is built — from a missing query parameter or a template
error, not from the quote reaching a parser.
*Early signal missed:* should have established a working baseline with no
metacharacter before treating any error as evidence of injection.
*Rejection rule:* **a 500 on a metacharacter proves nothing until the same request
without the metacharacter returns 200; always capture an unquoted control response
before attributing an error to injection.**

## 2. "Ordering changes when a CASE expression is appended to the sort parameter"

*Looked vulnerable:* `sort=id` returned ascending rows and
`sort=id,CASE WHEN 1=1 THEN 1 ELSE 0 END` returned a visibly different order.
*Disproof test:* repeat both requests three times each, compare the complete
ordered list of record identifiers, then repeat with a deliberately nonsense sort
key.
*Invalidated by:* the two orderings also differed between two **identical repeat**
requests — the ordering is unstable for reasons unrelated to the injected
expression, so the key was not reaching a query.
*Early signal missed:* should have checked whether baseline ordering is
deterministic before using order as the signal at all.
*Rejection rule:* **ordering is only a valid injection signal when a repeated
identical baseline request is byte-identical.**

## 3. "A UNION SELECT payload is accepted because the response returns a different column count"

*Looked vulnerable:* appending ` UNION SELECT 1,2,3--` changed response length and
the page rendered the appended values.
*Disproof test:* run the same UNION with deliberately wrong column counts (two,
four, ten) and confirm the injected values appear at a **stable position**.
*Invalidated by:* the response differed for every column count including impossible
ones, and the "injected" values were already present in the page's own template —
the difference was template rendering, not query execution.
*Early signal missed:* should have searched the unmodified page for the literal
test values 1,2,3 before concluding they were injected.
*Rejection rule:* **before claiming UNION injection, grep the baseline response for
the literal values you injected; a value already present in the template proves the
response difference came from rendering, not the query.**

## 4. "The endpoint is blind-injectable because a sleep payload measurably delays the response"

*Looked vulnerable:* `sort=1,SLEEP(5000)` returned in ~5.1s vs a 40ms baseline.
*Disproof test:* repeat each request **ten times alternating** baseline and
payload, and separately time a request to a hostname that does not resolve, to
isolate network latency.
*Invalidated by:* the delay was not correlated with the payload — alternating
requests showed the delay on baselines too, and an unresolvable host produced a
comparable timeout, so the latency is the network path.
*Early signal missed:* should have established baseline variance before treating a
single slow response as a signal.
*Rejection rule:* **timing-based injection requires repeated alternating samples
showing the delay tracks the payload; one slow response against an unbaselined
network is a network event, not a finding.** A concatenated slow operation that
leaves page-load time flat, or a delay that appears just as often on a control
request carrying no injected syntax, refutes it as a blind SQL injection oracle
[sqli.test.ht_therefore_a_good_way_to_discover].

## 5. "The id parameter is injectable because numeric ids return different data than string ids"

*Looked vulnerable:* `?id=1` returned a record; `?id=1'` returned HTTP 400
`invalid input`.
*Disproof test:* send a valid id, an out-of-range numeric id, an out-of-range id
with a trailing quote, and a negative id, comparing bodies.
*Invalidated by:* any out-of-range value returns the same 400 regardless of
quoting, and the message is a fixed application validation string with no
database wording — the quote is rejected by type validation before any query.
*Early signal missed:* should have separated "rejected by input validation" from
"reached the data layer".
*Rejection rule:* **a validation error that is byte-identical for any invalid
value indicates a type check, not a parser; a parser-specific error must name the
construct that failed.**

## 6. "An error-based payload exfiltrated database version information"

*Looked vulnerable:* the body contained `10.11.6-MariaDB` after injecting a
version-selecting expression.
*Disproof test:* search the unmodified baseline responses of several other
endpoints for the same version string, and repeat the payload against a parameter
that is definitely not a query.
*Invalidated by:* the version string appears in the response headers of every page
including ones with no injectable parameter — server disclosure, not something the
injection returned.
*Early signal missed:* should have checked whether the "exfiltrated" value was
already being disclosed by the server regardless of input.
*Rejection rule:* **before calling a value "extracted by injection", grep other
responses for it; a value the server already emits is information disclosure, a
different finding with a different fix.**

## 7. "The WAF is bypassable because the payload with a comment marker returned HTTP 200"

*Looked vulnerable:* `sort=id/**/UNION/**/SELECT` returned 200 where the
uncommented equivalent was blocked with 403.
*Disproof test:* send the same union payload repeatedly to see whether the 200 is
stable, and send a harmless but syntactically similar payload that returns no
data.
*Invalidated by:* the 200 response contained **no injected data**, and the same
payload alternated between 200 and 403 across repeats — the filter is
probabilistic rather than bypassed.
*Early signal missed:* should have checked for stable behaviour and for actual
returned data before declaring a filter bypass.
*Rejection rule:* **a filter bypass requires the bypassed request to return
attacker-chosen data consistently; a status code that alternates across identical
requests is filter noise, not a bypass.** WAFs that normalize, case-filter or
over-clean can be bypassed by comment-splitting, mixed case, encoding and parameter
pollution — but only a confirmed data return is the bypass
[sqli.bypass.waf_normalization_encoding]; if every encoded, case-varied and split
variant is rejected identically and no differential appears, the block is likely
enforced downstream of the WAF, not by it.

## 8. "The comment-terminated payload proves the input is concatenated rather than parameterised"

*Looked vulnerable:* appending `-- -` suppressed the trailing part of the query and
the result set changed.
*Disproof test:* apply the same comment terminator to a parameter with **no query
at all**, and compare against an **empty value** and a value with a trailing
space.
*Invalidated by:* a trailing `-- -` produced the same result as an empty value —
the application's own trimming behaviour; the result change came from the value
being empty, not from a comment being honoured.
*Early signal missed:* should have tested what the application does with an empty
value before attributing behaviour to comment syntax.
*Rejection rule:* **a comment marker only demonstrates concatenation if its effect
differs from an empty value; identical results mean the marker is ordinary input,
not a comment.**

---

## Corpus fp_rules — the negative cases and what invalidates them

### 9. Generic 500 / generic error page
*Rule:* a 500 or generic error page triggered by malformed input alone is not SQLi
evidence; many apps error identically for any invalid value
[sqli.fp_rule.generic_500_not_sqli].
*Disproof test:* establish a baseline with clearly invalid input such as a string
where a number is expected, and check whether that also 500s
[sqli.test.a_500_or_generic_error_page_triggered_by_malform].
*Invalidated by:* plain type-mismatch input producing the identical 500 response
with no SQL-specific text — the 500 is an input-validation artefact, not SQLi.

### 10. Parameterized ORM/HQL with a quote error
*Rule:* under a properly parameterized ORM/HQL query, quote and comment payloads
are matched as literal data, so their failure to inject is a true negative, not a
missed bug [sqli.fp_rule.orm_parameterized_quote_error].
*Disproof test:* confirm the endpoint routes through the ORM's bound-parameter API
rather than concatenated HQL or native SQL. If so, payloads like `tom'` or
`'1'='1` are searched for verbatim and produce zero rows or a type error — expected
behaviour.
*Invalidated by:* the ORM library having a known injection CVE for the deployed
version, or raw concatenated queries appearing in the code path. Either invalidates
the negative.

### 11. A parameterised call site whose error echoes the comment
*Rule:* a request that returns a database error echoing the caller's own input,
on a code path that passes that input as a bound parameter, is a verbose-error
disclosure and **not** SQL injection — the value never entered the statement text
[sqli.fp_rule.a_parameterized_query_whose_comment_appears_in_an_error_is_not_injection].
*Disproof test:* show that the *value* has no behavioural effect — quote, comment
and doubled-quote all produce the same result as the plain value.
*Invalidated by:* the same request also producing a behaviour change with the quote
removed — a boolean differential, a time delta, or an OAST callback — because then
the value is reaching the statement text by some other route even if this call site
is parameterised. Parameterisation is per call site, and applications routinely
have a safe read path and an unsafe report, export, or search path on the same
endpoint. The rule also fails when the framework's own **string escaping** is being
relied on rather than binding: a helper that quotes and doubles the value correctly
still yields a value that will break the moment a second, unescaped layer
concatenates it, so the presence of quotes in the output is not evidence of safety
at the statement level.

### 12. Dollar-quoting in a function body
*Rule:* a dollar-quoted string in PostgreSQL is a closed literal that ignores
backslashes and dollar signs, so a payload containing `$tag$` delimiters only
becomes dangerous if the attacker can supply the tag the application's own quoting
chose [sqli.fp_rule.dollar_quoting_in_a_function_body_is_not_an_injection].
*Disproof test:* confirm the value sits inside the application's dollar-quoted
region and that the tag is application-chosen, not attacker-controlled.
*Invalidated by:* the tag being attacker-controlled or absent in a way that lets the
payload close the literal — an unquoted dollar-quoted string in a function
definition whose body is built from user input lets an attacker insert their own
`$q$...$q$` and terminate it, and PostgreSQL's own nested-dollar-quote example shows
exactly that shape. It also fails if the payload is delivered **outside** the
dollar-quoted region: a second statement concatenated after the function body, or a
value reaching a non-dollar-quoted parameter such as a dynamic EXECUTE string, is
ordinary SQL and the standard payloads apply.

### 13. Full-text search query language
*Rule:* in a full-text search parameter the attacker-controlled text is a query
language, not a string literal, so single-quote and UNION payloads test nothing and
the injection point is the operator's own grammar
[sqli.validation.a_search_box_taking_a_fts_query_string_is_not_covered_by_the_quote_payload].
*Disproof test:* probe the operator's own metacharacters — for a boolean-mode
`MATCH ... AGAINST` clause, the quote and the boolean-mode operators rather than a
plain WHERE value [sqli.variant.ht_example_query_built_by_the_backend].
*Invalidated by:* the value being quoted or escaped before reaching the operator's
parser, which removes the grammar surface entirely and makes the standard payload
the right one again. Also, the mere existence of a rich query language in a search
box is not a finding: FTS5's own syntax is deliberately non-SQL, so a payload that
changes match results is a search-behaviour quirk rather than SQL injection. The
finding needs the grammar surface to reach a SQL-executing construct — for example
an FTS expression that a trigger, a view, or an auxiliary function expands into
further SQL — and that chain has to be demonstrated.

---

## Cross-cutting: the four controls that kill most of these at once

1. **Unquoted / empty / type-mismatch control.** Refutes 1, 5, 8 and 9.
2. **Repeat-and-interleave.** Refutes 2, 4 and 7.
3. **Grep the baseline for your own literals.** Refutes 3, 6 and 7.
4. **True/false inversion.** Refutes any "the response changed" claim that cannot
   reverse [sqli.validation.single_variable_differential]
   [sqli.technique.sql_injection_is_confirmed_by_a_boolean_differential_a_co].