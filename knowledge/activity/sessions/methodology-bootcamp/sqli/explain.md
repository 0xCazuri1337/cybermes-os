# explain — SQL Injection (sqli), the chain and the failing invariant

Class CWE-89, web surface, OWASP A03:2021. Corpus grounding for every step below is
cited inline to a promoted item in this class.

## The chain, end to end

1. **Attacker input.** Any request-controllable value that reaches a query is a
   candidate injection point, and "candidate" is broader than the URL query
   string — JSON/XML bodies, cookies and headers all qualify, not just GET
   parameters [sqli.prerequisite.entry_point_inventory].

2. **Parser.** The value lands in a statement whose structure is now partly
   attacker-written. The minimum viable grammar escape is a single quote, which
   closes the string literal the developer opened; the classic confirmation is
   that quote plus a paired `OR 1=1` / `OR 1=2` twin set producing a repeatable
   response difference [sqli.signal.quote_and_boolean_differential].

3. **Normalisation.** Before the parser ever runs, an endpoint may already have
   rewritten the value: trimmed it, doubled quotes, coerced it, or rejected it on
   type. This is where most false positives are born, and it is the reason a
   finding is only validated once one variable changes at a time and the
   difference is reproducible and explainable by query logic
   [sqli.validation.single_variable_differential]. WAF normalisation is the same
   phenomenon one layer earlier in the pipeline: a filter that normalises,
   case-filters or over-cleans can be bypassed by comment-splitting, mixed case,
   encoding and parameter pollution [sqli.bypass.waf_normalization_encoding].

4. **Validation.** Applications often *do* validate — and validation alone is not
   the defence, because free-form text fields must still accept arbitrary
   characters, so a denylist of quote-and-comment characters is defeated by the
   fact that it cannot enumerate the grammar. The durable control is the
   parameterization baseline: prepared/bind-variable statements force the database
   to separate code from data, and that is what must be established before a
   quote error is read as injection [sqli.prerequisite.parameterization_baseline].

5. **Trust decision.** The failing decision is the one that says "this value is
   data, not code". Under a properly parameterized ORM/HQL query, quote and
   comment payloads are matched as literal data, so their failure to inject is a
   true negative, not a missed bug [sqli.fp_rule.orm_parameterized_quote_error].
   Parameterization is a *per-call-site* property: an application can have a
   safe read path and an unsafe report, export or search path on the same
   endpoint [sqli.fp_rule.a_parameterized_query_whose_comment_appears_in_an_error_is_not_injection].

6. **Internal operation.** Once structure is attacker-controlled the database
   executes attacker-chosen predicates, row selectors and set operations. Column
   count is the first internal fact to recover, by matching the result-set width
   through successively longer runs of NULL placeholders — NULL is the filler
   because it type-checks in any column position and so maximises the chance the
   payload succeeds [sqli.technique.hth_union_select_null_union_se], and by
   walking `ORDER BY <n>` upward until the response changes, which works even
   where errors are suppressed [sqli.technique.orderby_column_count_probe].
   A string marker is then placed in each position to find a column type that can
   carry exfiltrated data [sqli.technique.union_null_type_probe]. Data leaves by
   positional read: a wildcard select over a named table returns a chosen
   position without ever needing the column's name
   [sqli.technique.ht_0_union_select_from_flag_it_s_p].

7. **Observable result.** The oracle need not be a reflected value. A condition
   that is always true returns the normal row count while the same condition
   forced false returns a different one
   [sqli.technique.sql_injection_is_confirmed_by_a_boolean_differential_a_co];
   arbitrary values can be extracted one character at a time by making the app's
   visible behaviour depend on a single condition
   [sqli.technique.boolean_character_extraction]; a deliberately slow
   concatenation produces a repeatable jump in page-load time the unmodified
   request does not show [sqli.test.ht_therefore_a_good_way_to_discover]; and a
   verbose database error that echoes the constructed query turns blind injection
   visible and independently confirms the injection point's context
   [sqli.validation.verbose_error_confirmation].

## The exact invariant that fails

**Invariant: the bytes the attacker supplies must be delivered to the database as
values, never as statement structure.** A parameterized statement maintains the
invariant because the driver emits the statement text and the values on
separated channels; the database parses the statement once, binds the values as
typed data, and no byte of the attacker input can terminate a literal, add a
predicate, or add a clause. String concatenation breaks the invariant at the
moment the value is appended to the statement text: after that point the same
bytes are re-parsed as grammar, so the parser's context — inside a literal,
inside an ORDER BY, inside a column list, inside an MATCH argument — becomes
attacker-selectable. This is a structural defect, not a filtering defect: any
allowlist that enumerates bad characters is incomplete with respect to the
grammar it is defending, which is exactly why the parameterization baseline, not
the filter, is the thing to establish
[sqli.prerequisite.parameterization_baseline].

A refinement matters for the grammar-shaped variants. In a full-text search
parameter the attacker-controlled text is a query language, not a string literal,
so single-quote and UNION payloads test nothing and the injection point is the
operator's own grammar — but the mere existence of a rich query language in a
search box is not a finding, because FTS5's own syntax is deliberately non-SQL; a
payload that only changes match results is a search-behaviour quirk rather than
SQL injection, and the grammar surface has to be shown reaching a
SQL-executing construct [sqli.validation.a_search_box_taking_a_fts_query_string_is_not_covered_by_the_quote_payload].
There, and in a `MATCH ... AGAINST` boolean-mode search box where the term is
concatenated inside the quoted argument
[sqli.variant.ht_example_query_built_by_the_backend], the class name still
applies but the payload vocabulary changes.

## Bounded impact

A confirmed SQLi typically yields bulk read of application data and can subvert
authentication, not just a single leaked record
[sqli.impact.data_and_auth_compromise] — but the ceiling is the database account's
grants, not the vulnerability class. An MSSQL injection point doubles as a
privilege-reach probe: `fn_my_permissions` filtered on a named permission tells
the tester which database-level grants the injected session actually holds before
they plan any escalation [sqli.technique.ht_select_from_fn_my_permissions_nu]. If
the account is restricted to read-only access to a single view and auth cannot be
subverted, impact is bounded to that view's data.

## What a class name does not tell you

Saying "SQL injection" names the defect, not the diagnosis. The corpus separates
the *existence* question (is the value reaching a parser as structure?)
[sqli.signal.quote_and_boolean_differential] from the *attribution* question (can
this difference be shown to come from query logic rather than normalisation,
caching or rendering?) [sqli.validation.single_variable_differential]. Most of the
work in this class lives in the second question.