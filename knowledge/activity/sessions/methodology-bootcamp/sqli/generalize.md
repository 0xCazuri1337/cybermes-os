# generalize — common, uncommon and defensive variants

The class generalizes along three axes: **context** (where in the statement the
value lands), **dialect** (which grammar is available), and **defence shape**
(what actually stands between the attacker and the parser). Reading a variant
wrong is what produces the false positives catalogued in `reject_fp.md`.

---

## A. Common variants — expect these first

**A1. Numeric/ID parameter.** The highest-yield context in the class, because
the developer often builds `WHERE id = ` + input with no quoting layer at all, so
there is no literal to escape. The differential shape is the boolean twin pair
[sqli.signal.quote_and_boolean_differential], and the reporting trap is the
type-validation 400 that looks like a rejection but is a type check
[sqli.fp_rule.generic_500_not_sqli].

**A2. Sort / ORDER BY parameter.** Concatenated by reflex while the WHERE clause
stays parameterised. Yields ordering and row-count differentials
[sqli.technique.orderby_column_count_probe] — and inherits false positive #2, so
prove baseline ordering is deterministic before you use it.

**A3. Search box / LIKE clause.** Usually the `%` wildcard makes developers
concatenate. Common in the FTS/boolean-mode flavour
[sqli.variant.ht_example_query_built_by_the_backend].

**A4. Authentication and lookup queries.** Where the impact ceiling is highest:
a confirmed SQLi typically yields bulk read of application data and can subvert
authentication, not just a single leaked record
[sqli.impact.data_and_auth_compromise].

**A5. UNION with recoverable column count.** Two routes, both standard:
successively longer runs of NULL placeholders — NULL type-checks in any column
position and so maximises the chance the payload succeeds
[sqli.technique.hth_union_select_null_union_se] — and walking `ORDER BY <n>` until
the response changes, which works where errors are suppressed
[sqli.technique.orderby_column_count_probe]. Once the width is matched, a string
marker finds a typed channel [sqli.technique.union_null_type_probe] and a
wildcard select reads a position without needing the column's name
[sqli.technique.ht_0_union_select_from_flag_it_s_p].

**A6. Blind boolean character-by-character.** The app's visible behaviour depends
on a single condition; arbitrary values are recovered one character at a time
[sqli.technique.boolean_character_extraction].

**A7. Time-based blind.** A deliberately slow operation concatenated into the
query produces a repeatable jump in page-load time the unmodified request does not
show [sqli.test.ht_therefore_a_good_way_to_discover]. Highest false-positive rate
of any technique — this is where the alternating-sample rule earns its keep.

## B. Uncommon variants — where the standard playbook does not fit

**B1. Boolean-mode full-text search.** The term is concatenated inside the quoted
argument of a `MATCH ... AGAINST` clause, so the correct probes are the quote and
the boolean-mode operators rather than a plain WHERE value
[sqli.variant.ht_example_query_built_by_the_backend]. A parameter that can neither
break out of the quotes nor change the boolean-mode search is refuted as an
injection point.

**B2. A parameter whose text *is* a query language.** In a full-text search
parameter the attacker-controlled text is a query language, not a string literal,
so single-quote and UNION payloads test nothing and the injection point is the
operator's own grammar
[sqli.validation.a_search_box_taking_a_fts_query_string_is_not_covered_by_the_quote_payload].
Critically, the rich grammar is not itself a finding — FTS5's syntax is
deliberately non-SQL — so a payload that only changes match results is a
search-behaviour quirk. The finding needs the grammar surface to reach a
SQL-executing construct, e.g. an FTS expression a trigger, a view or an auxiliary
function expands into further SQL, and that chain has to be demonstrated.

**B3. Second-order / stored injection.** Data written safely by one request can
become injectable when a later request concatenates the stored value into a new
query [sqli.chain_link.second_order_stored_flow]. The tell: every write-time probe
is negative, yet the application clearly re-uses stored values. Not second-order
injectable if the stored payload is only ever read back through parameterized
queries.

**B4. Asynchronous execution.** If the app neither returns query results nor error
differences nor timing changes, the query may run asynchronously; absence of
in-band signal does not mean absence of SQLi
[sqli.signal.async_query_oast_signal]. Only an OAST callback closes this, and
only *both* a null callback and conditional delays within baseline jitter support
a genuine negative.

**B5. PostgreSQL dollar-quoted function bodies.** The literal is closed and
ignores backslashes and dollar signs, so `$tag$` payloads are inert unless the
attacker supplies the tag the application's own quoting chose — or unless the
payload lands outside that region, e.g. a second statement concatenated after the
function body, or a value reaching a non-dollar-quoted parameter such as a dynamic
EXECUTE string
[sqli.fp_rule.dollar_quoting_in_a_function_body_is_not_an_injection].

**B6. MS Access quirks.** Extraction is gated on naming a real column such as
`username`, so the guess-and-check step on column names comes *before* any value
can be pulled out [sqli.prerequisite.ht_imagine_that_you_have_sql_injectio];
`TOP`/`LAST` act as row selectors so a table can be paged rather than dumped
[sqli.technique.ht_top_accepts_as_argument_an_integer]; and pointing the database
reference at a local file produces an invalid-database-format error only when the
file is really there, making file enumeration an error-comparison exercise
[sqli.test.ht_if_the_specified_file_exists_ms_a].

**B7. MSSQL-specific reach and read-back.** `sys.dm_exec_requests` joined to
`sys.dm_exec_sql_text` reads the live query text back, confirming the injection
really landed [sqli.test.ht_the_currently_executing_sql_query];
`fn_my_permissions` filtered on a named permission reveals which database-level
grants the injected session holds, before any escalation is planned
[sqli.technique.ht_select_from_fn_my_permissions_nu].

**B8. Non-parameterised entry points outside the URL.** JSON/XML bodies, cookies
and headers are all injection candidates, not just GET parameters
[sqli.prerequisite.entry_point_inventory] — and a field provably never used in any
query (client-side sorting, CSRF tokens) cannot be one.

**B9. WAF-mediated variants.** Comment-splitting, mixed case, encoding and
parameter pollution defeat filters that normalize, case-filter or over-clean
[sqli.bypass.waf_normalization_encoding]. For MySQL enumeration the alternating
letter case of quoted keywords is itself the point — the enumeration has to be
sent in mixed case so a filter matching keywords in one fixed case does not stop
it [sqli.technique.ht_mysql_union_based_sql_union_selec]. If every encoded,
case-varied and split variant is rejected identically and no differential appears,
the block is likely enforced downstream of the WAF, not by it.

## C. Defensive variants — what the defence actually changes

**C1. Properly parameterised ORM/HQL.** Quote and comment payloads are matched as
literal data, so their failure to inject is a true negative, not a missed bug
[sqli.fp_rule.orm_parameterized_quote_error]. Invalidated only by a known
injection CVE for the deployed version or raw concatenated queries in the code
path. Persistence layers such as Hibernate or EJB can provide significant
protection when used properly — the caveat being that the protection is a property
of *use*, not of the library's presence.

**C2. The parameterization baseline as the thing to establish.** Prepared/bind
statements force the database to separate code from data, and that is the baseline
you must establish before treating quote errors as SQLi
[sqli.prerequisite.parameterization_baseline]. If the query string is built by
concatenation at runtime even where a parameterized API exists, the endpoint is
not parameterized.

**C3. Input validation alone — insufficient.** Input validation will not always
prevent SQL injection, especially where free-form text fields must accept arbitrary
characters. A denylist of quote-and-comment characters is incomplete with respect
to the grammar it defends, which is why C1/C2 is the real control.

**C4. Escaping as a *layer* rather than a bound parameter.** A helper that quotes
and doubles a value correctly still yields a value that breaks the moment a
second, unescaped layer concatenates it. Quotes appearing in output are not
evidence of safety at the statement level
[sqli.fp_rule.a_parameterized_query_whose_comment_appears_in_an_error_is_not_injection].
This is the variant that most often produces "we fixed it" findings that return.

**C5. Per-call-site defence heterogeneity.** The same endpoint can have a safe read
path and an unsafe report, export or search path. "The main query is parameterised"
is a statement about one call site, not about the endpoint
[sqli.fp_rule.a_parameterized_query_whose_comment_appears_in_an_error_is_not_injection].

**C6. Verbose-error suppression.** A generic custom error page with no driver text
and no reflected query fragment removes the cheapest confirmation route
[sqli.validation.verbose_error_confirmation] — but it removes a *convenience*, not
the vulnerability, so boolean and time routes remain live.

**C7. Least-privilege as the impact ceiling.** Read-only grants scoped to a single
view bound impact to that view's data
[sqli.impact.data_and_auth_compromise]; `fn_my_permissions` is how you *measure*
that ceiling rather than assume it
[sqli.technique.ht_select_from_fn_my_permissions_nu].

## D. Generalization rules that survive contact with new targets

1. **Map the context before choosing the payload.** In-list vs in-string vs
   ORDER BY vs MATCH argument determine the payload vocabulary. A payload tuned to
   the wrong context returns "negative" and stops the hunt.
2. **The cheapest discriminator is the control request**, not the payload —
   unquoted, empty, and type-mismatch baselines decide more cases than any payload.
3. **Reversal is the only test that separates a signal from a coincidence.** A
   difference that does not reverse when the condition is inverted is not a
   validated SQLi [sqli.validation.single_variable_differential].
4. **Attribution can substitute for isolation in exactly two documented ways** — an
   out-of-band callback from a database-assembled payload, or an endpoint exposing
   the generated SQL [sqli.validation.one_variable_at_a_time_is_the_only_way_the_differential_is_attributable].
   Use those to escape a multi-parameter request rather than pretending isolation
   wasn't violated.
5. **A negative is only meaningful if the oracle is known to exist.** Confirm the
   response *can* vary before concluding it does not
   [sqli.technique.sql_injection_is_confirmed_by_a_boolean_differential_a_co].
6. **Bound the claim by grants, not by class name**
   [sqli.impact.data_and_auth_compromise]
   [sqli.technique.ht_select_from_fn_my_permissions_nu].