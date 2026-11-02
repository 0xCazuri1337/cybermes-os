# hypothesize — falsifiable hypotheses, each keyed to an observed signal

Each hypothesis below names (a) the signal that produced it and (b) the
observation that would refute it. A hypothesis with no refutation clause is a
claim, and claims do not go in this file.

---

**H1 — Boolean-context injection in the sort/comparison parameter.**
*Signal observed:* appending `CASE WHEN 1=1 THEN 1 ELSE 0 END` to a `sort` value
visibly reorders results, and a single quote on the same field changes the
response [sqli.signal.quote_and_boolean_differential].
*Statement:* the sort fragment is concatenated into the statement text, so its
value is parsed as grammar rather than bound as a value.
*Refuted by:* the true and false conditions returning byte-identical responses —
which indicates the value is escaped, parameterized, or never reaches a SQL parser
[sqli.technique.sql_injection_is_confirmed_by_a_boolean_differential_a_co]; or
two identical repeat requests returning different orderings, which makes the
baseline non-deterministic and the signal unattributable.

**H2 — Error-based injection in the search field.**
*Signal observed:* `?q=test'` returns a body containing database syntax-error
wording [sqli.validation.verbose_error_confirmation].
*Statement:* the quote reaches a SQL parser and the resulting error is
parser-generated, so the injection point's context is inside a string literal.
*Refuted by:* a 400 with fixed application validation wording and no database
text, byte-identical for any invalid value — that is a type check before the data
layer; or a 500 that also occurs on plain type-mismatch input
[sqli.fp_rule.generic_500_not_sqli].

**H3 — Blind boolean oracle (two-valued, no reflected data).**
*Signal observed:* true and false conditions change row count or ordering but no
injected value ever appears [sqli.technique.sql_injection_is_confirmed_by_a_boolean_differential_a_co].
*Statement:* the application has an in-band two-valued oracle, so arbitrary
characters can be recovered one at a time
[sqli.technique.boolean_character_extraction].
*Refuted by:* identical responses for true and false, which makes boolean
extraction impossible and requires time-based or OAST instead
[sqli.technique.boolean_character_extraction].

**H4 — Blind time-based oracle.**
*Signal observed:* a concatenated slow operation produces a repeatable jump in
page-load time that the unmodified request does not show
[sqli.test.ht_therefore_a_good_way_to_discover].
*Statement:* the delay is caused by the database executing the injected slow
operation, not by the network.
*Refuted by:* a concatenated slow operation that leaves page-load time flat, or a
delay that appears just as often on a control request carrying no injected syntax
[sqli.test.ht_therefore_a_good_way_to_discover]; equivalently, alternating
sampling where the delay appears on baselines too and an unresolvable host
produces a comparable timeout, which makes the latency the network path.

**H5 — Asynchronous / out-of-band execution only.**
*Signal observed:* no results, no error differences, no timing changes on any
in-band probe, on an endpoint that is known to enqueue work
[sqli.signal.async_query_oast_signal].
*Statement:* the query runs asynchronously and only an out-of-band callback can
expose it.
*Refuted by:* an OAST payload producing no collaborator/DNS callback and
conditional time delays staying within baseline jitter, which makes the parameter
very likely not injectable [sqli.signal.async_query_oast_signal].

**H6 — UNION-capable injection with recoverable column count.**
*Signal observed:* an appended `UNION SELECT` clause alters the response at one
specific width of placeholders and not at others
[sqli.technique.hth_union_select_null_union_se].
*Statement:* the column count is n and a UNION row will render in the response,
so a wildcard select can read a table positionally
[sqli.technique.ht_0_union_select_from_flag_it_s_p].
*Refuted by:* no NULL-counted payload ever producing the extra result set or
altering the response, meaning the count was never matched
[sqli.technique.hth_union_select_null_union_se]; or the response differing for
every column count including impossible ones
[sqli.technique.union_null_type_probe].

**H7 — Column count recoverable by ORDER BY despite suppressed errors.**
*Signal observed:* errors are generic and no statement text is echoed, but
incrementing `ORDER BY <n>` produces a response change at one index
[sqli.technique.orderby_column_count_probe].
*Statement:* the error suppression hides diagnostics but not the width limit.
*Refuted by:* every index from 1 upward yielding an identical response, which
forces a fall back to UNION NULL probing
[sqli.technique.orderby_column_count_probe].

**H8 — The value is safely bound at this call site (negative hypothesis).**
*Signal observed:* quote and comment payloads are matched as literal data, and
the endpoint routes through an ORM's bound-parameter API
[sqli.fp_rule.orm_parameterized_quote_error].
*Statement:* the payloads were searched verbatim; zero rows or a type error is
expected behaviour, and this is a true negative rather than a missed bug.
*Refuted by:* the ORM library having a known injection CVE for the deployed
version, or raw concatenated queries appearing in the code path
[sqli.fp_rule.orm_parameterized_quote_error].

**H9 — A second-order injection through stored data.**
*Signal observed:* a value the app accepted safely at write time is later used in
a query built by concatenation [sqli.chain_link.second_order_stored_flow].
*Statement:* the first request's payload becomes grammar on the second request.
*Refuted by:* the stored payload only ever being read back through parameterized
queries and never concatenated, which makes the flow not second-order injectable
[sqli.chain_link.second_order_stored_flow].

**H10 — The grammar surface is a query language, not a SQL literal.**
*Signal observed:* a full-text search field where operators change match results
but a quote does nothing [sqli.variant.ht_example_query_built_by_the_backend].
*Statement:* the injection point is the operator's grammar, so the correct probes
are boolean-mode operators rather than quote/UNION
[sqli.validation.a_search_box_taking_a_fts_query_string_is_not_covered_by_the_quote_payload].
*Refuted by:* the parameter being unable to break out of the quotes nor change the
boolean-mode search, or the operand being escaped before reaching the operator's
parser — which removes the grammar surface entirely
[sqli.validation.a_search_box_taking_a_fts_query_string_is_not_covered_by_the_quote_payload].

---

## How these are ranked

H1–H4 and H6–H7 are cheap, in-band, and either confirm or kill in a handful of
requests — they go first. H5 costs an external collaborator callback and latency
and is reserved for endpoints where the cheap ones are uniformly null. H8 is the
hypothesis that saves you from filing a false positive, and it is falsifiable in
the same breath. H9 and H10 are context-dependent and often invisible to
single-request probing, so they are raised *after* an in-band path is exhausted
rather than instead of it.

## A hypothesis discipline this class forces

Do not run several parameters at once and then reason about which one caused the
difference. A boolean or time differential found while several parameters are
being varied at once is not attributable to any of them, so the finding is only
valid once the same differential reproduces with exactly one variable changed
[sqli.validation.one_variable_at_a_time_is_the_only_way_the_differential_is_attributable].
The two documented exceptions are worth stating because they change the plan: an
out-of-band callback from a payload that could only have been assembled by the
database is attributable regardless of how many other parameters were in the
request, and an endpoint that exposes the generated SQL — a debug echo, a query
log, an error page printing the statement — settles where the value landed
[sqli.validation.one_variable_at_a_time_is_the_only_way_the_differential_is_attributable].
Holding the other parameters constant by construction (fixing them from a captured
baseline and varying only the target) also makes the differential attributable.