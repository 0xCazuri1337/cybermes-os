# validate — the request/response pair shape that proves impact

## What counts as proof

Proof in this class is a **paired differential plus an attributable cause**. The
minimum shape:

```
A) GET /item?sort=id&case=<plain value>          HTTP/1.1
   -> HTTP/1.1 200, body B0  (baseline, captured BEFORE any payload)

B) GET /item?sort=id&case=id,CASE WHEN 1=1 THEN 1 ELSE 0 END   HTTP/1.1
   -> HTTP/1.1 200, body B1  (row count N)

C) GET /item?sort=id&case=id,CASE WHEN 1=2 THEN 1 ELSE 0 END   HTTP/1.1
   -> HTTP/1.1 200, body B2  (row count M, M != N)
```

Both B and C replayed three times with all other parameters identical, diffing
status code, headers and body
[sqli.test.a_sqli_finding_is_only_validated_when_one_variab]. The finding is valid
only when the difference is reproducible and explainable by query logic
[sqli.validation.single_variable_differential] — the true and false conditions
must reverse each other, and the true condition must land on the baseline's
behaviour.

Where a verbose database error echoes the constructed query, that single response
upgrades a blind finding to a visible one and independently confirms the
injection point's context [sqli.validation.verbose_error_confirmation] — the
surrounding SQL in the error is the cheapest possible proof of where the value
landed.

Where errors are suppressed, an incrementally-walked `ORDER BY <n>` change at
exactly one index is the structural proof
[sqli.technique.orderby_column_count_probe], and a `UNION SELECT` accepted at
exactly one width of NULL placeholders is the structural proof
[sqli.technique.hth_union_select_null_union_se].

## Escalation from mechanism to impact

A differential proves the mechanism. Impact needs a data event:

- **Read proof.** `UNION SELECT <marker>,...` at the matched width, where the
  marker appears in the response at a stable position. Then a wildcard select
  over a named table reads a chosen position without needing the column's name
  [sqli.technique.ht_0_union_select_from_flag_it_s_p].
- **Schema proof.** A single injected `UNION SELECT` over `information_schema.columns`
  returns schema, table and column names of the current database at once
  [sqli.technique.ht_here_s_how_to_retrieve_the_schema]; naming a target table
  turns the same pattern into a column dictionary, so you move from which tables
  exist to exactly which attributes the injected query can reference
  [sqli.technique.ht_union_select_1_2_3_4_group_con]. On MySQL the schema and
  table names come out of a `GROUP_CONCAT` over `information_schema`, and the
  mixed case of the quoted keywords is deliberate so a filter matching keywords in
  one fixed case does not stop it [sqli.technique.ht_mysql_union_based_sql_union_selec].
- **Blind data proof.** One character at a time, making the app's visible
  behaviour depend on a single condition [sqli.technique.boolean_character_extraction],
  or a repeatable jump in page-load time the unmodified request does not show
  [sqli.test.ht_therefore_a_good_way_to_discover].
- **Reach proof.** `fn_my_permissions` filtered on a named permission tells you
  which database-level grants the injected session actually holds
  [sqli.technique.ht_select_from_fn_my_permissions_nu]; on MSSQL the DMVs
  `sys.dm_exec_requests` joined to `sys.dm_exec_sql_text` read the live query text
  back [sqli.test.ht_the_currently_executing_sql_query].
- **Second-order proof.** A value accepted safely at write time that is later
  concatenated into a new query; the flow is not second-order injectable if the
  stored payload is only ever read back through parameterized queries
  [sqli.chain_link.second_order_stored_flow].

## What does NOT count as proof

- **A 500, alone.** A 500 or generic error page triggered by malformed input alone
  is not SQLi evidence; many apps error identically for any invalid value
  [sqli.fp_rule.generic_500_not_sqli]. A 500 on a metacharacter proves nothing
  until the same request without the metacharacter returns 200.
- **A difference that does not reverse** under condition inversion — cache-,
  session-, or rate-limit-driven, so not a validated SQLi
  [sqli.validation.single_variable_differential].
- **A differential from varying several parameters at once.** It is not
  attributable to any of them. Two exceptions do substitute for isolation: an
  out-of-band callback from a payload that could only have been assembled by the
  database (the callback proves the injected expression executed), and an endpoint
  that exposes the generated SQL — a debug echo, a query log, an error page
  printing the statement [sqli.validation.one_variable_at_a_time_is_the_only_way_the_differential_is_attributable].
- **A 200 on a filtered request with no injected data in it.** A filter bypass
  requires the bypassed request to return attacker-chosen data consistently
  [sqli.bypass.waf_normalization_encoding].
- **A value the server already discloses.** A version string appearing in the
  response headers of every page, including pages with no injectable parameter, is
  information disclosure, not something the injection returned.
- **Injected literals that were already in the baseline page.** If the values you
  injected are already present in the template, the response difference came from
  rendering, not query execution.
- **Comment-marker effects identical to an empty value.** That is the app's own
  trimming; the marker is ordinary input, not a comment.
- **A quote payload that failed, on a parameterised call site.** Quote and comment
  payloads matched as literal data under a properly parameterized ORM/HQL query is a
  true negative [sqli.fp_rule.orm_parameterized_quote_error] — unless the ORM has a
  known injection CVE for the deployed version, or raw concatenated queries appear
  in the code path.
- **A search-behaviour change from operators alone.** FTS5's own syntax is
  deliberately non-SQL, so a payload that only changes match results is a
  search-behaviour quirk; the grammar surface has to be shown reaching a
  SQL-executing construct [sqli.validation.a_search_box_taking_a_fts_query_string_is_not_covered_by_the_quote_payload].

## Claim-bounding (the honest ceiling)

State impact as bounded by the account's grants, not by the class name. A
confirmed SQLi typically yields bulk read of application data and can subvert
authentication [sqli.impact.data_and_auth_compromise]; but if the DB account is
restricted to read-only access to a single view and auth cannot be subverted,
impact is bounded to the data in that view. Write the ceiling into the finding —
`fn_my_permissions` and the DMV read-back are how you earn it rather than assume it
[sqli.technique.ht_select_from_fn_my_permissions_nu]
[sqli.test.ht_the_currently_executing_sql_query].

## Two last validation traps

A database error echoing your own input on a bound-parameter call site is a
verbose-error disclosure, not injection — the value never entered the statement
text. It becomes injection only if the same request *also* produces a behaviour
change with the quote removed
[sqli.fp_rule.a_parameterized_query_whose_comment_appears_in_an_error_is_not_injection].
And in PostgreSQL a dollar-quoted string in a function body is a closed literal
that ignores backslashes and dollar signs, so a payload with `$tag$` delimiters
only becomes dangerous if the attacker can supply the tag the application's own
quoting chose — or if the payload is delivered outside the dollar-quoted region, a
second statement concatenated after the function body, or a value reaching a
non-dollar-quoted parameter such as a dynamic EXECUTE string
[sqli.fp_rule.dollar_quoting_in_a_function_body_is_not_an_injection].