# recognize — what you SEE that justifies investigating sqli

Not the class description. These are observations, each tied to the corpus item
that makes it a reason to look.

## Surface observations (ranked by how often they actually lead somewhere)

1. **A parameter whose value plausibly reaches an ORDER BY, LIKE, comparison or
   column list.** Sort/`sort`/`order`/`orderby` keys, search boxes, id and
   numeric selectors, and any field the UI describes as a filter are the classic
   carriers because developers routinely build those fragments by string
   concatenation while parameterizing the WHERE clause. Inventory every
   request-controllable value that reaches a query — JSON/XML bodies, cookies and
   headers included, not just GET parameters
   [sqli.prerequisite.entry_point_inventory].

2. **A single quote, or a paired boolean twin, changing something.** The primary
   first-order signal is a single quote or a paired `OR 1=1` / `OR 1=2` pair
   producing a repeatable response difference
   [sqli.signal.quote_and_boolean_differential]. "Repeatable" is the operative
   word — one differing response is not this signal.

3. **A database-specific wording in an error body.** Driver text, SQLSTATE-ish
   phrasing, a stack frame naming a driver, or a reflected fragment of the
   constructed statement. A verbose database error that echoes the constructed
   query turns blind injection visible and independently confirms the injection
   point's context [sqli.validation.verbose_error_confirmation]. Absence of this
   is not absence of the bug — if the app returns a generic custom error page with
   no driver text and no reflected query fragment, error-based confirmation is
   simply unavailable.

4. **A request accepted in a shape the UI never offers.** A trailing quote, a
   `%27`, a doubled quote, a backslash, `--`, `#`, `/*`, a bare `1 OR 1=1`, a
   parenthesised boolean, a stacked `;SELECT` — the field accepting a value the
   form would not submit is the observation, and it is visible in a proxy log
   without any deep testing.

5. **A full-text or boolean-mode search parameter.** A search box wired into a
   `MATCH ... AGAINST` clause in boolean mode is its own injection flavour: the
   search term is concatenated inside the quoted argument, so the quote and the
   boolean-mode operators are the right probes rather than a plain WHERE value
   [sqli.variant.ht_example_query_built_by_the_backend]. Also
   [sqli.validation.a_search_box_taking_a_fts_query_string_is_not_covered_by_the_quote_payload]
   — in a full-text parameter the text is a query language, not a string literal,
   so the quote payload tests nothing.

6. **Ordering or row count that responds to a `CASE`.** Visible result
   reordering or a row-count change when a boolean expression is appended to a
   sort or comparison parameter — but only if the baseline ordering is itself
   deterministic, which you must verify before using order as a signal.

7. **A WAF interstitial that is not uniform.** 403s on the plain form of a
   payload and 200s on a comment-split, mixed-case or encoded variant
   [sqli.bypass.waf_normalization_encoding] — that asymmetry is itself a
   recognition signal about the filter's shape.

8. **An asynchronous or fire-and-forget code path** — a queue publish, an audit
   write, an analytics sink, an export job. If the app neither returns query
   results nor error differences nor timing changes, the query may run
   asynchronously; absence of in-band signal does not mean absence of SQLi
   [sqli.signal.async_query_oast_signal].

9. **Data written by the app and later re-used in a query.** Registration
   profile fields, display names, tenant slugs, comment bodies — anything stored
   by one request and later concatenated into a new query. Data written safely by
   one request can become injectable when a later request concatenates the stored
   value into a new query [sqli.chain_link.second_order_stored_flow].

10. **A dialect tell.** Behaviour inconsistent with MySQL/Postgres/SQLite — MS
    Access quirks (TOP/LAST row selectors, `+` on booleans, file-existence errors
    from a bad database reference) [sqli.technique.ht_top_accepts_as_argument_an_integer]
    [sqli.test.ht_if_the_specified_file_exists_ms_a], MSSQL DMVs and
    `fn_my_permissions` [sqli.test.ht_the_currently_executing_sql_query]
    [sqli.technique.ht_select_from_fn_my_permissions_nu], or PostgreSQL
    dollar-quoting in a function body [sqli.fp_rule.dollar_quoting_in_a_function_body_is_not_an_injection].
    A dialect tell is a *recognition* signal, not a finding.

## Observations that are explicitly NOT this signal

- A 500 on a malformed value. Applications error identically for any invalid
  value [sqli.fp_rule.generic_500_not_sqli].
- A validation rejection carrying no database wording — that is a type check
  firing before the data layer.
- A value the server already discloses on every page (headers, banners). That is
  information disclosure, a different finding with a different fix.
- Ordering that varies between two identical repeat requests.
- A 200 on a filtered request that contains no injected data.

## Negative recognition

The absence of any of these is itself informative: if the quote and both boolean
twins produce byte-identical responses, the field shows no first-order SQLi signal
[sqli.signal.quote_and_boolean_differential]. Under a properly parameterized
ORM/HQL query, quote and comment payloads are matched as literal data, so their
failure to inject is a true negative, not a missed bug
[sqli.fp_rule.orm_parameterized_quote_error]. If an OAST payload produces no
collaborator/DNS callback and conditional time delays stay within baseline
jitter, the parameter is very likely not injectable
[sqli.signal.async_query_oast_signal]. Note the asymmetry: this class does not
permit "no signal" to become "no vulnerability" for asynchronous paths.