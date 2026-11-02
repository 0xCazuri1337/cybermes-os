# test — ordered plan, each step with its expected information gain

Ordering principle: spend one request to *establish a baseline* before spending
any request on a payload. Almost every false positive in this class is a
baseline that was never captured. The concrete instrument is the same across
steps: for each candidate field, replay the true/false pair three times with all
other parameters identical and diff status code, headers and body
[sqli.test.a_sqli_finding_is_only_validated_when_one_variab].

---

### Step 0 — Baseline capture (1 request per field)
Send a well-formed, ordinary value for the target field and store the complete
response.

*Expected information gain:* you gain the reference against which every later
difference is measured. Without it, nothing downstream is attributable, and a 500
on a metacharacter proves nothing until the same request without the
metacharacter returns 200 [sqli.fp_rule.generic_500_not_sqli]. This is the
single highest-gain step in the whole plan and it costs one request.

### Step 1 — Negative control (1–2 requests)
Send a clearly *invalid but structurally harmless* value — a string where a number
is expected — and check whether that also 500s
[sqli.test.a_500_or_generic_error_page_triggered_by_malform].

*Expected information gain:* you separate "the app errors on any bad input"
(which kills most error-based hypotheses) from "this value reaches a parser".
A validation error byte-identical for any invalid value indicates a type check,
not a parser; a parser-specific error must name the construct that failed.

### Step 2 — Quote / comment probe (2 requests)
Single quote, then doubled quote. Diff against baseline.

*Expected information gain:* a break in the string literal context, or a
parser-specific error naming the construct that failed. If the response is
byte-identical and there is no database wording, you have learned the value is
escaped or bound — which routes you to H8 rather than to more payloads.

### Step 3 — Boolean twin pair (2 requests, then 3× each)
`OR 1=1` / `OR 1=2` (or the equivalent true/false `CASE`), replayed three times
per the single-variable discipline
[sqli.test.a_sqli_finding_is_only_validated_when_one_variab].

*Expected information gain:* the primary first-order signal
[sqli.signal.quote_and_boolean_differential], and confirmation that the oracle is
stable enough to carry extraction. If the difference does not reverse when the
condition is inverted, or is non-deterministic/cache-driven, stop here — it is not
a validated SQLi [sqli.validation.single_variable_differential].

### Step 4 — Column count (n requests, cheap)
Two independent routes, whichever the endpoint permits. Walk `ORDER BY <n>`
upward until the response changes — this works even when errors are suppressed
[sqli.technique.orderby_column_count_probe]. If every index yields an identical
response, fall back to successively longer runs of `NULL` placeholders in a UNION
[sqli.technique.hth_union_select_null_union_se] — NULL is used as the filler
because it type-checks in any column position and so maximises the chance the
payload succeeds.

*Expected information gain:* the internal structural fact you need for every
subsequent technique, plus a map of which counting method this endpoint tolerates.

### Step 5 — Column type marker (n requests)
Place a string marker in each position to find a column that can carry
exfiltrated data [sqli.technique.union_null_type_probe]. On error-based vectors
every selected expression has to carry an alias or the query will not come back
[sqli.technique.ht_here_s_how_to_retrieve_the_schema].

*Expected information gain:* a typed, renderable channel — the difference between
proving a query executed and actually getting data out of it.

### Step 6 — Context confirmation (1 request, dialect-dependent)
Read the live statement back if the endpoint permits: on MSSQL the DMVs
`sys.dm_exec_requests` joined to `sys.dm_exec_sql_text` confirm the injection
really landed in the query and show the surrounding SQL, with the server-level
permission checked separately [sqli.test.ht_the_currently_executing_sql_query].
A single injected UNION SELECT over `information_schema.columns` hands back the
schema, table and column names of the current database at once
[sqli.technique.ht_here_s_how_to_retrieve_the_schema]; on MySQL, schema and table
names come out of a UNION SELECT with GROUP_CONCAT over `information_schema`,
sent in mixed case so a filter matching keywords in one fixed case does not stop
it [sqli.technique.ht_mysql_union_based_sql_union_selec].

*Expected information gain:* the surrounding SQL — the single cheapest way to
stop guessing at context. Note this route also resolves the attribution problem in
one shot, because an endpoint that exposes the generated SQL settles where the
value landed
[sqli.validation.one_variable_at_a_time_is_the_only_way_the_differential_is_attributable].

### Step 7 — Metadata and reach (2–4 requests)
Name a target table to turn the UNION pattern into a column dictionary, moving
from which tables exist to exactly which attributes the injected query can
reference [sqli.technique.ht_union_select_1_2_3_4_group_con]. On MSSQL call
`fn_my_permissions` against the database and filter on a named permission to
learn which database-level grants the injected session actually holds before
planning escalation [sqli.technique.ht_select_from_fn_my_permissions_nu].

*Expected information gain:* a read/write map and an honest impact ceiling —
you learn the vulnerability's reach before you escalate.

### Step 8 — Data read (1 request per value)
Positional wildcard select over the named table; the column's name is never
needed [sqli.technique.ht_0_union_select_from_flag_it_s_p]. On MS Access, name a
real column such as `username` first — extraction there is gated on that
guess-and-check step, which comes before any value can be pulled out
[sqli.prerequisite.ht_imagine_that_you_have_sql_injectio] — and use `TOP`/`LAST`
as row selectors to page out a table's records instead of dumping it whole
[sqli.technique.ht_top_accepts_as_argument_an_integer].

*Expected information gain:* actual application data, which is what turns a
mechanism finding into an impact finding.

### Step 9 — Blind extraction (only if no in-band oracle exists)
Make the app's visible behaviour depend on a single condition and recover values
one character at a time [sqli.technique.boolean_character_extraction]. If
behaviour is identical either way, use a deliberately slow operation and look for
a repeatable jump in page-load time that the unmodified request does not show
[sqli.test.ht_therefore_a_good_way_to_discover]. On MS Access, point the database
reference at a local file: the invalid-database-format error appears only when
that file is really there, so file enumeration is driven by comparing errors
across candidate paths [sqli.test.ht_if_the_specified_file_exists_ms_a].

*Expected information gain:* data without any reflected value — the only viable
route when every in-band oracle is closed.

### Step 10 — OAST (last, for asynchronous paths only)
If the app neither returns query results nor error differences nor timing changes,
the query may run asynchronously and absence of in-band signal does not mean
absence of SQLi [sqli.signal.async_query_oast_signal]. Send an out-of-band
callback payload and poll for interaction.

*Expected information gain:* resolves the one case where every in-band probe is
legitimately null. It is last because it costs an external collaborator, latency,
and an ambiguous negative.

---

## Interruption rules

Stop the plan and demote to a rejected finding when: the differential does not
reverse under inversion or is non-deterministic
[sqli.validation.single_variable_differential]; the endpoint is a confirmed
parameterized call site and no route bypasses binding
[sqli.fp_rule.orm_parameterized_quote_error]; or the parameter is provably never
used in any query, such as purely client-side sorting or a CSRF token
[sqli.prerequisite.entry_point_inventory].

Do **not** stop when: errors are generic (proceed to boolean), when ordering is
present but you have not yet confirmed the baseline is deterministic (measure it
first), or when a WAF blocks the plain payload (try the documented normalisation
variants before concluding — comment-splitting, mixed case, encoding and
parameter pollution [sqli.bypass.waf_normalization_encoding]).