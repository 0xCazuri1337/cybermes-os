# chain — prerequisites, transition, escalation, blocker

The corpus holds one recorded chain for this class:
`sqli-boolean-oracle-to-row-count-enumeration`, goal **data_disclosure**. Its
impact statement: the attacker reconstructs arbitrary data from tables the
application can read, including credentials, without producing a single error or
any visible injected value. The steps below are that chain, then the extensions
each step's blocker makes reachable.

---

## Chain model

### Step 1 — Establish a boolean oracle
**Action:** find a parameter where a true condition returns a measurably
different response than a false condition, using a differential response such as
row count, ordering, or a matching row.
**Why it works:** the app's visible behaviour is a function of the predicate the
injection supplies, so it becomes a two-valued channel
[sqli.technique.sql_injection_is_confirmed_by_a_boolean_differential_a_co].
**Prerequisite:** an injectable parameter that produces a visible, stable,
two-valued difference between a true and a false condition.
**Blocker:** identical responses for true and false — which indicates the value is
escaped, parameterized, or never reaches a SQL parser
[sqli.technique.sql_injection_is_confirmed_by_a_boolean_differential_a_co]. This
is also where the parameterization baseline gets established: prepared/bind
statements force the database to separate code from data
[sqli.prerequisite.parameterization_baseline], and a parameterised ORM call site
makes the negative a true one
[sqli.fp_rule.orm_parameterized_quote_error].

### Step 2 — Measure baseline variance
**Action:** repeat both the true and false condition many times before trusting
any single difference.
**Why it works:** it separates the oracle from caching, rate limiting and
connection reuse.
**Prerequisite:** an oracle that survives repeated sampling.
**Blocker:** the oracle is unstable — an ordering that differs between two
identical repeat requests, or a delay that appears on baselines too and is
reproduced by a request to an unresolvable host. Unstable ordering means the
parameter is not demonstrably reaching the query; a single slow response against
an unbaselined network is a network event, not a finding
[sqli.validation.single_variable_differential].

### Step 3 — Extract character by character
**Action:** binary-search each character position with a comparison expression,
using the oracle response to decide whether the guessed character is above or
below the true value, repeating until the value is recovered.
**Why it works:** the app's visible behaviour is made to depend on a single
condition, so each response leaks one bit [sqli.technique.boolean_character_extraction].
**Prerequisite:** a working oracle, a position-extraction expression, and a
character range to search.
**Blocker:** the response must be identical whether the condition is true or false —
then boolean extraction is impossible and time-based or OAST is required
[sqli.technique.boolean_character_extraction]. Time-based then imports its own
blocker: a concatenated slow operation that leaves page-load time flat, or a delay
that appears just as often on a control request carrying no injected syntax,
refutes it [sqli.test.ht_therefore_a_good_way_to_discover].

### Step 4 — Re-target at credentials and sessions
**Action:** repeat the extraction against credential or session tables, and test
whether any recovered value is accepted by an authentication endpoint elsewhere in
the application.
**Why it works:** this is where a data-disclosure chain becomes an
authentication-subversion chain
[sqli.impact.data_and_auth_compromise]; if authorization information is held in a
SQL database, a successful injection can change it, not merely read it.
**Prerequisite:** knowledge of which tables hold credentials or sessions, and an
authentication endpoint to test recovered values against.
**Blocker:** least privilege. If the DB account is restricted to read-only access
to a single view and auth cannot be subverted, impact is bounded to that view's
data [sqli.impact.data_and_auth_compromise].

**Edges in the recorded chain:** step 1 *enables* step 2; step 2 *enables* step 3;
step 3 *enables* step 4. Steps 1–3 are sqli-class; step 4 crosses into
`info_disclosure`, the one related class the corpus records for sqli (3 chains).

---

## Escalation branches and their blockers

### E1 — Mechanism → UNION read (shorter route)
**Transition:** from a confirmed in-band differential, recover the column count and
read positions.
**Why:** matching the result-set width through successively longer runs of NULL
placeholders makes a UNION row render
[sqli.technique.hth_union_select_null_union_se]; `ORDER BY <n>` walked upward does
it even where errors are suppressed [sqli.technique.orderby_column_count_probe];
a string marker per position finds a typed channel
[sqli.technique.union_null_type_probe]; a wildcard select then reads a chosen
position without needing the column's name
[sqli.technique.ht_0_union_select_from_flag_it_s_p].
**Blocker:** no NULL-counted payload ever produces the extra result set or alters
the response, meaning the count was never matched
[sqli.technique.hth_union_select_null_union_se]; and if every ORDER BY index yields
an identical response, UNION NULL probing is the only remaining count route
[sqli.technique.orderby_column_count_probe]. A further trap sits here: if the
response differs for *every* column count including impossible ones, the difference
is template rendering, not query execution.

### E2 — Read → schema
**Transition:** name a target table to turn the UNION pattern into a column
dictionary, moving from which tables exist to exactly which attributes the
injected query can reference [sqli.technique.ht_union_select_1_2_3_4_group_con].
On MSSQL a single injected UNION SELECT over `information_schema.columns` returns
schema, table and column names at once, and on error-based vectors every selected
expression has to carry an alias or the query will not come back
[sqli.technique.ht_here_s_how_to_retrieve_the_schema]. On MySQL the same comes
from `GROUP_CONCAT` over `information_schema`, sent in mixed case so a filter
matching keywords in one fixed case does not stop it
[sqli.technique.ht_mysql_union_based_sql_union_selec].
**Blocker:** column enumeration coming back empty for a table the same injection
point can already read rows from refutes the metadata route
[sqli.technique.ht_union_select_1_2_3_4_group_con].

### E3 — Read → privilege reach → escalation planning
**Transition:** an MSSQL injection point doubles as a privilege-reach probe —
`fn_my_permissions` filtered on a named permission tells the tester which
database-level grants the injected session holds *before* they plan escalation
[sqli.technique.ht_select_from_fn_my_permissions_nu]; the DMVs
`sys.dm_exec_requests` joined to `sys.dm_exec_sql_text` read the live query text
back to confirm the injection landed and to see the surrounding SQL, with the
server-level permission checked separately
[sqli.test.ht_the_currently_executing_sql_query].
**Blocker:** the DMVs returning nothing, or returning a query that does not contain
the injected syntax, refutes their use; `fn_my_permissions` returning no rows for a
login that demonstrably holds the named permission refutes it as a reach check
[sqli.technique.ht_select_from_fn_my_permissions_nu].

### E4 — First request → second request (stored / deferred)
**Transition:** data written safely by one request becomes injectable when a later
request concatenates the stored value into a new query
[sqli.chain_link.second_order_stored_flow]. This is the transition with the
widest gap: the write-time probe is negative, so the chain does not open on the
obvious test.
**Blocker:** the stored payload is only ever read back through parameterized queries
and never concatenated — then the flow is not second-order injectable
[sqli.chain_link.second_order_stored_flow].

### E5 — In-band → out-of-band (asynchronous)
**Transition:** when the app neither returns query results nor error differences nor
timing changes, the query may run asynchronously and only an out-of-band callback
exposes it [sqli.signal.async_query_oast_signal].
**Blocker:** no collaborator/DNS callback and conditional time delays within
baseline jitter — then the parameter is very likely not injectable
[sqli.signal.async_query_oast_signal]. This is also the one place the
single-variable isolation rule has an express exception: an out-of-band callback
from a payload that could only have been assembled by the database is attributable
regardless of how many other parameters were in the request
[sqli.validation.one_variable_at_a_time_is_the_only_way_the_differential_is_attributable].

### E6 — Injection → filter bypass
**Transition:** WAFs that normalize, case-filter or over-clean can be bypassed by
comment-splitting, mixed case, encoding and parameter pollution
[sqli.bypass.waf_normalization_encoding].
**Blocker:** every encoded, case-varied and split variant rejected identically with
no differential response — the block is then likely enforced downstream of the WAF,
not by it [sqli.bypass.waf_normalization_encoding]. A 200 with no attacker-chosen
data is not a bypass.

### E7 — MSSQL, MS Access — dialect-specific transitions
**MS Access:** extraction is gated on naming a real column such as `username`, so
the guess-and-check step comes before any value can be pulled out
[sqli.prerequisite.ht_imagine_that_you_have_sql_injectio]; `TOP`/`LAST` then cap or
reverse the result set so a table is paged rather than dumped
[sqli.technique.ht_top_accepts_as_argument_an_integer]; and pointing the database
reference at a local file yields an invalid-format error only when the file is
really there, making file enumeration an error-comparison exercise
[sqli.test.ht_if_the_specified_file_exists_ms_a].
**Blockers:** reading a value out of MS Access with no valid column name in the
injected query, or a fabricated column name returning data, refutes the ordering
[sqli.prerequisite.ht_imagine_that_you_have_sql_injectio]; `TOP`/`LAST` rejected as
syntax, or accepted but leaving rows unchanged, refutes their use as row-selection
controls [sqli.technique.ht_top_accepts_as_argument_an_integer]; the invalid-format
error appearing identically for non-existent names refutes the existence oracle
[sqli.test.ht_if_the_specified_file_exists_ms_a].

### E8 — Search-grammar transition
**Transition:** in a full-text search parameter the attacker-controlled text is a
query language, not a string literal, so the injection point is the operator's own
grammar [sqli.validation.a_search_box_taking_a_fts_query_string_is_not_covered_by_the_quote_payload];
in a boolean-mode `MATCH ... AGAINST` search box the term is concatenated inside
the quoted argument, so probe the quote and the boolean-mode operators rather than
a plain WHERE value [sqli.variant.ht_example_query_built_by_the_backend].
**Blocker:** a parameter that can neither break out of the quotes nor change the
boolean-mode search is refuted as an injection point; and the grammar surface must
be shown reaching a SQL-executing construct — an FTS expression a trigger, a view
or an auxiliary function expands into further SQL — because the mere existence of a
rich query language in a search box is not a finding
[sqli.validation.a_search_box_taking_a_fts_query_string_is_not_covered_by_the_quote_payload].

---

## Chain hygiene rules

1. **Measure before you chain.** Steps 1→2→3 are ordered because an unmeasured
   oracle makes every later step unfalsifiable
   [sqli.validation.single_variable_differential].
2. **Name the blocker when you stop.** Each transition above has a corpus-named
   blocker; an unmotivated stop is indistinguishable from an untried step.
3. **Do not chain across a trust decision you have not tested.** A parameterised
   call site whose error echoes your input is disclosure, not a foothold
   [sqli.fp_rule.a_parameterized_query_whose_comment_appears_in_an_error_is_not_injection]
   — and parameterisation is per call site, so a safe read path does not certify
   an unsafe report, export or search path on the same endpoint.
4. **Bound the destination by grants.** The chain's goal is data_disclosure; its
   ceiling is whatever `fn_my_permissions` and the DMV read-back say the session
   actually holds [sqli.technique.ht_select_from_fn_my_permissions_nu]
   [sqli.test.ht_the_currently_executing_sql_query].