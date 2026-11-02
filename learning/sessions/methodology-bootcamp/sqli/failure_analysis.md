# failure_analysis — a real failure mode of this class, diagnosed

## The failure

**Expected:** `GET /search?q=test'` returns HTTP 500 with the body containing
`You have an error in your SQL syntax`. I have a database-specific error string
naming SQL syntax, on a search parameter, so the quote reached a parser: SQL
injection confirmed, error-based, context is inside a string literal.

**Actual:** after an hour of payload work, the injection could not be converted
into a differential at all. The boolean twins returned identical bodies. The UNION
attempts returned nothing new. The "error" turned out to be reproducible from the
*home page*.

**Wrong assumption:** *a driver-flavoured error string on a request containing a
quote is itself the injection evidence.* I treated the error as the signal instead
of as a symptom, and I never captured the control request.

**Root cause, named precisely:** the unquoted control request **also** returned
HTTP 500. The error is raised *before* the query is built — from a missing query
parameter or a template error — so the quote never reached a parser at all. The
word "SQL" in a 500 body is not attribution; it is a string in a page.

## Why this failure is the modal failure of the class

It is cheap to make and expensive to detect, because the wrong path *feels*
productive: you are reading database wording, so you believe you are close. Every
other field-observed false positive in this class has the same shape — a real
observation that is systematically misattributed:

- ordering that changed, on an endpoint whose baseline ordering was not
  deterministic;
- a UNION response that changed at *every* column count, where the injected
  literals were already in the template;
- a version string that the server emits in the headers of every page;
- a comment terminator whose effect was identical to an empty value;
- a WAF "bypass" returning 200 with no injected data in it.

In every case the observation is genuine and the inference is wrong. The class's
high false-positive count is not because testers are careless; it is because the
signals are structurally confounded — normalisation, caching, template rendering,
server disclosure and network jitter all imitate a differential.

## What the corpus says the rule should have been

- A 500 on a metacharacter proves nothing until the same request without the
  metacharacter returns 200; **always capture an unquoted control response before
  attributing an error to injection** [sqli.fp_rule.generic_500_not_sqli]
  [sqli.test.a_500_or_generic_error_page_triggered_by_malform].
- A SQLi finding is only validated when **one variable changes** and the response
  difference is **reproducible and explainable by query logic**. If the difference
  is non-deterministic, cache- or session-driven, or does not reverse when the
  condition is inverted, it is not a validated SQLi
  [sqli.validation.single_variable_differential].
- Ordering is only a valid injection signal when a repeated identical baseline
  request is byte-identical.
- Timing-based injection requires repeated alternating samples showing the delay
  tracks the payload; one slow response against a network you have not baselined is
  a network event [sqli.test.ht_therefore_a_good_way_to_discover].

## Next tests, in order — what I would run instead

1. **Control request, full body diff.** `q=test`, `q=test'`, `q=test''`. Compare
   bodies, not status codes. Cost: 2 requests. This single step decides the case.
2. **Type-mismatch negative control.** A string where a number is expected. If it
   produces the identical 500 with no SQL-specific text, the 500 is an
   input-validation artefact [sqli.fp_rule.generic_500_not_sqli].
3. **Parser-naming test.** A parser-specific error must name the construct that
   failed. A byte-identical validation string for any invalid value indicates a
   type check [sqli.fp_rule.generic_500_not_sqli].
4. **Attribution.** Replay the true/false pair three times with all other
   parameters identical, diffing status, headers and body
   [sqli.test.a_sqli_finding_is_only_validated_when_one_variab]. A differential
   found while several parameters vary at once is attributable to none of them
   [sqli.validation.one_variable_at_a_time_is_the_only_way_the_differential_is_attributable]
   — unless an out-of-band callback or an endpoint exposing the generated SQL settles
   it.
5. **Grep the baseline for my own literals** before claiming a UNION or an
   exfiltration. A value already present in the template, or a value the server
   already emits everywhere, is rendering or disclosure — a different finding with
   a different fix.
6. **Empty-value control** before attributing anything to a comment marker.
7. **If every in-band probe is null**, and the endpoint enqueues work, go to OAST:
   absence of in-band signal does not mean absence of SQLi
   [sqli.signal.async_query_oast_signal]. Only a null callback *and* conditional
   delays within baseline jitter support a genuine negative.

## The gap this exposes, and the durable fix

The gap is not knowledge of payloads — I knew enough to build the boolean twins.
The gap is that **the first request in my plan was a payload, not a baseline.** The
corpus states this as a prerequisite, not a nicety: the parameterization baseline
must be established before quote errors are read as SQLi
[sqli.prerequisite.parameterization_baseline], and every candidate field's
true/false pair must be replayed three times with all other parameters identical
[sqli.test.a_sqli_finding_is_only_validated_when_one_variab].

Durable rule: **in this class, a control request is not a step in the plan — it is
a precondition for the plan.** Capture the unquoted, empty and type-mismatch
baselines before the first payload, and the four confounded signals (normalisation,
caching, template rendering, server disclosure) stop being able to impersonate a
differential. Cost: three requests per field. What it prevents: an entire
investigation built on a 500 whose cause was a missing parameter.

## Second-order failure worth naming

The follow-on mistake would have been filing this as "SQL injection, error-based,
information disclosure" — an impact claim with no attributable cause. The corpus
separates those explicitly: a verbose database error that echoes the constructed
query turns blind injection visible and independently confirms the injection
point's context [sqli.validation.verbose_error_confirmation], but if the app
returns a generic custom error page with no driver text and no reflected query
fragment, error-based confirmation is simply **unavailable**. Availability of a
signal is not evidence that the signal fired.