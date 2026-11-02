# failure_analysis — a real failure mode of this class

## The failure

**Expected.** `GET /download?name=../../../../etc/passwd` on a parameterised
download handler. I expected either file content (finding) or a clean refusal
(control). I got a **403 with a page body that contained my filename**, and the
surrounding evidence looked encouraging: the status differed from the
legitimate-name baseline, the body was non-empty, and the string I sent appeared
in it. That is three signals pointing the same way.

**Actual.** The 403 was a **routing/authorisation decision made by the
application layer**, and the filename in the body was my own input echoed into
an error template or a custom 404. No file outside the served tree was read. On
the next endpoint — a different one, parameterised the same way — the identical
payload returned **200 with an HTML error page**, which is the same failure in a
more seductive costume: 200 is a success status, and the body was non-empty, and
the payload's basename was visible in it.

**The wrong assumption.** I assumed **status-code differential implies
file-layer reachability**. It does not. A 403, a 400, a 404 and even a 200 all
describe whether *the application* served the request, not whether the *operating
system* opened a path. I had also conflated two different observables — "the
response changed" and "a file was read" — and treated the first as evidence for
the second. Neither is the right discriminator.

The corpus states this as a false-positive rule in its own terms: a traversal
payload that returns the same content as the baseline is not a traversal
[path_traversal.fprule.normalized_payload_returns_identical_content], and the
complementary error is worse — content that *differs* from baseline is equally
not a read unless the difference is **file content**. A filename echoed in an
error page, a stack trace, a web-root directory listing, or a session cookie
dropped on a custom 404 reads nothing outside the intended root
[path_traversal.evidence.a_filename_you_supplied_appearing_in_a_trave].

## Why the failure is this class's signature

The three claims in this class are distinguished by *which layer* produced the
response, and my test design collapsed them:

1. I never ran literal and percent-encoded forms side by side, so I could not
   tell a real allowlist bypass from a payload that was simply blocked — the
   bypass exists only where the filter compares the raw request path while the
   backend normalises percent-encoded octets before resolving the file
   [path_traversal.bypass.percent_encoding_normalization_defeats_allowlist], and
   the request/response comparison that decides it is
   [path_traversal.test.a_traversal_allowlist_is_bypassed_when_the_filte].
2. I never ran the disk-only probe, so I could not exclude a classpath fallback
   answering in place of the filesystem branch
   [path_traversal.validation.disk_only_file_probe].
3. I hashed nothing, so "the response changed" could not be refined into "the
   content changed" — the length-only decoy would have survived my test.

## The next test, in order

1. **Baseline first, always.** Legitimate name and nonexistent name: status,
   length, body hash. Fixes the ambiguous-differential problem permanently and
   costs one request.
2. **Hash, don't diff by eye.** A length change with identical content is a
   decoy response; only a content change counts
   [path_traversal.fprule.normalized_payload_returns_identical_content].
3. **Literal vs encoded, same payload, side by side.** Refutation of the bypass
   claim is the encoded form being rejected identically to the literal form, or
   the backend serving neither variant outside the directory
   [path_traversal.bypass.percent_encoding_normalization_defeats_allowlist].
4. **Disk-only target.** If a disk-only file 404s while a bundled asset 200s,
   the read came from the classpath and the finding is not actionable on that
   host [path_traversal.validation.disk_only_file_probe].
5. **Prove server-side normalisation before claiming a control.** The stripped
   dot components in my response path were ambiguous: consistent with
   normalisation by the client, the server, the framework, or the terminal, and
   therefore neither evidence of a filter nor proof that traversal failed
   [path_traversal.fp_rule.a_dot_component_removed_from_the_response_path_is_not_evidence_of_a_filter].
   The honest verdict without an origin-side artefact is "unobservable", not
   "blocked".
6. **Probe each endpoint on its own evidence.** I nearly carried the "static
   prefix is clean" result across to the parameterised handler; behaviour on a
   statically served prefix says nothing about a parameterised download handler
   and the reverse holds too, because the two are served by different code
   entirely [path_traversal.validation.a_statically_served_prefix_is_not_the_same_as_a_scoped_file_handler].

## Generalisable lesson

For this class the discriminating observable is never the status code. It is
**file content in the response body that the same route cannot otherwise
produce**. Everything else — status, length, an echoed filename, a stack trace,
a directory listing — is generated by the application and can be produced by an
application that never called `open()` at all. And the sink itself must be
present in *this* request path: traversal requires a request-controlled string
concatenated into a filesystem path with no canonicalisation and no prefix check
[path_traversal.prerequisite.user_controlled_path_component].
