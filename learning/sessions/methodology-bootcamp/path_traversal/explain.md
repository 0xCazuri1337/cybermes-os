# explain — path_traversal: the chain and the exact invariant that fails

The class is not "a filename with `../` in it". It is a trust decision about a
*resolved* path that is made on the *unresolved* string. The invariant that
fails is:

> every component that contributes to the final path must be known to the
> validator AND to the consumer, in the same representation, at the same moment.

When a filter inspects one representation and the filesystem resolves another,
that invariant is broken and the filter's verdict is irrelevant. That is the
single mechanism underneath every confirmed instance of this class.

## The seven-link chain

1. **attacker input** — a request-controlled string reaches a path-building
   site. Traversal requires that string be concatenated into a filesystem path
   with no canonicalisation and no prefix check
   [path_traversal.prerequisite.user_controlled_path_component]. A known-vulnerable
   version number is not a substitute for that condition; the sink must be
   present in *this* request path.

2. **parser** — the HTTP layer (or a framework layer) splits the request target
   or parameter into path components. This is where percent-encoding is
   decoded, and the decode point relative to the filter is what decides whether
   encoding is a bypass or a no-op.

3. **normalisation** — some component collapses `.` and `..`. Normalisation may
   occur in the client, a proxy, the framework, the server, or the terminal
   [path_traversal.fp_rule.a_dot_component_removed_from_the_response_path_is_not_evidence_of_a_filter].
   That ambiguity is precisely why a stripped path in a reflected value proves
   nothing on its own.

4. **validation** — an allowlist or blocklist compares the string. Two distinct
   failures live here:
   - the filter compares the *raw* request value while the backend normalises
     percent-encoded octets before resolving the file
     [path_traversal.bypass.percent_encoding_normalization_defeats_allowlist];
   - an LFI filter that strips `../` is matched against the decoded form the
     request never actually carries, so re-encoding as `%2e%2e%2f` walks past it
     [path_traversal.bypass.a_local_file_inclusion_filter_that_strips_is_bypasse].

5. **trust decision** — the app concludes "this name is inside the base
   directory". The decision is unsound in three structurally different ways:
   - **absolute path**: an attacker-influenced path lets `/etc/passwd` or the
     Windows hosts file be read with no traversal sequence at all
     [path_traversal.technique.including_an_attacker_influenced_path_lets_an_absolute_pat];
   - **string prefix**: confining a resolved path by string prefix does not
     contain a symlink, because resolving an absolute link body replaces the
     component and discards the preceding path
     [path_traversal.bypass.a_symlink_inside_a_trusted_directory_escapes_it_with_no_traversal_string];
   - **wrapper scheme**: `php://filter/.../convert.base64-encode` makes the
     consumer read a PHP source file as base64, turning a read into source
     disclosure that exposes credentials inside the code
     [path_traversal.technique.php_filter_with_a_base64_encode_conversion_stream_reads].

6. **internal operation** — an OS-level open or an include. This step matters
   for the third claim: an LFI sink is an *execution* primitive, so the moment
   it can be pointed at a tester-controlled file the included content runs with
   the web server's privileges
   [path_traversal.impact.ht_in_a_local_file_inclusion_if_you].

7. **observable result** — bytes of a file outside the served tree in the
   response body. A filename echoed in an error page is not this result
   [path_traversal.evidence.a_filename_you_supplied_appearing_in_a_trave].

## The three distinct claims in this class

One technique does not cover the class. Selection is per-claim:

| claim | entry condition | payload family | confirming observable |
|---|---|---|---|
| absolute-path read | path built from attacker input, no traversal needed | `/etc/passwd`, `C:\Windows\System32\drivers\etc\hosts` | disk-only file bytes in body |
| encoded-traversal bypass | filter inspects raw value, backend decodes | `%2e%2e%2f`, double-encoding | file bytes in body where literal form was refused |
| `php://filter` base64 read | PHP include/require sink accepting a scheme | `php://filter/read=convert.base64-encode/resource=<file>` | base64 of source, decodes to PHP |

The middle claim is a *bypass of an existing control*, so its disproof is
different from the outer two: the encoded form must be rejected identically to
the literal form, or the backend must serve neither variant outside the
directory [path_traversal.bypass.percent_encoding_normalization_defeats_allowlist].

## Normalisation collisions the hunt must sweep for

Backslash-versus-forward-slash on Windows, doubled encoding, and Unicode
normalisation are all instances of the same defect — a validator and a consumer
disagreeing on the component separator or on the encoded octet set — but the
corpus does **not** carry a promoted item for backslash, double-encoding, or
Unicode forms. Treat them as hypotheses to exercise, not as knowledge: the
supported statement is only that percent-encoded octet normalisation is a real
defeat vector [path_traversal.bypass.percent_encoding_normalization_defeats_allowlist]
and that stripping `../` from the raw value is defeated by re-encoding
[path_traversal.bypass.a_local_file_inclusion_filter_that_strips_is_bypasse].
