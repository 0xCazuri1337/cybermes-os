# hypothesize — falsifiable hypotheses, each keyed to an observation

Each hypothesis names the signal I actually saw and the observation that would
refute it. A claim is not a hypothesis; a claim has no refutation condition.

## H1 — the encoded form reaches the file layer where the literal form does not

**Signal observed:** literal `../../etc/passwd` returned 400 or a custom error
page, while `/%2e%2e/%2e%2e/etc/passwd` returned something structurally
different.

**Hypothesis:** the filter matches the raw request value while the backend
normalises percent-encoded octets before resolving the file
[path_traversal.bypass.percent_encoding_normalization_defeats_allowlist].

**Refuted by:** the encoded form being rejected identically to the literal form,
or the backend serving neither variant outside the intended directory. Either
way there is no allowlist bypass and the payload is simply blocked.

## H2 — the input reaches a filesystem call at all

**Signal observed:** any non-identical response to a traversal payload.

**Hypothesis:** a request-controlled string is concatenated into a filesystem
path with no canonicalisation and no prefix check
[path_traversal.prerequisite.user_controlled_path_component].

**Refuted by:** the response being identical for a traversal payload and for a
nonexistent filename, or the value being canonicalised and stripped of parent
segments before the open. Identical-to-baseline is the killer observation, and it
is the same observation that kills the report
[path_traversal.fprule.normalized_payload_returns_identical_content].

## H3 — the read came from the classpath, not the disk

**Signal observed:** the traversal returned 200 with plausible-looking content.

**Hypothesis:** no — the live hypothesis must be the *suspicion* that a bundled
asset resolved through a classpath fallback even though the filesystem branch
was unreachable. That fallback is exactly what makes a controller look
exploitable when it is not
[path_traversal.test.confirm_an_arbitrary_file_read_by_fetching_a_fil].

**Refuted by:** a file that exists only on disk returning 404 or an error while
the bundled asset returns 200 — the read is from the classpath and the finding is
not actionable on that host
[path_traversal.validation.disk_only_file_probe].

## H4 — the allow-list is directory-scoped, so absolute paths win where `../` fails

**Signal observed:** a filter that rejects traversal sequences but returns
different responses for different leading paths.

**Hypothesis:** including an attacker-influenced path lets an absolute path such
as `/etc/passwd` or the Windows hosts file be read with no traversal sequence at
all [path_traversal.technique.including_an_attacker_influenced_path_lets_an_absolute_pat].

**Refuted by:** the application validating the path against an allow-list of
permitted directories rather than rejecting traversal sequences, in which case
an absolute path outside the allow-list is refused. Note this refutation is
*identical in form* to the hypothesis — the distinction is empirical, so the test
must be run rather than assumed.

## H5 — the confinement is a string prefix, so a planted symlink escapes

**Signal observed:** an upload or user-writable directory inside the served tree,
plus a base-directory check that is plausibly textual.

**Hypothesis:** confining the resolved path under a base directory by string
prefix does not contain a symbolic link, because resolving the link replaces the
component and discards all preceding parts of the path when the link body is
absolute
[path_traversal.bypass.a_symlink_inside_a_trusted_directory_escapes_it_with_no_traversal_string].

**Refuted by any one of:** the open itself being confined below the base via an
openat-style call relative to a directory file descriptor, so kernel component
resolution cannot climb above the descriptor; a chroot, container mount
namespace, or filesystem sandbox that makes the out-of-tree target unreadable;
or no demonstrated link creation — an attacker-controlled directory that is not
writable gives no place to plant the link, and without the write the report is a
hypothesis, not a finding.

## H6 — the LFI sink executes, it does not merely read

**Signal observed:** a PHP include parameter reachable by an unauthenticated
request.

**Hypothesis:** an LFI sink is an execution primitive rather than a read
primitive, so the moment it can be pointed at a tester-controlled file the
included content runs with the web server's privileges
[path_traversal.impact.ht_in_a_local_file_inclusion_if_you].

**Refuted by:** the sink returning the uploaded file's content as inert data
without executing — for example because the include is downgraded to a read, or
the file's extension is never interpreted.

## H7 — the LFI-to-execution chain is gated on three conditions holding together

**Signal observed:** a reachable include parameter on a host where uploads are
also possible.

**Hypothesis:** the nested-remote-fetch chain needs `allow_url_fopen=On`, the
LFI sink must be permitted to include from the writable temp directory, and a
path-disclosure primitive must reveal the live temp file name
[path_traversal.prerequisite.ht_although_the_compression_wrapper_i].

**Refuted by:** the chain still reaching execution on a host with
`allow_url_fopen=Off`, or on a host with no path-disclosure primitive, or where
the sink refuses paths inside the temp directory.

## H8 — the echoed path is evidence of nothing

**Signal observed:** the response contains my filename but no file content.

**Hypothesis (this one is a null hypothesis and should win):** the response path
having `./` and `../` components stripped is consistent with normalisation by the
client, the server, the framework, or the terminal
[path_traversal.fp_rule.a_dot_component_removed_from_the_response_path_is_not_evidence_of_a_filter].

**Refuted by:** proving the normalisation is server-side and effective — showing
the request as received by the origin via a request log or a reflected value
only the server could have computed, with the traversal payload in that same
form still failing. Also refuted by evidence gathered over a channel with no
browser in it (raw socket, binary body, upload field), or by a genuinely
successful read, which is a finding regardless of how many stages normalised the
string on the way in.
