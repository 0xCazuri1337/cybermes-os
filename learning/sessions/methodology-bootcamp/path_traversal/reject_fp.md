# reject_fp — the misleading cases and the disproof test for each

This class has the cleanest false-positive shape in the corpus, because the
misleading artefact and the real one look identical at the status-code level.
Each case below names the trap and the test that kills it.

## FP-1 — "the app blocked my traversal" (routing decision, not a filter)

**The trap.** A 403/404/400 that looks like a blocked traversal, when the app
never passed the string to a filesystem call at all. It was rejected by a route
handler, or the request never matched the route.

**Disproof test.** Establish that the input reached an OS-level open by showing
**file content in the response body** that the route cannot otherwise produce.
A status code cannot do this. If the body carries nothing but app markup, the
filesystem layer was never the producer
[path_traversal.prerequisite.user_controlled_path_component].

**Where the trap bites hardest.** A 200 with an HTML error page — the app
rendered a template successfully, and 200 is the render status, not a read
status. Same conclusion: no file content, no finding.

## FP-2 — identical content (normalisation or cache)

**The trap.** A traversal payload that returns the same content as the baseline
request is not a traversal; the path was normalised or rejected before the file
layer [path_traversal.fprule.normalized_payload_returns_identical_content].

**Disproof test (for the report).** Hash the baseline and the traversal bodies.
Identical hashes → discard. Length-only differences are the decoy variant and
fail the same test: normalise for transfer-encoding and hash again.

**Disproof test (the carve-out).** The finding is real if a CDN or reverse proxy
caches by URL prefix and ignores your dot segments, and a cache-busting query
parameter still returns the outside-directory file — then the traversal is real
and the cache was the only thing hiding it
[path_traversal.fprule.normalized_payload_returns_identical_content].

## FP-3 — stripped dot components in the reflected path

**The trap.** A response whose echoed path has `./` and `../` components stripped
is consistent with normalisation by the client, the server, the framework, or
the terminal. It does not by itself evidence an input filter, and it is not
proof the traversal failed either
[path_traversal.fp_rule.a_dot_component_removed_from_the_response_path_is_not_evidence_of_a_filter].

**Disproof test.** Make the normalisation provably server-side and effective:
show the request as received by the origin — a request log entry, or a reflected
value that only the server could have computed — and show the traversal payload
in that same form still failing. That is a genuine control.

**Two more refutations of the trap itself.** Where the client is not in the
picture — a raw-socket request, a binary body carrying the path, a file upload
field — evidence from that channel is not subject to this ambiguity at all. And
a genuinely successful read is a finding regardless of how many stages normalised
the string on the way in, because the read happened
[path_traversal.fp_rule.a_dot_component_removed_from_the_response_path_is_not_evidence_of_a_filter].

## FP-4 — the encoded form was blocked, so there is no bypass

**The trap.** Concluding "filter works" from one representation. An LFI filter
that strips `../` is bypassed by re-encoding as `%2e%2e%2f`, because the filter
matches the decoded form the request never carries
[path_traversal.bypass.a_local_file_inclusion_filter_that_strips_is_bypasse].

**Disproof test.** Send the identical payload twice — literal `../` and
percent-encoded octets for the dot and slash — and compare response body and
status against a baseline for the same file outside the served directory
[path_traversal.test.a_traversal_allowlist_is_bypassed_when_the_filte].

**The genuine refutation.** When the server percent-decodes the parameter before
filtering, the encoded sequence is normalised to `../` and rejected, and the
bypass does not exist
[path_traversal.bypass.a_local_file_inclusion_filter_that_strips_is_bypasse].

## FP-5 — "prefix check means it is confined"

**The trap.** Treating a base-directory prefix check as containment.

**Disproof test.** Demonstrate a planted symlink resolving outside the tree, with
the write shown. String-prefix confinement does not contain a symbolic link,
because resolving the link replaces the component and discards all preceding
parts of the path when the link body is absolute
[path_traversal.bypass.a_symlink_inside_a_trusted_directory_escapes_it_with_no_traversal_string].

**Genuine refutations.** The open itself being confined below the base by an
openat-style call relative to a directory file descriptor for the base directory;
or a chroot, container mount namespace, or filesystem sandbox that makes the
out-of-tree target unreadable — the symlink exists but reaches nothing. And an
attacker-controlled directory that is not writable gives no place to plant the
link, so a report without a demonstrated link creation is a hypothesis.

## FP-6 — the classpath fallback

**The trap.** A bundled asset such as a properties template returns 200 through
a classpath fallback even when the filesystem branch is unreachable — exactly
the false positive that makes a controller look exploitable when it is not
[path_traversal.test.confirm_an_arbitrary_file_read_by_fetching_a_fil].

**Disproof test.** Fetch a file that exists only on disk, not a resource bundled
in the application's classpath or JAR
[path_traversal.validation.disk_only_file_probe]. If a file that exists only on
disk returns 404 or an error while the bundled asset returns 200, the read comes
from the classpath and the finding is not actionable on that host.

## FP-7 — "the static prefix is clean, so downloads are safe"

**The trap.** Transferring a conclusion between endpoints.

**Disproof test.** Probe the parameterised handler itself. Behaviour on a
statically served prefix says nothing about a parameterised download handler, and
the reverse holds too — each endpoint needs its own probe because the two are
served by different code entirely
[path_traversal.validation.a_statically_served_prefix_is_not_the_same_as_a_scoped_file_handler].

**Genuine refutation of the trap.** When both surfaces are served by the same
confined component — a single static-file handler in front of every asset class,
or a CDN/object-store gateway applying one prefix rule to all buckets — the
static route's behaviour *is* informative. It also fails when the static surface
is served by the web server itself from a document root, since the server's own
path handling is a separate implementation and equally consistent across every
alias it serves. And a specific finding on either endpoint still stands on its
own evidence.

## FP-8 — the read succeeded but proved nothing

**The trap.** A 200 on a file the requester was always entitled to read. The file
came from inside the served tree; routing worked; nothing was escaped.

**Disproof test.** Show the returned bytes come from *outside* the served tree —
an absolute system path, or a `../` that lands above the document root
[path_traversal.technique.including_an_attacker_influenced_path_lets_an_absolute_pat].
Compare against a legitimate-name baseline on the same route; if the legitimate
name returns the same file, the parameter never left the allowed set.

## FP-9 — the directory listing counted as a read

**The trap.** Treating a listing as file content.

**Disproof test.** Decide whether the response enumerates entries or returns file
content. On Java targets a traversal request aimed at a directory frequently comes
back as a directory listing
[path_traversal.signal.ht_java_list_directories_it_looks_li]. Refuted as evidence
if the listing appears for a path containing no traversal payload at all, or if
the response for a nonexistent path is identical to the response for the
traversal path. And a listing is only a map — the real file surface is reached by
pushing the discovered folder name through the sink and seeing whether it
resolves to server-side files
[path_traversal.technique.ht_discovered_folders_can_be_further].

## FP-10 — an "exploit" that never exploits

**The trap.** Claiming LFI→RCE from a read.

**Disproof test.** Show the included content *executing*. An LFI sink is an
execution primitive, so the moment it can be pointed at a tester-controlled file
the included content runs with the web server's privileges
[path_traversal.impact.ht_in_a_local_file_inclusion_if_you]. Refuted if the sink
returns the uploaded file's content as inert data without executing — the
include was downgraded to a read, or the extension is never interpreted.

Two further `fp_rule` rows exist in this class whose validation state is not
promoted. They are deliberately **not** cited as knowledge anywhere in this
artifact set, because an unpromoted claim is a lead, not a rule. Their subject
matter — the fixed-placeholder-body carve-out and the trusted-path-parameter
carve-out — is reachable through FP-1 and FP-6 above, which are promoted, so no
discrimination is lost by leaving them uncited.
