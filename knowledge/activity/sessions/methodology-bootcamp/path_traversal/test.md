# test — ordered plan, each step with expected information gain

Order is by information-per-request. Every early step can kill the hunt cheaply;
that is the whole point of putting them first.

## Step 0 — baseline (do not skip, costs 1 request)

Fetch the target file with a **legitimate** name, and fetch a name that does not
exist. Record status, byte length, and a hash of the body for each.

**Expected information gain:** establishes the two reference answers every later
comparison is scored against. Without it I cannot tell a length change from a
content change, and I cannot tell a 404 from a blocked traversal. Kills the
decoy-response ambiguity before it costs me a report.

## Step 1 — is there a traversal sink at all?

Send `../../../../etc/passwd` (and the Windows hosts file path on a Windows
host) as the literal form. Compare to baseline on **status and body content,
not length**.

**Expected information gain:** one binary answer. Identical to baseline →
abandon; the path was normalised or rejected before the file layer
[path_traversal.fprule.normalized_payload_returns_identical_content], and no
further step on this endpoint is worth a request. Structurally different → the
input reached a filesystem call [path_traversal.prerequisite.user_controlled_path_component].

## Step 2 — literal vs encoded, side by side

Send the **identical** payload twice: once with literal `../` sequences, once
with percent-encoded octets for the dot and slash (`%2e%2e%2f`). Compare
response body and status against the baseline request for the same file outside
the served directory [path_traversal.test.a_traversal_allowlist_is_bypassed_when_the_filte].

**Expected information gain:** distinguishes "no sink" from "sink with a broken
filter". Literal refused + encoded accepted is the allowlist-bypass claim
[path_traversal.bypass.percent_encoding_normalization_defeats_allowlist].
Both refused identically → the filter is on the decoded value and there is no
bypass [path_traversal.bypass.a_local_file_inclusion_filter_that_strips_is_bypasse].
This step is the only thing that separates those two worlds.

## Step 3 — absolute path, no traversal string

Request `/etc/passwd` and the hosts file directly, with no dot segments.

**Expected information gain:** tests the third payload family. A 200 here when
Step 1 failed means the control is a traversal-sequence blocklist rather than a
directory allow-list, and the report's mechanism changes
[path_traversal.technique.including_an_attacker_influenced_path_lets_an_absolute_pat].
A refusal confirms the allow-list shape, which is the stated refutation of that
technique.

## Step 4 — disk-only probe (the false-positive killer)

Request a file that exists only on disk, not a resource bundled in the
application's classpath or JAR.

**Expected information gain:** converts "content came back" into "arbitrary file
read on this host". A bundled asset such as a properties template returns 200
through a classpath fallback even when the filesystem branch is unreachable,
which is exactly the false positive that makes a controller look exploitable when
it is not [path_traversal.test.confirm_an_arbitrary_file_read_by_fetching_a_fil].
If a disk-only file 404s while the bundled asset 200s, the read is from the
classpath and the finding is not actionable on that host
[path_traversal.validation.disk_only_file_probe].

## Step 5 — wrapper scheme (PHP only, only on a confirmed include sink)

Request `php://filter/read=convert.base64-encode/resource=<target php file>`.

**Expected information gain:** upgrades the claim from file read to source
disclosure, which is where credentials live inside the code
[path_traversal.technique.php_filter_with_a_base64_encode_conversion_stream_reads].
Refuted when the wrapper scheme is disabled or the allow-list excludes any path
containing a stream wrapper — in which case no source text comes back.

## Step 6 — classification before exploitation is attempted

On a PHP include sink, read the ini posture before calling anything
exploitable: every candidate LFI sink must be classified by which of
`allow_url_include` and `allow_url_fopen` is actually on
[path_traversal.prerequisite.ht_in_php_url_aware_inclusion_is_dis].

**Expected information gain:** prevents the single largest waste in this class —
building a remote-inclusion chain on a host where the switch is off. One
information-gathering request saves an entire exploitation attempt.

## Step 7 — /proc reachability (only if the chain is being considered)

Before any temp-path brute force through an LFI sink, confirm the traversal
reaches `/proc` at all by walking `/proc/<pid>/cmdline` through the inclusion
until worker-process strings appear
[path_traversal.prerequisite.ht_fetch_proc_pid_cmdline_over_the].

**Expected information gain:** decides whether the whole
temp-file/`/proc/<pid>/fd` family is worth any effort, or whether the sink simply
cannot enumerate process metadata.

## Step 8 — symlink route (only if an upload surface was found in reconnaissance)

Plant a link inside the attacker-writable directory and request through it.

**Expected information gain:** tests a route that needs **no traversal string at
all** [path_traversal.bypass.a_symlink_inside_a_trusted_directory_escapes_it_with_no_traversal_string].
Refuted when the open is confined via an openat-style call relative to a base
directory descriptor, or under a chroot/container namespace/sandbox that makes
the target unreadable. And without a demonstrated link creation this step is a
hypothesis, not a finding.

## Step 9 — echo discrimination (do this before writing any report)

Re-read the successful response and ask whether the artefact is *file content*
or your own filename in an error page, stack trace, web-root directory listing,
or session cookie [path_traversal.evidence.a_filename_you_supplied_appearing_in_a_trave].

**Expected information gain:** the last gate before a false positive ships. A
filename echo is not a file read; the finding needs file CONTENT returned as the
response body.
