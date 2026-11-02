# chain — prerequisites, transition, escalation, blocker

The corpus carries one chain for this class
(`chain.path_traversal.auto.01`, goal: establish, exercise and confirm on an
authorised target without relying on anyone else's data). It is a three-step
single-class chain, and every step names its blocker.

## Model

| ord | action | why it is needed | blocker at this step |
|---|---|---|---|
| 1 | **Observe.** Record the baseline: fetch the target with a legitimate name and with a nonexistent name; capture status, length and body hash. Disclosed path information in errors is a finding in its own right and is what makes a blind file read navigable | Without a recorded baseline you cannot show what changed, and later steps have nothing to compare against | The surface may be unobservable — identical-in-every-case or server-side-only behaviour leaves nothing to show. A blind channel blocks step 1 entirely |
| 2 | **Exercise.** Send the identical traversal payload twice, literal `../` and percent-encoded octets for the dot and slash, and compare body and status against a baseline for the same file outside the served directory | This is the transition step. Literal vs encoded is what separates "no sink" from "sink with a broken filter" | The filter may sit on the decoded value, in which case both forms are rejected identically and there is no bypass — the chain stops with a negative result, correctly [path_traversal.bypass.percent_encoding_normalization_defeats_allowlist] [path_traversal.test.a_traversal_allowlist_is_bypassed_when_the_filte] |
| 3 | **Confirm.** Show a request-controlled string is concatenated into a filesystem path with no canonicalisation and no prefix check; capture raw request/response, and reproduce with a second run | Traversal needs the sink in this request path — a known-vulnerable version alone is not enough. Confirmation is what separates a reportable finding from a theoretical one | Canonicalisation that strips parent segments before the open, or an identical response for the traversal payload and a nonexistent file. Either blocks the chain at the last step [path_traversal.prerequisite.user_controlled_path_component] |

## Escalation beyond the recorded chain

Step 3 ends at *arbitrary file read*. Three escalations are corpus-supported,
each with its own precondition and its own blocker.

### Escalation A — read → source disclosure

**Transition:** the sink accepts a scheme, so `php://filter` with a
base64-encode conversion stream reads a PHP source file as base64, turning a
file read into source disclosure that reveals credentials inside the code
[path_traversal.technique.php_filter_with_a_base64_encode_conversion_stream_reads].

**Blocker:** the wrapper scheme is disabled, or the allow-list excludes any path
containing a stream wrapper — then the request returns no source text.

### Escalation B — read → execution (LFI → RCE)

**Transition:** an LFI sink is an execution primitive rather than a read
primitive, so the moment it can be pointed at a file the tester controls the
included content runs with the web server's privileges
[path_traversal.impact.ht_in_a_local_file_inclusion_if_you].

**Blocker:** the sink returns the uploaded file's content as inert data without
executing — because the include was downgraded to a read, or the file's
extension is never interpreted.

### Escalation C — read → execution without predicting the temp filename

This is the multi-condition chain and the one most often built on a host that
cannot support it. All three conditions must hold together: the nested remote
fetch needs `allow_url_fopen=On`; the LFI sink must be permitted to include from
the writable temp directory; and a path-disclosure primitive must reveal the
live temp file name
[path_traversal.prerequisite.ht_although_the_compression_wrapper_i].

**Transition path:** walk `/proc/<pid>/cmdline` through the inclusion until
worker-process strings appear [path_traversal.prerequisite.ht_fetch_proc_pid_cmdline_over_the]
→ read fd paths → feed those paths into the LFI parameter, which includes the
buffered request bytes directly
[path_traversal.technique.ht_feed_the_discovered_proc_pid_fd] → hold the request
open to brute-force unpredictable temp names
[path_traversal.technique.ht_if_we_manage_to_upload_files_and_m] →
scatter thousands of timed-out uploads once confirmed in the lab
[path_traversal.technique.ht_once_that_behavior_is_confirmed_in] →
saturate workers so at least one buffered body file survives
[path_traversal.technique.ht_use_multiple_processes_to_flood_wo].

**Blockers at each hop:**
- `/proc/<pid>/cmdline` reads return empty or error while other known local
  files read fine → the inclusion cannot enumerate process metadata; the family
  is dead [path_traversal.prerequisite.ht_fetch_proc_pid_cmdline_over_the].
- fd paths return empty, non-executable content, or the descriptor's own target
  rather than the buffered body → hop 2 fails
  [path_traversal.technique.ht_feed_the_discovered_proc_pid_fd].
- the race is lost because the temp file was already unlinked by the time the
  inclusion ran. Two observables decide it: whether the path still resolves, and
  whether the path disclosure actually reached the tester through output
  buffering [path_traversal.signal.ht_php_finishes_copying_closes_the_s].
- the LFI targets the temp backing file by its own local pathname, so the
  inclusion consumes the raw request body *before* the decompression wrapper
  runs and a post-decompression-valid payload will not execute
  [path_traversal.technique.ht_the_later_lfi_includes_the_tempora].
- connection abort, cleanup, or worker recycling shrinking file lifetime
  [path_traversal.technique.ht_if_we_manage_to_upload_files_and_m],
  [path_traversal.technique.ht_once_that_behavior_is_confirmed_in],
  [path_traversal.technique.ht_use_multiple_processes_to_flood_wo].
- ini posture: remote inclusion is decided by ini switches with different
  defaults, so the sink must be classified by which of `allow_url_include` and
  `allow_url_fopen` is actually on before it is called exploitable
  [path_traversal.prerequisite.ht_in_php_url_aware_inclusion_is_dis].

## Chain discipline

Every step in this chain can terminate in a **negative** result that is still a
correct outcome. Identical-to-baseline, literal-and-encoded-both-refused, and
disk-only-404 are all legitimate stops
[path_traversal.fprule.normalized_payload_returns_identical_content],
[path_traversal.validation.disk_only_file_probe]. A chain that cannot end in
"no" is not a chain, it is a narrative.
