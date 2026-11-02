# generalize — common, uncommon and defensive variants

## Common variants (expect these first)

| variant | shape | distinguishing observation |
|---|---|---|
| relative traversal | `../` sequences or `%2e%2e%2f` in a name/filename/path parameter | literal vs encoded differ in verdict [path_traversal.bypass.percent_encoding_normalization_defeats_allowlist] |
| absolute-path read | `/etc/passwd`, `C:\Windows\System32\drivers\etc\hosts` with no dot segments | succeeds where the traversal-sequence blocklist fails [path_traversal.technique.including_an_attacker_influenced_path_lets_an_absolute_pat] |
| source disclosure via wrapper | `php://filter/read=convert.base64-encode/resource=<file>` | response is base64 of source, not source [path_traversal.technique.php_filter_with_a_base64_encode_conversion_stream_reads] |
| LFI → execution | include sink pointed at a tester-controlled file | included content runs with web-server privileges [path_traversal.impact.ht_in_a_local_file_inclusion_if_you] |
| encoded-filter bypass | filter strips `../` from the raw value | `%2e%2e%2f` walks past it [path_traversal.bypass.a_local_file_inclusion_filter_that_strips_is_bypasse] |

## Uncommon variants (each is a different mechanism, not a payload tweak)

**Symlink escape with no traversal string.** Confinement by string prefix does
not contain a symbolic link, because resolving the link replaces the component
and discards all preceding parts of the path when the link body is absolute
[path_traversal.bypass.a_symlink_inside_a_trusted_directory_escapes_it_with_no_traversal_string].
The distinguishing feature is that the request contains *nothing* suspicious. This
is the variant that survives a "we block `../`" defence completely, and it
requires a demonstrated write into a served directory — without the write it
stays a hypothesis.

**Classpath/JAR fallback.** The filesystem branch is unreachable and a bundled
asset answers instead. A controller that looks exploitable and is not
[path_traversal.test.confirm_an_arbitrary_file_read_by_fetching_a_fil]; the
discipline that kills it is the disk-only probe
[path_traversal.validation.disk_only_file_probe].

**Directory-as-target.** On Java targets the request lands on a directory and
returns a listing [path_traversal.signal.ht_java_list_directories_it_looks_li].
The listing is reconnaissance: the real surface is reached by pushing the
discovered folder name through the sink
[path_traversal.technique.ht_discovered_folders_can_be_further].

**Temp-file / `/proc` family (LFI → RCE without upload naming).** The in-flight
request body is reachable through the process file-descriptor table, so once
`/proc` walking yields fd paths, feeding those paths into the LFI parameter
includes the buffered request bytes directly
[path_traversal.technique.ht_feed_the_discovered_proc_pid_fd]. Two timing
observables decide it: whether `/proc/<pid>/cmdline` reads at all
[path_traversal.prerequisite.ht_fetch_proc_pid_cmdline_over_the], and whether the
path disclosure actually reached the tester through output buffering
[path_traversal.signal.ht_php_finishes_copying_closes_the_s].

**Search-budget escalation for an unpredictable temp filename.** Hold an LFI
request open indefinitely and brute-force candidate names inside that window
[path_traversal.technique.ht_if_we_manage_to_upload_files_and_m]; then, once
confirmed in the lab, scatter thousands of timed-out uploads
[path_traversal.technique.ht_once_that_behavior_is_confirmed_in]; then saturate
workers concurrently so at least one buffered body file survives
[path_traversal.technique.ht_use_multiple_processes_to_flood_wo]. Each has a
stated refutation: the connection aborting before the candidate space is covered;
cleanup deleting every candidate before the include lands; added load recycling
workers so file lifetime *shrinks*.

**Nested compression wrapper.** When the LFI targets the temp backing file by its
own local pathname, the inclusion consumes the raw request body *as written
before* the decompression wrapper runs, so a payload only valid after
decompression will not execute
[path_traversal.technique.ht_the_later_lfi_includes_the_tempora]. Refuted if the
same inclusion executes a payload that is only well-formed after decompression.

## Defensive variants — the controls, and where each one leaks

| control | leaks because | corpus anchor |
|---|---|---|
| strip `../` from the input | matching the decoded form the request never carries | [path_traversal.bypass.a_local_file_inclusion_filter_that_strips_is_bypasse] |
| allow-list on the raw request path | backend normalises percent-encoded octets before resolving | [path_traversal.bypass.percent_encoding_normalization_defeats_allowlist] |
| allow-list of permitted directories | an attacker-influenced absolute path may still be readable — and the allow-list shape is what the absolute-path technique needs | [path_traversal.technique.including_an_attacker_influenced_path_lets_an_absolute_pat] |
| string-prefix base-directory check | does not contain a symlink with an absolute body | [path_traversal.bypass.a_symlink_inside_a_trusted_directory_escapes_it_with_no_traversal_string] |
| `open_basedir` / sandbox / chroot / mount namespace | not a bypass — makes the out-of-tree target unreadable, so the link reaches nothing | [path_traversal.bypass.a_symlink_inside_a_trusted_directory_escapes_it_with_no_traversal_string] |
| openat-style confinement relative to a base directory fd | the real fix for the symlink class; kernel component resolution cannot climb above the descriptor | [path_traversal.bypass.a_symlink_inside_a_trusted_directory_escapes_it_with_no_traversal_string] |
| ini posture on a PHP host | `allow_url_include` and `allow_url_fopen` have different defaults; the sink must be classified by which is actually on before it is called exploitable | [path_traversal.prerequisite.ht_in_php_url_aware_inclusion_is_dis] |
| wrapper-scheme allow-list | a filter excluding any path containing a stream wrapper defeats `php://filter` entirely | [path_traversal.technique.php_filter_with_a_base64_encode_conversion_stream_reads] |
| canonicalisation that strips parent segments **before** the open | a genuinely correct control: no traversal sink remains, because the prerequisite requires a request-controlled string concatenated into a path with no canonicalisation and no prefix check | [path_traversal.prerequisite.user_controlled_path_component] |

## The variant that generalises furthest

Every row above is one instance of a single rule: **a control is only as strong
as the representation it validates**. Percent-encoding, backslash vs forward
slash, double-encoding, and Unicode normalisation are all the same defect at
different layers. Only the percent-encoding forms are carried as promoted
knowledge in this class
[path_traversal.bypass.percent_encoding_normalization_defeats_allowlist],
[path_traversal.bypass.a_local_file_inclusion_filter_that_strips_is_bypasse].
The rest are hypotheses to sweep, not conclusions to report.
