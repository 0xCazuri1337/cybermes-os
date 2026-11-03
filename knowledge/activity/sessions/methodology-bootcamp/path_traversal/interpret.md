# interpret — result → meaning → next action

Hunts die in the ambiguous rows. They are written out first-class here.

| # | observed result | meaning | next action |
|---|---|---|---|
| 1 | 200 + file bytes whose content differs from anything the route serves with a legitimate name, and the target is disk-only | **Confirmed arbitrary file read.** The finding survives | Capture the request/response pair, price the impact, report [path_traversal.evidence.a_filename_you_supplied_appearing_in_a_trave] |
| 2 | Literal `../` refused, percent-encoded `%2e%2e%2f` accepted and returns file bytes | **Allowlist bypass.** The filter compared the raw request path while the backend normalised before resolving | Report as a filter-bypass with both requests side by side [path_traversal.bypass.percent_encoding_normalization_defeats_allowlist] |
| 3 | Literal and encoded forms refused identically, neither variant serves anything outside the directory | **No bypass.** The filter is on the decoded value; the payload is simply blocked | Stop here. Do not report [path_traversal.bypass.a_local_file_inclusion_filter_that_strips_is_bypasse] |
| 4 | Traversal payload returns **200 with an HTML error page** rather than file content | **Not a read.** The status is 200 because the app renders an error template; the body is application markup, not file bytes | Re-classify: hunt the disclosure of the template/page separately. Discard the traversal claim [path_traversal.evidence.a_filename_you_supplied_appearing_in_a_trave] |
| 5 | **Symlink resolves outside the tree** and the bytes come back | **Real escape, no traversal string.** String-prefix confinement does not contain a link whose body is absolute | Report, but *only* with the write demonstrated. If the directory was not writable, this is a hypothesis [path_traversal.bypass.a_symlink_inside_a_trusted_directory_escapes_it_with_no_traversal_string] |
| 6 | Symlink resolves outside the tree but the target is unreadable (chroot, mount namespace, sandbox) | The link exists and reaches nothing | Not a finding. Record as a contained condition [path_traversal.bypass.a_symlink_inside_a_trusted_directory_escapes_it_with_no_traversal_string] |
| 7 | Filter blocks the **literal `../`** but not its **encoded form** | The filter matches a decoded string the request never carries | Report as encoded-traversal bypass; pair with the two-request comparison [path_traversal.bypass.a_local_file_inclusion_filter_that_strips_is_bypasse] |
| 8 | Response differs in **LENGTH but not in CONTENT** from baseline (a decoy) | **Not a read.** Length moved; the bytes did not. Typical of an error page with a variable id, or gzip variance | Hash the bodies. If hashes match, discard [path_traversal.fprule.normalized_payload_returns_identical_content] |
| 9 | Response **identical to baseline** for the traversal payload | Not a traversal; the path was normalised or rejected before the file layer | Abandon this endpoint, unless a cache-busting query parameter still returns the outside-directory file — in which case the traversal is real and the cache was the only thing hiding it [path_traversal.fprule.normalized_payload_returns_identical_content] |
| 10 | Disk-only file 404s while a bundled classpath asset 200s | The read is from the classpath; the filesystem branch is unreachable | Discard as not actionable on this host [path_traversal.validation.disk_only_file_probe] |
| 11 | A bundled properties template 200s through a classpath fallback | The controller *looks* exploitable and is not | Discard [path_traversal.test.confirm_an_arbitrary_file_read_by_fetching_a_fil] |
| 12 | Response path has `./` and `../` components **stripped** | Ambiguous: normalisation by client, server, framework, or terminal. Not evidence of a filter, not proof of failure | Prove server-side reception (request log, or a reflected value only the server could compute) before claiming a control; a successful read is a finding anyway [path_traversal.fp_rule.a_dot_component_removed_from_the_response_path_is_not_evidence_of_a_filter] |
| 13 | Traversal aimed at a **directory** returns a **listing** of entries | On Java targets this is common. It is a *map*, not a result | Push the discovered folder name through the sink to see whether it resolves to server-side files. If the listing appears for a path with no traversal payload at all, it is not this class [path_traversal.signal.ht_java_list_directories_it_looks_li] [path_traversal.technique.ht_discovered_folders_can_be_further] |
| 14 | Your filename appears in an **error page, stack trace, web-root listing, or a session cookie** on a custom 404 | **The classic false positive.** No file outside the root was read | Discard the finding; nothing was read [path_traversal.evidence.a_filename_you_supplied_appearing_in_a_trave] |
| 15 | `/proc/<pid>/cmdline` reads come back empty or error while other known local files read fine | The inclusion cannot enumerate process metadata | Abandon the temp-file brute-force family [path_traversal.prerequisite.ht_fetch_proc_pid_cmdline_over_the] |
| 16 | `php://filter` returns no source text | Wrapper scheme disabled, or the allow-list excludes any path containing a stream wrapper | Report as plain file read only; drop the source-disclosure claim [path_traversal.technique.php_filter_with_a_base64_encode_conversion_stream_reads] |
| 17 | Static prefix behaves correctly, parameterised handler does not (or vice versa) | Expected — different code entirely. Each endpoint needs its own probe | Investigate the parameterised handler on its own evidence [path_traversal.validation.a_statically_served_prefix_is_not_the_same_as_a_scoped_file_handler] |
| 18 | Response identical in **every** case | Surrounding behaviour unobservable. No test applies, no report is possible | Stop; there is nothing to show [path_traversal.evidence.a_filename_you_supplied_appearing_in_a_trave] |

## The distinction that decides rows 3, 4, 8, 12 and 14

A 403/404/400 that *looks* like a blocked traversal may be a **routing
decision**: the app rejected the string in a route handler and never passed it
to a filesystem call. The proof that the input reached an OS-level `open()` is
not the status code — it is **file content in the response body that the route
cannot otherwise produce**. Row 4 is the sharpest case: a 200 whose body is an
HTML error page is a *rendered app response*, so the file layer was never the
producer. Conversely, a 400 that carries a stray stack-trace filename (row 14)
still is not a read.

Where you genuinely cannot tell whether the request reached the origin, the
audit trail is the tiebreaker: a request log entry or a reflected value only the
server could have computed settles server-side normalisation
[path_traversal.fp_rule.a_dot_component_removed_from_the_response_path_is_not_evidence_of_a_filter].
Without it, the honest verdict is "unobservable", not "blocked".
