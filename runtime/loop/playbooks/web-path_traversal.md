# Hunt card — path_traversal

17 promoted technique/test items, each mapped to an executable procedure derived from its shape.

## path_traversal.bypass.percent_encoding_normalization_defeats_allowlist

**Claim.** A traversal allowlist is bypassed when the filter compares the raw request path but the backend normalizes percent-encoded octets before resolving the file.

**Procedure — item-authored procedure** (shapes: http_param_probe, filter_bypass, encoding_ladder, filesystem_sink)

1. Send the identical traversal payload twice, once with literal ../ sequences and once with percent-encoded octets for the dot and slash, and compare the response body and status against a baseline request for the same file outside the served directory.

**Record:** baseline response hash, attack response hash, status delta, body-length delta, reproductions

## path_traversal.test.a_traversal_allowlist_is_bypassed_when_the_filte

**Claim.** To decide this case, observe: Step: send the identical traversal payload twice, once with literal ../ sequences and once with percent-encoded octets for the dot and slash, and compare the response body and status against a baseline request for the same file outside the served directory.

**Procedure — item-authored procedure** (shapes: http_param_probe, encoding_ladder, filesystem_sink)

1. Send the identical traversal payload twice, once with literal ../ sequences and once with percent-encoded octets for the dot and slash, and compare the response body and status against a baseline request for the same file outside the served directory.

**Record:** baseline response hash, attack response hash, status delta, body-length delta, reproductions

## path_traversal.validation.a_statically_served_prefix_is_not_the_same_as_a_scoped_file_handler

**Claim.** Behaviour on a static-file prefix says nothing about a parameterised download handler, and the reverse holds too - each endpoint needs its own probe because the two are served by different code entirely.

**Procedure — Single-parameter differential probe** (shapes: http_param_probe, filesystem_sink, state_change)

1. Record the BASELINE: request the endpoint with a benign, known-good value for the parameter. Save the full response (status, length, body hash).
2. Change exactly ONE variable: set the parameter to the attack value. Send it again with identical method, headers and cookies.
3. DIFF the two responses on all three axes: status code, body length, and body content hash.
4. Attribute every difference. A difference the control did not produce is the finding; a difference the control also produces is the application's normal behaviour.
5. Then re-run the attack value THREE times to separate a real condition from per-request noise (timing, nonce, ordering).

**Record:** baseline response hash, attack response hash, status delta, body-length delta, reproductions

## path_traversal.validation.disk_only_file_probe

**Claim.** Confirm an arbitrary file read by fetching a file that exists only on disk, not a resource bundled in the application's classpath or JAR.

**Procedure — Single-parameter differential probe** (shapes: http_param_probe, filesystem_sink)

1. Record the BASELINE: request the endpoint with a benign, known-good value for the parameter. Save the full response (status, length, body hash).
2. Change exactly ONE variable: set the parameter to the attack value. Send it again with identical method, headers and cookies.
3. DIFF the two responses on all three axes: status code, body length, and body content hash.
4. Attribute every difference. A difference the control did not produce is the finding; a difference the control also produces is the application's normal behaviour.
5. Then re-run the attack value THREE times to separate a real condition from per-request noise (timing, nonce, ordering).

**Record:** baseline response hash, attack response hash, status delta, body-length delta, reproductions

## path_traversal.test.confirm_an_arbitrary_file_read_by_fetching_a_fil

**Claim.** To decide this case, observe: A bundled asset such as a properties template returns 200 through a classpath fallback even when the filesystem branch is unreachable, which is exactly the false positive that makes a controller look exploitable when it is not.

**Procedure — Single-parameter differential probe** (shapes: http_param_probe, filesystem_sink)

1. Record the BASELINE: request the endpoint with a benign, known-good value for the parameter. Save the full response (status, length, body hash).
2. Change exactly ONE variable: set the parameter to the attack value. Send it again with identical method, headers and cookies.
3. DIFF the two responses on all three axes: status code, body length, and body content hash.
4. Attribute every difference. A difference the control did not produce is the finding; a difference the control also produces is the application's normal behaviour.
5. Then re-run the attack value THREE times to separate a real condition from per-request noise (timing, nonce, ordering).

**Record:** baseline response hash, attack response hash, status delta, body-length delta, reproductions

## path_traversal.signal.ht_java_list_directories_it_looks_li

**Claim.** On Java targets a path traversal request aimed at a directory frequently comes back as a directory listing, so a suspected traversal must be confirmed by whether the LFI response enumerates entries rather than returns file content.

**Procedure — Single-parameter differential probe** (shapes: http_param_probe, filesystem_sink)

1. Record the BASELINE: request the endpoint with a benign, known-good value for the parameter. Save the full response (status, length, body hash).
2. Change exactly ONE variable: set the parameter to the attack value. Send it again with identical method, headers and cookies.
3. DIFF the two responses on all three axes: status code, body length, and body content hash.
4. Attribute every difference. A difference the control did not produce is the finding; a difference the control also produces is the application's normal behaviour.
5. Then re-run the attack value THREE times to separate a real condition from per-request noise (timing, nonce, ordering).

**Record:** baseline response hash, attack response hash, status delta, body-length delta, reproductions

## path_traversal.technique.ht_the_later_lfi_includes_the_tempora

**Claim.** When an LFI sink targets the temporary backing file by its own local pathname, the file inclusion consumes the raw request body as written before the decompression wrapper runs, so a payload that only becomes valid after decompression will not execute.

**Procedure — Single-parameter differential probe** (shapes: http_param_probe, filesystem_sink)

1. Record the BASELINE: request the endpoint with a benign, known-good value for the parameter. Save the full response (status, length, body hash).
2. Change exactly ONE variable: set the parameter to the attack value. Send it again with identical method, headers and cookies.
3. DIFF the two responses on all three axes: status code, body length, and body content hash.
4. Attribute every difference. A difference the control did not produce is the finding; a difference the control also produces is the application's normal behaviour.
5. Then re-run the attack value THREE times to separate a real condition from per-request noise (timing, nonce, ordering).

**Record:** baseline response hash, attack response hash, status delta, body-length delta, reproductions

## path_traversal.technique.ht_feed_the_discovered_proc_pid_fd

**Claim.** The in-flight request body is reachable through the process file-descriptor table, so once /proc walking yields fd paths, feeding those paths straight into the LFI parameter includes the buffered request bytes directly.

**Procedure — Single-parameter differential probe** (shapes: http_param_probe, filesystem_sink)

1. Record the BASELINE: request the endpoint with a benign, known-good value for the parameter. Save the full response (status, length, body hash).
2. Change exactly ONE variable: set the parameter to the attack value. Send it again with identical method, headers and cookies.
3. DIFF the two responses on all three axes: status code, body length, and body content hash.
4. Attribute every difference. A difference the control did not produce is the finding; a difference the control also produces is the application's normal behaviour.
5. Then re-run the attack value THREE times to separate a real condition from per-request noise (timing, nonce, ordering).

**Record:** baseline response hash, attack response hash, status delta, body-length delta, reproductions

## path_traversal.technique.ht_discovered_folders_can_be_further

**Claim.** A directory listing from a traversal probe is only a map, not a result - the real file surface is reached by pushing the discovered folder name through the LFI sink and seeing whether it resolves to server-side files.

**Procedure — Filesystem sink confirmation** (shapes: filesystem_sink)

1. Prove the sink reads a file at all BEFORE testing traversal: fetch a file you KNOW exists on the target and confirm real content comes back.
2. If you cannot get a known-good read, there is no traversal finding to report — the sink is not proven.
3. Then apply the traversal value and confirm the returned content is from OUTSIDE the intended directory. Content, not status code.
4. Reject any result where only the status line differs: proxies, error handlers and WAFs produce status differentials with no file ever read.

**Record:** known-good read, outside-directory content sample, negative control (baseline vs traversal)

## path_traversal.signal.ht_php_finishes_copying_closes_the_s

**Claim.** The LFI race is lost when the temp file has already been unlinked by the time the inclusion request runs, so the two observables that decide it are whether the path still resolves and whether the path disclosure actually reached the tester through output buffering.

**Procedure — Single-parameter differential probe** (shapes: http_param_probe, filesystem_sink, race_condition)

1. Record the BASELINE: request the endpoint with a benign, known-good value for the parameter. Save the full response (status, length, body hash).
2. Change exactly ONE variable: set the parameter to the attack value. Send it again with identical method, headers and cookies.
3. DIFF the two responses on all three axes: status code, body length, and body content hash.
4. Attribute every difference. A difference the control did not produce is the finding; a difference the control also produces is the application's normal behaviour.
5. Then re-run the attack value THREE times to separate a real condition from per-request noise (timing, nonce, ordering).

**Record:** baseline response hash, attack response hash, status delta, body-length delta, reproductions

## path_traversal.technique.ht_if_we_manage_to_upload_files_and_m

**Claim.** Because the tester cannot predict the temporary filename, the practical approach is to hold an LFI request open indefinitely and brute-force candidate names inside that window, converting connection lifetime into a search budget.

**Procedure — Single-parameter differential probe** (shapes: http_param_probe, filesystem_sink, race_condition)

1. Record the BASELINE: request the endpoint with a benign, known-good value for the parameter. Save the full response (status, length, body hash).
2. Change exactly ONE variable: set the parameter to the attack value. Send it again with identical method, headers and cookies.
3. DIFF the two responses on all three axes: status code, body length, and body content hash.
4. Attribute every difference. A difference the control did not produce is the finding; a difference the control also produces is the application's normal behaviour.
5. Then re-run the attack value THREE times to separate a real condition from per-request noise (timing, nonce, ordering).

**Record:** baseline response hash, attack response hash, status delta, body-length delta, reproductions

## path_traversal.technique.ht_use_multiple_processes_to_flood_wo

**Claim.** When a single temp file does not live long enough to be caught by the LFI, saturating the workers with concurrent requests widens the window so at least one buffered body file survives for the file inclusion to reach.

**Procedure — Filesystem sink confirmation** (shapes: filesystem_sink, race_condition)

1. Prove the sink reads a file at all BEFORE testing traversal: fetch a file you KNOW exists on the target and confirm real content comes back.
2. If you cannot get a known-good read, there is no traversal finding to report — the sink is not proven.
3. Then apply the traversal value and confirm the returned content is from OUTSIDE the intended directory. Content, not status code.
4. Reject any result where only the status line differs: proxies, error handlers and WAFs produce status differentials with no file ever read.

**Record:** known-good read, outside-directory content sample, negative control (baseline vs traversal)

## path_traversal.technique.including_an_attacker_influenced_path_lets_an_absolute_pat

**Claim.** Including an attacker-influenced path lets an absolute path such as /etc/passwd or the Windows hosts file be read without any traversal sequence at all.

**Procedure — Single-parameter differential probe** (shapes: http_param_probe, filter_bypass, encoding_ladder, filesystem_sink, state_change)

1. Record the BASELINE: request the endpoint with a benign, known-good value for the parameter. Save the full response (status, length, body hash).
2. Change exactly ONE variable: set the parameter to the attack value. Send it again with identical method, headers and cookies.
3. DIFF the two responses on all three axes: status code, body length, and body content hash.
4. Attribute every difference. A difference the control did not produce is the finding; a difference the control also produces is the application's normal behaviour.
5. Then re-run the attack value THREE times to separate a real condition from per-request noise (timing, nonce, ordering).

**Record:** baseline response hash, attack response hash, status delta, body-length delta, reproductions

## path_traversal.bypass.a_symlink_inside_a_trusted_directory_escapes_it_with_no_traversal_string

**Claim.** Confining the resolved path under a base directory by string prefix does not contain a symbolic link, because resolving the link replaces the component and discards all preceding parts of the path when the link body is absolute.

**Procedure — Single-parameter differential probe** (shapes: http_param_probe, filesystem_sink, state_change)

1. Record the BASELINE: request the endpoint with a benign, known-good value for the parameter. Save the full response (status, length, body hash).
2. Change exactly ONE variable: set the parameter to the attack value. Send it again with identical method, headers and cookies.
3. DIFF the two responses on all three axes: status code, body length, and body content hash.
4. Attribute every difference. A difference the control did not produce is the finding; a difference the control also produces is the application's normal behaviour.
5. Then re-run the attack value THREE times to separate a real condition from per-request noise (timing, nonce, ordering).

**Record:** baseline response hash, attack response hash, status delta, body-length delta, reproductions

## path_traversal.technique.ht_once_that_behavior_is_confirmed_in

**Claim.** Once the held-open behaviour is confirmed in the lab or on the target version, scattering thousands of timed-out uploads raises the odds that one of those candidates is caught by the LFI, using fewer long-lived connections than brute force would.

**Procedure — Filesystem sink confirmation** (shapes: filesystem_sink)

1. Prove the sink reads a file at all BEFORE testing traversal: fetch a file you KNOW exists on the target and confirm real content comes back.
2. If you cannot get a known-good read, there is no traversal finding to report — the sink is not proven.
3. Then apply the traversal value and confirm the returned content is from OUTSIDE the intended directory. Content, not status code.
4. Reject any result where only the status line differs: proxies, error handlers and WAFs produce status differentials with no file ever read.

**Record:** known-good read, outside-directory content sample, negative control (baseline vs traversal)

## path_traversal.bypass.a_local_file_inclusion_filter_that_strips_is_bypasse

**Claim.** A local file inclusion filter that strips '../' is bypassed by re-encoding the traversal (%2e%2e%2f), because the filter matches the decoded form the request never carries.

**Procedure — Single-parameter differential probe** (shapes: http_param_probe, filter_bypass, encoding_ladder, filesystem_sink, state_change)

1. Record the BASELINE: request the endpoint with a benign, known-good value for the parameter. Save the full response (status, length, body hash).
2. Change exactly ONE variable: set the parameter to the attack value. Send it again with identical method, headers and cookies.
3. DIFF the two responses on all three axes: status code, body length, and body content hash.
4. Attribute every difference. A difference the control did not produce is the finding; a difference the control also produces is the application's normal behaviour.
5. Then re-run the attack value THREE times to separate a real condition from per-request noise (timing, nonce, ordering).

**Record:** baseline response hash, attack response hash, status delta, body-length delta, reproductions

## path_traversal.technique.php_filter_with_a_base64_encode_conversion_stream_reads

**Claim.** php://filter with a base64-encode conversion stream reads a PHP source file as base64, turning a file read into source disclosure that reveals credentials inside the code.

**Procedure — Filter-bypass ladder** (shapes: filter_bypass, encoding_ladder, filesystem_sink, state_change)

1. First establish what the filter rejects: send the plain attack value and record the rejection (status, message, silence).
2. Then vary ONE encoding dimension at a time: separators, case, trailing dots, alternate separators, redundant segments, container-level normalisation.
3. The first variation that passes identifies the filter's matching weakness precisely — which is the finding.
4. Confirm the bypass reaches the sink by observing an EFFECT, not by observing a different response status.

**Record:** plain value rejection, bypass variant that passed, observed effect at the sink
