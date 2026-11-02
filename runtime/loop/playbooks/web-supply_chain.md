# Hunt card — supply_chain

8 promoted technique/test items, each mapped to an executable procedure derived from its shape.

## supply_chain.validation.installed_artifact_matches_registry_publish_event

**Claim.** A supply-chain compromise is confirmed only by a mismatch between the artifact your build or runtime actually resolved and the artifact the upstream registry published for that version, corroborated by an unauthorized publish event on the package account.

**Procedure — Single-parameter differential probe** (shapes: http_param_probe, state_change, race_condition)

1. Record the BASELINE: request the endpoint with a benign, known-good value for the parameter. Save the full response (status, length, body hash).
2. Change exactly ONE variable: set the parameter to the attack value. Send it again with identical method, headers and cookies.
3. DIFF the two responses on all three axes: status code, body length, and body content hash.
4. Attribute every difference. A difference the control did not produce is the finding; a difference the control also produces is the application's normal behaviour.
5. Then re-run the attack value THREE times to separate a real condition from per-request noise (timing, nonce, ordering).

**Record:** baseline response hash, attack response hash, status delta, body-length delta, reproductions

## supply_chain.signal.post_install_execution_as_delivery_stage

**Claim.** Supply-chain attacks that avoid embedding malicious logic in the primary package and instead introduce a secondary dependency executed at install time are identifiable by a Node.js process spawning an OS-native execution path that fetches a remote payload, detached from the original process.

**Procedure — Single-parameter differential probe** (shapes: http_param_probe, filesystem_sink)

1. Record the BASELINE: request the endpoint with a benign, known-good value for the parameter. Save the full response (status, length, body hash).
2. Change exactly ONE variable: set the parameter to the attack value. Send it again with identical method, headers and cookies.
3. DIFF the two responses on all three axes: status code, body length, and body content hash.
4. Attribute every difference. A difference the control did not produce is the finding; a difference the control also produces is the application's normal behaviour.
5. Then re-run the attack value THREE times to separate a real condition from per-request noise (timing, nonce, ordering).

**Record:** baseline response hash, attack response hash, status delta, body-length delta, reproductions

## supply_chain.test.unpinned_ci_dependency_requires_the_resolved_commit_to_differ_between_two_resolutions_of_the_same_tag

**Claim.** An unpinned CI action or workflow reference is a demonstrable supply-chain exposure only when two resolutions of the same tag name yield different commit SHAs, proving the ref is mutable and the build's meaning changes without any change to your repository.

**Procedure — State-changing verification** (shapes: state_change)

1. Capture the pre-state with a read-only request and record it.
2. Perform the single state change.
3. Read the state again THROUGH THE SAME ACCOUNT and, if a second test identity exists, through that identity too.
4. A change visible only to the actor proves write access, not a vulnerability. Cross-account visibility is what makes it one.

**Record:** pre-state, post-state (same identity), post-state (second identity) if available

## supply_chain.lead.bbd_flatt.tech

**Claim.** Public writeup evidence for supply_chain: CI workflow -> supply chain.

**Procedure — Single-parameter differential probe** (shapes: http_param_probe, filesystem_sink)

1. Record the BASELINE: request the endpoint with a benign, known-good value for the parameter. Save the full response (status, length, body hash).
2. Change exactly ONE variable: set the parameter to the attack value. Send it again with identical method, headers and cookies.
3. DIFF the two responses on all three axes: status code, body length, and body content hash.
4. Attribute every difference. A difference the control did not produce is the finding; a difference the control also produces is the application's normal behaviour.
5. Then re-run the attack value THREE times to separate a real condition from per-request noise (timing, nonce, ordering).

**Record:** baseline response hash, attack response hash, status delta, body-length delta, reproductions

## supply_chain.test.artifact_carries_a_live_credential_requires_the_secret_to_work_from_inside_the_published_artifact

**Claim.** A leaked credential in a build artifact is a compromise only when the string extracted from the artifact authenticates successfully against the service it names - a valid token response, not a plausible-looking placeholder that the registry rejects.

**Procedure — Filesystem sink confirmation** (shapes: filesystem_sink, state_change)

1. Prove the sink reads a file at all BEFORE testing traversal: fetch a file you KNOW exists on the target and confirm real content comes back.
2. If you cannot get a known-good read, there is no traversal finding to report — the sink is not proven.
3. Then apply the traversal value and confirm the returned content is from OUTSIDE the intended directory. Content, not status code.
4. Reject any result where only the status line differs: proxies, error handlers and WAFs produce status differentials with no file ever read.

**Record:** known-good read, outside-directory content sample, negative control (baseline vs traversal)

## supply_chain.test.tampered_dependency_requires_the_installed_bytes_to_differ_from_the_published_hash_not_just_the_version_number

**Claim.** A tampered dependency is proved by recomputing the digest of the bytes your build actually consumed and showing it differs from the digest recorded in the lockfile or published by the registry - a version diff alone never establishes this.

**Procedure — Single-parameter differential probe** (shapes: http_param_probe, filesystem_sink)

1. Record the BASELINE: request the endpoint with a benign, known-good value for the parameter. Save the full response (status, length, body hash).
2. Change exactly ONE variable: set the parameter to the attack value. Send it again with identical method, headers and cookies.
3. DIFF the two responses on all three axes: status code, body length, and body content hash.
4. Attribute every difference. A difference the control did not produce is the finding; a difference the control also produces is the application's normal behaviour.
5. Then re-run the attack value THREE times to separate a real condition from per-request noise (timing, nonce, ordering).

**Record:** baseline response hash, attack response hash, status delta, body-length delta, reproductions

## supply_chain.test.post_install_execution_requires_the_lifecycle_script_to_run_and_produce_an_observable_effect

**Claim.** An install-time execution finding requires the dependency's lifecycle script to actually run during the install you performed and to produce an observable effect you captured - a spawned process, a file written outside the package directory, or an outbound connection - not merely a postinstall entry existing in the published package.json.

**Procedure — Filesystem sink confirmation** (shapes: filesystem_sink, state_change, blind_confirmation)

1. Prove the sink reads a file at all BEFORE testing traversal: fetch a file you KNOW exists on the target and confirm real content comes back.
2. If you cannot get a known-good read, there is no traversal finding to report — the sink is not proven.
3. Then apply the traversal value and confirm the returned content is from OUTSIDE the intended directory. Content, not status code.
4. Reject any result where only the status line differs: proxies, error handlers and WAFs produce status differentials with no file ever read.

**Record:** known-good read, outside-directory content sample, negative control (baseline vs traversal)

## supply_chain.technique.stolen-publish-token-self-propagation

**Claim.** A stolen package publish token lets an attacker ship further malicious versions, so one credential compromise propagates with no additional vulnerability required.

**Procedure — State-changing verification** (shapes: state_change)

1. Capture the pre-state with a read-only request and record it.
2. Perform the single state change.
3. Read the state again THROUGH THE SAME ACCOUNT and, if a second test identity exists, through that identity too.
4. A change visible only to the actor proves write access, not a vulnerability. Cross-account visibility is what makes it one.

**Record:** pre-state, post-state (same identity), post-state (second identity) if available
