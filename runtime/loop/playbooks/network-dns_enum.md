# Hunt card — dns_enum

5 promoted technique/test items, each mapped to an executable procedure derived from its shape.

## dns_enum.validation.serial_and_secondary_cross_check_confirms_a_real_disclosure

**Claim.** A zone-transfer disclosure is validated only by showing a full multi-record answer whose SOA serial is current and whose names exceed the public NS/SOA/MX set, because an empty or serial-stale answer is a replica, not a disclosure.

**Procedure — Single-parameter differential probe** (shapes: http_param_probe)

1. Record the BASELINE: request the endpoint with a benign, known-good value for the parameter. Save the full response (status, length, body hash).
2. Change exactly ONE variable: set the parameter to the attack value. Send it again with identical method, headers and cookies.
3. DIFF the two responses on all three axes: status code, body length, and body content hash.
4. Attribute every difference. A difference the control did not produce is the finding; a difference the control also produces is the application's normal behaviour.
5. Then re-run the attack value THREE times to separate a real condition from per-request noise (timing, nonce, ordering).

**Record:** baseline response hash, attack response hash, status delta, body-length delta, reproductions

## dns_enum.validation.refused_zone_transfer_is_not_enumeration_evidence

**Claim.** A refused DNS zone transfer proves the zone is not AXFR-open, not that no records were retrieved; enumeration evidence requires a returned record set from the transfer, an NSEC walk, or a secondary resolver.

**Procedure — Single-parameter differential probe** (shapes: http_param_probe, filesystem_sink, blind_confirmation)

1. Record the BASELINE: request the endpoint with a benign, known-good value for the parameter. Save the full response (status, length, body hash).
2. Change exactly ONE variable: set the parameter to the attack value. Send it again with identical method, headers and cookies.
3. DIFF the two responses on all three axes: status code, body length, and body content hash.
4. Attribute every difference. A difference the control did not produce is the finding; a difference the control also produces is the application's normal behaviour.
5. Then re-run the attack value THREE times to separate a real condition from per-request noise (timing, nonce, ordering).

**Record:** baseline response hash, attack response hash, status delta, body-length delta, reproductions

## dns_enum.technique.zone_transfer_enumerates_the_network

**Claim.** A DNS zone enumerates every host in a namespace without touching it, and an AXFR zone transfer returns the entire zone, so one query against a misconfigured server replaces host discovery.

**Procedure — Single-parameter differential probe** (shapes: http_param_probe, filesystem_sink, blind_confirmation)

1. Record the BASELINE: request the endpoint with a benign, known-good value for the parameter. Save the full response (status, length, body hash).
2. Change exactly ONE variable: set the parameter to the attack value. Send it again with identical method, headers and cookies.
3. DIFF the two responses on all three axes: status code, body length, and body content hash.
4. Attribute every difference. A difference the control did not produce is the finding; a difference the control also produces is the application's normal behaviour.
5. Then re-run the attack value THREE times to separate a real condition from per-request noise (timing, nonce, ordering).

**Record:** baseline response hash, attack response hash, status delta, body-length delta, reproductions

## dns_enum.technique.zone_transfer_or_a_misconfigured_dns_service_reveals_the_i

**Claim.** Zone transfer or a misconfigured DNS service reveals the internal host inventory that no port scan would expose.

**Procedure — Single-parameter differential probe** (shapes: http_param_probe, filesystem_sink, state_change, blind_confirmation)

1. Record the BASELINE: request the endpoint with a benign, known-good value for the parameter. Save the full response (status, length, body hash).
2. Change exactly ONE variable: set the parameter to the attack value. Send it again with identical method, headers and cookies.
3. DIFF the two responses on all three axes: status code, body length, and body content hash.
4. Attribute every difference. A difference the control did not produce is the finding; a difference the control also produces is the application's normal behaviour.
5. Then re-run the attack value THREE times to separate a real condition from per-request noise (timing, nonce, ordering).

**Record:** baseline response hash, attack response hash, status delta, body-length delta, reproductions

## dns_enum.technique.ns_and_soa_records_bound_what_a_zone_transfer_can_add

**Claim.** The value of a zone transfer is proportional to what the zone's NS and SOA records already imply, so enumerate those records first to size the transfer, then use the transfer to recover only the names those records never exposed.

**Procedure — Single-parameter differential probe** (shapes: http_param_probe, blind_confirmation)

1. Record the BASELINE: request the endpoint with a benign, known-good value for the parameter. Save the full response (status, length, body hash).
2. Change exactly ONE variable: set the parameter to the attack value. Send it again with identical method, headers and cookies.
3. DIFF the two responses on all three axes: status code, body length, and body content hash.
4. Attribute every difference. A difference the control did not produce is the finding; a difference the control also produces is the application's normal behaviour.
5. Then re-run the attack value THREE times to separate a real condition from per-request noise (timing, nonce, ordering).

**Record:** baseline response hash, attack response hash, status delta, body-length delta, reproductions
