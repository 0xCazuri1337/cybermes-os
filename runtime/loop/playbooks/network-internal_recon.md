# Hunt card — internal_recon

1 promoted technique/test items, each mapped to an executable procedure derived from its shape.

## internal_recon.bypass.rpcclient_through_socks_proxy_hides_command_line

**Claim.** Routing rpcclient enumeration through a Cobalt Strike socks proxy causes the enumeration arguments to never appear in the host's process-creation command line, so command-line based detection of internal domain recon returns nothing.

**Procedure — Filter-bypass ladder** (shapes: filter_bypass)

1. First establish what the filter rejects: send the plain attack value and record the rejection (status, message, silence).
2. Then vary ONE encoding dimension at a time: separators, case, trailing dots, alternate separators, redundant segments, container-level normalisation.
3. The first variation that passes identifies the filter's matching weakness precisely — which is the finding.
4. Confirm the bypass reaches the sink by observing an EFFECT, not by observing a different response status.

**Record:** plain value rejection, bypass variant that passed, observed effect at the sink
