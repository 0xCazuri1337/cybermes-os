# Hunt card — service_enumeration_detail

1 promoted technique/test items, each mapped to an executable procedure derived from its shape.

## service_enumeration_detail.technique.service_configuration_determines_reachability

**Claim.** Whether a service's protocol weaknesses are reachable is decided by that service's own configuration — signing requirements, binding, authentication method and lockout policy — so service identification must be followed by configuration assessment before any weakness is asserted.

**Procedure — Filter-bypass ladder** (shapes: filter_bypass, filesystem_sink)

1. First establish what the filter rejects: send the plain attack value and record the rejection (status, message, silence).
2. Then vary ONE encoding dimension at a time: separators, case, trailing dots, alternate separators, redundant segments, container-level normalisation.
3. The first variation that passes identifies the filter's matching weakness precisely — which is the finding.
4. Confirm the bypass reaches the sink by observing an EFFECT, not by observing a different response status.

**Record:** plain value rejection, bypass variant that passed, observed effect at the sink
