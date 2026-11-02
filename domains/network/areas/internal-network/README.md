# Internal Network classes

**Specialization of `../` — Internal Network.**

What is reachable, what answers, and which protocol carries you from one host
to the next. Classes here are about *reachability and movement*, not about the
configuration of the service itself.

| Class | What it covers |
|---|---|
| [`../../internal-network/internal_recon/knowledge/CLASS.md`](../../internal-network/internal_recon/knowledge/CLASS.md) | host and service discovery inside a network; naming and addressing as inference |
| [`../../internal-network/service_enumeration/knowledge/CLASS.md`](../../internal-network/service_enumeration/knowledge/CLASS.md) | banner/version discovery and what it selects |
| [`../../internal-network/lateral_movement/knowledge/CLASS.md`](../../internal-network/lateral_movement/knowledge/CLASS.md) | the choice among protocols available between two hosts |
| [`../../internal-network/tunneling_pivoting/knowledge/CLASS.md`](../../internal-network/tunneling_pivoting/knowledge/CLASS.md) | carrying one protocol inside another to reintroduce forbidden reachability |
| [`../../internal-network/segmentation_analysis/knowledge/CLASS.md`](../../internal-network/segmentation_analysis/knowledge/CLASS.md) | whether the claimed trust boundaries are real |

Service *configuration* lives one level up in [`../infrastructure/`](../infrastructure/),
which asks a different question: not "can I reach it" but "what does its own
configuration concede".
