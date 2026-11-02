# Internal Network classes

**Specialization of `../` — Internal Network.**

What is reachable, what answers, and which protocol carries you from one host
to the next. Classes here are about *reachability and movement*, not about the
configuration of the service itself.

| Class | What it covers |
|---|---|
| [`internal-recon.md`](internal-recon.md) | host and service discovery inside a network; naming and addressing as inference |
| [`service-enumeration.md`](service-enumeration.md) | banner/version discovery and what it selects |
| [`lateral-movement.md`](lateral-movement.md) | the choice among protocols available between two hosts |
| [`tunneling-pivoting.md`](tunneling-pivoting.md) | carrying one protocol inside another to reintroduce forbidden reachability |
| [`segmentation-analysis.md`](segmentation-analysis.md) | whether the claimed trust boundaries are real |

Service *configuration* lives one level up in [`../infrastructure/`](../infrastructure/),
which asks a different question: not "can I reach it" but "what does its own
configuration concede".
