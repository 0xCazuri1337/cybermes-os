# File security — the filesystem boundary

## What this directory represents

Flaws where a path, a filename or an uploaded file crosses a boundary it was
not meant to cross.

## What belongs inside it

`../../../file_upload/knowledge/CLASS.md` (**canonical**), `../../../path_traversal/knowledge/CLASS.md` (**canonical for LFI,
RFI and arbitrary file read/write**).

`../../../path_traversal/topics/lfi.md`, `../../../path_traversal/topics/rfi.md` and `../../../path_traversal/topics/arbitrary-file-read-write.md` are **pointer stubs**:
they are path traversal differing only in what the server does with the file it
reached. Keeping them as separate classes would duplicate knowledge for no
navigational gain.

## What does NOT belong inside it

- Inclusion of a *remote* URL by the application itself → a variant of
  `../../../path_traversal/knowledge/CLASS.md`
- Command execution via an uploaded file → `../server-side/rce.md`, chained
  from `../../../file_upload/knowledge/CLASS.md`

## How children are organised

By the direction of the violation: **inbound** (a file the client sends) versus
**outbound** (a path the client steers). Upload and traversal are the two
directions.

## Related bug classes

`../../../file_upload/knowledge/CLASS.md` chains to `../server-side/rce.md`;
`../../../path_traversal/knowledge/CLASS.md` chains to `../../attack-chains/ssrf-chains.md` when the
reachable path is a URL.

## How new entries should be added

Only for a direction that is neither inbound nor outbound. LFI/RFI-style
variants belong in the `Variations` section of `../../../path_traversal/knowledge/CLASS.md`.
