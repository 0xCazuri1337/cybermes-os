# validate — the request/response pair that proves impact

## The pair that counts

```
GET /download?name=%2e%2e%2f%2e%2e%2f%2e%2e%2fetc%2fpasswd HTTP/1.1
Host: target
Connection: close

HTTP/1.1 200 OK
Content-Type: text/plain; charset=utf-8
Content-Length: 1258
ETag: "b3f1-4e2"

root:x:0:0:root:/root:/bin/bash
daemon:x:1:1:daemon:/usr/sbin:/usr/sbin/nologin
...
```

Four things have to be true of that pair, and each is separately checkable:

1. **Status 200 with a body that is file content** — `root:x:0:0:...` is a
   system file, not something this route produces for a legitimate name. The
   finding survives when the response body contains data from the targeted file
   and that content differs from anything served by the same route with a
   legitimate name
   [path_traversal.evidence.a_filename_you_supplied_appearing_in_a_trave].
2. **The same route, same session, legitimate name, different body** — recorded
   at baseline. This is what makes the difference attributable to the payload.
3. **The target is disk-only** — not a resource bundled in the application's
   classpath or JAR [path_traversal.validation.disk_only_file_probe]. On JVM
   targets a bundled properties template can 200 through a classpath fallback
   even when the filesystem branch is unreachable
   [path_traversal.test.confirm_an_arbitrary_file_read_by_fetching_a_fil].
4. **The request was captured raw** — literal and encoded forms side by side if
   the claim is a filter bypass [path_traversal.test.a_traversal_allowlist_is_bypassed_when_the_filte].

## Proof variants, by claim

**Absolute-path read.** Pair is `GET /download?name=/etc/passwd` → 200 with
system-file body. No traversal sequence anywhere in the request. That absence is
the mechanism
[path_traversal.technique.including_an_attacker_influenced_path_lets_an_absolute_pat].

**Encoded-traversal bypass.** Pair is the two-request comparison: literal `../`
→ refused, `%2e%2e%2f` → 200 with file bytes
[path_traversal.bypass.percent_encoding_normalization_defeats_allowlist].

**`php://filter` source disclosure.** Pair is
`GET /page?lang=php://filter/read=convert.base64-encode/resource=config.php` →
200 with base64 that decodes to PHP source. Source disclosure, not a read — the
credential is in the returned code
[path_traversal.technique.php_filter_with_a_base64_encode_conversion_stream_reads].

**LFI-to-execution.** For an include sink the impact claim is that included
content runs with the web server's privileges
[path_traversal.impact.ht_in_a_local_file_inclusion_if_you]. The proving pair is
an uploaded file plus an include request that *executes* it. Refuted if the sink
returns the uploaded file's content as inert data — because the include was
downgraded to a read, or the extension is never interpreted.

## What does NOT count as proof

- **Your filename echoed back** in an error page, a stack trace, a web-root
  directory listing, or a session cookie dropped on a custom 404. None of those
  read a file outside the intended root
  [path_traversal.evidence.a_filename_you_supplied_appearing_in_a_trave].
- **A 200 whose body is an HTML error page.** The status says the app rendered
  successfully; it says nothing about a file layer.
- **A length change with identical content.** Length is not proof; hash the
  bodies [path_traversal.fprule.normalized_payload_returns_identical_content].
- **A response identical to baseline.** That is normalisation or rejection before
  the file layer — the opposite of proof
  [path_traversal.fprule.normalized_payload_returns_identical_content].
- **A bundled classpath asset returning 200.** That is the false positive that
  makes a controller look exploitable when it is not
  [path_traversal.test.confirm_an_arbitrary_file_read_by_fetching_a_fil].
- **A clean static prefix.** Behaviour on a statically served prefix says
  nothing about a parameterised download handler, and the reverse holds too —
  each endpoint needs its own probe because the two are served by different code
  entirely [path_traversal.validation.a_statically_served_prefix_is_not_the_same_as_a_scoped_file_handler].
- **A known-vulnerable version number.** Traversal needs the sink in this request
  path: a request-controlled string concatenated into a filesystem path with no
  canonicalisation or prefix check
  [path_traversal.prerequisite.user_controlled_path_component].
- **A file the user was always allowed to read.** A 200 on a legitimate in-tree
  filename proves routing, not escape. The body must be data from outside the
  served tree.
- **Nothing at all.** Blind, server-side-only, or identical-in-every-case
  behaviour leaves nothing to show
  [path_traversal.evidence.a_filename_you_supplied_appearing_in_a_trave].
