# recognize — the observations that justify investigating this class

Not the class description. These are things I can *see* in a target that make
this class worth minutes instead of hours.

## Sink-shaped observations

- A parameter that a name, a path, a filename, a template, a theme, a locale, a
  document or an avatar flows into. Any endpoint where the client chooses which
  file the server touches is a candidate, regardless of how the framework names
  its helper.
- Error output that discloses path information: the error names a base directory,
  a document root, or an absolute path. Disclosed path information is what turns
  a blind file read into a navigable one.
- On Java targets, a traversal request aimed at a *directory* frequently comes
  back as a directory listing rather than an error
  [path_traversal.signal.ht_java_list_directories_it_looks_li]. A listing is a
  reconnaissance goldmine and also a trap — it is a signal that the string
  reached a filesystem call, not yet a file read.

## Control-shaped observations (these make it *interesting*, not just present)

- The literal `../` form is refused but the encoded form is not, or is refused
  differently. Two answers to two representations of the same logical request is
  a control-inconsistency signature
  [path_traversal.bypass.percent_encoding_normalization_defeats_allowlist].
- A filter that visibly strips `../` from the request value
  [path_traversal.bypass.a_local_file_inclusion_filter_that_strips_is_bypasse].
  A visible filter means a modelled control, and a modelled control is a
  reportable failure when it is bypassed.
- An endpoint that validates the path against an allow-list of permitted
  directories rather than rejecting traversal sequences — that shape changes the
  payload family to absolute paths and lets the "no traversal string" claim be
  the correct one
  [path_traversal.technique.including_an_attacker_influenced_path_lets_an_absolute_pat].
- An upload surface anywhere near a file-serving surface. An attacker-writable
  directory inside the served tree is a symlink staging position, and a symlink
  defeats string-prefix confinement with no traversal string at all
  [path_traversal.bypass.a_symlink_inside_a_trusted_directory_escapes_it_with_no_traversal_string].
- A PHP `include`/`require` parameter. The wrapper-scheme claim
  ([path_traversal.technique.php_filter_with_a_base64_encode_conversion_stream_reads])
  and the execution claim
  ([path_traversal.impact.ht_in_a_local_file_inclusion_if_you]) live only here.

## Discrimination observations

- A response that changes with the traversal payload but is *identical* to the
  baseline is a normalisation or cache artefact, not a finding
  [path_traversal.fprule.normalized_payload_returns_identical_content].
- Your own filename appearing in an error page, a stack trace, a web-root
  directory listing, or a session cookie on a custom 404 is the single most
  common false positive in this class
  [path_traversal.evidence.a_filename_you_supplied_appearing_in_a_trave].
- A statically served prefix behaving correctly tells me nothing about a
  parameterised download handler, and vice versa — different code entirely
  [path_traversal.validation.a_statically_served_prefix_is_not_the_same_as_a_scoped_file_handler].
  If I see a clean static surface and a parameterised one, that is two
  investigations, not one conclusion.

## Do-not-start signals

- No request-controlled path component in the handler. Traversal needs a
  request-controlled string concatenated into a filesystem path with no
  canonicalisation or prefix check
  [path_traversal.prerequisite.user_controlled_path_component].
