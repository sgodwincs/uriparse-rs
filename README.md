# uriparse-rs

Implementation of [RFC3986](https://tools.ietf.org/html/rfc3986) including URIs and URI references.

# Normalization

No normalization is done on any parsed URIs. This needs to be done separately if desired. Specifically, this includes percent encoding normalization, path segment normalization (i.e. `.` and `..` are not handled), and any scheme/protocol-based normalization.

# Equality

Equality of URIs or URI references is based on percent encoding normalization, though the original strings are never normalized directly. Case-sensitivity of equality depends on each specific part (e.g. the host is case-insensitive).
