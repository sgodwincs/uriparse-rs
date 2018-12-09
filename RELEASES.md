# 0.4.0

 - Add new schemes:
   * calculator
   * ms-calculator
 - Fix typo in `ms-drive-to` scheme variant name.
 - Fix two duplicates in schemes: `aaas` and `tag`.
 - Fix percent encoding equality and hash implementations. Percent encoding comparison is now only
   done for characters in the unreserved set. An example of what would have passed before, but does
   not now is comparing the following two URIs:

   `http://example.com/#/`
   `http://example.com/#%2F`

   This is because while `/` is an allowed character in the fragment component, it is not in the
   unreserved character set and so percent decoding is not guaranteed to be a "safe" operation. It
   could be fine in a lot of protocols, but it may fail in another protocol that assigns a special
   meaning to `/` in the fragment component.
 - Fixed bug where parsing a username directly from a byte source would allow the username to
   contain colons.
 - Fixed bug where parsing a query directly from source containing percent-encoded characters would
   return the wrong query.
 - Added normalization for all components.
 - References can now be resolved against URIs.
 - Add missing `has_port` function to authority, URI, RelativeReference, and URIReference.

# 0.3.3

 - Add new schemes:
   * ms-eyecontrolspeech
   * ms-screenclip
   * ms-screensketch
   * ms-search
 - Small amount of refactoring.

# 0.3.2

 - Update number of schemes to include the newest from v0.3.1.

# 0.3.1

 - Add new schemes:
   * bitcoincash

# 0.3.0

 - Fix serialization of IPv6 addresses.
 - Changed behavior of `Path::push` when the current path is just one empty segment. For example:

```rust
let mut path = Path::try_from("/").unwrap();
path.push("test");
assert_eq!(path, "/test"); // Before, the path would have been `"//test"`.
```

   But the ability to make paths with a `//` prefix is still possible:

```rust
let mut path = Path::try_from("/").unwrap();
path.push("");
assert_eq!(path, "//"); // This conforms to the previous functionality.
```

 - Added authority mutability functions.
 - Added URI mutability functions.

# 0.2.1

 - Added more conversions between types.
 - Fixed lifetime issue with username.

# 0.2.0

 - Performance fixes.
 - Internal cleanup.
 - Fixed one parsing bug.
 - URI reference parsing has been fuzzed for an entire week!
 - Significantly increased testing coverage (mainly via doc tests).
 - Added a lot of documentation.
 - Added a `RelativeReference` struct that can only represent schemeless URI references.
 - Added builder types for `URI`, `RelativeReference` and `URIReference` structs.

# 0.1.0

Initial release.
