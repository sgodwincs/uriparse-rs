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

   But the ability to make paths with a `"//"` prefix is still possible:

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
