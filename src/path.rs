//! Path Component
//!
//! See [[RFC3986, Section 3.3](https://tools.ietf.org/html/rfc3986#section-3.3)].

use std::borrow::Cow;
use std::convert::TryFrom;
use std::error::Error;
use std::fmt::{self, Display, Formatter, Write};
use std::hash::{Hash, Hasher};
use std::mem;
use std::ops::Deref;
use std::str;

use crate::utility::{
    get_percent_encoded_value, normalize_string, percent_encoded_equality, percent_encoded_hash,
    UNRESERVED_CHAR_MAP,
};

/// A map of byte characters that determines if a character is a valid path character.
#[cfg_attr(rustfmt, rustfmt_skip)]
const PATH_CHAR_MAP: [u8; 256] = [
 // 0     1     2     3     4     5     6     7     8     9     A     B     C     D     E     F
    0,    0,    0,    0,    0,    0,    0,    0,    0,    0,    0,    0,    0,    0,    0,    0, // 0
    0,    0,    0,    0,    0,    0,    0,    0,    0,    0,    0,    0,    0,    0,    0,    0, // 1
    0, b'!',    0,    0, b'$', b'%', b'&',b'\'', b'(', b')', b'*', b'+', b',', b'-', b'.',    0, // 2
 b'0', b'1', b'2', b'3', b'4', b'5', b'6', b'7', b'8', b'9', b':', b';',    0, b'=',    0,    0, // 3
 b'@', b'A', b'B', b'C', b'D', b'E', b'F', b'G', b'H', b'I', b'J', b'K', b'L', b'M', b'N', b'O', // 4
 b'P', b'Q', b'R', b'S', b'T', b'U', b'V', b'W', b'X', b'Y', b'Z',    0,    0,    0,    0, b'_', // 5
    0, b'a', b'b', b'c', b'd', b'e', b'f', b'g', b'h', b'i', b'j', b'k', b'l', b'm', b'n', b'o', // 6
 b'p', b'q', b'r', b's', b't', b'u', b'v', b'w', b'x', b'y', b'z',    0,    0,    0, b'~',    0, // 7
    0,    0,    0,    0,    0,    0,    0,    0,    0,    0,    0,    0,    0,    0,    0,    0, // 8
    0,    0,    0,    0,    0,    0,    0,    0,    0,    0,    0,    0,    0,    0,    0,    0, // 9
    0,    0,    0,    0,    0,    0,    0,    0,    0,    0,    0,    0,    0,    0,    0,    0, // A
    0,    0,    0,    0,    0,    0,    0,    0,    0,    0,    0,    0,    0,    0,    0,    0, // B
    0,    0,    0,    0,    0,    0,    0,    0,    0,    0,    0,    0,    0,    0,    0,    0, // C
    0,    0,    0,    0,    0,    0,    0,    0,    0,    0,    0,    0,    0,    0,    0,    0, // D
    0,    0,    0,    0,    0,    0,    0,    0,    0,    0,    0,    0,    0,    0,    0,    0, // E
    0,    0,    0,    0,    0,    0,    0,    0,    0,    0,    0,    0,    0,    0,    0,    0, // F
];

/// The path component as defined in
/// [[RFC3986, Section 3.3](https://tools.ietf.org/html/rfc3986#section-3.3)].
///
/// A path is composed of a sequence of segments. It is also either absolute or relative, where an
/// absolute path starts with a `'/'`. A URI with an authority *always* has an absolute path
/// regardless of whether or not the path was empty (i.e. "http://example.com" has a single empty
/// path segment and is absolute).
#[derive(Clone, Debug, Eq, Hash, PartialEq)]
pub struct Path<'path> {
    /// Whether or not the path is absolute. Specifically, a path is absolute if it starts with a
    /// `'/'`.
    absolute: bool,

    /// The sequence of segments that compose the path.
    segments: Vec<Segment<'path>>,

    unnormalized_count: usize,
}

impl<'path> Path<'path> {
    /// Clears all segments from the path leaving a single empty segment.
    ///
    /// # Examples
    ///
    /// ```
    /// # #![feature(try_from)]
    /// #
    /// use std::convert::TryFrom;
    ///
    /// use uriparse::Path;
    ///
    /// let mut path = Path::try_from("/my/path").unwrap();
    /// assert_eq!(path, "/my/path");
    /// path.clear();
    /// assert_eq!(path, "/");
    /// ```
    pub fn clear(&mut self) {
        self.segments.clear();
        self.segments.push(Segment::empty());
    }

    /// Converts the [`Path`] into an owned copy.
    ///
    /// If you construct the path from a source with a non-static lifetime, you may run into
    /// lifetime problems due to the way the struct is designed. Calling this function will ensure
    /// that the returned value has a static lifetime.
    ///
    /// This is different from just cloning. Cloning the path will just copy the references, and
    /// thus the lifetime will remain the same.
    pub fn into_owned(self) -> Path<'static> {
        let segments = self
            .segments
            .into_iter()
            .map(|segment| segment.into_owned())
            .collect::<Vec<Segment<'static>>>();

        Path {
            absolute: self.absolute,
            segments,
            unnormalized_count: self.unnormalized_count,
        }
    }

    /// Returns whether or not the path is absolute (i.e. it starts with a `'/'`).
    ///
    /// Any path following an [`Authority`] will *always* be parsed to be absolute.
    ///
    /// # Examples
    ///
    /// ```
    /// # #![feature(try_from)]
    /// #
    /// use std::convert::TryFrom;
    ///
    /// use uriparse::Path;
    ///
    /// let path = Path::try_from("/my/path").unwrap();
    /// assert_eq!(path.is_absolute(), true);
    /// ```
    pub fn is_absolute(&self) -> bool {
        self.absolute
    }

    /// Returns whether or not the path is relative (i.e. it does not start with a `'/'`).
    ///
    /// Any path following an [`Authority`] will *always* be parsed to be absolute.
    ///
    /// # Examples
    ///
    /// ```
    /// # #![feature(try_from)]
    /// #
    /// use std::convert::TryFrom;
    ///
    /// use uriparse::Path;
    ///
    /// let path = Path::try_from("my/path").unwrap();
    /// assert_eq!(path.is_relative(), true);
    /// ```
    pub fn is_relative(&self) -> bool {
        !self.absolute
    }

    /// Creates a path with no segments on it.
    ///
    /// This is only used to avoid allocations for temporary paths. Any path created using this
    /// function is **not** valid!
    pub(crate) unsafe fn new_with_no_segments(absolute: bool) -> Path<'static> {
        Path {
            absolute: absolute,
            segments: Vec::new(),
            unnormalized_count: 0,
        }
    }

    pub fn normalize(&mut self, mut as_reference: bool) {
        if self.absolute {
            as_reference = false;
        }

        self.unnormalized_count = 0;

        if !as_reference {
            self.remove_dot_segments_helper(true);
            return;
        }

        let mut last_dot_segment = None;
        let mut new_length = 0;

        for i in 0..self.segments.len() {
            let segment = self.segments[i].as_str();

            if segment == "."
                && (new_length > 0
                    || i == self.segments.len() - 1
                    || !self.segments[i + 1].as_str().contains(':'))
            {
                continue;
            }

            if segment == ".." {
                match last_dot_segment {
                    None if new_length == 0 => (),
                    Some(index) if index == new_length - 1 => (),
                    _ => {
                        new_length -= 1;
                        continue;
                    }
                }

                last_dot_segment = Some(new_length);
            }

            self.segments.swap(i, new_length);
            self.segments[new_length].normalize();
            new_length += 1;
        }

        if new_length == 0 {
            self.segments[0] = Segment::empty();
            new_length = 1;
        }

        self.segments.truncate(new_length);
    }

    /// Pops the last segment off of the path.
    ///
    /// If the path only contains one segment, then that segment will become empty.
    ///
    /// ```
    /// # #![feature(try_from)]
    /// #
    /// use std::convert::TryFrom;
    ///
    /// use uriparse::Path;
    ///
    /// let mut path = Path::try_from("/my/path").unwrap();
    /// path.pop();
    /// assert_eq!(path, "/my");
    /// path.pop();
    /// assert_eq!(path, "/");
    /// ```
    pub fn pop(&mut self) {
        if !self.segments.pop().unwrap().is_normalized() {
            self.unnormalized_count -= 1;
        }

        if self.segments.is_empty() {
            self.segments.push(Segment::empty());
        }
    }

    /// Pushes a segment onto the path.
    ///
    /// If the conversion to a [`Segment`] fails, an [`InvalidPath`] will be returned.
    ///
    /// The behavior of this function is different if the current path is just one empty segment. In
    /// this case, the pushed segment will replace that empty segment unless the pushed segment is
    /// itself empty.
    ///
    /// ```
    /// # #![feature(try_from)]
    /// #
    /// use std::convert::TryFrom;
    ///
    /// use uriparse::Path;
    ///
    /// let mut path = Path::try_from("/my/path").unwrap();
    /// path.push("test");
    /// assert_eq!(path, "/my/path/test");
    ///
    /// let mut path = Path::try_from("/").unwrap();
    /// path.push("test");
    /// assert_eq!(path, "/test");
    ///
    /// let mut path = Path::try_from("/").unwrap();
    /// path.push("");
    /// assert_eq!(path, "//");
    /// ```
    pub fn push<SegmentType, SegmentError>(
        &mut self,
        segment: SegmentType,
    ) -> Result<(), InvalidPath>
    where
        Segment<'path>: TryFrom<SegmentType, Error = SegmentError>,
        InvalidPath: From<SegmentError>,
    {
        let segment = Segment::try_from(segment)?;

        if !segment.is_normalized() {
            self.unnormalized_count += 1;
        }

        if segment != "" && self.segments.len() == 1 && self.segments[0].as_str().is_empty() {
            self.segments[0] = segment;
        } else {
            self.segments.push(segment);
        }

        Ok(())
    }

    pub fn remove_dot_segments(&mut self) {
        self.remove_dot_segments_helper(false);
    }

    fn remove_dot_segments_helper(&mut self, normalize_segments: bool) {
        let mut input_absolute = self.absolute;
        let mut new_length = 0;

        for i in 0..self.segments.len() {
            let segment = self.segments[i].as_str();

            if input_absolute {
                if segment == "." {
                    continue;
                } else if segment == ".." {
                    if new_length > 0 {
                        new_length -= 1;
                    } else {
                        self.absolute = false;
                    }

                    continue;
                }

                if new_length == 0 {
                    self.absolute = true;
                }
            } else if segment == ".." || segment == "." {
                continue;
            }

            self.segments.swap(i, new_length);

            if normalize_segments {
                self.segments[new_length].normalize();
            }

            new_length += 1;

            if i < self.segments.len() - 1 {
                input_absolute = true;
            } else {
                input_absolute = false;
            }
        }

        if input_absolute {
            if new_length == 0 {
                self.absolute = true;
            } else {
                self.segments[new_length] = Segment::empty();
                new_length += 1;
            }
        }

        if new_length == 0 {
            self.segments[0] = Segment::empty();
            new_length = 1;
        }

        self.segments.truncate(new_length);
    }

    /// Returns the segments of the path.
    ///
    /// If you require mutability, use [`Path::segments_mut`].
    ///
    /// # Examples
    ///
    /// ```
    /// # #![feature(try_from)]
    /// #
    /// use std::convert::TryFrom;
    ///
    /// use uriparse::Path;
    ///
    /// let mut path = Path::try_from("/my/path").unwrap();
    /// assert_eq!(path.segments()[1], "path");
    /// ```
    pub fn segments(&self) -> &[Segment<'path>] {
        &self.segments
    }

    /// Returns the segments of the path mutably.
    ///
    /// Due to the required restriction that there must be at least one segment in a path, this
    /// mutability only applies to the segments themselves, not the container.
    ///
    /// # Examples
    ///
    /// ```
    /// # #![feature(try_from)]
    /// #
    /// use std::convert::TryFrom;
    ///
    /// use uriparse::{Path, Segment};
    ///
    /// let mut path = Path::try_from("/my/path").unwrap();
    ///
    /// // TODO: Remove this block once NLL is stable.
    /// {
    ///     let mut segments = path.segments_mut();
    ///     segments[1] = Segment::try_from("test").unwrap();
    /// }
    ///
    /// assert_eq!(path, "/my/test");
    /// ```
    pub fn segments_mut(&mut self) -> &mut [Segment<'path>] {
        &mut self.segments
    }

    /// Sets whether or not the path is absolute (i.e. it starts with a `'/'`).
    ///
    /// # Examples
    ///
    /// ```
    /// # #![feature(try_from)]
    /// #
    /// use std::convert::TryFrom;
    ///
    /// use uriparse::Path;
    ///
    /// let mut path = Path::try_from("/my/path").unwrap();
    /// path.set_absolute(false);
    /// assert_eq!(path, "my/path");
    /// ```
    pub fn set_absolute(&mut self, absolute: bool) {
        self.absolute = absolute;
    }

    pub fn to_borrowed(&self) -> Path {
        let segments = self
            .segments
            .iter()
            .map(|segment| segment.as_borrowed())
            .collect();

        Path {
            absolute: self.absolute,
            segments,
            unnormalized_count: self.unnormalized_count,
        }
    }
}

impl Display for Path<'_> {
    fn fmt(&self, formatter: &mut Formatter) -> fmt::Result {
        if self.absolute {
            formatter.write_char('/')?;
        }

        for (index, segment) in self.segments.iter().enumerate() {
            formatter.write_str(segment.as_str())?;

            if index < self.segments.len() - 1 {
                formatter.write_char('/')?;
            }
        }

        Ok(())
    }
}

impl<'path> From<Path<'path>> for String {
    fn from(value: Path<'path>) -> Self {
        value.to_string()
    }
}

impl PartialEq<[u8]> for Path<'_> {
    fn eq(&self, mut other: &[u8]) -> bool {
        if self.absolute {
            match other.get(0) {
                Some(&byte) => {
                    if byte != b'/' {
                        return false;
                    }
                }
                None => return false,
            }

            other = &other[1..];
        }

        for (index, segment) in self.segments.iter().enumerate() {
            let len = segment.as_str().len();

            if other.len() < len || &other[..len] != segment {
                return false;
            }

            other = &other[len..];

            if index < self.segments.len() - 1 {
                match other.get(0) {
                    Some(&byte) => {
                        if byte != b'/' {
                            return false;
                        }
                    }
                    None => return false,
                }

                other = &other[1..];
            }
        }

        return true;
    }
}

impl<'path> PartialEq<Path<'path>> for [u8] {
    fn eq(&self, other: &Path<'path>) -> bool {
        self == other
    }
}

impl<'a> PartialEq<&'a [u8]> for Path<'_> {
    fn eq(&self, other: &&'a [u8]) -> bool {
        self == *other
    }
}

impl<'a, 'path> PartialEq<Path<'path>> for &'a [u8] {
    fn eq(&self, other: &Path<'path>) -> bool {
        self == other
    }
}

impl PartialEq<str> for Path<'_> {
    fn eq(&self, other: &str) -> bool {
        self == other.as_bytes()
    }
}

impl<'path> PartialEq<Path<'path>> for str {
    fn eq(&self, other: &Path<'path>) -> bool {
        self.as_bytes() == other
    }
}

impl<'a> PartialEq<&'a str> for Path<'_> {
    fn eq(&self, other: &&'a str) -> bool {
        self == other.as_bytes()
    }
}

impl<'a, 'path> PartialEq<Path<'path>> for &'a str {
    fn eq(&self, other: &Path<'path>) -> bool {
        self.as_bytes() == other
    }
}

impl<'path> TryFrom<&'path [u8]> for Path<'path> {
    type Error = InvalidPath;

    fn try_from(value: &'path [u8]) -> Result<Self, Self::Error> {
        let (path, rest) = parse_path(value)?;

        if rest.is_empty() {
            Ok(path)
        } else {
            Err(InvalidPath::ExpectedEOF)
        }
    }
}

impl<'path> TryFrom<&'path str> for Path<'path> {
    type Error = InvalidPath;

    fn try_from(value: &'path str) -> Result<Self, Self::Error> {
        Path::try_from(value.as_bytes())
    }
}

/// A segment of a path.
///
/// Segments are separated from other segments with the `'/'` delimiter.
#[derive(Clone, Debug)]
pub struct Segment<'segment> {
    normalized: bool,
    segment: Cow<'segment, str>,
}

impl Segment<'_> {
    pub fn as_borrowed(&self) -> Segment {
        use self::Cow::*;

        let segment = match &self.segment {
            Borrowed(borrowed) => *borrowed,
            Owned(owned) => owned.as_str(),
        };

        Segment {
            normalized: self.normalized,
            segment: Cow::Borrowed(segment),
        }
    }

    /// Returns a `str` representation of the segment.
    ///
    /// # Examples
    ///
    /// ```
    /// # #![feature(try_from)]
    /// #
    /// use std::convert::TryFrom;
    ///
    /// use uriparse::Segment;
    ///
    /// let segment = Segment::try_from("segment").unwrap();
    /// assert_eq!(segment.as_str(), "segment");
    /// ```
    pub fn as_str(&self) -> &str {
        &self.segment
    }

    /// Constructs a segment that is empty.
    ///
    /// # Examples
    ///
    /// ```
    /// use uriparse::Segment;
    ///
    /// assert_eq!(Segment::empty(),  "");
    /// ```
    pub fn empty() -> Segment<'static> {
        Segment {
            normalized: true,
            segment: Cow::from(""),
        }
    }

    /// Converts the [`Segment`] into an owned copy.
    ///
    /// If you construct the segment from a source with a non-static lifetime, you may run into
    /// lifetime problems due to the way the struct is designed. Calling this function will ensure
    /// that the returned value has a static lifetime.
    ///
    /// This is different from just cloning. Cloning the segment will just copy the references, and
    /// thus the lifetime will remain the same.
    pub fn into_owned(self) -> Segment<'static> {
        Segment {
            normalized: self.normalized,
            segment: Cow::from(self.segment.into_owned()),
        }
    }

    pub fn is_normalized(&self) -> bool {
        self.normalized
    }

    pub fn normalize(&mut self) {
        if !self.normalized {
            normalize_string(&mut self.segment.to_mut());
            self.normalized = true;
        }
    }
}

impl AsRef<[u8]> for Segment<'_> {
    fn as_ref(&self) -> &[u8] {
        self.segment.as_bytes()
    }
}

impl AsRef<str> for Segment<'_> {
    fn as_ref(&self) -> &str {
        &self.segment
    }
}

impl Deref for Segment<'_> {
    type Target = str;

    fn deref(&self) -> &Self::Target {
        &self.segment
    }
}

impl Display for Segment<'_> {
    fn fmt(&self, formatter: &mut Formatter) -> fmt::Result {
        formatter.write_str(&self.segment)
    }
}

impl Eq for Segment<'_> {}

impl<'segment> From<Segment<'segment>> for String {
    fn from(value: Segment<'segment>) -> Self {
        value.to_string()
    }
}

impl Hash for Segment<'_> {
    fn hash<H>(&self, state: &mut H)
    where
        H: Hasher,
    {
        percent_encoded_hash(self.segment.as_bytes(), state, true);
    }
}

impl PartialEq for Segment<'_> {
    fn eq(&self, other: &Segment) -> bool {
        percent_encoded_equality(self.segment.as_bytes(), other.segment.as_bytes(), true)
    }
}

impl PartialEq<[u8]> for Segment<'_> {
    fn eq(&self, other: &[u8]) -> bool {
        percent_encoded_equality(self.segment.as_bytes(), other, true)
    }
}

impl<'segment> PartialEq<Segment<'segment>> for [u8] {
    fn eq(&self, other: &Segment<'segment>) -> bool {
        percent_encoded_equality(self, other.segment.as_bytes(), true)
    }
}

impl<'a> PartialEq<&'a [u8]> for Segment<'_> {
    fn eq(&self, other: &&'a [u8]) -> bool {
        percent_encoded_equality(self.segment.as_bytes(), other, true)
    }
}

impl<'a, 'segment> PartialEq<Segment<'segment>> for &'a [u8] {
    fn eq(&self, other: &Segment<'segment>) -> bool {
        percent_encoded_equality(self, other.segment.as_bytes(), true)
    }
}

impl PartialEq<str> for Segment<'_> {
    fn eq(&self, other: &str) -> bool {
        percent_encoded_equality(self.segment.as_bytes(), other.as_bytes(), true)
    }
}

impl<'segment> PartialEq<Segment<'segment>> for str {
    fn eq(&self, other: &Segment<'segment>) -> bool {
        percent_encoded_equality(self.as_bytes(), other.segment.as_bytes(), true)
    }
}

impl<'a> PartialEq<&'a str> for Segment<'_> {
    fn eq(&self, other: &&'a str) -> bool {
        percent_encoded_equality(self.segment.as_bytes(), other.as_bytes(), true)
    }
}

impl<'a, 'segment> PartialEq<Segment<'segment>> for &'a str {
    fn eq(&self, other: &Segment<'segment>) -> bool {
        percent_encoded_equality(self.as_bytes(), other.segment.as_bytes(), true)
    }
}

impl<'segment> TryFrom<&'segment [u8]> for Segment<'segment> {
    type Error = InvalidPath;

    fn try_from(value: &'segment [u8]) -> Result<Self, Self::Error> {
        let mut bytes = value.iter();
        let mut normalized = true;

        while let Some(&byte) = bytes.next() {
            match PATH_CHAR_MAP[byte as usize] {
                0 => return Err(InvalidPath::InvalidCharacter),
                b'%' => {
                    match get_percent_encoded_value(bytes.next().cloned(), bytes.next().cloned()) {
                        Ok((hex_value, uppercase)) => {
                            if !uppercase || UNRESERVED_CHAR_MAP[hex_value as usize] != 0 {
                                normalized = false;
                            }
                        }
                        Err(_) => return Err(InvalidPath::InvalidPercentEncoding),
                    }
                }
                _ => (),
            }
        }

        let segment = Segment {
            normalized,
            segment: Cow::Borrowed(unsafe { str::from_utf8_unchecked(value) }),
        };
        Ok(segment)
    }
}

impl<'segment> TryFrom<&'segment str> for Segment<'segment> {
    type Error = InvalidPath;

    fn try_from(value: &'segment str) -> Result<Self, Self::Error> {
        Segment::try_from(value.as_bytes())
    }
}

/// An error representing an invalid path.
#[derive(Clone, Copy, Debug, Eq, Hash, PartialEq)]
pub enum InvalidPath {
    /// This error occurs when the string from which the path is parsed is not entirely consumed
    /// during the parsing. For example, parsing the string `"/my/path?query"` would generate
    /// this error since `"?query"` would still be left over.
    ///
    /// This only applies to the [`Path::try_from`] functions.
    ExpectedEOF,

    /// The path contained an invalid character.
    InvalidCharacter,

    /// The path contained an invalid percent encoding (e.g. `"%ZZ"`).
    InvalidPercentEncoding,
}

impl Display for InvalidPath {
    fn fmt(&self, formatter: &mut Formatter) -> fmt::Result {
        formatter.write_str(self.description())
    }
}

impl Error for InvalidPath {
    fn description(&self) -> &str {
        use self::InvalidPath::*;

        match self {
            ExpectedEOF => "expected EOF",
            InvalidCharacter => "invalid path character",
            InvalidPercentEncoding => "invalid path percent encoding",
        }
    }
}

impl From<!> for InvalidPath {
    fn from(value: !) -> Self {
        value
    }
}

/// Parses the path from the given byte string.
pub(crate) fn parse_path<'path>(
    value: &'path [u8],
) -> Result<(Path<'path>, &'path [u8]), InvalidPath> {
    fn new_segment<'segment>(
        segment: &'segment [u8],
        normalized: bool,
        unnormalized_count: &mut usize,
    ) -> Segment<'segment> {
        if !normalized {
            *unnormalized_count += 1;
        }

        // Unsafe: The loop below makes sure this is safe.

        Segment {
            normalized,
            segment: Cow::from(unsafe { str::from_utf8_unchecked(segment) }),
        }
    }

    let (value, absolute) = if value.starts_with(b"/") {
        (&value[1..], true)
    } else {
        (value, false)
    };

    let mut bytes = value.iter();
    let mut normalized = true;
    let mut unnormalized_count = 0;
    let mut segment_end_index = 0;
    let mut segment_start_index = 0;

    // Set some moderate initial capacity. This seems to help with performance a bit.
    let mut segments = Vec::with_capacity(10);

    while let Some(&byte) = bytes.next() {
        match PATH_CHAR_MAP[byte as usize] {
            0 if byte == b'?' || byte == b'#' => {
                let segment = new_segment(
                    &value[segment_start_index..segment_end_index],
                    normalized,
                    &mut unnormalized_count,
                );
                segments.push(segment);
                let path = Path {
                    absolute,
                    segments,
                    unnormalized_count,
                };

                return Ok((path, &value[segment_end_index..]));
            }
            0 if byte == b'/' => {
                let segment = new_segment(
                    &value[segment_start_index..segment_end_index],
                    normalized,
                    &mut unnormalized_count,
                );
                segments.push(segment);
                segment_end_index += 1;
                segment_start_index = segment_end_index;
                normalized = true;
            }
            0 => return Err(InvalidPath::InvalidCharacter),
            b'%' => match get_percent_encoded_value(bytes.next().cloned(), bytes.next().cloned()) {
                Ok((hex_value, uppercase)) => {
                    if !uppercase || UNRESERVED_CHAR_MAP[hex_value as usize] != 0 {
                        normalized = false;
                    }

                    segment_end_index += 3;
                }
                Err(_) => return Err(InvalidPath::InvalidPercentEncoding),
            },
            _ => segment_end_index += 1,
        }
    }

    let segment = new_segment(
        &value[segment_start_index..],
        normalized,
        &mut unnormalized_count,
    );
    segments.push(segment);

    let path = Path {
        absolute,
        segments,
        unnormalized_count,
    };
    Ok((path, b""))
}

#[cfg(test)]
mod test {
    use super::*;

    #[test]
    fn test_normalize() {
        fn test_case(value: &str, expected: &str, as_reference: bool) {
            let mut path = Path::try_from(value).unwrap();
            path.normalize(as_reference);
            assert!(!path.segments().is_empty());
            assert_eq!(path.to_string(), expected);
        }

        test_case("", "", true);
        test_case(".", "", true);
        test_case("..", "..", true);
        test_case("../", "../", true);
        test_case("/.", "/", true);
        test_case("/..", "/", true);
        test_case("../..", "../..", true);
        test_case("../a/../..", "../..", true);
        test_case("a", "a", true);
        test_case("a/..", "", true);
        test_case("a/../", "", true);
        test_case("a/../..", "..", true);
        test_case("./a:b", "./a:b", true);
        test_case("./../a:b", "../a:b", true);
        test_case("../a/../", "../", true);
        test_case("../../.././.././../../../.", "../../../../../../..", true);
        test_case("a/.././a:b", "./a:b", true);

        test_case("", "", false);
        test_case(".", "", false);
        test_case("..", "", false);
        test_case("../", "", false);
        test_case("/.", "/", false);
        test_case("/..", "/", false);
        test_case("../../.././.././../../../.", "", false);
        test_case("a/../..", "/", false);
        test_case("a/../../", "/", false);
        test_case("/a/../../../../", "/", false);
        test_case("/a/./././././././c", "/a/c", false);
        test_case("/a/.", "/a/", false);
        test_case("/a/./", "/a/", false);
        test_case("/a/..", "/", false);
        test_case("/a/b/./..", "/a/", false);
        test_case("/a/b/./../", "/a/", false);
        test_case("/a/b/c/./../../g", "/a/g", false);
        test_case("mid/content=5/../6", "mid/6", false);

        test_case("this/is/a/t%65st/path/%ff", "this/is/a/test/path/%FF", true);
        test_case(
            "this/is/a/t%65st/path/%ff",
            "this/is/a/test/path/%FF",
            false,
        );
    }

    #[test]
    fn test_remove_dot_segments() {
        fn test_case(value: &str, expected: &str) {
            let mut path = Path::try_from(value).unwrap();
            path.remove_dot_segments();
            assert!(!path.segments().is_empty());
            assert_eq!(path.to_string(), expected);
        }

        test_case("", "");
        test_case(".", "");
        test_case("..", "");
        test_case("../", "");
        test_case("/.", "/");
        test_case("/..", "/");
        test_case("../../.././.././../../../.", "");
        test_case("a/../..", "/");
        test_case("a/../../", "/");
        test_case("/a/../../../..", "/");
        test_case("/a/../../../../", "/");
        test_case("/a/./././././././c", "/a/c");
        test_case("/a/.", "/a/");
        test_case("/a/./", "/a/");
        test_case("/a/..", "/");
        test_case("/a/b/./..", "/a/");
        test_case("/a/b/./../", "/a/");
        test_case("/a/b/c/./../../g", "/a/g");
        test_case("mid/content=5/../6", "mid/6");
    }
}
