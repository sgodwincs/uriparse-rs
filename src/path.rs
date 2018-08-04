//! Path Component
//!
//! See [[RFC3986, Section 3.3](https://tools.ietf.org/html/rfc3986#section-3.3)].

use std::borrow::Cow;
use std::convert::TryFrom;
use std::error::Error;
use std::fmt::{self, Display, Formatter, Write};
use std::hash::{Hash, Hasher};
use std::ops::Deref;
use std::str;

use utility::{percent_encoded_equality, percent_encoded_hash};

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
/// absolute path starts with a `'/'`. Note that a URI with an authority *always* has an absolute
/// path regardless of whether or not the path was empty (i.e. "http://example.com" has a single
/// empty path segment and is absolute).
#[derive(Clone, Debug, Eq, Hash, PartialEq)]
pub struct Path<'path> {
    /// Whether or not the path is absolute. Specifically, a path is absolute if it starts with a
    /// `'/'`.
    is_absolute: bool,

    /// The sequence of segments that compose the path.
    segments: Vec<Segment<'path>>,
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

    pub fn into_owned(self) -> Path<'static> {
        let segments = self
            .segments
            .into_iter()
            .map(|segment| segment.into_owned())
            .collect::<Vec<Segment<'static>>>();

        Path {
            is_absolute: self.is_absolute,
            segments,
        }
    }

    pub fn is_absolute(&self) -> bool {
        self.is_absolute
    }

    pub fn pop(&mut self) {
        if self.segments.len() == 1 {
            let segment = self.segments.first_mut().unwrap();
            *segment = Segment("".into());
        } else {
            self.segments.pop();
        }
    }

    pub fn push<S, E>(&mut self, segment: S) -> Result<(), InvalidPath>
    where
        Segment<'path>: TryFrom<S, Error = E>,
        InvalidPath: From<E>,
    {
        let segment = Segment::try_from(segment)?;
        self.segments.push(segment);
        Ok(())
    }

    pub fn segments(&self) -> &[Segment<'path>] {
        &self.segments
    }

    pub fn set_absolute(&mut self, absolute: bool) {
        self.is_absolute = absolute;
    }
}

impl<'path> Display for Path<'path> {
    fn fmt(&self, formatter: &mut Formatter) -> fmt::Result {
        if self.is_absolute {
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

impl<'path> PartialEq<[u8]> for Path<'path> {
    fn eq(&self, mut other: &[u8]) -> bool {
        if self.is_absolute {
            match other.get(0) {
                Some(&byte) => if byte != b'/' {
                    return false;
                },
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
                    Some(&byte) => if byte != b'/' {
                        return false;
                    },
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

impl<'a, 'path> PartialEq<&'a [u8]> for Path<'path> {
    fn eq(&self, other: &&'a [u8]) -> bool {
        self == *other
    }
}

impl<'a, 'path> PartialEq<Path<'path>> for &'a [u8] {
    fn eq(&self, other: &Path<'path>) -> bool {
        self == other
    }
}

impl<'path> PartialEq<str> for Path<'path> {
    fn eq(&self, other: &str) -> bool {
        self == other.as_bytes()
    }
}

impl<'path> PartialEq<Path<'path>> for str {
    fn eq(&self, other: &Path<'path>) -> bool {
        self.as_bytes() == other
    }
}

impl<'a, 'path> PartialEq<&'a str> for Path<'path> {
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

#[derive(Clone, Debug)]
pub struct Segment<'segment>(Cow<'segment, str>);

impl<'segment> Segment<'segment> {
    pub fn as_str(&self) -> &str {
        &self.0
    }

    pub fn empty() -> Segment<'static> {
        Segment(Cow::from(""))
    }

    pub fn into_owned(self) -> Segment<'static> {
        Segment(Cow::from(self.0.into_owned()))
    }
}

impl<'segment> AsRef<[u8]> for Segment<'segment> {
    fn as_ref(&self) -> &[u8] {
        self.0.as_bytes()
    }
}

impl<'segment> AsRef<str> for Segment<'segment> {
    fn as_ref(&self) -> &str {
        &self.0
    }
}

impl<'segment> Deref for Segment<'segment> {
    type Target = str;

    fn deref(&self) -> &Self::Target {
        &self.0
    }
}

impl<'segment> Display for Segment<'segment> {
    fn fmt(&self, formatter: &mut Formatter) -> fmt::Result {
        formatter.write_str(&self.0)
    }
}

impl<'segment> Eq for Segment<'segment> {}

impl<'segment> Hash for Segment<'segment> {
    fn hash<H>(&self, state: &mut H)
    where
        H: Hasher,
    {
        percent_encoded_hash(self.0.as_bytes(), state, true);
    }
}

impl<'segment> PartialEq for Segment<'segment> {
    fn eq(&self, other: &Segment) -> bool {
        percent_encoded_equality(self.0.as_bytes(), other.0.as_bytes(), true)
    }
}

impl<'segment> PartialEq<[u8]> for Segment<'segment> {
    fn eq(&self, other: &[u8]) -> bool {
        percent_encoded_equality(self.0.as_bytes(), other, true)
    }
}

impl<'segment> PartialEq<Segment<'segment>> for [u8] {
    fn eq(&self, other: &Segment<'segment>) -> bool {
        percent_encoded_equality(self, other.0.as_bytes(), true)
    }
}

impl<'a, 'segment> PartialEq<&'a [u8]> for Segment<'segment> {
    fn eq(&self, other: &&'a [u8]) -> bool {
        percent_encoded_equality(self.0.as_bytes(), other, true)
    }
}

impl<'a, 'segment> PartialEq<Segment<'segment>> for &'a [u8] {
    fn eq(&self, other: &Segment<'segment>) -> bool {
        percent_encoded_equality(self, other.0.as_bytes(), true)
    }
}

impl<'segment> PartialEq<str> for Segment<'segment> {
    fn eq(&self, other: &str) -> bool {
        percent_encoded_equality(self.0.as_bytes(), other.as_bytes(), true)
    }
}

impl<'segment> PartialEq<Segment<'segment>> for str {
    fn eq(&self, other: &Segment<'segment>) -> bool {
        percent_encoded_equality(self.as_bytes(), other.0.as_bytes(), true)
    }
}

impl<'a, 'segment> PartialEq<&'a str> for Segment<'segment> {
    fn eq(&self, other: &&'a str) -> bool {
        percent_encoded_equality(self.0.as_bytes(), other.as_bytes(), true)
    }
}

impl<'a, 'segment> PartialEq<Segment<'segment>> for &'a str {
    fn eq(&self, other: &Segment<'segment>) -> bool {
        percent_encoded_equality(self.as_bytes(), other.0.as_bytes(), true)
    }
}

impl<'segment> TryFrom<&'segment [u8]> for Segment<'segment> {
    type Error = InvalidPath;

    fn try_from(value: &'segment [u8]) -> Result<Self, Self::Error> {
        let mut bytes = value.iter();

        while let Some(&byte) = bytes.next() {
            match PATH_CHAR_MAP[byte as usize] {
                0 => return Err(InvalidPath::InvalidCharacter),
                b'%' => match (bytes.next(), bytes.next()) {
                    (Some(byte_1), Some(byte_2))
                        if byte_1.is_ascii_hexdigit() && byte_2.is_ascii_hexdigit() =>
                    {
                        ()
                    }
                    _ => return Err(InvalidPath::InvalidPercentEncoding),
                },
                _ => (),
            }
        }

        let segment = Segment(Cow::Borrowed(unsafe { str::from_utf8_unchecked(value) }));
        Ok(segment)
    }
}

impl<'segment> TryFrom<&'segment str> for Segment<'segment> {
    type Error = InvalidPath;

    fn try_from(value: &'segment str) -> Result<Self, Self::Error> {
        Segment::try_from(value.as_bytes())
    }
}

#[derive(Clone, Copy, Debug, Eq, Hash, PartialEq)]
pub enum InvalidPath {
    ExpectedEOF,
    InvalidCharacter,
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

pub(crate) fn parse_path<'path>(
    value: &'path [u8],
) -> Result<(Path<'path>, &'path [u8]), InvalidPath> {
    fn new_segment<'segment>(segment: &'segment [u8]) -> Segment<'segment> {
        Segment(Cow::from(unsafe { str::from_utf8_unchecked(segment) }))
    }

    let (value, is_absolute) = if value.starts_with(b"/") {
        (&value[1..], true)
    } else {
        (value, false)
    };

    let mut bytes = value.iter();
    let mut segment_end_index = 0;
    let mut segment_start_index = 0;
    let mut segments = Vec::with_capacity(10);

    while let Some(&byte) = bytes.next() {
        match PATH_CHAR_MAP[byte as usize] {
            0 if byte == b'?' || byte == b'#' => {
                segments.push(new_segment(&value[segment_start_index..segment_end_index]));
                let path = Path {
                    is_absolute,
                    segments,
                };

                return Ok((path, &value[segment_end_index..]));
            }
            0 if byte == b'/' => {
                segments.push(new_segment(&value[segment_start_index..segment_end_index]));
                segment_end_index += 1;
                segment_start_index = segment_end_index;
            }
            0 => return Err(InvalidPath::InvalidCharacter),
            b'%' => match (bytes.next(), bytes.next()) {
                (Some(byte_1), Some(byte_2))
                    if byte_1.is_ascii_hexdigit() && byte_2.is_ascii_hexdigit() =>
                {
                    segment_end_index += 3;
                }
                _ => return Err(InvalidPath::InvalidPercentEncoding),
            },
            _ => segment_end_index += 1,
        }
    }

    segments.push(new_segment(&value[segment_start_index..]));
    let path = Path {
        is_absolute,
        segments,
    };

    Ok((path, b""))
}
