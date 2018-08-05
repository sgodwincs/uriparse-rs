//! Query Component
//!
//! See [[RFC3986, Section 3.4](https://tools.ietf.org/html/rfc3986#section-3.4)].
//!
//! This crate does not do query string parsing, it will simply make sure that it is a valid query
//! string as defined by the RFC. You will need to use another crate (e.g.
//! [queryst](https://github.com/rustless/queryst)) if you want it parsed.

use std::borrow::Cow;
use std::convert::TryFrom;
use std::error::Error;
use std::fmt::{self, Display, Formatter};
use std::hash::{Hash, Hasher};
use std::ops::Deref;
use std::str;

use utility::{percent_encoded_equality, percent_encoded_hash};

/// A map of byte characters that determines if a character is a valid query character.
#[cfg_attr(rustfmt, rustfmt_skip)]
const QUERY_CHAR_MAP: [u8; 256] = [
 // 0     1     2     3     4     5     6     7     8     9     A     B     C     D     E     F
    0,    0,    0,    0,    0,    0,    0,    0,    0,    0,    0,    0,    0,    0,    0,    0, // 0
    0,    0,    0,    0,    0,    0,    0,    0,    0,    0,    0,    0,    0,    0,    0,    0, // 1
    0, b'!',    0,    0, b'$', b'%', b'&',b'\'', b'(', b')', b'*', b'+', b',', b'-', b'.', b'/', // 2
 b'0', b'1', b'2', b'3', b'4', b'5', b'6', b'7', b'8', b'9', b':', b';',    0, b'=',    0, b'?', // 3
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

/// The query component as defined in
/// [[RFC3986, Section 3.4](https://tools.ietf.org/html/rfc3986#section-3.4)].
///
/// The query is case-sensitive. Furthermore, percent-encoding plays no role in equality checking
/// meaning that `"query"` and `"que%72y"` are the same query. Both of these attributes are
/// reflected in the equality and hash functions.
///
/// However, be aware that just because percent-encoding plays no role in equality checking does not
/// mean that the query is normalized. The original query string will always be preserved as is with
/// no normalization performed.
#[derive(Clone, Debug)]
pub struct Query<'query>(Cow<'query, str>);

impl<'query> Query<'query> {
    /// Returns a `str` representation of the query.
    ///
    /// # Examples
    ///
    /// ```
    /// # #![feature(try_from)]
    /// #
    /// use std::convert::TryFrom;
    ///
    /// use uriparse::Query;
    ///
    /// let query = Query::try_from("query").unwrap();
    /// assert_eq!(query.as_str(), "query");
    /// ```
    pub fn as_str(&self) -> &str {
        &self.0
    }

    /// Converts the [`Query`] into an owned copy.
    ///
    /// If you construct the query from a source with a non-static lifetime, you may run into
    /// lifetime problems due to the way the struct is designed. Calling this function will ensure
    /// that the returned value has a static lifetime.
    ///
    /// This is different from just cloning. Cloning the query will just copy the references, and
    /// thus the lifetime will remain the same.
    pub fn into_owned(self) -> Query<'static> {
        Query(Cow::from(self.0.into_owned()))
    }
}

impl<'query> AsRef<[u8]> for Query<'query> {
    fn as_ref(&self) -> &[u8] {
        self.0.as_bytes()
    }
}

impl<'query> AsRef<str> for Query<'query> {
    fn as_ref(&self) -> &str {
        &self.0
    }
}

impl<'query> Deref for Query<'query> {
    type Target = str;

    fn deref(&self) -> &Self::Target {
        &self.0
    }
}

impl<'query> Display for Query<'query> {
    fn fmt(&self, formatter: &mut Formatter) -> fmt::Result {
        formatter.write_str(&self.0)
    }
}

impl<'query> Eq for Query<'query> {}

impl<'query> From<Query<'query>> for String {
    fn from(value: Query<'query>) -> String {
        value.to_string()
    }
}

impl<'query> Hash for Query<'query> {
    fn hash<H>(&self, state: &mut H)
    where
        H: Hasher,
    {
        percent_encoded_hash(self.0.as_bytes(), state, true);
    }
}

impl<'query> PartialEq for Query<'query> {
    fn eq(&self, other: &Query) -> bool {
        percent_encoded_equality(self.0.as_bytes(), other.0.as_bytes(), true)
    }
}

impl<'query> PartialEq<[u8]> for Query<'query> {
    fn eq(&self, other: &[u8]) -> bool {
        percent_encoded_equality(self.0.as_bytes(), other, true)
    }
}

impl<'query> PartialEq<Query<'query>> for [u8] {
    fn eq(&self, other: &Query<'query>) -> bool {
        percent_encoded_equality(self, other.0.as_bytes(), true)
    }
}

impl<'a, 'query> PartialEq<&'a [u8]> for Query<'query> {
    fn eq(&self, other: &&'a [u8]) -> bool {
        percent_encoded_equality(self.0.as_bytes(), other, true)
    }
}

impl<'a, 'query> PartialEq<Query<'query>> for &'a [u8] {
    fn eq(&self, other: &Query<'query>) -> bool {
        percent_encoded_equality(self, other.0.as_bytes(), true)
    }
}

impl<'query> PartialEq<str> for Query<'query> {
    fn eq(&self, other: &str) -> bool {
        percent_encoded_equality(self.0.as_bytes(), other.as_bytes(), true)
    }
}

impl<'query> PartialEq<Query<'query>> for str {
    fn eq(&self, other: &Query<'query>) -> bool {
        percent_encoded_equality(self.as_bytes(), other.0.as_bytes(), true)
    }
}

impl<'a, 'query> PartialEq<&'a str> for Query<'query> {
    fn eq(&self, other: &&'a str) -> bool {
        percent_encoded_equality(self.0.as_bytes(), other.as_bytes(), true)
    }
}

impl<'a, 'query> PartialEq<Query<'query>> for &'a str {
    fn eq(&self, other: &Query<'query>) -> bool {
        percent_encoded_equality(self.as_bytes(), other.0.as_bytes(), true)
    }
}

impl<'query> TryFrom<&'query [u8]> for Query<'query> {
    type Error = InvalidQuery;

    fn try_from(value: &'query [u8]) -> Result<Self, Self::Error> {
        let (query, rest) = parse_query(value)?;

        if rest.is_empty() {
            Ok(query)
        } else {
            Err(InvalidQuery::ExpectedEOF)
        }
    }
}

impl<'query> TryFrom<&'query str> for Query<'query> {
    type Error = InvalidQuery;

    fn try_from(value: &'query str) -> Result<Self, Self::Error> {
        Query::try_from(value.as_bytes())
    }
}

/// An error representing an invalid query.
#[derive(Clone, Copy, Debug, Eq, Hash, PartialEq)]
pub enum InvalidQuery {
    /// This error occurs when the string from which the query is parsed is not entirely consumed
    /// during the parsing. For example, parsing the string `"my=query#fragment"` would generate
    /// this error since `"#fragment"` would still be left over.
    ///
    /// This only applies to the [`Query::try_from`] functions.
    ExpectedEOF,

    /// The fragment contained an invalid character.
    InvalidCharacter,

    /// The fragment contained an invalid percent encoding (e.g. `"%ZZ"`).
    InvalidPercentEncoding,
}

impl Display for InvalidQuery {
    fn fmt(&self, formatter: &mut Formatter) -> fmt::Result {
        formatter.write_str(self.description())
    }
}

impl Error for InvalidQuery {
    fn description(&self) -> &str {
        use self::InvalidQuery::*;

        match self {
            ExpectedEOF => "expected EOF",
            InvalidCharacter => "invalid query character",
            InvalidPercentEncoding => "invalid query percent encoding",
        }
    }
}

/// Parses the query from the given byte string.
pub(crate) fn parse_query<'query>(
    value: &'query [u8],
) -> Result<(Query<'query>, &'query [u8]), InvalidQuery> {
    let mut bytes = value.iter();
    let mut end_index = 0;

    while let Some(&byte) = bytes.next() {
        match QUERY_CHAR_MAP[byte as usize] {
            0 if byte == b'#' => break,
            0 => return Err(InvalidQuery::InvalidCharacter),
            b'%' => match (bytes.next(), bytes.next()) {
                (Some(byte_1), Some(byte_2))
                    if byte_1.is_ascii_hexdigit() && byte_2.is_ascii_hexdigit() =>
                {
                    end_index += 3;
                }
                _ => return Err(InvalidQuery::InvalidPercentEncoding),
            },
            _ => end_index += 1,
        }
    }

    // Unsafe: The loop above makes sure this is safe.

    let (value, rest) = value.split_at(end_index);
    let query = Query(Cow::from(unsafe { str::from_utf8_unchecked(value) }));
    Ok((query, rest))
}
