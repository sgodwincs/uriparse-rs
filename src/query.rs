use std::borrow::Cow;
use std::convert::TryFrom;
use std::error::Error;
use std::fmt::{self, Display, Formatter};
use std::hash::{Hash, Hasher};
use std::ops::Deref;
use std::str;

use utility::{percent_encoded_hash, percent_encoded_string_equality};

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

#[derive(Clone, Debug)]
pub struct Query<'query>(Cow<'query, str>);

impl<'query> Query<'query> {
    pub fn as_str(&self) -> &str {
        &self.0
    }

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

impl<'query> Hash for Query<'query> {
    fn hash<H>(&self, state: &mut H)
    where
        H: Hasher,
    {
        percent_encoded_hash(&self.0, state, true);
    }
}

impl<'query> PartialEq for Query<'query> {
    fn eq(&self, other: &Query) -> bool {
        percent_encoded_string_equality(&self.0, &other.0, true)
    }
}

impl<'query> PartialEq<str> for Query<'query> {
    fn eq(&self, other: &str) -> bool {
        percent_encoded_string_equality(&self.0, other, true)
    }
}

impl<'query> PartialEq<Query<'query>> for str {
    fn eq(&self, other: &Query<'query>) -> bool {
        percent_encoded_string_equality(self, &other.0, true)
    }
}

impl<'a, 'query> PartialEq<&'a str> for Query<'query> {
    fn eq(&self, other: &&'a str) -> bool {
        percent_encoded_string_equality(&self.0, *other, true)
    }
}

impl<'a, 'query> PartialEq<Query<'query>> for &'a str {
    fn eq(&self, other: &Query<'query>) -> bool {
        percent_encoded_string_equality(self, &other.0, true)
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

#[derive(Clone, Copy, Debug, Eq, Hash, PartialEq)]
pub enum InvalidQuery {
    ExpectedEOF,
    InvalidCharacter,
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

    let (value, rest) = value.split_at(end_index);
    let query = Query(Cow::from(unsafe { str::from_utf8_unchecked(value) }));
    Ok((query, rest))
}
