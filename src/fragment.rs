use std::borrow::Cow;
use std::convert::TryFrom;
use std::error::Error;
use std::fmt::{self, Display, Formatter};
use std::hash::{Hash, Hasher};
use std::ops::Deref;
use std::str;

use utility::{percent_encoded_hash, percent_encoded_string_equality};

#[cfg_attr(rustfmt, rustfmt_skip)]
const FRAGMENT_CHAR_MAP: [u8; 256] = [
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
pub struct Fragment<'fragment>(Cow<'fragment, str>);

impl<'fragment> Fragment<'fragment> {
    pub fn as_str(&self) -> &str {
        &self.0
    }

    pub fn into_owned(self) -> Fragment<'static> {
        Fragment(Cow::from(self.0.into_owned()))
    }
}

impl<'fragment> AsRef<[u8]> for Fragment<'fragment> {
    fn as_ref(&self) -> &[u8] {
        self.0.as_bytes()
    }
}

impl<'fragment> AsRef<str> for Fragment<'fragment> {
    fn as_ref(&self) -> &str {
        &self.0
    }
}

impl<'fragment> Deref for Fragment<'fragment> {
    type Target = str;

    fn deref(&self) -> &Self::Target {
        &self.0
    }
}

impl<'fragment> Display for Fragment<'fragment> {
    fn fmt(&self, formatter: &mut Formatter) -> fmt::Result {
        formatter.write_str(&self.0)
    }
}

impl<'fragment> Eq for Fragment<'fragment> {}

impl<'fragment> Hash for Fragment<'fragment> {
    fn hash<H>(&self, state: &mut H)
    where
        H: Hasher,
    {
        percent_encoded_hash(&self.0, state, true);
    }
}

impl<'fragment> PartialEq for Fragment<'fragment> {
    fn eq(&self, other: &Fragment) -> bool {
        percent_encoded_string_equality(&self.0, &other.0, true)
    }
}

impl<'fragment> PartialEq<str> for Fragment<'fragment> {
    fn eq(&self, other: &str) -> bool {
        percent_encoded_string_equality(&self.0, other, true)
    }
}

impl<'fragment> PartialEq<Fragment<'fragment>> for str {
    fn eq(&self, other: &Fragment<'fragment>) -> bool {
        percent_encoded_string_equality(self, &other.0, true)
    }
}

impl<'a, 'fragment> PartialEq<&'a str> for Fragment<'fragment> {
    fn eq(&self, other: &&'a str) -> bool {
        percent_encoded_string_equality(&self.0, *other, true)
    }
}

impl<'a, 'fragment> PartialEq<Fragment<'fragment>> for &'a str {
    fn eq(&self, other: &Fragment<'fragment>) -> bool {
        percent_encoded_string_equality(self, &other.0, true)
    }
}

impl<'fragment> TryFrom<&'fragment [u8]> for Fragment<'fragment> {
    type Error = InvalidFragment;

    fn try_from(value: &'fragment [u8]) -> Result<Self, Self::Error> {
        let mut bytes = value.iter();

        while let Some(&byte) = bytes.next() {
            match FRAGMENT_CHAR_MAP[byte as usize] {
                0 => return Err(InvalidFragment::InvalidCharacter),
                b'%' => match (bytes.next(), bytes.next()) {
                    (Some(byte_1), Some(byte_2))
                        if byte_1.is_ascii_hexdigit() && byte_2.is_ascii_hexdigit() =>
                    {
                        ()
                    }
                    _ => return Err(InvalidFragment::InvalidPercentEncoding),
                },
                _ => (),
            }
        }

        let fragment = Fragment(Cow::from(unsafe { str::from_utf8_unchecked(value) }));
        Ok(fragment)
    }
}

impl<'fragment> TryFrom<&'fragment str> for Fragment<'fragment> {
    type Error = InvalidFragment;

    fn try_from(value: &'fragment str) -> Result<Self, Self::Error> {
        Fragment::try_from(value.as_bytes())
    }
}

#[derive(Clone, Copy, Debug, Eq, Hash, PartialEq)]
pub enum InvalidFragment {
    InvalidCharacter,
    InvalidPercentEncoding,
}

impl Display for InvalidFragment {
    fn fmt(&self, formatter: &mut Formatter) -> fmt::Result {
        formatter.write_str(self.description())
    }
}

impl Error for InvalidFragment {
    fn description(&self) -> &str {
        use self::InvalidFragment::*;

        match self {
            InvalidCharacter => "invalid fragment character",
            InvalidPercentEncoding => "invalid fragment percent encoding",
        }
    }
}
