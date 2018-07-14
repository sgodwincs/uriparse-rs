use std::borrow::Cow;
use std::convert::TryFrom;
use std::error::Error;
use std::fmt::{self, Display, Formatter, Write};
use std::hash::{Hash, Hasher};
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};
use std::ops::Deref;
use std::str;

use utility::{percent_encoded_hash, percent_encoded_string_equality};

#[cfg_attr(rustfmt, rustfmt_skip)]
const IPV4_AND_REGISTERED_NAME_CHAR_MAP: [u8; 256] = [
 // 0     1     2     3     4     5     6     7     8     9     A     B     C     D     E     F
    0,    0,    0,    0,    0,    0,    0,    0,    0,    0,    0,    0,    0,    0,    0,    0, // 0
    0,    0,    0,    0,    0,    0,    0,    0,    0,    0,    0,    0,    0,    0,    0,    0, // 1
    0, b'!',    0,    0, b'$', b'%', b'&',b'\'', b'(', b')', b'*', b'+', b',', b'-', b'.',    0, // 2
 b'0', b'1', b'2', b'3', b'4', b'5', b'6', b'7', b'8', b'9',    0, b';',    0, b'=',    0,    0, // 3
    0, b'A', b'B', b'C', b'D', b'E', b'F', b'G', b'H', b'I', b'J', b'K', b'L', b'M', b'N', b'O', // 4
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

#[cfg_attr(rustfmt, rustfmt_skip)]
const IPV_FUTURE_CHAR_MAP: [u8; 256] = [
 // 0     1     2     3     4     5     6     7     8     9     A     B     C     D     E     F
    0,    0,    0,    0,    0,    0,    0,    0,    0,    0,    0,    0,    0,    0,    0,    0, // 0
    0,    0,    0,    0,    0,    0,    0,    0,    0,    0,    0,    0,    0,    0,    0,    0, // 1
    0, b'!',    0,    0, b'$',    0, b'&',b'\'', b'(', b')', b'*', b'+', b',', b'-', b'.',    0, // 2
 b'0', b'1', b'2', b'3', b'4', b'5', b'6', b'7', b'8', b'9', b':', b';',    0, b'=',    0,    0, // 3
    0, b'A', b'B', b'C', b'D', b'E', b'F', b'G', b'H', b'I', b'J', b'K', b'L', b'M', b'N', b'O', // 4
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

#[cfg_attr(rustfmt, rustfmt_skip)]
const USER_INFO_CHAR_MAP: [u8; 256] = [
 // 0     1     2     3     4     5     6     7     8     9     A     B     C     D     E     F
    0,    0,    0,    0,    0,    0,    0,    0,    0,    0,    0,    0,    0,    0,    0,    0, // 0
    0,    0,    0,    0,    0,    0,    0,    0,    0,    0,    0,    0,    0,    0,    0,    0, // 1
    0, b'!',    0,    0, b'$', b'%', b'&',b'\'', b'(', b')', b'*', b'+', b',', b'-', b'.',    0, // 2
 b'0', b'1', b'2', b'3', b'4', b'5', b'6', b'7', b'8', b'9', b':', b';',    0, b'=',    0,    0, // 3
    0, b'A', b'B', b'C', b'D', b'E', b'F', b'G', b'H', b'I', b'J', b'K', b'L', b'M', b'N', b'O', // 4
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

#[derive(Clone, Debug, Eq, Hash, PartialEq)]
pub struct Authority<'authority> {
    host: Host<'authority>,
    password: Option<Password<'authority>>,
    port: Option<u16>,
    username: Option<Username<'authority>>,
}

impl<'authority> Authority<'authority> {
    pub fn from_parts<
        'new_authority,
        UsernameType,
        PasswordType,
        HostType,
        UsernameError,
        PasswordError,
        HostError,
    >(
        username: Option<UsernameType>,
        password: Option<PasswordType>,
        host: HostType,
        port: Option<u16>,
    ) -> Result<Authority<'new_authority>, InvalidAuthority>
    where
        Username<'new_authority>: TryFrom<UsernameType, Error = UsernameError>,
        Password<'new_authority>: TryFrom<PasswordType, Error = PasswordError>,
        Host<'new_authority>: TryFrom<HostType, Error = HostError>,
        InvalidAuthority: From<UsernameError> + From<PasswordError> + From<HostError>,
    {
        let username = match username {
            Some(username) => Some(Username::try_from(username)?),
            None => None,
        };

        let password = match password {
            Some(password) => Some(Password::try_from(password)?),
            None => None,
        };

        let host = Host::try_from(host)?;

        Ok(Authority {
            host,
            password,
            port,
            username,
        })
    }

    pub fn has_password(&self) -> bool {
        self.password.is_some()
    }

    pub fn has_username(&self) -> bool {
        self.username.is_some()
    }

    pub fn host(&self) -> &Host<'authority> {
        &self.host
    }

    pub fn into_owned(self) -> Authority<'static> {
        let password = self.password.map(|password| password.into_owned());
        let username = self.username.map(|username| username.into_owned());
        let host = match self.host {
            Host::RegisteredName(name) => Host::RegisteredName(name.into_owned()),
            Host::IPv4Address(ipv4) => Host::IPv4Address(ipv4),
            Host::IPv6Address(ipv6) => Host::IPv6Address(ipv6),
        };

        Authority {
            host,
            port: self.port,
            password,
            username,
        }
    }

    pub fn into_parts(
        self,
    ) -> (
        Option<Username<'authority>>,
        Option<Password<'authority>>,
        Host<'authority>,
        Option<u16>,
    ) {
        (self.username, self.password, self.host, self.port)
    }

    pub fn password(&self) -> Option<&Password<'authority>> {
        self.password.as_ref()
    }

    pub fn port(&self) -> Option<u16> {
        self.port
    }

    pub fn username(&self) -> Option<&Username<'authority>> {
        self.username.as_ref()
    }
}

impl<'authority> Display for Authority<'authority> {
    fn fmt(&self, formatter: &mut Formatter) -> fmt::Result {
        use self::Host::*;

        if let Some(ref username) = self.username {
            username.fmt(formatter)?;

            if self.password.is_some() {
                formatter.write_char(':')?;

                // Do not display password.
            }

            formatter.write_char('@')?;
        }

        match self.host {
            IPv4Address(ref address) => address.fmt(formatter)?,
            IPv6Address(ref address) => address.fmt(formatter)?,
            RegisteredName(ref name) => name.fmt(formatter)?,
        }

        if let Some(port) = self.port {
            formatter.write_char(':')?;
            port.fmt(formatter)?;
        }

        Ok(())
    }
}

impl<'authority> From<Authority<'authority>> for String {
    fn from(value: Authority<'authority>) -> String {
        format!("{}", value)
    }
}

impl<'authority> TryFrom<&'authority [u8]> for Authority<'authority> {
    type Error = InvalidAuthority;

    fn try_from(value: &'authority [u8]) -> Result<Self, Self::Error> {
        let (authority, rest) = parse_authority(value)?;

        if rest.is_empty() {
            Ok(authority)
        } else {
            Err(InvalidAuthority::FoundPath)
        }
    }
}

impl<'authority> TryFrom<&'authority str> for Authority<'authority> {
    type Error = InvalidAuthority;

    fn try_from(value: &'authority str) -> Result<Self, Self::Error> {
        Authority::try_from(value.as_bytes())
    }
}

#[derive(Clone, Debug, Eq, Hash, PartialEq)]
pub enum Host<'host> {
    IPv4Address(Ipv4Addr),
    IPv6Address(Ipv6Addr),
    RegisteredName(RegisteredName<'host>),
}

impl<'host> Display for Host<'host> {
    fn fmt(&self, formatter: &mut Formatter) -> fmt::Result {
        use self::Host::*;

        match self {
            IPv4Address(address) => write!(formatter, "{}", address),
            IPv6Address(address) => write!(formatter, "{}", address),
            RegisteredName(name) => formatter.write_str(name.as_str()),
        }
    }
}

impl From<IpAddr> for Host<'static> {
    fn from(value: IpAddr) -> Self {
        match value {
            IpAddr::V4(address) => Host::IPv4Address(address),
            IpAddr::V6(address) => Host::IPv6Address(address),
        }
    }
}

impl<'host> TryFrom<&'host [u8]> for Host<'host> {
    type Error = InvalidHost;

    fn try_from(value: &'host [u8]) -> Result<Self, Self::Error> {
        if value.is_empty() {
            return Ok(Host::RegisteredName(RegisteredName(Cow::from(""))));
        }

        match (value.get(0), value.get(value.len() - 1)) {
            (Some(b'['), Some(b']')) => {
                match value.get(1..3) {
                    Some(&[prefix, version])
                        if prefix.to_ascii_lowercase() == b'v' && version.is_ascii_hexdigit() =>
                    {
                        // IPvFuture

                        let ipvfuture = &value[3..value.len() - 1];

                        if check_ipvfuture(ipvfuture) {
                            return Err(InvalidHost::AddressMechanismNotSupport);
                        } else {
                            return Err(InvalidHost::InvalidIPvFutureCharacter);
                        }
                    }
                    _ => (),
                }

                // IPv6

                let ipv6 = &value[1..value.len() - 1];

                if !check_ipv6(ipv6) {
                    return Err(InvalidHost::InvalidIPv6Character);
                }

                let ipv6: Ipv6Addr = unsafe { str::from_utf8_unchecked(ipv6) }
                    .parse()
                    .map_err(|_| InvalidHost::InvalidIPv6)?;
                Ok(Host::IPv6Address(ipv6))
            }
            _ => {
                if check_ipv4_or_registered_name(value) {
                    match unsafe { str::from_utf8_unchecked(value) }.parse() {
                        Ok(ipv4) => Ok(Host::IPv4Address(ipv4)),
                        Err(_) => {
                            let name = unsafe { str::from_utf8_unchecked(value) };
                            Ok(Host::RegisteredName(RegisteredName(Cow::from(name))))
                        }
                    }
                } else {
                    Err(InvalidHost::InvalidIPv4OrRegisteredNameCharacter)
                }
            }
        }
    }
}

impl<'host> TryFrom<&'host str> for Host<'host> {
    type Error = InvalidHost;

    fn try_from(value: &'host str) -> Result<Self, Self::Error> {
        Host::try_from(value.as_bytes())
    }
}

#[derive(Clone, Debug)]
pub struct Password<'password>(Cow<'password, str>);

impl<'password> Password<'password> {
    pub fn as_str(&self) -> &str {
        &self.0
    }

    pub fn into_owned(self) -> Password<'static> {
        Password(Cow::from(self.0.into_owned()))
    }
}

impl<'password> AsRef<[u8]> for Password<'password> {
    fn as_ref(&self) -> &[u8] {
        self.0.as_bytes()
    }
}

impl<'password> AsRef<str> for Password<'password> {
    fn as_ref(&self) -> &str {
        &self.0
    }
}

impl<'password> Deref for Password<'password> {
    type Target = str;

    fn deref(&self) -> &Self::Target {
        &self.0
    }
}

impl<'password> Eq for Password<'password> {}

impl<'password> Hash for Password<'password> {
    fn hash<H>(&self, state: &mut H)
    where
        H: Hasher,
    {
        percent_encoded_hash(&self.0, state, true);
    }
}

impl<'password> PartialEq for Password<'password> {
    fn eq(&self, other: &Password) -> bool {
        percent_encoded_string_equality(&self.0, &other.0, true)
    }
}

impl<'password> PartialEq<str> for Password<'password> {
    fn eq(&self, other: &str) -> bool {
        percent_encoded_string_equality(&self.0, other, true)
    }
}

impl<'password> PartialEq<Password<'password>> for str {
    fn eq(&self, other: &Password<'password>) -> bool {
        percent_encoded_string_equality(self, &other.0, true)
    }
}

impl<'a, 'password> PartialEq<&'a str> for Password<'password> {
    fn eq(&self, other: &&'a str) -> bool {
        percent_encoded_string_equality(&self.0, *other, true)
    }
}

impl<'a, 'password> PartialEq<Password<'password>> for &'a str {
    fn eq(&self, other: &Password<'password>) -> bool {
        percent_encoded_string_equality(self, &other.0, true)
    }
}

impl<'password> TryFrom<&'password [u8]> for Password<'password> {
    type Error = InvalidUserInfo;

    fn try_from(value: &'password [u8]) -> Result<Self, Self::Error> {
        check_user_info(value)?;
        let password = Password(Cow::from(unsafe { str::from_utf8_unchecked(value) }));
        Ok(password)
    }
}

impl<'password> TryFrom<&'password str> for Password<'password> {
    type Error = InvalidUserInfo;

    fn try_from(value: &'password str) -> Result<Self, Self::Error> {
        Password::try_from(value.as_bytes())
    }
}

#[derive(Clone, Debug)]
pub struct RegisteredName<'name>(Cow<'name, str>);

impl<'name> RegisteredName<'name> {
    pub fn as_str(&self) -> &str {
        &self.0
    }

    pub fn into_owned(self) -> RegisteredName<'static> {
        RegisteredName(Cow::from(self.0.into_owned()))
    }
}

impl<'name> AsRef<[u8]> for RegisteredName<'name> {
    fn as_ref(&self) -> &[u8] {
        self.0.as_bytes()
    }
}

impl<'name> AsRef<str> for RegisteredName<'name> {
    fn as_ref(&self) -> &str {
        &self.0
    }
}

impl<'name> Display for RegisteredName<'name> {
    fn fmt(&self, formatter: &mut Formatter) -> fmt::Result {
        formatter.write_str(&self.0)
    }
}

impl<'name> Eq for RegisteredName<'name> {}

impl<'name> Hash for RegisteredName<'name> {
    fn hash<H>(&self, state: &mut H)
    where
        H: Hasher,
    {
        percent_encoded_hash(&self.0, state, false);
    }
}

impl<'name> PartialEq for RegisteredName<'name> {
    fn eq(&self, other: &RegisteredName) -> bool {
        percent_encoded_string_equality(&self.0, &other.0, false)
    }
}

impl<'name> PartialEq<str> for RegisteredName<'name> {
    fn eq(&self, other: &str) -> bool {
        percent_encoded_string_equality(&self.0, other, false)
    }
}

impl<'name> PartialEq<RegisteredName<'name>> for str {
    fn eq(&self, other: &RegisteredName<'name>) -> bool {
        percent_encoded_string_equality(self, &other.0, false)
    }
}

impl<'a, 'name> PartialEq<&'a str> for RegisteredName<'name> {
    fn eq(&self, other: &&'a str) -> bool {
        percent_encoded_string_equality(&self.0, *other, false)
    }
}

impl<'a, 'name> PartialEq<RegisteredName<'name>> for &'a str {
    fn eq(&self, other: &RegisteredName<'name>) -> bool {
        percent_encoded_string_equality(self, &other.0, false)
    }
}

impl<'name> TryFrom<&'name [u8]> for RegisteredName<'name> {
    type Error = InvalidRegisteredName;

    fn try_from(value: &'name [u8]) -> Result<Self, Self::Error> {
        match Host::try_from(value) {
            Ok(Host::RegisteredName(name)) => Ok(name),
            _ => Err(InvalidRegisteredName),
        }
    }
}

impl<'name> TryFrom<&'name str> for RegisteredName<'name> {
    type Error = InvalidRegisteredName;

    fn try_from(value: &'name str) -> Result<Self, Self::Error> {
        RegisteredName::try_from(value.as_bytes())
    }
}

#[derive(Clone, Debug)]
pub struct Username<'username>(Cow<'username, str>);

impl<'username> Username<'username> {
    pub fn as_str(&self) -> &str {
        &self.0
    }

    pub fn into_owned(self) -> Username<'static> {
        Username(Cow::from(self.0.into_owned()))
    }
}

impl<'username> AsRef<[u8]> for Username<'username> {
    fn as_ref(&self) -> &[u8] {
        self.0.as_bytes()
    }
}

impl<'username> AsRef<str> for Username<'username> {
    fn as_ref(&self) -> &str {
        &self.0
    }
}

impl<'username> Deref for Username<'username> {
    type Target = str;

    fn deref(&self) -> &Self::Target {
        &self.0
    }
}

impl<'username> Display for Username<'username> {
    fn fmt(&self, formatter: &mut Formatter) -> fmt::Result {
        formatter.write_str(&self.0)
    }
}

impl<'username> Eq for Username<'username> {}

impl<'username> Hash for Username<'username> {
    fn hash<H>(&self, state: &mut H)
    where
        H: Hasher,
    {
        percent_encoded_hash(&self.0, state, true);
    }
}

impl<'username> PartialEq for Username<'username> {
    fn eq(&self, other: &Username) -> bool {
        percent_encoded_string_equality(&self.0, &other.0, true)
    }
}

impl<'username> PartialEq<str> for Username<'username> {
    fn eq(&self, other: &str) -> bool {
        percent_encoded_string_equality(&self.0, other, true)
    }
}

impl<'username> PartialEq<Username<'username>> for str {
    fn eq(&self, other: &Username<'username>) -> bool {
        percent_encoded_string_equality(self, &other.0, true)
    }
}

impl<'a, 'username> PartialEq<&'a str> for Username<'username> {
    fn eq(&self, other: &&'a str) -> bool {
        percent_encoded_string_equality(&self.0, *other, true)
    }
}

impl<'a, 'username> PartialEq<Username<'username>> for &'a str {
    fn eq(&self, other: &Username<'username>) -> bool {
        percent_encoded_string_equality(self, &other.0, true)
    }
}

impl<'username> TryFrom<&'username [u8]> for Username<'username> {
    type Error = InvalidUserInfo;

    fn try_from(value: &'username [u8]) -> Result<Self, Self::Error> {
        if let Some(_) = check_user_info(value)? {
            return Err(InvalidUserInfo::InvalidCharacter);
        }

        let username = Username(Cow::from(unsafe { str::from_utf8_unchecked(value) }));
        Ok(username)
    }
}

impl<'username> TryFrom<&'username str> for Username<'username> {
    type Error = InvalidUserInfo;

    fn try_from(value: &'username str) -> Result<Self, Self::Error> {
        Username::try_from(value.as_bytes())
    }
}

#[derive(Clone, Copy, Debug, Eq, Hash, PartialEq)]
pub enum InvalidAuthority {
    FoundPath,
    InvalidHost(InvalidHost),
    InvalidPort(InvalidPort),
    InvalidUserInfo(InvalidUserInfo),
}

impl Display for InvalidAuthority {
    fn fmt(&self, formatter: &mut Formatter) -> fmt::Result {
        formatter.write_str(self.description())
    }
}

impl Error for InvalidAuthority {
    fn description(&self) -> &str {
        use self::InvalidAuthority::*;

        match self {
            FoundPath => "path not allowed in authority",
            InvalidHost(invalid_host) => invalid_host.description(),
            InvalidPort(invalid_port) => invalid_port.description(),
            InvalidUserInfo(invalid_user_info) => invalid_user_info.description(),
        }
    }
}

impl From<!> for InvalidAuthority {
    fn from(value: !) -> Self {
        value
    }
}

impl From<InvalidHost> for InvalidAuthority {
    fn from(value: InvalidHost) -> Self {
        InvalidAuthority::InvalidHost(value)
    }
}

impl From<InvalidPort> for InvalidAuthority {
    fn from(value: InvalidPort) -> Self {
        InvalidAuthority::InvalidPort(value)
    }
}

impl From<InvalidUserInfo> for InvalidAuthority {
    fn from(value: InvalidUserInfo) -> Self {
        InvalidAuthority::InvalidUserInfo(value)
    }
}

#[derive(Clone, Copy, Debug, Eq, Hash, PartialEq)]
pub enum InvalidHost {
    AddressMechanismNotSupport,
    InvalidIPv4OrRegisteredNameCharacter,
    InvalidIPv6,
    InvalidIPv6Character,
    InvalidIPvFutureCharacter,
}

impl Display for InvalidHost {
    fn fmt(&self, formatter: &mut Formatter) -> fmt::Result {
        formatter.write_str(self.description())
    }
}

impl Error for InvalidHost {
    fn description(&self) -> &str {
        use self::InvalidHost::*;

        match self {
            AddressMechanismNotSupport => "address mechanism not supported",
            InvalidIPv4OrRegisteredNameCharacter => "invalid IPv4 or registered name character",
            InvalidIPv6 => "invalid IPv6",
            InvalidIPv6Character => "invalid IPv6 character",
            InvalidIPvFutureCharacter => "invalid IPvFuture character",
        }
    }
}

#[derive(Clone, Copy, Debug, Eq, Hash, PartialEq)]
pub enum InvalidPort {
    InvalidCharacter,
    Overflow,
}

impl Display for InvalidPort {
    fn fmt(&self, formatter: &mut Formatter) -> fmt::Result {
        formatter.write_str(self.description())
    }
}

impl Error for InvalidPort {
    fn description(&self) -> &str {
        use self::InvalidPort::*;

        match self {
            InvalidCharacter => "invalid port character",
            Overflow => "port overflow",
        }
    }
}

#[derive(Clone, Copy, Debug, Eq, Hash, PartialEq)]
pub struct InvalidRegisteredName;

impl Display for InvalidRegisteredName {
    fn fmt(&self, formatter: &mut Formatter) -> fmt::Result {
        formatter.write_str(self.description())
    }
}

impl Error for InvalidRegisteredName {
    fn description(&self) -> &str {
        "invalid registered name"
    }
}

#[derive(Clone, Copy, Debug, Eq, Hash, PartialEq)]
pub enum InvalidUserInfo {
    InvalidCharacter,
    InvalidPercentEncoding,
}

impl Display for InvalidUserInfo {
    fn fmt(&self, formatter: &mut Formatter) -> fmt::Result {
        formatter.write_str(self.description())
    }
}

impl Error for InvalidUserInfo {
    fn description(&self) -> &str {
        use self::InvalidUserInfo::*;

        match self {
            InvalidCharacter => "invalid user info character",
            InvalidPercentEncoding => "invalid user info percent encoding",
        }
    }
}

fn check_ipv4_or_registered_name(value: &[u8]) -> bool {
    let mut bytes = value.iter();

    while let Some(&byte) = bytes.next() {
        match IPV4_AND_REGISTERED_NAME_CHAR_MAP[byte as usize] {
            0 => return false,
            b'%' => match (bytes.next(), bytes.next()) {
                (Some(byte_1), Some(byte_2))
                    if byte_1.is_ascii_hexdigit() && byte_2.is_ascii_hexdigit() =>
                {
                    ()
                }
                _ => return false,
            },
            _ => (),
        }
    }

    true
}

fn check_ipv6(value: &[u8]) -> bool {
    for &byte in value {
        if !byte.is_ascii_hexdigit() && byte != b':' {
            return false;
        }
    }

    true
}

fn check_ipvfuture(value: &[u8]) -> bool {
    for &byte in value {
        match IPV_FUTURE_CHAR_MAP[byte as usize] {
            0 => return false,
            _ => (),
        }
    }

    true
}

fn check_user_info(value: &[u8]) -> Result<Option<usize>, InvalidUserInfo> {
    let mut bytes = value.iter().enumerate();
    let mut first_colon_index = None;

    while let Some((index, &byte)) = bytes.next() {
        match USER_INFO_CHAR_MAP[byte as usize] {
            0 => return Err(InvalidUserInfo::InvalidCharacter),
            b'%' => match (bytes.next(), bytes.next()) {
                (Some((_, byte_1)), Some((_, byte_2)))
                    if byte_1.is_ascii_hexdigit() && byte_2.is_ascii_hexdigit() =>
                {
                    ()
                }
                _ => return Err(InvalidUserInfo::InvalidPercentEncoding),
            },
            b':' => if first_colon_index.is_none() {
                first_colon_index = Some(index);
            },
            _ => (),
        }
    }

    Ok(first_colon_index)
}

pub fn parse_authority<'authority>(
    value: &'authority [u8],
) -> Result<(Authority<'authority>, &'authority [u8]), InvalidAuthority> {
    let mut at_index = None;
    let mut last_colon_index = None;
    let mut end_index = value.len();

    for (index, &byte) in value.iter().enumerate() {
        match byte {
            b'@' => if at_index.is_none() {
                at_index = Some(index);
            },
            b':' => last_colon_index = Some(index),
            b']' => last_colon_index = None,
            b'/' | b'?' | b'#' => {
                end_index = index;
                break;
            }
            _ => (),
        }
    }

    let (value, rest) = value.split_at(end_index);
    let (username, password, host_start_index) = match at_index {
        Some(index) => {
            let (username, password) = parse_user_info(&value[..index])?;
            (Some(username), password, index + 1)
        }
        None => (None, None, 0),
    };

    let (host, port) = match last_colon_index {
        Some(index) => (
            Host::try_from(&value[host_start_index..index])?,
            parse_port(&value[index + 1..])?,
        ),
        None => (Host::try_from(&value[host_start_index..])?, None),
    };

    let authority = Authority {
        host,
        port,
        password,
        username,
    };

    Ok((authority, rest))
}

fn parse_port(value: &[u8]) -> Result<Option<u16>, InvalidPort> {
    if value.is_empty() {
        Ok(None)
    } else {
        let mut port = 0u16;

        for &byte in value {
            if !byte.is_ascii_digit() {
                return Err(InvalidPort::InvalidCharacter);
            }

            port = port.checked_mul(10).ok_or(InvalidPort::Overflow)?;
            port = port
                .checked_add((byte - b'0') as u16)
                .ok_or(InvalidPort::Overflow)?;
        }

        Ok(Some(port))
    }
}

fn parse_user_info<'user_info>(
    value: &'user_info [u8],
) -> Result<(Username<'user_info>, Option<Password<'user_info>>), InvalidUserInfo> {
    let mut bytes = value.iter().enumerate();
    let mut first_colon_index = None;

    while let Some((index, &byte)) = bytes.next() {
        match USER_INFO_CHAR_MAP[byte as usize] {
            0 => return Err(InvalidUserInfo::InvalidCharacter),
            b'%' => match (bytes.next(), bytes.next()) {
                (Some((_, byte_1)), Some((_, byte_2)))
                    if byte_1.is_ascii_hexdigit() && byte_2.is_ascii_hexdigit() =>
                {
                    ()
                }
                _ => return Err(InvalidUserInfo::InvalidPercentEncoding),
            },
            b':' => if first_colon_index.is_none() {
                first_colon_index = Some(index);
            },
            _ => (),
        }
    }

    Ok(match first_colon_index {
        Some(index) => {
            let username = unsafe { str::from_utf8_unchecked(&value[..index]) };
            let password = unsafe { str::from_utf8_unchecked(&value[index + 1..]) };
            (
                Username(Cow::from(username)),
                Some(Password(Cow::from(password))),
            )
        }
        _ => {
            let username = unsafe { str::from_utf8_unchecked(value) };
            (Username(Cow::from(username)), None)
        }
    })
}
