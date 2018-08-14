//! Authority Component
//!
//! See [[RFC3986, Section 3.2](https://tools.ietf.org/html/rfc3986#section-3.2)].
//!
//! # Examples
//!
//! ```
//! # #![feature(try_from)]
//! #
//! use std::convert::TryFrom;
//!
//! use uriparse::Authority;
//!
//! let authority = Authority::try_from("example.com").unwrap();
//! let host = authority.into_parts().2;
//! let authority =
//!     Authority::from_parts(Some("username"), Some("password"), host, Some(80)).unwrap();
//! assert_eq!(authority.to_string(), "username:password@example.com:80");
//! ```
//!
//! # Equality
//!
//! While many components in this library support string comparison, [`Authority`] does not. This
//! comes down to it just being too expensive to do a proper host comparison. To do so would require
//! conversion to [`IpAddr`], which in the case of [`Ipv6Addr`] can be expensive.
//!
//! Some testing reveals that doing incremental parsing and equality of the host string for IP
//! addresses allow for considerably faster checks. For example, a custom IPv4 parser I wrote
//! performed ~2.5 faster than what the `std` uses. Part of this is that I have to find the end of
//! the host before I can use the `std` parser. I may in the future allow [`Authority`] comparison
//! with custom written IPv4/IPv6 address parsers.

use std::borrow::Cow;
use std::convert::TryFrom;
use std::error::Error;
use std::fmt::{self, Display, Formatter, Write};
use std::hash::{Hash, Hasher};
use std::mem;
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};
use std::ops::Deref;
use std::str;

use utility::{percent_encoded_equality, percent_encoded_hash};

/// A map of byte characters that determines if a character is a valid IPv4 or registered name
/// character.
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

/// A map of byte characters that determines if a character is a valid future IP literal character.
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

/// A map of byte characters that determines if a character is a valid user information character.
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

/// The authority component as defined in
/// [[RFC3986, Section 3.2](https://tools.ietf.org/html/rfc3986#section-3.2)].
///
/// Any conversions to a string will **not** hide the password component of the authority. Be
/// careful if you decide to perform logging.
#[derive(Clone, Debug, Eq, Hash, PartialEq)]
pub struct Authority<'authority> {
    /// The host component of the authority as defined in
    /// [[RFC3986, Section 3.2.2](https://tools.ietf.org/html/rfc3986#section-3.2.2)].
    host: Host<'authority>,

    /// The password component of the authority as defined in
    /// [[RFC3986, Section 3.2.1](https://tools.ietf.org/html/rfc3986#section-3.2.1)].
    password: Option<Password<'authority>>,

    /// The port component of the authority as defined in
    /// [[RFC3986, Section 3.2.3](https://tools.ietf.org/html/rfc3986#section-3.2.3)].
    port: Option<u16>,

    /// The username component of the authority as defined in
    /// [[RFC3986, Section 3.2.1](https://tools.ietf.org/html/rfc3986#section-3.2.1)].
    username: Option<Username<'authority>>,
}

impl<'authority> Authority<'authority> {
    /// Constructs a new [`Authority`] from the individual parts: username, password, host, and
    /// port.
    ///
    /// The lifetime used by the resulting value will be the lifetime of the part that is most
    /// restricted in scope.
    ///
    /// # Examples
    ///
    /// ```
    /// # #![feature(try_from)]
    /// #
    /// use std::convert::TryFrom;
    ///
    /// use uriparse::Authority;
    ///
    /// let authority = Authority::from_parts(
    ///     Some("username"),
    ///     Some("password"),
    ///     "example.com",
    ///     Some(80)
    /// ).unwrap();
    /// assert_eq!(authority.to_string(), "username:password@example.com:80");
    /// ```
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

    /// Returns whether or not there is a password in the authority as defined in
    /// [[RFC3986, Section 3.2.1](https://tools.ietf.org/html/rfc3986#section-3.2.1)].
    ///
    /// There will only be a password if the URI has a user information component *and* the
    /// component contains the `':'` delimiter.
    ///
    /// # Examples
    ///
    /// ```
    /// # #![feature(try_from)]
    /// #
    /// use std::convert::TryFrom;
    ///
    /// use uriparse::Authority;
    ///
    /// let authority = Authority::try_from("username:password@example.com").unwrap();
    /// assert_eq!(authority.has_password(), true);
    /// ```
    pub fn has_password(&self) -> bool {
        self.password.is_some()
    }

    /// Returns whether or not there is a username in the authority as defined in
    /// [[RFC3986, Section 3.2.1](https://tools.ietf.org/html/rfc3986#section-3.2.1)].
    ///
    /// There will *always* be a username as long as there is a `'@'` delimiter present in the
    /// authority.
    ///
    /// # Examples
    ///
    /// ```
    /// # #![feature(try_from)]
    /// #
    /// use std::convert::TryFrom;
    ///
    /// use uriparse::Authority;
    ///
    /// let authority = Authority::try_from("username@example.com").unwrap();
    /// assert_eq!(authority.has_username(), true);
    /// ```
    pub fn has_username(&self) -> bool {
        self.username.is_some()
    }

    /// The host component of the authority as defined in
    /// [[RFC3986, Section 3.2.2](https://tools.ietf.org/html/rfc3986#section-3.2.2)].
    ///
    /// An authority component always has a host, though it may be an empty registered name.
    ///
    ///
    /// # Examples
    ///
    /// ```
    /// # #![feature(try_from)]
    /// #
    /// use std::convert::TryFrom;
    ///
    /// use uriparse::Authority;
    ///
    /// let authority = Authority::try_from("username:password@example.com").unwrap();
    /// assert_eq!(authority.host().to_string().as_str(), "example.com");
    /// ```
    pub fn host(&self) -> &Host<'authority> {
        &self.host
    }

    /// Converts the [`Authority`] into an owned copy.
    ///
    /// If you construct the authority from a source with a non-static lifetime, you may run into
    /// lifetime problems due to the way the struct is designed. Calling this function will ensure
    /// that the returned value has a static lifetime.
    ///
    /// This is different from just cloning. Cloning the authority will just copy the eferences, and
    /// thus the lifetime will remain the same.
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

    /// Consumes the [`Authority`] and returns its parts: username, password, host, and port.
    ///
    /// # Examples
    ///
    /// ```
    /// # #![feature(try_from)]
    /// #
    /// use std::convert::TryFrom;
    ///
    /// use uriparse::Authority;
    ///
    /// let authority = Authority::try_from("username:password@example.com:80").unwrap();
    /// let (username, password, host, port) = authority.into_parts();
    ///
    /// assert_eq!(username.unwrap(), "username");
    /// assert_eq!(password.unwrap(), "password");
    /// assert_eq!(host.to_string(), "example.com");
    /// assert_eq!(port.unwrap(), 80);
    /// ```
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

    /// Maps the host using the given map function.
    ///
    /// # Examples
    ///
    /// ```
    /// # #![feature(try_from)]
    /// #
    /// use std::convert::TryFrom;
    ///
    /// use uriparse::{Authority, Host};
    ///
    /// let mut authority = Authority::try_from("example.com").unwrap();
    /// authority.map_host(|_| Host::try_from("127.0.0.1").unwrap());
    /// assert_eq!(authority.to_string(), "127.0.0.1");
    /// ```
    pub fn map_host<Mapper>(&mut self, mapper: Mapper) -> &Host<'authority>
    where
        Mapper: FnOnce(Host<'authority>) -> Host<'authority>,
    {
        let temp_host = Host::RegisteredName(RegisteredName(Cow::from("")));
        let host = mapper(mem::replace(&mut self.host, temp_host));
        self.set_host(host)
            .expect("mapped host resulted in invalid state")
    }

    /// Maps the password using the given map function.
    ///
    /// # Examples
    ///
    /// ```
    /// # #![feature(try_from)]
    /// #
    /// use std::convert::TryFrom;
    ///
    /// use uriparse::{Authority, Password};
    ///
    /// let mut authority = Authority::try_from("example.com").unwrap();
    /// authority.map_password(|_| Some(Password::try_from("password").unwrap()));
    /// assert_eq!(authority.to_string(), ":password@example.com");
    /// ```
    pub fn map_password<Mapper>(&mut self, mapper: Mapper) -> Option<&Password<'authority>>
    where
        Mapper: FnOnce(Option<Password<'authority>>) -> Option<Password<'authority>>,
    {
        let password = mapper(self.password.take());
        self.set_password(password)
            .expect("mapped password resulted in invalid state")
    }

    /// Maps the port using the given map function.
    ///
    /// # Examples
    ///
    /// ```
    /// # #![feature(try_from)]
    /// #
    /// use std::convert::TryFrom;
    ///
    /// use uriparse::Authority;
    ///
    /// let mut authority = Authority::try_from("example.com").unwrap();
    /// authority.map_port(|_| Some(8080));
    /// assert_eq!(authority.to_string(), "example.com:8080");
    /// ```
    pub fn map_port<Mapper>(&mut self, mapper: Mapper) -> Option<u16>
    where
        Mapper: FnOnce(Option<u16>) -> Option<u16>,
    {
        let port = mapper(self.port);
        self.set_port(port)
    }

    /// Maps the username using the given map function.
    ///
    /// # Examples
    ///
    /// ```
    /// # #![feature(try_from)]
    /// #
    /// use std::convert::TryFrom;
    ///
    /// use uriparse::{Authority, Username};
    ///
    /// let mut authority = Authority::try_from("example.com").unwrap();
    /// authority.map_username(|_| Some(Username::try_from("username").unwrap()));
    /// assert_eq!(authority.to_string(), "username@example.com");
    /// ```
    pub fn map_username<Mapper>(&mut self, mapper: Mapper) -> Option<&Username<'authority>>
    where
        Mapper: FnOnce(Option<Username<'authority>>) -> Option<Username<'authority>>,
    {
        let username = mapper(self.username.take());
        self.set_username(username)
            .expect("mapped username resulted in invalid state")
    }

    /// The password component of the authority as defined in
    /// [[RFC3986, Section 3.2.1](https://tools.ietf.org/html/rfc3986#section-3.2.1)].
    ///
    /// The password will be `None` if the user information component of the authority did not
    /// contain a `':'`. Otherwise, it will be whatever is after the `':'` until the `'@'`
    /// character. It may be empty as well.
    ///
    /// # Examples
    ///
    /// ```
    /// # #![feature(try_from)]
    /// #
    /// use std::convert::TryFrom;
    ///
    /// use uriparse::Authority;
    ///
    /// let authority = Authority::try_from("username:password@example.com").unwrap();
    /// assert_eq!(authority.password().unwrap(), "password");
    /// ```
    pub fn password(&self) -> Option<&Password<'authority>> {
        self.password.as_ref()
    }

    /// The port component of the authority as defined in
    /// [[RFC3986, Section 3.2.3]](https://tools.ietf.org/html/rfc3986#section-3.2.3).
    ///
    /// The port will be `None` if a port was not specified.
    ///
    /// # Examples
    ///
    /// ```
    /// # #![feature(try_from)]
    /// #
    /// use std::convert::TryFrom;
    ///
    /// use uriparse::Authority;
    ///
    /// let authority = Authority::try_from("example.com:80").unwrap();
    /// assert_eq!(authority.port().unwrap(), 80);
    /// ```
    pub fn port(&self) -> Option<u16> {
        self.port
    }

    /// Sets the host of the authority.
    ///
    /// An error will be returned if the conversion to a [`Host`] fails.
    ///
    /// # Examples
    ///
    /// ```
    /// # #![feature(try_from)]
    /// #
    /// use std::convert::TryFrom;
    /// use std::net::Ipv6Addr;
    ///
    /// use uriparse::{Authority, Host};
    ///
    /// let mut authority = Authority::try_from("example.com:8080").unwrap();
    /// authority.set_host("127.0.0.1");
    /// assert_eq!(authority.to_string(), "127.0.0.1:8080");
    /// authority.set_host(Host::IPv6Address("::1".parse().unwrap()));
    /// assert_eq!(authority.to_string(), "[::1]:8080");
    /// ```
    pub fn set_host<HostType, HostError>(
        &mut self,
        host: HostType,
    ) -> Result<&Host<'authority>, InvalidAuthority>
    where
        Host<'authority>: TryFrom<HostType, Error = HostError>,
        InvalidAuthority: From<HostError>,
    {
        self.host = Host::try_from(host)?;
        Ok(self.host())
    }

    /// Sets the password of the authority.
    ///
    /// An error will be returned if the conversion to a [`Password`] fails.
    ///
    /// If the given password is not `None`, then the username will be set to `""` if it is
    /// currently not set.
    ///
    /// # Examples
    ///
    /// ```
    /// # #![feature(try_from)]
    /// #
    /// use std::convert::TryFrom;
    ///
    /// use uriparse::Authority;
    ///
    /// let mut authority = Authority::try_from("example.com").unwrap();
    /// authority.set_password(Some("secret"));
    /// assert_eq!(authority.to_string(), ":secret@example.com");
    /// ```
    pub fn set_password<PasswordType, PasswordError>(
        &mut self,
        password: Option<PasswordType>,
    ) -> Result<Option<&Password<'authority>>, InvalidAuthority>
    where
        Password<'authority>: TryFrom<PasswordType, Error = PasswordError>,
        InvalidAuthority: From<PasswordError>,
    {
        self.password = match password {
            Some(password) => {
                let password = Password::try_from(password)?;

                if self.username.is_none() {
                    self.username = Some(Username(Cow::from("")));
                }

                Some(password)
            }
            None => None,
        };
        Ok(self.password())
    }

    /// Sets the port of the authority.
    ///
    /// # Examples
    ///
    /// ```
    /// # #![feature(try_from)]
    /// #
    /// use std::convert::TryFrom;
    ///
    /// use uriparse::Authority;
    ///
    /// let mut authority = Authority::try_from("example.com").unwrap();
    /// authority.set_port(Some(8080));
    /// assert_eq!(authority.to_string(), "example.com:8080");
    /// ```
    pub fn set_port(&mut self, port: Option<u16>) -> Option<u16> {
        self.port = port;
        self.port
    }

    /// Sets the username of the authority.
    ///
    /// An error will be returned if the conversion to a [`Username`] fails.
    ///
    /// If the given username is `None`, this will also remove any set password.
    ///
    /// # Examples
    ///
    /// ```
    /// # #![feature(try_from)]
    /// #
    /// use std::convert::TryFrom;
    ///
    /// use uriparse::{Authority, Username};
    ///
    /// let mut authority = Authority::try_from("example.com").unwrap();
    /// authority.set_username(Some("myname"));
    /// assert_eq!(authority.to_string(), "myname@example.com");
    ///
    /// let mut authority = Authority::try_from("user:pass@example.com").unwrap();
    /// authority.set_username(None::<Username>);
    /// assert_eq!(authority.to_string(), "example.com");
    /// ```
    pub fn set_username<UsernameType, UsernameError>(
        &mut self,
        username: Option<UsernameType>,
    ) -> Result<Option<&Username<'authority>>, InvalidAuthority>
    where
        Username<'authority>: TryFrom<UsernameType, Error = UsernameError>,
        InvalidAuthority: From<UsernameError>,
    {
        self.username = match username {
            Some(username) => Some(Username::try_from(username)?),
            None => {
                self.password = None;
                None
            }
        };
        Ok(self.username())
    }

    /// The username component of the authority as defined in
    /// [[RFC3986, Section 3.2.1](https://tools.ietf.org/html/rfc3986#section-3.2.1)].
    ///
    /// The username will be `None` if the user information component of the authority did not
    /// contain a `':'`. Otherwise, it will be whatever is after the `':'` until the `'@'`
    /// character. It may be empty as well.
    ///
    /// # Examples
    ///
    /// ```
    /// # #![feature(try_from)]
    /// #
    /// use std::convert::TryFrom;
    ///
    /// use uriparse::Authority;
    ///
    /// let authority = Authority::try_from("username:password@example.com").unwrap();
    /// assert_eq!(authority.password().unwrap(), "password");
    /// ```
    pub fn username(&self) -> Option<&Username<'authority>> {
        self.username.as_ref()
    }
}

impl<'authority> Display for Authority<'authority> {
    fn fmt(&self, formatter: &mut Formatter) -> fmt::Result {
        if let Some(ref username) = self.username {
            username.fmt(formatter)?;

            if let Some(ref password) = self.password {
                formatter.write_char(':')?;
                password.fmt(formatter)?;
            }

            formatter.write_char('@')?;
        }

        self.host.fmt(formatter)?;

        if let Some(port) = self.port {
            formatter.write_char(':')?;
            port.fmt(formatter)?;
        }

        Ok(())
    }
}

impl<'authority> From<Authority<'authority>> for String {
    fn from(value: Authority<'authority>) -> String {
        value.to_string()
    }
}

impl<'authority> TryFrom<&'authority [u8]> for Authority<'authority> {
    type Error = InvalidAuthority;

    fn try_from(value: &'authority [u8]) -> Result<Self, Self::Error> {
        let (authority, rest) = parse_authority(value)?;

        if rest.is_empty() {
            Ok(authority)
        } else {
            Err(InvalidAuthority::ExpectedEOF)
        }
    }
}

impl<'authority> TryFrom<&'authority str> for Authority<'authority> {
    type Error = InvalidAuthority;

    fn try_from(value: &'authority str) -> Result<Self, Self::Error> {
        Authority::try_from(value.as_bytes())
    }
}

/// The host component of the authority as defined in
/// [[RFC3986, Section 3.2.2](https://tools.ietf.org/html/rfc3986#section-3.2.2)].
///
/// The RFC mentions support for future IP address literals. Of course, as of this moment there
/// exist none, so hosts of the form `"[v*...]"` where `'*'` is a hexadecimal digit and `'...'` is the
/// actual IP literal are not considered valid.
///
/// Also, the host is case-insensitive meaning that `"example.com"` and `"ExAmPlE.CoM"` refer to the
/// same host. Furthermore, percent-encoding plays no role in equality checking meaning that
/// `"example.com"` and `"exampl%65.com"` also refer to the same host. Both of these attributes are
/// reflected in the equality and hash functions.
///
/// However, be aware that just because percent-encoding plays no role in equality checking does not
/// mean that the host is normalized. The original host string (in the case of a registered name)
/// will always be preserved as is with no normalization performed.
#[derive(Clone, Debug, Eq, Hash, PartialEq)]
pub enum Host<'host> {
    /// An IPv4 address. Based on the `std`'s implementation, leading zeros for octets are allowed
    /// for up to three digits. So for example, `"000.000.000.000"` is still considered a valid IPv4
    /// address, but `"000.000.000.0000"` is not. Thus, it would be considered a registered name.
    IPv4Address(Ipv4Addr),

    /// An IPv6 address. This will always be encased in brackets (`'['` and `']'`).
    IPv6Address(Ipv6Addr),

    /// Any other host that does not follow the syntax of an IP address. This includes even hosts of
    /// the form `"999.999.999.999"`. One might expect this to produce an invalid IPv4 error, but
    /// the RFC states that it is a "first-match-wins" algorithm, and that host does not match the
    /// IPv4 literal syntax.
    ///
    /// This may be changed in the future, since arguments can be made from either side.
    RegisteredName(RegisteredName<'host>),
}

impl<'host> Host<'host> {
    /// Returns whether or not the host is an IPv4 address.
    ///
    /// # Examples
    ///
    /// ```
    /// # #![feature(try_from)]
    /// #
    /// use std::convert::TryFrom;
    ///
    /// use uriparse::Host;
    ///
    /// let host = Host::try_from("192.168.1.1").unwrap();
    /// assert!(host.is_ipv4_address());
    /// ```
    pub fn is_ipv4_address(&self) -> bool {
        match self {
            Host::IPv4Address(_) => true,
            _ => false,
        }
    }

    /// Returns whether or not the host is an IPv6 address.
    ///
    /// # Examples
    ///
    /// ```
    /// # #![feature(try_from)]
    /// #
    /// use std::convert::TryFrom;
    ///
    /// use uriparse::Host;
    ///
    /// let host = Host::try_from("[::1]").unwrap();
    /// assert!(host.is_ipv6_address());
    /// ```
    pub fn is_ipv6_address(&self) -> bool {
        match self {
            Host::IPv6Address(_) => true,
            _ => false,
        }
    }

    /// Returns whether or not the host is a registered name.
    ///
    /// # Examples
    ///
    /// ```
    /// # #![feature(try_from)]
    /// #
    /// use std::convert::TryFrom;
    ///
    /// use uriparse::Host;
    ///
    /// let host = Host::try_from("example.com").unwrap();
    /// assert!(host.is_registered_name());
    /// ```
    pub fn is_registered_name(&self) -> bool {
        match self {
            Host::RegisteredName(_) => true,
            _ => false,
        }
    }
}

impl<'host> Display for Host<'host> {
    fn fmt(&self, formatter: &mut Formatter) -> fmt::Result {
        use self::Host::*;

        match self {
            IPv4Address(address) => address.fmt(formatter),
            IPv6Address(address) => {
                formatter.write_char('[')?;
                address.fmt(formatter)?;
                formatter.write_char(']')
            }
            RegisteredName(name) => formatter.write_str(name.as_str()),
        }
    }
}

impl<'host> From<Host<'host>> for String {
    fn from(value: Host<'host>) -> String {
        value.to_string()
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

impl From<Ipv4Addr> for Host<'static> {
    fn from(value: Ipv4Addr) -> Self {
        Host::IPv4Address(value)
    }
}

impl From<Ipv6Addr> for Host<'static> {
    fn from(value: Ipv6Addr) -> Self {
        Host::IPv6Address(value)
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
                            return Err(InvalidHost::AddressMechanismNotSupported);
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

                // Unsafe: The function above [`check_ipv6`] ensures this is valid ASCII implying
                // valid UTF-8.

                let ipv6: Ipv6Addr = unsafe { str::from_utf8_unchecked(ipv6) }
                    .parse()
                    .map_err(|_| InvalidHost::InvalidIPv6Format)?;
                Ok(Host::IPv6Address(ipv6))
            }
            _ => {
                if check_ipv4_or_registered_name(value) {
                    match unsafe { str::from_utf8_unchecked(value) }.parse() {
                        Ok(ipv4) => Ok(Host::IPv4Address(ipv4)),
                        Err(_) => {
                            // Unsafe: The function above [`check_ipv4_or_registered_name`] ensures
                            // this is valid ASCII implying valid UTF-8.

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

/// The password component of the authority as defined in
/// [[RFC3986, Section 3.2.1](https://tools.ietf.org/html/rfc3986#section-3.2.1)].
///
/// Even though this library supports parsing the password from the user information, it should be
/// noted that the format "username:password" is deprecated. Also, be careful logging this!
///
/// The password is case-sensitive. However, percent-encoding plays no role in equality checking
/// meaning that `"password"` and `"p%61ssword"` refer to the same password. Both of these
/// attributes are reflected in the equality and hash functions.
///
/// sBe aware that just because percent-encoding plays no role in equality checking does not
/// mean that the password is normalized. The original password string will always be preserved as
/// is with no normalization performed. You should perform percent-encoding normalization if you
/// want to use the password for any sort of authentication (not recommended).
#[derive(Clone, Debug)]
pub struct Password<'password>(Cow<'password, str>);

impl<'password> Password<'password> {
    /// Returns a `str` representation of the password.
    ///
    /// # Examples
    ///
    /// ```
    /// # #![feature(try_from)]
    /// #
    /// use std::convert::TryFrom;
    ///
    /// use uriparse::Password;
    ///
    /// let password = Password::try_from("password").unwrap();
    /// assert_eq!(password, "password");
    /// ```
    pub fn as_str(&self) -> &str {
        &self.0
    }

    /// Converts the [`Password`] into an owned copy.
    ///
    /// If you construct the authority from a source with a non-static lifetime, you may run into
    /// lifetime problems due to the way the struct is designed. Calling this function will ensure
    /// that the returned value has a static lifetime.
    ///
    /// This is different from just cloning. Cloning the password will just copy the references, and
    /// thus the lifetime will remain the same.
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

impl<'password> Display for Password<'password> {
    fn fmt(&self, formatter: &mut Formatter) -> fmt::Result {
        formatter.write_str(&self.0)
    }
}

impl<'password> Eq for Password<'password> {}

impl<'password> From<Password<'password>> for String {
    fn from(value: Password<'password>) -> String {
        value.to_string()
    }
}

impl<'password> Hash for Password<'password> {
    fn hash<H>(&self, state: &mut H)
    where
        H: Hasher,
    {
        percent_encoded_hash(self.0.as_bytes(), state, true);
    }
}

impl<'password> PartialEq for Password<'password> {
    fn eq(&self, other: &Password) -> bool {
        percent_encoded_equality(self.0.as_bytes(), other.0.as_bytes(), true)
    }
}

impl<'password> PartialEq<[u8]> for Password<'password> {
    fn eq(&self, other: &[u8]) -> bool {
        percent_encoded_equality(self.0.as_bytes(), other, true)
    }
}

impl<'password> PartialEq<Password<'password>> for [u8] {
    fn eq(&self, other: &Password<'password>) -> bool {
        percent_encoded_equality(self, other.0.as_bytes(), true)
    }
}

impl<'a, 'password> PartialEq<&'a [u8]> for Password<'password> {
    fn eq(&self, other: &&'a [u8]) -> bool {
        percent_encoded_equality(self.0.as_bytes(), other, true)
    }
}

impl<'a, 'password> PartialEq<Password<'password>> for &'a [u8] {
    fn eq(&self, other: &Password<'password>) -> bool {
        percent_encoded_equality(self, other.0.as_bytes(), true)
    }
}

impl<'password> PartialEq<str> for Password<'password> {
    fn eq(&self, other: &str) -> bool {
        percent_encoded_equality(self.0.as_bytes(), other.as_bytes(), true)
    }
}

impl<'password> PartialEq<Password<'password>> for str {
    fn eq(&self, other: &Password<'password>) -> bool {
        percent_encoded_equality(self.as_bytes(), other.0.as_bytes(), true)
    }
}

impl<'a, 'password> PartialEq<&'a str> for Password<'password> {
    fn eq(&self, other: &&'a str) -> bool {
        percent_encoded_equality(self.0.as_bytes(), other.as_bytes(), true)
    }
}

impl<'a, 'password> PartialEq<Password<'password>> for &'a str {
    fn eq(&self, other: &Password<'password>) -> bool {
        percent_encoded_equality(self.as_bytes(), other.0.as_bytes(), true)
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

/// A host that is a registered name (i.e. not an IP literal).
///
/// The host is case-insensitive meaning that `"example.com"` and `"ExAmPlE.CoM"` refer to the same
/// host. Furthermore, percent-encoding plays no role in equality checking meaning that
///`"example.com"` and `"exampl%65.com"` also refer to the same host. Both of these attributes are
/// reflected in the equality and hash functions.
///
/// However, be aware that just because percent-encoding plays no role in equality checking does not
/// mean that the host is normalized. The original host string will always be preserved as is with
/// no normalization performed.
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

impl<'name> From<RegisteredName<'name>> for String {
    fn from(value: RegisteredName<'name>) -> String {
        value.to_string()
    }
}

impl<'name> Hash for RegisteredName<'name> {
    fn hash<H>(&self, state: &mut H)
    where
        H: Hasher,
    {
        percent_encoded_hash(self.0.as_bytes(), state, false);
    }
}

impl<'name> PartialEq for RegisteredName<'name> {
    fn eq(&self, other: &RegisteredName) -> bool {
        percent_encoded_equality(self.0.as_bytes(), other.0.as_bytes(), false)
    }
}

impl<'name> PartialEq<[u8]> for RegisteredName<'name> {
    fn eq(&self, other: &[u8]) -> bool {
        percent_encoded_equality(self.0.as_bytes(), other, false)
    }
}

impl<'name> PartialEq<RegisteredName<'name>> for [u8] {
    fn eq(&self, other: &RegisteredName<'name>) -> bool {
        percent_encoded_equality(self, other.0.as_bytes(), false)
    }
}

impl<'a, 'name> PartialEq<&'a [u8]> for RegisteredName<'name> {
    fn eq(&self, other: &&'a [u8]) -> bool {
        percent_encoded_equality(self.0.as_bytes(), other, false)
    }
}

impl<'a, 'name> PartialEq<RegisteredName<'name>> for &'a [u8] {
    fn eq(&self, other: &RegisteredName<'name>) -> bool {
        percent_encoded_equality(self, other.0.as_bytes(), false)
    }
}

impl<'name> PartialEq<str> for RegisteredName<'name> {
    fn eq(&self, other: &str) -> bool {
        percent_encoded_equality(self.0.as_bytes(), other.as_bytes(), false)
    }
}

impl<'name> PartialEq<RegisteredName<'name>> for str {
    fn eq(&self, other: &RegisteredName<'name>) -> bool {
        percent_encoded_equality(self.as_bytes(), other.0.as_bytes(), false)
    }
}

impl<'a, 'name> PartialEq<&'a str> for RegisteredName<'name> {
    fn eq(&self, other: &&'a str) -> bool {
        percent_encoded_equality(self.0.as_bytes(), other.as_bytes(), false)
    }
}

impl<'a, 'name> PartialEq<RegisteredName<'name>> for &'a str {
    fn eq(&self, other: &RegisteredName<'name>) -> bool {
        percent_encoded_equality(self.as_bytes(), other.0.as_bytes(), false)
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

/// The username component of the authority as defined in
/// [[RFC3986, Section 3.2.1](https://tools.ietf.org/html/rfc3986#section-3.2.1)].
///
/// The username is case-sensitive. However, percent-encoding plays no role in equality checking
/// meaning that `"username"` and `"usern%61me"` refer to the same username. Both of these
/// attributes are reflected in the equality and hash functions.
///
/// Be aware that just because percent-encoding plays no role in equality checking does not
/// mean that the username is normalized. The original username string will always be preserved as
/// is with no normalization performed.
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

impl<'username> From<Username<'username>> for String {
    fn from(value: Username<'username>) -> String {
        value.to_string()
    }
}

impl<'username> Hash for Username<'username> {
    fn hash<H>(&self, state: &mut H)
    where
        H: Hasher,
    {
        percent_encoded_hash(self.0.as_bytes(), state, true);
    }
}

impl<'username> PartialEq for Username<'username> {
    fn eq(&self, other: &Username) -> bool {
        percent_encoded_equality(self.0.as_bytes(), other.0.as_bytes(), true)
    }
}

impl<'username> PartialEq<[u8]> for Username<'username> {
    fn eq(&self, other: &[u8]) -> bool {
        percent_encoded_equality(self.0.as_bytes(), other, true)
    }
}

impl<'username> PartialEq<Username<'username>> for [u8] {
    fn eq(&self, other: &Username<'username>) -> bool {
        percent_encoded_equality(self, other.as_bytes(), true)
    }
}

impl<'a, 'username> PartialEq<&'a [u8]> for Username<'username> {
    fn eq(&self, other: &&'a [u8]) -> bool {
        percent_encoded_equality(self.0.as_bytes(), other, true)
    }
}

impl<'a, 'username> PartialEq<Username<'username>> for &'a [u8] {
    fn eq(&self, other: &Username<'username>) -> bool {
        percent_encoded_equality(self, other.as_bytes(), true)
    }
}

impl<'username> PartialEq<str> for Username<'username> {
    fn eq(&self, other: &str) -> bool {
        percent_encoded_equality(self.0.as_bytes(), other.as_bytes(), true)
    }
}

impl<'username> PartialEq<Username<'username>> for str {
    fn eq(&self, other: &Username<'username>) -> bool {
        percent_encoded_equality(self.as_bytes(), other.0.as_bytes(), true)
    }
}

impl<'a, 'username> PartialEq<&'a str> for Username<'username> {
    fn eq(&self, other: &&'a str) -> bool {
        percent_encoded_equality(self.0.as_bytes(), other.as_bytes(), true)
    }
}

impl<'a, 'username> PartialEq<Username<'username>> for &'a str {
    fn eq(&self, other: &Username<'username>) -> bool {
        percent_encoded_equality(self.as_bytes(), other.0.as_bytes(), true)
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

/// An error representing an invalid authority.
#[derive(Clone, Copy, Debug, Eq, Hash, PartialEq)]
pub enum InvalidAuthority {
    /// This error occurs when the string from which the authority is parsed is not entirely
    /// consumed during the parsing. For example, parsing the string `"example.com/"` would generate
    /// this error since `"/"` would still be left over.
    ///
    /// This only applies to the [`Authority::try_from`] functions.
    ExpectedEOF,

    /// The host component of the authority was invalid.
    InvalidHost(InvalidHost),

    /// The port component of the authority was invalid.
    InvalidPort(InvalidPort),

    /// The user information component of the authority was invalid.
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
            ExpectedEOF => "expected end of file",
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

/// An error representing an invalid host.
#[derive(Clone, Copy, Debug, Eq, Hash, PartialEq)]
pub enum InvalidHost {
    /// The syntax for a future IP literal was used and is not currently supported.
    AddressMechanismNotSupported,

    /// An invalid character for an IPv4 address or registered name was used. Due to the ambiguity
    /// of the grammar, it is not possible to say which. It is also possible that all the characters
    /// were valid, but there was an invalid percent encoding (e.g. `"%ZZ"`).
    InvalidIPv4OrRegisteredNameCharacter,

    /// The syntax for an IPv6 literal was used (i.e. `"[...]"`) and all of the characters were
    /// valid IPv6 characters. However, the format of the literal was invalid.
    InvalidIPv6Format,

    /// The syntax for an IPv6 literal was used (i.e. `"[...]"`), but it contained an invalid IPv6
    /// character.
    InvalidIPv6Character,

    /// The syntax for a future IP literal was used (i.e. `"[v*...]"` where `"*"` is a hexadecimal
    /// digit), but it contained an invalid character.
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
            AddressMechanismNotSupported => "address mechanism not supported",
            InvalidIPv4OrRegisteredNameCharacter => "invalid IPv4 or registered name character",
            InvalidIPv6Format => "invalid IPv6 format",
            InvalidIPv6Character => "invalid IPv6 character",
            InvalidIPvFutureCharacter => "invalid IPvFuture character",
        }
    }
}

/// An error representing an invalid port.
#[derive(Clone, Copy, Debug, Eq, Hash, PartialEq)]
pub enum InvalidPort {
    /// An invalid character was used in the port. Only decimal digits are allowed.
    InvalidCharacter,

    /// The port was a valid number, but it was too large to fit in a `u16`.
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

/// An error representing an invalid registered name.
///
/// This implies that the registered name contained an invalid host character or had an invalid
/// percent encoding. This error is not possible from parsing an authority. It can only be returned
/// from directly parsing a registered name.
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

/// An error representing an invalid user information component.
#[derive(Clone, Copy, Debug, Eq, Hash, PartialEq)]
pub enum InvalidUserInfo {
    /// The user information contained an invalid character.
    InvalidCharacter,

    /// The user information contained an invalid percent encoding (e.g. `"%ZZ"`).
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

/// Returns true if the byte string contains only valid IPv4 or registered name characters. This
/// also ensures that percent encodings are valid.
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

/// Returns true if the byte string contains only valid IPv6 characters.
fn check_ipv6(value: &[u8]) -> bool {
    for &byte in value {
        if !byte.is_ascii_hexdigit() && byte != b':' {
            return false;
        }
    }

    true
}

/// Returns true if the byte string contains only valid future IP literal characters. This also
/// ensures that percent encodings are valid.
fn check_ipvfuture(value: &[u8]) -> bool {
    for &byte in value {
        match IPV_FUTURE_CHAR_MAP[byte as usize] {
            0 => return false,
            _ => (),
        }
    }

    true
}

/// Checks if the user information component contains valid characters and percent encodings. If so,
/// it will return an `Option<usize>` indicating the separator index for the username and password.
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

/// Parses the authority from the given byte string.
pub(crate) fn parse_authority<'authority>(
    value: &'authority [u8],
) -> Result<(Authority<'authority>, &'authority [u8]), InvalidAuthority> {
    let mut at_index = None;
    let mut last_colon_index = None;
    let mut end_index = value.len();

    for (index, &byte) in value.iter().enumerate() {
        match byte {
            b'@' => if at_index.is_none() {
                at_index = Some(index);
                last_colon_index = None;
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

/// Parses the port from the given byte string.
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

/// Parses the user information from the given byte string.
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

    // Unsafe: All uses of unsafe below have already been checked by [`check_user_info`] prior to
    // calling this function.

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
