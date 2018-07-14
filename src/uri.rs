use std::borrow::Cow;
use std::convert::TryFrom;
use std::fmt::{self, Display, Formatter, Write};

use authority::{parse_authority, Authority, Host, InvalidAuthority, Password, Username};
use fragment::{Fragment, InvalidFragment};
use path::{parse_path, InvalidPath, Path};
use query::{parse_query, InvalidQuery, Query};
use scheme::{parse_scheme, InvalidScheme, Scheme};

#[derive(Clone, Debug, Eq, Hash, PartialEq)]
pub struct URI<'uri> {
    uri_reference: URIReference<'uri>,
}

impl From<!> for InvalidURI {
    fn from(value: !) -> Self {
        value
    }
}

impl<'uri> URI<'uri> {
    pub fn authority(&self) -> Option<&Authority<'uri>> {
        self.authority.as_ref()
    }

    pub fn from_parts<
        'new_uri,
        SchemeType,
        AuthorityType,
        PathType,
        QueryType,
        FragmentType,
        SchemeError,
        AuthorityError,
        PathError,
        QueryError,
        FragmentError,
    >(
        scheme: SchemeType,
        authority: Option<AuthorityType>,
        path: PathType,
        query: Option<QueryType>,
        fragment: Option<FragmentType>,
    ) -> Result<URIReference<'new_uri>, InvalidURI>
    where
        Scheme<'new_uri>: TryFrom<SchemeType, Error = SchemeError>,
        Authority<'new_uri>: TryFrom<AuthorityType, Error = AuthorityError>,
        Path<'new_uri>: TryFrom<PathType, Error = PathError>,
        Query<'new_uri>: TryFrom<QueryType, Error = QueryError>,
        Fragment<'new_uri>: TryFrom<FragmentType, Error = FragmentError>,
        InvalidURIReference: From<SchemeError>
            + From<AuthorityError>
            + From<PathError>
            + From<QueryError>
            + From<FragmentError>,
    {
        let uri_reference =
            URIReference::from_parts(Some(scheme), authority, path, query, fragment)?;
        Ok(URI { uri_reference })
    }

    pub fn fragment(&self) -> Option<&Fragment<'uri>> {
        self.uri_reference.has_fragment()
    }

    pub fn has_authority(&self) -> bool {
        self.uri_reference.has_authority()
    }

    pub fn has_fragment(&self) -> bool {
        self.uri_reference.has_fragment()
    }

    pub fn has_password(&self) -> bool {
        self.uri_reference.has_password()
    }

    pub fn has_query(&self) -> bool {
        self.uri_reference.has_query()
    }

    pub fn has_username(&self) -> bool {
        self.uri_reference.has_username()
    }

    pub fn host(&self) -> Option<&Host<'uri>> {
        self.uri_reference.host()
    }

    pub fn into_parts(
        self,
    ) -> (
        Scheme<'uri>,
        Option<Authority<'uri>>,
        Path<'uri>,
        Option<Query<'uri>>,
        Option<Fragment<'uri>>,
    ) {
        let (scheme, authority, path, query, fragment) = self.uri_reference.into_parts();
        (scheme.unwrap(), authority, path, query, fragment)
    }

    pub fn path(&self) -> &Path<'uri> {
        self.uri_reference.path()
    }

    pub fn password(&self) -> Option<&Password<'uri>> {
        self.uri_reference.password()
    }

    pub fn port(&self) -> Option<u16> {
        self.uri_reference.port()
    }

    pub fn query(&self) -> Option<&Query<'uri>> {
        self.uri_reference.query()
    }

    pub fn scheme(&self) -> &Scheme<'uri> {
        self.uri_reference.scheme().unwrap()
    }

    pub fn username(&self) -> Option<&Username> {
        self.uri_reference.username()
    }
}

impl<'uri> Display for URI<'uri> {
    fn fmt(&self, formatter: &mut Formatter) -> fmt::Result {
        self.uri_reference.fmt(formatter)
    }
}

impl<'uri> PartialEq<str> for URI<'uri> {
    fn eq(&self, other: &str) -> bool {
        self.uri_reference == other
    }
}

impl<'uri> PartialEq<URI<'uri>> for str {
    fn eq(&self, other: &URI<'uri>) -> bool {
        self == other.uri_reference
    }
}

impl<'a, 'uri> PartialEq<&'a str> for URI<'uri> {
    fn eq(&self, other: &&'a str) -> bool {
        self.uri_reference == *other
    }
}

impl<'a, 'uri> PartialEq<URI<'uri>> for &'a str {
    fn eq(&self, other: &URI<'uri>) -> bool {
        *self == other.uri_reference
    }
}

impl<'uri> TryFrom<&'uri [u8]> for URI<'uri> {
    type Error = InvalidURI;

    fn try_from(value: &'uri [u8]) -> Result<Self, Self::Error> {
        let uri_reference = URIReference::try_from(value)?;

        if uri_reference.is_relative_reference() {
            Err(InvalidURI::CannotBeRelativeReference)
        } else {
            Ok(URI { uri_reference })
        }
    }
}

impl<'uri> TryFrom<&'uri str> for URI<'uri> {
    type Error = InvalidURI;

    fn try_from(value: &'uri str) -> Result<Self, Self::Error> {
        URI::try_from(value.as_bytes())
    }
}

#[derive(Clone, Debug, Eq, Hash, PartialEq)]
pub struct URIReference<'uri> {
    authority: Option<Authority<'uri>>,
    fragment: Option<Fragment<'uri>>,
    path: Path<'uri>,
    query: Option<Query<'uri>>,
    scheme: Option<Scheme<'uri>>,
}

impl From<!> for InvalidURIReference {
    fn from(value: !) -> Self {
        value
    }
}

impl<'uri> URIReference<'uri> {
    pub fn authority(&self) -> Option<&Authority<'uri>> {
        self.authority.as_ref()
    }

    pub fn from_parts<
        'new_uri,
        SchemeType,
        AuthorityType,
        PathType,
        QueryType,
        FragmentType,
        SchemeError,
        AuthorityError,
        PathError,
        QueryError,
        FragmentError,
    >(
        scheme: Option<SchemeType>,
        authority: Option<AuthorityType>,
        path: PathType,
        query: Option<QueryType>,
        fragment: Option<FragmentType>,
    ) -> Result<URIReference<'new_uri>, InvalidURIReference>
    where
        Scheme<'new_uri>: TryFrom<SchemeType, Error = SchemeError>,
        Authority<'new_uri>: TryFrom<AuthorityType, Error = AuthorityError>,
        Path<'new_uri>: TryFrom<PathType, Error = PathError>,
        Query<'new_uri>: TryFrom<QueryType, Error = QueryError>,
        Fragment<'new_uri>: TryFrom<FragmentType, Error = FragmentError>,
        InvalidURIReference: From<SchemeError>
            + From<AuthorityError>
            + From<PathError>
            + From<QueryError>
            + From<FragmentError>,
    {
        let scheme = match scheme {
            Some(scheme) => Some(Scheme::try_from(scheme)?),
            None => None,
        };

        let authority = match authority {
            Some(authority) => Some(Authority::try_from(authority)?),
            None => None,
        };

        let path = Path::try_from(path)?;

        if scheme.is_some()
            && authority.is_none()
            && path.segments().len() > 1
            && path.segments().first().unwrap().is_empty()
        {
            return Err(InvalidURIReference::AbsolutePathCannotStartWithTwoSlashes);
        }

        if scheme.is_none() && authority.is_none()
            && path
                .segments()
                .first()
                .unwrap()
                .bytes()
                .any(|byte| byte == b':')
        {
            return Err(InvalidURIReference::SchemelessPathCannotStartWithColonSegment);
        }

        let query = match query {
            Some(query) => Some(Query::try_from(query)?),
            None => None,
        };

        let fragment = match fragment {
            Some(fragment) => Some(Fragment::try_from(fragment)?),
            None => None,
        };

        Ok(URIReference {
            authority,
            fragment,
            path,
            query,
            scheme,
        })
    }

    pub fn fragment(&self) -> Option<&Fragment<'uri>> {
        self.fragment.as_ref()
    }

    pub fn has_authority(&self) -> bool {
        self.authority.is_some()
    }

    pub fn has_fragment(&self) -> bool {
        self.fragment.is_some()
    }

    pub fn has_password(&self) -> bool {
        if let Some(ref authority) = self.authority {
            authority.has_password()
        } else {
            false
        }
    }

    pub fn has_query(&self) -> bool {
        self.query.is_some()
    }

    pub fn has_username(&self) -> bool {
        if let Some(ref authority) = self.authority {
            authority.has_username()
        } else {
            false
        }
    }

    pub fn host(&self) -> Option<&Host<'uri>> {
        if let Some(ref authority) = self.authority {
            Some(authority.host())
        } else {
            None
        }
    }

    pub fn into_parts(
        self,
    ) -> (
        Option<Scheme<'uri>>,
        Option<Authority<'uri>>,
        Path<'uri>,
        Option<Query<'uri>>,
        Option<Fragment<'uri>>,
    ) {
        (
            self.scheme,
            self.authority,
            self.path,
            self.query,
            self.fragment,
        )
    }

    pub fn is_absolute(&self) -> bool {
        self.scheme.is_some()
    }

    pub fn is_absolute_path_reference(&self) -> bool {
        self.scheme.is_none() && self.authority.is_none() && self.path.is_absolute()
    }

    pub fn is_network_path_reference(&self) -> bool {
        self.scheme.is_none() && self.authority.is_some()
    }

    pub fn is_relative_path_reference(&self) -> bool {
        self.scheme.is_none() && self.authority.is_none() && !self.path.is_absolute()
    }

    pub fn is_relative_reference(&self) -> bool {
        self.scheme.is_none()
    }

    pub fn is_same_document_reference<'other_uri>(&self, other: &URIReference<'other_uri>) -> bool {
        self.scheme == other.scheme
            && self.authority == other.authority
            && self.path == other.path
            && self.query == other.query
    }

    pub fn path(&self) -> &Path<'uri> {
        &self.path
    }

    pub fn password(&self) -> Option<&Password<'uri>> {
        if let Some(ref authority) = self.authority {
            authority.password()
        } else {
            None
        }
    }

    pub fn port(&self) -> Option<u16> {
        if let Some(ref authority) = self.authority {
            authority.port()
        } else {
            None
        }
    }

    pub fn query(&self) -> Option<&Query<'uri>> {
        self.query.as_ref()
    }

    pub fn scheme(&self) -> Option<&Scheme<'uri>> {
        self.scheme.as_ref()
    }

    pub fn username(&self) -> Option<&Username> {
        if let Some(ref authority) = self.authority {
            authority.username()
        } else {
            None
        }
    }
}

impl<'uri> Display for URIReference<'uri> {
    fn fmt(&self, formatter: &mut Formatter) -> fmt::Result {
        if let Some(ref scheme) = self.scheme {
            formatter.write_str(scheme.as_str())?;
            formatter.write_char(':')?;
        }

        if let Some(ref authority) = self.authority {
            formatter.write_str("//")?;
            formatter.write_str(&authority.to_string())?;
        }

        formatter.write_str(&self.path.to_string())?;

        if let Some(ref query) = self.query {
            formatter.write_char('?')?;
            formatter.write_str(query.as_str())?;
        }

        if let Some(ref fragment) = self.fragment {
            formatter.write_char('#')?;
            formatter.write_str(fragment.as_str())?;
        }

        Ok(())
    }
}

impl<'uri> PartialEq<str> for URIReference<'uri> {
    fn eq(&self, other: &str) -> bool {
        let uri_reference = match URIReference::try_from(other) {
            Ok(uri_reference) => uri_reference,
            Err(_) => return false,
        };

        *self == uri_reference
    }
}

impl<'uri> PartialEq<URIReference<'uri>> for str {
    fn eq(&self, other: &URIReference<'uri>) -> bool {
        let uri_reference = match URIReference::try_from(self) {
            Ok(uri_reference) => uri_reference,
            Err(_) => return false,
        };

        uri_reference == *other
    }
}

impl<'a, 'uri> PartialEq<&'a str> for URIReference<'uri> {
    fn eq(&self, other: &&'a str) -> bool {
        let uri_reference = match URIReference::try_from(*other) {
            Ok(uri_reference) => uri_reference,
            Err(_) => return false,
        };

        *self == uri_reference
    }
}

impl<'a, 'uri> PartialEq<URIReference<'uri>> for &'a str {
    fn eq(&self, other: &URIReference<'uri>) -> bool {
        let uri_reference = match URIReference::try_from(*self) {
            Ok(uri_reference) => uri_reference,
            Err(_) => return false,
        };

        uri_reference == *other
    }
}

impl<'uri> TryFrom<&'uri [u8]> for URIReference<'uri> {
    type Error = InvalidURIReference;

    fn try_from(value: &'uri [u8]) -> Result<Self, Self::Error> {
        let (scheme, value) = match parse_scheme(value) {
            Ok((scheme, rest)) => if rest.starts_with(b":") {
                (Some(scheme), &rest[1..])
            } else {
                (None, value)
            },
            _ => (None, value),
        };

        let (authority, value) = match value.get(0..2) {
            Some(b"//") => {
                let (authority, value) = parse_authority(&value[2..])?;
                (Some(authority), value)
            }
            _ => (None, value),
        };

        let (mut path, value) = parse_path(value)?;

        if authority.is_some() {
            path.set_absolute(true);
        }

        let (query, value) = if value.starts_with(b"?") {
            let (query, value) = parse_query(&value[1..])?;
            (Some(query), value)
        } else {
            (None, value)
        };

        let fragment = if value.starts_with(b"#") {
            Some(Fragment::try_from(&value[1..])?)
        } else {
            None
        };

        Ok(URIReference {
            authority,
            fragment,
            path,
            query,
            scheme,
        })
    }
}

impl<'uri> TryFrom<&'uri str> for URIReference<'uri> {
    type Error = InvalidURIReference;

    fn try_from(value: &'uri str) -> Result<Self, Self::Error> {
        URIReference::try_from(value.as_bytes())
    }
}

#[derive(Clone, Debug, Eq, Hash, PartialEq)]
pub enum InvalidURI {
    CannotBeRelativeReference,
    InvalidAuthority(InvalidAuthority),
    InvalidFragment(InvalidFragment),
    InvalidPath(InvalidPath),
    InvalidQuery(InvalidQuery),
    InvalidScheme(InvalidScheme),
}

impl Display for InvalidURI {
    fn fmt(&self, formatter: &mut Formatter) -> fmt::Result {
        formatter.write_str(self.description())
    }
}

impl Error for InvalidURI {
    fn description(&self) -> &str {
        use self::InvalidURI::*;

        match self {
            CannotBeRelativeReference => "cannot be relative reference",
            InvalidAuthority(invalid_authority) => invalid_authority.description(),
            InvalidFragment(invalid_fragment) => invalid_fragment.description(),
            InvalidPath(invalid_path) => invalid_path.description(),
            InvalidQuery(invalid_query) => invalid_query.description(),
            InvalidScheme(invalid_scheme) => invalid_scheme.description(),
        }
    }
}

impl TryFrom<InvalidURIReference> for InvalidURI {
    type Error = ();

    fn try_from(value: InvalidURIReference) -> Result<Self, Self::Error> {
        use self::InvalidURI::*;

        match value {
            InvalidURIReference::AbsolutePathCannotStartWithTwoSlashes
            | InvalidURIReference::SchemelessPathCannotStartWithColonSegment => Err(()),
            InvalidURIReference::InvalidAuthority(invalid_authority) => {
                InvalidAuthority(invalid_authority)
            }
            InvalidURIReference::InvalidFragment(invalid_fragment) => {
                InvalidFragment(invalid_fragment)
            }
            InvalidURIReference::InvalidPath(invalid_path) => Ok(InvalidPath(invalid_path)),
            InvalidURIReference::InvalidQuery(invalid_query) => Ok(InvalidQuery(invalid_query)),
            InvalidURIReference::InvalidScheme(invalid_scheme) => Ok(InvalidScheme(invalid_scheme)),
        }
    }
}

#[derive(Clone, Debug, Eq, Hash, PartialEq)]
pub enum InvalidURIReference {
    AbsolutePathCannotStartWithTwoSlashes,
    SchemelessPathCannotStartWithColonSegment,
    InvalidAuthority(InvalidAuthority),
    InvalidFragment(InvalidFragment),
    InvalidPath(InvalidPath),
    InvalidQuery(InvalidQuery),
    InvalidScheme(InvalidScheme),
}

impl Display for InvalidURIReference {
    fn fmt(&self, formatter: &mut Formatter) -> fmt::Result {
        formatter.write_str(self.description())
    }
}

impl Error for InvalidURIReference {
    fn description(&self) -> &str {
        use self::InvalidURIReference::*;

        match self {
            AbsolutePathCannotStartWithTwoSlashes => "absolute path cannot start with two slashes",
            SchemelessPathCannotStartWithColonSegment => {
                "schemeless path cannot start with colon segment"
            }
            InvalidAuthority(invalid_authority) => invalid_authority.description(),
            InvalidFragment(invalid_fragment) => invalid_fragment.description(),
            InvalidPath(invalid_path) => invalid_path.description(),
            InvalidQuery(invalid_query) => invalid_query.description(),
            InvalidScheme(invalid_scheme) => invalid_scheme.description(),
        }
    }
}

impl From<InvalidAuthority> for InvalidURIReference {
    fn from(value: InvalidAuthority) -> Self {
        InvalidURIReference::InvalidAuthority(value)
    }
}

impl From<InvalidFragment> for InvalidURIReference {
    fn from(value: InvalidFragment) -> Self {
        InvalidURIReference::InvalidFragment(value)
    }
}

impl From<InvalidPath> for InvalidURIReference {
    fn from(value: InvalidPath) -> Self {
        InvalidURIReference::InvalidPath(value)
    }
}

impl From<InvalidQuery> for InvalidURIReference {
    fn from(value: InvalidQuery) -> Self {
        InvalidURIReference::InvalidQuery(value)
    }
}

impl From<InvalidScheme> for InvalidURIReference {
    fn from(value: InvalidScheme) -> Self {
        InvalidURIReference::InvalidScheme(value)
    }
}

#[cfg(test)]
mod test {
    use super::*;

    use authority::Host;

    #[test]
    fn test_parse_uri_reference() {
        let actual = URIReference::try_from("http://example.com").unwrap();
        let expected = URIReference::from_parts(
            Some(Scheme::HTTP),
            Some("example.com"),
            "/",
            None::<&str>,
            None::<&str>,
        ).unwrap();
        assert_eq!(actual, expected);

        let actual = URIReference::try_from("http://example.com/").unwrap();
        let expected = URIReference::from_parts(
            Some(Scheme::HTTP),
            Some("example.com"),
            "/",
            None::<&str>,
            None::<&str>,
        ).unwrap();
        assert_eq!(actual, expected);

        let actual = URIReference::try_from("http:").unwrap();
        let expected = URIReference::from_parts(
            Some(Scheme::HTTP),
            None::<Authority>,
            "",
            None::<Query>,
            None::<Fragment>,
        ).unwrap();
        assert_eq!(actual, expected);

        let actual = URIReference::try_from("http:/").unwrap();
        let expected = URIReference::from_parts(
            Some(Scheme::HTTP),
            None::<Authority>,
            "/",
            None::<Query>,
            None::<Fragment>,
        ).unwrap();
        assert_eq!(actual, expected);

        let actual = URIReference::try_from("http:/path").unwrap();
        let expected = URIReference::from_parts(
            Some(Scheme::HTTP),
            None::<Authority>,
            "/path",
            None::<Query>,
            None::<Fragment>,
        ).unwrap();
        assert_eq!(actual, expected);

        let actual = URIReference::try_from("//example.com/").unwrap();
        let expected = URIReference::from_parts(
            None::<Scheme>,
            Some("example.com"),
            "/",
            None::<Query>,
            None::<Fragment>,
        ).unwrap();
        assert_eq!(actual, expected);

        let actual = URIReference::try_from("").unwrap();
        let expected = URIReference::from_parts(
            None::<Scheme>,
            None::<Authority>,
            "",
            None::<Query>,
            None::<Fragment>,
        ).unwrap();
        assert_eq!(actual, expected);

        let actual = URIReference::try_from("*").unwrap();
        let expected = URIReference::from_parts(
            None::<Scheme>,
            None::<Authority>,
            "*",
            None::<Query>,
            None::<Fragment>,
        ).unwrap();
        assert_eq!(actual, expected);

        let actual = URIReference::try_from("/").unwrap();
        let expected = URIReference::from_parts(
            None::<Scheme>,
            None::<Authority>,
            "/",
            None::<Query>,
            None::<Fragment>,
        ).unwrap();
        assert_eq!(actual, expected);

        let actual = URIReference::try_from("test/path").unwrap();
        let expected = URIReference::from_parts(
            None::<Scheme>,
            None::<Authority>,
            "test/path",
            None::<Query>,
            None::<Fragment>,
        ).unwrap();
        assert_eq!(actual, expected);
    }
}
