use std::convert::{Infallible, TryFrom};
use std::error::Error;
use std::fmt::{self, Display, Formatter, Write};
use std::mem;

use crate::authority::{parse_authority, Authority, Host, InvalidAuthority, Password, Username};
use crate::fragment::{Fragment, InvalidFragment};
use crate::path::{parse_path, InvalidPath, Path};
use crate::query::{parse_query, InvalidQuery, Query};
use crate::scheme::{parse_scheme, InvalidScheme, Scheme};

/// A URI reference as defined in
/// [[RFC3986, Section 4.1]](https://tools.ietf.org/html/rfc3986#section-4.1).
///
/// Specifically, a URI reference is either a URI or a relative reference (a schemeless URI).
#[derive(Clone, Debug, Eq, Hash, PartialEq)]
pub struct URIReference<'uri> {
    /// The authority component of the URI reference as defined in
    /// [[RFC3986, Section 3.2]](https://tools.ietf.org/html/rfc3986#section-3.2).
    authority: Option<Authority<'uri>>,

    /// The fragment component of the URI reference as defined in
    /// [[RFC3986, Section 3.5]](https://tools.ietf.org/html/rfc3986#section-3.5).
    fragment: Option<Fragment<'uri>>,

    /// The path component of the URI reference as defined in
    /// [[RFC3986, Section 3.3]](https://tools.ietf.org/html/rfc3986#section-3.3).
    path: Path<'uri>,

    /// The query component of the URI reference as defined in
    /// [[RFC3986, Section 3.4]](https://tools.ietf.org/html/rfc3986#section-3.4).
    query: Option<Query<'uri>>,

    /// The scheme component of the URI reference as defined in
    /// [[RFC3986, Section 3.1](https://tools.ietf.org/html/rfc3986#section-3.1).
    scheme: Option<Scheme<'uri>>,
}

impl<'uri> URIReference<'uri> {
    /// Returns the authority, if present, of the URI reference.
    ///
    /// # Examples
    ///
    /// ```
    /// use std::convert::TryFrom;
    ///
    /// use uriparse::URIReference;
    ///
    /// let reference = URIReference::try_from("//example.com/my/path").unwrap();
    /// assert_eq!(reference.authority().unwrap().to_string(), "example.com");
    /// ```
    pub fn authority(&self) -> Option<&Authority<'uri>> {
        self.authority.as_ref()
    }

    /// Constructs a default builder for a URI reference.
    ///
    /// This provides an alternative means of constructing a URI reference besides parsing and
    /// [`URIReference::from_parts`].
    ///
    /// # Examples
    ///
    /// ```
    /// use uriparse::URIReference;
    ///
    /// let mut builder = URIReference::builder();
    /// builder.scheme(Some("http")).authority(Some("example.com")).path("/my/path");
    /// let reference = builder.build().unwrap();
    /// assert_eq!(reference.to_string(), "http://example.com/my/path");
    /// ```
    pub fn builder<'new_uri>() -> URIReferenceBuilder<'new_uri> {
        URIReferenceBuilder::default()
    }

    /// Returns whether the URI reference can act as a base URI.
    ///
    /// A URI can be a base if it is absolute (i.e. it has no fragment component).
    ///
    /// # Examples
    ///
    /// ```
    /// use std::convert::TryFrom;
    ///
    /// use uriparse::URIReference;
    ///
    /// let reference = URIReference::try_from("http://example.com/my/path").unwrap();
    /// assert!(reference.can_be_a_base());
    ///
    /// let reference = URIReference::try_from("ftp://127.0.0.1#fragment").unwrap();
    /// assert!(!reference.can_be_a_base());
    /// ```
    pub fn can_be_a_base(&self) -> bool {
        self.has_scheme() && !self.has_fragment()
    }

    /// Constructs a new [`URIReference`] from the individual parts: scheme, authority, path, query,
    /// and fragment.
    ///
    /// The lifetime used by the resulting value will be the lifetime of the part that is most
    /// restricted in scope.
    ///
    /// # Examples
    ///
    /// ```
    /// use std::convert::TryFrom;
    ///
    /// use uriparse::{Scheme, URIReference};
    ///
    /// let reference = URIReference::from_parts(
    ///     None::<Scheme>,
    ///     Some("example.com"),
    ///     "/my/path",
    ///     Some("query"),
    ///     Some("fragment")
    /// ).unwrap();
    /// assert_eq!(reference.to_string(), "//example.com/my/path?query#fragment");
    /// ```
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

        let mut path = Path::try_from(path)?;

        if authority.is_some() {
            path.set_absolute(true);
        }

        validate_absolute_path(authority.as_ref(), &path)?;
        validate_schemeless_path(scheme.as_ref(), authority.as_ref(), &path)?;

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

    /// Returns the fragment, if present, of the URI reference.
    ///
    /// # Examples
    ///
    /// ```
    /// use std::convert::TryFrom;
    ///
    /// use uriparse::URIReference;
    ///
    /// let reference = URIReference::try_from("http://example.com#fragment").unwrap();
    /// assert_eq!(reference.fragment().unwrap(), "fragment");
    /// ```
    pub fn fragment(&self) -> Option<&Fragment<'uri>> {
        self.fragment.as_ref()
    }

    /// Returns whether the URI reference has an authority component.
    ///
    /// # Examples
    ///
    /// ```
    /// use std::convert::TryFrom;
    ///
    /// use uriparse::URIReference;
    ///
    /// let reference = URIReference::try_from("http://example.com").unwrap();
    /// assert!(reference.has_authority());
    ///
    /// let reference = URIReference::try_from("").unwrap();
    /// assert!(!reference.has_authority());
    /// ```
    pub fn has_authority(&self) -> bool {
        self.authority.is_some()
    }

    /// Returns whether the URI reference has a fragment component.
    ///
    /// # Examples
    ///
    /// ```
    /// use std::convert::TryFrom;
    ///
    /// use uriparse::URIReference;
    ///
    /// let reference = URIReference::try_from("#test").unwrap();
    /// assert!(reference.has_fragment());
    ///
    /// let reference = URIReference::try_from("http://example.com").unwrap();
    /// assert!(!reference.has_fragment());
    /// ```
    pub fn has_fragment(&self) -> bool {
        self.fragment.is_some()
    }

    /// Returns whether the URI reference has a password component.
    ///
    /// # Examples
    ///
    /// ```
    /// use std::convert::TryFrom;
    ///
    /// use uriparse::URIReference;
    ///
    /// let reference = URIReference::try_from("http://user:pass@127.0.0.1").unwrap();
    /// assert!(reference.has_password());
    ///
    /// let reference = URIReference::try_from("http://user@127.0.0.1").unwrap();
    /// assert!(!reference.has_password());
    /// ```
    pub fn has_password(&self) -> bool {
        if let Some(ref authority) = self.authority {
            authority.has_password()
        } else {
            false
        }
    }

    /// Returns whether the URI reference has a port.
    ///
    /// # Examples
    ///
    /// ```
    /// use std::convert::TryFrom;
    ///
    /// use uriparse::URIReference;
    ///
    /// let reference = URIReference::try_from("http://127.0.0.1:8080").unwrap();
    /// assert!(reference.has_port());
    ///
    /// let reference = URIReference::try_from("http://127.0.0.1").unwrap();
    /// assert!(!reference.has_port());
    /// ```
    pub fn has_port(&self) -> bool {
        if let Some(ref authority) = self.authority {
            authority.has_port()
        } else {
            false
        }
    }

    /// Returns whether the URI reference has a query component.
    ///
    /// # Examples
    ///
    /// ```
    /// use std::convert::TryFrom;
    ///
    /// use uriparse::URIReference;
    ///
    /// let reference = URIReference::try_from("/?my=query").unwrap();
    /// assert!(reference.has_query());
    ///
    /// let reference = URIReference::try_from("http://example.com/my/path").unwrap();
    /// assert!(!reference.has_query());
    /// ```
    pub fn has_query(&self) -> bool {
        self.query.is_some()
    }

    /// Returns whether the URI reference has a scheme component.
    ///
    /// # Examples
    ///
    /// ```
    /// use std::convert::TryFrom;
    ///
    /// use uriparse::URIReference;
    ///
    /// let reference = URIReference::try_from("http://example.com?my=query").unwrap();
    /// assert!(reference.has_scheme());
    ///
    /// let reference = URIReference::try_from("/my/path").unwrap();
    /// assert!(!reference.has_scheme());
    /// ```
    pub fn has_scheme(&self) -> bool {
        self.scheme.is_some()
    }

    /// Returns whether the URI reference has a username component.
    ///
    /// # Examples
    ///
    /// ```
    /// use std::convert::TryFrom;
    ///
    /// use uriparse::URIReference;
    ///
    /// let reference = URIReference::try_from("//username@example.com").unwrap();
    /// assert!(reference.has_username());
    ///
    /// let reference = URIReference::try_from("http://example.com").unwrap();
    /// assert!(!reference.has_username());
    /// ```
    pub fn has_username(&self) -> bool {
        if let Some(ref authority) = self.authority {
            authority.has_username()
        } else {
            false
        }
    }

    /// Returns the host, if present, of the URI reference.
    ///
    /// # Examples
    ///
    /// ```
    /// use std::convert::TryFrom;
    ///
    /// use uriparse::URIReference;
    ///
    /// let reference = URIReference::try_from("http://username@example.com").unwrap();
    /// assert_eq!(reference.host().unwrap().to_string(), "example.com");
    /// ```
    pub fn host(&self) -> Option<&Host<'uri>> {
        if let Some(ref authority) = self.authority {
            Some(authority.host())
        } else {
            None
        }
    }

    /// Consumes the URI reference and converts it into a builder with the same values.
    ///
    /// # Examples
    ///
    /// ```
    /// use std::convert::TryFrom;
    ///
    /// use uriparse::{Fragment, Query, URIReference};
    ///
    /// let reference = URIReference::try_from("//example.com/path?query#fragment").unwrap();
    /// let mut builder = reference.into_builder();
    /// builder.query(None::<Query>).fragment(None::<Fragment>);
    /// let reference = builder.build().unwrap();
    /// assert_eq!(reference.to_string(), "//example.com/path");
    /// ```
    pub fn into_builder(self) -> URIReferenceBuilder<'uri> {
        let mut builder = URIReferenceBuilder::new();
        builder
            .scheme(self.scheme)
            .authority(self.authority)
            .path(self.path)
            .query(self.query)
            .fragment(self.fragment);
        builder
    }

    /// Converts the [`URIReference`] into an owned copy.
    ///
    /// If you construct the URI reference from a source with a non-static lifetime, you may run
    /// into lifetime problems due to the way the struct is designed. Calling this function will
    /// ensure that the returned value has a static lifetime.
    ///
    /// This is different from just cloning. Cloning the URI reference will just copy the
    /// references, and thus the lifetime will remain the same.
    pub fn into_owned(self) -> URIReference<'static> {
        let scheme = self.scheme.map(|scheme| scheme.into_owned());
        let authority = self.authority.map(|authority| authority.into_owned());
        let path = self.path.into_owned();
        let query = self.query.map(|query| query.into_owned());
        let fragment = self.fragment.map(|fragment| fragment.into_owned());

        URIReference {
            authority,
            fragment,
            path,
            query,
            scheme,
        }
    }

    /// Consumes the [`URIReference`] and returns its parts: scheme, authority, path, query, and
    /// fragment.
    ///
    /// # Examples
    ///
    /// ```
    /// use std::convert::TryFrom;
    ///
    /// use uriparse::URIReference;
    ///
    /// let reference = URIReference::try_from(
    ///     "http://username:password@example.com:80/my/path?my=query#fragment",
    /// ).unwrap();
    /// let (scheme, authority, path, query, fragment) = reference.into_parts();
    ///
    /// assert_eq!(scheme.unwrap(), "http");
    /// assert_eq!(authority.unwrap().to_string(), "username:password@example.com:80");
    /// assert_eq!(path, "/my/path");
    /// assert_eq!(query.unwrap(), "my=query");
    /// assert_eq!(fragment.unwrap(), "fragment");
    /// ```
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

    /// Returns whether the URI reference is an absolute path reference.
    ///
    /// A URI reference is an absolute path reference if it is a relative reference that begins with
    /// a single `'/'`.
    ///
    /// # Examples
    ///
    /// ```
    /// use std::convert::TryFrom;
    ///
    /// use uriparse::URIReference;
    ///
    /// let reference = URIReference::try_from("/my/path").unwrap();
    /// assert!(reference.is_absolute_path_reference());
    /// ```
    pub fn is_absolute_path_reference(&self) -> bool {
        self.scheme.is_none() && self.authority.is_none() && self.path.is_absolute()
    }

    /// Returns whether the URI reference is a network path reference.
    ///
    /// A URI reference is a network path reference if it is a relative reference that begins with
    /// two `'/'`.
    ///
    /// # Examples
    ///
    /// ```
    /// use std::convert::TryFrom;
    ///
    /// use uriparse::URIReference;
    ///
    /// let reference = URIReference::try_from("//example.com").unwrap();
    /// assert!(reference.is_network_path_reference());
    /// ```
    pub fn is_network_path_reference(&self) -> bool {
        self.scheme.is_none() && self.authority.is_some()
    }

    /// Returns whether the URI reference is normalized.
    ///
    /// A normalized URI reference will have all of its components normalized.
    ///
    /// # Examples
    ///
    /// ```
    /// use std::convert::TryFrom;
    ///
    /// use uriparse::URIReference;
    ///
    /// let reference = URIReference::try_from("http://example.com/?a=b").unwrap();
    /// assert!(reference.is_normalized());
    ///
    /// let mut reference = URIReference::try_from("http://EXAMPLE.com/?a=b").unwrap();
    /// assert!(!reference.is_normalized());
    /// reference.normalize();
    /// assert!(reference.is_normalized());
    /// ```
    pub fn is_normalized(&self) -> bool {
        if let Some(scheme) = self.scheme.as_ref() {
            if !scheme.is_normalized() {
                return false;
            }
        }

        if let Some(authority) = self.authority.as_ref() {
            if !authority.is_normalized() {
                return false;
            }
        }

        if !self.path.is_normalized(self.scheme.is_none()) {
            return false;
        }

        if let Some(query) = self.query.as_ref() {
            if !query.is_normalized() {
                return false;
            }
        }

        if let Some(fragment) = self.fragment.as_ref() {
            if !fragment.is_normalized() {
                return false;
            }
        }

        true
    }

    /// Returns whether the URI reference is a relative path reference.
    ///
    /// A URI reference is a relative path reference if it is a relative reference that does not
    /// begin with a `'/'`.
    ///
    /// # Examples
    ///
    /// ```
    /// use std::convert::TryFrom;
    ///
    /// use uriparse::URIReference;
    ///
    /// let reference = URIReference::try_from("my/path").unwrap();
    /// assert!(reference.is_relative_path_reference());
    /// ```
    pub fn is_relative_path_reference(&self) -> bool {
        self.scheme.is_none() && self.authority.is_none() && !self.path.is_absolute()
    }

    /// Returns whether the URI reference is a relative reference.
    ///
    /// A URI reference is a relative reference if it has no scheme.
    ///
    /// # Examples
    ///
    /// ```
    /// use std::convert::TryFrom;
    ///
    /// use uriparse::URIReference;
    ///
    /// let reference = URIReference::try_from("/my/path").unwrap();
    /// assert!(reference.is_relative_reference());
    /// ```
    pub fn is_relative_reference(&self) -> bool {
        self.scheme.is_none()
    }

    /// Returns whether the URI reference is a URI.
    ///
    /// A URI reference is a URI if it has a scheme.
    ///
    /// # Examples
    ///
    /// ```
    /// use std::convert::TryFrom;
    ///
    /// use uriparse::URIReference;
    ///
    /// let reference = URIReference::try_from("http://example.com").unwrap();
    /// assert!(reference.is_uri());
    /// ```
    pub fn is_uri(&self) -> bool {
        self.scheme.is_some()
    }

    /// Maps the authority using the given map function.
    ///
    /// This function will panic if, as a result of the authority change, the URI reference becomes
    /// invalid.
    ///
    /// # Examples
    ///
    /// ```
    /// use std::convert::TryFrom;
    ///
    /// use uriparse::{Authority, URIReference};
    ///
    /// let mut reference = URIReference::try_from("http://example.com").unwrap();
    /// reference.map_authority(|_| Some(Authority::try_from("127.0.0.1").unwrap()));
    /// assert_eq!(reference.to_string(), "http://127.0.0.1/");
    /// ```
    pub fn map_authority<Mapper>(&mut self, mapper: Mapper) -> Option<&Authority<'uri>>
    where
        Mapper: FnOnce(Option<Authority<'uri>>) -> Option<Authority<'uri>>,
    {
        let authority = mapper(self.authority.take());
        self.set_authority(authority)
            .expect("mapped authority resulted in invalid state")
    }

    /// Maps the fragment using the given map function.
    ///
    /// # Examples
    ///
    /// ```
    /// use std::convert::TryFrom;
    ///
    /// use uriparse::{Fragment, URIReference};
    ///
    /// let mut reference = URIReference::try_from("http://example.com").unwrap();
    /// reference.map_fragment(|_| Some(Fragment::try_from("fragment").unwrap()));
    /// assert_eq!(reference.to_string(), "http://example.com/#fragment");
    /// ```
    pub fn map_fragment<Mapper>(&mut self, mapper: Mapper) -> Option<&Fragment<'uri>>
    where
        Mapper: FnOnce(Option<Fragment<'uri>>) -> Option<Fragment<'uri>>,
    {
        let fragment = mapper(self.fragment.take());
        self.set_fragment(fragment)
            .expect("mapped fragment resulted in invalid state")
    }

    /// Maps the path using the given map function.
    ///
    /// This function will panic if, as a result of the path change, the URI reference becomes
    /// invalid.
    ///
    /// # Examples
    ///
    /// ```
    /// use std::convert::TryFrom;
    ///
    /// use uriparse::{Authority, URIReference};
    ///
    /// let mut reference = URIReference::try_from("http://example.com").unwrap();
    /// reference.map_path(|mut path| {
    ///     path.push("test").unwrap();
    ///     path.push("path").unwrap();
    ///     path
    /// });
    /// assert_eq!(reference.to_string(), "http://example.com/test/path");
    /// ```
    pub fn map_path<Mapper>(&mut self, mapper: Mapper) -> &Path<'uri>
    where
        Mapper: FnOnce(Path<'uri>) -> Path<'uri>,
    {
        // Unsafe: We're creating an invalid path just as a temporary sentinel value, but it is
        // replaced shortly after.
        let temp_path = unsafe { Path::new_with_no_segments(true) };
        let path = mapper(mem::replace(&mut self.path, temp_path));
        self.set_path(path)
            .expect("mapped path resulted in invalid state")
    }

    /// Maps the query using the given map function.
    ///
    /// # Examples
    ///
    /// ```
    /// use std::convert::TryFrom;
    ///
    /// use uriparse::{Query, URIReference};
    ///
    /// let mut reference = URIReference::try_from("http://example.com").unwrap();
    /// reference.map_query(|_| Some(Query::try_from("query").unwrap()));
    /// assert_eq!(reference.to_string(), "http://example.com/?query");
    /// ```
    pub fn map_query<Mapper>(&mut self, mapper: Mapper) -> Option<&Query<'uri>>
    where
        Mapper: FnOnce(Option<Query<'uri>>) -> Option<Query<'uri>>,
    {
        let query = mapper(self.query.take());
        self.set_query(query)
            .expect("mapped query resulted in invalid state")
    }

    /// Maps the scheme using the given map function.
    ///
    /// This function will panic if, as a result of the scheme change, the URI reference becomes
    /// invalid.
    ///
    /// # Examples
    ///
    /// ```
    /// use std::convert::TryFrom;
    ///
    /// use uriparse::{Scheme, URIReference};
    ///
    /// let mut reference = URIReference::try_from("http://example.com").unwrap();
    /// reference.map_scheme(|_| Some(Scheme::try_from("https").unwrap()));
    /// assert_eq!(reference.to_string(), "https://example.com/");
    /// ```
    pub fn map_scheme<Mapper>(&mut self, mapper: Mapper) -> Option<&Scheme<'uri>>
    where
        Mapper: FnOnce(Option<Scheme<'uri>>) -> Option<Scheme<'uri>>,
    {
        let scheme = mapper(self.scheme.take());
        self.set_scheme(scheme)
            .expect("mapped scheme resulted in invalid state")
    }

    /// Normalizes the URI reference.
    ///
    /// A normalized URI reference will have all of its components normalized.
    ///
    /// # Examples
    ///
    /// ```
    /// use std::convert::TryFrom;
    ///
    /// use uriparse::URIReference;
    ///
    /// let mut reference = URIReference::try_from("http://example.com/?a=b").unwrap();
    /// reference.normalize();
    /// assert_eq!(reference.to_string(), "http://example.com/?a=b");
    ///
    /// let mut reference = URIReference::try_from("http://EXAMPLE.com/?a=b").unwrap();
    /// assert_eq!(reference.to_string(), "http://EXAMPLE.com/?a=b");
    /// reference.normalize();
    /// assert_eq!(reference.to_string(), "http://example.com/?a=b");
    /// ```
    pub fn normalize(&mut self) {
        if let Some(scheme) = self.scheme.as_mut() {
            scheme.normalize();
        }

        if let Some(authority) = self.authority.as_mut() {
            authority.normalize();
        }

        self.path.normalize(self.scheme.is_none());

        if let Some(query) = self.query.as_mut() {
            query.normalize();
        }

        if let Some(fragment) = self.fragment.as_mut() {
            fragment.normalize();
        }
    }

    /// Returns the path of the URI reference.
    ///
    /// # Examples
    ///
    /// ```
    /// use std::convert::TryFrom;
    ///
    /// use uriparse::URIReference;
    ///
    /// let reference = URIReference::try_from("http://127.0.0.1/my/path").unwrap();
    /// assert_eq!(reference.path(), "/my/path");
    /// ```
    pub fn path(&self) -> &Path<'uri> {
        &self.path
    }

    /// Returns the password, if present, of the URI reference.
    ///
    /// Usage of a password in URI and URI references is deprecated.
    ///
    /// # Examples
    ///
    /// ```
    /// use std::convert::TryFrom;
    ///
    /// use uriparse::URIReference;
    ///
    /// let reference = URIReference::try_from("http://user:pass@example.com").unwrap();
    /// assert_eq!(reference.password().unwrap(), "pass");
    /// ```
    pub fn password(&self) -> Option<&Password<'uri>> {
        if let Some(ref authority) = self.authority {
            authority.password()
        } else {
            None
        }
    }

    /// Returns the port, if present, of the URI reference.
    ///
    /// # Examples
    ///
    /// ```
    /// use std::convert::TryFrom;
    ///
    /// use uriparse::URIReference;
    ///
    /// let reference = URIReference::try_from("http://example.com:8080/").unwrap();
    /// assert_eq!(reference.port().unwrap(), 8080);
    /// ```
    pub fn port(&self) -> Option<u16> {
        if let Some(ref authority) = self.authority {
            authority.port()
        } else {
            None
        }
    }

    /// Returns the query, if present, of the URI reference.
    ///
    /// # Examples
    ///
    /// ```
    /// use std::convert::TryFrom;
    ///
    /// use uriparse::URIReference;
    ///
    /// let reference = URIReference::try_from("http://127.0.0.1?my=query").unwrap();
    /// assert_eq!(reference.query().unwrap(), "my=query");
    /// ```
    pub fn query(&self) -> Option<&Query<'uri>> {
        self.query.as_ref()
    }

    /// Returns the scheme, if present, of the URI reference.
    ///
    /// # Examples
    ///
    /// ```
    /// use std::convert::TryFrom;
    ///
    /// use uriparse::URIReference;
    ///
    /// let reference = URIReference::try_from("http://127.0.0.1/").unwrap();
    /// assert_eq!(reference.scheme().unwrap(), "http");
    /// ```
    pub fn scheme(&self) -> Option<&Scheme<'uri>> {
        self.scheme.as_ref()
    }

    /// Sets the authority of the URI reference.
    ///
    /// An error will be returned if the conversion to an [`Authority`] fails.
    ///
    /// The existing path will be set to absolute (i.e. starts with a `'/'`).
    ///
    /// # Examples
    ///
    /// ```
    /// use std::convert::TryFrom;
    ///
    /// use uriparse::URIReference;
    ///
    /// let mut reference = URIReference::try_from("http://example.com").unwrap();
    /// reference.set_authority(Some("user@example.com:80"));
    /// assert_eq!(reference.to_string(), "http://user@example.com:80/");
    /// ```
    pub fn set_authority<AuthorityType, AuthorityError>(
        &mut self,
        authority: Option<AuthorityType>,
    ) -> Result<Option<&Authority<'uri>>, InvalidURIReference>
    where
        Authority<'uri>: TryFrom<AuthorityType, Error = AuthorityError>,
        InvalidURIReference: From<AuthorityError>,
    {
        self.authority = match authority {
            Some(authority) => {
                self.path.set_absolute(true);
                Some(Authority::try_from(authority)?)
            }
            None => {
                validate_absolute_path(None, &self.path)?;
                None
            }
        };
        Ok(self.authority())
    }

    /// Sets the fragment of the URI reference.
    ///
    /// An error will be returned if the conversion to a [`Fragment`] fails.
    ///
    /// # Examples
    ///
    /// ```
    /// use std::convert::TryFrom;
    ///
    /// use uriparse::URIReference;
    ///
    /// let mut reference = URIReference::try_from("http://example.com").unwrap();
    /// reference.set_fragment(Some("fragment"));
    /// assert_eq!(reference.to_string(), "http://example.com/#fragment");
    /// ```
    pub fn set_fragment<FragmentType, FragmentError>(
        &mut self,
        fragment: Option<FragmentType>,
    ) -> Result<Option<&Fragment<'uri>>, InvalidURIReference>
    where
        Fragment<'uri>: TryFrom<FragmentType, Error = FragmentError>,
        InvalidURIReference: From<FragmentError>,
    {
        self.fragment = match fragment {
            Some(fragment) => Some(Fragment::try_from(fragment)?),
            None => None,
        };
        Ok(self.fragment())
    }

    /// Sets the path of the URI reference.
    ///
    /// An error will be returned in one of two cases:
    ///  - The conversion to [`Path`] failed.
    ///  - The path was set to a value that resulted in an invalid URI reference.
    ///
    /// Regardless of whether the given path was set as absolute or relative, if the URI
    /// reference currently has an authority, the path will be forced to be absolute.
    ///
    /// # Examples
    ///
    /// ```
    /// use std::convert::TryFrom;
    ///
    /// use uriparse::URIReference;
    ///
    /// let mut reference = URIReference::try_from("http://example.com").unwrap();
    /// reference.set_path("my/path");
    /// assert_eq!(reference.to_string(), "http://example.com/my/path");
    /// ```
    pub fn set_path<PathType, PathError>(
        &mut self,
        path: PathType,
    ) -> Result<&Path<'uri>, InvalidURIReference>
    where
        Path<'uri>: TryFrom<PathType, Error = PathError>,
        InvalidURIReference: From<PathError>,
    {
        let mut path = Path::try_from(path)?;
        validate_absolute_path(self.authority.as_ref(), &path)?;
        validate_schemeless_path(self.scheme.as_ref(), self.authority.as_ref(), &path)?;

        if self.authority.is_some() {
            path.set_absolute(true);
        }

        self.path = path;
        Ok(self.path())
    }

    /// Sets the query of the URI reference.
    ///
    /// An error will be returned if the conversion to a [`Query`] fails.
    ///
    /// # Examples
    ///
    /// ```
    /// use std::convert::TryFrom;
    ///
    /// use uriparse::URIReference;
    ///
    /// let mut reference = URIReference::try_from("http://example.com").unwrap();
    /// reference.set_query(Some("myquery"));
    /// assert_eq!(reference.to_string(), "http://example.com/?myquery");
    /// ```
    pub fn set_query<QueryType, QueryError>(
        &mut self,
        query: Option<QueryType>,
    ) -> Result<Option<&Query<'uri>>, InvalidURIReference>
    where
        Query<'uri>: TryFrom<QueryType, Error = QueryError>,
        InvalidURIReference: From<QueryError>,
    {
        self.query = match query {
            Some(query) => Some(Query::try_from(query)?),
            None => None,
        };
        Ok(self.query())
    }

    /// Sets the scheme of the URI reference.
    ///
    /// An error will be returned in one of two cases:
    ///  - The conversion to [`Scheme`] failed.
    ///  - The scheme was set to `None`, but the resulting URI reference has an invalid schemeless
    ///    path.
    ///
    /// # Examples
    ///
    /// ```
    /// use std::convert::TryFrom;
    ///
    /// use uriparse::URIReference;
    ///
    /// let mut reference = URIReference::try_from("http://example.com").unwrap();
    /// reference.set_scheme(Some("https"));
    /// assert_eq!(reference.to_string(), "https://example.com/");
    /// ```
    pub fn set_scheme<SchemeType, SchemeError>(
        &mut self,
        scheme: Option<SchemeType>,
    ) -> Result<Option<&Scheme<'uri>>, InvalidURIReference>
    where
        Scheme<'uri>: TryFrom<SchemeType, Error = SchemeError>,
        InvalidURIReference: From<SchemeError>,
    {
        self.scheme = match scheme {
            Some(scheme) => Some(Scheme::try_from(scheme)?),
            None => {
                validate_schemeless_path(None, self.authority.as_ref(), &self.path)?;
                None
            }
        };
        Ok(self.scheme())
    }

    /// Returns the username, if present, of the URI reference.
    ///
    /// # Examples
    ///
    /// ```
    /// use std::convert::TryFrom;
    ///
    /// use uriparse::URIReference;
    ///
    /// let reference = URIReference::try_from("http://username@example.com").unwrap();
    /// assert_eq!(reference.username().unwrap(), "username");
    /// ```
    pub fn username(&self) -> Option<&Username<'uri>> {
        if let Some(ref authority) = self.authority {
            authority.username()
        } else {
            None
        }
    }
}

impl Display for URIReference<'_> {
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

impl<'uri> From<URIReference<'uri>> for String {
    fn from(value: URIReference<'uri>) -> Self {
        value.to_string()
    }
}

impl<'uri> TryFrom<&'uri [u8]> for URIReference<'uri> {
    type Error = InvalidURIReference;

    fn try_from(value: &'uri [u8]) -> Result<Self, Self::Error> {
        let (scheme, value) = match parse_scheme(value) {
            Ok((scheme, rest)) => {
                if rest.starts_with(b":") {
                    (Some(scheme), &rest[1..])
                } else {
                    (None, value)
                }
            }
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

/// A builder type for [`URIReference]`.
///
/// You must use the [`URIReference::path`] function before building as URI references always have
/// have a path. Everything else is optional.
#[derive(Clone, Debug, Default, Eq, PartialEq)]
pub struct URIReferenceBuilder<'uri> {
    /// The authority component of the URI reference as defined in
    /// [[RFC3986, Section 3.2]](https://tools.ietf.org/html/rfc3986#section-3.2).
    authority: Option<Result<Authority<'uri>, InvalidAuthority>>,

    /// The fragment component of the URI reference as defined in
    /// [[RFC3986, Section 3.5]](https://tools.ietf.org/html/rfc3986#section-3.5).
    fragment: Option<Result<Fragment<'uri>, InvalidFragment>>,

    /// The path component of the URI reference as defined in
    /// [[RFC3986, Section 3.3]](https://tools.ietf.org/html/rfc3986#section-3.3).
    path: Option<Result<Path<'uri>, InvalidPath>>,

    /// The query component of the URI reference as defined in
    /// [[RFC3986, Section 3.4]](https://tools.ietf.org/html/rfc3986#section-3.4).
    query: Option<Result<Query<'uri>, InvalidQuery>>,

    /// The scheme component of the URI reference as defined in
    /// [[RFC3986, Section 3.1]](https://tools.ietf.org/html/rfc3986#section-3.1).
    scheme: Option<Result<Scheme<'uri>, InvalidScheme>>,
}

impl<'uri> URIReferenceBuilder<'uri> {
    /// Sets the authority part of the URI reference.
    ///
    /// If the given authority is not a valid authority (i.e. the conversion fails), an error is
    /// stored internally and checked during the [`URIBuilder::build`] function. The error state
    /// will be rewritten for any following calls to this function.
    ///
    /// It is optional to specify an authority.
    ///
    /// # Examples
    ///
    /// ```
    /// use uriparse::URIReferenceBuilder;
    ///
    /// let mut builder = URIReferenceBuilder::new();
    /// builder.authority(Some("example.com")).path("/my/path");
    /// let reference = builder.build().unwrap();
    /// assert_eq!(reference.to_string(), "//example.com/my/path");
    /// ```
    pub fn authority<AuthorityType, AuthorityError>(
        &mut self,
        authority: Option<AuthorityType>,
    ) -> &mut Self
    where
        Authority<'uri>: TryFrom<AuthorityType, Error = AuthorityError>,
        InvalidAuthority: From<AuthorityError>,
    {
        self.authority =
            authority.map(|authority| Authority::try_from(authority).map_err(|error| error.into()));
        self
    }

    /// Consumes the builder and tries to build a [`URIReference`].
    ///
    /// This function will error in one of three situations:
    ///  - One of the components specified in the builder is invalid.
    ///  - A path was not specified in the builder.
    ///  - While all individual components were valid, their combination as a URI reference was
    ///    invalid.
    ///
    /// # Examples
    ///
    /// First error type (invalid path):
    ///
    /// ```
    /// use uriparse::URIReferenceBuilder;
    ///
    /// let mut builder = URIReferenceBuilder::new();
    /// builder.path("this is an invalid path %%%");
    /// assert!(builder.build().is_err());
    /// ```
    ///
    /// Second error type (path not specified):
    ///
    /// ```
    /// use uriparse::URIReferenceBuilder;
    ///
    /// let builder = URIReferenceBuilder::new();
    /// assert!(builder.build().is_err());
    /// ```
    ///
    /// Third error type (first segment in schemeless path cannot contain a `':'`):
    ///
    /// ```
    /// use uriparse::URIReferenceBuilder;
    ///
    /// let mut builder = URIReferenceBuilder::new();
    /// builder.path("my:/path");
    /// assert!(builder.build().is_err());
    /// ```
    pub fn build(self) -> Result<URIReference<'uri>, InvalidURIReference> {
        let scheme = match self.scheme {
            Some(scheme) => Some(scheme?),
            None => None,
        };
        let authority = match self.authority {
            Some(authority) => Some(authority?),
            None => None,
        };
        let path = match self.path {
            Some(path) => path?,
            None => return Err(InvalidURIReference::MissingPath),
        };
        let query = match self.query {
            Some(query) => Some(query?),
            None => None,
        };
        let fragment = match self.fragment {
            Some(fragment) => Some(fragment?),
            None => None,
        };

        URIReference::from_parts(scheme, authority, path, query, fragment)
    }

    /// Sets the fragment part of the URI reference.
    ///
    /// If the given fragment is not a valid fragment (i.e. the conversion fails), an error is
    /// stored internally and checked during the [`URIReferenceBuilder::build`] function. The error
    /// state will be rewritten for any following calls to this function.
    ///
    /// It is optional to specify a fragment.
    ///
    /// # Examples
    ///
    /// ```
    /// use uriparse::URIReferenceBuilder;
    ///
    /// let mut builder = URIReferenceBuilder::new();
    /// builder.path("/my/path").fragment(Some("fragment"));
    /// let reference = builder.build().unwrap();
    /// assert_eq!(reference.to_string(), "/my/path#fragment");
    /// ```
    pub fn fragment<FragmentType, FragmentError>(
        &mut self,
        fragment: Option<FragmentType>,
    ) -> &mut Self
    where
        Fragment<'uri>: TryFrom<FragmentType, Error = FragmentError>,
        InvalidFragment: From<FragmentError>,
    {
        self.fragment =
            fragment.map(|fragment| Fragment::try_from(fragment).map_err(|error| error.into()));
        self
    }

    /// Constructs a new builder with nothing set.
    pub fn new() -> Self {
        URIReferenceBuilder::default()
    }

    /// Sets the path part of the URI reference.
    ///
    /// If the given path is not a valid path (i.e. the conversion fails), an error is stored
    /// internally and checked during the [`URIReferenceBuilder::build`] function. The error state
    /// will be rewritten for any following calls to this function.
    ///
    /// It is required to specify an path. Not doing so will result in an error during the
    /// [`URIReferenceBuilder::build`] function.
    ///
    /// # Examples
    ///
    /// ```
    /// use uriparse::URIReferenceBuilder;
    ///
    /// let mut builder = URIReferenceBuilder::new();
    /// builder.path("/my/path");
    /// let reference = builder.build().unwrap();
    /// assert_eq!(reference.to_string(), "/my/path");
    /// ```
    pub fn path<PathType, PathError>(&mut self, path: PathType) -> &mut Self
    where
        Path<'uri>: TryFrom<PathType, Error = PathError>,
        InvalidPath: From<PathError>,
    {
        self.path = Some(Path::try_from(path).map_err(|error| error.into()));
        self
    }

    /// Sets the query part of the URI reference.
    ///
    /// If the given query is not a valid query (i.e. the conversion fails), an error is stored
    /// internally and checked during the [`URIReferenceBuilder::build`] function. The error state
    /// will be rewritten for any following calls to this function.
    ///
    /// It is optional to specify a query.
    ///
    /// # Examples
    ///
    /// ```
    /// use uriparse::URIReferenceBuilder;
    ///
    /// let mut builder = URIReferenceBuilder::new();
    /// builder.path("/my/path").query(Some("query"));
    /// let reference = builder.build().unwrap();
    /// assert_eq!(reference.to_string(), "/my/path?query");
    /// ```
    pub fn query<QueryType, QueryError>(&mut self, query: Option<QueryType>) -> &mut Self
    where
        Query<'uri>: TryFrom<QueryType, Error = QueryError>,
        InvalidQuery: From<QueryError>,
    {
        self.query = query.map(|query| Query::try_from(query).map_err(|error| error.into()));
        self
    }

    /// Sets the scheme part of the URI reference.
    ///
    /// If the given scheme is not a valid scheme (i.e. the conversion fails), an error is stored
    /// internally and checked during the [`URIReferenceBuilder::build`] function. The error state
    /// will be rewritten for any following calls to this function.
    ///
    /// It is optional to specify a scheme.
    ///
    /// # Examples
    ///
    /// ```
    /// use uriparse::URIReferenceBuilder;
    ///
    /// let mut builder = URIReferenceBuilder::new();
    /// builder.scheme(Some("urn")).path("path");
    /// let uri = builder.build().unwrap();
    /// assert_eq!(uri.to_string(), "urn:path");
    /// ```
    pub fn scheme<SchemeType, SchemeError>(&mut self, scheme: Option<SchemeType>) -> &mut Self
    where
        Scheme<'uri>: TryFrom<SchemeType, Error = SchemeError>,
        InvalidScheme: From<SchemeError>,
    {
        self.scheme = scheme.map(|scheme| Scheme::try_from(scheme).map_err(|error| error.into()));
        self
    }
}

/// An error representing an invalid URI reference.
#[derive(Clone, Copy, Debug, Eq, Hash, PartialEq)]
#[non_exhaustive]
pub enum InvalidURIReference {
    /// Represents the case when there is no authority, but the first path segment starts with
    /// `"//"`. This is not allowed because it would be interpreted as an authority component.
    ///
    /// This can only occur when using creation functions that act on individual parts (e.g.
    /// [`URIReference::from_parts`]).
    AbsolutePathCannotStartWithTwoSlashes,

    /// The authority component of the relative reference was invalid.
    InvalidAuthority(InvalidAuthority),

    /// The fragment component of the relative reference was invalid.
    InvalidFragment(InvalidFragment),

    /// The path component of the relative reference was invalid.
    InvalidPath(InvalidPath),

    /// The query component of the relative reference was invalid.
    InvalidQuery(InvalidQuery),

    /// The scheme component of the relative reference was invalid.
    InvalidScheme(InvalidScheme),

    /// This error occurs when you do not specify a path component on the builder.
    ///
    /// This can only occur when using [`URIReferenceBuilder`].
    MissingPath,

    /// Represents the case when there is no authority, but the first path segment starts with
    /// `"//"`. This is not allowed because it would be interpreted as an authority component.
    ///
    /// This can only occur when using creation functions that act on individual parts (e.g.
    /// [`URIReference::from_parts`]).
    SchemelessPathCannotStartWithColonSegment,
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
            InvalidAuthority(invalid_authority) => invalid_authority.description(),
            InvalidFragment(invalid_fragment) => invalid_fragment.description(),
            InvalidPath(invalid_path) => invalid_path.description(),
            InvalidQuery(invalid_query) => invalid_query.description(),
            InvalidScheme(invalid_scheme) => invalid_scheme.description(),
            MissingPath => "missing path",
            SchemelessPathCannotStartWithColonSegment => {
                "schemeless path cannot start with colon segment"
            }
        }
    }
}

impl From<Infallible> for InvalidURIReference {
    fn from(_: Infallible) -> Self {
        InvalidURIReference::AbsolutePathCannotStartWithTwoSlashes
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

fn validate_absolute_path(
    authority: Option<&Authority>,
    path: &Path,
) -> Result<(), InvalidURIReference> {
    if authority.is_some()
        || path.is_relative()
        || path.segments().len() == 1
        || !path.segments().first().unwrap().is_empty()
    {
        Ok(())
    } else {
        Err(InvalidURIReference::AbsolutePathCannotStartWithTwoSlashes)
    }
}

fn validate_schemeless_path(
    scheme: Option<&Scheme>,
    authority: Option<&Authority>,
    path: &Path,
) -> Result<(), InvalidURIReference> {
    if scheme.is_some()
        || authority.is_some()
        || !path
            .segments()
            .first()
            .unwrap()
            .bytes()
            .any(|byte| byte == b':')
    {
        Ok(())
    } else {
        Err(InvalidURIReference::SchemelessPathCannotStartWithColonSegment)
    }
}

#[cfg(test)]
mod test {
    use super::*;

    #[test]
    fn test_parse_uri_reference() {
        let actual = URIReference::try_from("http://example.com").unwrap();
        let expected = URIReference::from_parts(
            Some(Scheme::HTTP),
            Some("example.com"),
            "/",
            None::<Query>,
            None::<Fragment>,
        )
        .unwrap();
        assert_eq!(actual, expected);

        let actual = URIReference::try_from("http://example.com/").unwrap();
        let expected = URIReference::from_parts(
            Some(Scheme::HTTP),
            Some("example.com"),
            "/",
            None::<Query>,
            None::<Fragment>,
        )
        .unwrap();
        assert_eq!(actual, expected);

        let actual = URIReference::try_from("http://example.com").unwrap();
        let expected = URIReference::from_parts(
            Some(Scheme::HTTP),
            Some("example.com"),
            "",
            None::<Query>,
            None::<Fragment>,
        )
        .unwrap();
        assert_eq!(actual, expected);

        let actual = URIReference::try_from("http://example.com/").unwrap();
        let expected = URIReference::from_parts(
            Some(Scheme::HTTP),
            Some("example.com"),
            "",
            None::<Query>,
            None::<Fragment>,
        )
        .unwrap();
        assert_eq!(actual, expected);

        let actual = URIReference::try_from("http:").unwrap();
        let expected = URIReference::from_parts(
            Some(Scheme::HTTP),
            None::<Authority>,
            "",
            None::<Query>,
            None::<Fragment>,
        )
        .unwrap();
        assert_eq!(actual, expected);

        let actual = URIReference::try_from("http:/").unwrap();
        let expected = URIReference::from_parts(
            Some(Scheme::HTTP),
            None::<Authority>,
            "/",
            None::<Query>,
            None::<Fragment>,
        )
        .unwrap();
        assert_eq!(actual, expected);

        let actual = URIReference::try_from("http:/path").unwrap();
        let expected = URIReference::from_parts(
            Some(Scheme::HTTP),
            None::<Authority>,
            "/path",
            None::<Query>,
            None::<Fragment>,
        )
        .unwrap();
        assert_eq!(actual, expected);

        let actual = URIReference::try_from("//example.com/").unwrap();
        let expected = URIReference::from_parts(
            None::<Scheme>,
            Some("example.com"),
            "/",
            None::<Query>,
            None::<Fragment>,
        )
        .unwrap();
        assert_eq!(actual, expected);

        let actual = URIReference::try_from("").unwrap();
        let expected = URIReference::from_parts(
            None::<Scheme>,
            None::<Authority>,
            "",
            None::<Query>,
            None::<Fragment>,
        )
        .unwrap();
        assert_eq!(actual, expected);

        let actual = URIReference::try_from("*").unwrap();
        let expected = URIReference::from_parts(
            None::<Scheme>,
            None::<Authority>,
            "*",
            None::<Query>,
            None::<Fragment>,
        )
        .unwrap();
        assert_eq!(actual, expected);

        let actual = URIReference::try_from("/").unwrap();
        let expected = URIReference::from_parts(
            None::<Scheme>,
            None::<Authority>,
            "/",
            None::<Query>,
            None::<Fragment>,
        )
        .unwrap();
        assert_eq!(actual, expected);

        let actual = URIReference::try_from("test/path").unwrap();
        let expected = URIReference::from_parts(
            None::<Scheme>,
            None::<Authority>,
            "test/path",
            None::<Query>,
            None::<Fragment>,
        )
        .unwrap();
        assert_eq!(actual, expected);
    }
}
