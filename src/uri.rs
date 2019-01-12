//! URIs, Relative References, and URI References
//!
//! See [RFC3986](https://tools.ietf.org/html/rfc3986).
//!
//! This module is composed of three primary types [`URI`], [`RelativeReference`], and
//! [`URIReference`] that are all very similar. The first thing to note is that URIs and relative
//! references are types of URI references. They differ in only one way: URIs have schemes, while
//! relative references do not.
//!
//! As a result, choose the type that best fits your use case. If you need absolute URIs, you should
//! use [`URI`], but if you want relative references (e.g. `"/"` in a GET request) use
//! [`RelativeReference`]. If you can accept both, then use [`URIReference`].

use std::convert::TryFrom;
use std::error::Error;
use std::fmt::{self, Display, Formatter};

use crate::authority::{Authority, Host, InvalidAuthority, Password, Username};
use crate::fragment::{Fragment, InvalidFragment};
use crate::path::{InvalidPath, Path};
use crate::query::{InvalidQuery, Query};
use crate::scheme::{InvalidScheme, Scheme};
use crate::uri_reference::{InvalidURIReference, URIReference, URIReferenceBuilder};

/// A Uniform Resource Identifier (URI) as defined in
/// [RFC3986](https://tools.ietf.org/html/rfc3986).
///
/// A URI is a URI reference, one with a scheme.
#[derive(Clone, Debug, Eq, Hash, PartialEq)]
pub struct URI<'uri> {
    /// All URIs are also URI references, so we just maintain a [`URIReference`] underneath.
    uri_reference: URIReference<'uri>,
}

impl<'uri> URI<'uri> {
    pub fn as_uri_reference(&self) -> &URIReference<'uri> {
        &self.uri_reference
    }

    /// Returns the authority, if present, of the URI.
    ///
    /// # Examples
    ///
    /// ```
    /// # #![feature(try_from)]
    /// #
    /// use std::convert::TryFrom;
    ///
    /// use uriparse::URI;
    ///
    /// let uri = URI::try_from("http://example.com:80/my/path").unwrap();
    /// assert_eq!(uri.authority().unwrap().to_string(), "example.com:80");
    /// ```
    pub fn authority(&self) -> Option<&Authority<'uri>> {
        self.uri_reference.authority()
    }

    /// Constructs a default builder for a URI.
    ///
    /// This provides an alternative means of constructing a URI besides parsing and
    /// [`URI::from_parts`].
    ///
    /// # Examples
    ///
    /// ```
    /// use uriparse::URI;
    ///
    /// let mut builder = URI::builder();
    /// builder.scheme("http").authority(Some("example.com")).path("/my/path");
    /// let uri = builder.build().unwrap();
    /// assert_eq!(uri.to_string(), "http://example.com/my/path");
    /// ```
    pub fn builder<'new_uri>() -> URIBuilder<'new_uri> {
        URIBuilder::new()
    }

    /// Returns whether the URI can act as a base URI.
    ///
    /// A URI can be a base if it is absolute (i.e. it has no fragment component).
    ///
    /// # Examples
    ///
    /// ```
    /// # #![feature(try_from)]
    /// #
    /// use std::convert::TryFrom;
    ///
    /// use uriparse::URI;
    ///
    /// let uri = URI::try_from("http://example.com/my/path").unwrap();
    /// assert!(uri.can_be_a_base());
    ///
    /// let uri = URI::try_from("ftp://127.0.0.1#fragment").unwrap();
    /// assert!(!uri.can_be_a_base());
    /// ```
    pub fn can_be_a_base(&self) -> bool {
        !self.uri_reference.has_fragment()
    }

    /// Constructs a new [`URI`] from the individual parts: scheme, authority, path, query, and
    /// fragment.
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
    /// use uriparse::{Fragment, URI};
    ///
    /// let uri = URI::from_parts(
    ///     "http",
    ///     Some("example.com"),
    ///     "",
    ///     Some("query"),
    ///     None::<Fragment>
    /// ).unwrap();
    /// assert_eq!(uri.to_string(), "http://example.com/?query");
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
        scheme: SchemeType,
        authority: Option<AuthorityType>,
        path: PathType,
        query: Option<QueryType>,
        fragment: Option<FragmentType>,
    ) -> Result<URI<'new_uri>, InvalidURI>
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
            URIReference::from_parts(Some(scheme), authority, path, query, fragment)
                .map_err(|error| InvalidURI::try_from(error).unwrap())?;
        Ok(URI { uri_reference })
    }

    /// Returns the fragment, if present, of the URI.
    ///
    /// # Examples
    ///
    /// ```
    /// # #![feature(try_from)]
    /// #
    /// use std::convert::TryFrom;
    ///
    /// use uriparse::URI;
    ///
    /// let uri = URI::try_from("http://example.com#fragment").unwrap();
    /// assert_eq!(uri.fragment().unwrap(), "fragment");
    /// ```
    pub fn fragment(&self) -> Option<&Fragment<'uri>> {
        self.uri_reference.fragment()
    }

    /// Returns whether the URI has an authority component.
    ///
    /// # Examples
    ///
    /// ```
    /// # #![feature(try_from)]
    /// #
    /// use std::convert::TryFrom;
    ///
    /// use uriparse::URI;
    ///
    /// let uri = URI::try_from("http://example.com").unwrap();
    /// assert!(uri.has_authority());
    ///
    /// let uri = URI::try_from("urn:test").unwrap();
    /// assert!(!uri.has_authority());
    /// ```
    pub fn has_authority(&self) -> bool {
        self.uri_reference.has_authority()
    }

    /// Returns whether the URI has a fragment component.
    ///
    /// # Examples
    ///
    /// ```
    /// # #![feature(try_from)]
    /// #
    /// use std::convert::TryFrom;
    ///
    /// use uriparse::URI;
    ///
    /// let uri = URI::try_from("http://example.com#test").unwrap();
    /// assert!(uri.has_fragment());
    ///
    /// let uri = URI::try_from("http://example.com").unwrap();
    /// assert!(!uri.has_fragment());
    /// ```
    pub fn has_fragment(&self) -> bool {
        self.uri_reference.has_fragment()
    }

    /// Returns whether the URI has a password component.
    ///
    /// # Examples
    ///
    /// ```
    /// # #![feature(try_from)]
    /// #
    /// use std::convert::TryFrom;
    ///
    /// use uriparse::URI;
    ///
    /// let uri = URI::try_from("http://user:pass@127.0.0.1").unwrap();
    /// assert!(uri.has_password());
    ///
    /// let uri = URI::try_from("http://user@127.0.0.1").unwrap();
    /// assert!(!uri.has_password());
    /// ```
    pub fn has_password(&self) -> bool {
        self.uri_reference.has_password()
    }

    /// Returns whether the URI has a port.
    ///
    /// # Examples
    ///
    /// ```
    /// # #![feature(try_from)]
    /// #
    /// use std::convert::TryFrom;
    ///
    /// use uriparse::URI;
    ///
    /// let uri = URI::try_from("http://127.0.0.1:8080").unwrap();
    /// assert!(uri.has_port());
    ///
    /// let uri = URI::try_from("http://127.0.0.1").unwrap();
    /// assert!(!uri.has_port());
    /// ```
    pub fn has_port(&self) -> bool {
        self.uri_reference.has_port()
    }

    /// Returns whether the URI has a query component.
    ///
    /// # Examples
    ///
    /// ```
    /// # #![feature(try_from)]
    /// #
    /// use std::convert::TryFrom;
    ///
    /// use uriparse::URI;
    ///
    /// let uri = URI::try_from("http://example.com/my/path?my=query").unwrap();
    /// assert!(uri.has_query());
    ///
    /// let uri = URI::try_from("http://example.com/my/path").unwrap();
    /// assert!(!uri.has_query());
    /// ```
    pub fn has_query(&self) -> bool {
        self.uri_reference.has_query()
    }

    /// Returns whether the URI has a username component.
    ///
    /// # Examples
    ///
    /// ```
    /// # #![feature(try_from)]
    /// #
    /// use std::convert::TryFrom;
    ///
    /// use uriparse::URI;
    ///
    /// let uri = URI::try_from("http://username@example.com").unwrap();
    /// assert!(uri.has_username());
    ///
    /// let uri = URI::try_from("http://example.com").unwrap();
    /// assert!(!uri.has_username());
    /// ```
    pub fn has_username(&self) -> bool {
        self.uri_reference.has_username()
    }

    /// Returns the host, if present, of the URI.
    ///
    /// # Examples
    ///
    /// ```
    /// # #![feature(try_from)]
    /// #
    /// use std::convert::TryFrom;
    ///
    /// use uriparse::URI;
    ///
    /// let uri = URI::try_from("http://username@example.com").unwrap();
    /// assert_eq!(uri.host().unwrap().to_string(), "example.com");
    /// ```
    pub fn host(&self) -> Option<&Host<'uri>> {
        self.uri_reference.host()
    }

    /// Converts the URI into a base URI (i.e. the fragment component is removed).
    ///
    /// # Examples
    ///
    /// ```
    /// # #![feature(try_from)]
    /// #
    /// use std::convert::TryFrom;
    ///
    /// use uriparse::URI;
    ///
    /// let uri = URI::try_from("http://example.com#fragment").unwrap();
    /// assert_eq!(uri.to_string(), "http://example.com/#fragment");
    /// let uri = uri.into_base_uri();
    /// assert_eq!(uri.to_string(), "http://example.com/");
    /// ```
    pub fn into_base_uri(self) -> URI<'uri> {
        let (scheme, authority, path, query, _) = self.uri_reference.into_parts();
        let uri_reference =
            URIReference::from_parts(scheme, authority, path, query, None::<Fragment>).unwrap();
        URI { uri_reference }
    }

    /// Consumes the URI and converts it into a builder with the same values.
    ///
    /// # Examples
    ///
    /// ```
    /// # #![feature(try_from)]
    /// #
    /// use std::convert::TryFrom;
    ///
    /// use uriparse::{Fragment, Query, URI};
    ///
    /// let uri = URI::try_from("http://example.com/path?query#fragment").unwrap();
    /// let mut builder = uri.into_builder();
    /// builder.query(None::<Query>).fragment(None::<Fragment>);
    /// let uri = builder.build().unwrap();
    /// assert_eq!(uri.to_string(), "http://example.com/path");
    /// ```
    pub fn into_builder(self) -> URIBuilder<'uri> {
        let (scheme, authority, path, query, fragment) = self.uri_reference.into_parts();
        let mut builder = URIBuilder::new();
        builder
            .scheme(scheme.unwrap())
            .authority(authority)
            .path(path)
            .query(query)
            .fragment(fragment);
        builder
    }

    /// Converts the [`URI`] into an owned copy.
    ///
    /// If you construct the URI from a source with a non-static lifetime, you may run into
    /// lifetime problems due to the way the struct is designed. Calling this function will ensure
    /// that the returned value has a static lifetime.
    ///
    /// This is different from just cloning. Cloning the URI will just copy the references, and thus
    /// the lifetime will remain the same.
    pub fn into_owned(self) -> URI<'static> {
        URI {
            uri_reference: self.uri_reference.into_owned(),
        }
    }

    /// Consumes the [`URI`] and returns its parts: scheme, authority, path, query, and fragment.
    ///
    /// # Examples
    ///
    /// ```
    /// # #![feature(try_from)]
    /// #
    /// use std::convert::TryFrom;
    ///
    /// use uriparse::URI;
    ///
    /// let uri = URI::try_from(
    ///     "http://username:password@example.com:80/my/path?my=query#fragment",
    /// ).unwrap();
    /// let (scheme, authority, path, query, fragment) = uri.into_parts();
    ///
    /// assert_eq!(scheme, "http");
    /// assert_eq!(authority.unwrap().to_string(), "username:password@example.com:80");
    /// assert_eq!(path, "/my/path");
    /// assert_eq!(query.unwrap(), "my=query");
    /// assert_eq!(fragment.unwrap(), "fragment");
    /// ```
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

    /// Returns whether the URI is normalized.
    ///
    /// A normalized URI will have all of its components normalized.
    ///
    /// # Examples
    ///
    /// ```
    /// # #![feature(try_from)]
    /// #
    /// use std::convert::TryFrom;
    ///
    /// use uriparse::URI;
    ///
    /// let uri = URI::try_from("http://example.com/?a=b").unwrap();
    /// assert!(uri.is_normalized());
    ///
    /// let mut uri = URI::try_from("http://EXAMPLE.com/?a=b").unwrap();
    /// assert!(!uri.is_normalized());
    /// uri.normalize();
    /// assert!(uri.is_normalized());
    /// ```
    pub fn is_normalized(&self) -> bool {
        self.uri_reference.is_normalized()
    }

    /// Maps the authority using the given map function.
    ///
    /// This function will panic if, as a result of the authority change, the URI reference becomes
    /// invalid.
    ///
    /// # Examples
    ///
    /// ```
    /// # #![feature(try_from)]
    /// #
    /// use std::convert::TryFrom;
    ///
    /// use uriparse::{Authority, URI};
    ///
    /// let mut uri = URI::try_from("http://example.com").unwrap();
    /// uri.map_authority(|_| Some(Authority::try_from("127.0.0.1").unwrap()));
    /// assert_eq!(uri.to_string(), "http://127.0.0.1/");
    /// ```
    pub fn map_authority<Mapper>(&mut self, mapper: Mapper) -> Option<&Authority<'uri>>
    where
        Mapper: FnOnce(Option<Authority<'uri>>) -> Option<Authority<'uri>>,
    {
        self.uri_reference.map_authority(mapper)
    }

    /// Maps the fragment using the given map function.
    ///
    /// # Examples
    ///
    /// ```
    /// # #![feature(try_from)]
    /// #
    /// use std::convert::TryFrom;
    ///
    /// use uriparse::{Fragment, URI};
    ///
    /// let mut uri = URI::try_from("http://example.com").unwrap();
    /// uri.map_fragment(|_| Some(Fragment::try_from("fragment").unwrap()));
    /// assert_eq!(uri.to_string(), "http://example.com/#fragment");
    /// ```
    pub fn map_fragment<Mapper>(&mut self, mapper: Mapper) -> Option<&Fragment<'uri>>
    where
        Mapper: FnOnce(Option<Fragment<'uri>>) -> Option<Fragment<'uri>>,
    {
        self.uri_reference.map_fragment(mapper)
    }

    /// Maps the path using the given map function.
    ///
    /// This function will panic if, as a result of the path change, the URI becomes invalid.
    ///
    /// # Examples
    ///
    /// ```
    /// # #![feature(try_from)]
    /// #
    /// use std::convert::TryFrom;
    ///
    /// use uriparse::URI;
    ///
    /// let mut uri = URI::try_from("http://example.com").unwrap();
    /// uri.map_path(|mut path| {
    ///     path.push("test").unwrap();
    ///     path.push("path").unwrap();
    ///     path
    /// });
    /// assert_eq!(uri.to_string(), "http://example.com/test/path");
    /// ```
    pub fn map_path<Mapper>(&mut self, mapper: Mapper) -> &Path<'uri>
    where
        Mapper: FnOnce(Path<'uri>) -> Path<'uri>,
    {
        self.uri_reference.map_path(mapper)
    }

    /// Maps the query using the given map function.
    ///
    /// # Examples
    ///
    /// ```
    /// # #![feature(try_from)]
    /// #
    /// use std::convert::TryFrom;
    ///
    /// use uriparse::{Query, URI};
    ///
    /// let mut uri = URI::try_from("http://example.com").unwrap();
    /// uri.map_query(|_| Some(Query::try_from("query").unwrap()));
    /// assert_eq!(uri.to_string(), "http://example.com/?query");
    /// ```
    pub fn map_query<Mapper>(&mut self, mapper: Mapper) -> Option<&Query<'uri>>
    where
        Mapper: FnOnce(Option<Query<'uri>>) -> Option<Query<'uri>>,
    {
        self.uri_reference.map_query(mapper)
    }

    /// Maps the scheme using the given map function.
    ///
    /// # Examples
    ///
    /// ```
    /// # #![feature(try_from)]
    /// #
    /// use std::convert::TryFrom;
    ///
    /// use uriparse::{Scheme, URI};
    ///
    /// let mut uri = URI::try_from("http://example.com").unwrap();
    /// uri.map_scheme(|_| Scheme::try_from("https").unwrap());
    /// assert_eq!(uri.to_string(), "https://example.com/");
    /// ```
    pub fn map_scheme<Mapper>(&mut self, mapper: Mapper) -> Option<&Scheme<'uri>>
    where
        Mapper: FnOnce(Scheme<'uri>) -> Scheme<'uri>,
    {
        self.uri_reference
            .map_scheme(|scheme| Some(mapper(scheme.unwrap())))
    }

    /// Normalizes the URI.
    ///
    /// A normalized URI will have all of its components normalized.
    ///
    /// # Examples
    ///
    /// ```
    /// # #![feature(try_from)]
    /// #
    /// use std::convert::TryFrom;
    ///
    /// use uriparse::URI;
    ///
    /// let mut uri = URI::try_from("http://example.com/?a=b").unwrap();
    /// uri.normalize();
    /// assert_eq!(uri.to_string(), "http://example.com/?a=b");
    ///
    /// let mut uri = URI::try_from("http://EXAMPLE.com/?a=b").unwrap();
    /// assert_eq!(uri.to_string(), "http://EXAMPLE.com/?a=b");
    /// uri.normalize();
    /// assert_eq!(uri.to_string(), "http://example.com/?a=b");
    /// ```
    pub fn normalize(&mut self) {
        self.uri_reference.normalize();
    }

    /// Returns the path of the URI.
    ///
    /// # Examples
    ///
    /// ```
    /// # #![feature(try_from)]
    /// #
    /// use std::convert::TryFrom;
    ///
    /// use uriparse::URI;
    ///
    /// let uri = URI::try_from("http://127.0.0.1/my/path").unwrap();
    /// assert_eq!(uri.path(), "/my/path");
    /// ```
    pub fn path(&self) -> &Path<'uri> {
        self.uri_reference.path()
    }

    /// Returns the password, if present, of the URI.
    ///
    /// Usage of a password in URIs is deprecated.
    ///
    /// # Examples
    ///
    /// ```
    /// # #![feature(try_from)]
    /// #
    /// use std::convert::TryFrom;
    ///
    /// use uriparse::URI;
    ///
    /// let uri = URI::try_from("http://user:pass@example.com").unwrap();
    /// assert_eq!(uri.password().unwrap(), "pass");
    /// ```
    pub fn password(&self) -> Option<&Password<'uri>> {
        self.uri_reference.password()
    }

    /// Returns the port, if present, of the URI.
    ///
    /// # Examples
    ///
    /// ```
    /// # #![feature(try_from)]
    /// #
    /// use std::convert::TryFrom;
    ///
    /// use uriparse::URI;
    ///
    /// let uri = URI::try_from("http://example.com:8080/").unwrap();
    /// assert_eq!(uri.port().unwrap(), 8080);
    /// ```
    pub fn port(&self) -> Option<u16> {
        self.uri_reference.port()
    }

    /// Returns the query, if present, of the URI.
    ///
    /// # Examples
    ///
    /// ```
    /// # #![feature(try_from)]
    /// #
    /// use std::convert::TryFrom;
    ///
    /// use uriparse::URI;
    ///
    /// let uri = URI::try_from("http://127.0.0.1?my=query").unwrap();
    /// assert_eq!(uri.query().unwrap(), "my=query");
    /// ```
    pub fn query(&self) -> Option<&Query<'uri>> {
        self.uri_reference.query()
    }

    /// Creates a new URI which is created by resolving the given reference against this URI.
    ///
    /// The algorithm used for resolving the reference is described in
    /// [[RFC3986, Section 5.2.2](https://tools.ietf.org/html/rfc3986#section-5.2.2)].
    pub fn resolve(&self, reference: &'uri URIReference<'uri>) -> URI<'uri> {
        let mut builder = URIBuilder::new();

        if let Some(scheme) = reference.scheme() {
            let mut path = reference.path().clone();
            path.remove_dot_segments();

            builder
                .scheme(scheme.clone())
                .authority(reference.authority().cloned())
                .path(path)
                .query(reference.query().cloned());
        } else {
            if reference.authority().is_some() {
                let mut path = reference.path().clone();
                path.remove_dot_segments();

                builder
                    .authority(reference.authority().cloned())
                    .path(path)
                    .query(reference.query().cloned());
            } else {
                if reference.path().is_relative()
                    && reference.path().segments().len() == 1
                    && reference.path().segments()[0].is_empty()
                {
                    let mut path = self.path().clone();
                    path.remove_dot_segments();
                    builder.path(path);

                    if reference.query().is_some() {
                        builder.query(reference.query().cloned());
                    } else {
                        builder.query(self.query().cloned());
                    }
                } else {
                    if reference.path().is_absolute() {
                        let mut path = reference.path().clone();
                        path.remove_dot_segments();
                        builder.path(path);
                    } else {
                        let mut path = if self.authority().is_some()
                            && self.path().segments().len() == 1
                            && self.path().segments()[0].is_empty()
                        {
                            let mut path = reference.path().clone();
                            path.set_absolute(true);
                            path
                        } else {
                            let mut path = self.path().clone();
                            path.pop();

                            for segment in reference.path().segments() {
                                path.push(segment.clone()).unwrap();
                            }

                            path
                        };

                        path.remove_dot_segments();
                        builder.path(path);
                    }

                    builder.query(reference.query().cloned());
                }

                builder.authority(self.authority().cloned());
            }

            builder.scheme(self.scheme().clone());
        }

        builder.fragment(reference.fragment().cloned());
        builder.build().unwrap()
    }

    /// Returns the scheme of the URI.
    ///
    /// # Examples
    ///
    /// ```
    /// # #![feature(try_from)]
    /// #
    /// use std::convert::TryFrom;
    ///
    /// use uriparse::URI;
    ///
    /// let uri = URI::try_from("http://127.0.0.1/").unwrap();
    /// assert_eq!(uri.scheme(), "http");
    /// ```
    pub fn scheme(&self) -> &Scheme<'uri> {
        self.uri_reference.scheme().unwrap()
    }

    /// Sets the authority of the URI.
    ///
    /// An error will be returned if the conversion to an [`Authority`] fails.
    ///
    /// The existing path will be set to absolute (i.e. starts with a `'/'`).
    ///
    /// # Examples
    ///
    /// ```
    /// # #![feature(try_from)]
    /// #
    /// use std::convert::TryFrom;
    ///
    /// use uriparse::URI;
    ///
    /// let mut uri = URI::try_from("http://example.com").unwrap();
    /// uri.set_authority(Some("user@example.com:80"));
    /// assert_eq!(uri.to_string(), "http://user@example.com:80/");
    /// ```
    pub fn set_authority<AuthorityType, AuthorityError>(
        &mut self,
        authority: Option<AuthorityType>,
    ) -> Result<Option<&Authority<'uri>>, InvalidURI>
    where
        Authority<'uri>: TryFrom<AuthorityType, Error = AuthorityError>,
        InvalidURIReference: From<AuthorityError>,
    {
        self.uri_reference
            .set_authority(authority)
            .map_err(|error| InvalidURI::try_from(error).unwrap())
    }

    /// Sets the fragment of the URI.
    ///
    /// An error will be returned if the conversion to a [`Fragment`] fails.
    ///
    /// # Examples
    ///
    /// ```
    /// # #![feature(try_from)]
    /// #
    /// use std::convert::TryFrom;
    ///
    /// use uriparse::URI;
    ///
    /// let mut uri = URI::try_from("http://example.com").unwrap();
    /// uri.set_fragment(Some("fragment"));
    /// assert_eq!(uri.to_string(), "http://example.com/#fragment");
    /// ```
    pub fn set_fragment<FragmentType, FragmentError>(
        &mut self,
        fragment: Option<FragmentType>,
    ) -> Result<Option<&Fragment<'uri>>, InvalidURI>
    where
        Fragment<'uri>: TryFrom<FragmentType, Error = FragmentError>,
        InvalidURIReference: From<FragmentError>,
    {
        self.uri_reference
            .set_fragment(fragment)
            .map_err(|error| InvalidURI::try_from(error).unwrap())
    }

    /// Sets the path of the URI.
    ///
    /// An error will be returned in one of two cases:
    ///  - The conversion to [`Path`] failed.
    ///  - The path was set to a value that resulted in an invalid URI.
    ///
    /// Regardless of whether the given path was set as absolute or relative, if the URI
    /// reference currently has an authority, the path will be forced to be absolute.
    ///
    /// # Examples
    ///
    /// ```
    /// # #![feature(try_from)]
    /// #
    /// use std::convert::TryFrom;
    ///
    /// use uriparse::URI;
    ///
    /// let mut uri = URI::try_from("http://example.com").unwrap();
    /// uri.set_path("my/path");
    /// assert_eq!(uri.to_string(), "http://example.com/my/path");
    /// ```
    pub fn set_path<PathType, PathError>(
        &mut self,
        path: PathType,
    ) -> Result<&Path<'uri>, InvalidURI>
    where
        Path<'uri>: TryFrom<PathType, Error = PathError>,
        InvalidURIReference: From<PathError>,
    {
        self.uri_reference
            .set_path(path)
            .map_err(|error| InvalidURI::try_from(error).unwrap())
    }

    /// Sets the query of the URI.
    ///
    /// An error will be returned if the conversion to a [`Query`] fails.
    ///
    /// # Examples
    ///
    /// ```
    /// # #![feature(try_from)]
    /// #
    /// use std::convert::TryFrom;
    ///
    /// use uriparse::URI;
    ///
    /// let mut uri = URI::try_from("http://example.com").unwrap();
    /// uri.set_query(Some("myquery"));
    /// assert_eq!(uri.to_string(), "http://example.com/?myquery");
    /// ```
    pub fn set_query<QueryType, QueryError>(
        &mut self,
        query: Option<QueryType>,
    ) -> Result<Option<&Query<'uri>>, InvalidURI>
    where
        Query<'uri>: TryFrom<QueryType, Error = QueryError>,
        InvalidURIReference: From<QueryError>,
    {
        self.uri_reference
            .set_query(query)
            .map_err(|error| InvalidURI::try_from(error).unwrap())
    }

    /// Sets the scheme of the URI.
    ///
    /// An error will be returned if the conversion to a [`Scheme`] fails.
    ///
    /// # Examples
    ///
    /// ```
    /// # #![feature(try_from)]
    /// #
    /// use std::convert::TryFrom;
    ///
    /// use uriparse::URI;
    ///
    /// let mut uri = URI::try_from("http://example.com").unwrap();
    /// uri.set_scheme("https");
    /// assert_eq!(uri.to_string(), "https://example.com/");
    /// ```
    pub fn set_scheme<SchemeType, SchemeError>(
        &mut self,
        scheme: SchemeType,
    ) -> Result<&Scheme<'uri>, InvalidURI>
    where
        Scheme<'uri>: TryFrom<SchemeType, Error = SchemeError>,
        InvalidURIReference: From<SchemeError>,
    {
        self.uri_reference
            .set_scheme(Some(scheme))
            .map_err(|error| InvalidURI::try_from(error).unwrap())?;
        Ok(self.scheme())
    }

    /// Returns the username, if present, of the URI.
    ///
    /// # Examples
    ///
    /// ```
    /// # #![feature(try_from)]
    /// #
    /// use std::convert::TryFrom;
    ///
    /// use uriparse::URI;
    ///
    /// let uri = URI::try_from("http://username@example.com").unwrap();
    /// assert_eq!(uri.username().unwrap(), "username");
    /// ```
    pub fn username(&self) -> Option<&Username<'uri>> {
        self.uri_reference.username()
    }
}

impl Display for URI<'_> {
    fn fmt(&self, formatter: &mut Formatter) -> fmt::Result {
        self.uri_reference.fmt(formatter)
    }
}

impl<'uri> From<URI<'uri>> for String {
    fn from(value: URI<'uri>) -> Self {
        value.to_string()
    }
}

impl<'uri> From<URI<'uri>> for URIReference<'uri> {
    fn from(value: URI<'uri>) -> Self {
        value.uri_reference
    }
}

impl<'uri> TryFrom<&'uri [u8]> for URI<'uri> {
    type Error = InvalidURI;

    fn try_from(value: &'uri [u8]) -> Result<Self, Self::Error> {
        let uri_reference =
            URIReference::try_from(value).map_err(|error| InvalidURI::try_from(error).unwrap())?;

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

impl<'uri> TryFrom<URIReference<'uri>> for URI<'uri> {
    type Error = InvalidURI;

    fn try_from(value: URIReference<'uri>) -> Result<Self, Self::Error> {
        if value.is_uri() {
            Ok(URI {
                uri_reference: value,
            })
        } else {
            Err(InvalidURI::CannotBeRelativeReference)
        }
    }
}

/// A builder type for [`URI]`.
///
/// You must use the [`URI::scheme`] and [`URI::path`] functions before building as URIs always
/// have a scheme and path. Everything else is optional.
#[derive(Clone, Debug, Default, Eq, PartialEq)]
pub struct URIBuilder<'uri> {
    /// All URIs are also URI references, so we just maintain a [`URIReferenceBuilder`] underneath.
    uri_reference_builder: URIReferenceBuilder<'uri>,
}

impl<'uri> URIBuilder<'uri> {
    /// Sets the authority part of the URI.
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
    /// use uriparse::URIBuilder;
    ///
    /// let mut builder = URIBuilder::new();
    /// builder.scheme("http").authority(Some("example.com")).path("/my/path");
    /// let uri = builder.build().unwrap();
    /// assert_eq!(uri.to_string(), "http://example.com/my/path");
    /// ```
    pub fn authority<AuthorityType, AuthorityError>(
        &mut self,
        authority: Option<AuthorityType>,
    ) -> &mut Self
    where
        Authority<'uri>: TryFrom<AuthorityType, Error = AuthorityError>,
        InvalidAuthority: From<AuthorityError>,
    {
        self.uri_reference_builder.authority(authority);
        self
    }

    /// Consumes the builder and tries to build a [`URI`].
    ///
    /// This function will error in one of three situations:
    ///  - One of the components specified in the builder is invalid.
    ///  - A scheme and path were not specified in the builder.
    ///  - While all individual components were valid, their combination as a URI was invalid.
    ///
    /// # Examples
    ///
    /// First error type (invalid path):
    ///
    /// ```
    /// use uriparse::URIBuilder;
    ///
    /// let mut builder = URIBuilder::new();
    /// builder.scheme("urn").path("this is an invalid path %%%");
    /// assert!(builder.build().is_err());
    /// ```
    ///
    /// Second error type (scheme and/or path were not specified):
    ///
    /// ```
    /// use uriparse::URIBuilder;
    ///
    /// let mut builder = URIBuilder::new();
    /// builder.path("/my/path");
    /// assert!(builder.build().is_err());
    /// ```
    ///
    /// Third error type (URI with no authority cannot have path starting with `"//"`):
    ///
    /// ```
    /// use uriparse::URIBuilder;
    ///
    /// let mut builder = URIBuilder::new();
    /// builder.scheme("urn").path("//path");
    /// assert!(builder.build().is_err());
    /// ```
    pub fn build(self) -> Result<URI<'uri>, InvalidURI> {
        let uri_reference = self
            .uri_reference_builder
            .build()
            .map_err(|error| InvalidURI::try_from(error).unwrap())?;

        if !uri_reference.has_scheme() {
            return Err(InvalidURI::MissingScheme);
        }

        Ok(URI { uri_reference })
    }

    /// Sets the fragment part of the URI.
    ///
    /// If the given fragment is not a valid fragment (i.e. the conversion fails), an error is
    /// stored internally and checked during the [`URIBuilder::build`] function. The error state
    /// will be rewritten for any following calls to this function.
    ///
    /// It is optional to specify a fragment.
    ///
    /// # Examples
    ///
    /// ```
    /// use uriparse::URIBuilder;
    ///
    /// let mut builder = URIBuilder::new();
    /// builder.scheme("urn").path("path").fragment(Some("fragment"));
    /// let uri = builder.build().unwrap();
    /// assert_eq!(uri.to_string(), "urn:path#fragment");
    /// ```
    pub fn fragment<FragmentType, FragmentError>(
        &mut self,
        fragment: Option<FragmentType>,
    ) -> &mut Self
    where
        Fragment<'uri>: TryFrom<FragmentType, Error = FragmentError>,
        InvalidFragment: From<FragmentError>,
    {
        self.uri_reference_builder.fragment(fragment);
        self
    }

    /// Constructs a new builder with nothing set.
    pub fn new() -> Self {
        URIBuilder::default()
    }

    /// Sets the path part of the URI.
    ///
    /// If the given path is not a valid path (i.e. the conversion fails), an error is stored
    /// internally and checked during the [`URIBuilder::build`] function. The error state will be
    /// rewritten for any following calls to this function.
    ///
    /// It is required to specify a path.
    ///
    /// # Examples
    ///
    /// ```
    /// use uriparse::URIBuilder;
    ///
    /// let mut builder = URIBuilder::new();
    /// builder.scheme("urn").path("path");
    /// let uri = builder.build().unwrap();
    /// assert_eq!(uri.to_string(), "urn:path");
    /// ```
    pub fn path<PathType, PathError>(&mut self, path: PathType) -> &mut Self
    where
        Path<'uri>: TryFrom<PathType, Error = PathError>,
        InvalidPath: From<PathError>,
    {
        self.uri_reference_builder.path(path);
        self
    }

    /// Sets the query part of the URI.
    ///
    /// If the given query is not a valid query (i.e. the conversion fails), an error is stored
    /// internally and checked during the [`URIBuilder::build`] function. The error state will be
    /// rewritten for any following calls to this function.
    ///
    /// It is optional to specify a query.
    ///
    /// # Examples
    ///
    /// ```
    /// use uriparse::URIBuilder;
    ///
    /// let mut builder = URIBuilder::new();
    /// builder.scheme("urn").path("path").query(Some("query"));
    /// let uri = builder.build().unwrap();
    /// assert_eq!(uri.to_string(), "urn:path?query");
    /// ```
    pub fn query<QueryType, QueryError>(&mut self, query: Option<QueryType>) -> &mut Self
    where
        Query<'uri>: TryFrom<QueryType, Error = QueryError>,
        InvalidQuery: From<QueryError>,
    {
        self.uri_reference_builder.query(query);
        self
    }

    /// Sets the scheme part of the URI.
    ///
    /// If the given scheme is not a valid scheme (i.e. the conversion fails), an error is stored
    /// internally and checked during the [`URIBuilder::build`] function. The error state will be
    /// rewritten for any following calls to this function.
    ///
    /// It is required to specify a scheme.
    ///
    /// # Examples
    ///
    /// ```
    /// use uriparse::URIBuilder;
    ///
    /// let mut builder = URIBuilder::new();
    /// builder.scheme("urn").path("path");
    /// let uri = builder.build().unwrap();
    /// assert_eq!(uri.to_string(), "urn:path");
    /// ```
    pub fn scheme<SchemeType, SchemeError>(&mut self, scheme: SchemeType) -> &mut Self
    where
        Scheme<'uri>: TryFrom<SchemeType, Error = SchemeError>,
        InvalidScheme: From<SchemeError>,
    {
        self.uri_reference_builder.scheme(Some(scheme));
        self
    }
}

/// An error representing an invalid URI.
#[derive(Clone, Copy, Debug, Eq, Hash, PartialEq)]
#[non_exhaustive]
pub enum InvalidURI {
    /// Represents the case when there is no authority, but the first path segment starts with
    /// `"//"`. This is not allowed because it would be interpreted as an authority component.
    ///
    /// This can only occur when using creation functions that act on individual parts (e.g.
    /// [`URI::from_parts`]).
    AbsolutePathCannotStartWithTwoSlashes,

    /// When parsing from some byte string source, if the source ends up being a relative reference,
    /// then it is obviously not a URI.
    ///
    /// This can only occur when parsing from a byte string source.
    CannotBeRelativeReference,

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
    /// This can only occur when using [`URIBuilder`].
    MissingPath,

    /// This error occurs when you do not specify a scheme component on the builder.
    ///
    /// This can only occur when using [`URIBuilder`].
    MissingScheme,
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
            AbsolutePathCannotStartWithTwoSlashes => "absolute path cannot start with two slashes",
            CannotBeRelativeReference => "cannot be relative reference",
            InvalidAuthority(invalid_authority) => invalid_authority.description(),
            InvalidFragment(invalid_fragment) => invalid_fragment.description(),
            InvalidPath(invalid_path) => invalid_path.description(),
            InvalidQuery(invalid_query) => invalid_query.description(),
            InvalidScheme(invalid_scheme) => invalid_scheme.description(),
            MissingPath => "missing path",
            MissingScheme => "missing scheme",
        }
    }
}

impl From<!> for InvalidURI {
    fn from(value: !) -> Self {
        value
    }
}

impl From<InvalidAuthority> for InvalidURI {
    fn from(value: InvalidAuthority) -> Self {
        InvalidURI::InvalidAuthority(value)
    }
}

impl From<InvalidFragment> for InvalidURI {
    fn from(value: InvalidFragment) -> Self {
        InvalidURI::InvalidFragment(value)
    }
}

impl From<InvalidPath> for InvalidURI {
    fn from(value: InvalidPath) -> Self {
        InvalidURI::InvalidPath(value)
    }
}

impl From<InvalidQuery> for InvalidURI {
    fn from(value: InvalidQuery) -> Self {
        InvalidURI::InvalidQuery(value)
    }
}

impl From<InvalidScheme> for InvalidURI {
    fn from(value: InvalidScheme) -> Self {
        InvalidURI::InvalidScheme(value)
    }
}

impl TryFrom<InvalidURIReference> for InvalidURI {
    type Error = ();

    fn try_from(value: InvalidURIReference) -> Result<Self, Self::Error> {
        use self::InvalidURI::*;

        match value {
            InvalidURIReference::SchemelessPathCannotStartWithColonSegment => Err(()),
            InvalidURIReference::AbsolutePathCannotStartWithTwoSlashes => {
                Ok(AbsolutePathCannotStartWithTwoSlashes)
            }
            InvalidURIReference::InvalidAuthority(invalid_authority) => {
                Ok(InvalidAuthority(invalid_authority))
            }
            InvalidURIReference::InvalidFragment(invalid_fragment) => {
                Ok(InvalidFragment(invalid_fragment))
            }
            InvalidURIReference::InvalidPath(invalid_path) => Ok(InvalidPath(invalid_path)),
            InvalidURIReference::InvalidQuery(invalid_query) => Ok(InvalidQuery(invalid_query)),
            InvalidURIReference::InvalidScheme(invalid_scheme) => Ok(InvalidScheme(invalid_scheme)),
            InvalidURIReference::MissingPath => Ok(MissingPath),
        }
    }
}

#[cfg(test)]
mod test {
    use super::*;

    #[test]
    fn test_resolve() {
        fn test_case(value: &str, expected: &str) {
            let base_uri = URI::try_from("http://a/b/c/d;p?q").unwrap();
            let reference = URIReference::try_from(value).unwrap();
            assert_eq!(base_uri.resolve(&reference).to_string(), expected);
        }

        test_case("g:h", "g:h");
        test_case("g", "http://a/b/c/g");
        test_case("./g", "http://a/b/c/g");
        test_case("g/", "http://a/b/c/g/");
        test_case("/g", "http://a/g");
        test_case("//g", "http://g/");
        test_case("?y", "http://a/b/c/d;p?y");
        test_case("g?y", "http://a/b/c/g?y");
        test_case("#s", "http://a/b/c/d;p?q#s");
        test_case("g#s", "http://a/b/c/g#s");
        test_case("g?y#s", "http://a/b/c/g?y#s");
        test_case(";x", "http://a/b/c/;x");
        test_case("g;x", "http://a/b/c/g;x");
        test_case("g;x?y#s", "http://a/b/c/g;x?y#s");
        test_case("", "http://a/b/c/d;p?q");
        test_case(".", "http://a/b/c/");
        test_case("./", "http://a/b/c/");
        test_case("..", "http://a/b/");
        test_case("../", "http://a/b/");
        test_case("../g", "http://a/b/g");
        test_case("../..", "http://a/");
        test_case("../../", "http://a/");
        test_case("../../g", "http://a/g");
        test_case("../../../g", "http://a/g");
        test_case("../../../g", "http://a/g");
        test_case("/./g", "http://a/g");
        test_case("/../g", "http://a/g");
        test_case("g.", "http://a/b/c/g.");
        test_case(".g", "http://a/b/c/.g");
        test_case("g..", "http://a/b/c/g..");
        test_case("..g", "http://a/b/c/..g");
        test_case("./../g", "http://a/b/g");
        test_case("./g/.", "http://a/b/c/g/");
        test_case("g/./h", "http://a/b/c/g/h");
        test_case("g/../h", "http://a/b/c/h");
        test_case("g;x=1/./y", "http://a/b/c/g;x=1/y");
        test_case("g;x=1/../y", "http://a/b/c/y");
        test_case("g?y/./x", "http://a/b/c/g?y/./x");
        test_case("g?y/../x", "http://a/b/c/g?y/../x");
        test_case("g#s/./x", "http://a/b/c/g#s/./x");
        test_case("g#s/../x", "http://a/b/c/g#s/../x");
        test_case("http:g", "http:g");
    }
}
