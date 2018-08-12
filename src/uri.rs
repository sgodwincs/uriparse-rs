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
//!
//! Each type also has a corresponding builder type to allow for convenient construction and
//! modification via the [`RelativeReference::into_builder`], [`URI::into_builder`] and
//! [`URIReference::into_builder`] functions.
//!
//! All three types are immutable, so if you want to change a component such as the path, you need
//! to reconstruct the type via either the builder or by converting it into its parts and back.

use std::convert::TryFrom;
use std::error::Error;
use std::fmt::{self, Display, Formatter, Write};

use authority::{parse_authority, Authority, Host, InvalidAuthority, Password, Username};
use fragment::{Fragment, InvalidFragment};
use path::{parse_path, InvalidPath, Path};
use query::{parse_query, InvalidQuery, Query};
use scheme::{parse_scheme, InvalidScheme, Scheme};

/// A relative reference as defined in
/// [[RFC3986, Section 4.1]](https://tools.ietf.org/html/rfc3986#section-4.1).
///
/// Specifically, a relative reference is a URI reference without a scheme.
#[derive(Clone, Debug, Eq, Hash, PartialEq)]
pub struct RelativeReference<'uri> {
    /// All relative references are also URI references, so we just maintain a [`URIReference`]
    /// underneath.
    uri_reference: URIReference<'uri>,
}

impl<'uri> RelativeReference<'uri> {
    /// Returns the authority, if present, of the relative reference.
    ///
    /// # Examples
    ///
    /// ```
    /// # #![feature(try_from)]
    /// #
    /// use std::convert::TryFrom;
    ///
    /// use uriparse::RelativeReference;
    ///
    /// let reference = RelativeReference::try_from("//example.com/my/path").unwrap();
    /// assert_eq!(reference.authority().unwrap().to_string(), "example.com");
    /// ```
    pub fn authority(&self) -> Option<&Authority<'uri>> {
        self.uri_reference.authority()
    }

    /// Constructs a default builder for a relative reference.
    ///
    /// This provides an alternative means of constructing a relative reference besides parsing and
    /// [`RelativeReference::from_parts`].
    ///
    /// # Examples
    ///
    /// ```
    /// use uriparse::RelativeReference;
    ///
    /// let mut builder = RelativeReference::builder();
    /// builder.path("/my/path").fragment(Some("fragment"));
    /// let reference = builder.build().unwrap();
    /// assert_eq!(reference.to_string(), "/my/path#fragment");
    /// ```
    pub fn builder<'new_uri>() -> RelativeReferenceBuilder<'new_uri> {
        RelativeReferenceBuilder::new()
    }

    /// Constructs a new [`RelativeReference`] from the individual parts: authority, path, query,
    /// and fragment.
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
    /// use uriparse::{Scheme, RelativeReference};
    ///
    /// let reference = RelativeReference::from_parts(
    ///     Some("example.com"),
    ///     "/my/path",
    ///     Some("query"),
    ///     Some("fragment")
    /// ).unwrap();
    /// assert_eq!(reference.to_string(), "//example.com/my/path?query#fragment");
    /// ```
    pub fn from_parts<
        'new_uri,
        AuthorityType,
        PathType,
        QueryType,
        FragmentType,
        AuthorityError,
        PathError,
        QueryError,
        FragmentError,
    >(
        authority: Option<AuthorityType>,
        path: PathType,
        query: Option<QueryType>,
        fragment: Option<FragmentType>,
    ) -> Result<RelativeReference<'new_uri>, InvalidRelativeReference>
    where
        Authority<'new_uri>: TryFrom<AuthorityType, Error = AuthorityError>,
        Path<'new_uri>: TryFrom<PathType, Error = PathError>,
        Query<'new_uri>: TryFrom<QueryType, Error = QueryError>,
        Fragment<'new_uri>: TryFrom<FragmentType, Error = FragmentError>,
        InvalidURIReference:
            From<AuthorityError> + From<PathError> + From<QueryError> + From<FragmentError>,
    {
        let uri_reference =
            URIReference::from_parts(None::<Scheme>, authority, path, query, fragment)
                .map_err(|error| InvalidRelativeReference::try_from(error).unwrap())?;
        Ok(RelativeReference { uri_reference })
    }

    /// Returns the fragment, if present, of the relative reference.
    ///
    /// # Examples
    ///
    /// ```
    /// # #![feature(try_from)]
    /// #
    /// use std::convert::TryFrom;
    ///
    /// use uriparse::RelativeReference;
    ///
    /// let reference = RelativeReference::try_from("//example.com#fragment").unwrap();
    /// assert_eq!(reference.fragment().unwrap(), "fragment");
    /// ```
    pub fn fragment(&self) -> Option<&Fragment<'uri>> {
        self.uri_reference.fragment()
    }

    /// Returns whether or not the relative reference has an authority component.
    ///
    /// # Examples
    ///
    /// ```
    /// # #![feature(try_from)]
    /// #
    /// use std::convert::TryFrom;
    ///
    /// use uriparse::RelativeReference;
    ///
    /// let reference = RelativeReference::try_from("//example.com").unwrap();
    /// assert!(reference.has_authority());
    ///
    /// let reference = RelativeReference::try_from("").unwrap();
    /// assert!(!reference.has_authority());
    /// ```
    pub fn has_authority(&self) -> bool {
        self.uri_reference.has_authority()
    }

    /// Returns whether or not the relative reference has a fragment component.
    ///
    /// # Examples
    ///
    /// ```
    /// # #![feature(try_from)]
    /// #
    /// use std::convert::TryFrom;
    ///
    /// use uriparse::RelativeReference;
    ///
    /// let reference = RelativeReference::try_from("#test").unwrap();
    /// assert!(reference.has_fragment());
    ///
    /// let reference = RelativeReference::try_from("/").unwrap();
    /// assert!(!reference.has_fragment());
    /// ```
    pub fn has_fragment(&self) -> bool {
        self.uri_reference.has_fragment()
    }

    /// Returns whether or not the relative reference has a password component.
    ///
    /// # Examples
    ///
    /// ```
    /// # #![feature(try_from)]
    /// #
    /// use std::convert::TryFrom;
    ///
    /// use uriparse::RelativeReference;
    ///
    /// let reference = RelativeReference::try_from("//user:pass@127.0.0.1").unwrap();
    /// assert!(reference.has_password());
    ///
    /// let reference = RelativeReference::try_from("//user@127.0.0.1").unwrap();
    /// assert!(!reference.has_password());
    /// ```
    pub fn has_password(&self) -> bool {
        self.uri_reference.has_password()
    }

    /// Returns whether or not the relative reference has a query component.
    ///
    /// # Examples
    ///
    /// ```
    /// # #![feature(try_from)]
    /// #
    /// use std::convert::TryFrom;
    ///
    /// use uriparse::RelativeReference;
    ///
    /// let reference = RelativeReference::try_from("/?my=query").unwrap();
    /// assert!(reference.has_query());
    ///
    /// let reference = RelativeReference::try_from("/my/path").unwrap();
    /// assert!(!reference.has_query());
    /// ```
    pub fn has_query(&self) -> bool {
        self.uri_reference.has_query()
    }

    /// Returns whether or not the relative reference has a username component.
    ///
    /// # Examples
    ///
    /// ```
    /// # #![feature(try_from)]
    /// #
    /// use std::convert::TryFrom;
    ///
    /// use uriparse::RelativeReference;
    ///
    /// let reference = RelativeReference::try_from("//username@example.com").unwrap();
    /// assert!(reference.has_username());
    ///
    /// let reference = RelativeReference::try_from("").unwrap();
    /// assert!(!reference.has_username());
    /// ```
    pub fn has_username(&self) -> bool {
        self.uri_reference.has_username()
    }

    /// Returns the host, if present, of the relative reference.
    ///
    /// # Examples
    ///
    /// ```
    /// # #![feature(try_from)]
    /// #
    /// use std::convert::TryFrom;
    ///
    /// use uriparse::RelativeReference;
    ///
    /// let reference = RelativeReference::try_from("//username@example.com").unwrap();
    /// assert_eq!(reference.host().unwrap().to_string(), "example.com");
    /// ```
    pub fn host(&self) -> Option<&Host<'uri>> {
        self.uri_reference.host()
    }

    /// Consumes the relative reference and converts it into a builder with the same values.
    ///
    /// # Examples
    ///
    /// ```
    /// # #![feature(try_from)]
    /// #
    /// use std::convert::TryFrom;
    ///
    /// use uriparse::{Fragment, Query, RelativeReference};
    ///
    /// let reference = RelativeReference::try_from("//example.com/path?query#fragment").unwrap();
    /// let mut builder = reference.into_builder();
    /// builder.query(None::<Query>).fragment(None::<Fragment>);
    /// let reference = builder.build().unwrap();
    /// assert_eq!(reference.to_string(), "//example.com/path");
    /// ```
    pub fn into_builder(self) -> RelativeReferenceBuilder<'uri> {
        let mut builder = RelativeReferenceBuilder::new();
        builder
            .authority(self.uri_reference.authority)
            .path(self.uri_reference.path)
            .query(self.uri_reference.query)
            .fragment(self.uri_reference.fragment);
        builder
    }

    /// Converts the [`RelativeReference`] into an owned copy.
    ///
    /// If you construct the relative reference from a source with a non-static lifetime, you may
    /// run into lifetime problems due to the way the struct is designed. Calling this function will
    /// ensure that the returned value has a static lifetime.
    ///
    /// This is different from just cloning. Cloning the relative reference will just copy the
    /// references, and thus the lifetime will remain the same.
    pub fn into_owned(self) -> RelativeReference<'static> {
        RelativeReference {
            uri_reference: self.uri_reference.into_owned(),
        }
    }

    /// Consumes the [`RelativeReference`] and returns its parts: authority, path, query, and
    /// fragment.
    ///
    /// # Examples
    ///
    /// ```
    /// # #![feature(try_from)]
    /// #
    /// use std::convert::TryFrom;
    ///
    /// use uriparse::RelativeReference;
    ///
    /// let reference = RelativeReference::try_from(
    ///     "/my/path?my=query#fragment",
    /// ).unwrap();
    /// let (authority, path, query, fragment) = reference.into_parts();
    ///
    /// assert_eq!(authority, None);
    /// assert_eq!(path, "/my/path");
    /// assert_eq!(query.unwrap(), "my=query");
    /// assert_eq!(fragment.unwrap(), "fragment");
    /// ```
    pub fn into_parts(
        self,
    ) -> (
        Option<Authority<'uri>>,
        Path<'uri>,
        Option<Query<'uri>>,
        Option<Fragment<'uri>>,
    ) {
        let (_, authority, path, query, fragment) = self.uri_reference.into_parts();
        (authority, path, query, fragment)
    }

    /// Returns whether or not the relative reference is an absolute path reference.
    ///
    /// A URI reference is an absolute path reference if it is a relative reference that begins with
    /// a single `'/'`.
    ///
    /// # Examples
    ///
    /// ```
    /// # #![feature(try_from)]
    /// #
    /// use std::convert::TryFrom;
    ///
    /// use uriparse::RelativeReference;
    ///
    /// let reference = RelativeReference::try_from("/my/path").unwrap();
    /// assert!(reference.is_absolute_path_reference());
    /// ```
    pub fn is_absolute_path_reference(&self) -> bool {
        self.uri_reference.is_absolute_path_reference()
    }

    /// Returns whether or not the relative reference is a network path reference.
    ///
    /// A relative reference is a network path reference if it is a relative reference that begins
    /// with two `'/'`.
    ///
    /// # Examples
    ///
    /// ```
    /// # #![feature(try_from)]
    /// #
    /// use std::convert::TryFrom;
    ///
    /// use uriparse::RelativeReference;
    ///
    /// let reference = RelativeReference::try_from("//example.com").unwrap();
    /// assert!(reference.is_network_path_reference());
    /// ```
    pub fn is_network_path_reference(&self) -> bool {
        self.uri_reference.is_network_path_reference()
    }

    /// Returns whether or not the relative reference is a relative path reference.
    ///
    /// A relative reference is a relative path reference if it is a relative reference that does
    /// not begin with a `'/'`.
    ///
    /// # Examples
    ///
    /// ```
    /// # #![feature(try_from)]
    /// #
    /// use std::convert::TryFrom;
    ///
    /// use uriparse::RelativeReference;
    ///
    /// let reference = RelativeReference::try_from("my/path").unwrap();
    /// assert!(reference.is_relative_path_reference());
    /// ```
    pub fn is_relative_path_reference(&self) -> bool {
        self.uri_reference.is_relative_path_reference()
    }

    /// Returns the path of the relative reference.
    ///
    /// # Examples
    ///
    /// ```
    /// # #![feature(try_from)]
    /// #
    /// use std::convert::TryFrom;
    ///
    /// use uriparse::RelativeReference;
    ///
    /// let reference = RelativeReference::try_from("/my/path").unwrap();
    /// assert_eq!(reference.path(), "/my/path");
    /// ```
    pub fn path(&self) -> &Path<'uri> {
        self.uri_reference.path()
    }

    /// Returns the password, if present, of the relative reference.
    ///
    /// Usage of a password in URI and URI references is deprecated.
    ///
    /// # Examples
    ///
    /// ```
    /// # #![feature(try_from)]
    /// #
    /// use std::convert::TryFrom;
    ///
    /// use uriparse::RelativeReference;
    ///
    /// let reference = RelativeReference::try_from("//user:pass@example.com").unwrap();
    /// assert_eq!(reference.password().unwrap(), "pass");
    /// ```
    pub fn password(&self) -> Option<&Password<'uri>> {
        self.uri_reference.password()
    }

    /// Returns the port, if present, of the relative reference.
    ///
    /// # Examples
    ///
    /// ```
    /// # #![feature(try_from)]
    /// #
    /// use std::convert::TryFrom;
    ///
    /// use uriparse::RelativeReference;
    ///
    /// let reference = RelativeReference::try_from("//example.com:8080/").unwrap();
    /// assert_eq!(reference.port().unwrap(), 8080);
    /// ```
    pub fn port(&self) -> Option<u16> {
        self.uri_reference.port()
    }

    /// Returns the query, if present, of the relative reference.
    ///
    /// # Examples
    ///
    /// ```
    /// # #![feature(try_from)]
    /// #
    /// use std::convert::TryFrom;
    ///
    /// use uriparse::RelativeReference;
    ///
    /// let reference = RelativeReference::try_from("?my=query").unwrap();
    /// assert_eq!(reference.query().unwrap(), "my=query");
    /// ```
    pub fn query(&self) -> Option<&Query<'uri>> {
        self.uri_reference.query()
    }

    /// Returns the username, if present, of the relative reference.
    ///
    /// # Examples
    ///
    /// ```
    /// # #![feature(try_from)]
    /// #
    /// use std::convert::TryFrom;
    ///
    /// use uriparse::RelativeReference;
    ///
    /// let reference = RelativeReference::try_from("//username@example.com").unwrap();
    /// assert_eq!(reference.username().unwrap(), "username");
    /// ```
    pub fn username(&self) -> Option<&Username<'uri>> {
        self.uri_reference.username()
    }
}

impl<'uri> Display for RelativeReference<'uri> {
    fn fmt(&self, formatter: &mut Formatter) -> fmt::Result {
        self.uri_reference.fmt(formatter)
    }
}

impl<'uri> From<RelativeReference<'uri>> for String {
    fn from(value: RelativeReference<'uri>) -> String {
        value.to_string()
    }
}

impl<'uri> TryFrom<&'uri [u8]> for RelativeReference<'uri> {
    type Error = InvalidRelativeReference;

    fn try_from(value: &'uri [u8]) -> Result<Self, Self::Error> {
        let uri_reference = URIReference::try_from(value)
            .map_err(|error| InvalidRelativeReference::try_from(error).unwrap())?;

        if uri_reference.is_uri() {
            Err(InvalidRelativeReference::CannotBeURI)
        } else {
            Ok(RelativeReference { uri_reference })
        }
    }
}

impl<'uri> TryFrom<&'uri str> for RelativeReference<'uri> {
    type Error = InvalidRelativeReference;

    fn try_from(value: &'uri str) -> Result<Self, Self::Error> {
        RelativeReference::try_from(value.as_bytes())
    }
}

impl<'uri> TryFrom<URIReference<'uri>> for RelativeReference<'uri> {
    type Error = InvalidRelativeReference;

    fn try_from(value: URIReference<'uri>) -> Result<Self, Self::Error> {
        if value.is_relative_reference() {
            Ok(RelativeReference {
                uri_reference: value,
            })
        } else {
            Err(InvalidRelativeReference::CannotBeURI)
        }
    }
}

/// A builder type for [`RelativeReference]`.
///
/// You must use the [`RelativeReferenceBuilder::path`] function before building as relative
/// references always have a path. Everything else is optional.
#[derive(Clone, Debug, Default, Eq, PartialEq)]
pub struct RelativeReferenceBuilder<'uri> {
    /// All relative references are also URI references, so we just maintain a
    /// [`URIReferenceBuilder`] underneath.
    uri_reference_builder: URIReferenceBuilder<'uri>,
}

impl<'uri> RelativeReferenceBuilder<'uri> {
    /// Sets the authority part of the relative reference.
    ///
    /// If the given authority is not a valid authority (i.e. the conversion fails), an error is
    /// stored internally and checked during the [`RelativeReferenceBuilder::build`] function. The
    /// error state will be rewritten for any following calls to this function.
    ///
    /// It is optional to specify an authority.
    ///
    /// # Examples
    ///
    /// ```
    /// use uriparse::RelativeReferenceBuilder;
    ///
    /// let mut builder = RelativeReferenceBuilder::new();
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
        self.uri_reference_builder.authority(authority);
        self
    }

    /// Consumes the builder and tries to build a [`RelativeReference`].
    ///
    /// This function will error in one of three situations:
    ///  - One of the components specified in the builder is invalid.
    ///  - A path was not specified in the builder.
    ///  - While all individual components were valid, their combination as a relative reference was
    ///    invalid.
    ///
    /// # Examples
    ///
    /// First error type (invalid path):
    ///
    /// ```
    /// use uriparse::RelativeReferenceBuilder;
    ///
    /// let mut builder = RelativeReferenceBuilder::new();
    /// builder.path("this is an invalid path %%%");
    /// assert!(builder.build().is_err());
    /// ```
    ///
    /// Second error type (path not specified):
    ///
    /// ```
    /// use uriparse::RelativeReferenceBuilder;
    ///
    /// let builder = RelativeReferenceBuilder::new();
    /// assert!(builder.build().is_err());
    /// ```
    ///
    /// Third error type (first segment in schemeless path cannot contain a `':'`):
    ///
    /// ```
    /// use uriparse::RelativeReferenceBuilder;
    ///
    /// let mut builder = RelativeReferenceBuilder::new();
    /// builder.path("my:/path");
    /// assert!(builder.build().is_err());
    /// ```
    pub fn build(self) -> Result<RelativeReference<'uri>, InvalidRelativeReference> {
        Ok(RelativeReference {
            uri_reference: self
                .uri_reference_builder
                .build()
                .map_err(|error| InvalidRelativeReference::try_from(error).unwrap())?,
        })
    }

    /// Sets the fragment part of the relative reference.
    ///
    /// If the given fragment is not a valid fragment (i.e. the conversion fails), an error is
    /// stored internally and checked during the [`RelativeReferenceBuilder::build`] function. The
    /// error state will be rewritten for any following calls to this function.
    ///
    /// It is optional to specify a fragment.
    ///
    /// # Examples
    ///
    /// ```
    /// use uriparse::RelativeReferenceBuilder;
    ///
    /// let mut builder = RelativeReferenceBuilder::new();
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
        self.uri_reference_builder.fragment(fragment);
        self
    }

    /// Constructs a new builder with nothing set.
    pub fn new() -> Self {
        RelativeReferenceBuilder::default()
    }

    /// Sets the path part of the relative reference.
    ///
    /// If the given path is not a valid path (i.e. the conversion fails), an error is stored
    /// internally and checked during the [`RelativeReferenceBuilder::build`] function. The error
    /// state will be rewritten for any following calls to this function.
    ///
    /// It is required to specify an path. Not doing so will result in an error during the
    /// [`RelativeReferenceBuilder::build`] function.
    ///
    /// # Examples
    ///
    /// ```
    /// use uriparse::RelativeReferenceBuilder;
    ///
    /// let mut builder = RelativeReferenceBuilder::new();
    /// builder.path("/my/path");
    /// let reference = builder.build().unwrap();
    /// assert_eq!(reference.to_string(), "/my/path");
    /// ```
    pub fn path<PathType, PathError>(&mut self, path: PathType) -> &mut Self
    where
        Path<'uri>: TryFrom<PathType, Error = PathError>,
        InvalidPath: From<PathError>,
    {
        self.uri_reference_builder.path(path);
        self
    }

    /// Sets the query part of the relative reference.
    ///
    /// If the given query is not a valid query (i.e. the conversion fails), an error is stored
    /// internally and checked during the [`RelativeReferenceBuilder::build`] function. The error
    /// state will be rewritten for any following calls to this function.
    ///
    /// It is optional to specify a query.
    ///
    /// # Examples
    ///
    /// ```
    /// use uriparse::RelativeReferenceBuilder;
    ///
    /// let mut builder = RelativeReferenceBuilder::new();
    /// builder.path("/my/path").query(Some("query"));
    /// let reference = builder.build().unwrap();
    /// assert_eq!(reference.to_string(), "/my/path?query");
    /// ```
    pub fn query<QueryType, QueryError>(&mut self, query: Option<QueryType>) -> &mut Self
    where
        Query<'uri>: TryFrom<QueryType, Error = QueryError>,
        InvalidQuery: From<QueryError>,
    {
        self.uri_reference_builder.query(query);
        self
    }
}

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

    /// Returns whether or not the URI can act as a base URI.
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

    /// Returns whether or not the URI has an authority component.
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

    /// Returns whether or not the URI has a fragment component.
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

    /// Returns whether or not the URI has a password component.
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

    /// Returns whether or not the URI has a query component.
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

    /// Returns whether or not the URI has a username component.
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
        let mut builder = URIBuilder::new();
        builder
            .scheme(self.uri_reference.scheme.unwrap())
            .authority(self.uri_reference.authority)
            .path(self.uri_reference.path)
            .query(self.uri_reference.query)
            .fragment(self.uri_reference.fragment);
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

impl<'uri> Display for URI<'uri> {
    fn fmt(&self, formatter: &mut Formatter) -> fmt::Result {
        self.uri_reference.fmt(formatter)
    }
}

impl<'uri> From<URI<'uri>> for String {
    fn from(value: URI<'uri>) -> String {
        value.to_string()
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
    /// # #![feature(try_from)]
    /// #
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

    /// Returns whether or not the URI reference can act as a base URI.
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
    /// # #![feature(try_from)]
    /// #
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

        if authority.is_some() {
            path.set_absolute(true);
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

    /// Returns the fragment, if present, of the URI reference.
    ///
    /// # Examples
    ///
    /// ```
    /// # #![feature(try_from)]
    /// #
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

    /// Returns whether or not the URI reference has an authority component.
    ///
    /// # Examples
    ///
    /// ```
    /// # #![feature(try_from)]
    /// #
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

    /// Returns whether or not the URI reference has a fragment component.
    ///
    /// # Examples
    ///
    /// ```
    /// # #![feature(try_from)]
    /// #
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

    /// Returns whether or not the URI reference has a password component.
    ///
    /// # Examples
    ///
    /// ```
    /// # #![feature(try_from)]
    /// #
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

    /// Returns whether or not the URI reference has a query component.
    ///
    /// # Examples
    ///
    /// ```
    /// # #![feature(try_from)]
    /// #
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

    /// Returns whether or not the URI reference has a scheme component.
    ///
    /// # Examples
    ///
    /// ```
    /// # #![feature(try_from)]
    /// #
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

    /// Returns whether or not the URI reference has a username component.
    ///
    /// # Examples
    ///
    /// ```
    /// # #![feature(try_from)]
    /// #
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
    /// # #![feature(try_from)]
    /// #
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
    /// # #![feature(try_from)]
    /// #
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
    /// # #![feature(try_from)]
    /// #
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

    /// Returns whether or not the URI reference is an absolute path reference.
    ///
    /// A URI reference is an absolute path reference if it is a relative reference that begins with
    /// a single `'/'`.
    ///
    /// # Examples
    ///
    /// ```
    /// # #![feature(try_from)]
    /// #
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

    /// Returns whether or not the URI reference is a network path reference.
    ///
    /// A URI reference is a network path reference if it is a relative reference that begins with
    /// two `'/'`.
    ///
    /// # Examples
    ///
    /// ```
    /// # #![feature(try_from)]
    /// #
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

    /// Returns whether or not the URI reference is a relative path reference.
    ///
    /// A URI reference is a relative path reference if it is a relative reference that does not
    /// begin with a `'/'`.
    ///
    /// # Examples
    ///
    /// ```
    /// # #![feature(try_from)]
    /// #
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

    /// Returns whether or not the URI reference is a relative reference.
    ///
    /// A URI reference is a relative reference if it has no scheme.
    ///
    /// # Examples
    ///
    /// ```
    /// # #![feature(try_from)]
    /// #
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

    /// Returns whether or not the URI reference is a URI.
    ///
    /// A URI reference is a URI if it has a scheme.
    ///
    /// # Examples
    ///
    /// ```
    /// # #![feature(try_from)]
    /// #
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

    /// Returns the path of the URI reference.
    ///
    /// # Examples
    ///
    /// ```
    /// # #![feature(try_from)]
    /// #
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
    /// # #![feature(try_from)]
    /// #
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
    /// # #![feature(try_from)]
    /// #
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
    /// # #![feature(try_from)]
    /// #
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
    /// # #![feature(try_from)]
    /// #
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

    /// Returns the username, if present, of the URI reference.
    ///
    /// # Examples
    ///
    /// ```
    /// # #![feature(try_from)]
    /// #
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

impl<'uri> From<URIReference<'uri>> for String {
    fn from(value: URIReference<'uri>) -> String {
        value.to_string()
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

/// An error representing an invalid relative reference.
#[derive(Clone, Debug, Eq, Hash, PartialEq)]
pub enum InvalidRelativeReference {
    /// Represents the case where there is no authority, but the first path segment starts with
    /// `"//"`. This is not allowed because it would be interpreted as an authority component.
    ///
    /// This can only occur when using creation functions that act on individual parts (e.g.
    /// [`RelativeReference::from_parts`]).
    AbsolutePathCannotStartWithTwoSlashes,

    /// When parsing from some byte string source, if the source ends up being a URI, then it is
    /// obviously not a relative reference.
    ///
    /// This can only occur when parsing from a byte string source.
    CannotBeURI,

    /// The authority component of the relative reference was invalid.
    InvalidAuthority(InvalidAuthority),

    /// The fragment component of the relative reference was invalid.
    InvalidFragment(InvalidFragment),

    /// The path component of the relative reference was invalid.
    InvalidPath(InvalidPath),

    /// The query component of the relative reference was invalid.
    InvalidQuery(InvalidQuery),

    /// This error occurs when you do not specify a path component on the builder.
    ///
    /// This can only occur when using [`RelativeReferenceBuilder`].
    MissingPath,

    /// Represents the case where the first path segment contains a `':'`. This is not allowed
    /// because it would be interpreted as a scheme component.
    ///
    /// This can only occur when using creation functions that act on individual parts (e.g.
    /// [`RelativeReference::from_parts`]).
    SchemelessPathCannotStartWithColonSegment,
}

impl Display for InvalidRelativeReference {
    fn fmt(&self, formatter: &mut Formatter) -> fmt::Result {
        formatter.write_str(self.description())
    }
}

impl Error for InvalidRelativeReference {
    fn description(&self) -> &str {
        use self::InvalidRelativeReference::*;

        match self {
            AbsolutePathCannotStartWithTwoSlashes => "absolute path cannot start with two slashes",
            CannotBeURI => "cannot be URI",
            InvalidAuthority(invalid_authority) => invalid_authority.description(),
            InvalidFragment(invalid_fragment) => invalid_fragment.description(),
            InvalidPath(invalid_path) => invalid_path.description(),
            InvalidQuery(invalid_query) => invalid_query.description(),
            MissingPath => "missing path",
            SchemelessPathCannotStartWithColonSegment => {
                "schemeless path cannot start with colon segment"
            }
        }
    }
}

impl From<!> for InvalidRelativeReference {
    fn from(value: !) -> Self {
        value
    }
}

impl From<InvalidAuthority> for InvalidRelativeReference {
    fn from(value: InvalidAuthority) -> Self {
        InvalidRelativeReference::InvalidAuthority(value)
    }
}

impl From<InvalidFragment> for InvalidRelativeReference {
    fn from(value: InvalidFragment) -> Self {
        InvalidRelativeReference::InvalidFragment(value)
    }
}

impl From<InvalidPath> for InvalidRelativeReference {
    fn from(value: InvalidPath) -> Self {
        InvalidRelativeReference::InvalidPath(value)
    }
}

impl From<InvalidQuery> for InvalidRelativeReference {
    fn from(value: InvalidQuery) -> Self {
        InvalidRelativeReference::InvalidQuery(value)
    }
}

impl TryFrom<InvalidURIReference> for InvalidRelativeReference {
    type Error = ();

    fn try_from(value: InvalidURIReference) -> Result<Self, Self::Error> {
        use self::InvalidRelativeReference::*;

        match value {
            InvalidURIReference::InvalidScheme(_) => Err(()),
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
            InvalidURIReference::MissingPath => Ok(MissingPath),
            InvalidURIReference::SchemelessPathCannotStartWithColonSegment => {
                Ok(SchemelessPathCannotStartWithColonSegment)
            }
        }
    }
}

/// An error representing an invalid URI.
#[derive(Clone, Debug, Eq, Hash, PartialEq)]
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

/// An error representing an invalid URI reference.
#[derive(Clone, Debug, Eq, Hash, PartialEq)]
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

impl From<!> for InvalidURIReference {
    fn from(value: !) -> Self {
        value
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

    #[test]
    fn test_parse_uri_reference() {
        let actual = URIReference::try_from("http://example.com").unwrap();
        let expected = URIReference::from_parts(
            Some(Scheme::HTTP),
            Some("example.com"),
            "/",
            None::<Query>,
            None::<Fragment>,
        ).unwrap();
        assert_eq!(actual, expected);

        let actual = URIReference::try_from("http://example.com/").unwrap();
        let expected = URIReference::from_parts(
            Some(Scheme::HTTP),
            Some("example.com"),
            "/",
            None::<Query>,
            None::<Fragment>,
        ).unwrap();
        assert_eq!(actual, expected);

        let actual = URIReference::try_from("http://example.com").unwrap();
        let expected = URIReference::from_parts(
            Some(Scheme::HTTP),
            Some("example.com"),
            "",
            None::<Query>,
            None::<Fragment>,
        ).unwrap();
        assert_eq!(actual, expected);

        let actual = URIReference::try_from("http://example.com/").unwrap();
        let expected = URIReference::from_parts(
            Some(Scheme::HTTP),
            Some("example.com"),
            "",
            None::<Query>,
            None::<Fragment>,
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
