use std::convert::TryFrom;
use std::error::Error;
use std::fmt::{self, Display, Formatter};

use crate::authority::{Authority, Host, InvalidAuthority, Password, Username};
use crate::fragment::{Fragment, InvalidFragment};
use crate::path::{InvalidPath, Path};
use crate::query::{InvalidQuery, Query};
use crate::scheme::Scheme;
use crate::uri_reference::{InvalidURIReference, URIReference, URIReferenceBuilder};

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
        let (_, authority, path, query, fragment) = self.uri_reference.into_parts();
        let mut builder = RelativeReferenceBuilder::new();

        builder
            .authority(authority)
            .path(path)
            .query(query)
            .fragment(fragment);
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

    /// Maps the authority using the given map function.
    ///
    /// This function will panic if, as a result of the authority change, the relative reference
    /// becomes invalid.
    ///
    /// # Examples
    ///
    /// ```
    /// # #![feature(try_from)]
    /// #
    /// use std::convert::TryFrom;
    ///
    /// use uriparse::{Authority, RelativeReference};
    ///
    /// let mut reference = RelativeReference::try_from("").unwrap();
    /// reference.map_authority(|_| Some(Authority::try_from("127.0.0.1").unwrap()));
    /// assert_eq!(reference.to_string(), "//127.0.0.1/");
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
    /// use uriparse::{Fragment, RelativeReference};
    ///
    /// let mut reference = RelativeReference::try_from("/").unwrap();
    /// reference.map_fragment(|_| Some(Fragment::try_from("fragment").unwrap()));
    /// assert_eq!(reference.to_string(), "/#fragment");
    /// ```
    pub fn map_fragment<Mapper>(&mut self, mapper: Mapper) -> Option<&Fragment<'uri>>
    where
        Mapper: FnOnce(Option<Fragment<'uri>>) -> Option<Fragment<'uri>>,
    {
        self.uri_reference.map_fragment(mapper)
    }

    /// Maps the path using the given map function.
    ///
    /// This function will panic if, as a result of the path change, the relative reference becomes
    /// invalid.
    ///
    /// # Examples
    ///
    /// ```
    /// # #![feature(try_from)]
    /// #
    /// use std::convert::TryFrom;
    ///
    /// use uriparse::{Authority, URIReference};
    ///
    /// let mut reference = URIReference::try_from("").unwrap();
    /// reference.map_path(|mut path| {
    ///     path.push("test").unwrap();
    ///     path.push("path").unwrap();
    ///     path
    /// });
    /// assert_eq!(reference.to_string(), "test/path");
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
    /// use uriparse::{Query, RelativeReference};
    ///
    /// let mut reference = RelativeReference::try_from("/path").unwrap();
    /// reference.map_query(|_| Some(Query::try_from("query").unwrap()));
    /// assert_eq!(reference.to_string(), "/path?query");
    /// ```
    pub fn map_query<Mapper>(&mut self, mapper: Mapper) -> Option<&Query<'uri>>
    where
        Mapper: FnOnce(Option<Query<'uri>>) -> Option<Query<'uri>>,
    {
        self.uri_reference.map_query(mapper)
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

    /// Sets the authority of the relative reference.
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
    /// use uriparse::RelativeReference;
    ///
    /// let mut reference = RelativeReference::try_from("//example.com").unwrap();
    /// reference.set_authority(Some("user@example.com:80"));
    /// assert_eq!(reference.to_string(), "//user@example.com:80/");
    /// ```
    pub fn set_authority<AuthorityType, AuthorityError>(
        &mut self,
        authority: Option<AuthorityType>,
    ) -> Result<Option<&Authority<'uri>>, InvalidRelativeReference>
    where
        Authority<'uri>: TryFrom<AuthorityType, Error = AuthorityError>,
        InvalidURIReference: From<AuthorityError>,
    {
        self.uri_reference
            .set_authority(authority)
            .map_err(|error| InvalidRelativeReference::try_from(error).unwrap())
    }

    /// Sets the fragment of the relative reference.
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
    /// use uriparse::RelativeReference;
    ///
    /// let mut reference = RelativeReference::try_from("/my/path").unwrap();
    /// reference.set_fragment(Some("fragment"));
    /// assert_eq!(reference.to_string(), "/my/path#fragment");
    /// ```
    pub fn set_fragment<FragmentType, FragmentError>(
        &mut self,
        fragment: Option<FragmentType>,
    ) -> Result<Option<&Fragment<'uri>>, InvalidRelativeReference>
    where
        Fragment<'uri>: TryFrom<FragmentType, Error = FragmentError>,
        InvalidURIReference: From<FragmentError>,
    {
        self.uri_reference
            .set_fragment(fragment)
            .map_err(|error| InvalidRelativeReference::try_from(error).unwrap())
    }

    /// Sets the path of the relative reference.
    ///
    /// An error will be returned in one of two cases:
    ///  - The conversion to [`Path`] failed.
    ///  - The path was set to a value that resulted in an invalid URI reference.
    ///
    /// Regardless of whether or not the given path was set as absolute or relative, if the relative
    /// reference currently has an authority, the path will be forced to be absolute.
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
    /// let mut reference = RelativeReference::try_from("").unwrap();
    /// reference.set_path("my/path");
    /// assert_eq!(reference.to_string(), "my/path");
    /// ```
    pub fn set_path<PathType, PathError>(
        &mut self,
        path: PathType,
    ) -> Result<&Path<'uri>, InvalidRelativeReference>
    where
        Path<'uri>: TryFrom<PathType, Error = PathError>,
        InvalidURIReference: From<PathError>,
    {
        self.uri_reference
            .set_path(path)
            .map_err(|error| InvalidRelativeReference::try_from(error).unwrap())
    }

    /// Sets the query of the relative reference.
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
    /// use uriparse::RelativeReference;
    ///
    /// let mut reference = RelativeReference::try_from("").unwrap();
    /// reference.set_query(Some("myquery"));
    /// assert_eq!(reference.to_string(), "?myquery");
    /// ```
    pub fn set_query<QueryType, QueryError>(
        &mut self,
        query: Option<QueryType>,
    ) -> Result<Option<&Query<'uri>>, InvalidRelativeReference>
    where
        Query<'uri>: TryFrom<QueryType, Error = QueryError>,
        InvalidURIReference: From<QueryError>,
    {
        self.uri_reference
            .set_query(query)
            .map_err(|error| InvalidRelativeReference::try_from(error).unwrap())
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

impl Display for RelativeReference<'_> {
    fn fmt(&self, formatter: &mut Formatter) -> fmt::Result {
        self.uri_reference.fmt(formatter)
    }
}

impl<'uri> From<RelativeReference<'uri>> for String {
    fn from(value: RelativeReference<'uri>) -> Self {
        value.to_string()
    }
}

impl<'uri> From<RelativeReference<'uri>> for URIReference<'uri> {
    fn from(value: RelativeReference<'uri>) -> Self {
        value.uri_reference
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
