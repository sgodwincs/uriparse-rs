#![feature(never_type)]
#![feature(non_exhaustive)]
#![feature(try_from)]

mod utility;

pub mod authority;
pub mod fragment;
pub mod path;
pub mod query;
pub mod relative_reference;
pub mod scheme;
pub mod uri;
pub mod uri_reference;

pub use self::authority::{
    Authority, Host, InvalidAuthority, InvalidHost, InvalidPort, InvalidUserInfo, Password,
    RegisteredName, Username,
};
pub use self::fragment::{Fragment, InvalidFragment};
pub use self::path::{InvalidPath, Path, Segment};
pub use self::query::{InvalidQuery, Query};
pub use self::relative_reference::{
    InvalidRelativeReference, RelativeReference, RelativeReferenceBuilder,
};
pub use self::scheme::{InvalidScheme, Scheme, SchemeStatus, UnregisteredScheme};
pub use self::uri::{InvalidURI, URIBuilder, URI};
pub use self::uri_reference::{InvalidURIReference, URIReference, URIReferenceBuilder};
