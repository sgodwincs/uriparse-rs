#![feature(non_exhaustive)]
#![feature(try_from)]
#![feature(never_type)]

#[macro_use]
extern crate lazy_static;

mod utility;

pub mod authority;
pub mod fragment;
pub mod path;
pub mod query;
pub mod scheme;
pub mod uri;

pub use authority::{
    Authority, Host, InvalidAuthority, InvalidHost, InvalidPort, InvalidUserInfo, Password,
    RegisteredName, Username,
};
pub use fragment::{Fragment, InvalidFragment};
pub use path::{InvalidPath, Path, Segment};
pub use query::{InvalidQuery, Query};
pub use scheme::{InvalidScheme, Scheme, SchemeStatus, UnregisteredScheme};
pub use uri::{InvalidURI, InvalidURIReference, RelativeReference, URIReference, URI};
