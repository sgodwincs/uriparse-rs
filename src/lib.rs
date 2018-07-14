#![feature(non_exhaustive)]
#![feature(try_from)]
#![feature(test)]
#![feature(specialization)]
#![feature(never_type)]

#[macro_use]
extern crate lazy_static;
extern crate test;

#[macro_use]
macro_rules! byte_map {
    ($($flag:expr,)*) => ([
        $($flag != 0,)*
    ])
}

mod utility;

pub mod authority;
pub mod fragment;
pub mod path;
pub mod query;
pub mod scheme;
pub mod uri;

pub use scheme::{InvalidScheme, Scheme, SchemeStatus};
pub use uri::URIReference;

extern crate url;
use test::Bencher;
use url::Url;

#[bench]
fn bench_test(b: &mut Bencher) {
    let s = "rtsp://user:pass@192.168.1.1:8080/this/is/a/test/path?complex=query#thisisafragment";

    b.iter(|| {
        Url::parse(s).unwrap();
    });
}
