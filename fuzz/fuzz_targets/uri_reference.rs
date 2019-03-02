#![no_main]

#[macro_use]
extern crate libfuzzer_sys;
extern crate uriparse;

use std::convert::TryFrom;
use uriparse::URIReference;

fuzz_target!(|data: &[u8]| {
    URIReference::try_from(data).ok();
});
