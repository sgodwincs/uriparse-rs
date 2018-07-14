#![feature(try_from)]

#[macro_use]
extern crate criterion;
extern crate uri;

use criterion::Criterion;
use std::convert::TryFrom;
use uri::URIReference;

fn parse_benchmark(c: &mut Criterion) {
    let uri = "http://user:pass@192.168.1.1:8080/this/is/a/test/path?thisis=aquery#thisisafragment";

    c.bench_function("parse URI", move |b| {
        b.iter(|| URIReference::try_from(uri).unwrap())
    });
}

criterion_group!(benches, parse_benchmark);
criterion_main!(benches);
