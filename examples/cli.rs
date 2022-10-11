use std::env;

fn main() {
    let mut args = env::args();
    let argv0 = args.next()
        .expect("First argument is always present");

    if args.size_hint().1 == Some(0) {
        eprintln!("No URIs were given on the command line.");
        eprintln!("Try running this as `{} http://example.com:1234/hello ../../path`", argv0);
    }

    for uri in args {
        let parsed = uriparse::URIReference::try_from(uri.as_str());
        println!("<{}>: {:#?}", uri, parsed);

        if let Ok(parsed) = parsed {
            let reconstructed = format!("{}", parsed);
            if reconstructed != uri {
                println!("Warning: URI doesn't round-trip -- serializes into:");
                println!("<{}>", reconstructed);
            }
        }
    }
}
