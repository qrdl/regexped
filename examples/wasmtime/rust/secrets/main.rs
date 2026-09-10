// A Rust HOST for a regexped component.
//
// The module-format examples compile themselves to wasm32-wasip1 and are merged
// with the regexp module by wasm-merge, calling it through generated FFI stubs.
// A component is the other way round: this is a native binary that embeds
// wasmtime, loads the component, and calls it through bindings generated from
// the WIT at compile time.
//
// Two consequences worth seeing in the code below:
//
//   * There is no generated iterator. `find` answers ONE match, so the host owns
//     the drive loop — including the advance rule that makes it terminate over a
//     zero-length match. That rule is the whole content of the generated
//     FindIter in the module-format stubs.
//   * The engine's "I don't know" is in the type. A Backtracking pattern that
//     exhausts its frame budget yields Err(ErrorCode::BacktrackOverflow), which
//     is NOT "no secrets found".

wasmtime::component::bindgen!({
    // Written next to the component by `regexped compile`.
    path: "secrets.wit",
    world: "secrets",
});

use wasmtime::component::{Component, Linker};
use wasmtime::{Engine, Store};

use exports::regexped::secrets::matcher::ErrorCode;

fn main() {
    let args: Vec<String> = std::env::args().collect();
    if args.len() < 2 {
        eprintln!("Usage: secrets <input>");
        std::process::exit(1);
    }
    if let Err(err) = run(args[1].as_bytes()) {
        eprintln!("cannot decide: {err}");
        std::process::exit(2);
    }
}

fn run(input: &[u8]) -> anyhow::Result<()> {
    let engine = Engine::default();
    let component = Component::from_file(&engine, "secrets.wasm")?;
    let linker = Linker::new(&engine);
    let mut store = Store::new(&engine, ());
    let secrets = Secrets::instantiate(&mut store, &component, &linker)?;
    let matcher = secrets.regexped_secrets_matcher();

    let mut found = false;
    for (label, which) in [
        ("GitHub token", Which::GitHub),
        ("JWT", Which::Jwt),
        ("AWS key", Which::Aws),
    ] {
        // The host's own drive loop. `find` reports the leftmost match at or
        // after `start`; advancing by (end - start), or by one when the match was
        // empty, is what keeps this from spinning forever.
        let mut start: u32 = 0;
        loop {
            let answer = match which {
                Which::GitHub => matcher.call_find_github_token(&mut store, input, start)?,
                Which::Jwt => matcher.call_find_jwt_token(&mut store, input, start)?,
                Which::Aws => matcher.call_find_aws_key(&mut store, input, start)?,
            };
            let span = match answer {
                Ok(Some(span)) => span,
                Ok(None) => break,
                // The engine abandoned part of the search space, so it does not
                // know whether the input matches. Reporting "no secrets" here
                // would be a lie of exactly the dangerous kind.
                Err(ErrorCode::BacktrackOverflow) => {
                    anyhow::bail!("{label}: the engine exhausted its backtrack budget")
                }
            };
            let (s, e) = (span.0 as usize, span.1 as usize);
            let text = std::str::from_utf8(&input[s..e]).unwrap_or("?");
            println!("{label} at {s}..{e}: {text}");
            found = true;
            start = if span.1 > span.0 { span.1 } else { span.0 + 1 };
            if start as usize > input.len() {
                break;
            }
        }
    }
    if !found {
        println!("No secrets found");
    }
    Ok(())
}

enum Which {
    GitHub,
    Jwt,
    Aws,
}
