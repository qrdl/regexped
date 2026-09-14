// secret-scanner, the COMPONENT route: the same ten patterns and the same set,
// consumed through the Component Model interface instead of the raw WASM ABI.
//
// The contrast with main.rs beside it is the point of this binary. There the
// host does the work the ABI requires:
//
//   grow memory, pick an input base and an output base, write the input,
//   allocate and ZERO the gate array, call with six arguments, read 12-byte
//   triples out of guest memory, advance `from` by hand
//
// Here none of that exists. `bindgen!` generates the host side from the .wit
// regexped emitted beside the component, the scan is a resource, and the matches
// arrive as a Vec of records. No stub is involved: a stub is for a guest
// compiled to WASM, and this binary is native.
//
// Usage: secret-scanner-component <text>
//        echo "..." | secret-scanner-component -
//
// Build: make component
use anyhow::{anyhow, Result};
use wasmtime::component::{Component, Linker};
use wasmtime::{Config, Engine, Store};

// The path is the .wit regexped wrote beside the component, and the world is
// `wit_package` (a config may override it with `wit_world`). The macro reads the
// file at COMPILE time, so `regexped compile` has to have run — which is what
// the Makefile's ordering guarantees.
wasmtime::component::bindgen!({ path: "component/secrets.wit", world: "secrets" });

include!("pattern_names.rs");

fn main() -> Result<()> {
    let args: Vec<String> = std::env::args().collect();
    let input: Vec<u8> = if args.get(1).map(|s| s.as_str()) == Some("-") {
        use std::io::Read;
        let mut buf = Vec::new();
        std::io::stdin().read_to_end(&mut buf)?;
        buf
    } else if let Some(text) = args.get(1) {
        text.as_bytes().to_vec()
    } else {
        eprintln!("Usage: secret-scanner-component <text>  or  echo '...' | secret-scanner-component -");
        std::process::exit(1);
    };

    let engine = Engine::new(&Config::new())?;
    let component = Component::from_file(&engine, "component/secrets.wasm").map_err(|e| {
        anyhow!("failed to load component/secrets.wasm (run 'make component' first): {}", e)
    })?;
    // Nothing to add to the linker: the component imports nothing.
    let linker = Linker::new(&engine);
    let mut store = Store::new(&engine, ());
    let world = Secrets::instantiate(&mut store, &component, &linker)?;
    let sets = world.regexped_secrets_sets();

    // The scan is a RESOURCE. The constructor copies the input into the
    // component once — which is why the per-position cost below is a call and
    // not a call plus a copy of the input — and owns the gate array the module
    // route has to allocate and zero itself.
    let scan = sets.scan_secrets().call_constructor(&mut store, &input, 0)?;

    let mut total = 0;
    loop {
        // One call per matching POSITION, as in the module route. Every match in
        // a batch shares a start; an empty batch means the scan is finished.
        //
        // The inner Result is the interface's own `error-code`: a Backtracking
        // member exhausted its frame budget, so what remains is UNKNOWN. It is
        // NOT "no more matches", which is why it cannot simply end the loop.
        let batch = match sets.scan_secrets().call_next(&mut store, scan)? {
            Ok(batch) => batch,
            Err(e) => {
                scan.resource_drop(&mut store)?;
                return Err(anyhow!("cannot decide: the engine gave up ({e:?})"));
            }
        };
        if batch.is_empty() {
            break;
        }
        for m in &batch {
            let matched = &input[m.start as usize..m.end as usize];
            println!(
                "[{}] at {}..{}: {}",
                pattern_name(m.id as i32),
                m.start,
                m.end,
                std::str::from_utf8(matched).unwrap_or("<non-utf8>")
            );
            total += 1;
        }
    }

    // Dropping the handle is what releases the scan's state — the input copy,
    // the gate array and the position all live inside the component. The module
    // route has nothing to release, which is exactly the difference the C stubs
    // paper over with a no-op `<func>_free`.
    scan.resource_drop(&mut store)?;

    if total == 0 {
        println!("No secrets found.");
    } else {
        println!("\n{} secret(s) found.", total);
    }
    Ok(())
}
