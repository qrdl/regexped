// secret-scanner: demonstrates regexped set composition for multi-pattern scanning.
//
// Compiles 10 secret-detection patterns into one merged WASM set, then scans
// input text returning (pattern_id, start, length) tuples via a single
// find_all export. One WASM call returns all matches; no N-pattern loop.
//
// Usage: secret-scanner <text>
//        echo "..." | secret-scanner -
//
// Build: make

use anyhow::{anyhow, Result};
use wasmtime::{Engine, Instance, Module, Store};

// Pattern names — must match the order of `regexps:` in regexped.yaml.
const PATTERN_NAMES: &[&str] = &[
    "aws_key",
    "aws_secret",
    "github_pat",
    "github_oauth",
    "github_app",
    "jwt",
    "slack_token",
    "stripe_live",
    "stripe_test",
    "google_api",
];

fn pattern_name(id: i32) -> &'static str {
    PATTERN_NAMES.get(id as usize).copied().unwrap_or("unknown")
}

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
        eprintln!("Usage: secret-scanner <text>  or  echo '...' | secret-scanner -");
        std::process::exit(1);
    };

    // Load the standalone WASM module compiled by: regexped compile --config=regexped.yaml
    let engine = Engine::default();
    let module = Module::from_file(&engine, "secrets.wasm")
        .map_err(|e| anyhow!("failed to load secrets.wasm (run 'make compile' first): {}", e))?;
    let mut store = Store::new(&engine, ());
    let instance = Instance::new(&mut store, &module, &[])?;

    let memory = instance
        .get_memory(&mut store, "memory")
        .ok_or_else(|| anyhow!("WASM module has no 'memory' export"))?;

    // The default (gated) `find` body: (ptr, len, from, gate_ptr, out_ptr, out_cap) -> total
    let scan_fn = instance
        .get_typed_func::<(i32, i32, i32, i32, i32, i32), i32>(&mut store, "scan_secrets")
        .map_err(|e| anyhow!("'scan_secrets' export not found: {}", e))?;

    // out_cap is the set's pattern count: the exact worst case for one
    // position, so a call can never overflow.
    const PATTERN_COUNT: i32 = 10;

    // Derive input/output bases from the module's actual initial memory size.
    // The initial pages cover all DFA table data; input, output and the gate
    // array go in the two pages grown immediately after.
    let in_base: i32 = (memory.size(&store) * 65536) as i32;
    memory.grow(&mut store, 2)?; // 1 page for input, 1 page for output + gates
    let out_base: i32 = in_base + 65536;
    let gate_base: i32 = out_base + PATTERN_COUNT * 12;

    // Write input into WASM memory (input page: [in_base, out_base)).
    let max_input = (out_base - in_base) as usize;
    if input.len() > max_input {
        return Err(anyhow!("input too large: {} bytes (max {} bytes)", input.len(), max_input));
    }
    memory.write(&mut store, in_base as usize, &input)
        .map_err(|e| anyhow!("memory write failed: {}", e))?;

    // The gate array is the caller's: zero it for a clean scan. Its contents
    // are opaque — zeroing is the only operation a caller ever performs on it.
    memory.write(&mut store, gate_base as usize, &vec![0u8; (PATTERN_COUNT * 4) as usize])
        .map_err(|e| anyhow!("gate array init failed: {}", e))?;

    // Scan: each call returns every match at the next matching position.
    let mut from: i32 = 0;
    let mut total_matches = 0;

    loop {
        let count = scan_fn.call(
            &mut store,
            (in_base, input.len() as i32, from, gate_base, out_base, PATTERN_COUNT),
        )?;
        if count == 0 {
            break;
        }

        // Read match tuples: each is (pattern_id i32, start i32, end i32) = 12 bytes.
        // Every tuple in one call shares the same start.
        let mem_data = memory.data(&store);
        let mut this_start = 0i32;
        for i in 0..count as usize {
            let base = out_base as usize + i * 12;
            let pid    = i32::from_le_bytes(mem_data[base..base+4].try_into()?);
            let mstart = i32::from_le_bytes(mem_data[base+4..base+8].try_into()?);
            let mend   = i32::from_le_bytes(mem_data[base+8..base+12].try_into()?);
            this_start = mstart;
            let matched = &input[mstart as usize..mend as usize];
            println!(
                "[{}] at {}..{}: {}",
                pattern_name(pid),
                mstart,
                mend,
                std::str::from_utf8(matched).unwrap_or("<non-utf8>")
            );
            total_matches += 1;
        }

        // Resume one past the reported position. Gating (the default) makes
        // the engine skip anything a pattern has already reported, so this
        // yields Go FindAll semantics per pattern.
        from = this_start + 1;
    }

    if total_matches == 0 {
        println!("No secrets found.");
    } else {
        println!("\n{} secret(s) found.", total_matches);
    }

    Ok(())
}
