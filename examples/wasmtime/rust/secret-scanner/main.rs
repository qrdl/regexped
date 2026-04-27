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

// Pattern names — must match the order of `regexes:` in regexped.yaml.
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

    let scan_fn = instance
        .get_typed_func::<(i32, i32, i32, i32, i32), i32>(&mut store, "scan_secrets")
        .map_err(|e| anyhow!("'scan_secrets' export not found: {}", e))?;

    // Memory layout for standalone WASM:
    //   pages 0–1: DFA tables for 10 patterns (≤128 KB for this set)
    //   page  2:   input buffer  (offset 131072)
    //   page  3:   output buffer (offset 196608)
    const IN_BASE: i32 = 131_072; // page 2
    const OUT_BASE: i32 = 196_608; // page 3
    const OUT_CAP: i32 = 64; // up to 64 matches per batch

    // Grow memory to 4 pages (256 KB) to fit tables + input + output.
    let needed: u64 = 4;
    let current = memory.size(&store);
    if current < needed {
        memory.grow(&mut store, needed - current)?;
    }

    // Write input into WASM memory.
    memory.write(&mut store, IN_BASE as usize, &input)
        .map_err(|_| anyhow!("input too large for page 2 buffer (max 65535 bytes)"))?;

    // Scan: call find_all in batches until exhausted.
    let mut start_pos: i32 = 0;
    let mut total_matches = 0;

    loop {
        let count = scan_fn.call(&mut store, (IN_BASE, input.len() as i32, OUT_BASE, OUT_CAP, start_pos))?;
        if count == 0 {
            break;
        }

        // Read match tuples: each is (pattern_id i32, start i32, length i32) = 12 bytes.
        let mem_data = memory.data(&store);
        for i in 0..count as usize {
            let base = OUT_BASE as usize + i * 12;
            let pid    = i32::from_le_bytes(mem_data[base..base+4].try_into()?);
            let mstart = i32::from_le_bytes(mem_data[base+4..base+8].try_into()?);
            let mlen   = i32::from_le_bytes(mem_data[base+8..base+12].try_into()?);
            let matched = &input[mstart as usize..(mstart + mlen) as usize];
            println!(
                "[{}] at {}..{}: {}",
                pattern_name(pid),
                mstart,
                mstart + mlen,
                std::str::from_utf8(matched).unwrap_or("<non-utf8>")
            );
            total_matches += 1;
        }

        // Advance start_pos past the last match.
        let last = OUT_BASE as usize + (count as usize - 1) * 12;
        let last_start = i32::from_le_bytes(mem_data[last+4..last+8].try_into()?);
        let last_len   = i32::from_le_bytes(mem_data[last+8..last+12].try_into()?);
        start_pos = last_start + last_len.max(1);
    }

    if total_matches == 0 {
        println!("No secrets found.");
    } else {
        println!("\n{} secret(s) found.", total_matches);
    }

    Ok(())
}
