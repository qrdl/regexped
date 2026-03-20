// Find-mode harness: calls a regexped WASM function that returns i64.
// The WASM export is always named "pattern_find" from import module "pattern".

#[link(wasm_import_module = "pattern")]
unsafe extern "C" {
    #[link_name = "pattern_find"]
    fn ffi_pattern_find(ptr: *const u8, len: usize) -> i64;
}

fn pattern_find(input: &[u8]) -> Option<(usize, usize)> {
    match unsafe { ffi_pattern_find(input.as_ptr(), input.len()) } {
        -1 => None,
        n  => Some(((n as u64 >> 32) as usize, (n as u32) as usize)),
    }
}

use std::time::Instant;

const N: u32 = 10_000;

fn main() {
    let args: Vec<String> = std::env::args().collect();
    if args.len() < 2 {
        eprintln!("Usage: regexped_find_harness <input>");
        std::process::exit(1);
    }
    let input = args[1].as_bytes();

    let t0 = Instant::now();
    let mut sum: usize = 0;
    for _ in 0..N {
        sum = sum.wrapping_add(pattern_find(input).map_or(0, |(_, e)| e));
    }
    let avg_ns = t0.elapsed().as_nanos() / N as u128;

    eprintln!("checksum:{}", sum);

    println!("find: {}ns", avg_ns);
}
