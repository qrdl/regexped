include!("stub.rs");

use std::time::Instant;

const N: u32 = 10_000;

fn main() {
    let args: Vec<String> = std::env::args().collect();
    if args.len() < 2 {
        eprintln!("Usage: regexped_harness <input>");
        std::process::exit(1);
    }
    let input = args[1].as_bytes();

    let t0 = Instant::now();
    let mut sum: usize = 0;
    for _ in 0..N {
        sum = sum.wrapping_add(pattern_match(input).unwrap_or(0));
    }
    let avg_ns = t0.elapsed().as_nanos() / N as u128;

    // eprintln forces the JIT to actually compute sum — it cannot know stderr
    // is redirected, so it must treat this write as observable.
    eprintln!("checksum:{}", sum);

    println!("match: {}ns", avg_ns);
    println!("result:{}", if pattern_match(input).is_some() { "match" } else { "none" });
}
