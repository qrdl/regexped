include!("stub.rs");

use std::time::Instant;

const N: u32 = 10_000;

fn main() {
    let args: Vec<String> = std::env::args().collect();
    if args.len() < 2 {
        eprintln!("Usage: regexped_groups_harness <input>");
        std::process::exit(1);
    }
    let input = args[1].as_bytes();

    let t0 = Instant::now();
    let mut sum: usize = 0;
    for _ in 0..N {
        if let Some(groups) = pattern_groups(input) {
            sum = sum.wrapping_add(groups.len());
        }
    }
    let avg_ns = t0.elapsed().as_nanos() / N as u128;

    eprintln!("checksum:{}", sum);
    println!("match: {}ns", avg_ns);
    match pattern_groups(input) {
        Some(ref groups) => match groups.get(0) {
            Some(Some((s, e))) => println!("result:{}:{}", s, e),
            _ => println!("result:none"),
        },
        None => println!("result:none"),
    }
}
