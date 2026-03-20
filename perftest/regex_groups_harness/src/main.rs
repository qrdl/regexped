use std::time::Instant;

const N: u32 = 10_000;

fn main() {
    let args: Vec<String> = std::env::args().collect();
    if args.len() < 3 {
        eprintln!("Usage: regex_groups_harness <pattern> <input>");
        std::process::exit(1);
    }
    let pattern = &args[1];
    let input = &args[2];

    let t0 = Instant::now();
    let re = regex::Regex::new(pattern).unwrap();
    let compile_us = t0.elapsed().as_micros();

    let t1 = Instant::now();
    let mut sum: usize = 0;
    for _ in 0..N {
        if let Some(caps) = re.captures(input) {
            sum = sum.wrapping_add(caps.len());
        }
    }
    let avg_ns = t1.elapsed().as_nanos() / N as u128;

    eprintln!("checksum:{}", sum);
    println!("compile: {}µs  match: {}ns", compile_us, avg_ns);
}
