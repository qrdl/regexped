// regex_bench: WASM harness for benchmarking the regex crate from Go via wasmtime-go.
// Built as wasm32-wasip1 binary. The exported functions are called directly by Go;
// fn main() is empty and never invoked during benchmarking.
//
// Exports:
//   get_input_ptr() -> i32   address of a static 512KB input buffer
//   get_output_ptr() -> i32  address of a static output buffer (i32 slots)
//   regex_init(len: i32)     compile pattern from input_buf[..len]
//   regex_match(len: i32) -> i32   1 if match, 0 otherwise
//   regex_find(len: i32) -> i64    start<<32|end, or -1 on no match
//   regex_groups(len: i32) -> i32  writes slots to output buf, returns end pos or -1
//   regex_bench_match(len: i32, iters: i32) -> i64   total ns for iters iterations
//   regex_bench_find(len: i32, iters: i32) -> i64    total ns for iters iterations
//   regex_bench_groups(len: i32, iters: i32) -> i64  total ns for iters iterations
//
// The Go host writes data directly into WASM linear memory at the addresses
// returned by get_input_ptr() / get_output_ptr().

use std::sync::OnceLock;
use regex::Regex;

// 512KB input buffer — large enough for the biggest test inputs (~100KB).
static mut INPUT_BUF: [u8; 512 * 1024] = [0u8; 512 * 1024];

// Output buffer for capture group slots: [start0, end0, start1, end1, ...]
static mut OUTPUT_BUF: [i32; 256] = [0i32; 256];

static REGEX: OnceLock<Regex> = OnceLock::new();

fn main() {}

/// Returns the address of the input buffer within WASM linear memory.
#[no_mangle]
pub extern "C" fn get_input_ptr() -> i32 {
    core::ptr::addr_of!(INPUT_BUF) as i32
}

/// Returns the address of the output (capture slots) buffer.
#[no_mangle]
pub extern "C" fn get_output_ptr() -> i32 {
    core::ptr::addr_of!(OUTPUT_BUF) as i32
}

/// Compiles the regex pattern stored in input_buf[..len].
/// Must be called exactly once per instance before any match/find/groups calls.
#[no_mangle]
pub extern "C" fn regex_init(len: i32) {
    let pat = unsafe {
        std::str::from_utf8(&INPUT_BUF[..len as usize]).expect("pattern is not valid UTF-8")
    };
    let re = Regex::new(pat).expect("invalid regex pattern");
    let _ = REGEX.set(re);
}

/// Returns 1 if the compiled regex matches input_buf[..len], 0 otherwise.
#[no_mangle]
pub extern "C" fn regex_match(len: i32) -> i32 {
    let re = REGEX.get().expect("regex not initialised");
    let input = unsafe { std::str::from_utf8_unchecked(&INPUT_BUF[..len as usize]) };
    if re.is_match(input) { 1 } else { 0 }
}

/// Finds the first match in input_buf[..len].
/// Returns (start << 32) | end as i64, or -1 on no match.
#[no_mangle]
pub extern "C" fn regex_find(len: i32) -> i64 {
    let re = REGEX.get().expect("regex not initialised");
    let input = unsafe { std::str::from_utf8_unchecked(&INPUT_BUF[..len as usize]) };
    match re.find(input) {
        Some(m) => ((m.start() as i64) << 32) | (m.end() as i64),
        None => -1,
    }
}

/// Finds the first match with captures in input_buf[..len].
/// Writes [start0, end0, start1, end1, ...] into the output buffer (-1 for unmatched groups).
/// Returns the end position of the full match, or -1 on no match.
#[no_mangle]
pub extern "C" fn regex_groups(len: i32) -> i32 {
    let re = REGEX.get().expect("regex not initialised");
    let input = unsafe { std::str::from_utf8_unchecked(&INPUT_BUF[..len as usize]) };
    match re.captures(input) {
        None => -1,
        Some(caps) => {
            let out = unsafe { &mut *core::ptr::addr_of_mut!(OUTPUT_BUF) };
            let n = re.captures_len(); // includes group 0
            for i in 0..n.min(128) {
                match caps.get(i) {
                    None => {
                        out[i * 2]     = -1;
                        out[i * 2 + 1] = -1;
                    }
                    Some(m) => {
                        out[i * 2]     = m.start() as i32;
                        out[i * 2 + 1] = m.end() as i32;
                    }
                }
            }
            caps.get(0).map_or(-1, |m| m.end() as i32)
        }
    }
}

// --------------------------------------------------------------------------
// Bench functions — loop iters times internally using std::time::Instant,
// return total nanoseconds as i64. A single Go→WASM call amortises CGo overhead
// across all iterations, giving true per-iteration execution time.

/// Runs regex_match iters times and returns total elapsed nanoseconds.
#[no_mangle]
pub extern "C" fn regex_bench_match(len: i32, iters: i32) -> i64 {
    let re = REGEX.get().expect("regex not initialised");
    let input = unsafe { std::str::from_utf8_unchecked(&INPUT_BUF[..len as usize]) };
    let start = std::time::Instant::now();
    for _ in 0..iters {
        let _ = re.is_match(std::hint::black_box(input));
    }
    start.elapsed().as_nanos() as i64
}

/// Runs regex_find iters times and returns total elapsed nanoseconds.
#[no_mangle]
pub extern "C" fn regex_bench_find(len: i32, iters: i32) -> i64 {
    let re = REGEX.get().expect("regex not initialised");
    let input = unsafe { std::str::from_utf8_unchecked(&INPUT_BUF[..len as usize]) };
    let start = std::time::Instant::now();
    for _ in 0..iters {
        let _ = re.find(std::hint::black_box(input));
    }
    start.elapsed().as_nanos() as i64
}

/// Runs regex_groups iters times and returns total elapsed nanoseconds.
#[no_mangle]
pub extern "C" fn regex_bench_groups(len: i32, iters: i32) -> i64 {
    let re = REGEX.get().expect("regex not initialised");
    let input = unsafe { std::str::from_utf8_unchecked(&INPUT_BUF[..len as usize]) };
    let start = std::time::Instant::now();
    for _ in 0..iters {
        let _ = std::hint::black_box(re.captures(std::hint::black_box(input)));
    }
    start.elapsed().as_nanos() as i64
}
