// regex_bench: WASM harness for benchmarking the regex crate from Go via wasmtime-go.
// Built as wasm32-wasip1 binary. The exported functions are called directly by Go;
// fn main() is empty and never invoked during benchmarking.
//
// Exports:
//   get_input_ptr() -> i32   address of a static 512KB input buffer
//   get_output_ptr() -> i32  address of a static output buffer (i32 slots)
//   get_timings_ptr() -> i32 address of the timings buffer (u32 ns per iteration)
//   regex_init(len: i32)     compile pattern from input_buf[..len]
//   regex_match(len: i32) -> i32   1 if match, 0 otherwise
//   regex_find(len: i32) -> i64    start<<32|end, or -1 on no match
//   regex_groups(len: i32) -> i32  writes slots to output buf, returns end pos or -1
//   regex_bench_match(len: i32, iters: i32)   times iters iterations; writes ns to timings buf
//   regex_bench_find(len: i32, iters: i32)    times iters iterations (all matches); writes ns to timings buf
//   regex_bench_groups(len: i32, iters: i32)  times iters iterations (all matches); writes ns to timings buf
//
// The Go host writes data directly into WASM linear memory at the addresses
// returned by get_input_ptr() / get_output_ptr().

use std::sync::OnceLock;
use regex::{Regex, RegexSet};

// 512KB input buffer — large enough for the biggest test inputs (~100KB).
static mut INPUT_BUF: [u8; 512 * 1024] = [0u8; 512 * 1024];

// Output buffer for capture group slots: [start0, end0, start1, end1, ...]
static mut OUTPUT_BUF: [i32; 256] = [0i32; 256];

// Timings buffer: one u32 nanosecond value per iteration.
static mut TIMINGS_BUF: [u32; 10_000] = [0u32; 10_000];

static REGEX: OnceLock<Regex> = OnceLock::new();

// --------------------------------------------------------------------------
// Multi-pattern set benchmarking (RegexSet + per-pattern re-scan for positions)

// Separate 64KB buffer for receiving newline-delimited patterns.
static mut SET_PATTERNS_BUF: [u8; 64 * 1024] = [0u8; 64 * 1024];

struct SetState {
    set: RegexSet,
    patterns: Vec<Regex>,
}

static SET_STATE: OnceLock<SetState> = OnceLock::new();

/// Returns the address of the set-patterns buffer (newline-delimited UTF-8 patterns).
#[no_mangle]
pub extern "C" fn get_set_patterns_ptr() -> i32 {
    core::ptr::addr_of!(SET_PATTERNS_BUF) as i32
}

/// Compiles N patterns from set_patterns_buf[..len] (newline-delimited).
/// Must be called before regex_bench_set_find.
#[no_mangle]
pub extern "C" fn regex_set_init(len: i32) {
    let data = unsafe {
        std::str::from_utf8(&SET_PATTERNS_BUF[..len as usize]).expect("set patterns not valid UTF-8")
    };
    let pats: Vec<&str> = data.split('\n').filter(|s| !s.is_empty()).collect();
    let set = RegexSet::new(&pats).expect("invalid regex set");
    let patterns: Vec<Regex> = pats.iter()
        .map(|p| Regex::new(p).expect("invalid pattern"))
        .collect();
    let _ = SET_STATE.set(SetState { set, patterns });
}

/// Benchmarks the two-pass RegexSet approach:
///   Pass 1: RegexSet::matches(input) → which patterns match (no positions)
///   Pass 2: for each matched pattern, Regex::find_iter(input) → positions
///
/// This is the idiomatic way to get positions out of RegexSet, and is exactly
/// the extra cost that regexped's find_all avoids by returning positions directly.
///
/// Times each full two-pass scan over the input; writes ns per iteration to TIMINGS_BUF.
#[no_mangle]
pub extern "C" fn regex_bench_set_find(input_len: i32, iters: i32) {
    let state = SET_STATE.get().expect("set not initialised — call regex_set_init first");
    let input = unsafe { std::str::from_utf8_unchecked(&INPUT_BUF[..input_len as usize]) };
    let timings = unsafe { &mut *core::ptr::addr_of_mut!(TIMINGS_BUF) };
    let mut prev = std::time::Instant::now();
    for i in 0..iters as usize {
        // Pass 1: which patterns match? (no positions)
        let matched: Vec<usize> = state.set
            .matches(std::hint::black_box(input))
            .into_iter()
            .collect();
        // Pass 2: for each matched pattern, re-scan for positions
        let mut total: usize = 0;
        for pat_idx in &matched {
            for m in state.patterns[*pat_idx].find_iter(input) {
                let _ = std::hint::black_box((m.start(), m.end(), pat_idx));
                total += 1;
            }
        }
        let _ = std::hint::black_box(total);
        let cur = std::time::Instant::now();
        timings[i] = cur.duration_since(prev).as_nanos() as u32;
        prev = cur;
    }
}

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

/// Returns the address of the timings buffer (u32 ns per iteration).
#[no_mangle]
pub extern "C" fn get_timings_ptr() -> i32 {
    core::ptr::addr_of!(TIMINGS_BUF) as i32
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
// Bench functions — loop iters times internally, timing each iteration
// individually with std::time::Instant and storing the nanosecond duration
// as u32 into TIMINGS_BUF. The Go host reads the buffer to compute avg or pN.

/// Benchmarks regex_match: times each of iters iterations; writes ns to timings buf.
#[no_mangle]
pub extern "C" fn regex_bench_match(len: i32, iters: i32) {
    let re = REGEX.get().expect("regex not initialised");
    let input = unsafe { std::str::from_utf8_unchecked(&INPUT_BUF[..len as usize]) };
    let timings = unsafe { &mut *core::ptr::addr_of_mut!(TIMINGS_BUF) };
    let mut prev = std::time::Instant::now();
    for i in 0..iters as usize {
        let _ = re.is_match(std::hint::black_box(input));
        let cur = std::time::Instant::now();
        timings[i] = cur.duration_since(prev).as_nanos() as u32;
        prev = cur;
    }
}

/// Benchmarks regex_find: exhausts all matches per iteration; writes ns to timings buf.
#[no_mangle]
pub extern "C" fn regex_bench_find(len: i32, iters: i32) {
    let re = REGEX.get().expect("regex not initialised");
    let input = unsafe { std::str::from_utf8_unchecked(&INPUT_BUF[..len as usize]) };
    let timings = unsafe { &mut *core::ptr::addr_of_mut!(TIMINGS_BUF) };
    let mut prev = std::time::Instant::now();
    for i in 0..iters as usize {
        for m in re.find_iter(std::hint::black_box(input)) {
            let _ = std::hint::black_box(m);
        }
        let cur = std::time::Instant::now();
        timings[i] = cur.duration_since(prev).as_nanos() as u32;
        prev = cur;
    }
}

/// Benchmarks regex_groups: exhausts all capture matches per iteration; writes ns to timings buf.
#[no_mangle]
pub extern "C" fn regex_bench_groups(len: i32, iters: i32) {
    let re = REGEX.get().expect("regex not initialised");
    let input = unsafe { std::str::from_utf8_unchecked(&INPUT_BUF[..len as usize]) };
    let timings = unsafe { &mut *core::ptr::addr_of_mut!(TIMINGS_BUF) };
    let mut prev = std::time::Instant::now();
    for i in 0..iters as usize {
        for caps in re.captures_iter(std::hint::black_box(input)) {
            let _ = std::hint::black_box(caps);
        }
        let cur = std::time::Instant::now();
        timings[i] = cur.duration_since(prev).as_nanos() as u32;
        prev = cur;
    }
}
