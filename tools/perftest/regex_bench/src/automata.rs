// regex-automata pairings for tools/setperf.
//
// `perftest --sets` compares regexped's set find against the `regex` crate's
// RegexSet plus a per-pattern rescan — a fair model of what a `regex` user
// would write, but an unfair model of the engine, because RegexSet
// deliberately never reports *where*. `regex-automata` is the layer
// underneath and maps onto the new set API almost one-to-one:
//
//   Input::span(from..)        <-> the `from` parameter
//   PatternSet / PatternID     <-> our bitmask + pattern ids
//   MatchKind::LeftmostFirst   <-> our RE2/Perl semantics (default here)
//
// Capability pairings implemented below (the "honest" rows):
//
//   scan       -> re.is_match(Input::new(h).span(from..))
//   scan_any   -> re.find(Input::new(h).span(from..)) -> (pattern, start)
//   scan_all   -> re.which_overlapping_matches(&input, &mut PatternSet), on an
//                 automaton built with MatchKind::All — see RaState::overlap
//   match*     -> a second automaton over `\A(?:p)\z`-wrapped patterns,
//                 searched anchored at 0.  Wrapping rather than an
//                 `end() == len` check on the raw pattern is deliberate:
//                 leftmost-first would stop at the shorter alternative
//                 (`a|ab` on "ab" ends at 1) and under-report, while our
//                 anchored `match` asks "is 0..len an accepting run", which
//                 is exactly `\A(?:p)\z`.
//   find(gated)-> per-pattern find_iter, merged — the same construction as
//                 the Go union oracle.  regex-automata's own multi-pattern
//                 find_iter is *set-wide* non-overlapping while our gated
//                 find is *per-pattern*; pairing those directly would produce
//                 a confidently wrong number.
//
// `find` with `overlapping: true` has no equivalent and is deliberately
// absent — setperf prints "no comparison" for it.

use std::sync::OnceLock;

use regex_automata::{meta::Regex as MetaRegex, Anchored, Input, MatchKind, PatternSet};

use crate::{INPUT_BUF, SET_PATTERNS_BUF, TIMINGS_BUF};

/// Output buffer for --verify runs: 3 i32 per tuple (pattern_id, start, end).
static mut RA_OUT_BUF: [i32; 3 * 65536] = [0i32; 3 * 65536];

struct RaState {
    /// Non-anchored multi-pattern automaton over the raw patterns.
    set: MetaRegex,
    /// The same patterns built with MatchKind::All, for
    /// which_overlapping_matches.
    ///
    /// This is NOT a detail: with the default MatchKind::LeftmostFirst the
    /// meta engine's overlapping search short-circuits and reports only the
    /// first pattern, so pairing scan_all against it produces a confidently
    /// wrong "regexped over-reports". Measured against a 32-pattern set where
    /// every pattern matches: LeftmostFirst returns {0}, All returns all 32.
    overlap: MetaRegex,
    /// Anchored-and-full-consumption automaton: patterns wrapped `\A(?:p)\z`.
    full: MetaRegex,
    /// One single-pattern automaton per pattern, for the per-pattern merged
    /// `find` pairing.
    each: Vec<MetaRegex>,
    /// Pattern count. Also the capacity of the reusable PatternSet below —
    /// which used to be described HERE as "Reusable PatternSet", a reuse that
    /// did not exist: every scan_all call built a fresh one, allocation
 /// included, inside the metered/timed body..
    npat: usize,
}

/// The reusable PatternSet `scan_all` writes into.
///
/// Its allocation is a per-call cost regex-automata was being charged and we
/// were not: our side's equivalent — zeroing the caller's bitmap — runs
/// host-side in Go and is neither metered nor timed. Constructing it once at
/// init and clearing it per call is the closest honest pairing available.
///
/// A plain `static mut` rather than a RefCell: this module is a
/// single-threaded WASM harness, every other buffer here is already addressed
/// this way, and a RefCell's borrow flag would be one more thing inside the
/// timed body.
static mut RA_PATSET: Option<PatternSet> = None;

/// Returns the reusable PatternSet, CLEARED.
///
/// The clear stays inside the caller (and so inside the timed body) on
/// purpose: it is the part regex-automata genuinely has to do per call, and
/// hoisting it too would flatter their side instead of ours. Only the
/// allocation moved out.
fn patset() -> &'static mut PatternSet {
    let slot = unsafe { &mut *core::ptr::addr_of_mut!(RA_PATSET) };
    slot.as_mut().expect("PatternSet not initialised — call ra_set_init first")
}

static RA_STATE: OnceLock<RaState> = OnceLock::new();

fn state() -> &'static RaState {
    RA_STATE
        .get()
        .expect("regex-automata set not initialised — call ra_set_init first")
}

fn haystack(len: i32) -> &'static [u8] {
    unsafe { &*core::ptr::addr_of!(INPUT_BUF) }
        .get(..len as usize)
        .expect("input length out of range")
}

/// Returns the address of the regex-automata output buffer.
#[no_mangle]
pub extern "C" fn ra_out_ptr() -> i32 {
    core::ptr::addr_of!(RA_OUT_BUF) as i32
}

/// Compiles the newline-delimited patterns in SET_PATTERNS_BUF[..len].
#[no_mangle]
pub extern "C" fn ra_set_init(len: i32) -> i32 {
    let data = unsafe {
        std::str::from_utf8(&SET_PATTERNS_BUF[..len as usize])
            .expect("set patterns not valid UTF-8")
    };
    let pats: Vec<&str> = data.split('\n').filter(|s| !s.is_empty()).collect();
    let set = match MetaRegex::new_many(&pats) {
        Ok(r) => r,
        Err(_) => return 0,
    };
    let wrapped: Vec<String> = pats.iter().map(|p| format!(r"\A(?:{})\z", p)).collect();
    let wrapped_refs: Vec<&str> = wrapped.iter().map(|s| s.as_str()).collect();
    let full = match MetaRegex::new_many(&wrapped_refs) {
        Ok(r) => r,
        Err(_) => return 0,
    };
    let overlap = match MetaRegex::builder()
        .configure(MetaRegex::config().match_kind(MatchKind::All))
        .build_many(&pats)
    {
        Ok(r) => r,
        Err(_) => return 0,
    };
    let mut each = Vec::with_capacity(pats.len());
    for p in &pats {
        match MetaRegex::new(p) {
            Ok(r) => each.push(r),
            Err(_) => return 0,
        }
    }
    let npat = pats.len();
    unsafe {
        *core::ptr::addr_of_mut!(RA_PATSET) = Some(PatternSet::new(npat));
    }
    let _ = RA_STATE.set(RaState { set, overlap, full, each, npat });
    1
}

// --------------------------------------------------------------------------
// Correctness (--verify) entry points. Each writes into RA_OUT_BUF and
// returns the number of i32 slots or the packed answer directly, mirroring
// the shape of the regexped export it is paired with.

/// scan_any: (start << 32) | pattern_id, or -1.
#[no_mangle]
pub extern "C" fn ra_scan_any(len: i32, from: i32) -> i64 {
    let st = state();
    let h = haystack(len);
    if from as usize > h.len() {
        return -1;
    }
    let input = Input::new(h).span(from as usize..h.len());
    match st.set.find(input) {
        Some(m) => ((m.start() as i64) << 32) | (m.pattern().as_u64() as i64),
        None => -1,
    }
}

/// scan_all: writes matching pattern ids to RA_OUT_BUF, returns the count.
#[no_mangle]
pub extern "C" fn ra_scan_all(len: i32, from: i32) -> i32 {
    let st = state();
    let h = haystack(len);
    if from as usize > h.len() {
        return 0;
    }
    let input = Input::new(h).span(from as usize..h.len());
    let ps = patset();
    ps.clear();
    st.overlap.which_overlapping_matches(&input, ps);
    let out = unsafe { &mut *core::ptr::addr_of_mut!(RA_OUT_BUF) };
    let mut n = 0usize;
    for pid in ps.iter() {
        out[n] = pid.as_u32() as i32;
        n += 1;
    }
    n as i32
}

/// match: 1 if any pattern matches the whole input (0..len), else 0.
#[no_mangle]
pub extern "C" fn ra_match(len: i32) -> i32 {
    let st = state();
    let h = haystack(len);
    let input = Input::new(h).anchored(Anchored::Yes);
    if st.full.is_match(input) {
        1
    } else {
        0
    }
}

/// match_all: writes matching pattern ids to RA_OUT_BUF, returns the count.
#[no_mangle]
pub extern "C" fn ra_match_all(len: i32) -> i32 {
    let st = state();
    let h = haystack(len);
    let out = unsafe { &mut *core::ptr::addr_of_mut!(RA_OUT_BUF) };
    let mut n = 0usize;
    for k in 0..st.npat {
        let input = Input::new(h).anchored(Anchored::Pattern(
            regex_automata::PatternID::must(k),
        ));
        if st.full.is_match(input) {
            out[n] = k as i32;
            n += 1;
        }
    }
    n as i32
}

/// find (gated / default): the per-pattern merged enumeration. Writes
/// (pattern_id, start, end) triples to RA_OUT_BUF and returns the tuple count.
#[no_mangle]
pub extern "C" fn ra_find_gated(len: i32, from: i32) -> i32 {
    let st = state();
    let h = haystack(len);
    if from as usize > h.len() {
        return 0;
    }
    let out = unsafe { &mut *core::ptr::addr_of_mut!(RA_OUT_BUF) };
    let mut n = 0usize;
    for (k, re) in st.each.iter().enumerate() {
        let input = Input::new(h).span(from as usize..h.len());
        for m in re.find_iter(input) {
            if n * 3 + 2 >= out.len() {
                return n as i32;
            }
            out[n * 3] = k as i32;
            out[n * 3 + 1] = m.start() as i32;
            out[n * 3 + 2] = m.end() as i32;
            n += 1;
        }
    }
    n as i32
}

/// find, LAZILY: the single leftmost match at or after `from`, packed as
/// `(start << 32) | end`, or -1 when there is none.
///
/// Every other `find` pairing here enumerates the
/// whole input in one call, which is a fair comparison against our BATCHED
/// find and an unfair one against our bare `find` — that returns to the host
/// once per matching position, so the timed row compares two API shapes rather
/// than two engines (the matrix now labels it `api-shape`). This entry point
/// is the missing half: driven one match per call from Go, both sides pay the
/// same N host crossings, and the ratio is a real "our lazy API vs their lazy
/// API" number for the first time.
///
/// It answers the same question our `find` does — the FIRST POSITION at or
/// after `from` where anything in the set matches — so it uses the multi-
/// pattern automaton (`set`) rather than the per-pattern `each` loop the bulk
/// pairing uses. Per-pattern iteration would make one call O(P) searches and
/// measure a different algorithm; the leftmost match over the set is one
/// search, which is what our single pass computes.
#[no_mangle]
pub extern "C" fn ra_find_next(len: i32, from: i32) -> i64 {
    let st = state();
    let h = haystack(len);
    if from < 0 || from as usize > h.len() {
        return -1;
    }
    let input = Input::new(h).span(from as usize..h.len());
    match st.set.find(input) {
        Some(m) => ((m.start() as i64) << 32) | (m.end() as i64),
        None => -1,
    }
}

// --------------------------------------------------------------------------
// Benchmark entry points. Each times `iters` iterations of one whole-input
// operation and writes the per-iteration nanosecond duration to TIMINGS_BUF,
// exactly like the `regex`-crate benches in main.rs.

macro_rules! timed {
    ($iters:expr, $body:block) => {{
        let timings = unsafe { &mut *core::ptr::addr_of_mut!(TIMINGS_BUF) };
        let mut prev = std::time::Instant::now();
        for i in 0..$iters as usize {
            $body
            let cur = std::time::Instant::now();
            timings[i] = cur.duration_since(prev).as_nanos() as u32;
            prev = cur;
        }
    }};
}

#[no_mangle]
pub extern "C" fn ra_bench_scan_any(len: i32, iters: i32) {
    let st = state();
    let h = haystack(len);
    timed!(iters, {
        let input = Input::new(std::hint::black_box(h));
        let _ = std::hint::black_box(st.set.find(input));
    });
}

#[no_mangle]
pub extern "C" fn ra_bench_scan_all(len: i32, iters: i32) {
    let st = state();
    let h = haystack(len);
    timed!(iters, {
        let input = Input::new(std::hint::black_box(h));
        let ps = patset();
        ps.clear();
        st.overlap.which_overlapping_matches(&input, ps);
        let _ = std::hint::black_box(ps.len());
    });
}

#[no_mangle]
pub extern "C" fn ra_bench_match(len: i32, iters: i32) {
    let st = state();
    let h = haystack(len);
    timed!(iters, {
        let input = Input::new(std::hint::black_box(h)).anchored(Anchored::Yes);
        let _ = std::hint::black_box(st.full.is_match(input));
    });
}

#[no_mangle]
pub extern "C" fn ra_bench_match_all(len: i32, iters: i32) {
    let st = state();
    let h = haystack(len);
    timed!(iters, {
        let mut n = 0usize;
        for k in 0..st.npat {
            let input = Input::new(std::hint::black_box(h)).anchored(Anchored::Pattern(
                regex_automata::PatternID::must(k),
            ));
            if st.full.is_match(input) {
                n += 1;
            }
        }
        let _ = std::hint::black_box(n);
    });
}

/// The per-pattern merged `find` pairing: one full find_iter exhaustion per
/// pattern over the whole input.
#[no_mangle]
pub extern "C" fn ra_bench_find_gated(len: i32, iters: i32) {
    let st = state();
    let h = haystack(len);
    timed!(iters, {
        let mut n = 0usize;
        for re in st.each.iter() {
            for m in re.find_iter(std::hint::black_box(h)) {
                let _ = std::hint::black_box((m.start(), m.end()));
                n += 1;
            }
        }
        let _ = std::hint::black_box(n);
    });
}
