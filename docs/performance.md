# Performance

Regexped against Rust's [`regex`](https://crates.io/crates/regex) crate and
[`regex-automata`](https://crates.io/crates/regex-automata), the engine under
it — all three compiled to WASM and run in wasmtime. Every ratio below is the
other engine's figure divided by regexped's, so above 1× regexped is ahead.

**On average** — the geometric mean, the right average for ratios, of the
median-time column below, a range counting as the geometric mean of its two
ends: **4.7× faster than `regex`** over its 19 scenarios (single patterns,
Unicode mode, and pattern sets against `RegexSet` plus a rescan), and **6.2×
faster than `regex-automata`** over its 6 timed set scenarios. In
instructions executed the same averages are 5.5× and 10.6×.

**DFA/TDFA matching:** O(n) time, O(1) runtime stack — no worst-case blowup.

**Backtracking:** LeftmostFirst (RE2/Perl) semantics for non-deterministic capture patterns. BitState memoization bounds runtime to O(n × numStates) for patterns with zero-matchable loops; stack overflow guard prevents memory corruption on deeply nested patterns.

**SIMD prefix scan:** First-byte and two-byte Teddy algorithm skips non-matching positions in bulk using WASM SIMD instructions, reducing DFA transitions on typical inputs.

**Comparison vs [regex crate](https://crates.io/crates/regex)** (both compiled to WASM and run in wasmtime by `tools/perftest`):

| Scenario | Capability | Instructions executed | Median time |
|---|---|---|---|
| Anchored match (email, URL) | `match_func` | 1.1–2.4× | 1.1–1.7× |
| Non-anchored find (secrets, URLs, SQL injection, comments; 1–100 KB) | `find_func` | 1.0–26× | 1.3–28× |
| Multi-pattern alternation find (combined secrets, 10–100 KB) | `find_func` | 5.6–11× | 4.0–13× |
| TDFA capture groups (URL parse, log fields) | `groups_func` | 0.7–8.2× | 1.3–14× |
| Backtracking capture groups (CSV, HTML, logs) | `groups_func` | 2.4–10× | 2.1–9.4× |
| No-match fast reject (9–300 bytes) | `match_func`, `groups_func` | 7.0–33× | 1.8–16× |

**Unicode mode** (`tools/perftest -unicode`, over mixed-script text — Latin with diacritics, Cyrillic, Greek, CJK — against the `regex` crate, whose classes are Unicode too; same ratio):

| Scenario | Capability | Instructions executed | Median time |
|---|---|---|---|
| International e-mail addresses, `[\pL\pN._%+-]+@[\pL\pN-]+\.\pL{2,}` (10 KB) | `find_func` | 3.0–3.2× | 2.2× |
| Cyrillic words, `\p{Cyrillic}{4,}` (10 KB) | `find_func` | 5.0× | 3.4× |
| Words in any script, `\pL+` (10 KB, with and without letters) | `find_func` | 1.3–6.2× | 2.2–6.3× |
| Case-insensitive keywords in two scripts, `(?i)straße\|ΣΟΦΙΑ` (10 KB) | `find_func` | 6.4–6.5× | 5.7× |
| A fixed Cyrillic word and the word after it, `привет\s+\pL+` (10 KB) | `find_func` | 1.9–2.0× | 2.4–2.5× |
| A whole Greek phrase, `\p{Greek}+(?:\s\p{Greek}+)*` | `match_func` | 1.4–22× | 1.4–1.8× |
| Name and number, `(\pL+)\s(\pN+)` (`Straße 42`, up to 353 B) | `groups_func` | 2.7–2.9× | 2.2–3.0× |
| CSV field and HTML tag over non-ASCII text, `([^,]+),`, `<([^>]+)>` (~490 B) | `groups_func` | 22–23× | 15× |
| `key=value`, `(.+)=(.+)` (33–641 B) | `groups_func` | 6.2–8.4× | 4.4–5.9× |

**Pattern sets** against the `regex` crate's `RegexSet` plus a per-pattern rescan (the usual way to get positions out of it, `tools/perftest`), or against [regex-automata](https://crates.io/crates/regex-automata), the engine under `regex`, which answers each question directly (`tools/setperf`); same ratio:

| Scenario | Capability | Against | Instructions executed | Median time |
|---|---|---|---|---|
| Secret scanning (10 patterns, 100 KB) | `find` | `RegexSet` + rescan | 3.5–4.4× | 3.2–4.1× |
| Log-level lines (8 patterns, 100 KB, up to 5 matches) | `find` | `RegexSet` + rescan | 7.1–11× | 6.3–9.2× |
| Log-level lines (8 patterns, 100 KB, 1,545 matches) | `find` | `RegexSet` + rescan | 10× | 11× |
| Prefixed tokens (20 patterns, 100 KB) | `find` | `RegexSet` + rescan | 17–28× | 18–27× |
| Is any secret present? (4 patterns, 100 KB) | `scan_any` | regex-automata | 7.1× | 4.7–6.1× |
| Which secrets are present? (4 patterns, 100 KB) | `scan_all` | regex-automata | 7.1× | 5.6–5.7× |
| Secret scanning (4 patterns, 100 KB) | `find`, batched | regex-automata | 4.3× | 3.3–3.4× |
| Which keyword-prefixed tokens appear? (8–32 patterns, 100 KB) | `scan_all` | regex-automata | 5.1–18× | 2.2–17× |
| Keyword-prefixed tokens with positions (8–32 patterns, 100 KB) | `find`, batched | regex-automata | 18–59× | 11–38× |
| Which `[a-z]{n}[0-9]{m}` tokens appear? (32 patterns, 100 KB, dense) | `scan_all` | regex-automata | 10× | 4.5× |
| Is a 100 KB input one of 4–32 formats? (rejected within a few bytes) | `match_any`, `match_all` | regex-automata | 3.6–142× | too short to time |

## How these are measured

`tools/perftest` runs each pattern over each input in both engines, inside
wasmtime, and reports the median of many timed runs and the exact number of
WASM instructions executed (fuel); `tools/setperf` does the same for pattern
sets against `regex-automata`. Instructions executed are exact and repeatable;
time depends on the machine, which is why both are given. See
[tools/README.md](../tools/README.md) for running them.
