# Generated AssemblyScript API

Regexped generates an AssemblyScript stub file that imports compiled WASM regexp
functions and re-exports them with a higher-level interface. Because AssemblyScript
compiles to WASM itself, the stubs are merged with the regexp modules via
`wasm-merge` into a single final `.wasm` binary.

## Requirements

- [AssemblyScript](https://www.assemblyscript.org/) 0.27 or later
- [`wasm-merge`](https://github.com/WebAssembly/binaryen) (Binaryen) in `$PATH` or set via `wasm_merge` in config
- The config must have an `output` field so that `regexped merge` knows where to write the merged module

## Project setup

```sh
regexped compile  --config regexped.yaml   # compile regexp WASM files
regexped generate --config regexped.yaml   # write stub.ts (or the path from stub_file)
asc index.ts --target release              # compile AS → main.wasm
regexped merge    --config regexped.yaml   # merge main.wasm + regexp WASMs → output.wasm
```

Specify `stub_type: "as"` in your config to opt into AssemblyScript stubs. Without
this, `.ts` extension defaults to the TypeScript (host-JS) stub type.

```yaml
stub_type: as
stub_file: src/stub.ts
```

Include the generated stub in your AssemblyScript source:

```ts
import { my_match } from "./stub";
```

---

## Encoding strings

AssemblyScript strings are UTF-16 internally. Convert to a UTF-8 `ArrayBuffer`
before passing to any stub function:

```ts
const buf = String.UTF8.encode(text);
```

---

## Generated functions by config field

### `match_func` — anchored match

```ts
export function <func>(input: ArrayBuffer): i32
```

Tries to match the pattern at position 0 of `input`. Returns the **end position**
(`>= 0`) if the full input matches from the start, or `-1` if no match.

```ts
import { url_match } from "./stub";

const buf = String.UTF8.encode("https://example.com");
const end = url_match(buf);
if (end >= 0) {
  console.log("matched " + end.toString() + " bytes");
} else {
  console.log("no match");
}
```

---

### `find_func` — non-anchored find iterator

```ts
export class <func>_iter {
  next(): i64;   // packed (start << 32 | end); -1 finished; RX_ERR_BT_OVERFLOW unknown
}
export function <func>(input: ArrayBuffer, offset: u32): <func>_iter
```

Scans for non-overlapping matches at or after `offset`. The whole input stays visible to the engine — `offset` bounds where the search starts, it does not truncate the left context a leading `\b`, `\B` or `(?m:^)` is judged against. Positions are absolute.

```ts
const iter = find_token(input, 0);
let packed = iter.next();
while (packed >= 0) {
  const start = i32(<u64>packed >> 32);
  const end   = i32(<u32>packed);
  // use input[start .. end]
  packed = iter.next();
}
if (packed == i64(RX_ERR_BT_OVERFLOW)) {
  // the result is unknown, not "no more matches"
}
```

The iterator owns the advance past a zero-length match and Go's `FindAllIndex` rule — an empty match beginning exactly where the previous reported match ended is not reported. Both used to be your job, copied from this document.

Nothing is allocated per match: `next()` returns a number, not an object. AssemblyScript nullability is reference-types only, so an object-returning `next()` would allocate on every step.

---

### `groups_func` — capture-match iterator

```ts
export class <func>_iter {
  next(): u32;   // slot pointer; 0 finished; RX_ITER_ERROR unknown
}
export function <func>(input: ArrayBuffer, offset: u32): <func>_iter
export function <func>_capture(input: ArrayBuffer, slots: u32, groupNum: i32): string | null
export const <FUNC_UPPER>_GROUPS: i32
```

`next()` returns a pointer to **this iterator's** slot buffer. Slot layout is `[g0_start, g0_end, g1_start, g1_end, …]` as `i32`, absolute offsets; group 0 is the whole match, and a group that did not participate has `start == -1`.

The pointer is valid only until the next `next()` call — the buffer is reused.

```ts
const iter = parse_url(input, 0);
let slots = iter.next();
while (slots != 0 && slots != RX_ITER_ERROR) {
  const host = parse_url_capture(input, slots, parse_url_host);
  if (host != null) { /* decoded text */ }
  slots = iter.next();
}
if (slots == RX_ITER_ERROR) {
  // the result is unknown, not "no more matches"
}
```

The buffer lives **inside the iterator**. It used to be module-level, which was not re-entrant: two interleaved scans clobbered each other, and the returned pointer was silently invalidated by the next call.

---

### Named groups — index constants

`named_groups_func` used to be **rejected** for AssemblyScript. It is now retired for every language, and AS gains the named access it never had: when a pattern has at least one named group, `groups_func` additionally emits

```ts
export const <func>_scheme: i32 = 1;   // one per NAMED group; index 0 is the whole match
export const <func>_host:   i32 = 2;

export function <func>_index(name: string): i32;   // -1 if unknown
export function <func>_names(): string[];          // aligned with indices
```

Flat constants rather than JS/TS's single object: AS has no `as const`, and its object support is heavier than a handful of `i32`s.

The constants cover a name known at compile time; `_index` is for one chosen at runtime. An **empty** name is never found — a pattern may hold several unnamed groups, so `""` identifies nothing.

These names follow **your** config's casing, not AssemblyScript's.

---

## Sets

When the config has a `sets:` block, the generator also emits, per set (see
[sets.md](sets.md) for the full config schema and wire format):

```ts
export const <SET>_PATTERN_COUNT: i32 = 12;
export const <SET>_ID_SPACE: i32 = 12;

class SetMatch { constructor(public patternId: i32, public start: u32, public end: u32) {} }

// anchored: the pattern must match the WHOLE input
export function <match_any>(input: ArrayBuffer): i32              // id, -1, or RX_ERR_BT_OVERFLOW
export function <match_all>(input: ArrayBuffer): Array<i32> | null   // null = unknown

// non-anchored: each takes an offset bounding the search
export function <scan_any>(input: ArrayBuffer, offset: u32): i32  // id, -1, or RX_ERR_BT_OVERFLOW; NO position
export function <scan_all>(input: ArrayBuffer, offset: u32): Array<i32> | null

// AssemblyScript has no generators, so `find` is an explicit iterator object.
export function <find>(input: ArrayBuffer, offset: u32): <Find>Iter
class <Find>Iter { next(): SetMatch | null }

// only if any set in the config sets emit_name_map: true
export function patternName(id: i32): string
```

The iterator is caller-owned: two scans can be in flight at once, and creating
a new one restarts the scan. It owns its tuple buffer and its gate array —
both overlap policies take one — so neither ever appears here.

`<match_all>`/`<scan_all>` return an `Array<i32>` of pattern ids, **not** a
boolean. `<scan_any>` decomposes the engine's packed `i64` for you.

`patternName` is a single shared lookup across every set in the config that
requested `emit_name_map: true`.

---

## Summary

| Config field | Generated function | Returns |
|---|---|---|
| `match_func` | `<func>(input: ArrayBuffer): i32` | end position `≥ 0`, or `-1` |
| `find_func` | `<func>(input: ArrayBuffer, offset: u32): i64` | packed `(absStart << 32 \| absEnd)`, or `-1` |
| `groups_func` | `<func>(input: ArrayBuffer, offset: u32): u32` | `dataStart` pointer to slot buffer, or `0` |
| `groups_func` | `<FUNC>_GROUPS: i32` | how many groups the slot buffer holds, group 0 included |
| `groups_func` | `<func>_capture(input, slots: u32, g: i32): string \| null` | the decoded text of group `g` |

**Offsets are `u32`.** An offset into an input cannot be negative, and the type
says so. This CHANGES an existing parameter rather than adding one, so an AS
caller passing a signed expression needs a cast.

`<func>_capture` exists because AssemblyScript is the one language where
captures are addressed purely by arithmetic: without it, reading capture
`groupNum` means computing `load<i32>(slots + 8*groupNum)` twice and
hand-rolling a UTF-8 decode. `<FUNC>_GROUPS` is what makes bounds-checking and
looping over all groups possible at all, and the generated index constants give
the named ones a name.

It takes `input` again ON PURPOSE: the slots are offsets, so decoding needs the
buffer, and a stub that remembered the last input would break the moment two
scans interleave. It returns `null` both when the group did not participate and
when `g` is out of range — those are different errors and this return does not
separate them; an empty capture is legal, so `""` could not separate them
either. The raw offsets stay reachable, so this is additive.
| `<func>_index` / `<func>_names` | name → index, and the index-aligned name table | emitted when the pattern has named groups |

### Batching is a JS/TS-only hint

`hints: [batch-find]` is a **no-op for AssemblyScript**, as it is for C, Go and
Rust. Batching amortises host-boundary crossings and nothing else, and an AS
stub is compiled to wasm and merged, so its call into the module is a direct
call inside one module with no boundary to amortise. There is no `find_batch`
function; `find` is the whole positional surface.

## Notes

- The `batch-find` hint ([`hints:`](cli.md#hints--likelymode-and-batch-find-compile-hints)) is a no-op for AssemblyScript: it's effective for the JS and TS generators only. Setting it does not change the generated stub or its performance.

---

## Backtracking stack overflow

Patterns compiled to the Backtracking engine have a backtrack-frame budget fixed at compile time, while the number of frames actually needed can grow with input length. When an input exhausts the budget, the engine has abandoned part of the search space and cannot say whether the input matches, so the WASM returns a distinct `-2` sentinel rather than "no match".

The generated function **returns a sentinel**. It used to throw, and that was wrong: verified against this repo's own `asc` (0.28.13), `try { } catch { }` is rejected outright —

```
ERROR AS100: Not implemented: Exceptions
```

— and a `throw` compiles to a call to the imported `abort`, a one-way trap the AS caller cannot handle. A throw here was strictly *worse* than a sentinel, not equivalent to one. So AssemblyScript follows C:

```ts
export const RX_ERR_BT_OVERFLOW: i32 = -2;      // scalar and i64 returns
export const RX_ITER_ERROR: u32 = 0xFFFFFFFF;   // pointer returns, where 0 already means "finished"
```

| Function shape | Value on overflow |
|---|---|
| `match_func`, `match_any`, `scan_any` (`i32`) | `RX_ERR_BT_OVERFLOW` |
| `find_func` iterator (`i64`) | `RX_ERR_BT_OVERFLOW` |
| `groups_func` iterator (`u32`) | `RX_ITER_ERROR` |
| `match_all`, `scan_all` | `null` — `Array` is a reference type, so it can be nullable |
| set `find` iterator | `next()` returns `null`; `err()` after the loop distinguishes it from exhaustion |

**`match_any` used to swallow it**, returning the raw `-2` under a doc comment promising only `-1`. It reports it now.

The NARROW `match_all` / `scan_all` do **not** test for it, and must not: their
`i64` return IS the bitmask, so every 64-bit value is a legal answer. `-2` is
`0xFFFF_FFFF_FFFF_FFFE` — ids 1..63 matched and id 0 did not — which a
sentinel test would report as an engine failure on a perfectly good result.
The real sentinel cannot reach that form at all: a set with a Backtracking
member is compiled to the WIDE `_all` ABI, where the return is a COUNT and
`-2` is unambiguous.

This is rare: it needs a pattern that keeps an untried alternation branch live as input is consumed (for example `(?:ab|cd)*?x`), and an input long enough to pass the budget. But when it happens the honest answer is "unknown", and treating it as "no match" would be an input-length-dependent false negative. See [engines.md](engines.md) for the budget formula and which pattern shapes can reach it.
