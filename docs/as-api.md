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

### `find_func` — non-anchored find

```ts
export function <func>(input: ArrayBuffer, offset: i32): i64
```

Scans `input[offset..]` for the next match. Returns a **packed** `i64`:

```
(absStart << 32) | absEnd
```

Both positions are absolute byte offsets into the original `input`. Returns `-1` if
no match is found from `offset` onward.

To iterate all non-overlapping matches:

```ts
import { find_token } from "./stub";

const buf = String.UTF8.encode(text);
let off: i32 = 0;
while (true) {
  const r = find_token(buf, off);
  if (r < 0) break;
  const start = i32(<u64>r >> 32);
  const end   = i32(<u32>r);
  // use start, end ...
  off = end > start ? end : start + 1;  // advance past zero-length matches
}
```

---

### `groups_func` — capture groups

```ts
export function <func>(input: ArrayBuffer, offset: i32): i32
```

Scans `input[offset..]` for the next match and fills a **static `Int32Array`** slot
buffer with absolute byte positions for each capture group.

Returns the **`dataStart`** pointer of the slot buffer (a non-zero `i32`) on match,
or `0` if no match is found from `offset` onward.

#### Slot layout

The buffer contains `numGroups * 2` entries:

```
index 0, 1  →  group 0 start, end  (full match)
index 2, 3  →  group 1 start, end  (first capture group)
index 4, 5  →  group 2 start, end
…
```

Values are absolute byte offsets into `input`. An optional group that did not
participate has both its `start` and `end` set to `-1`.

#### Reading slots with `load<i32>`

```ts
import { find_email } from "./stub";

function slice(buf: ArrayBuffer, start: i32, end: i32): string {
  return String.UTF8.decodeUnsafe(
    changetype<usize>(buf) + <usize>start,
    <usize>(end - start),
    false,
  );
}

const buf = String.UTF8.encode(text);
let off: i32 = 0;
while (true) {
  const slots = find_email(buf, off);
  if (!slots) break;
  const matchStart = load<i32>(slots);          // group 0 start
  const matchEnd   = load<i32>(slots + 4);      // group 0 end
  const userStart  = load<i32>(slots + 8);      // group 1 start
  const userEnd    = load<i32>(slots + 12);      // group 1 end
  const domStart   = load<i32>(slots + 16);     // group 2 start
  const domEnd     = load<i32>(slots + 20);     // group 2 end
  // … use the slices
  off = matchEnd > matchStart ? matchEnd : matchStart + 1;
}
```

Each slot entry is a 4-byte `i32`, so consecutive groups are at `slots + 0`,
`slots + 4`, `slots + 8`, etc.

> **Warning:** the slot buffer is **static and overwritten on each call**, and is
> **not thread-safe** — concurrent calls on the same module instance will race
> on the buffer. Read all slot values before calling the same function again.

---

### `named_groups_func` — not supported

`named_groups_func` is **not supported** for AssemblyScript stubs. The generator
returns an error if this field is set.

Use `groups_func` instead and access groups by their numeric index. Named groups keep
their original order in the pattern, so the mapping from name to index is stable and
known at compile time.

---

## Sets

When the config has a `sets:` block, the generator also emits, per set (see
[sets.md](sets.md) for the full config schema and wire format):

```ts
export const <SET>_PATTERN_COUNT: i32 = 12;

class SetMatch  { constructor(public patternId: i32, public start: i32, public end: i32) {} }
class SetAnchor { constructor(public patternId: i32, public start: i32) {} }

// anchored: the pattern must match the WHOLE input
export function <match>(input: ArrayBuffer): bool
export function <match_any>(input: ArrayBuffer): i32              // id, or -1
export function <match_all>(input: ArrayBuffer): Array<i32>

// non-anchored: each takes a `from` position
export function <scan>(input: ArrayBuffer, from: i32): bool
export function <scan_any>(input: ArrayBuffer, from: i32): SetAnchor | null
export function <scan_all>(input: ArrayBuffer, from: i32): Array<i32>

// AssemblyScript has no generators, so `find` is an explicit iterator object.
export function <find>(input: ArrayBuffer, from: i32): <Find>Iter
class <Find>Iter { next(): SetMatch | null }

// only if any set in the config sets emit_name_map: true
export function patternName(id: i32): string
```

The iterator is caller-owned: two scans can be in flight at once, and creating
a new one restarts the scan. It owns its tuple buffer and — for the default
non-overlapping `find` — its gate array, so gates never appear here.

`<match_all>`/`<scan_all>` return an `Array<i32>` of pattern ids, **not** a
boolean. `<scan_any>` decomposes the engine's packed `i64` for you.

`patternName` is a single shared lookup across every set in the config that
requested `emit_name_map: true`.

---

## Summary

| Config field | Generated function | Returns |
|---|---|---|
| `match_func` | `<func>(input: ArrayBuffer): i32` | end position `≥ 0`, or `-1` |
| `find_func` | `<func>(input: ArrayBuffer, offset: i32): i64` | packed `(absStart << 32 \| absEnd)`, or `-1` |
| `groups_func` | `<func>(input: ArrayBuffer, offset: i32): i32` | `dataStart` pointer to slot buffer, or `0` |
| `named_groups_func` | **not supported** — generator returns an error | — |

## Notes

- The `batch-find` hint ([`hints:`](cli.md#hints--likelymode-and-batch-find-compile-hints)) is a no-op for AssemblyScript: it's effective for the JS and TS generators only. Setting it does not change the generated stub or its performance.

---

## Backtracking stack overflow

Patterns compiled to the Backtracking engine have a backtrack-frame budget fixed at compile time, while the number of frames actually needed can grow with input length. When an input exhausts the budget, the engine has abandoned part of the search space and cannot say whether the input matches, so the WASM returns a distinct `-2` sentinel rather than "no match".

The generated function **throws** an `Error` whose message names the function. Note that in AssemblyScript an uncaught `throw` compiles to an abort, so the host sees a WASM trap.

This is rare: it needs a pattern that keeps an untried alternation branch live as input is consumed (for example `(?:ab|cd)*?x`), and an input long enough to pass the budget. But when it happens the honest answer is "unknown", and treating it as "no match" would be an input-length-dependent false negative. See [engines.md](engines.md) for the budget formula and which pattern shapes can reach it.
