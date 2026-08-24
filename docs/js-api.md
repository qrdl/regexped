# Generated JavaScript API

Regexped generates a JavaScript ES module stub that loads a compiled WASM regexp module and exports wrapper functions. This document explains how to initialise the module and use the generated functions.

## Including stubs in your project

The stub is a single `.js` ES module file. Import it directly from your application:

```js
import { init, url_match, find_token } from './regexp.js';
```

The stub requires the merged WASM file (produced by `regexped merge`) to be loaded at startup via `init()`. The module exports one `init` function plus one function per configured `_func` field.

---

## Initialisation

```js
export async function init(wasm): Promise<void>
```

Must be called once before any matcher function. Accepts a `BufferSource` (e.g. `ArrayBuffer`, `Buffer`, `Uint8Array`) or a pre-compiled `WebAssembly.Module`.

```js
// Browser
await init(await fetch('./merged.wasm').then(r => r.arrayBuffer()));

// Node.js
import { readFileSync } from 'node:fs';
await init(readFileSync('./merged.wasm'));

// Cloudflare Workers
import wasm from './merged.wasm';
await init(wasm);
```

---

## Generated functions by config field

### `match_func` — anchored match

```js
export function <func>(input: string | Uint8Array): number | null
```

Returns `[endPos, true]` if the pattern matches starting at position 0, or `[0, false]` if no match. `endPos` is the exclusive end position of the match in bytes.

To test whether the full input matches (anchored at both ends):

```js
const enc = new TextEncoder();
const bytes = enc.encode('https://example.com/path');
const end = url_match(bytes);
if (end === bytes.length) {
    console.log('valid URL');
}
```

For start-anchored use cases where the end position matters:

```js
const end = url_match(input);
if (end !== null) {
    console.log('matched first', end, 'bytes');
}
```

---

### `find_func` — non-anchored find generator

```js
export function* <func>(input: string | Uint8Array): Generator<[number, number]>
```

Generator that yields `[start, end]` absolute byte positions for each non-overlapping match. After a zero-length match the iterator advances by one byte to avoid infinite loops, and — following Go's `FindAllIndex` — an empty match beginning exactly where the previous reported match ended is not reported.

The whole input is passed on every call and `offset` only bounds where the search STARTS, so a leading `\b`, `\B`, `^` or `(?m:^)` is judged against the real preceding byte rather than a slice edge.

```js
// All matches:
for (const [start, end] of find_token(text)) {
    console.log('match:', text.slice(start, end));
}

// First match only:
const first = find_token(text).next().value;
if (first) {
    const [start, end] = first;
    console.log('first match:', text.slice(start, end));
}
```

---

### `groups_func` — capture groups generator

```js
export function* <func>(input: string | Uint8Array): Generator<Array<[number, number] | null>>
```

Generator that yields one array per non-overlapping match. Each element is `[start, end]` (absolute byte positions) or `null` for a group that did not participate. Index 0 is the full match; subsequent indices are capture groups in order.

```js
// All matches:
for (const groups of parse_groups(text)) {
    if (groups[1] !== null) {
        const [s, e] = groups[1];
        console.log('group 1:', text.slice(s, e));
    }
}

// First match only:
const first = parse_groups(text).next().value;
if (first && first[1] !== null) {
    const [s, e] = first[1];
    console.log('group 1:', text.slice(s, e));
}
```

---

### `named_groups_func` — named capture groups generator

```js
export function* <func>(input: string | Uint8Array): Generator<Object>
```

Generator that yields one plain object per non-overlapping match. Each key is a capture group name; the value is `[start, end]` (absolute byte positions). Only groups that participated in the match are present.

```js
// All matches:
for (const parts of parse_url(text)) {
    if ('host' in parts) {
        const [s, e] = parts['host'];
        console.log('host:', text.slice(s, e));
    }
}

// First match only:
const first = parse_url(text).next().value;
if (first?.host) {
    const [s, e] = first['host'];
    console.log('host:', text.slice(s, e));
}
```

---

## Set composition exports

When the config has a `sets:` block, the stub also exports one function per
declared capability (see [sets.md](sets.md) for the full config schema and
wire format):

```js
export const <set>PatternCount = 12;

// anchored: the pattern must match the WHOLE input
export function <match_any>(input)            // -> number | null   (a pattern id)
export function <match_all>(input)            // -> number[]        NOT a boolean

// non-anchored: each takes an offset bounding the search
export function <scan_any>(input, offset = 0) // -> number | null   (an id; NO position)
export function <scan_all>(input, offset = 0) // -> number[]        NOT a boolean

export function* <find>(input, offset = 0)    // yields {patternId, start, end}

// with hints: [batch-find] the find generator gains a third parameter, and the
// set exports its ceiling. Without the hint the parameter does not exist.
export const <set>BatchMaxSize
export function* <find>(input, offset = 0, batchSize = 256)

export function patternName(id)             // only if any set sets emit_name_map: true
```

**`_all` and `_any` return data, not predicates.** JavaScript cannot catch the
misreading, and an empty array is truthy:

```js
if (scan_all(input)) { ... }   // ALWAYS true, even with zero matches
if (scan_all(input).length) { ... }   // what you meant
```

The `find` generator owns the gate array for the default (non-overlapping)
configuration: dropping it and creating a new one restarts the scan with clean
gates. There is no stateless single-position probe — the generator is the only
find surface, matching every other language.

`scan_any` and the `_all` pair are backed by `i64` WASM returns, which surface
as BigInt. The stub decomposes them; a BigInt never reaches you.

**Do not call other stub functions while a generator is suspended.** The staged
input and the shared output region belong to whichever call ran last, so an
interleaved call makes the suspended generator scan the wrong bytes and report
offsets against them, silently. The same constraint already applies to the
single-pattern `find_func`/`groups_func`/`named_groups_func` generators.

`patternName` is a single shared lookup across every set in the config that
requested `emit_name_map: true`.

---

## Summary table

| Config field | Generated export | Returns |
|---|---|---|
| `match_func` | `function <func>(input)` | `number \| null` — the end position, or null |
| `find_func` | `function* <func>(input, offset = 0)` | generator of `[start, end]` |
| `groups_func` | `function* <func>(input, offset = 0)` | generator of `Array<[start,end]\|null>` |
| `named_groups_func` | `function* <func>(input, offset = 0)` | generator of `Object` (name → `[start,end]`) |

Generated export names match the config field values exactly (no case conversion). All positions are byte offsets in the UTF-8 encoded form of the input. Input can be a `string` (UTF-8 encoded automatically) or a `Uint8Array`.

---

### `batchSize` — the same matches, a bufferful per call

`find` crosses the host boundary once per matching position. With
`hints: [batch-find]` on the set, `find` gains an optional `batchSize` and
fills a buffer with as many consecutive positions as fit, so a caller who will
consume the whole scan crosses once per bufferful instead. Leave it out when
you may stop early — a batched call does the work for matches you never look
at, which is exactly why batching is opt-in rather than the default.

It is the SAME function either way: same matches, same order, same overlap
policy. Only how much work one crossing does changes. `batchSize` is clamped
into `[1, <set>BatchMaxSize]`; any value of 1 or more makes progress, since a
position whose matches do not all fit is delivered in part and resumed inside.
Group by the match's `start` field rather than by call boundary if you need
per-position grouping.

**JS and TS are the only languages with this parameter.** Batching amortises
host-boundary crossings, and C, Go, Rust and AssemblyScript are compiled to
wasm and merged — their call into the module is a direct call inside one module
with no boundary to amortise. The hint is a no-op there.

## Notes

- `init()` must be awaited before calling any matcher. Calling a matcher before `init()` will throw.
- The stub uses top-level `await` internally — it is designed for ES module environments (browser, Node.js with `"type": "module"`, Cloudflare Workers).
- `init()` grows WASM memory by two pages beyond the DFA table area: one for input, one for capture group output and set result buffers. The stub is not re-entrant: do not call two generators concurrently on the same stub module instance.
- `find_func`, `groups_func`, and `named_groups_func` generators automatically detect and use an internal `<func>_batch` WASM export when present, draining several matches per host↔WASM call instead of one. This export only exists when the pattern was compiled with `hints: [batch-find]` (see [`hints:`](cli.md#hints--likelymode-and-batch-find-compile-hints)); it's purely an internal performance path and doesn't change the generator's external `[start,end]` / capture-array / named-object output. Covers every `groups_func`/`named_groups_func` shape, including the native lit-chain ("Path B") groups bodies. When both `groups_func` and `named_groups_func` are set on the same entry they share one batch export (named after `groups_func`); a `named_groups_func`-only entry gets its own, named after itself.

---

## Backtracking stack overflow

Patterns compiled to the Backtracking engine have a backtrack-frame budget fixed at compile time, while the number of frames actually needed can grow with input length. When an input exhausts the budget, the engine has abandoned part of the search space and cannot say whether the input matches, so the WASM returns a distinct `-2` sentinel rather than "no match".

The generated function **throws** an `Error` whose message names the function. Since the find/groups functions are generators, the throw surfaces from the `next()` call (i.e. from the `for...of` loop), not from the call that creates the generator.

This is rare: it needs a pattern that keeps an untried alternation branch live as input is consumed (for example `(?:ab|cd)*?x`), and an input long enough to pass the budget. But when it happens the honest answer is "unknown", and treating it as "no match" would be an input-length-dependent false negative. See [engines.md](engines.md) for the budget formula and which pattern shapes can reach it.
