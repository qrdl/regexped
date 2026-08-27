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

### Named groups — one frozen index object

`named_groups_func` is **retired** (a config key using it is a load error). It was never a separate capability: both stubs called the *same* WASM export, and the two differed only in how the item was assembled — an object keyed by name instead of an array indexed by number, minus the whole match and minus the groups that did not participate.

When a pattern has at least one named group, `groups_func` additionally emits one object:

```js
export const <groups_func>_indices = Object.freeze({
    scheme: 1,   // one per NAMED group; index 0 is the whole match
    host:   2,
});
```

```js
for (const match of parse_url(text)) {
    const host = match[parse_url_indices.host];
    if (host) console.log('host:', text.slice(host[0], host[1]));
}

Object.keys(parse_url_indices);   // the group names
```

The `_indices` suffix is required, not decorative: the object is the only derived symbol with no suffix of its own, so without one its name would be the generator function's and the two would collide.

The name follows **your** config's casing — `groups_func: parse_url` yields `parse_url_indices`, `groups_func: parseUrl` yields `parseUrlIndices`.

Duplicate or colliding group names are rejected at **config load**: `regexp/syntax` accepts `(?P<a>x)(?P<a>y)` and `(?P<host>x)(?P<Host>y)`, but both would collapse to one generated key.

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

The `find` generator owns the gate array, whichever overlap policy the set
declares: dropping it and creating a new one restarts the scan with a clean
array. There is no stateless single-position probe — the generator is the only
find surface, matching every other language.

`scan_any` and the `_all` pair are backed by `i64` WASM returns, which surface
as BigInt. The stub decomposes them; a BigInt never reaches you.

**Calling other stub functions while a generator is suspended is safe.** So is
running two generators over two different inputs at once, or nesting one inside
the other:

```js
for (const m of findSecrets(document)) {
    if (matchAllUrls(someOtherString).length) { … }   // fine
}
```

Each live generator owns its input and scratch region for its whole lifetime,
which is the same guarantee the Rust and Go stubs get from passing a host
pointer. A generator that exits early — `break`, `return`, or a thrown error —
releases its region on the way out, so nothing leaks.

*This was not always true.* Until 2026-08-25 every call staged its input at one
shared address, so an interleaved call left a suspended generator scanning
another string's bytes and reporting offsets against it — silently, with no
exception and plausible-looking output (TODO 58). If you are on an older
generated stub, that hazard is real and the old rule ("do not call other stub
functions while a generator is suspended") still applies to it.

`patternName` is a single shared lookup across every set in the config that
requested `emit_name_map: true`.

---

## Summary table

| Config field | Generated export | Returns |
|---|---|---|
| `match_func` | `function <func>(input)` | `number \| null` — the end position, or null |
| `find_func` | `function* <func>(input, offset = 0)` | generator of `[start, end]` |
| `groups_func` | `function* <func>(input, offset = 0)` | generator of `Array<[start,end]\|null>` |
| `<groups_func>_indices` | frozen object | name → group index, emitted when the pattern has named groups |

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
- `find_func` and `groups_func` generators automatically detect and use an internal `<func>_batch` WASM export when present, draining several matches per host↔WASM call instead of one. This export only exists when the pattern was compiled with `hints: [batch-find]` (see [`hints:`](cli.md#hints--likelymode-and-batch-find-compile-hints)); it's purely an internal performance path and doesn't change the generator's external `[start,end]` / capture-array output. Covers every `groups_func` shape, including the native lit-chain ("Path B") groups bodies.

  The rule about `groups_func` and `named_groups_func` *sharing* a batch export is gone with the key: one capability, one export, one name.

---

## Backtracking stack overflow

Patterns compiled to the Backtracking engine have a backtrack-frame budget fixed at compile time, while the number of frames actually needed can grow with input length. When an input exhausts the budget, the engine has abandoned part of the search space and cannot say whether the input matches, so the WASM returns a distinct `-2` sentinel rather than "no match".

The generated function **throws** an `Error` whose message names the function. Since the find/groups functions are generators, the throw surfaces from the `next()` call (i.e. from the `for...of` loop), not from the call that creates the generator.

**Three set exports used to swallow it.** `match_any` folded `-2` into `null`, and the narrow `match_all`/`scan_all` treated it as a bitmask — `-2` reads as *every id except 0 matched*. All three now throw. Neither could fire in practice, but the invariants that kept them safe lived in the compiler rather than beside the code that depended on them.

This is rare: it needs a pattern that keeps an untried alternation branch live as input is consumed (for example `(?:ab|cd)*?x`), and an input long enough to pass the budget. But when it happens the honest answer is "unknown", and treating it as "no match" would be an input-length-dependent false negative. See [engines.md](engines.md) for the budget formula and which pattern shapes can reach it.
