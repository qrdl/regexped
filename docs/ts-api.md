# Generated TypeScript API

Regexped generates a TypeScript ES module stub that loads a compiled WASM regexp module and exports typed wrapper functions. The TypeScript stub matches the JavaScript stub's external API and behaviour, with one internal exception noted in [Notes](#notes) below (JS's `find_func`/`groups_func` generators have an internal fast path the TS stub doesn't yet have).

## Including stubs in your project

The stub is a single `.ts` ES module file. Import it directly:

```ts
import { init, url_match, find_token } from './regexp.ts';
```

The stub requires the merged WASM file (produced by `regexped merge`) to be loaded at startup via `init()`. The module exports one `init` function plus one function per configured `_func` field.

---

## Initialisation

```ts
export async function init(wasm: BufferSource | WebAssembly.Module): Promise<void>
```

Must be called once before any matcher function. Accepts a `BufferSource` (e.g. `ArrayBuffer`, `Buffer`, `Uint8Array`) or a pre-compiled `WebAssembly.Module`.

```ts
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

```ts
export function <func>(input: string | Uint8Array): number | null
```

Returns `[endPos, true]` if the pattern matches starting at position 0, or `[0, false]` if no match. `endPos` is the exclusive end position of the match in bytes.

To test whether the full input matches (anchored at both ends):

```ts
const enc = new TextEncoder();
const bytes = enc.encode('https://example.com/path');
const end = url_match(bytes);
if (end === bytes.length) {
    console.log('valid URL');
}
```

For start-anchored use cases where the end position matters:

```ts
const end: number | null = url_match(input);
if (end !== null) {
    console.log('matched first', end, 'bytes');
}
```

---

### `find_func` — non-anchored find generator

```ts
export function* <func>(input: string | Uint8Array): Generator<[number, number]>
```

Generator that yields `[start, end]` absolute byte positions for each non-overlapping match. After a zero-length match the iterator advances by one byte to avoid infinite loops, and — following Go's `FindAllIndex` — an empty match beginning exactly where the previous reported match ended is not reported.

The whole input is passed on every call and `offset` only bounds where the search STARTS, so a leading `\b`, `\B`, `^` or `(?m:^)` is judged against the real preceding byte rather than a slice edge.

```ts
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

```ts
export function* <func>(input: string | Uint8Array): Generator<Array<[number, number] | null>>
```

Generator that yields one array per non-overlapping match. Each element is `[start, end]` (absolute byte positions) or `null` for a group that did not participate. Index 0 is the full match; subsequent indices are capture groups in order.

```ts
// All matches:
for (const groups of parse_groups(text)) {
    const g = groups[1];
    if (g !== null) {
        const [s, e] = g;
        console.log('group 1:', text.slice(s, e));
    }
}

// First match only:
const first = parse_groups(text).next().value;
if (first) {
    const g = first[1];
    if (g !== null) console.log('group 1:', text.slice(g[0], g[1]));
}
```

---

### Named groups — one frozen index object

`named_groups_func` is **retired** (a config key using it is a load error). It was never a separate capability: both stubs called the *same* WASM export, and the two differed only in how the item was assembled — an object keyed by name instead of an array indexed by number, minus the whole match and minus the groups that did not participate.

When a pattern has at least one named group, `groups_func` additionally emits one object:

```ts
export const <groups_func>_indices = {
    scheme: 1,   // one per NAMED group; index 0 is the whole match
    host:   2,
} as const;
```

`as const` gives the values literal types, so indexing the yielded array with one is checked.

```ts
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
declared capability (see [sets.md](sets.md) for the full config schema and wire
format):

```ts
export const <set>PatternCount: number;
export const <set>IdSpace: number;

export interface SetMatch { patternId: number; start: number; end: number; }

// anchored: the pattern must match the WHOLE input
export function <match_any>(input: string | Uint8Array): number | null
export function <match_all>(input: string | Uint8Array): number[]

// non-anchored: each takes an offset bounding the search
export function <scan_any>(input: string | Uint8Array, offset?: number): number | null
export function <scan_all>(input: string | Uint8Array, offset?: number): number[]

// find: without the `batch-find` hint there is no batchSize parameter at all,
// so TypeScript rejects find(input, 0, 64) at build time.
export function* <find>(input: string | Uint8Array, offset?: number): Generator<SetMatch>

// with hints: [batch-find]
export const <set>BatchMaxSize: number;
export function* <find>(input: string | Uint8Array, offset?: number, batchSize?: number): Generator<SetMatch>
```

`<match_all>` and `<scan_all>` stay **arrays, not generators**. That is
deliberate and is where TS does not follow Go's `iter.Seq[int]` or Rust's
`impl Iterator`: an array materialises before returning and cannot be suspended,
so it needs no region of its own. The allocation argument that carried Go and
Rust does not transfer — JS allocates the array either way, and the host
crossing dominates it. (This once also avoided the suspended-generator hazard;
that hazard is fixed, so it is no longer part of the reason.)

The types make the `_any`/`_all` shapes explicit, which is the difference from
the JavaScript stub — there, `if (scanAll(x))` is always true because an empty
array is truthy. `<scan_any>` reports **no position**, only an id: see
[sets.md](sets.md) for why that is what makes it cheap. The `find` generator owns the gate array under either overlap policy;
creating a new one restarts the scan.

**Calling other stub functions while a generator is suspended is safe**, as is
running or nesting two generators over different inputs. Each live generator
owns its input and scratch region for its whole lifetime — the guarantee Rust
and Go get from passing a host pointer — and releases it on any exit, including
an early `break`. Until 2026-08-25 this was not true: one shared staging address
meant an interleaved call left a suspended generator scanning another string's
bytes, silently (TODO 58).

`patternName(id)` is emitted once per config when any set sets
`emit_name_map: true`.

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
- The stub is designed for ES module environments (browser, Node.js with `"type": "module"`, Cloudflare Workers, Deno).
- `init()` grows WASM memory by two pages beyond the DFA table area: one for input, one for capture group output and set result buffers. The stub is not re-entrant: do not call two generators concurrently on the same stub module instance.
- The TypeScript and JavaScript stubs are independent generators (`generate/ts_stub.go` / `generate/js_stub.go`) that produce the same external API, typed vs. untyped, including the same batch behaviour: `find_func` and `groups_func` generators auto-detect and drain an internal `<func>_batch` WASM export when present, reducing host↔WASM call overhead. This export only exists when the pattern was compiled with `hints: [batch-find]` (see [`hints:`](cli.md#hints--likelymode-and-batch-find-compile-hints)); it has no effect on the output shape, only on call overhead.

  The rule about `groups_func` and `named_groups_func` *sharing* a batch export is gone with the key: one capability, one export, one name.

---

## Backtracking stack overflow

Patterns compiled to the Backtracking engine have a backtrack-frame budget fixed at compile time, while the number of frames actually needed can grow with input length. When an input exhausts the budget, the engine has abandoned part of the search space and cannot say whether the input matches, so the WASM returns a distinct `-2` sentinel rather than "no match".

The generated function **throws** an `Error` whose message names the function. Since the find/groups functions are generators, the throw surfaces from the `next()` call (i.e. from the `for...of` loop), not from the call that creates the generator.

**`match_any` used to swallow it.** It folded `-2` into `null`; it now throws.

The NARROW `match_all` / `scan_all` do **not** test for it, and must not: their
`i64` return IS the bitmask, so every 64-bit value is a legal answer. `-2` is
`0xFFFF_FFFF_FFFF_FFFE` — ids 1..63 matched and id 0 did not — which a
sentinel test would report as an engine failure on a perfectly good result.
The real sentinel cannot reach that form at all: a set with a Backtracking
member is compiled to the WIDE `_all` ABI, where the return is a COUNT and
`-2` is unambiguous.

This is rare: it needs a pattern that keeps an untried alternation branch live as input is consumed (for example `(?:ab|cd)*?x`), and an input long enough to pass the budget. But when it happens the honest answer is "unknown", and treating it as "no match" would be an input-length-dependent false negative. See [engines.md](engines.md) for the budget formula and which pattern shapes can reach it.
