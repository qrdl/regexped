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

### `named_groups_func` — named capture groups generator

```ts
export function* <func>(input: string | Uint8Array): Generator<Record<string, [number, number]>>
```

Generator that yields one `Record` per non-overlapping match. Keys are capture group names; values are `[start, end]` absolute byte positions. Only groups that participated in the match are present.

```ts
// All matches:
for (const parts of parse_url(text)) {
    const host = parts['host'];
    if (host) console.log('host:', text.slice(host[0], host[1]));
}

// First match only:
const first = parse_url(text).next().value;
if (first?.host) {
    console.log('host:', text.slice(first.host[0], first.host[1]));
}
```

---

## Summary table

| Config field | Generated export | Return type |
|---|---|---|
| `match_func` | `function <func>(input)` | `number \| null` — the end position, or null |
| `find_func` | `function* <func>(input)` | `Generator<[number, number]>` |
| `groups_func` | `function* <func>(input)` | `Generator<Array<[number, number] \| null>>` |
| `named_groups_func` | `function* <func>(input)` | `Generator<Record<string, [number, number]>>` |

Generated export names match the config field values exactly (no case conversion). All positions are byte offsets in the UTF-8 encoded form of the input. Input can be a `string` (UTF-8 encoded automatically) or a `Uint8Array`.

---

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
[sets.md](sets.md) for why that is what makes it cheap. The `find` generator owns the gate array for the default
non-overlapping configuration; creating a new one restarts the scan.

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
- The TypeScript and JavaScript stubs are independent generators (`generate/ts_stub.go` / `generate/js_stub.go`) that produce the same external API, typed vs. untyped, including the same batch behaviour: `find_func`, `groups_func`, and `named_groups_func` generators auto-detect and drain an internal `<func>_batch` WASM export when present, reducing host↔WASM call overhead. This export only exists when the pattern was compiled with `hints: [batch-find]` (see [`hints:`](cli.md#hints--likelymode-and-batch-find-compile-hints)); it has no effect on the output shape, only on call overhead. When both `groups_func` and `named_groups_func` are set on the same entry they share one batch export (named after `groups_func`); a `named_groups_func`-only entry gets its own, named after itself.

---

## Backtracking stack overflow

Patterns compiled to the Backtracking engine have a backtrack-frame budget fixed at compile time, while the number of frames actually needed can grow with input length. When an input exhausts the budget, the engine has abandoned part of the search space and cannot say whether the input matches, so the WASM returns a distinct `-2` sentinel rather than "no match".

The generated function **throws** an `Error` whose message names the function. Since the find/groups functions are generators, the throw surfaces from the `next()` call (i.e. from the `for...of` loop), not from the call that creates the generator.

This is rare: it needs a pattern that keeps an untried alternation branch live as input is consumed (for example `(?:ab|cd)*?x`), and an input long enough to pass the budget. But when it happens the honest answer is "unknown", and treating it as "no match" would be an input-length-dependent false negative. See [engines.md](engines.md) for the budget formula and which pattern shapes can reach it.
