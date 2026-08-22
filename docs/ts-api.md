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
export function <func>(input: string | Uint8Array): [number, boolean]
```

Returns `[endPos, true]` if the pattern matches starting at position 0, or `[0, false]` if no match. `endPos` is the exclusive end position of the match in bytes.

To test whether the full input matches (anchored at both ends):

```ts
const enc = new TextEncoder();
const bytes = enc.encode('https://example.com/path');
const [end, ok] = url_match(bytes);
if (ok && end === bytes.length) {
    console.log('valid URL');
}
```

For start-anchored use cases where the end position matters:

```ts
const [end, ok]: [number, boolean] = url_match(input);
if (ok) {
    console.log('matched first', end, 'bytes');
}
```

---

### `find_func` — non-anchored find generator

```ts
export function* <func>(input: string | Uint8Array): Generator<[number, number]>
```

Generator that yields `[start, end]` absolute byte positions for each non-overlapping match. After a zero-length match the iterator advances by one byte to avoid infinite loops.

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
| `match_func` | `function <func>(input)` | `[number, boolean]` — `[endPos, matched]` |
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

export interface SetMatch  { patternId: number; start: number; end: number; }
export interface SetAnchor { patternId: number; start: number; }

// anchored: the pattern must match the WHOLE input
export function <match>(input: string | Uint8Array): boolean
export function <match_any>(input: string | Uint8Array): number | null
export function <match_all>(input: string | Uint8Array): number[]

// non-anchored: each takes a `from` position
export function <scan>(input: string | Uint8Array, from?: number): boolean
export function <scan_any>(input: string | Uint8Array, from?: number): SetAnchor | null
export function <scan_all>(input: string | Uint8Array, from?: number): number[]

export function* <find>(input: string | Uint8Array, from?: number): Generator<SetMatch>
```

The types make the `_any`/`_all` shapes explicit, which is the difference from
the JavaScript stub — there, `if (scanAll(x))` is always true because an empty
array is truthy. The `find` generator owns the gate array for the default
non-overlapping configuration; creating a new one restarts the scan.

**Do not call other stub functions while a generator is suspended** — the
staged input and the shared output region belong to whichever call ran last.

`patternName(id)` is emitted once per config when any set sets
`emit_name_map: true`.

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
