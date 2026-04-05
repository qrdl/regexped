# Generated TypeScript API

Regexped generates a TypeScript ES module stub that loads a compiled WASM regex module and exports typed wrapper functions. The TypeScript stub is identical in behaviour to the JavaScript stub but adds full type annotations.

## Including stubs in your project

The stub is a single `.ts` ES module file. Import it directly:

```ts
import { init, url_match, find_token } from './regex.ts';
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
export function <func>(input: string | Uint8Array): boolean
```

Returns `true` if the full input matches the pattern, `false` otherwise. The match is anchored: the pattern must match the entire input from position 0.

```ts
if (url_match('https://example.com/path')) {
    console.log('valid URL');
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
| `match_func` | `function <func>(input)` | `boolean` |
| `find_func` | `function* <func>(input)` | `Generator<[number, number]>` |
| `groups_func` | `function* <func>(input)` | `Generator<Array<[number, number] \| null>>` |
| `named_groups_func` | `function* <func>(input)` | `Generator<Record<string, [number, number]>>` |

Generated export names match the config field values exactly (no case conversion). All positions are byte offsets in the UTF-8 encoded form of the input. Input can be a `string` (UTF-8 encoded automatically) or a `Uint8Array`.

---

## Notes

- `init()` must be awaited before calling any matcher. Calling a matcher before `init()` will throw.
- The stub is designed for ES module environments (browser, Node.js with `"type": "module"`, Cloudflare Workers, Deno).
- Capture group output is written to a fixed offset (1024) inside WASM linear memory. The stub is not re-entrant: do not call two generators concurrently on the same stub module instance.
- The TypeScript stub and the JavaScript stub are generated from the same template; the only differences are the type annotations on `init`, `_mem`, `_exp`, and each exported function signature.
