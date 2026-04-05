# Generated JavaScript API

Regexped generates a JavaScript ES module stub that loads a compiled WASM regex module and exports wrapper functions. This document explains how to initialise the module and use the generated functions.

## Including stubs in your project

The stub is a single `.js` ES module file. Import it directly from your application:

```js
import { init, url_match, find_token } from './regex.js';
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
export function <func>(input: string | Uint8Array): boolean
```

Returns `true` if the full input matches the pattern, `false` otherwise. The match is anchored: the pattern must match the entire input from position 0.

```js
if (url_match('https://example.com/path')) {
    console.log('valid URL');
}
```

---

### `find_func` — non-anchored find generator

```js
export function* <func>(input: string | Uint8Array): Generator<[number, number]>
```

Generator that yields `[start, end]` absolute byte positions for each non-overlapping match. After a zero-length match the iterator advances by one byte to avoid infinite loops.

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

## Summary table

| Config field | Generated export | Returns |
|---|---|---|
| `match_func` | `function <func>(input)` | `boolean` |
| `find_func` | `function* <func>(input)` | generator of `[start, end]` |
| `groups_func` | `function* <func>(input)` | generator of `Array<[start,end]\|null>` |
| `named_groups_func` | `function* <func>(input)` | generator of `Object` (name → `[start,end]`) |

Generated export names match the config field values exactly (no case conversion). All positions are byte offsets in the UTF-8 encoded form of the input. Input can be a `string` (UTF-8 encoded automatically) or a `Uint8Array`.

---

## Notes

- `init()` must be awaited before calling any matcher. Calling a matcher before `init()` will throw.
- The stub uses top-level `await` internally — it is designed for ES module environments (browser, Node.js with `"type": "module"`, Cloudflare Workers).
- Capture group output is written to a fixed offset (1024) inside WASM linear memory. The stub is not re-entrant: do not call two generators concurrently on the same stub module instance.
