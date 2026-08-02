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

## Notes

- `init()` must be awaited before calling any matcher. Calling a matcher before `init()` will throw.
- The stub is designed for ES module environments (browser, Node.js with `"type": "module"`, Cloudflare Workers, Deno).
- `init()` grows WASM memory by two pages beyond the DFA table area: one for input, one for capture group output and set result buffers. The stub is not re-entrant: do not call two generators concurrently on the same stub module instance.
- The TypeScript and JavaScript stubs are independent generators (`generate/ts_stub.go` / `generate/js_stub.go`) that produce the same external API, typed vs. untyped. One current internal difference: the JS stub's `find_func`/`groups_func` generators auto-detect and drain an internal `<func>_batch` WASM export (present when the pattern was compiled with `hints: [prefer-match]`) to reduce host↔WASM call overhead — the TS stub does not yet do this and always issues one call per match. This has no effect on the output shape, only on call overhead under `prefer-match`.
