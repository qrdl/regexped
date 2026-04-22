# Embedding Regexped in a Browser Application

This guide covers compiling regex patterns to a standalone WASM file and generating a JS module for use in a browser, with no Rust, WASI runtime, or wasm-merge required.

## Overview

The browser workflow produces two files:

- **`regexps.wasm`** — standalone WASM containing all regex engines with their own memory
- **`regex.js`** — generated ES module that loads `regexps.wasm` and exports typed JS wrapper functions

The `index.html` imports `regex.js` as an ES module and calls the exported functions directly.

## Configuration

```yaml
# regexped.yaml
wasm_file:     "regexps.wasm"   # compiled standalone WASM output
stub_file:     "regex.js"       # generated JS module
import_module: "regexps"        # module name used in generated stubs

regexes:
  - pattern:    '[a-zA-Z0-9._%+\-]+@[a-zA-Z0-9.\-]+\.[a-zA-Z]{2,}'
    match_func: "email_match"

  - pattern:    'https?://[a-zA-Z0-9.\-]+\.[a-zA-Z]{2,}(/[^\s]*)?'
    match_func: "url_match"
```

No `output` field means standalone mode: the compiled WASM owns its own memory and can be loaded directly in JS without merging.

## Build Steps

```bash
# 1. Compile regex patterns to a standalone WASM module
regexped compile --config=regexped.yaml

# 2. Generate the JS ES module stub
regexped generate --config=regexped.yaml
```

See [`examples/browser/Makefile`](../examples/browser/Makefile) for a complete Makefile that automates these steps.

## Generated JS API

`regex.js` is an ES module. Call `init()` with the WASM bytes before using any exported function:

```js
import { init, email_match, url_match } from './regex.js';

await init(await fetch('./regexps.wasm').then(r => r.arrayBuffer()));
```

Input can be a `string` or `Uint8Array`.

### `match_func` — boolean validation

```js
const [end, ok] = email_match('user@example.com');
const valid = ok && end === input.length;   // true — full input matched
```

Returns `[endPos, matched]`. `matched` is true if the pattern matched; `endPos` is the byte position where the match ended. For full-string validation, check both `matched` and `end === input.length`.

### `find_func` — scan for all matches

```js
import { url_find } from './regex.js';

for (const [start, end] of url_find(text)) {
    console.log(text.slice(start, end));
}

// First match only:
const first = url_find(text).next().value;  // [start, end] or undefined
```

Returns a generator that yields `[start, end]` absolute byte positions for each non-overlapping match.

### `groups_func` — indexed capture groups

```js
import { parse_record } from './regex.js';

for (const groups of parse_record(text)) {
    // groups[0] = full match [start, end]
    // groups[1] = first capture group [start, end], or null if unmatched
}
```

Returns a generator yielding `Array<[start, end] | null>` per match. Index 0 is the full match.

### `named_groups_func` — named capture groups

```js
import { parse_url } from './regex.js';

for (const parts of parse_url(text)) {
    const [s, e] = parts['host'] ?? [0, 0];
    console.log('host:', text.slice(s, e));
}
```

Returns a generator yielding a plain object mapping group name → `[start, end]` for groups that participated in the match.

## Embedding in HTML

```html
<!DOCTYPE html>
<html>
<head>
  <meta charset="UTF-8">
</head>
<body>
  <script type="module">
    import { init, email_match, url_match } from './regex.js';

    await init(await fetch('./regexps.wasm').then(r => r.arrayBuffer()));

    document.getElementById('email').addEventListener('input', e => {
      const bytes = new TextEncoder().encode(e.target.value);
      const [end, ok] = email_match(bytes);
      const valid = ok && end === bytes.length;
      e.target.style.borderColor = valid ? 'green' : 'red';
    });
  </script>
</body>
</html>
```

The page must be served over HTTP (not `file://`) so that `fetch` can load `regexps.wasm`. Any static file server works: `python3 -m http.server`, `npx serve`, `caddy file-server`, etc.

## How the standalone WASM works

The standalone WASM (no `output` field in config):
- Owns its own memory — no JS memory setup needed
- Exports each regex function under its `_func` name (e.g. `email_match`, `url_match`)
- The generated `regex.js` instantiates it with no imports and accesses exports directly

Input strings are written to memory at address 0; capture group output buffers are placed at offset 1024. Both areas are well within the module's minimum memory.
