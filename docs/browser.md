# Embedding Regexped in a Browser Application

This guide covers building a single merged WASM file and a generated JS module for use in a browser, with no Rust or WASI runtime required.

## Overview

The browser workflow produces two files:

- **`final.wasm`** — merged WASM containing all regex engines and their own memory
- **`regex.js`** — generated ES module that loads `final.wasm` and exports typed JS wrapper functions

The `index.html` imports `regex.js` as an ES module and calls the exported functions directly.

## Configuration

```yaml
# regexped.yaml
wasm_merge: "path/to/wasm-merge"   # required for merge step
output:    "final.wasm"            # merged WASM output
stub_file: "regex.js"              # generated JS module

regexes:
  - wasm_file:     "email.wasm"
    import_module: "email"
    pattern:       '[a-zA-Z0-9._%+\-]+@[a-zA-Z0-9.\-]+\.[a-zA-Z]{2,}'
    match_func:    "email_match"

  - wasm_file:     "url.wasm"
    import_module: "url"
    pattern:       'https?://[a-zA-Z0-9.\-]+\.[a-zA-Z]{2,}(/[^\s]*)?'
    find_func:     "url_find"
```

## Build Steps

```bash
# 1. Generate a minimal main WASM (memory-only placeholder, no Rust code needed)
regexped generate --dummy_main

# 2. Compile each regex pattern to WASM
regexped compile --config=regexped.yaml --wasm-input=main.wasm

# 3. Merge everything into a single self-contained WASM
#    The merged module owns its memory — no JS memory management needed
regexped merge --config=regexped.yaml main.wasm email.wasm url.wasm

# 4. Generate the JS ES module stub
regexped generate --config=regexped.yaml --js
```

See [`examples/browser/Makefile`](../examples/browser/Makefile) for a complete Makefile that automates these steps.

## Generated JS API

`regex.js` is an ES module using top-level `await`. It loads `final.wasm` at import time and exports wrapper functions named after the `_func` fields in the config.

### `match_func` — boolean validation

```js
import { email_match } from './regex.js';

email_match('user@example.com');   // true
email_match('not-an-email');       // false
```

Returns `true` if the entire input matches the pattern (anchored at both ends), `false` otherwise. Input can be a `string` or `Uint8Array`.

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

// First match only:
const groups = parse_record(text).next().value;
```

Returns a generator yielding `Array<[start, end] | null>` per match. Index 0 is the full match.

### `named_groups_func` — named capture groups

```js
import { parse_url } from './regex.js';

for (const parts of parse_url(text)) {
    const [s, e] = parts['host'] ?? [0, 0];
    console.log('host:', text.slice(s, e));
}

// First match only:
const parts = parse_url(text).next().value;
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
    // regex.js uses top-level await — import it as a module.
    import { email_match, url_find } from './regex.js';

    document.getElementById('email').addEventListener('input', e => {
      const valid = email_match(e.target.value);
      e.target.style.borderColor = valid ? 'green' : 'red';
    });
  </script>
</body>
</html>
```

The page must be served over HTTP (not `file://`) so that `fetch` can load `final.wasm`. Any static file server works: `python3 -m http.server`, `npx serve`, `caddy file-server`, etc.

## How the merged WASM works

After `wasm-merge`:
- `final.wasm` contains all DFA/OnePass tables as data segments
- It exports `memory` (from the dummy main module) — no JS memory setup needed
- It exports each regex function under its `_func` name (e.g. `email_match`, `url_find`)
- The generated `regex.js` instantiates it with no imports and accesses exports directly

Input strings are written to memory at address 0; capture group output buffers are placed at offset 1024. Both areas are well within the module's 2-page (128 KB) minimum memory.
