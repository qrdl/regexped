# browser — email and URL validation

A single-page demo that validates an email address and URL as the user types, powered entirely by compiled WASM — no JS regex engine. Uses **DFA anchored match** for both patterns.

See [docs/browser.md](../../docs/browser.md) for the full guide.

## Prerequisites

- `regexped` binary (run `make` in the repo root)
- Node.js 18+ (for the local HTTP server)

## Run

```sh
make run
# Open http://localhost:8080 in a browser
```

## Usage in your own page

```js
import { init, email_match, url_match } from './regex.js';
await init(await fetch('./regexps.wasm').then(r => r.arrayBuffer()));
```

## Build pipeline

```
regexped compile    →  compile regex patterns to standalone WASM
regexped generate   →  generate JS ES module stub
```
