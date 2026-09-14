# browser — email and URL validation

A single-page demo that validates an email address and URL as the user types, powered entirely by compiled WASM — no JS regexp engine. Uses **DFA anchored match** for both patterns.

See [docs/browser.md](../../docs/browser.md) for the full guide.

## Prerequisites

The Makefile installs nothing. Install these first:

| Tool | How to install |
|---|---|
| `regexped` | run `make` in the repo root |
| `python3` (`make run` only) | your OS package manager, or [python.org](https://www.python.org/downloads/) |

What each target needs:

| Target | What it does | Needs |
|---|---|---|
| `make` | compiles the patterns and generates `regexp.js` | `regexped` |
| `make run` | builds if needed, then serves this directory on port 8080 until you stop it | `regexped`, `python3` |
| `make clean` | removes the build outputs | — |

## Run

```sh
make run
# Open http://localhost:8080 in a browser
```

## Usage in your own page

```js
import { init, email_match, url_match } from './regexp.js';
await init(await fetch('./regexps.wasm').then(r => r.arrayBuffer()));
```

## Build pipeline

```
regexped compile    →  compile regexp patterns to standalone WASM
regexped generate   →  generate JS ES module stub
```
