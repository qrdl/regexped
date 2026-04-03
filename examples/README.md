# Regexped WASM Examples

Self-contained examples showing how to compile regex patterns to WASM and call them from Rust, Node.js, a browser, or a Cloudflare Worker.

## Prerequisites

- **regexped** binary: run `make` in the repo root
- **wasm-merge** from [Binaryen](https://github.com/WebAssembly/binaryen)

Each example's `regexped.yaml` references wasm-merge via a path relative to the config file (`../../../binaryen/bin/wasm-merge`). Adjust if your Binaryen install is elsewhere.

**For Rust examples only:**
- **Rust** with the WASI target: `rustup target add wasm32-wasip1`
- **wasmtime**: https://wasmtime.dev

**For JS examples (node, browser, cf-worker):**
- **Node.js** 18+

## Build pipeline

### Rust examples

```
regexped generate --rust  →  generate Rust FFI stubs from regexped.yaml
cargo build               →  compile Rust + stubs to WASM (wasm32-wasip1)
regexped compile          →  compile regex pattern(s) to WASM
regexped merge            →  merge Rust WASM + regex WASM(s) into final binary
wasmtime run              →  execute with test inputs
```

### JS examples

```
regexped generate --dummy_main  →  generate minimal main WASM (memory layout)
regexped compile                →  compile regex pattern(s) to WASM
regexped merge                  →  merge main WASM + regex WASM(s) into final binary
regexped generate --js          →  generate JS ES module stub
```

Run `make` in any example directory to execute all steps end-to-end.

---

## url-ipv6 — find IPv6-addressed URLs  *(Rust)*

Scans arbitrary text for HTTP/HTTPS URLs whose host is an IPv6 address in bracket notation (`[2001:db8::1]`). Uses **DFA find mode** (non-anchored scan).

```sh
cd url-ipv6 && make
```

Expected output:
```
=== IPv6 URL, no port ===
Found IPv6 URL at bytes 11..36: https://[2001:db8::1]/api
```

---

## secrets — detect leaked credentials  *(Rust)*

Searches text for three types of secrets using three independent DFA find-mode patterns compiled to separate WASM modules and merged together:

| Pattern         | Example match                          |
|-----------------|----------------------------------------|
| GitHub PAT      | `ghp_` + 36 alphanumeric chars         |
| JWT             | `eyJ...eyJ...` (three base64url parts) |
| AWS access key  | `AKIA` + 16 uppercase alphanumeric     |

```sh
cd secrets && make
```

Expected output:
```
=== AWS access key ===
GitHub token: not found
JWT:          not found
AWS key:      found at 26..46: AKIAIOSFODNN7EXAMPLE
```

---

## url-parts — parse a URL into components  *(Rust)*

Parses a URL into named capture groups using the **TDFA engine** — a tagged DFA with inline capture slot tracking, faster than backtracking for deterministic patterns.

Groups returned: `scheme`, `host`, `port`, `path`, `query`, `fragment`.

```sh
cd url-parts && make
```

Expected output:
```
=== full URL ===
scheme     = https
host       = example.com
port       = 8080
path       = /path/to/page
query      = q=1&r=2
fragment   = section
```

The pattern is anchored — pass the URL itself as the argument, not surrounding text.

---

## node — extract domains from URLs  *(Node.js)*

Reads text from stdin and prints the domain of every URL found, one per line. Uses **named capture groups** with the backtracking engine to extract just the `host` group.

```sh
cd node && make build
echo "See https://example.com and http://foo.org/path" | node main.mjs
```

Expected output:
```
example.com
foo.org
```

---

## browser — email and URL validation  *(Browser)*

A single-page demo that validates an email address and URL as the user types, powered entirely by compiled WASM — no JS regex engine. Uses **DFA anchored match** for both patterns.

```sh
cd browser && make run
# Open http://localhost:8080 in a browser
```

The JS stub (`regex.js`) is generated with `regexped generate --js`. Load it in your own page with:
```js
import { init, email_match, url_match } from './regex.js';
await init(await fetch('./final.wasm').then(r => r.arrayBuffer()));
```

---

## cf-worker — secret scanner edge API  *(Cloudflare Worker)*

An edge API that scans the POST body for leaked secrets (GitHub tokens, JWTs, AWS keys) and returns a JSON list of findings. Demonstrates importing a WASM module at the top of a Worker module.

```sh
cd cf-worker && make build
# Deploy: make deploy  (requires: wrangler login)
# Local:  make dev     (requires: npx wrangler)
```

Example call once deployed:
```sh
curl -X POST https://your-worker.workers.dev \
     -H 'Content-Type: text/plain' \
     --data-binary @path/to/file.txt
```

Response:
```json
{"findings":[{"type":"github-token","start":0,"end":40,"value":"ghp_..."}]}
```

