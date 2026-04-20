# Using Regexped in Cloudflare Workers

Cloudflare Workers support WASM modules as first-class ES module imports. The workflow is the same as browser/Node: compile a standalone WASM, generate a JS stub.

## Configuration

```yaml
# regexped.yaml
wasm_file:     "regexps.wasm"
import_module: "regexps"
stub_file:     "regex.js"

regexes:
  - pattern:   'ghp_[A-Za-z0-9]{36}'
    find_func: "find_github_token"

  - pattern:   'eyJ[A-Za-z0-9+/\-_]+\.[A-Za-z0-9+/\-_]+\.[A-Za-z0-9+/\-_]+'
    find_func: "find_jwt_token"

  - pattern:   'AKIA[A-Z0-9]{16}'
    find_func: "find_aws_key"
```

No `output` field → standalone WASM, no merge step needed.

## Build

```bash
regexped compile --config=regexped.yaml   # → regexps.wasm
regexped generate --config=regexped.yaml  # → regex.js
```

See [`examples/workers/Makefile`](../examples/workers/Makefile) for a complete Makefile including `wrangler dev` and `wrangler deploy` targets.

## Usage

```js
// Import WASM as a module — Workers bundles it automatically.
import wasm from './regexps.wasm';
import { init, find_github_token, find_jwt_token, find_aws_key } from './regex.js';

// Instantiate once at module load time, outside the fetch handler.
// Workers reuse the isolate across requests, so this runs only once per isolate.
const ready = init(wasm);

export default {
    async fetch(request) {
        await ready;

        const text = await request.text();
        const findings = [];

        for (const [start, end] of find_github_token(text)) {
            findings.push({ type: 'github-token', start, end });
        }
        for (const [start, end] of find_jwt_token(text)) {
            findings.push({ type: 'jwt', start, end });
        }
        for (const [start, end] of find_aws_key(text)) {
            findings.push({ type: 'aws-key', start, end });
        }

        return Response.json({ findings });
    },
};
```

Workers import WASM as a module object (not bytes), so `init(wasm)` receives the compiled `WebAssembly.Module` directly — no `fetch` or `readFileSync` needed.

## Deploy

```bash
npx wrangler dev     # local dev server
npx wrangler deploy  # deploy to Cloudflare
```

See [`examples/workers/`](../examples/workers/) for the complete example including `wrangler.toml`.
