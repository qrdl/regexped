# Using Regexped in Node.js

Node.js supports WASM natively. The workflow is identical to the browser: compile a standalone WASM, generate a TypeScript (or JS) stub, load and use.

## Configuration

```yaml
# regexped.yaml
wasm_file:     "urls.wasm"
import_module: "urls"
stub_file:     "regex.ts"    # .ts → TypeScript stub; use .js for plain JS

regexps:
  - pattern:           'https?://(?P<host>[a-zA-Z0-9.\-]+\.[a-zA-Z]{2,})(?:/[^\s]*)?'
    named_groups_func: "extract_domain"
```

No `output` field → standalone WASM, no merge step needed.

## Build

```bash
regexped compile --config=regexped.yaml   # → urls.wasm
regexped generate --config=regexped.yaml  # → regex.ts
```

See [`examples/node/Makefile`](../examples/node/Makefile) for a complete Makefile.

## Usage

```ts
import { readFileSync } from 'node:fs';
import { fileURLToPath } from 'node:url';
import { init, extract_domain } from './regex.ts';

const wasmPath = fileURLToPath(new URL('./urls.wasm', import.meta.url));
await init(readFileSync(wasmPath));

const text = readFileSync('/dev/stdin');
for (const match of extract_domain(text)) {
    const [start, end] = match['host'];
    console.log(text.subarray(start, end).toString('utf8'));
}
```

Node `Buffer` is a subtype of `Uint8Array` — no re-encoding needed when reading files or request bodies.

Run with Node.js 22+ (`--experimental-strip-types`) or `tsx`:

```bash
node --experimental-strip-types main.ts
# or
npx tsx main.ts
```

See [`examples/node/`](../examples/node/) for the complete example.
