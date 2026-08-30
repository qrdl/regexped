# Using Regexped in Node.js

Node.js supports WASM natively. The workflow is identical to the browser: compile a standalone WASM, generate a TypeScript (or JS) stub, load and use.

## Configuration

```yaml
# regexped.yaml
wasm_file:     "urls.wasm"
import_module: "urls"
stub_file:     "regexp.ts"    # .ts → TypeScript stub; use .js for plain JS

regexps:
  - pattern:           'https?://(?P<host>[a-zA-Z0-9.\-]+\.[a-zA-Z]{2,})(?:/[^\s]*)?'
    groups_func:       "extract_domain"
```

No `output` field → standalone WASM, no merge step needed.

## Build

```bash
regexped compile --config=regexped.yaml   # → urls.wasm
regexped generate --config=regexped.yaml  # → regexp.ts
```

See [`examples/node/domain-extract/Makefile`](../examples/node/domain-extract/Makefile) for a complete Makefile (`examples/node/Makefile` itself just dispatches into each subdirectory's own Makefile).

## Usage

```ts
import { readFileSync } from 'node:fs';
import { fileURLToPath } from 'node:url';
import { init, extract_domain, extract_domain_indices } from './regexp.ts';

const wasmPath = fileURLToPath(new URL('./urls.wasm', import.meta.url));
await init(readFileSync(wasmPath));

const text = readFileSync('/dev/stdin');
for (const match of extract_domain(text)) {
    const host = match[extract_domain_indices.host];
    if (host) console.log(text.subarray(host[0], host[1]).toString('utf8'));
}
```

Node `Buffer` is a subtype of `Uint8Array` — no re-encoding needed when reading files or request bodies.

Run with Node.js 22+ (`--experimental-strip-types`) or `tsx`:

```bash
node --experimental-strip-types main.ts
# or
npx tsx main.ts
```

See [`examples/node/domain-extract/`](../examples/node/domain-extract/) for the complete example above (a single pattern with `groups_func` and a named group).

## Set composition example

[`examples/node/sql-validator/`](../examples/node/sql-validator/) demonstrates the `sets:` composition feature instead — classifying SQL statements by which of four patterns matches, via an anchored `match` set with `emit_name_map: true`:

```yaml
regexps:
  - name: "select"
    pattern: 'SELECT\s+.+\s+FROM\s+\w[\w.]*(\s+.*)?'
  # ... insert, update, delete

sets:
  - name: "sql"
    match: "validate_sql"
    emit_name_map: true
    patterns: ["select", "insert", "update", "delete"]
```

```ts
import { init, validate_sql, patternName } from './stubs.ts';

const m = validate_sql(sql);
if (m) {
    console.log(`${patternName(m.patternId)}: ${sql}`);
}
```

See [sets.md](sets.md) for the full `sets:` schema and output format.
