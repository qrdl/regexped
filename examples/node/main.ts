import { readFileSync } from 'node:fs';
import { fileURLToPath } from 'node:url';
import { init, extract_domain } from './regex.ts';

// Load and instantiate the WASM module.
const wasmPath = fileURLToPath(new URL('./urls.wasm', import.meta.url));
await init(readFileSync(wasmPath));

// Read text from stdin as a Buffer (subtype of Uint8Array — no re-encoding needed).
const text = readFileSync('/dev/stdin');

// Print the domain of each URL found, one per line.
for (const match of extract_domain(text)) {
    const [start, end] = match['host'];
    console.log(text.subarray(start, end).toString('utf8'));
}
