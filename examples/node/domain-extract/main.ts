import { readFileSync } from 'node:fs';
import { fileURLToPath } from 'node:url';
import { init, extract_domain, extract_domain_indices } from './regexp.ts';

// Load and instantiate the WASM module.
const wasmPath = fileURLToPath(new URL('./urls.wasm', import.meta.url));
await init(readFileSync(wasmPath));

// Read text from stdin as a Buffer (subtype of Uint8Array — no re-encoding needed).
const text = readFileSync('/dev/stdin');

// Print the domain of each URL found, one per line.
//
// Named groups are an index object now, not a per-match map: one capability,
// one WASM export, and the whole match stays reachable at index 0.
for (const match of extract_domain(text)) {
    const host = match[extract_domain_indices.host];
    if (host) console.log(text.subarray(host[0], host[1]).toString('utf8'));
}
