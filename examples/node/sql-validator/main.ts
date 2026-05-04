import { readFileSync } from 'node:fs';
import { fileURLToPath } from 'node:url';
import { init, classify_statement, patternName } from './stubs.ts';

const wasmPath = fileURLToPath(new URL('./patterns.wasm', import.meta.url));
await init(readFileSync(wasmPath));

// Allow-list: only SELECT is permitted in this read-only context.
const ALLOWED = new Set(['select']);

const lines = readFileSync('/dev/stdin', 'utf8').split('\n').filter(l => l.trim());
for (const sql of lines) {
    const m = classify_statement(sql);
    if (!m) {
        console.log(`[UNKNOWN] ${sql}`);
        continue;
    }
    const type = patternName(m.patternId);
    const status = ALLOWED.has(type) ? 'ALLOWED' : 'BLOCKED';
    console.log(`[${type.toUpperCase()} / ${status}] ${sql}`);
}
