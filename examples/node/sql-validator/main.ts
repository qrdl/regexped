import { readFileSync } from 'node:fs';
import { fileURLToPath } from 'node:url';
import { init, validate_sql, patternName } from './stubs.ts';

const wasmPath = fileURLToPath(new URL('./patterns.wasm', import.meta.url));
await init(readFileSync(wasmPath));

const lines = readFileSync('/dev/stdin', 'utf8').split('\n').filter(l => l.trim());
for (const sql of lines) {
    const m = validate_sql(sql);
    if (m) {
        console.log(`[VALID ${patternName(m.patternId).toUpperCase()}] ${sql}`);
    } else {
        console.log(`[INVALID] ${sql}`);
    }
}
