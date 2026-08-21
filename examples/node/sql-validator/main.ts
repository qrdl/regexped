import { readFileSync } from 'node:fs';
import { fileURLToPath } from 'node:url';
import { init, validate_sql, patternName } from './stubs.ts';

const wasmPath = fileURLToPath(new URL('./patterns.wasm', import.meta.url));
await init(readFileSync(wasmPath));

const lines = readFileSync('/dev/stdin', 'utf8').split('\n').filter(l => l.trim());
for (const sql of lines) {
    // match_any is anchored: the statement must match a pattern end to end.
    // It returns a pattern id or null — NOT a boolean.
    const id = validate_sql(sql);
    if (id !== null) {
        console.log(`[VALID ${patternName(id).toUpperCase()}] ${sql}`);
    } else {
        console.log(`[INVALID] ${sql}`);
    }
}
