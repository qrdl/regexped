// Cloudflare Worker: scans POST body text for leaked secrets.
//
// Usage:
//   curl -X POST https://your-worker.workers.dev \
//        -H 'Content-Type: text/plain' \
//        --data-binary @path/to/file.txt
//
// Response: JSON { findings: [{ type, start, end, value }] }

import wasm from './final.wasm';
import { init, find_github_token, find_jwt_token, find_aws_key } from './regex.js';

// Instantiate once at module load time (outside the fetch handler).
// CF Workers reuse the isolate across requests, so this runs only once per isolate.
const ready = init(wasm);

export default {
    async fetch(request) {
        if (request.method === 'GET') {
            return new Response(
                'POST plain text to scan for secrets (GitHub tokens, JWTs, AWS keys).\n',
                { status: 200, headers: { 'Content-Type': 'text/plain' } }
            );
        }
        if (request.method !== 'POST') {
            return new Response('Method Not Allowed', { status: 405 });
        }

        await ready;

        const text = await request.text();
        const findings = [];

        for (const [start, end] of find_github_token(text)) {
            findings.push({ type: 'github-token', start, end, value: text.slice(start, end) });
        }
        for (const [start, end] of find_jwt_token(text)) {
            findings.push({ type: 'jwt', start, end, value: text.slice(start, end) });
        }
        for (const [start, end] of find_aws_key(text)) {
            findings.push({ type: 'aws-key', start, end, value: text.slice(start, end) });
        }

        findings.sort((a, b) => a.start - b.start);

        return Response.json({ findings });
    },
};
