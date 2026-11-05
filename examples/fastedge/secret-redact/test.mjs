// Runs secret-redact.wasm under the FastEdge runtime (fastedge-run, through
// @gcoredev/fastedge-test) in front of a local origin, and checks what each
// origin response becomes.
//
//   npm install && npm test        (or `make test`, after `make`)
//   node test.mjs --print          (or `make run`: also prints each response)

import { createServer } from 'node:http';
import { mkdtempSync, rmSync, writeFileSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { gzipSync } from 'node:zlib';
import {
  defineTestSuite, runAndExit, runHttpRequest,
  assertHttpStatus, assertHttpHeader, assertHttpNoHeader,
} from '@gcoredev/fastedge-test/test';

const PRINT = process.argv.includes('--print');

// Sample secrets: documented examples or obviously fake values.
const AWS_KEY = 'AKIAIOSFODNN7EXAMPLE';
const GITHUB = 'ghp_abc123456789012345678901234567890xyz';
const STRIPE = 'sk_live_AbCdEfGhIjKlMnOpQrStUvWx';
const JWT = 'eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9'
  + '.eyJzdWIiOiIxMjM0NTY3ODkwIiwibmFtZSI6IkpvaG4gRG9lIiwiaWF0IjoxNTE2MjM5MDIyfQ'
  + '.SflKxwRJSMeKKF2QT4fwpMeJf36POk6yJV_adQssw5c';

const large = Array.from({ length: 16 }, (_, i) => `${'lorem ipsum '.repeat(5461)}token ${GITHUB} #${i}\n`).join('');

// The origin: path → [status, headers, body].
const pages = {
  '/notes.txt': [200, { 'content-type': 'text/plain' },
    `deploy with key=${AWS_KEY} and token ${GITHUB}\n`],
  '/config.json': [200, { 'content-type': 'application/json' },
    JSON.stringify({ stripe: STRIPE, session: JWT, region: 'eu' })],
  // An AWS key inside an aws_secret_access_key line: two patterns match, one mask.
  '/overlap.txt': [200, { 'content-type': 'text/plain' },
    `aws_secret_access_key = ${AWS_KEY}wJalrXUtnFEMI/K7MDEN\n`],
  '/clean.html': [200, { 'content-type': 'text/html; charset=utf-8' }, '<p>nothing to hide</p>\n'],
  '/missing': [404, { 'content-type': 'text/plain' }, `no such page; ask ${GITHUB}\n`],
  '/logo.png': [200, { 'content-type': 'image/png' }, Buffer.from(`\x89PNG ${GITHUB}`, 'latin1')],
  // Compressed although asked not to be: it cannot be scanned, so it is refused.
  '/compressed.txt': [200, { 'content-type': 'text/plain', 'content-encoding': 'gzip' },
    gzipSync(`token ${GITHUB}\n`)],
  '/large.txt': [200, { 'content-type': 'text/plain' }, large],
};

const origin = createServer((req, res) => {
  const chunks = [];
  req.on('data', (c) => chunks.push(c));
  req.on('end', () => {
    if (req.url === '/echo') {
      res.writeHead(200, { 'content-type': 'text/plain' });
      res.end(Buffer.concat(chunks));
      return;
    }
    const [status, headers, body] = pages[req.url] ?? [404, { 'content-type': 'text/plain' }, 'not found\n'];
    res.writeHead(status, headers);
    res.end(body);
  });
});
await new Promise((resolve) => origin.listen(0, '127.0.0.1', resolve));

// The app reads its origin from the ORIGIN environment variable.
const dotenv = mkdtempSync(join(tmpdir(), 'secret-redact-'));
writeFileSync(join(dotenv, '.env.variables'), `ORIGIN=http://127.0.0.1:${origin.address().port}\n`);
process.on('exit', () => rmSync(dotenv, { recursive: true, force: true }));

const fetchPath = async (runner, path, options = {}) => {
  const response = await runHttpRequest(runner, { path, ...options });
  if (PRINT) {
    const body = response.isBase64 ? `(${Buffer.from(response.body, 'base64').length} bytes)`
      : response.body.length > 200 ? `${response.body.slice(0, 200)}… (${response.body.length} bytes)`
        : response.body;
    console.log(`${options.method ?? 'GET'} ${path} → ${response.status}, x-redacted: ${response.headers['x-redacted'] ?? '-'}\n  ${body.trimEnd()}`);
  }
  return response;
};

const expectBody = (response, expected) => {
  if (response.body !== expected) {
    throw new Error(`expected body ${JSON.stringify(expected)}, got ${JSON.stringify(response.body)}`);
  }
};

const tests = [
  ['masks an AWS key and a GitHub token', async (runner) => {
    const r = await fetchPath(runner, '/notes.txt');
    assertHttpStatus(r, 200);
    assertHttpHeader(r, 'x-redacted', '2');
    expectBody(r, 'deploy with key=[REDACTED aws_key] and token [REDACTED github_pat]\n');
  }],
  ['masks a Stripe key and a JWT in JSON', async (runner) => {
    const r = await fetchPath(runner, '/config.json');
    assertHttpHeader(r, 'x-redacted', '2');
    expectBody(r, JSON.stringify({ stripe: '[REDACTED stripe_live]', session: '[REDACTED jwt]', region: 'eu' }));
  }],
  ['masks overlapping matches once', async (runner) => {
    const r = await fetchPath(runner, '/overlap.txt');
    assertHttpHeader(r, 'x-redacted', '1');
    expectBody(r, '[REDACTED aws_secret]\n');
  }],
  ['leaves a clean page unchanged', async (runner) => {
    const r = await fetchPath(runner, '/clean.html');
    assertHttpHeader(r, 'x-redacted', '0');
    expectBody(r, '<p>nothing to hide</p>\n');
  }],
  ['keeps the origin status', async (runner) => {
    const r = await fetchPath(runner, '/missing');
    assertHttpStatus(r, 404);
    expectBody(r, 'no such page; ask [REDACTED github_pat]\n');
  }],
  ['passes a non-text response through unchanged', async (runner) => {
    const r = await fetchPath(runner, '/logo.png');
    assertHttpStatus(r, 200);
    assertHttpNoHeader(r, 'x-redacted');
    const body = r.isBase64 ? Buffer.from(r.body, 'base64') : Buffer.from(r.body, 'latin1');
    if (!body.equals(pages['/logo.png'][2])) throw new Error('the image was changed');
  }],
  ['refuses a compressed text response', async (runner) => {
    assertHttpStatus(await fetchPath(runner, '/compressed.txt'), 502);
  }],
  ['masks every secret in 1 MB', async (runner) => {
    const r = await fetchPath(runner, '/large.txt');
    assertHttpHeader(r, 'x-redacted', '16');
    expectBody(r, large.replaceAll(GITHUB, '[REDACTED github_pat]'));
  }],
  ['forwards the request body', async (runner) => {
    const r = await fetchPath(runner, '/echo', { method: 'POST', body: `echo ${STRIPE}` });
    expectBody(r, 'echo [REDACTED stripe_live]');
  }],
];

// runAndExit ends the process, which also stops the origin.
await runAndExit(defineTestSuite({
  wasmPath: './secret-redact.wasm',
  runnerConfig: { dotenv: { enabled: true, path: dotenv } },
  tests: tests.map(([name, run]) => ({ name, run })),
}));
