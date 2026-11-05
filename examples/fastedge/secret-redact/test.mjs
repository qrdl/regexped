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
const AWS_SECRET = 'wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY';
// Short JWTs: no `typ` and small claims (HS256 with the key "secret"), and an
// unsigned one, the shortest a JWT library accepts.
const SHORT_JWT = 'eyJhbGciOiJIUzI1NiJ9.eyJzdWIiOiIxIn0.M11_c_Mkz5wKz70TPIkcPwzBTd5M-3ZW69WFmxuEnHk';
const UNSIGNED_JWT = 'eyJhbGciOiJub25lIn0.e30.';
const JWT = 'eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9'
  + '.eyJzdWIiOiIxMjM0NTY3ODkwIiwibmFtZSI6IkpvaG4gRG9lIiwiaWF0IjoxNTE2MjM5MDIyfQ'
  + '.SflKxwRJSMeKKF2QT4fwpMeJf36POk6yJV_adQssw5c';

// ASCII text in UTF-32LE, which Node cannot encode.
const utf32le = (s) => Buffer.from([...s].flatMap((c) => [c.charCodeAt(0), 0, 0, 0]));
const xml = `<?xml version="1.0" encoding="UTF-16"?><k>${GITHUB}</k>`;

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
  // ASCII written as ASCII bytes: scanned.
  '/latin1.txt': [200, { 'content-type': 'text/plain; charset="ISO-8859-1"' }, `token ${GITHUB}\n`],
  // ASCII not written as ASCII bytes: refused.
  '/utf16.txt': [200, { 'content-type': 'text/plain; charset=utf-16le' }, Buffer.from(`token ${GITHUB}\n`, 'utf16le')],
  '/bom.txt': [200, { 'content-type': 'text/plain' }, Buffer.concat([Buffer.from([0xFF, 0xFE]), Buffer.from(`token ${GITHUB}\n`, 'utf16le')])],
  // UTF-16 and UTF-32 with no byte-order mark and no charset: refused.
  '/utf16le.xml': [200, { 'content-type': 'application/xml' }, Buffer.from(xml, 'utf16le')],
  '/utf16be.xml': [200, { 'content-type': 'application/xml' }, Buffer.from(xml, 'utf16le').swap16()],
  '/utf32.json': [200, { 'content-type': 'application/json' }, utf32le(JSON.stringify({ token: GITHUB }))],
  // No type: scanned as text.
  '/untyped': [200, {}, `token ${GITHUB}\n`],
  // A key written straight after another of its kind: the first match takes
  // the second key's `sk`, and the rest of the second key is not found.
  '/chain.txt': [200, { 'content-type': 'text/plain' }, `sk_live_${'A'.repeat(24)}sk_live_${'B'.repeat(24)}\n`],
  // An AWS secret key with its `/` escaped, by a form and by a JSON writer.
  '/form': [200, { 'content-type': 'application/x-www-form-urlencoded' },
    `aws_secret_access_key=${encodeURIComponent(AWS_SECRET)}`],
  '/escaped.json': [200, { 'content-type': 'application/json' },
    `{"env":"aws_secret_access_key = ${AWS_SECRET.replaceAll('/', '\\/')}"}`],
  '/short-jwt.txt': [200, { 'content-type': 'text/plain' }, `token ${SHORT_JWT} or ${UNSIGNED_JWT} end\n`],
  // Validators and digests of the origin's bytes.
  '/tagged.txt': [200, {
    'content-type': 'text/plain', etag: '"v1"', 'content-digest': 'sha-256=:AAAA:', digest: 'SHA-256=AAAA',
  }, `token ${GITHUB}\n`],
  '/tagged-clean.txt': [200, { 'content-type': 'text/plain', etag: '"v1"', 'content-digest': 'sha-256=:AAAA:' },
    'nothing to hide\n'],
  // Statuses with no body, typed as text.
  '/no-content': [204, { 'content-type': 'text/plain' }, ''],
  '/not-modified': [304, { 'content-type': 'text/plain' }, ''],
};

// The origin answers a `Range: bytes=a-b` request with that part alone, as a
// real one does, so a range the app forwarded would come back as 206.
const origin = createServer((req, res) => {
  const chunks = [];
  req.on('data', (c) => chunks.push(c));
  req.on('end', () => {
    if (req.url === '/echo') {
      res.writeHead(200, { 'content-type': 'text/plain' });
      res.end(Buffer.concat(chunks));
      return;
    }
    // The connection drops in the middle of the body.
    if (req.url === '/truncated') {
      res.writeHead(200, { 'content-type': 'text/plain', 'content-length': '100000' });
      res.write(`token ${GITHUB.slice(0, 10)}`);
      setTimeout(() => res.socket.destroy(), 50);
      return;
    }
    const [status, headers, body] = pages[req.url] ?? [404, { 'content-type': 'text/plain' }, `not found: ${req.url}\n`];
    const range = /^bytes=(\d+)-(\d+)$/.exec(req.headers.range ?? '');
    if (range && status === 200) {
      const [from, to] = [Number(range[1]), Number(range[2])];
      res.writeHead(206, { ...headers, 'content-range': `bytes ${from}-${to}/${Buffer.byteLength(body)}` });
      res.end(Buffer.from(body).subarray(from, to + 1));
      return;
    }
    res.writeHead(status, headers);
    res.end(req.method === 'HEAD' ? undefined : body);
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
  // Bytes 0-19 end inside the AWS key: forwarded, the range would come back
  // as "deploy with key=AKIA", which no pattern matches.
  ['scans the whole body when a range is asked for', async (runner) => {
    const r = await fetchPath(runner, '/notes.txt', { headers: { range: 'bytes=0-19' } });
    assertHttpStatus(r, 200);
    expectBody(r, 'deploy with key=[REDACTED aws_key] and token [REDACTED github_pat]\n');
  }],
  ['keeps a path that looks like a host on the origin', async (runner) => {
    const r = await fetchPath(runner, '//elsewhere.example/notes.txt');
    assertHttpStatus(r, 404);
    expectBody(r, 'not found: //elsewhere.example/notes.txt\n');
  }],
  ['scans a charset that writes ASCII as ASCII', async (runner) => {
    const r = await fetchPath(runner, '/latin1.txt');
    assertHttpHeader(r, 'x-redacted', '1');
    expectBody(r, 'token [REDACTED github_pat]\n');
  }],
  ['refuses a UTF-16 response', async (runner) => {
    assertHttpStatus(await fetchPath(runner, '/utf16.txt'), 502);
  }],
  ['refuses a response starting with a UTF-16 byte-order mark', async (runner) => {
    assertHttpStatus(await fetchPath(runner, '/bom.txt'), 502);
  }],
  ['refuses UTF-16LE XML with no byte-order mark', async (runner) => {
    assertHttpStatus(await fetchPath(runner, '/utf16le.xml'), 502);
  }],
  ['refuses UTF-16BE XML with no byte-order mark', async (runner) => {
    assertHttpStatus(await fetchPath(runner, '/utf16be.xml'), 502);
  }],
  ['refuses UTF-32 JSON', async (runner) => {
    assertHttpStatus(await fetchPath(runner, '/utf32.json'), 502);
  }],
  ['scans a response with no type', async (runner) => {
    const r = await fetchPath(runner, '/untyped');
    assertHttpHeader(r, 'x-redacted', '1');
    expectBody(r, 'token [REDACTED github_pat]\n');
  }],
  // A known limit: the second key's tail goes out unmasked.
  ['masks only the first of two keys written back to back', async (runner) => {
    const r = await fetchPath(runner, '/chain.txt');
    assertHttpHeader(r, 'x-redacted', '1');
    expectBody(r, `[REDACTED stripe_live]_live_${'B'.repeat(24)}\n`);
  }],
  ['masks short JWTs', async (runner) => {
    const r = await fetchPath(runner, '/short-jwt.txt');
    assertHttpHeader(r, 'x-redacted', '2');
    expectBody(r, 'token [REDACTED jwt] or [REDACTED jwt] end\n');
  }],
  ['refuses a response whose body cannot be read', async (runner) => {
    assertHttpStatus(await fetchPath(runner, '/truncated'), 502);
  }],
  ['drops digests and weakens the ETag of a masked response', async (runner) => {
    const r = await fetchPath(runner, '/tagged.txt');
    assertHttpHeader(r, 'x-redacted', '1');
    assertHttpHeader(r, 'etag', 'W/"v1"');
    assertHttpNoHeader(r, 'content-digest');
    assertHttpNoHeader(r, 'digest');
  }],
  ['keeps the ETag and digests of an unchanged response', async (runner) => {
    const r = await fetchPath(runner, '/tagged-clean.txt');
    assertHttpHeader(r, 'x-redacted', '0');
    assertHttpHeader(r, 'etag', '"v1"');
    assertHttpHeader(r, 'content-digest', 'sha-256=:AAAA:');
  }],
  ['masks an AWS secret key in a form body', async (runner) => {
    const r = await fetchPath(runner, '/form');
    assertHttpHeader(r, 'x-redacted', '1');
    expectBody(r, '[REDACTED aws_secret]');
  }],
  ['masks an AWS secret key escaped by a JSON writer', async (runner) => {
    const r = await fetchPath(runner, '/escaped.json');
    assertHttpHeader(r, 'x-redacted', '1');
    expectBody(r, '{"env":"[REDACTED aws_secret]"}');
  }],
  ['passes a 204 through', async (runner) => {
    const r = await fetchPath(runner, '/no-content');
    assertHttpStatus(r, 204);
    assertHttpNoHeader(r, 'x-redacted');
  }],
  ['passes a 304 through', async (runner) => {
    const r = await fetchPath(runner, '/not-modified');
    assertHttpStatus(r, 304);
    assertHttpNoHeader(r, 'x-redacted');
  }],
  ['passes a HEAD response through', async (runner) => {
    const r = await fetchPath(runner, '/notes.txt', { method: 'HEAD' });
    assertHttpStatus(r, 200);
    assertHttpNoHeader(r, 'x-redacted');
    expectBody(r, '');
  }],
];

// runAndExit ends the process, which also stops the origin.
await runAndExit(defineTestSuite({
  wasmPath: './secret-redact.wasm',
  runnerConfig: { dotenv: { enabled: true, path: dotenv } },
  tests: tests.map(([name, run]) => ({ name, run })),
}));
