// A FastEdge HTTP app that proxies an origin and masks the secrets in its text
// responses: AWS, GitHub, Slack, Stripe and Google keys, and JWTs.
//
// The ten patterns are ONE regexped set (regexped.yaml), compiled to a
// component and imported like a JS module. The response body crosses into the
// component once, when the scanner is constructed; each `next()` then returns
// the matches at the next position, so the whole body is scanned once for all
// ten patterns.

import { getEnv } from 'fastedge::env';
import { FindSecrets } from 'regexped:secrets/sets';

// A match's id is its pattern's index in regexped.yaml.
const NAMES = [
  'aws_key', 'aws_secret', 'github_pat', 'github_oauth', 'github_app',
  'jwt', 'slack_token', 'stripe_live', 'stripe_test', 'google_api',
];

// Responses scanned; any other content type passes through unchanged.
const TEXT = /^\s*(?:text\/|application\/(?:json|javascript|xml|x-www-form-urlencoded)\b|[^;]*\+(?:json|xml)\b)/i;

const encoder = new TextEncoder();

// The secrets in `body` as [start, end, name] byte ranges, in order and not
// overlapping. The set reports each pattern's matches; two patterns can match
// overlapping text (an AWS key inside an `aws_secret_access_key = …` line), so
// overlapping matches are joined and keep the first one's name.
function secretRanges(body) {
  const ranges = [];
  const scanner = new FindSecrets(body, 0);
  try {
    for (let matches = scanner.next(); matches.length > 0; matches = scanner.next()) {
      for (const { id, start, end } of matches) {
        const last = ranges[ranges.length - 1];
        if (last && start < last[1]) last[1] = Math.max(last[1], end);
        else ranges.push([start, end, NAMES[id]]);
      }
    }
  } finally {
    // Frees the scanner's copy of the body. A scan run to its end has already
    // freed it, but a scan that stops early (an error here) has not, and this
    // runtime never runs the finalizer that would free it later.
    scanner[Symbol.dispose]();
  }
  return ranges;
}

// `body` with every range replaced by `[REDACTED <name>]`.
function redact(body, ranges) {
  const labels = ranges.map(([, , name]) => encoder.encode(`[REDACTED ${name}]`));
  let size = body.length;
  ranges.forEach(([start, end], i) => { size += labels[i].length - (end - start); });
  const out = new Uint8Array(size);
  let from = 0;
  let at = 0;
  ranges.forEach(([start, end], i) => {
    out.set(body.subarray(from, start), at);
    at += start - from;
    out.set(labels[i], at);
    at += labels[i].length;
    from = end;
  });
  out.set(body.subarray(from), at);
  return out;
}

async function handler(event) {
  const origin = getEnv('ORIGIN');
  if (!origin) return new Response('ORIGIN is not set\n', { status: 500 });

  const request = event.request;
  const url = new URL(request.url);
  const headers = new Headers(request.headers);
  headers.delete('host');
  // A compressed body cannot be scanned: ask the origin not to compress.
  headers.set('accept-encoding', 'identity');
  let upstream;
  try {
    upstream = await fetch(new URL(url.pathname + url.search, origin), {
      method: request.method,
      headers,
      body: request.method === 'GET' || request.method === 'HEAD' ? undefined : await request.arrayBuffer(),
    });
  } catch (err) {
    console.error(`cannot reach the origin: ${err}`);
    return new Response('cannot reach the origin\n', { status: 502 });
  }

  if (!TEXT.test(upstream.headers.get('content-type') ?? '')) return upstream;

  // Fail closed: a text response that cannot be scanned is not passed on.
  const encoding = upstream.headers.get('content-encoding');
  if (encoding && encoding.toLowerCase() !== 'identity') {
    return new Response(`cannot scan a ${encoding} response\n`, { status: 502 });
  }
  const body = new Uint8Array(await upstream.arrayBuffer());
  let ranges;
  try {
    ranges = secretRanges(body);
  } catch (err) {
    console.error(`cannot scan the response: ${err}`);
    return new Response('cannot scan the response\n', { status: 502 });
  }

  const out = new Headers(upstream.headers);
  out.delete('content-length');
  out.set('x-redacted', String(ranges.length));
  return new Response(ranges.length > 0 ? redact(body, ranges) : body, {
    status: upstream.status,
    statusText: upstream.statusText,
    headers: out,
  });
}

addEventListener('fetch', (event) => event.respondWith(handler(event)));
