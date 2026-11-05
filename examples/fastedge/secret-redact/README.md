# fastedge/secret-redact — mask secrets in origin responses

A FastEdge HTTP application in **JavaScript** that proxies an origin and masks
the secrets in its text responses — AWS, GitHub, Slack, Stripe and Google keys,
and JWTs — before they leave the edge:

```
origin:  deploy with key=AKIAIOSFODNN7EXAMPLE and token ghp_abc123456789012345678901234567890xyz
client:  deploy with key=[REDACTED aws_key] and token [REDACTED github_pat]
         x-redacted: 2
```

The ten patterns are one regexped **set** compiled to a **component**
(`wasm_format: component`), and the app imports it like a JS module through the
FastEdge JS SDK (`@gcoredev/fastedge-sdk-js` 2.7.0 or later):

```js
import { FindSecrets } from 'regexped:secrets/sets';
```

## Why a regexped set rather than `RegExp`

JavaScript's `RegExp` matches one pattern per pass, so ten patterns means ten
passes over the body, then sorting and joining their matches. A set is one
pass for all ten: the body crosses into the component once, when the scanner
is constructed, and each `next()` returns the matches at the next position, in
order. The scan's run time is linear in the body's length for every pattern
and every input; JavaScript's `RegExp` engine backtracks.

## What it answers

The origin is the URL in the `ORIGIN` environment variable; every request is
forwarded to it, method, headers and body, with its path and query. The path
is set on the origin's URL rather than resolved against it, so a path such as
`//elsewhere.example/` stays on the origin. `Range` and `If-Range` are not
forwarded: a secret split across two ranges would match in neither, so the
app always asks for, scans and answers the whole body.

| Origin response | Answer |
|---|---|
| A text type — `text/*`, `application/json`, `application/javascript`, `application/xml`, `application/x-www-form-urlencoded`, `*+json`, `*+xml` — or no type at all | the same status and headers, every secret replaced by `[REDACTED <pattern>]`, and `x-redacted: <count>` |
| Any other type | passed through unchanged |
| A response with no body — to a `HEAD` request, or a `101`, `103`, `204`, `205` or `304` | passed through unchanged |
| A text type that is compressed (`content-encoding` other than `identity`) | `502`: it cannot be scanned, so it is not passed on. The app asks for `accept-encoding: identity`, so an origin that honours it never sends one |
| A text type in a charset that does not write ASCII as ASCII bytes — anything but none given, UTF-8, US-ASCII, ISO-8859-*, Latin-1 and windows-125* — or a body starting with a UTF-16 byte-order mark, or a body containing a 0x00 byte (UTF-16 or UTF-32 that declares neither, which XML and JSON may) | `502`: the patterns are ASCII, so they would miss every secret in it |
| A scan that fails | `502` — fail closed |
| No answer from the origin | `502` |

The set reports every match at every start position (`overlapping: true`), so
matches can overlap: two patterns over the same text — an AWS key inside an
`aws_secret_access_key = …` line — or a token running straight into the next
(`sk_live_…sk_live_…`, where the first match takes the second token's `sk`).
Overlapping matches are masked once, named after the first.

The AWS secret key is also found with its `/`, `+` and `=` escaped the way a
form body writes them (`%2F`, `%2B`, `%3D`) and its `/` the way some JSON
writers do (`\/`). Nothing else is decoded: a secret written with other escapes
(`\u002F` in JSON, `&#x2F;` in HTML) is not found.

## Prerequisites

The Makefile installs nothing. Install these first:

| Tool | How to install |
|---|---|
| `regexped` | run `make` in the repo root |
| `wasm-tools` | a [release](https://github.com/bytecodealliance/wasm-tools/releases) on `PATH`, or `cargo install --locked wasm-tools` |
| Node.js 22.12 or later, with npm | [nodejs.org](https://nodejs.org); then run `npm install` here once, which installs the SDK (`fastedge-build`) and the FastEdge test runner `@gcoredev/fastedge-test` |

What each target needs:

| Target | What it does | Needs |
|---|---|---|
| `make` | builds `secret-redact.wasm` — the steps below | everything above |
| `make compile` | compiles the patterns to the component `secrets.wasm` and its `secrets.wit` | `regexped`, `wasm-tools` |
| `make build` | `fastedge-build`: bundles `src/index.js`, generates the bindings to the component and composes the two into `secret-redact.wasm` — the same as `make` | everything above |
| `make run` | runs `secret-redact.wasm` under the FastEdge runtime itself (`fastedge-run`, through `@gcoredev/fastedge-test`) in front of a local origin, prints each response and checks it — [`test.mjs`](test.mjs) | everything above |
| `make test` | the same checks, without printing | everything above |
| `make clean` | removes the build outputs | — |

## How it works

1. [`regexped.yaml`](regexped.yaml) declares the ten patterns and one set,
   `secrets`, with the `find` capability and `overlapping: true`: every match
   at every start position, with its pattern's id and its position.
2. `fastedge-build --component regexped:secrets/sets=secrets.wasm` reads the
   interface from the component, generates the JavaScript bindings and
   composes the component into the output. It also writes
   `src/fastedge-components.d.ts`, the interface's TypeScript declarations:

   ```ts
   export class FindSecrets implements Disposable {
     constructor(input: Uint8Array, start: number)
     next(): Array<SetMatch>;          // { id, start, end }; empty when finished
     [Symbol.dispose](): void;
   }
   ```

3. [`src/index.js`](src/index.js) fetches the origin, scans a text body once,
   joins overlapping matches and writes the masked body.

The scanner is disposed in a `finally`. A scan run to its end has already
released the component's copy of the body; one that stops early has not, and
the FastEdge runtime never runs the finalizer that would release it later, so
every abandoned scanner would hold its body until the request ends.
`scanner[Symbol.dispose]()` rather than a `using` declaration, because
`fastedge-build` checks the syntax with the Node it runs on, and Node 22
rejects `using`.

The app passes the body to the component once per response. That matters with
SDK 2.7.0: every component call that passes data leaves its copy of that data
allocated until the request ends, so calling a component once per line or per
word of a large body can exhaust the request's memory.

## Deploying

`secret-redact.wasm` is a complete FastEdge HTTP application: upload it as a
binary, create an application from it and set its `ORIGIN` environment
variable. See [docs/fastedge.md](../../../docs/fastedge.md) and the FastEdge
documentation.
