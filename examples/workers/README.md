# workers — credential scanner edge API

A Cloudflare Worker that scans the POST body for leaked credentials (GitHub tokens, JWTs, AWS keys) and returns a JSON list of findings. Demonstrates importing a WASM module directly in a Worker module.

See [docs/workers.md](../../docs/workers.md) for the full guide.

## Batched scanning

All three patterns are compiled with `hints: [batch-find]` (see [`hints:`](../../docs/cli.md#hints--likelymode-and-batch-find-compile-hints) in the CLI reference) — a pasted log or diff often contains more than one leaked secret, and the worker rescans the whole POST body for every pattern, so draining several matches per host↔WASM call instead of one adds up. `worker.js` needs no changes for this: the generated `find_github_token`/`find_jwt_token`/`find_aws_key` generators feature-detect the `_batch` WASM export at runtime and prefer it automatically, falling back to the one-call-per-match loop unmodified if it's ever absent.

## Prerequisites

- `regexped` binary (run `make` in the repo root)
- Node.js + [Wrangler](https://developers.cloudflare.com/workers/wrangler/) (`npm install -g wrangler`)

## Run locally

```sh
make dev
```

## Deploy

```sh
make deploy   # requires: wrangler login
```

## Usage

```sh
curl -X POST https://your-worker.workers.dev \
     -H 'Content-Type: text/plain' \
     --data-binary @path/to/file.txt
```

Response:
```json
{"findings":[{"type":"github-token","start":0,"end":40,"value":"ghp_..."}]}
```

## Build pipeline

```
regexped compile    →  compile regexp patterns to WASM
regexped generate   →  generate JS ES module stub
```
