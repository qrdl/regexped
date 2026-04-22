# workers — credential scanner edge API

A Cloudflare Worker that scans the POST body for leaked credentials (GitHub tokens, JWTs, AWS keys) and returns a JSON list of findings. Demonstrates importing a WASM module directly in a Worker module.

See [docs/workers.md](../../docs/workers.md) for the full guide.

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
regexped compile    →  compile regex patterns to WASM
regexped generate   →  generate JS ES module stub
```
