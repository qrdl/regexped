# workers — credential scanner edge API

A Cloudflare Worker that scans the POST body for leaked credentials (GitHub tokens, JWTs, AWS keys) and returns a JSON list of findings. Demonstrates importing a WASM module directly in a Worker module.

See [docs/workers.md](../../docs/workers.md) for the full guide.

## Batched scanning

All three patterns are compiled with `hints: [batch-find]` (see [`hints:`](../../docs/cli.md#hints--likelymode-and-batch-find-compile-hints) in the CLI reference) — a pasted log or diff often contains more than one leaked secret, and the worker rescans the whole POST body for every pattern, so draining several matches per host↔WASM call instead of one adds up. `worker.js` needs no changes for this: the generated `find_github_token`/`find_jwt_token`/`find_aws_key` generators feature-detect the `_batch` WASM export at runtime and prefer it automatically, falling back to the one-call-per-match loop unmodified if it's ever absent.

## Prerequisites

The Makefile installs nothing. Install these first:

| Tool | How to install |
|---|---|
| `regexped` | run `make` in the repo root |
| [Node.js](https://nodejs.org) 22+ with `npm` | from nodejs.org or a version manager such as [nvm](https://github.com/nvm-sh/nvm) — Wrangler 4 refuses to start on older Node |
| [Wrangler](https://developers.cloudflare.com/workers/wrangler/) | `npm install -g wrangler`; for `make deploy`, also `wrangler login` |

What each target needs:

| Target | What it does | Needs |
|---|---|---|
| `make` | compiles the patterns and generates `regexp.js` | `regexped` |
| `make run` | nothing: a Worker does not run as a local program, so it only points at `make dev` and `make deploy` | — |
| `make dev` | builds if needed, then runs the Worker locally with `wrangler dev` | `regexped`, Wrangler |
| `make deploy` | builds if needed, then publishes it with `wrangler deploy` | `regexped`, Wrangler, logged in |
| `make clean` | removes the build outputs | — |

`make dev` and `make deploy` stop with a message if `wrangler` is not on `PATH`;
set `WRANGLER=/path/to/wrangler` to use another.

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
