# wasmtime/go/secret-scanner — multi-pattern secret detection

A Go (wasip1) program that scans text for 10 known secret patterns using
**set composition**. One `scan_secrets()` call checks all patterns simultaneously
and returns all matches with their pattern name and position.

## Patterns detected

| ID | Pattern |
|---|---|
| `aws_key` | AWS access key (`AKIA...`) |
| `aws_secret` | AWS secret key in config format |
| `github_pat` | GitHub personal access token (`ghp_...`) |
| `github_oauth` | GitHub OAuth token (`gho_...`) |
| `github_app` | GitHub App token (`ghu_...`) |
| `jwt` | JSON Web Token (`eyJ...`) |
| `slack_token` | Slack bot/app token (`xox...`) |
| `stripe_live` | Stripe live secret key (`sk_live_...`) |
| `stripe_test` | Stripe test secret key (`sk_test_...`) |
| `google_api` | Google API key (`AIza...`) |

## Prerequisites

The Makefile installs nothing. Install these first:

| Tool | How to install |
|---|---|
| `regexped` | run `make` in the repo root |
| Go 1.23+ | [go.dev/dl](https://go.dev/dl/) |
| `wasm-merge` | from [Binaryen](https://github.com/WebAssembly/binaryen/releases): unpack a release and put its `bin/` on `PATH` |
| `wasmtime` | `curl https://wasmtime.dev/install.sh -sSf \| bash` — see [wasmtime.dev](https://wasmtime.dev) |

What each target needs:

| Target | What it does | Needs |
|---|---|---|
| `make` | builds `final.wasm` — the steps below | `regexped`, Go, `wasm-merge` |
| `make generate` | generates the Go stub `stub.go` | `regexped` |
| `make build` | generates the stub if needed, then `GOOS=wasip1 GOARCH=wasm go build` into `app.wasm` | `regexped`, Go |
| `make compile` | compiles the patterns to `secrets.wasm` | `regexped` |
| `make merge` | merges the two into `final.wasm` — the same as `make` | `regexped`, Go, `wasm-merge` |
| `make run` | builds if needed, then runs `final.wasm` under wasmtime on a sample token | all of the above, plus `wasmtime` |
| `make clean` | removes the build outputs | — |

`wasm-merge` is looked up on `PATH` (a config can name it with `wasm_merge_path:` instead).

## Build and run

```sh
make       # build final.wasm
make run   # run it on a sample token
echo "token: ghp_abcdef123456789012345678901234567890" | wasmtime final.wasm   # or on your own input
```

## Build pipeline

```
regexped generate   →  generate Go set stub (stub.go)
go build            →  compile Go app to WASM (wasip1)
regexped compile    →  compile 10 secret patterns to WASM
regexped merge      →  merge app + patterns into final.wasm
```

## How it works

`stub.go` is auto-generated. The scan function keeps the config's name
VERBATIM — `find: scan_secrets` in `regexped.yaml` yields `func scan_secrets`,
not `ScanSecrets`; the PascalCase transform was retired. Symbols
with no user-supplied name, like `PatternName`, keep Go's convention.

`main.go` is ~20 lines:

```go
scanIter := scan_secrets(input, 0)
for m := range scanIter.Matches() {
    fmt.Printf("[%s] at %d..%d: %s\n",
        PatternName(m.PatternID), m.Start, m.End,
        string(input[m.Start:m.End]))
}
// Err() after the loop: an engine that gave up ends iteration the same way
// exhausting the input does, so the two are only distinguishable here.
if err := scanIter.Err(); err != nil { /* handle */ }
```

No WASM memory management, no manual tuple decoding, no batch loop.
