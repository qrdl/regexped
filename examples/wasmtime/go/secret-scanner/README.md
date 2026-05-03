# wasmtime/go/secret-scanner — multi-pattern secret detection

A Go (wasip1) program that scans text for 10 known secret patterns using
**set composition**. One `ScanSecrets()` call checks all patterns simultaneously
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

- `regexped` binary (run `make` in the repo root)
- Go 1.23+ with `GOOS=wasip1 GOARCH=wasm` support
- `wasm-merge` from [Binaryen](https://github.com/WebAssembly/binaryen)
- `wasmtime` CLI

## Build and run

```sh
make
echo "token: ghp_abc123456789012345678901234567890" | wasmtime final.wasm
```

## Build pipeline

```
regexped generate   →  generate Go set stub (stub.go)
go build            →  compile Go app to WASM (wasip1)
regexped compile    →  compile 10 secret patterns to WASM
regexped merge      →  merge app + patterns into final.wasm
```

## How it works

`stub.go` is auto-generated and exposes `ScanSecrets([]byte) iter.Seq[SetMatch]`
and `PatternName(int) string`. `main.go` is ~20 lines:

```go
for m := range ScanSecrets(input) {
    fmt.Printf("[%s] at %d..%d: %s\n",
        PatternName(m.PatternID), m.Start, m.End,
        string(input[m.Start:m.End]))
}
```

No WASM memory management, no manual tuple decoding, no batch loop.
