# fastedge/ua-parser — User-Agent parsing in Go

A FastEdge HTTP application that parses a User-Agent string into the browser
and its version, the OS and its version, the device type, and the bot, if it
is one. `GET` parses the request's own `User-Agent` header; `POST` parses the
body.

```sh
$ curl --data-binary 'Mozilla/5.0 (iPhone; CPU iPhone OS 17_2 like Mac OS X) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/17.2 Mobile/15E148 Safari/604.1' http://127.0.0.1:8080/
{"browser":{"name":"Safari","version":"17.2"},"os":{"name":"iOS","version":"17.2"},"device":"mobile","bot":null}
```

It is a **Component Model** application in **Go**, built with
[componentize-go](https://github.com/bytecodealliance/componentize-go): the
app is a `wasi:http` guest component, the patterns are a regexped component
(`wasm_format: component`), and `regexped merge` composes the two into
`ua-parser.wasm`.

There is **no regexped Go stub** on this route. regexped writes the
component's interface as a `.wit` file, componentize-go generates Go bindings
from it, and the app calls those bindings directly — see
[Calling regexped from Go](#calling-regexped-from-go) below.

## What it answers

```json
{"browser": {"name": "Edge", "version": "120.0.2210.91"},
 "os":      {"name": "Windows", "version": "10"},
 "device":  "desktop",
 "bot":     null}
```

| Field | Values |
|---|---|
| `browser` | Edge, Opera, Samsung Internet, Yandex Browser, Vivaldi, UC Browser, DuckDuckGo, Firefox, Chrome, Safari, Internet Explorer — or `null` |
| `os` | iOS, Android, ChromeOS, Windows, macOS, Linux — or `null`. Linux carries no version; Windows' is the release name (`Windows NT 6.1` is `7`) |
| `device` | `tablet`, `mobile`, `desktop` (ChromeOS, Windows, macOS, Linux), or `unknown` |
| `bot` | a named crawler (`Googlebot`, `bingbot`, `GPTBot`, …), an HTTP tool (`curl`, `python-requests`, …), `unidentified bot` for anything else that says bot, crawler, spider or headless — or `null` |

A crawler is reported beside the browser it claims to be: Googlebot's
smartphone crawler answers `Chrome`, `Android`, `mobile` **and**
`{"name":"Googlebot","version":"2.1"}`.

A User-Agent string is whatever the client sends, so this is a best guess, as
every User-Agent parser's is. Two known blind spots: Windows 11 still says
`Windows NT 10.0`, so it answers `10`; and Safari on iPadOS asks for desktop
sites by default, sending a macOS User-Agent string.

`POST` takes at most 8 KB (413 above that); a method other than `GET` and
`POST` answers 405.

## Prerequisites

The Makefile installs nothing. Install these first:

| Tool | How to install |
|---|---|
| `regexped` | run `make` in the repo root |
| Go 1.27.1 or later | [go.dev/dl](https://go.dev/dl/). With an older Go on `PATH`, `GOTOOLCHAIN=go1.27.3 make` has the `go` command fetch one |
| `componentize-go` 0.5 | a [release](https://github.com/bytecodealliance/componentize-go/releases) on `PATH` (or `go install github.com/bytecodealliance/componentize-go@latest`); `COMPONENTIZE_GO=<path>` names it otherwise |
| `wasm-tools` | a [release](https://github.com/bytecodealliance/wasm-tools/releases) on `PATH`, or `cargo install --locked wasm-tools` |
| `wac` | a [release](https://github.com/bytecodealliance/wac/releases) (the `wac-cli-<platform>` binary, renamed to `wac`) on `PATH`, or `cargo install --locked wac-cli` |
| `wasmtime` | `curl https://wasmtime.dev/install.sh -sSf \| bash` — see [wasmtime.dev](https://wasmtime.dev); for `make run` and `make serve` only |
| `curl` | your package manager — for `make run` only |
| Node.js 22.12 or later, with npm | [nodejs.org](https://nodejs.org) — for `make test` only; then run `npm install` here once, which installs the FastEdge test runner `@gcoredev/fastedge-test` |

What each target needs:

| Target | What it does | Needs |
|---|---|---|
| `make` | builds `ua-parser.wasm` — the steps below | `regexped`, `wasm-tools`, Go, `componentize-go`, `wac` |
| `make compile` | compiles the patterns to the component `uaparser.wasm` and its `uaparser.wit` | `regexped`, `wasm-tools` |
| `make bindings` | copies `uaparser.wit` into `wit/deps/`, generates the Go bindings for [`wit/world.wit`](wit/world.wit) (and `go.mod`), then `go mod tidy` | the above, Go, `componentize-go` |
| `make build` | builds the app as the guest component `main.wasm` | the above |
| `make compose` | composes the two into `ua-parser.wasm` — the same as `make` | the `make` tools |
| `make run` | serves the app on `127.0.0.1:8080` in the background, POSTs five sample User-Agent strings, stops the server | the above, `wasmtime`, `curl` |
| `make serve` | serves the app until Ctrl-C, for your own `curl` | the above, `wasmtime` |
| `make test` | runs `ua-parser.wasm` under the FastEdge runtime itself (`fastedge-run`, through `@gcoredev/fastedge-test`) and checks 16 User-Agent strings, `GET`, the 405 and the 413 — [`test.mjs`](test.mjs) | the `make` tools, Node.js, `npm install` |
| `make clean` | removes the build outputs and the generated Go files | — |

`make test` takes about a second per request: the local runner compiles the
module for every request, where FastEdge compiles it once when it is deployed.
`make run` and `make serve` use `wasmtime serve`, which answers in a
millisecond or two. `PORT=<n>` moves both off 8080.

The Go files at the top of this directory — `go.mod`, `go.sum`,
`wit_exports.go`, `regexped_uaparser_*/`, `wasi_*/` — are generated by `make
bindings`; until it has run, a Go editor cannot resolve the app's imports.

## How it works

[`regexped.yaml`](regexped.yaml) declares 23 patterns in four groups —
browsers, operating systems, device type, bots — and one set over all of
them:

1. **`classify`** (`scan_all`) runs every pattern over the User-Agent string
   in one pass and returns the ids of those that occur anywhere in it.
2. Per group, the app takes the **first** pattern that occurred, in the order
   the config lists them. Order is priority: an Edge User-Agent string also
   carries `Chrome/` and `Safari/`, and an Android one carries `Linux`, so
   Edge comes before Chrome before Safari, and Android before Linux.
3. For each winner, the pattern's own **`groups_func`** extracts the version
   — or a bot's name and version — through a named group:
   `Edg(?:e|A|iOS)?/(?<version>[0-9]+(?:\.[0-9]+)*)`.

The device type has no versions: `tablet` (`iPad|Tablet|Kindle|Silk/`) and
`mobile` (`Mobi|iPhone|iPod`) are set members only, and Android with neither
is a tablet.

All the matching is in the 445 KB regexped component;
[`export_wasi_http_incoming_handler/ua.go`](export_wasi_http_incoming_handler/ua.go)
only chooses, per group, and writes the JSON.
[`handler.go`](export_wasi_http_incoming_handler/handler.go) is the
`wasi:http` handler componentize-go's generated glue calls once per request.

## Calling regexped from Go

componentize-go generates one Go package per imported interface:
`regexped_uaparser_matcher` (the patterns' `groups_func`s) and
`regexped_uaparser_sets` (the set). Their API is the WIT's, in Go:

| regexped config | WIT | Generated Go |
|---|---|---|
| set `scan_all: classify` | `classify: func(input: list<u8>, start: u32) -> result<list<u32>, error-code>` | `regexped_uaparser_sets.Classify(input, 0)` → `witTypes.Result[[]uint32, ErrorCode]` |
| `groups_func: edge_version` | `resource edge-version { constructor(input, start); next: func() -> result<list<option<tuple<u32, u32>>>, error-code>; }` | `m := MakeEdgeVersion(input, 0)`; `m.Next()` per match, an empty list when finished; `m.Drop()` |

Compared with the Go **module** stub ([docs/go-api.md](../../../docs/go-api.md)):

- **Results are WIT types**, `witTypes.Result` / `witTypes.Option` /
  `witTypes.Tuple2`, rather than `Matches()` iterators and `Err()`.
- **Capture groups are positions only.** The WIT carries no group names, so
  `version` is index 1; the module stub's `<groups>_index("version")` has no
  counterpart.
- **Set ids are positions only.** A member's id is its index in `patterns:`,
  and the WIT carries no name map, so `ua.go`'s table must follow the config's
  order.
- **A scan is a resource** the app releases with `Drop()`.
- **An error is an answer**: `ErrorCode` means the engine could not answer
  (the Backtracking engine gave up), which the app returns as 500, not as "no
  match".

`wit/deps/` holds the WASI 0.2.0 WIT the app's world includes, vendored from
componentize-go v0.5.3's `wasip2` example; `make bindings` adds the regexped
component's own `uaparser.wit` beside it.

## Deploying

`ua-parser.wasm` is a complete FastEdge HTTP application: upload it as a binary
and create an application from it. See
[docs/fastedge.md](../../../docs/fastedge.md) and the FastEdge documentation.
