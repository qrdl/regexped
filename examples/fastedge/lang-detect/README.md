# fastedge/lang-detect — script and European-language detection

A FastEdge HTTP application that takes text as a POST body and returns a JSON
array of the European languages its letters allow. It looks at **letters only,
never words**: the point is to show Unicode regexps, not to be a full
language identifier.

```sh
$ curl --data-binary 'Zażółć gęślą jaźń' http://127.0.0.1:8080/
["Polish"]
```

It is a **Component Model** application in Rust: the app is a `wasi:http` guest
component, the patterns are a regexped component (`wasm_format: component`),
and `regexped merge` composes the two into `lang-detect.wasm`.

## What it answers

A language matches when the text contains at least one of its own letters, and
every letter of that script in the text belongs to the language's alphabet.
"Its own letters" are the ones beyond the script's core: `a`–`z` for Latin,
and for Cyrillic the letters Russian, Ukrainian and Bulgarian share. Every
matching language is returned. When a script is present but none of its
languages matches, the script's name is returned instead.

| Input | Result |
|---|---|
| `Hello world` | `["Latin"]` — no letter beyond `a`–`z` |
| `Grüße aus Köln` | `["German"]` |
| `Un café, por favor` | `["French","Spanish","Portuguese","Italian","Dutch","Norwegian","Danish","Icelandic","Czech","Slovak","Hungarian"]` — every alphabet with `é` |
| `Zażółć gęślą jaźń` | `["Polish"]` |
| `Příliš žluťoučký kůň` | `["Czech"]` |
| `Привет` | `["Cyrillic"]` — only shared letters |
| `Привіт` | `["Ukrainian"]` |
| `Съешь` | `["Russian","Bulgarian"]` — both have `ъ` |
| `Ђорђе` | `["Serbian"]` |
| `Καλημέρα κόσμε` | `["Greek"]` |
| `Привет, Grüße` | `["Cyrillic","German"]` — scripts in order of appearance |

Languages: English, German, French, Spanish, Portuguese, Italian, Dutch,
Swedish, Norwegian, Danish, Finnish, Icelandic, Estonian, Latvian, Lithuanian,
Polish, Czech, Slovak, Slovenian, Croatian, Hungarian, Romanian, Albanian and
Maltese in Latin script; Russian, Ukrainian, Belarusian, Bulgarian, Serbian and
Macedonian in Cyrillic; Greek. English has no letters of its own, so English
text answers `["Latin"]`, and Greek is the only language of its script, so it
is reported by the script's name.

A body that is not UTF-8 is refused with 400, and a method other than POST
with 405.

## Prerequisites

The Makefile installs nothing. Install these first:

| Tool | How to install |
|---|---|
| `regexped` | run `make` in the repo root |
| Rust with the `wasm32-wasip2` target | [rustup](https://rustup.rs), then `rustup target add wasm32-wasip2` |
| `wasm-tools` | a [release](https://github.com/bytecodealliance/wasm-tools/releases) on `PATH`, or `cargo install --locked wasm-tools` |
| `wac` | a [release](https://github.com/bytecodealliance/wac/releases) (the `wac-cli-<platform>` binary, renamed to `wac`) on `PATH`, or `cargo install --locked wac-cli` |
| `wasmtime` | `curl https://wasmtime.dev/install.sh -sSf \| bash` — see [wasmtime.dev](https://wasmtime.dev); for `make run` and `make serve` only |
| `curl` | your package manager — for `make run` only |
| Node.js 22.12 or later, with npm | [nodejs.org](https://nodejs.org) — for `make test` only; then run `npm install` here once, which installs the FastEdge test runner `@gcoredev/fastedge-test` |

What each target needs:

| Target | What it does | Needs |
|---|---|---|
| `make` | builds `lang-detect.wasm` — the steps below | `regexped`, `wasm-tools`, Rust, `wac` |
| `make compile` | compiles the patterns to the component `langdetect.wasm` and its `langdetect.wit` | `regexped`, `wasm-tools` |
| `make generate` | generates the Rust stub `stubs.rs` | `regexped` |
| `make build` | generates the stub if needed, then `cargo build --target wasm32-wasip2` | `regexped`, Rust |
| `make compose` | composes the two into `lang-detect.wasm` — the same as `make` | `regexped`, `wasm-tools`, Rust, `wac` |
| `make run` | serves the app on `127.0.0.1:8080` in the background, POSTs the sample texts above, stops the server | the above, `wasmtime`, `curl` |
| `make serve` | serves the app until Ctrl-C, for your own `curl` | the above, `wasmtime` |
| `make test` | runs `lang-detect.wasm` under the FastEdge runtime itself (`fastedge-run`, through `@gcoredev/fastedge-test`) and checks every sample's answer, the empty body and the 405 — [`test.mjs`](test.mjs) | the `make` tools, Node.js, `npm install` |
| `make clean` | removes the build outputs | — |

`make run` and `make serve` use `wasmtime serve`, which runs any `wasi:http`
component; `make test` uses the runtime FastEdge runs. `PORT=<n>` moves both
wasmtime servers off 8080. `wasm-tools` and `wac` are looked up on
`PATH` (a config can name them with `wasm_tools_path:` and `wac_path:` instead).

## How it works

[`regexped.yaml`](regexped.yaml) declares 32 patterns in three sets. Every
pattern names a Unicode script class (`\p{Latin}`) or a letter above U+007F, so
each compiles in **Unicode mode**: a class reads a whole character rather than
a byte, and `(?i)` folds across Unicode — `(?i:[äöüß])` also matches `Ä`, `Ö`,
`Ü` and `ẞ`.

1. **`scripts`** (`find`) runs `\p{Latin}+`, `\p{Cyrillic}+` and `\p{Greek}+`
   over the text, which gives the scripts it uses in order of first appearance.
2. **`latin`** and **`cyrillic`** (`match_all`) hold one pattern per language.
   `match_all` is anchored — the pattern must match the WHOLE text — and
   returns every pattern that does. A language's pattern is its alphabet
   rule written out:

   ```
   (?:\P{Latin}|(?i:[a-zäöüß]))*  (?i:[äöüß])  (?:\P{Latin}|(?i:[a-zäöüß]))*
   ```

   Anything that is not a Latin letter — another script, a digit, a space,
   punctuation — is `\P{Latin}` and passes through; every Latin letter must be
   in German's alphabet; and the middle term requires at least one of German's
   own letters. Cyrillic patterns spell out each language's whole alphabet the
   same way.
3. [`lib.rs`](lib.rs) asks the language set of each script found and turns the
   ids into names with `pattern_name` (`emit_name_map: true`): the pattern
   names in the config ARE the display names.

The three sets compile to one 490 KB component. All matching is in it; `lib.rs`
only chooses which set to ask.

## Deploying

`lang-detect.wasm` is a complete FastEdge HTTP application: upload it as a
binary and create an application from it. See
[docs/fastedge.md](../../../docs/fastedge.md) and the FastEdge documentation.
