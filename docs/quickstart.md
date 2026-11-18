# Quick start

One config, two commands, and the matchers are functions in your language.
Every listing below was run as shown.

## 1. The config

`regexped.yaml`:

```yaml
import_module: patterns          # the name the generated code imports the matchers from
wasm_file:     patterns.wasm     # what `regexped compile` writes
stub_file:     patterns.js       # what `regexped generate` writes; the extension picks the language

patterns:
  - name: email
    regexp: '[a-z0-9._%+-]+@[a-z0-9.-]+\.[a-z]{2,}'
    match_func: is_email         # is the WHOLE input an email address?
    find_func:  find_emails      # every email address in the input

  - name: date
    regexp: '(?<year>\d{4})-(?<month>\d{2})-(?<day>\d{2})'
    groups_func: dates           # every date, with its year, month and day
```

Each `_func` key becomes one function: `match_func` tests the whole input,
`find_func` iterates over every match, `groups_func` over every match with its
capture groups. A regexp is written in Go's syntax (RE2) and matched with its
leftmost-first rules. [cli.md](cli.md) has every key.

`regexped check` runs every test `compile` and `generate` make and writes
nothing; it answers by its exit code. With `--verbose` it also tells you what
the compiler will do with each pattern:

```
$ regexped check --verbose
email  match,find  Compiled DFA  switch → start-anywhere  scan: SIMD literal                     memory: grows with input: per-search notes
date   groups      TDFA          linear                   scan: SIMD literal, mandatory literal  memory: constant
```

[cli.md](cli.md#the-report---verbose-and---verbose-format) explains every
column, and `--verbose=full` says why.

## 2. JavaScript

```
$ regexped compile      # → patterns.wasm
$ regexped generate     # → patterns.js
```

```js
import { readFile } from 'node:fs/promises';
import * as rx from './patterns.js';

await rx.init(await readFile('patterns.wasm'));

console.log(rx.is_email('ann@example.com'));   // 15: where the match ends
console.log(rx.is_email('not an email'));      // null

const text = 'Mail ann@example.com or bob@example.org by 2026-11-30.';
for (const [start, end] of rx.find_emails(text)) {
    console.log(text.slice(start, end));        // ann@example.com, then bob@example.org
}
for (const groups of rx.dates(text)) {
    const [start, end] = groups[rx.dates_indices.year];
    console.log(text.slice(start, end));        // 2026
}
```

Positions are offsets into the input's UTF-8 bytes — string indices too, for
ASCII text like this. The same module and stub run
in a browser, Node.js and Cloudflare Workers; for TypeScript set
`stub_file: patterns.ts`. See [js-api.md](js-api.md), [ts-api.md](ts-api.md),
[browser.md](browser.md), [node.md](node.md).

## 3. Rust and Go

Here the patterns are LINKED into your program's own WASM binary, so the config
gains `output:` — the linked result — and `stub_file:` names the language:

```yaml
output:        app.wasm          # what `regexped merge` writes: your program with the patterns linked in
stub_file:     src/patterns.rs   # .rs: a Rust module (for Go: patterns.go, plus go_package: main)
```

The build is compile, generate, your own build, then `merge`, which needs
[`wasm-merge`](https://github.com/WebAssembly/binaryen) on `$PATH` (or
`wasm_merge_path:` in the config; the Docker image has it):

```
$ regexped compile
$ regexped generate
$ cargo build --release --target wasm32-wasip1
$ regexped merge --main=target/wasm32-wasip1/release/app.wasm patterns.wasm
$ wasmtime run app.wasm
```

Rust, `src/main.rs`:

```rust
include!("patterns.rs"); // written by `regexped generate`

fn main() -> patterns::Result<()> {
    println!("{:?}", patterns::is_email(b"ann@example.com")?); // Some(15)
    println!("{:?}", patterns::is_email(b"not an email")?);    // None

    let text = b"Mail ann@example.com or bob@example.org by 2026-11-30.";
    for m in patterns::find_emails(text, 0) {
        let (start, end) = m?;
        println!("{}", std::str::from_utf8(&text[start..end]).unwrap());
    }
    for groups in patterns::dates(text, 0) {
        if let Some(year) = groups?[patterns::dates_year] {
            println!("{}", std::str::from_utf8(&text[year.range()]).unwrap()); // 2026
        }
    }
    Ok(())
}
```

Go (1.23 or later), built with `GOOS=wasip1 GOARCH=wasm go build -o main.wasm .`
and merged with `--main=main.wasm`:

```go
//go:build wasip1

package main

import "fmt"

func main() {
	end, ok, err := is_email([]byte("ann@example.com"))
	fmt.Println(end, ok, err) // 15 true <nil>

	text := []byte("Mail ann@example.com or bob@example.org by 2026-11-30.")
	emails := find_emails(text, 0)
	for start, end := range emails.Matches() {
		fmt.Println(string(text[start:end]))
	}
	if err := emails.Err(); err != nil {
		panic(err)
	}
	found := dates(text, 0)
	for groups := range found.Matches() {
		year := groups[dates_year]
		fmt.Println(string(text[year.Start:year.End])) // 2026
	}
	if err := found.Err(); err != nil {
		panic(err)
	}
}
```

An error is the engine saying it cannot decide — out of memory for a
Backtracking search — never "no match". See [rust-api.md](rust-api.md),
[go-api.md](go-api.md), [wasmtime.md](wasmtime.md); C and AssemblyScript are
[c-api.md](c-api.md) and [as-api.md](as-api.md).

## Next

- Many patterns at once — which matched, where — is a **set**: [sets.md](sets.md).
- A Component Model component instead of a module: [component.md](component.md).
- Working programs in every language: [examples/](../examples).
