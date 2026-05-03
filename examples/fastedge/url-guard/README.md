# fastedge/url-guard — OWASP URL attack detection

A Gcore FastEdge application that scans incoming request URLs for OWASP Top 10
attack patterns and blocks matching requests with a 403 response.

Uses **set composition**: 8 attack patterns are compiled into a single WASM set.
One `scan_url()` call checks all patterns simultaneously; `.next()` returns the
first match (if any) so blocked requests incur minimal overhead.

## Attack patterns detected

| ID | Pattern |
|---|---|
| `sql_injection` | UNION SELECT, DROP TABLE, exec(), etc. |
| `path_traversal` | `../`, `%2e%2e`, URL-encoded traversal sequences |
| `xss` | `<script>`, `onerror=`, `javascript:`, `eval()` |
| `shell_injection` | `` ;wget ``, `$(...)`, backtick expressions |
| `log4shell` | `${jndi:`, `${lower:`, and related Log4Shell payloads |
| `dir_bruteforce` | Common sensitive paths: `.git`, `.env`, `wp-admin`, etc. |
| `open_redirect` | Redirect/return/goto params pointing to external URLs |
| `sensitive_file_exposure` | Backup, config, and archive file extensions in path |
| `ssrf` | URL params pointing to internal/loopback addresses |
| `xxe` | XML/DOCTYPE injection sequences in URL |
| `null_byte` | Null byte injection (`%00`) |
| `crlf_injection` | CRLF sequences for header injection (`%0D%0A`) |
| `cmd_execution` | PHP command execution functions in path (`/exec`, `/system`, etc.) |
| `template_injection` | Jinja2/Twig/Freemarker/ERB template syntax in URL |
| `prototype_pollution` | JavaScript prototype chain attacks (`__proto__`, `constructor[`) |
| `ssti_probe` | Expression evaluation probes used in SSTI scanning (`{{7*7}}`) |
| `host_header_injection` | `@evil.com/` embedded in URL to hijack routing |
| `request_smuggling` | HTTP header names (`transfer-encoding:`, `content-length:`) in path |
| `ldap_injection` | LDAP filter metacharacters (`)(`, `*)(`, `,uid=`) |
| `xpath_injection` | XPath injection probes (`' or '1'='1`, `contains(`, `substring(`) |
| `nosql_injection` | MongoDB/NoSQL operator injection (`$where`, `$gt`, `$regex`, etc.) |
| `unicode_normalization` | Overlong UTF-8 encodings of `/` and `.` used to bypass path filters |

## Prerequisites

- `regexped` binary (run `make` in the repo root)
- Rust with `wasm32-wasip1` target (`rustup target add wasm32-wasip1`)
- `wasm-merge` from [Binaryen](https://github.com/WebAssembly/binaryen)

## Build

```sh
make
```

## Build pipeline

```
regexped generate   →  generate Rust FFI stubs (stubs.rs)
cargo build         →  compile Rust app to WASM
regexped compile    →  compile 8 attack patterns to WASM
regexped merge      →  merge app + patterns into final.wasm
```

## How it works

`lib.rs` intercepts every HTTP request at the `on_http_request_headers` phase,
extracts the `:path` header, and passes it to the generated `patterns::scan_url()`
iterator. If any pattern matches, the request is blocked immediately with a 403
and the matched attack category is logged. If no pattern matches, the request
continues to the origin.

The calling code is minimal — the generated `stubs.rs` hides all WASM FFI details:

```rust
if let Some(m) = patterns::scan_url(url.as_bytes()).next() {
    let attack = patterns::pattern_name(m.pattern_id);
    // block with 403
}
```
