// perftest benchmarks regexped WASM against the regex crate and prints a summary table.
//
// Run from the perf_test/ directory:
//
//	cd perf_test && go run ./perftest
package main

import (
	"flag"
	"fmt"
	"io"
	"log/slog"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"strconv"
	"strings"

	"github.com/qrdl/regexped/compile"
	"github.com/qrdl/regexped/config"
	"github.com/qrdl/regexped/merge"
	"github.com/qrdl/regexped/utils"
)

// --------------------------------------------------------------------------
// Test case definitions

type matchMode int

const (
	anchored matchMode = iota
	find
	anchoredGroups // OnePass: (ptr, len, out_ptr) → i32
)

type testCase struct {
	name    string
	pattern string
	mode    matchMode
	inputs  []namedInput
}

type namedInput struct {
	label string
	value string
}

var tests = []testCase{
	{
		name:    "email",
		pattern: `[a-zA-Z0-9_%+\-]+(?:\.[a-zA-Z0-9_%+\-]+)*@[a-zA-Z0-9](?:[a-zA-Z0-9\-]*[a-zA-Z0-9])?(?:\.[a-zA-Z0-9](?:[a-zA-Z0-9\-]*[a-zA-Z0-9])?)*\.[a-zA-Z][a-zA-Z]+`,
		mode:    anchored,
		inputs: []namedInput{
			{"match", "user@example.com"},
			{"match-complex", "user.name+tag@sub.domain.org"},
			{"no-match", "not-an-email"},
		},
	},
	{
		name:    "url-ipv4",
		pattern: `[Hh][Tt][Tt][Pp][Ss]?://(?:[a-zA-Z0-9._~!$&'()*+,;=:-]+@)?(?:(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)|[a-zA-Z0-9](?:[a-zA-Z0-9-]*[a-zA-Z0-9])?(?:\.[a-zA-Z0-9](?:[a-zA-Z0-9-]*[a-zA-Z0-9])?)*)(?::(?:[0-9]|[1-9][0-9]|[1-9][0-9]{2}|[1-9][0-9]{3}|[1-5][0-9]{4}|6[0-4][0-9]{3}|65[0-4][0-9]{2}|655[0-2][0-9]|6553[0-5]))?(?:[/?#][/a-zA-Z0-9._~!$&'()*+,;=:@%?#-]*)?`,
		mode:    anchored,
		inputs: []namedInput{
			{"ipv4-short", "https://192.168.1.1:8080/path/to/resource?q=1&r=2#section"},
			{"ipv4-auth", "https://user:pass@sub.example.com:8443/path/to/resource?q=1&r=2#section"},
			{"ipv4-long", "https://user:password@sub.domain.example.com:8443/path/to/some/resource/page.html?param1=value1&param2=value2&param3=value3#section-anchor"},
			{"no-match", "not-a-url"},
		},
	},
	{
		name:    "url-ipv6",
		pattern: `[Hh][Tt][Tt][Pp][Ss]?://(?:[a-zA-Z0-9._~!$&'()*+,;=:-]+@)?(?:(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)|\[(?:(?:[0-9a-fA-F]{1,4}:){7}[0-9a-fA-F]{1,4}|(?:[0-9a-fA-F]{1,4}:){1,7}:|:(?::[0-9a-fA-F]{1,4}){1,7}|(?:[0-9a-fA-F]{1,4}:){1,6}:[0-9a-fA-F]{1,4}|(?:[0-9a-fA-F]{1,4}:){1,5}(?::[0-9a-fA-F]{1,4}){1,2}|(?:[0-9a-fA-F]{1,4}:){1,4}(?::[0-9a-fA-F]{1,4}){1,3}|(?:[0-9a-fA-F]{1,4}:){1,3}(?::[0-9a-fA-F]{1,4}){1,4}|(?:[0-9a-fA-F]{1,4}:){1,2}(?::[0-9a-fA-F]{1,4}){1,5}|[0-9a-fA-F]{1,4}:(?::[0-9a-fA-F]{1,4}){1,6}|::)\]|[a-zA-Z0-9](?:[a-zA-Z0-9-]*[a-zA-Z0-9])?(?:\.[a-zA-Z0-9](?:[a-zA-Z0-9-]*[a-zA-Z0-9])?)*)(?::(?:[0-9]|[1-9][0-9]|[1-9][0-9]{2}|[1-9][0-9]{3}|[1-5][0-9]{4}|6[0-4][0-9]{3}|65[0-4][0-9]{2}|655[0-2][0-9]|6553[0-5]))?(?:[/?#][/a-zA-Z0-9._~!$&'()*+,;=:@%?#-]*)?`,
		mode:    anchored,
		inputs: []namedInput{
			{"ipv6-auth", "https://user:pass@[2001:db8:85a3::8a2e:370:7334]:8443/path/to/resource?q=1#section"},
			{"ipv6-short", "https://[::1]/path"},
			{"ipv6-long", "https://user:password@sub.domain.example.com:8443/path/to/some/resource/page.html?param1=value1&param2=value2&param3=value3#section-anchor"},
			{"no-match", "not-a-url"},
		},
	},
	// ── Secret detection ─────────────────────────────────────────────────────
	// All three patterns have a well-defined literal prefix; find mode scans a
	// ~10 KB config file. These cases establish a baseline before literal-prefix
	// optimisation is implemented.
	{
		// JWT: prefix "eyJ" (base64url of '{"'). 'e' is very common in config
		// files, so the DFA restarts frequently — ideal for prefix optimisation.
		name:    "secrets-jwt",
		pattern: `eyJ[A-Za-z0-9+/\-_]+\.[A-Za-z0-9+/\-_]+\.[A-Za-z0-9+/\-_]+`,
		mode:    find,
		inputs: []namedInput{
			{"no-secret ~10KB", secretBaseInput("")},
			{"with-secret ~10KB", secretBaseInput(
				"export AUTH_TOKEN=eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9." +
					"eyJzdWIiOiIxMjM0NTY3ODkwIiwibmFtZSI6IkpvaG4gRG9lIiwiaWF0IjoxNTE2MjM5MDIyfQ." +
					"SflKxwRJSMeKKF2QT4fwpMeJf36POk6yJV_adQssw5c")},
		},
	},
	{
		// GitHub PAT: prefix "ghp_". 'g' is moderately common.
		name:    "secrets-github",
		pattern: `ghp_[A-Za-z0-9]{36}`,
		mode:    find,
		inputs: []namedInput{
			{"no-secret ~10KB", secretBaseInput("")},
			{"with-secret ~10KB", secretBaseInput("ghp_AbCdEfGhIjKlMnOpQrStUvWxYz0123456789Ab")},
		},
	},
	{
		// AWS access key: prefix "AKIA". 'A' is common (API, AWS, APP variables).
		name:    "secrets-aws",
		pattern: `AKIA[A-Z0-9]{16}`,
		mode:    find,
		inputs: []namedInput{
			{"no-secret ~10KB", secretBaseInput("")},
			{"with-secret ~10KB", secretBaseInput("export AWS_ACCESS_KEY_ID=AKIAIOSFODNN7EXAMPLE")},
		},
	},
	{
		// Combined: single DFA covering all three secret types.
		// Fast-skip uses union first-byte set {e, g, A} — skips all other bytes.
		name:    "secrets-combined",
		pattern: `eyJ[A-Za-z0-9+/\-_]+\.[A-Za-z0-9+/\-_]+\.[A-Za-z0-9+/\-_]+|ghp_[A-Za-z0-9]{36}|AKIA[A-Z0-9]{16}`,
		mode:    find,
		inputs: []namedInput{
			{"no-secret ~10KB", secretBaseInput("")},
			{"JWT ~10KB", secretBaseInput("export AUTH_TOKEN=eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIxMjM0NTY3ODkwIn0.SflKxwRJSMeKKF2QT4fwpMeJf36POk6yJV_adQssw5c")},
			{"GitHub ~10KB", secretBaseInput("ghp_AbCdEfGhIjKlMnOpQrStUvWxYz0123456789Ab")},
			{"AWS ~10KB", secretBaseInput("export AWS_ACCESS_KEY_ID=AKIAIOSFODNN7EXAMPLE")},
		},
	},
	{
		// Combined secrets in a large 100KB file — realistic log/config scanning scenario.
		// Contains multiple secret occurrences spread throughout the file.
		name:    "secrets-combined-100kb",
		pattern: `eyJ[A-Za-z0-9+/\-_]+\.[A-Za-z0-9+/\-_]+\.[A-Za-z0-9+/\-_]+|ghp_[A-Za-z0-9]{36}|AKIA[A-Z0-9]{16}`,
		mode:    find,
		inputs: []namedInput{
			{"no-secret 100KB", secretLargeInput(nil)},
			{"3 secrets 100KB", secretLargeInput([]string{
				"eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIxMjM0NTY3ODkwIn0.SflKxwRJSMeKKF2QT4fwpMeJf36POk6yJV_adQssw5c",
				"ghp_AbCdEfGhIjKlMnOpQrStUvWxYz0123456789Ab",
				"export AWS_ACCESS_KEY_ID=AKIAIOSFODNN7EXAMPLE",
			})},
		},
	},
	{
		// URL find in prose — benchmarks non-prefix mandatory literal extraction.
		// First-byte set [a-zA-Z] matches ~20% of bytes in typical text, but
		// "://" is very rare. This is the ideal pattern for mandatory-literal
		// optimisation: noisy prefix, highly selective interior literal.
		name:    "url-find-100kb",
		pattern: `[a-zA-Z]{2,8}://[^\s]+`,
		mode:    find,
		inputs: []namedInput{
			{"no-url 100KB", urlProseInput(nil)},
			{"5 urls 100KB", urlProseInput([]string{
				"https://example.com/path/to/page?q=hello&lang=en",
				"http://api.internal/v2/users/42/profile",
				"ftp://files.example.org/pub/release-2.3.tar.gz",
				"https://cdn.example.net/static/js/bundle.min.js?v=8a3f1b",
				"https://auth.example.com/oauth2/token?grant_type=client_credentials",
			})},
		},
	},
	{
		// URL parsing with named capture groups — benchmarks OnePass engine
		// against regex crate's capture group extraction.
		// Credentials omitted: [^@]+ and [^/:+] overlap making it non-one-pass.
		name: "url-parse",
		pattern: `(?P<scheme>https?)://(?P<host>[^/:?#]+)` +
			`(?::(?P<port>[0-9]+))?(?P<path>/[^?#]*)?` +
			`(?:\?(?P<query>[^#]*))?(?:#(?P<fragment>.*))?`,
		mode: anchoredGroups,
		inputs: []namedInput{
			{"full URL", "https://example.com:8080/path/to/page?q=1&r=2#section"},
			{"simple URL", "https://example.com/path"},
			{"no-match", "not-a-url"},
		},
	},
	{
		// Non-anchored groups: find URLs anywhere in 10KB prose and capture host.
		// This exercises the wrapper's internal find_internal scan over a large buffer.
		name:    "url-domains-10k",
		pattern: `https?://(?P<host>[^/:?#\s]+)`,
		mode:    anchoredGroups,
		inputs: []namedInput{
			{"no-url 10KB", urlProseInputSmall(nil)},
			{"5 urls 10KB", urlProseInputSmall([]string{
				"https://example.com",
				"https://api.github.com/repos",
				"https://storage.googleapis.com/bucket",
				"https://cdn.cloudflare.net/assets",
				"https://docs.anthropic.com/api",
			})},
		},
	},
	{
		name:    "sql-inject",
		pattern: `'\s*(?:OR|AND)\s+[0-9]+\s*=\s*[0-9]+|UNION\s+(?:ALL\s+)?SELECT|'\s*;\s*(?:DROP|TRUNCATE)\s+TABLE`,
		mode:    find,
		inputs: []namedInput{
			{"no-inject ~1KB", sqlCleanInput()},
			{"injected ~1KB", sqlInjectInput()},
		},
	},
	{
		// CSV row parsing with 3 capture groups — benchmarks non-anchored Backtracking engine.
		// Fields can be unquoted or double-quoted (RFC 4180); quoted fields may contain commas
		// and doubled quotes (""). The alternation "..."|[^,\n]* is non-OnePass (overlapping
		// first-char sets), so the Backtracking engine is used automatically.
		// Input is a 16-line CSV file; groups_func scans for each row and extracts 3 columns.
		name:    "csv-parse",
		pattern: `((?:"(?:[^"]|"")*"|[^,\n]*)),((?:"(?:[^"]|"")*"|[^,\n]*)),((?:"(?:[^"]|"")*"|[^,\n]*))`,
		mode:    anchoredGroups,
		inputs: []namedInput{
			{"16-line CSV", csvInput()},
		},
	},
	{
		// Comment extraction from source code — benchmarks per-state SIMD in DFA inner loop.
		// Two self-loop states qualify (255/256 bytes each):
		//   - inside // comment: [^\n]+ self-loops until newline
		//   - inside /* */ comment body: everything except '*' self-loops
		// Block comments can be hundreds of bytes long, making long self-loop runs likely.
		// (?s) enables DOTALL so /* */ spans newlines correctly.
		name:    "comments-100kb",
		pattern: `//[^\n]+|/\*(?s:.*?)\*/`,
		mode:    find,
		inputs: []namedInput{
			{"no-comments 100KB", sourceCodeInput(nil, nil)},
			{"comments 100KB",    sourceCodeInput(
				[]string{"// initialise connection pool", "// retry with exponential backoff", "// validate request parameters"},
				[]string{"/*\n * Copyright 2026 Example Corp.\n * Licensed under the Apache License, Version 2.0.\n */",
					"/* TODO: replace with proper error handling once the new\n   error framework is merged into main branch */"},
			)},
		},
	},
	// ── Backtracking engine benchmark ────────────────────────────────────────
	// .* before (ERROR|WARNING|FATAL) makes this non-OnePass: the .* loop and
	// the keyword alternation share overlapping first-character sets.
	// The Backtracking engine is used automatically as a fallback.
	// Inputs are single matching log lines; anchoredGroups mode matches the
	// full line and extracts timestamp, level, and message captures.
	{
		name:    "log-capture",
		pattern: `^(\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}) .*(ERROR|WARNING|FATAL): (.+)$`,
		mode:    anchoredGroups,
		inputs: []namedInput{
			{"ERROR short",   "2026-03-22T14:05:01 app[42] ERROR: connection refused"},
			{"WARNING long",  "2026-03-22T14:05:02 service.worker.pool[7] WARNING: queue depth 9823 exceeds threshold 5000, consider scaling"},
			{"FATAL long",    "2026-03-22T14:05:03 db.connection.manager[1] FATAL: unable to acquire lock on table users after 30000ms, shutting down"},
		},
	},
}

// secretBaseInput returns a ~10KB environment/config file with many 'e', 'g', 'A'
// characters (common prefix chars for JWT, GitHub, AWS patterns) but no secrets.
// insertAt controls where the secret is spliced in (use -1 for no secret).
func secretBaseInput(secret string) string {
	// Realistic env file block — high density of 'e', 'g', 'A' characters.
	const block = `# Application Configuration
export APP_ENV=production
export DATABASE_URL=postgres://appuser:secure_password@db.example.com:5432/appdb
export REDIS_URL=redis://cache.example.com:6379/0
export EMAIL_HOST=smtp.example.com
export EMAIL_FROM=noreply@example.com
export ENABLE_METRICS=true
export METRICS_ENDPOINT=http://metrics.example.com:9090/metrics
export LOG_LEVEL=error
export LOG_FORMAT=json
export API_BASE_URL=https://api.example.com/v2
export API_TIMEOUT=30000
export MAX_CONNECTIONS=100
export ENABLE_CACHE=true
export CACHE_TTL=3600
export SESSION_SECRET=change_me_in_production
export GITHUB_ORG=example-org
export GITHUB_REPO=example-repo
export AWS_REGION=us-east-1
export AWS_S3_BUCKET=example-data-bucket
export ENCRYPTION_KEY=replace_with_actual_key
`
	base := strings.Repeat(block, 14) // ~10 KB
	if secret == "" {
		return base
	}
	mid := len(base) / 2
	return base[:mid] + secret + "\n" + base[mid:]
}

// secretLargeInput returns a ~100KB environment/config file. If secrets is non-nil,
// they are spread evenly throughout the file.
func secretLargeInput(secrets []string) string {
	const block = `# Application Configuration
export APP_ENV=production
export DATABASE_URL=postgres://appuser:secure_password@db.example.com:5432/appdb
export REDIS_URL=redis://cache.example.com:6379/0
export EMAIL_HOST=smtp.example.com
export EMAIL_FROM=noreply@example.com
export ENABLE_METRICS=true
export METRICS_ENDPOINT=http://metrics.example.com:9090/metrics
export LOG_LEVEL=error
export LOG_FORMAT=json
export API_BASE_URL=https://api.example.com/v2
export API_TIMEOUT=30000
export MAX_CONNECTIONS=100
export ENABLE_CACHE=true
export CACHE_TTL=3600
export SESSION_SECRET=change_me_in_production
export GITHUB_ORG=example-org
export GITHUB_REPO=example-repo
export AWS_REGION=us-east-1
export AWS_S3_BUCKET=example-data-bucket
export ENCRYPTION_KEY=replace_with_actual_key
`
	// ~100KB: block is ~450 bytes, repeat ~230 times
	repeat := (100 * 1024) / len(block)
	base := strings.Repeat(block, repeat)

	if len(secrets) == 0 {
		return base
	}

	// Spread secrets evenly through the file.
	result := []byte(base)
	step := len(result) / (len(secrets) + 1)
	offset := 0
	for i, secret := range secrets {
		pos := (i+1)*step + offset
		if pos > len(result) {
			pos = len(result)
		}
		line := []byte(secret + "\n")
		result = append(result[:pos], append(line, result[pos:]...)...)
		offset += len(line)
	}
	return string(result)
}

// urlProseInput returns a ~100KB block of prose-like text dense with alphabetic
// characters (high false-positive rate for [a-zA-Z] prefix) but containing no
// "://" sequences unless URLs are explicitly injected. Ideal for benchmarking
// non-prefix mandatory literal extraction for the [a-zA-Z]{2,8}://[^\s]+ pattern.
// sourceCodeInput returns ~100KB of C-style source code. singleLine comments are
// injected as // ... lines, blockComments as /* ... */ blocks, spread evenly.
// With nil slices the output contains no comment tokens at all.
func sourceCodeInput(singleLine, blockComments []string) string {
	const block = `int processRequest(Request *req, Response *resp) {
    if (req == NULL || resp == NULL) {
        return ERR_INVALID_ARG;
    }
    int status = validateHeaders(req->headers, req->headerCount);
    if (status != OK) {
        resp->statusCode = 400;
        setBody(resp, "Bad Request");
        return status;
    }
    Connection *conn = poolAcquire(globalPool, POOL_TIMEOUT_MS);
    if (conn == NULL) {
        resp->statusCode = 503;
        setBody(resp, "Service Unavailable");
        return ERR_NO_CONNECTION;
    }
    QueryResult result = executeQuery(conn, req->path, req->params);
    poolRelease(globalPool, conn);
    if (result.error != 0) {
        resp->statusCode = 500;
        setBody(resp, "Internal Server Error");
        return result.error;
    }
    resp->statusCode = 200;
    resp->body = result.data;
    resp->bodyLen = result.dataLen;
    return OK;
}

`
	repeat := (100 * 1024) / len(block)
	base := strings.Repeat(block, repeat)

	if len(singleLine) == 0 && len(blockComments) == 0 {
		return base
	}

	all := make([]string, 0, len(singleLine)+len(blockComments))
	for _, c := range singleLine {
		all = append(all, c)
	}
	for _, c := range blockComments {
		all = append(all, c)
	}

	result := []byte(base)
	step := len(result) / (len(all) + 1)
	offset := 0
	for i, comment := range all {
		pos := (i+1)*step + offset
		if pos > len(result) {
			pos = len(result)
		}
		line := []byte(comment + "\n")
		result = append(result[:pos], append(line, result[pos:]...)...)
		offset += len(line)
	}
	return string(result)
}

func urlProseInputSmall(urls []string) string {
	const block = `The application encountered an error while processing the request from the
client. The server returned status code four hundred and three, indicating that
the user does not have permission to access the requested resource. Please
contact your system administrator if you believe this is a mistake. The event
has been logged for review by the security team. Timestamp of the failure was
recorded along with the originating address and the affected service name.
`
	repeat := (10 * 1024) / len(block)
	base := strings.Repeat(block, repeat)
	if len(urls) == 0 {
		return base
	}
	result := []byte(base)
	step := len(result) / (len(urls) + 1)
	offset := 0
	for i, url := range urls {
		pos := (i+1)*step + offset
		if pos > len(result) {
			pos = len(result)
		}
		line := []byte("See " + url + " for details.\n")
		result = append(result[:pos], append(line, result[pos:]...)...)
		offset += len(line)
	}
	return string(result)
}

func urlProseInput(urls []string) string {
	const block = `The application encountered an error while processing the request from the
client. The server returned status code four hundred and three, indicating that
the user does not have permission to access the requested resource. Please
contact your system administrator if you believe this is a mistake. The event
has been logged for review by the security team. Timestamp of the failure was
recorded along with the originating address and the affected service name.
The retry policy specifies that failed requests are retried up to three times
with exponential backoff before being sent to the dead letter queue. Operators
should monitor the queue depth and alert threshold configured in the service
manifest. Configuration values must not contain unescaped special characters.
All field names are case sensitive and must match the schema definition exactly.
`
	repeat := (100 * 1024) / len(block)
	base := strings.Repeat(block, repeat)

	if len(urls) == 0 {
		return base
	}

	result := []byte(base)
	step := len(result) / (len(urls) + 1)
	offset := 0
	for i, url := range urls {
		pos := (i+1)*step + offset
		if pos > len(result) {
			pos = len(result)
		}
		line := []byte("See " + url + " for details.\n")
		result = append(result[:pos], append(line, result[pos:]...)...)
		offset += len(line)
	}
	return string(result)
}

// csvInput returns a 16-line CSV with 3 columns per row. Rows use a mix of
// unquoted fields, quoted fields containing commas, and fields with doubled
// quotes (RFC 4180 escaping). Exercises the Backtracking engine's
// non-anchored groups path.
func csvInput() string {
	return `John,Doe,john.doe@example.com
"Smith, Jr.",Alice,alice@example.com
Bob,"O'Brien, Jr.","bob@example.com"
"""Admin""",root,root@localhost
Carol,White,"carol.white@corp.example.com"
Dave,"Sales, EMEA",dave@corp.com
Eve,"R&D ""Lab""",eve@lab.example.com
Frank,,frank@example.com
"Grace, PhD","AI, ML",grace@uni.edu
Heidi,Blue,heidi@example.com
"Ivan ""The Terrible""","Marketing, Global",ivan@corp.com
Judy,Green,judy@example.com
"Karl, III","Finance, APAC",karl@corp.com
Laura,Red,laura@example.com
"Mallory ""M""","Ops, EU",mallory@corp.com
Niaj,Black,niaj@example.com
`
}

func sqlCleanInput() string {
	return "POST /search HTTP/1.1\r\nHost: example.com\r\nContent-Type: application/x-www-form-urlencoded\r\n\r\nq=" +
		strings.Repeat("a", 400) +
		"&page=1&sort=name&order=asc&limit=20&offset=0&filter=active&category=electronics"
}

func sqlInjectInput() string {
	return "POST /search HTTP/1.1\r\nHost: example.com\r\nContent-Type: application/x-www-form-urlencoded\r\n\r\nq=" +
		strings.Repeat("a", 200) + "' OR 1=1 --" + strings.Repeat("b", 200) +
		"&page=1"
}

// --------------------------------------------------------------------------
// Paths

const wasmTarget = "wasm32-wasip1"

func harnessWasm(dir, name string) string {
	return filepath.Join(dir, name, "target", wasmTarget, "release", name+".wasm")
}

// wasmMergePath is set by the --wasm-merge flag.
var wasmMergePath string

// wasmMerge returns the wasm-merge binary path from the flag, or "wasm-merge" for $PATH lookup.
func wasmMerge() string {
	if wasmMergePath != "" {
		return wasmMergePath
	}
	return "wasm-merge"
}

// --------------------------------------------------------------------------
// Measurement

var reNs        = regexp.MustCompile(`(?:match|find):\s*(\d+)ns`)
var reUs        = regexp.MustCompile(`compile:\s*(\d+)`)
var reResultAll = regexp.MustCompile(`result:(\S+)`)

// runHarness runs a pre-built WASM harness via wasmtime and parses timing output.
// results collects all "result:X" lines (excluding "result:done").
// For single-result modes (anchored, groups) results has one element.
// For find mode results holds all match spans.
func runHarness(harnessPath string, args ...string) (compileUs, opNs int64, results []string, err error) {
	cmdArgs := append([]string{"run", harnessPath}, args...)
	out, err := exec.Command("wasmtime", cmdArgs...).Output()
	if err != nil {
		return 0, 0, nil, err
	}
	s := string(out)
	if m := reUs.FindStringSubmatch(s); m != nil {
		compileUs, _ = strconv.ParseInt(m[1], 10, 64)
	}
	if m := reNs.FindStringSubmatch(s); m != nil {
		opNs, _ = strconv.ParseInt(m[1], 10, 64)
	}
	for _, m := range reResultAll.FindAllStringSubmatch(s, -1) {
		if m[1] == "done" {
			break
		}
		results = append(results, m[1])
	}
	return compileUs, opNs, results, nil
}

func resultsEqual(a, b []string) bool {
	if len(a) != len(b) {
		return false
	}
	for i := range a {
		if a[i] != b[i] {
			return false
		}
	}
	return true
}

// buildRegexped compiles pattern to WASM, merges with the harness, and returns
// the merged WASM path (caller must delete the temp file).
func buildRegexped(dir, harnessName, exportName string, mode compile.MatchMode, pattern string) (string, error) {
	opts := compile.CompileOptions{
		MaxDFAStates:  100000,
		ForceEngine:   compile.EngineDFA,
		Mode:          mode,
		LeftmostFirst: mode == compile.ModeFind, // required for non-greedy semantics in find mode
	}
	// Determine tableBase from the harness's Rust memory top so DFA tables don't overlap.
	harness := harnessWasm(dir, harnessName)
	rustTop, err := utils.RustMemTop(harness)  //nolint
	if err != nil {
		return "", fmt.Errorf("read harness memory: %w", err)
	}
	// Place DFA tables 512KB above rustTop to prevent overlap with the Rust heap.
	//
	// The Rust harnesses receive input as a WASI command-line argument (args[1]),
	// which the WASI runtime heap-allocates starting near __heap_base (≈ rustTop).
	// For a 100KB input the heap can grow to roughly rustTop + 100KB + runtime overhead
	// (~50KB), putting the heap top at rustTop + ~150KB. The 512KB margin keeps DFA
	// tables safely above that.
	//
	// If you add a test whose input exceeds ~350KB (i.e. rustTop + 512KB - ~150KB
	// runtime overhead), increase this margin accordingly, OR refactor the harnesses
	// to write input into a fixed buffer placed above the DFA tables instead of
	// passing it as a WASI command-line argument. See the "Fixed Input Buffer" plan
	// in the code comments / design notes for the proper long-term fix.
	tableBase := utils.PageAlign(rustTop + 512*1024)
	wasmBytes, _, err := compile.CompileRegex(pattern, exportName, tableBase, false, opts)
	if err != nil {
		return "", fmt.Errorf("compile: %w", err)
	}

	// Write pattern WASM to temp file.
	patTmp, err := os.CreateTemp("", "pattern-*.wasm")
	if err != nil {
		return "", err
	}
	patPath := patTmp.Name()
	patTmp.Write(wasmBytes)
	patTmp.Close()
	defer os.Remove(patPath)

	// Prepare merged output file.
	mergedTmp, err := os.CreateTemp("", "merged-*.wasm")
	if err != nil {
		return "", err
	}
	mergedPath := mergedTmp.Name()
	mergedTmp.Close()

	// Use merge.CmdMerge which handles memory patching and wasm-merge invocation.
	cfg := config.BuildConfig{
		WasmMerge: wasmMerge(),
		Regexes: []config.RegexEntry{
			{WasmFile: patPath, ImportModule: "pattern"},
		},
	}
	if err := merge.CmdMerge(cfg, mergedPath, []string{harness, patPath}); err != nil {
		os.Remove(mergedPath)
		return "", fmt.Errorf("merge: %w", err)
	}
	return mergedPath, nil
}

// buildRegexpedGroups compiles a pattern to a groups WASM (OnePass or
// Backtracking) and merges it with the groups harness.
func buildRegexpedGroups(dir, harnessName, exportName, pattern string) (string, error) {
	harness := harnessWasm(dir, harnessName)
	rustTop, err := utils.RustMemTop(harness)
	if err != nil {
		return "", fmt.Errorf("read harness memory: %w", err)
	}
	// Same 512KB margin as buildRegexped — see comment there for details and the
	// threshold above which this margin must be increased.
	tableBase := utils.PageAlign(rustTop + 512*1024)
	re := config.RegexEntry{Pattern: pattern, GroupsFunc: exportName}
	wasmBytes, _, err := compile.Compile([]config.RegexEntry{re}, tableBase, false)
	if err != nil {
		return "", fmt.Errorf("compile: %w", err)
	}

	patTmp, err := os.CreateTemp("", "pattern-*.wasm")
	if err != nil {
		return "", err
	}
	patPath := patTmp.Name()
	patTmp.Write(wasmBytes)
	patTmp.Close()
	defer os.Remove(patPath)

	mergedTmp, err := os.CreateTemp("", "merged-*.wasm")
	if err != nil {
		return "", err
	}
	mergedPath := mergedTmp.Name()
	mergedTmp.Close()

	cfg := config.BuildConfig{
		WasmMerge: wasmMerge(),
		Regexes:   []config.RegexEntry{{WasmFile: patPath, ImportModule: "pattern"}},
	}
	if err := merge.CmdMerge(cfg, mergedPath, []string{harness, patPath}); err != nil {
		os.Remove(mergedPath)
		return "", fmt.Errorf("merge: %w", err)
	}
	return mergedPath, nil
}

// --------------------------------------------------------------------------
// Table output

type row struct {
	label      string
	compileUs  int64 // regex crate compile time (µs); shown only on first input
	regexNs    int64
	regexpedNs int64
}

const (
	wLabel    = 28
	wCompile  = 14
	wRegex    = 12
	wRegexped = 12
	wSpeedup  = 8
)

func printTable(tc testCase, rows []row) {
	modeStr := "anchored"
	switch tc.mode {
	case find:
		modeStr = "find"
	case anchoredGroups:
		modeStr = "groups"
	}

	sep := strings.Repeat("─", wLabel+2) + "┼" +
		strings.Repeat("─", wCompile+2) + "┼" +
		strings.Repeat("─", wRegex+2) + "┼" +
		strings.Repeat("─", wRegexped+2) + "┼" +
		strings.Repeat("─", wSpeedup+2)

	fmt.Printf("\nPattern: %-20s [%s]\n", tc.name, modeStr)
	fmt.Printf("  %-*s  %-*s  %-*s  %-*s  %-*s\n",
		wLabel, "input",
		wCompile, "regex compile",
		wRegex, "regex crate",
		wRegexped, "regexped",
		wSpeedup, "speedup")
	fmt.Printf("  %s\n", sep)

	for _, r := range rows {
		compileStr := ""
		if r.compileUs > 0 {
			compileStr = fmt.Sprintf("%dµs", r.compileUs)
		}
		speedup := ""
		if r.regexNs > 0 && r.regexpedNs > 0 {
			ratio := float64(r.regexNs) / float64(r.regexpedNs)
			if ratio >= 1.0 {
				speedup = fmt.Sprintf("%.1f×", ratio)
			} else {
				speedup = fmt.Sprintf("%.2f×", ratio)
			}
		}
		fmt.Printf("  %-*s  %-*s  %-*s  %-*s  %-*s\n",
			wLabel, truncate(r.label, wLabel),
			wCompile, compileStr,
			wRegex, fmtNs(r.regexNs),
			wRegexped, fmtNs(r.regexpedNs),
			wSpeedup, speedup)
	}
}

func fmtNs(ns int64) string {
	if ns <= 0 {
		return "-"
	}
	return fmt.Sprintf("%dns", ns)
}

func truncate(s string, max int) string {
	if len(s) <= max {
		return s
	}
	return s[:max-1] + "…"
}

// --------------------------------------------------------------------------
// Main

func main() {
	flag.StringVar(&wasmMergePath, "wasm-merge", "", "path to wasm-merge binary (default: search $PATH)")
	flag.Parse()

	// Silence library log output — only the table goes to stdout.
	slog.SetDefault(slog.New(slog.NewTextHandler(io.Discard, nil)))

	dir, _ := os.Getwd()

	for _, tc := range tests {
		isGroups := tc.mode == anchoredGroups

		// Select harnesses.
		var regexHarness, regexpedHarness, exportName string
		switch tc.mode {
		case find:
			regexHarness = harnessWasm(dir, "regex_find_harness")
			regexpedHarness = "regexped_find_harness"
			exportName = "pattern_find"
		case anchoredGroups:
			regexHarness = harnessWasm(dir, "regex_groups_harness")
			regexpedHarness = "regexped_groups_harness"
			exportName = "groups"
		default:
			regexHarness = harnessWasm(dir, "regex_harness")
			regexpedHarness = "regexped_harness"
			exportName = "pattern_match"
		}

		// Build merged regexped WASM once per pattern.
		fmt.Fprintf(os.Stderr, "==> compiling %s...\n", tc.name)
		var mergedPath string
		var err error
		if isGroups {
			mergedPath, err = buildRegexpedGroups(dir, regexpedHarness, exportName, tc.pattern)
		} else {
			compileMode := compile.ModeAnchoredMatch
			if tc.mode == find {
				compileMode = compile.ModeFind
			}
			mergedPath, err = buildRegexped(dir, regexpedHarness, exportName, compileMode, tc.pattern)
		}
		if err != nil {
			fmt.Fprintf(os.Stderr, "SKIP %s: %v\n", tc.name, err)
			continue
		}
		defer os.Remove(mergedPath)

		var rows []row
		var sharedCompileUs int64

		for i, inp := range tc.inputs {
			// Regex crate timing + result.
			compileUs, regexNs, regexResult, hErr := runHarness(regexHarness, tc.pattern, inp.value)
			if hErr != nil {
				fmt.Fprintf(os.Stderr, "  warn: regex harness failed for %q: %v\n", inp.label, hErr)
			}
			if i == 0 {
				sharedCompileUs = compileUs
			}

			// Regexped timing + result.
			_, regexpedNs, regexpedResult, rErr := runHarness(mergedPath, inp.value)
			if rErr != nil {
				fmt.Fprintf(os.Stderr, "  warn: regexped harness failed for %q: %v\n", inp.label, rErr)
			}

			// Correctness check: compare all results (all matches for find, single for others).
			if len(regexResult) > 0 && len(regexpedResult) > 0 && !resultsEqual(regexResult, regexpedResult) {
				fmt.Fprintf(os.Stderr, "  MISMATCH %s / %q: regex=%v regexped=%v\n",
					tc.name, inp.label, regexResult, regexpedResult)
			}

			r := row{
				label:      inp.label,
				regexNs:    regexNs,
				regexpedNs: regexpedNs,
			}
			if i == 0 {
				r.compileUs = sharedCompileUs
			}
			rows = append(rows, r)
		}

		printTable(tc, rows)
	}
	fmt.Println()
}
