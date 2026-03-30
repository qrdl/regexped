// perftest benchmarks regexped WASM against the regex crate and prints a summary table.
//
// Run from the perftest/ directory:
//
//	cd perftest && make run
package main

import (
	"flag"
	"fmt"
	"io"
	"log/slog"
	"os"
	"path/filepath"
	"strings"
	"time"

	wasmtime "github.com/bytecodealliance/wasmtime-go/v42"
	"github.com/qrdl/regexped/compile"
	"github.com/qrdl/regexped/config"
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
		// Email domain filter — non-anchored find with alternating literal "@foo.com"|"@bar.com".
		// Baseline for the split-pattern non-anchored optimisation (Part 2).
		// The literal alternation (foo|bar) sits at a bounded interior offset;
		// currently the firstByteFlags scan fires on every alphabetic character.
		name:    "email-domain-find",
		pattern: `[a-zA-Z0-9_%+\-]+(?:\.[a-zA-Z0-9_%+\-]+)*@(foo|bar)\.com`,
		mode:    find,
		inputs: []namedInput{
			{"no-match 10KB", emailDomainInput(nil)},
			{"5 matches 10KB", emailDomainInput([]string{
				"alice@foo.com",
				"bob.smith@bar.com",
				"carol@foo.com",
				"dave.r@bar.com",
				"eve@foo.com",
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
			{"comments 100KB", sourceCodeInput(
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
	// (?m:^...multiline...$) makes ^ and $ match at line boundaries so the
	// non-anchored groups wrapper scans a multi-line log and extracts one
	// match per ERROR/WARNING/FATAL line.
	{
		name:    "log-capture",
		pattern: `(?m:^(\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}) .*(ERROR|WARNING|FATAL): (.+)$)`,
		mode:    anchoredGroups,
		inputs: []namedInput{
			{"few matches", logInput(true)},
			{"no matches", logInput(false)},
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

// logInput returns a 20-line structured log. If withErrors is true, 4 lines
// are ERROR/WARNING/FATAL entries that match the log-capture pattern; the
// rest are INFO/DEBUG lines that do not match.
func logInput(withErrors bool) string {
	info := "2026-03-22T14:05:00 app[1] INFO: server started on port 8080\n" +
		"2026-03-22T14:05:01 app[1] DEBUG: accepted connection from 10.0.0.5:54321\n" +
		"2026-03-22T14:05:02 db.pool[3] INFO: acquired connection from pool (idle=4)\n" +
		"2026-03-22T14:05:03 cache[2] DEBUG: cache hit for key user:1042\n" +
		"2026-03-22T14:05:04 app[1] INFO: GET /api/v1/users/1042 200 3ms\n" +
		"2026-03-22T14:05:05 app[1] DEBUG: accepted connection from 10.0.0.6:54322\n" +
		"2026-03-22T14:05:06 cache[2] DEBUG: cache miss for key user:9999\n" +
		"2026-03-22T14:05:07 db.pool[3] INFO: query executed in 12ms rows=1\n" +
		"2026-03-22T14:05:08 app[1] INFO: GET /api/v1/users/9999 200 15ms\n" +
		"2026-03-22T14:05:09 app[1] DEBUG: connection from 10.0.0.5:54321 closed\n" +
		"2026-03-22T14:05:10 app[1] INFO: GET /healthz 200 1ms\n" +
		"2026-03-22T14:05:11 db.pool[3] DEBUG: pool stats: active=2 idle=3 waiting=0\n" +
		"2026-03-22T14:05:12 cache[2] INFO: evicted 128 entries (maxmem reached)\n" +
		"2026-03-22T14:05:13 app[1] INFO: POST /api/v1/jobs 202 8ms\n" +
		"2026-03-22T14:05:14 worker[5] DEBUG: job 7f3a picked up by worker pool\n" +
		"2026-03-22T14:05:15 worker[5] INFO: job 7f3a completed in 340ms\n"
	if !withErrors {
		return info
	}
	return "2026-03-22T14:05:00 app[1] INFO: server started on port 8080\n" +
		"2026-03-22T14:05:01 app[1] DEBUG: accepted connection from 10.0.0.5:54321\n" +
		"2026-03-22T14:05:02 db.pool[3] ERROR: connection refused after 3 retries\n" +
		"2026-03-22T14:05:03 cache[2] DEBUG: cache miss for key user:9999\n" +
		"2026-03-22T14:05:04 app[1] INFO: GET /api/v1/users/1042 200 3ms\n" +
		"2026-03-22T14:05:05 service.worker.pool[7] WARNING: queue depth 9823 exceeds threshold 5000, consider scaling\n" +
		"2026-03-22T14:05:06 cache[2] DEBUG: cache miss for key session:abc\n" +
		"2026-03-22T14:05:07 db.pool[3] INFO: query executed in 12ms rows=1\n" +
		"2026-03-22T14:05:08 app[1] ERROR: panic in handler: runtime error: index out of range [3] with length 3\n" +
		"2026-03-22T14:05:09 app[1] DEBUG: connection from 10.0.0.5:54321 closed\n" +
		"2026-03-22T14:05:10 app[1] INFO: GET /healthz 200 1ms\n" +
		"2026-03-22T14:05:11 db.pool[3] DEBUG: pool stats: active=2 idle=3 waiting=0\n" +
		"2026-03-22T14:05:12 db.connection.manager[1] FATAL: unable to acquire lock on table users after 30000ms, shutting down\n" +
		"2026-03-22T14:05:13 app[1] INFO: POST /api/v1/jobs 202 8ms\n" +
		"2026-03-22T14:05:14 worker[5] DEBUG: job 7f3a picked up by worker pool\n" +
		"2026-03-22T14:05:15 worker[5] INFO: job 7f3a completed in 340ms\n"
}

// emailDomainInput returns a ~10KB block of prose with realistic email addresses
// at various domains (example.com, corp.org, etc.) but no @foo.com or @bar.com
// occurrences unless explicitly injected. The '@' character appears frequently,
// giving the first-byte scanner many false-positive candidates.
func emailDomainInput(emails []string) string {
	const block = `Team update: contact support@example.com or helpdesk@corp.org for account issues.
New registrations: user@company.org, admin@example.net, noreply@platform.io.
Deployment alerts go to devops@internal.io and pagerduty@monitoring.net.
Unsubscribe via newsletter@example.com; billing queries to billing@vendor.example.com.
Security events forwarded to sec@example.com and abuse@example.com for triage.
Service account: service@platform.example.com; CI notifications: ci@build.example.com.
`
	repeat := (10 * 1024) / len(block)
	base := strings.Repeat(block, repeat)
	if len(emails) == 0 {
		return base
	}
	result := []byte(base)
	step := len(result) / (len(emails) + 1)
	offset := 0
	for i, email := range emails {
		pos := (i+1)*step + offset
		if pos > len(result) {
			pos = len(result)
		}
		line := []byte("Contact " + email + " for domain-specific support.\n")
		result = append(result[:pos], append(line, result[pos:]...)...)
		offset += len(line)
	}
	return string(result)
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
// Constants and types

const (
	// inputBase is where test inputs are written in regexped WASM memory.
	inputBase = int32(0)
	// tableBase is the start of DFA/OnePass tables; must be page-aligned and above input.
	// The largest test inputs are ~100 KB (102400 bytes), so tableBase must be at least
	// pageAlign(102400) = 131072 to prevent inputs written at inputBase=0 from overwriting
	// the DFA table data segment.
	tableBase = int64(131072) // page 2; pages 0-1 are reserved for input
	// slotsBase is where capture output slots are written for groups calls.
	slotsBase = int32(512)
	// benchIters is the number of iterations run inside WASM per benchmark call.
	// The loop executes entirely within WASM so CGo overhead is paid only once.
	benchIters = 100_000
)

type benchResult struct {
	instantiation time.Duration
	compilation   time.Duration // zero means n/a (regexped has no runtime compilation)
	avgExec       time.Duration
	wasmSize      int
}

// --------------------------------------------------------------------------
// Bench shim WASM modules
//
// Each shim imports one regexped function and loops it benchIters times.
// The shim is instantiated via NewInstance with the regexped export as the
// single extern — no Linker needed. One Go→WASM call per benchmark, so
// CGo overhead is amortised across all iterations.
//
// Hand-encoded WASM binary format. Sections in order:
//
//	magic+version, type, import, function, export, code
//
// matchBenchShim: imports "regexped"."match" (i32,i32)->i32
//
//	exports "bench"            (i32,i32,i32)->void
var matchBenchShim = []byte{
	0x00, 0x61, 0x73, 0x6d, 0x01, 0x00, 0x00, 0x00, // magic, version
	// type section: (i32,i32)->i32 ; (i32,i32,i32)->void
	0x01, 0x0d, 0x02,
	0x60, 0x02, 0x7f, 0x7f, 0x01, 0x7f,
	0x60, 0x03, 0x7f, 0x7f, 0x7f, 0x00,
	// import section: "regexped"."match" = func type 0
	0x02, 0x12, 0x01,
	0x08, 0x72, 0x65, 0x67, 0x65, 0x78, 0x70, 0x65, 0x64,
	0x05, 0x6d, 0x61, 0x74, 0x63, 0x68,
	0x00, 0x00,
	// function section: 1 func of type 1
	0x03, 0x02, 0x01, 0x01,
	// export section: "bench" -> func 1
	0x07, 0x09, 0x01, 0x05, 0x62, 0x65, 0x6e, 0x63, 0x68, 0x00, 0x01,
	// code section: bench body (ptr,len,iters; local i)
	0x0a, 0x23, 0x01, 0x21, 0x01, 0x01, 0x7f,
	0x02, 0x40, 0x03, 0x40,
	0x20, 0x03, 0x20, 0x02, 0x4e, 0x0d, 0x01,
	0x20, 0x00, 0x20, 0x01, 0x10, 0x00, 0x1a,
	0x20, 0x03, 0x41, 0x01, 0x6a, 0x21, 0x03,
	0x0c, 0x00, 0x0b, 0x0b, 0x0b,
}

// findBenchShim: imports "regexped"."find" (i32,i32)->i64
//
//	exports "bench"           (i32,i32,i32)->void
var findBenchShim = []byte{
	0x00, 0x61, 0x73, 0x6d, 0x01, 0x00, 0x00, 0x00,
	// type section: (i32,i32)->i64 ; (i32,i32,i32)->void
	0x01, 0x0d, 0x02,
	0x60, 0x02, 0x7f, 0x7f, 0x01, 0x7e, // note 0x7e = i64
	0x60, 0x03, 0x7f, 0x7f, 0x7f, 0x00,
	// import section: "regexped"."find" = func type 0
	0x02, 0x11, 0x01,
	0x08, 0x72, 0x65, 0x67, 0x65, 0x78, 0x70, 0x65, 0x64,
	0x04, 0x66, 0x69, 0x6e, 0x64,
	0x00, 0x00,
	0x03, 0x02, 0x01, 0x01,
	0x07, 0x09, 0x01, 0x05, 0x62, 0x65, 0x6e, 0x63, 0x68, 0x00, 0x01,
	0x0a, 0x23, 0x01, 0x21, 0x01, 0x01, 0x7f,
	0x02, 0x40, 0x03, 0x40,
	0x20, 0x03, 0x20, 0x02, 0x4e, 0x0d, 0x01,
	0x20, 0x00, 0x20, 0x01, 0x10, 0x00, 0x1a,
	0x20, 0x03, 0x41, 0x01, 0x6a, 0x21, 0x03,
	0x0c, 0x00, 0x0b, 0x0b, 0x0b,
}

// groupsBenchShim: imports "regexped"."groups" (i32,i32,i32)->i32
//
//	exports "bench"             (i32,i32,i32,i32)->void
var groupsBenchShim = []byte{
	0x00, 0x61, 0x73, 0x6d, 0x01, 0x00, 0x00, 0x00,
	// type section: (i32,i32,i32)->i32 ; (i32,i32,i32,i32)->void
	0x01, 0x0f, 0x02,
	0x60, 0x03, 0x7f, 0x7f, 0x7f, 0x01, 0x7f,
	0x60, 0x04, 0x7f, 0x7f, 0x7f, 0x7f, 0x00,
	// import section: "regexped"."groups" = func type 0
	0x02, 0x13, 0x01,
	0x08, 0x72, 0x65, 0x67, 0x65, 0x78, 0x70, 0x65, 0x64,
	0x06, 0x67, 0x72, 0x6f, 0x75, 0x70, 0x73,
	0x00, 0x00,
	0x03, 0x02, 0x01, 0x01,
	0x07, 0x09, 0x01, 0x05, 0x62, 0x65, 0x6e, 0x63, 0x68, 0x00, 0x01,
	// code section: bench body (ptr,len,out_ptr,iters; local i)
	0x0a, 0x25, 0x01, 0x23, 0x01, 0x01, 0x7f,
	0x02, 0x40, 0x03, 0x40,
	0x20, 0x04, 0x20, 0x03, 0x4e, 0x0d, 0x01,
	0x20, 0x00, 0x20, 0x01, 0x20, 0x02, 0x10, 0x00, 0x1a,
	0x20, 0x04, 0x41, 0x01, 0x6a, 0x21, 0x04,
	0x0c, 0x00, 0x0b, 0x0b, 0x0b,
}

// --------------------------------------------------------------------------
// Warmup

// minimalWASM is the smallest valid WASM module: magic + version, no sections.
var minimalWASM = []byte{0x00, 0x61, 0x73, 0x6d, 0x01, 0x00, 0x00, 0x00}

// warmup compiles a trivial WASM module to bring Cranelift's JIT machinery into CPU
// i-cache before the first real instantiation measurement.
func warmup(engine *wasmtime.Engine) {
	mod, err := wasmtime.NewModule(engine, minimalWASM)
	if err != nil {
		return
	}
	store := wasmtime.NewStore(engine)
	_, _ = wasmtime.NewInstance(store, mod, []wasmtime.AsExtern{})
}

// --------------------------------------------------------------------------
// Benchmark helpers

// regexpedEngineName returns the name of the engine regexped uses for this test case.
func regexpedEngineName(tc testCase) string {
	if tc.mode != anchoredGroups {
		// Captures are stripped for anchored/find modes; engine is always DFA.
		return "DFA"
	}
	opts := compile.CompileOptions{MaxDFAStates: 100000}
	et, err := compile.SelectEngine(tc.pattern, opts)
	if err != nil {
		return "?"
	}
	return et.String()
}

// benchRegexped compiles tc.pattern to a standalone WASM module and benchmarks
// instantiation and execution. Execution is timed via a bench shim WASM that
// imports the regexped function and loops benchIters times internally — only
// one CGo crossing for the entire measurement.
func benchRegexped(tc testCase, input string, engine *wasmtime.Engine) benchResult {
	re := config.RegexEntry{Pattern: tc.pattern}
	var fnExport string
	switch tc.mode {
	case anchored:
		re.MatchFunc = "match"
		fnExport = "match"
	case find:
		re.FindFunc = "find"
		fnExport = "find"
	case anchoredGroups:
		re.GroupsFunc = "groups"
		fnExport = "groups"
	}
	wasmBytes, _, err := compile.Compile([]config.RegexEntry{re}, tableBase, true)
	if err != nil {
		fmt.Fprintf(os.Stderr, "  regexped compile(%s): %v\n", tc.name, err)
		return benchResult{}
	}

	// Measure JIT instantiation of the regexped module.
	t0 := time.Now()
	mod, err := wasmtime.NewModule(engine, wasmBytes)
	if err != nil {
		fmt.Fprintf(os.Stderr, "  regexped NewModule(%s): %v\n", tc.name, err)
		return benchResult{}
	}
	store := wasmtime.NewStore(engine)
	inst, err := wasmtime.NewInstance(store, mod, []wasmtime.AsExtern{})
	if err != nil {
		fmt.Fprintf(os.Stderr, "  regexped NewInstance(%s): %v\n", tc.name, err)
		return benchResult{}
	}
	instantiation := time.Since(t0)

	// Get memory and the exported function.
	var mem *wasmtime.Memory
	if exp := inst.GetExport(store, "memory"); exp != nil {
		mem = exp.Memory()
	}
	rpdFn := inst.GetFunc(store, fnExport)
	if rpdFn == nil || mem == nil {
		fmt.Fprintf(os.Stderr, "  regexped: missing export for %s\n", tc.name)
		return benchResult{instantiation: instantiation}
	}

	// Instantiate the bench shim with the regexped function as its single import.
	var shimBytes []byte
	switch tc.mode {
	case anchored:
		shimBytes = matchBenchShim
	case find:
		shimBytes = findBenchShim
	case anchoredGroups:
		shimBytes = groupsBenchShim
	}
	shimMod, err := wasmtime.NewModule(engine, shimBytes)
	if err != nil {
		fmt.Fprintf(os.Stderr, "  regexped shim parse(%s): %v\n", tc.name, err)
		return benchResult{instantiation: instantiation}
	}
	shimInst, err := wasmtime.NewInstance(store, shimMod, []wasmtime.AsExtern{rpdFn})
	if err != nil {
		fmt.Fprintf(os.Stderr, "  regexped shim instantiate(%s): %v\n", tc.name, err)
		return benchResult{instantiation: instantiation}
	}
	benchFn := shimInst.GetFunc(store, "bench")
	if benchFn == nil {
		fmt.Fprintf(os.Stderr, "  regexped shim: missing bench export for %s\n", tc.name)
		return benchResult{instantiation: instantiation}
	}

	// Write input into regexped's memory and make a single timed call.
	buf := mem.UnsafeData(store)
	copy(buf[inputBase:], []byte(input))
	inputLen := int32(len(input))

	var callErr error
	t1 := time.Now()
	if tc.mode == anchoredGroups {
		_, callErr = benchFn.Call(store, inputBase, inputLen, slotsBase, int32(benchIters))
	} else {
		_, callErr = benchFn.Call(store, inputBase, inputLen, int32(benchIters))
	}
	total := time.Since(t1)
	if callErr != nil {
		fmt.Fprintf(os.Stderr, "  regexped bench(%s): %v\n", tc.name, callErr)
		return benchResult{instantiation: instantiation}
	}

	return benchResult{
		instantiation: instantiation,
		avgExec:       total / benchIters,
		wasmSize:      len(wasmBytes),
	}
}

// benchRegex instantiates regex_bench.wasm, compiles the pattern via regex_init,
// and times execution via the internal-timing regex_bench_* functions.
// A single Go→WASM call runs benchIters iterations internally and returns
// total nanoseconds, eliminating CGo overhead from the per-iteration measurement.
func benchRegex(regexWasmBytes []byte, tc testCase, input string, engine *wasmtime.Engine) benchResult {
	// Measure JIT instantiation (NewModule + linker.Instantiate).
	t0 := time.Now()
	mod, err := wasmtime.NewModule(engine, regexWasmBytes)
	if err != nil {
		fmt.Fprintf(os.Stderr, "  regex NewModule(%s): %v\n", tc.name, err)
		return benchResult{}
	}
	linker := wasmtime.NewLinker(engine)
	if err = linker.DefineWasi(); err != nil {
		fmt.Fprintf(os.Stderr, "  regex DefineWasi(%s): %v\n", tc.name, err)
		return benchResult{}
	}
	store := wasmtime.NewStore(engine)
	store.SetWasi(wasmtime.NewWasiConfig())
	inst, err := linker.Instantiate(store, mod)
	if err != nil {
		fmt.Fprintf(os.Stderr, "  regex Instantiate(%s): %v\n", tc.name, err)
		return benchResult{}
	}
	instantiation := time.Since(t0)

	// Get exported functions and memory.
	var mem *wasmtime.Memory
	if exp := inst.GetExport(store, "memory"); exp != nil {
		mem = exp.Memory()
	}
	getPtrFn := inst.GetFunc(store, "get_input_ptr")
	initFn := inst.GetFunc(store, "regex_init")
	var benchExecFn *wasmtime.Func
	switch tc.mode {
	case anchored:
		benchExecFn = inst.GetFunc(store, "regex_bench_match")
	case find:
		benchExecFn = inst.GetFunc(store, "regex_bench_find")
	case anchoredGroups:
		benchExecFn = inst.GetFunc(store, "regex_bench_groups")
	}
	if mem == nil || getPtrFn == nil || initFn == nil || benchExecFn == nil {
		fmt.Fprintf(os.Stderr, "  regex: missing export for %s\n", tc.name)
		return benchResult{instantiation: instantiation}
	}

	// Get the address of the static input buffer inside WASM.
	ptrRes, err := getPtrFn.Call(store)
	if err != nil {
		fmt.Fprintf(os.Stderr, "  regex get_input_ptr(%s): %v\n", tc.name, err)
		return benchResult{instantiation: instantiation}
	}
	inputPtr := int(ptrRes.(int32))
	buf := mem.UnsafeData(store)

	// Write pattern and time regex compilation.
	pat := tc.pattern
	if tc.mode == anchored {
		pat = "^(?:" + tc.pattern + ")$"
	}
	patBytes := []byte(pat)
	copy(buf[inputPtr:], patBytes)
	t1 := time.Now()
	_, err = initFn.Call(store, int32(len(patBytes)))
	compilation := time.Since(t1)
	if err != nil {
		fmt.Fprintf(os.Stderr, "  regex_init(%s): %v\n", tc.name, err)
		return benchResult{instantiation: instantiation}
	}

	// Write input and call the bench function once — it loops internally and
	// returns total nanoseconds via std::time::Instant.
	copy(buf[inputPtr:], []byte(input))
	inputLen := int32(len(input))

	nsRes, callErr := benchExecFn.Call(store, inputLen, int32(benchIters))
	if callErr != nil {
		fmt.Fprintf(os.Stderr, "  regex bench(%s): %v\n", tc.name, callErr)
		return benchResult{instantiation: instantiation, compilation: compilation}
	}
	totalNs := nsRes.(int64)

	return benchResult{
		instantiation: instantiation,
		compilation:   compilation,
		avgExec:       time.Duration(totalNs / int64(benchIters)),
		wasmSize:      len(regexWasmBytes),
	}
}

// --------------------------------------------------------------------------
// Output

func fmtDur(d time.Duration) string {
	if d == 0 {
		return "n/a"
	}
	if d >= time.Millisecond {
		return fmt.Sprintf("%.2f ms", float64(d)/float64(time.Millisecond))
	}
	if d >= time.Microsecond {
		return fmt.Sprintf("%.1f µs", float64(d)/float64(time.Microsecond))
	}
	return fmt.Sprintf("%d ns", d.Nanoseconds())
}

func fmtSize(n int) string {
	if n == 0 {
		return "n/a"
	}
	if n >= 1024 {
		return fmt.Sprintf("%.1f KB", float64(n)/1024)
	}
	return fmt.Sprintf("%d B", n)
}

func fmtRatio(rped, rxp time.Duration) string {
	if rped == 0 || rxp == 0 {
		return "n/a"
	}
	return fmt.Sprintf("%.2fx", float64(rxp)/float64(rped))
}

type inputResult struct {
	label   string
	size    int
	rxpAvg  time.Duration
	rpedAvg time.Duration
}

func printResults(tc testCase, engineName string, rxp, rped benchResult, inputs []inputResult, full bool) {
	modeStr := "anchored"
	switch tc.mode {
	case find:
		modeStr = "find"
	case anchoredGroups:
		modeStr = "groups"
	}
	fmt.Printf("\n=== %s  [%s, %s] ===\n", tc.name, engineName, modeStr)
	fmt.Printf("  %-26s  %14s  %14s  %8s\n", "", "regex", "regexped", "ratio")
	if full {
		fmt.Printf("  %-26s  %14s  %14s  %8s\n",
			"instantiation:",
			fmtDur(rxp.instantiation),
			fmtDur(rped.instantiation),
			fmtRatio(rped.instantiation, rxp.instantiation))
		fmt.Printf("  %-26s  %14s  %14s\n",
			"wasm size:",
			fmtSize(rxp.wasmSize),
			fmtSize(rped.wasmSize))
		fmt.Printf("  %-26s  %14s\n",
			"compilation:",
			fmtDur(rxp.compilation))
	}
	for _, inp := range inputs {
		fmt.Printf("\n  input: %s (%d bytes)\n", inp.label, inp.size)
		fmt.Printf("    %-24s  %14s  %14s  %8s\n",
			"avg execution:",
			fmtDur(inp.rxpAvg),
			fmtDur(inp.rpedAvg),
			fmtRatio(inp.rpedAvg, inp.rxpAvg))
	}
}

// --------------------------------------------------------------------------
// Fuel measurement

const fuelBudget = uint64(10_000_000_000) // 10 billion units; enough for any test input

type fuelInputResult struct {
	label    string
	size     int
	rxpFuel  uint64
	rpedFuel uint64
}

// measFuelRegexped compiles tc.pattern, instantiates the module with a fuel-enabled
// store, then measures fuel consumed by a single exported function call.
func measFuelRegexped(tc testCase, input string, fuelEngine *wasmtime.Engine) (uint64, bool) {
	re := config.RegexEntry{Pattern: tc.pattern}
	var fnExport string
	switch tc.mode {
	case anchored:
		re.MatchFunc = "match"
		fnExport = "match"
	case find:
		re.FindFunc = "find"
		fnExport = "find"
	case anchoredGroups:
		re.GroupsFunc = "groups"
		fnExport = "groups"
	}
	wasmBytes, _, err := compile.Compile([]config.RegexEntry{re}, tableBase, true)
	if err != nil {
		fmt.Fprintf(os.Stderr, "  fuel regexped compile(%s): %v\n", tc.name, err)
		return 0, false
	}
	mod, err := wasmtime.NewModule(fuelEngine, wasmBytes)
	if err != nil {
		return 0, false
	}
	store := wasmtime.NewStore(fuelEngine)
	if err := store.SetFuel(fuelBudget); err != nil {
		return 0, false
	}
	inst, err := wasmtime.NewInstance(store, mod, []wasmtime.AsExtern{})
	if err != nil {
		return 0, false
	}
	var mem *wasmtime.Memory
	if exp := inst.GetExport(store, "memory"); exp != nil {
		mem = exp.Memory()
	}
	fn := inst.GetFunc(store, fnExport)
	if fn == nil || mem == nil {
		return 0, false
	}
	buf := mem.UnsafeData(store)
	copy(buf[inputBase:], []byte(input))
	inputLen := int32(len(input))

	before, _ := store.GetFuel()
	var callErr error
	if tc.mode == anchoredGroups {
		_, callErr = fn.Call(store, inputBase, inputLen, slotsBase)
	} else {
		_, callErr = fn.Call(store, inputBase, inputLen)
	}
	after, _ := store.GetFuel()
	if callErr != nil {
		fmt.Fprintf(os.Stderr, "  fuel regexped call(%s): %v\n", tc.name, callErr)
		return 0, false
	}
	return before - after, true
}

// measFuelRegex instantiates the regex harness, compiles the pattern, warms up the
// lazy DFA with one uncounted call, then measures fuel for a single direct match call.
// Uses regex_match/find/groups directly (no bench wrapper) to avoid Instant::now overhead.
func measFuelRegex(regexWasmBytes []byte, tc testCase, input string, fuelEngine *wasmtime.Engine) (uint64, bool) {
	mod, err := wasmtime.NewModule(fuelEngine, regexWasmBytes)
	if err != nil {
		return 0, false
	}
	linker := wasmtime.NewLinker(fuelEngine)
	if err = linker.DefineWasi(); err != nil {
		return 0, false
	}
	store := wasmtime.NewStore(fuelEngine)
	store.SetWasi(wasmtime.NewWasiConfig())
	if err := store.SetFuel(fuelBudget); err != nil {
		return 0, false
	}
	inst, err := linker.Instantiate(store, mod)
	if err != nil {
		return 0, false
	}
	var mem *wasmtime.Memory
	if exp := inst.GetExport(store, "memory"); exp != nil {
		mem = exp.Memory()
	}
	getPtrFn := inst.GetFunc(store, "get_input_ptr")
	initFn := inst.GetFunc(store, "regex_init")
	// Use direct match functions (no bench wrapper) to avoid Instant::now/elapsed fuel.
	var execFn *wasmtime.Func
	switch tc.mode {
	case anchored:
		execFn = inst.GetFunc(store, "regex_match")
	case find:
		execFn = inst.GetFunc(store, "regex_find")
	case anchoredGroups:
		execFn = inst.GetFunc(store, "regex_groups")
	}
	if mem == nil || getPtrFn == nil || initFn == nil || execFn == nil {
		return 0, false
	}
	ptrRes, err := getPtrFn.Call(store)
	if err != nil {
		return 0, false
	}
	inputPtr := int(ptrRes.(int32))
	buf := mem.UnsafeData(store)
	pat := tc.pattern
	if tc.mode == anchored {
		pat = "^(?:" + tc.pattern + ")$"
	}
	copy(buf[inputPtr:], []byte(pat))
	if _, err = initFn.Call(store, int32(len([]byte(pat)))); err != nil {
		return 0, false
	}
	copy(buf[inputPtr:], []byte(input))
	// Warm-up call: the regex crate uses a lazy DFA that builds states on first use.
	// This uncounted call lets it reach steady state before we measure fuel.
	if _, err = execFn.Call(store, int32(len(input))); err != nil {
		return 0, false
	}
	// Measure a single steady-state call.
	before, _ := store.GetFuel()
	if _, err = execFn.Call(store, int32(len(input))); err != nil {
		fmt.Fprintf(os.Stderr, "  fuel regex call(%s): %v\n", tc.name, err)
		return 0, false
	}
	after, _ := store.GetFuel()
	return before - after, true
}

func fmtFuel(n uint64) string {
	if n == 0 {
		return "n/a"
	}
	s := fmt.Sprintf("%d", n)
	var b []byte
	for i, c := range s {
		if i > 0 && (len(s)-i)%3 == 0 {
			b = append(b, ',')
		}
		b = append(b, byte(c))
	}
	return string(b)
}

func printFuelResults(tc testCase, engineName string, inputs []fuelInputResult) {
	modeStr := "anchored"
	switch tc.mode {
	case find:
		modeStr = "find"
	case anchoredGroups:
		modeStr = "groups"
	}
	fmt.Printf("\n=== %s  [%s, %s] ===\n", tc.name, engineName, modeStr)
	fmt.Printf("  %-26s  %14s  %14s  %8s\n", "", "regex", "regexped", "ratio")
	for _, inp := range inputs {
		fmt.Printf("\n  input: %s (%d bytes)\n", inp.label, inp.size)
		ratio := "n/a"
		if inp.rpedFuel > 0 && inp.rxpFuel > 0 {
			ratio = fmt.Sprintf("%.2fx", float64(inp.rxpFuel)/float64(inp.rpedFuel))
		}
		fmt.Printf("    %-24s  %14s  %14s  %8s\n",
			"fuel consumed:",
			fmtFuel(inp.rxpFuel),
			fmtFuel(inp.rpedFuel),
			ratio)
	}
}

// --------------------------------------------------------------------------
// Main

func main() {
	// Silence library log output — only the benchmark table goes to stdout.
	slog.SetDefault(slog.New(slog.NewTextHandler(io.Discard, nil)))

	full := flag.Bool("full", false, "show wasm size and instantiation/compilation time")
	fuel := flag.Bool("fuel", false, "measure fuel (WASM instruction count) for a single call instead of timing")
	flag.Parse()

	// Load the pre-built regex_bench.wasm harness.
	dir, _ := os.Getwd()
	regexWasmPath := filepath.Join(dir, "regex_bench", "target", "wasm32-wasip1", "release", "regex_bench.wasm")
	regexWasmBytes, err := os.ReadFile(regexWasmPath)
	if err != nil {
		fmt.Fprintf(os.Stderr, "error: cannot read %s: %v\n", regexWasmPath, err)
		fmt.Fprintf(os.Stderr, "hint: run 'make harnesses' first\n")
		os.Exit(1)
	}

	engine := wasmtime.NewEngine()

	// Warm up Cranelift before the first real measurement.
	warmup(engine)

	var fuelEngine *wasmtime.Engine
	if *fuel {
		fuelCfg := wasmtime.NewConfig()
		fuelCfg.SetConsumeFuel(true)
		fuelEngine = wasmtime.NewEngineWithConfig(fuelCfg)
	}

	for _, tc := range tests {
		fmt.Fprintf(os.Stderr, "==> %s\n", tc.name)
		engineName := regexpedEngineName(tc)

		if *fuel {
			var fuelInputs []fuelInputResult
			for _, inp := range tc.inputs {
				rxpF, _ := measFuelRegex(regexWasmBytes, tc, inp.value, fuelEngine)
				rpedF, _ := measFuelRegexped(tc, inp.value, fuelEngine)
				fuelInputs = append(fuelInputs, fuelInputResult{
					label:    inp.label,
					size:     len(inp.value),
					rxpFuel:  rxpF,
					rpedFuel: rpedF,
				})
			}
			printFuelResults(tc, engineName, fuelInputs)
			continue
		}

		// Benchmark all inputs; use the first input's instantiation timing for display
		// (instantiation depends only on pattern/module, not on input content).
		var rxpInst, rpedInst benchResult
		var inputResults []inputResult

		for i, inp := range tc.inputs {
			rxp := benchRegex(regexWasmBytes, tc, inp.value, engine)
			rped := benchRegexped(tc, inp.value, engine)
			if i == 0 {
				rxpInst = rxp
				rpedInst = rped
			}
			inputResults = append(inputResults, inputResult{
				label:   inp.label,
				size:    len(inp.value),
				rxpAvg:  rxp.avgExec,
				rpedAvg: rped.avgExec,
			})
		}

		printResults(tc, engineName, benchResult{
			instantiation: rxpInst.instantiation,
			compilation:   rxpInst.compilation,
			wasmSize:      rxpInst.wasmSize,
		}, benchResult{
			instantiation: rpedInst.instantiation,
			wasmSize:      rpedInst.wasmSize,
		}, inputResults, *full)
	}
	fmt.Println()
}
