// perftest benchmarks regexped WASM against the regex crate and prints a summary table.
//
// Run from the perftest/ directory:
//
//	cd perftest && make run
package main

import (
	"bufio"
	"flag"
	"fmt"
	"io"
	"log/slog"
	"math"
	"os"
	"path/filepath"
	"strconv"
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
		// Baseline for the literal-anchored matching non-anchored optimisation.
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
	{
		// HTML tag extraction — benchmarks BitState memo zero-init overhead.
		// The outer *? loop body (\s*(attr)?(="val")?) can match zero bytes, so
		// needsBitState fires: a memo table of N×(len+1) bits is zeroed at the
		// start of every BT capture call.  Each '<' in the input triggers one
		// such call, including closing tags that fail immediately (the '/' is
		// not \w).
		// "bare-tags": 18 '<' positions, 0 lazy iterations per matching tag.
		// "attr-tags": same '<' count; each opening tag requires multiple lazy
		// iterations to step past attributes, adding BT work atop zeroing overhead.
		name:    "html-tags",
		pattern: `<(?P<tag>\w+)(?:\s*(?P<attr>\w+)?(?:="(?P<val>[^"]*)")?)*?>`,
		mode:    anchoredGroups,
		inputs: []namedInput{
			{"bare-tags", htmlTagInput(false)},
			{"attr-tags", htmlTagInput(true)},
		},
	},
	// ── BT find-mode baselines ────────────────────────────────────────────────
	// NOTE: These cases do NOT exercise the BT find code path.  Despite having
	// Backtracking capture engines, both patterns have compact LeftmostFirst DFAs
	// (25 and 27 states respectively), so their find bodies use DFA find.  The BT
	// find path (dfaTooLarge=true) requires the LF DFA to exceed 1024 states,
	// which almost never happens because LeftmostFirst construction is inherently
	// compact.  These cases are kept as performance baselines for the BT capture
	// engine on log-structured input.
	{
		// BT capture baseline on a 100KB log file.  The LF DFA (25 states) handles
		// the find phase; the BT engine handles the capture phase.  Groups_func
		// scans the log and captures worker/id/severity/message for each event line.
		name:    "bt-find-mand-lit",
		pattern: `(\w+)\[(\d+)\] .*(ERROR|FAILURE|CRASH): (.+)`,
		mode:    anchoredGroups,
		inputs: []namedInput{
			{"no events 100KB", largeLogInput(nil)},
			{"5 events 100KB", largeLogInput([]string{
				"2026-03-22T14:30:01 worker[12] info: connect attempt 3, ERROR: connection refused: CRASH: code=1",
				"2026-03-22T14:30:15 worker[7] info: query timed out, FAILURE: deadline exceeded after 30s",
				"2026-03-22T14:30:28 worker[3] info: task aborted, ERROR: out of memory allocating 512MB",
				"2026-03-22T14:30:42 worker[19] info: upstream unreachable, CRASH: signal 11 received",
				"2026-03-22T14:30:57 worker[5] info: retry limit reached, FAILURE: giving up after 5 attempts",
			})},
		},
	},
	{
		// BT capture baseline on a 100KB log file.  The LF DFA (27 states) handles
		// the find phase; the BT engine handles the capture phase.  The pattern
		// starts with one of three keywords (E/F/W first bytes); groups_func scans
		// and captures severity/component/elapsed for each event line.
		name:    "bt-find-prefix",
		pattern: `(ERROR|FAILURE|WARNING): (\w+) .+ (\d+)ms`,
		mode:    anchoredGroups,
		inputs: []namedInput{
			{"no events 100KB", largeLogInput(nil)},
			{"5 events 100KB", largeLogInput([]string{
				"ERROR: worker[12] connection refused after retry, elapsed 3000ms",
				"FAILURE: worker[7] query deadline exceeded, total wait 15000ms",
				"WARNING: worker[3] memory pressure detected, threshold 85%, check 500ms",
				"ERROR: worker[19] upstream timeout, attempted 3 retries over 9000ms",
				"FAILURE: worker[5] task aborted, cleanup finished in 250ms",
			})},
		},
	},

	// ── Phase 0 new patterns — compatibility baseline coverage ────────────────
	// These four patterns extend the baseline corpus to cover engine paths that
	// the Phase 1–4 grouping work touches.  See plans/COMBINING_PATTERNS_PLAN.md
	// "Phase 0 — Perftest expansion and baseline capture".

	{
		// 0.1: word-boundary pattern.
		// \bERROR\b exercises the doubled DFA state space caused by the
		// prevWasWord context bit (CLAUDE.md "Word Boundaries in DFA").
		// The Phase 1 BFS-relabel work touches this state-numbering path.
		name:    "word-boundary",
		pattern: `\bERROR\b`,
		mode:    find,
		inputs: []namedInput{
			{"no-error 100KB", largeLogInput(nil)},
			{"5 errors 100KB", largeLogInput([]string{
				"2026-03-22T14:05:02 db.pool[3] ERROR: connection refused after 3 retries",
				"2026-03-22T14:05:08 app[1] ERROR: panic in handler: index out of range",
				"2026-03-22T14:05:12 service[1] ERROR: unable to acquire lock on table users",
				"2026-03-22T14:05:20 cache[2] ERROR: eviction policy enforcement failed",
				"2026-03-22T14:05:35 worker[5] ERROR: job 7f3a exceeded deadline of 30s",
			})},
		},
	},
	{
		// 0.2: scalar firstByteFlags fallback pattern.
		// [a-zA-Z_] has 53 distinct first bytes (> 16 threshold in prefix_scan.go:217),
		// forcing the 256-byte scalar flag-table path instead of Teddy or multi-eq SIMD.
		// No mandatory literal — the full first-byte filter is exercised each scan.
		name:    "identifier-scan",
		pattern: `[a-zA-Z_][a-zA-Z0-9_]{7,}`,
		mode:    find,
		inputs: []namedInput{
			{"source 100KB", sourceCodeInput(nil, nil)},
		},
	},
	{
		// 0.3: high-register TDFA pattern — 10 named capture groups.
		// Uses narrow character classes (\d, [A-Z], [a-z]) so getFirstRuneSet
		// can prove each quantifier-loop alternation is deterministic → TDFA.
		// Stresses register allocation (20 register slots) and tag-op emission.
		name:    "log-fields-10g",
		pattern: `(?P<y>\d+)-(?P<mo>\d+)-(?P<d>\d+) (?P<H>\d+):(?P<mi>\d+):(?P<s>\d+) (?P<lv>[A-Z]+) (?P<comp>[a-z]+) (?P<msg>[a-z]+) (?P<dur>\d+)`,
		mode:    anchoredGroups,
		inputs: []namedInput{
			{"match", "2026-01-15 14:30:00 INFO worker completed 350"},
			{"no-match", strings.Repeat("not-a-log-line ", 20)},
		},
	},
	{
		// 0.4: TDFA → Backtracking fallback pattern.
		// 17 deeply nested capture groups create 34 tag slots, exceeding
		// MaxTDFARegs=32, so selectBestEngine falls back to Backtracking.
		// Verified: SelectEngine returns Backtracking with default options,
		// TDFA with MaxTDFARegs=100 (confirming the cause is register count).
		name:    "deep-captures",
		pattern: `(?P<l1>(?P<l2>(?P<l3>(?P<l4>(?P<l5>(?P<l6>(?P<l7>(?P<l8>(?P<l9>(?P<l10>(?P<l11>(?P<l12>(?P<l13>(?P<l14>(?P<l15>(?P<l16>(?P<l17>.+)))))))))))))))))`,
		mode:    anchoredGroups,
		inputs: []namedInput{
			{"short match", "hello world"},
			{"long match", strings.Repeat("abcdefghij", 100)},
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

// largeLogInput returns a ~100KB structured log file. Each line is realistic
// log output dense with words starting with E, F, W (event, elapsed, function,
// fetching, worker, writing, etc.) so the BT first-byte scan fires frequently,
// but without ERROR/FAILURE/CRASH/WARNING occurrences unless injected.
// Used as input for the bt-find-mand-lit and bt-find-prefix BT capture baselines.
func largeLogInput(events []string) string {
	const block = `2026-03-22T14:05:00 worker[1] info: function started, event_id=7f3a received from event queue
2026-03-22T14:05:00 worker[2] info: fetching resource from storage backend, elapsed=2ms
2026-03-22T14:05:01 worker[3] info: event processed, writing result to database, rows=1
2026-03-22T14:05:01 scheduler[4] info: worker allocated for task execution, waiting for slot
2026-03-22T14:05:02 worker[1] info: finished processing event, elapsed=12ms, events_total=3
2026-03-22T14:05:02 worker[2] info: enqueueing follow-up event for downstream worker, queue_depth=4
2026-03-22T14:05:03 worker[3] info: fetching next event from queue, worker_id=3, attempt=1
2026-03-22T14:05:03 scheduler[4] info: evaluating worker load, free_slots=2, enqueued=7
2026-03-22T14:05:04 worker[1] info: event forwarded to external endpoint, waited=5ms
2026-03-22T14:05:04 worker[2] info: writing event metadata, fields=8, elapsed=1ms
`
	repeat := (100 * 1024) / len(block)
	base := strings.Repeat(block, repeat)
	if len(events) == 0 {
		return base
	}
	result := []byte(base)
	step := len(result) / (len(events) + 1)
	offset := 0
	for i, event := range events {
		pos := (i+1)*step + offset
		if pos > len(result) {
			pos = len(result)
		}
		line := []byte(event + "\n")
		result = append(result[:pos], append(line, result[pos:]...)...)
		offset += len(line)
	}
	return string(result)
}

// htmlTagInput returns a small HTML document (~165 / ~355 bytes). The pattern
// <(\w+)(?:\s*(\w+)?(="([^"]*)")?)*?> triggers needsBitState because the outer
// *? loop body is entirely optional (can match zero bytes); a BitState memo
// table (25 NFA states × (len+1) bits) is therefore zeroed on every BT capture
// call — one per '<' character, closing tags included (they fail after one byte).
// withAttrs=false: bare tags, 0 lazy iterations per matching tag.
// withAttrs=true:  attribute-bearing tags, multiple lazy iterations per match.
func htmlTagInput(withAttrs bool) string {
	if !withAttrs {
		return "<html><head><title>Test Page</title></head>" +
			"<body><div><h1>Hello World</h1>" +
			"<p>First paragraph text here.</p>" +
			"<a>Click here</a>" +
			"<span>Some note.</span>" +
			"</div></body></html>\n"
	}
	return `<html lang="en"><head><meta charset="UTF-8"><title>Test Page</title></head>` +
		`<body class="page" id="main"><div class="container" id="content">` +
		`<h1 class="title">Hello World</h1>` +
		`<p class="intro" id="p1">First paragraph text here.</p>` +
		`<a href="https://example.com" class="link" target="_blank">Click here</a>` +
		`<span class="note">Some note.</span>` +
		`</div></body></html>` + "\n"
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
	benchIters = 10_000
)

type benchResult struct {
	instantiation time.Duration
	compilation   time.Duration // zero means n/a (regexped has no runtime compilation)
	avgExec       time.Duration
	wasmSize      int
}

// --------------------------------------------------------------------------
// Bench shim WASM modules — built at startup by shims.go.
//
// Each shim imports wasi_snapshot_preview1.clock_time_get and one regexped
// function, times each of benchIters iterations individually, and writes the
// u32 nanosecond samples into its exported memory starting at offset 0.
// find/groups shims exhaust all matches per iteration for a fair comparison.
// See shims.go for details.

var (
	matchBenchShim  = buildMatchBenchShim()
	findBenchShim   = buildFindBenchShim()
	groupsBenchShim = buildGroupsBenchShim()
)

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
func benchRegexped(tc testCase, input string, engine *wasmtime.Engine, pct int) benchResult {
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
	store.SetWasi(wasmtime.NewWasiConfig())
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

	// Instantiate the bench shim via a linker (needs WASI for clock_time_get).
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
	linker := wasmtime.NewLinker(engine)
	if err = linker.DefineWasi(); err != nil {
		fmt.Fprintf(os.Stderr, "  regexped shim DefineWasi(%s): %v\n", tc.name, err)
		return benchResult{instantiation: instantiation}
	}
	if err = linker.Define(store, "regexped", fnExport, rpdFn); err != nil {
		fmt.Fprintf(os.Stderr, "  regexped shim Define(%s): %v\n", tc.name, err)
		return benchResult{instantiation: instantiation}
	}
	shimInst, err := linker.Instantiate(store, shimMod)
	if err != nil {
		fmt.Fprintf(os.Stderr, "  regexped shim instantiate(%s): %v\n", tc.name, err)
		return benchResult{instantiation: instantiation}
	}
	var shimMem *wasmtime.Memory
	if exp := shimInst.GetExport(store, "memory"); exp != nil {
		shimMem = exp.Memory()
	}
	benchFn := shimInst.GetFunc(store, "bench")
	if benchFn == nil || shimMem == nil {
		fmt.Fprintf(os.Stderr, "  regexped shim: missing bench/memory export for %s\n", tc.name)
		return benchResult{instantiation: instantiation}
	}

	// Write input into regexped's memory and call the bench function.
	buf := mem.UnsafeData(store)
	copy(buf[inputBase:], []byte(input))
	inputLen := int32(len(input))

	warmupEnd := time.Now().Add(50 * time.Millisecond)
	for time.Now().Before(warmupEnd) {
		if tc.mode == anchoredGroups {
			benchFn.Call(store, inputBase, inputLen, slotsBase, int32(benchIters)) //nolint:errcheck
		} else {
			benchFn.Call(store, inputBase, inputLen, int32(benchIters)) //nolint:errcheck
		}
	}

	var callErr error
	if tc.mode == anchoredGroups {
		_, callErr = benchFn.Call(store, inputBase, inputLen, slotsBase, int32(benchIters))
	} else {
		_, callErr = benchFn.Call(store, inputBase, inputLen, int32(benchIters))
	}
	if callErr != nil {
		fmt.Fprintf(os.Stderr, "  regexped bench(%s): %v\n", tc.name, callErr)
		return benchResult{instantiation: instantiation}
	}

	shimBuf := shimMem.UnsafeData(store)
	return benchResult{
		instantiation: instantiation,
		avgExec:       computeStat(shimBuf[:timingsBytes], pct),
		wasmSize:      len(wasmBytes),
	}
}

// benchRegex instantiates regex_bench.wasm, compiles the pattern via regex_init,
// and times execution via the internal-timing regex_bench_* functions.
// Each iteration is timed individually inside WASM; the timings buffer is read
// back by Go to compute avg or a percentile.
func benchRegex(regexWasmBytes []byte, tc testCase, input string, engine *wasmtime.Engine, pct int) benchResult {
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
	getTimingsPtrFn := inst.GetFunc(store, "get_timings_ptr")
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
	if mem == nil || getPtrFn == nil || getTimingsPtrFn == nil || initFn == nil || benchExecFn == nil {
		fmt.Fprintf(os.Stderr, "  regex: missing export for %s\n", tc.name)
		return benchResult{instantiation: instantiation}
	}

	// Get the addresses of the static input and timings buffers inside WASM.
	ptrRes, err := getPtrFn.Call(store)
	if err != nil {
		fmt.Fprintf(os.Stderr, "  regex get_input_ptr(%s): %v\n", tc.name, err)
		return benchResult{instantiation: instantiation}
	}
	timPtrRes, err := getTimingsPtrFn.Call(store)
	if err != nil {
		fmt.Fprintf(os.Stderr, "  regex get_timings_ptr(%s): %v\n", tc.name, err)
		return benchResult{instantiation: instantiation}
	}
	inputPtr := int(ptrRes.(int32))
	timingsPtr := int(timPtrRes.(int32))
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

	// Write input and run the bench function; it times each iteration individually
	// and writes u32 ns samples to the timings buffer.
	copy(buf[inputPtr:], []byte(input))
	inputLen := int32(len(input))

	warmupEnd := time.Now().Add(50 * time.Millisecond)
	for time.Now().Before(warmupEnd) {
		benchExecFn.Call(store, inputLen, int32(benchIters)) //nolint:errcheck
	}

	_, callErr := benchExecFn.Call(store, inputLen, int32(benchIters))
	if callErr != nil {
		fmt.Fprintf(os.Stderr, "  regex bench(%s): %v\n", tc.name, callErr)
		return benchResult{instantiation: instantiation, compilation: compilation}
	}

	return benchResult{
		instantiation: instantiation,
		compilation:   compilation,
		avgExec:       computeStat(buf[timingsPtr:timingsPtr+timingsBytes], pct),
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

func execLabel(pct int) string {
	if pct == 0 {
		return "avg execution:"
	}
	return fmt.Sprintf("p%d execution:", pct)
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

func printResults(tc testCase, engineName string, rxp, rped benchResult, inputs []inputResult, full bool, pct int) {
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
			execLabel(pct),
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
// WASM size helpers (for -size-only mode)

func tcModeStr(tc testCase) string {
	switch tc.mode {
	case find:
		return "find"
	case anchoredGroups:
		return "groups"
	default:
		return "anchored"
	}
}

func compileTestWasm(tc testCase) ([]byte, error) {
	re := config.RegexEntry{Pattern: tc.pattern}
	switch tc.mode {
	case anchored:
		re.MatchFunc = "match"
	case find:
		re.FindFunc = "find"
	case anchoredGroups:
		re.GroupsFunc = "groups"
	}
	wasmBytes, _, err := compile.Compile([]config.RegexEntry{re}, tableBase, true)
	return wasmBytes, err
}

func runSizeOnly() {
	for _, tc := range tests {
		wasmBytes, err := compileTestWasm(tc)
		if err != nil {
			fmt.Fprintf(os.Stderr, "size-only compile(%s): %v\n", tc.name, err)
			continue
		}
		fmt.Printf("%s:%s %d\n", tc.name, tcModeStr(tc), len(wasmBytes))
	}
}

// --------------------------------------------------------------------------
// Speedup-ratio baseline comparison (for -compare-time mode)

// parseDur parses the output of fmtDur back into a time.Duration.
func parseDur(s string) (time.Duration, error) {
	s = strings.TrimSpace(s)
	switch {
	case strings.HasSuffix(s, " ms"):
		f, err := strconv.ParseFloat(strings.TrimSuffix(s, " ms"), 64)
		return time.Duration(math.Round(f * float64(time.Millisecond))), err
	case strings.HasSuffix(s, " µs"):
		f, err := strconv.ParseFloat(strings.TrimSuffix(s, " µs"), 64)
		return time.Duration(math.Round(f * float64(time.Microsecond))), err
	case strings.HasSuffix(s, " ns"):
		n, err := strconv.ParseInt(strings.TrimSuffix(s, " ns"), 10, 64)
		return time.Duration(n), err
	case s == "n/a":
		return 0, nil
	}
	return 0, fmt.Errorf("unknown duration format: %q", s)
}

type timeBaseline struct{ rxp, rped time.Duration }

// parseTimeBaseline reads baseline_time.txt and returns a map of
// "name:mode:input_label" → {rxp, rped} durations.
func parseTimeBaseline(path string) (map[string]timeBaseline, error) {
	f, err := os.Open(path)
	if err != nil {
		return nil, err
	}
	defer f.Close()

	result := make(map[string]timeBaseline)
	var curKey string
	var curInput string

	scanner := bufio.NewScanner(f)
	for scanner.Scan() {
		line := scanner.Text()
		trimmed := strings.TrimSpace(line)

		if strings.HasPrefix(trimmed, "===") && strings.HasSuffix(trimmed, "===") {
			inner := strings.TrimSpace(strings.TrimSuffix(strings.TrimPrefix(trimmed, "==="), "==="))
			bracketIdx := strings.LastIndex(inner, "  [")
			if bracketIdx < 0 {
				continue
			}
			name := strings.TrimSpace(inner[:bracketIdx])
			rest := strings.TrimSuffix(strings.TrimPrefix(inner[bracketIdx:], "  ["), "]")
			parts := strings.SplitN(rest, ", ", 2)
			if len(parts) != 2 {
				continue
			}
			curKey = name + ":" + strings.TrimSpace(parts[1])
			curInput = ""
			continue
		}

		if strings.HasPrefix(trimmed, "input: ") {
			after := strings.TrimPrefix(trimmed, "input: ")
			if idx := strings.LastIndex(after, " ("); idx >= 0 {
				curInput = strings.TrimSpace(after[:idx])
			} else {
				curInput = strings.TrimSpace(after)
			}
			continue
		}

		if strings.Contains(trimmed, "execution:") && curKey != "" && curInput != "" {
			idx := strings.Index(trimmed, "execution:")
			after := trimmed[idx+len("execution:"):]
			fields := strings.Fields(after)
			// fields: [rxp_val, rxp_unit, rped_val, rped_unit, ratio]
			if len(fields) >= 4 {
				rxpD, err1 := parseDur(fields[0] + " " + fields[1])
				rpedD, err2 := parseDur(fields[2] + " " + fields[3])
				if err1 == nil && err2 == nil && rxpD > 0 && rpedD > 0 {
					result[curKey+":"+curInput] = timeBaseline{rxp: rxpD, rped: rpedD}
				}
			}
			continue
		}
	}
	return result, scanner.Err()
}

// runCompareTime measures speedup ratio (rxp/rped) and compares against baseline.
// Patterns where min(rxp_base, rped_base) < 1µs are skipped — too noisy.
// Tolerance: ±10%.
func runCompareTime(baselinePath string, regexWasmBytes []byte, engine *wasmtime.Engine) bool {
	baseline, err := parseTimeBaseline(baselinePath)
	if err != nil {
		fmt.Fprintf(os.Stderr, "compare-time: cannot read baseline %s: %v\n", baselinePath, err)
		return false
	}

	const pct = 50
	const tolerance = 0.10
	const minBaseline = 1 * time.Microsecond
	ok := true

	for _, tc := range tests {
		fmt.Fprintf(os.Stderr, "==> %s\n", tc.name)
		modeKey := tcModeStr(tc)
		for _, inp := range tc.inputs {
			key := tc.name + ":" + modeKey + ":" + inp.label
			base, found := baseline[key]
			if !found {
				fmt.Fprintf(os.Stderr, "  compare-time: no baseline for %q\n", key)
				continue
			}
			if base.rxp < minBaseline || base.rped < minBaseline {
				continue // too noisy
			}
			baseRatio := float64(base.rxp) / float64(base.rped)
			rxp := benchRegex(regexWasmBytes, tc, inp.value, engine, pct)
			rped := benchRegexped(tc, inp.value, engine, pct)
			if rxp.avgExec <= 0 || rped.avgExec <= 0 {
				continue
			}
			curRatio := float64(rxp.avgExec) / float64(rped.avgExec)
			drift := math.Abs(curRatio-baseRatio) / baseRatio
			if drift > tolerance {
				fmt.Printf("REGRESSION %s input=%q: baseline ratio=%.2fx current=%.2fx (%.1f%% drift, limit ±%.0f%%)\n",
					tc.name, inp.label, baseRatio, curRatio, drift*100, tolerance*100)
				ok = false
			}
		}
	}
	return ok
}

// --------------------------------------------------------------------------
// Fuel baseline comparison (for -compare-fuel mode)

// parseFuelValue parses a comma-formatted fuel count like "2,863,498" → uint64.
func parseFuelValue(s string) (uint64, error) {
	s = strings.ReplaceAll(s, ",", "")
	return strconv.ParseUint(s, 10, 64)
}

// parseFuelBaseline reads baseline_fuel.txt and returns a map of
// "name:mode:input_label" → regexped fuel consumed.
func parseFuelBaseline(path string) (map[string]uint64, error) {
	f, err := os.Open(path)
	if err != nil {
		return nil, err
	}
	defer f.Close()

	result := make(map[string]uint64)
	var curKey string
	var curInput string

	scanner := bufio.NewScanner(f)
	for scanner.Scan() {
		line := scanner.Text()
		trimmed := strings.TrimSpace(line)

		if strings.HasPrefix(trimmed, "===") && strings.HasSuffix(trimmed, "===") {
			inner := strings.TrimSpace(strings.TrimSuffix(strings.TrimPrefix(trimmed, "==="), "==="))
			bracketIdx := strings.LastIndex(inner, "  [")
			if bracketIdx < 0 {
				continue
			}
			name := strings.TrimSpace(inner[:bracketIdx])
			rest := strings.TrimPrefix(inner[bracketIdx:], "  [")
			rest = strings.TrimSuffix(rest, "]")
			parts := strings.SplitN(rest, ", ", 2)
			if len(parts) != 2 {
				continue
			}
			curKey = name + ":" + strings.TrimSpace(parts[1])
			curInput = ""
			continue
		}

		if strings.HasPrefix(trimmed, "input: ") {
			after := strings.TrimPrefix(trimmed, "input: ")
			if idx := strings.LastIndex(after, " ("); idx >= 0 {
				curInput = strings.TrimSpace(after[:idx])
			} else {
				curInput = strings.TrimSpace(after)
			}
			continue
		}

		if strings.HasPrefix(trimmed, "fuel consumed:") && curKey != "" && curInput != "" {
			fields := strings.Fields(trimmed)
			// fields: ["fuel", "consumed:", REGEX_fuel, RPED_fuel, ratio]
			if len(fields) >= 4 {
				v, err := parseFuelValue(fields[3])
				if err == nil {
					key := curKey + ":" + curInput
					result[key] = v
				}
			}
			continue
		}
	}
	return result, scanner.Err()
}

// runCompareFuel measures fuel and compares against a baseline with exact (0%) tolerance.
// Fuel is fully deterministic after the TDFA setOps sort fix (engine_tdfa.go): both DFA
// and TDFA now produce identical WASM bytecode across runs, giving identical fuel counts.
func runCompareFuel(baselinePath string, regexWasmBytes []byte, fuelEngine *wasmtime.Engine) bool {
	baseline, err := parseFuelBaseline(baselinePath)
	if err != nil {
		fmt.Fprintf(os.Stderr, "compare-fuel: cannot read baseline %s: %v\n", baselinePath, err)
		return false
	}

	const tolerancePct = 0.0 // exact match — TDFA is now deterministic after fixing setOps sort
	ok := true

	for _, tc := range tests {
		modeKey := tcModeStr(tc)
		for _, inp := range tc.inputs {
			rpedF, measured := measFuelRegexped(tc, inp.value, fuelEngine)
			if !measured {
				continue
			}
			key := tc.name + ":" + modeKey + ":" + inp.label
			base, found := baseline[key]
			if !found {
				fmt.Fprintf(os.Stderr, "  compare-fuel: no baseline for %q\n", key)
				continue
			}
			if base == 0 {
				continue
			}
			ratio := math.Abs(float64(rpedF)-float64(base)) / float64(base)
			if ratio > tolerancePct {
				fmt.Printf("REGRESSION %s input=%q: baseline=%s current=%s (%.1f%% drift, limit ±%.0f%%)\n",
					tc.name, inp.label, fmtFuel(base), fmtFuel(rpedF), ratio*100, tolerancePct*100)
				ok = false
			}
		}
	}
	return ok
}

// --------------------------------------------------------------------------
// Size baseline comparison (for -compare-size mode)

// parseSizeBaseline reads baseline_size.txt ("name:mode bytes" per line).
func parseSizeBaseline(path string) (map[string]int, error) {
	f, err := os.Open(path)
	if err != nil {
		return nil, err
	}
	defer f.Close()

	result := make(map[string]int)
	scanner := bufio.NewScanner(f)
	for scanner.Scan() {
		line := strings.TrimSpace(scanner.Text())
		if line == "" {
			continue
		}
		parts := strings.Fields(line)
		if len(parts) != 2 {
			continue
		}
		n, err := strconv.Atoi(parts[1])
		if err != nil {
			continue
		}
		result[parts[0]] = n
	}
	return result, scanner.Err()
}

// runCompareSize compiles each test case and compares WASM size against baseline.
// Exact match (0% tolerance) — WASM emission is deterministic after the TDFA setOps sort fix.
func runCompareSize(baselinePath string) bool {
	baseline, err := parseSizeBaseline(baselinePath)
	if err != nil {
		fmt.Fprintf(os.Stderr, "compare-size: cannot read baseline %s: %v\n", baselinePath, err)
		return false
	}

	const tolerancePct = 0.0
	ok := true

	for _, tc := range tests {
		wasmBytes, err := compileTestWasm(tc)
		if err != nil {
			fmt.Fprintf(os.Stderr, "compare-size compile(%s): %v\n", tc.name, err)
			continue
		}
		key := tc.name + ":" + tcModeStr(tc)
		base, found := baseline[key]
		if !found {
			fmt.Fprintf(os.Stderr, "  compare-size: no baseline for %q\n", key)
			continue
		}
		if base == 0 {
			continue
		}
		ratio := math.Abs(float64(len(wasmBytes))-float64(base)) / float64(base)
		if ratio > tolerancePct {
			fmt.Printf("REGRESSION %s: baseline=%d bytes current=%d bytes (%.1f%% drift, limit ±%.0f%%)\n",
				key, base, len(wasmBytes), ratio*100, tolerancePct*100)
			ok = false
		}
	}
	return ok
}

// --------------------------------------------------------------------------
// Main

func main() {
	// Silence library log output — only the benchmark table goes to stdout.
	slog.SetDefault(slog.New(slog.NewTextHandler(io.Discard, nil)))

	full := flag.Bool("full", false, "show wasm size and instantiation/compilation time")
	fuel := flag.Bool("fuel", false, "measure fuel (WASM instruction count) for a single call instead of timing")
	pct := flag.Int("p", 0, "report this percentile (1-99) instead of average (e.g. -p 95)")
	sizeOnly := flag.Bool("size-only", false, "print WASM module sizes per test case and exit (no harness required)")
	compareTime := flag.String("compare-time", "", "compare speedup ratio (rxp/rped p50) against baseline file; exit 1 if outside ±10%")
	compareFuel := flag.String("compare-fuel", "", "compare fuel counts against baseline file; exit 1 if outside ±20% (TDFA non-determinism budget)")
	compareSize := flag.String("compare-size", "", "compare WASM sizes against baseline file; exit 1 if outside ±5%")
	flag.Parse()

	// -size-only and -compare-size do not need the regex_bench.wasm harness.
	if *sizeOnly {
		runSizeOnly()
		return
	}
	if *compareSize != "" {
		if !runCompareSize(*compareSize) {
			os.Exit(1)
		}
		return
	}

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

	// -compare-time measures speedup ratio and compares against a baseline.
	if *compareTime != "" {
		if !runCompareTime(*compareTime, regexWasmBytes, engine) {
			os.Exit(1)
		}
		return
	}

	var fuelEngine *wasmtime.Engine
	if *fuel || *compareFuel != "" {
		fuelCfg := wasmtime.NewConfig()
		fuelCfg.SetConsumeFuel(true)
		fuelEngine = wasmtime.NewEngineWithConfig(fuelCfg)
	}

	// -compare-fuel measures fuel and compares against a baseline.
	if *compareFuel != "" {
		if !runCompareFuel(*compareFuel, regexWasmBytes, fuelEngine) {
			os.Exit(1)
		}
		return
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
			rxp := benchRegex(regexWasmBytes, tc, inp.value, engine, *pct)
			rped := benchRegexped(tc, inp.value, engine, *pct)
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
		}, inputResults, *full, *pct)
	}
	fmt.Println()
}
