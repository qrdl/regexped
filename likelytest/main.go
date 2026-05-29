// likelytest is a focused benchmark harness that compares regexped's WASM output
// across the three LikelyMode compile modes (neutral, likely-match, likely-nomatch)
// for a hand-picked set of patterns where the LIKELY.md structural optimisations
// (SIMD counted-chain verify, SIMD dominant-self-loop skip) are expected to
// move the needle.
//
// For each test case it produces a per-pattern matrix:
//
//	mode             match-input        no-match-input
//	neutral          time / fuel        time / fuel
//	likely-match     time / fuel (Δ%)   time / fuel (Δ%)
//	likely-nomatch   time / fuel (Δ%)   time / fuel (Δ%)
//
// Δ% is the gain/loss vs the neutral row.
//
// Note: LikelyMode is a stub today — all three modes produce identical WASM. The
// columns will only diverge once the LIKELY.md optimisations land in compile/.
// Run via `make run` from this directory.
package main

import (
	"fmt"
	"io"
	"log/slog"
	"os"
	"strings"
	"time"

	wasmtime "github.com/bytecodealliance/wasmtime-go/v42"
	"github.com/qrdl/regexped/compile"
	"github.com/qrdl/regexped/config"
)

// --------------------------------------------------------------------------
// Memory layout (same scheme as perftest)

const (
	inputBase  = int32(0)
	tableBase  = int64(131072) // page 2; pages 0-1 reserved for input
	slotsBase  = int32(512)
	benchIters = 10_000
	fuelBudget = uint64(10_000_000_000)
)

// --------------------------------------------------------------------------
// Test cases

type matchMode int

const (
	modeFind matchMode = iota
	modeAnchored
)

func (m matchMode) String() string {
	if m == modeAnchored {
		return "anchored"
	}
	return "find"
}

type testCase struct {
	name         string
	pattern      string
	mode         matchMode
	notes        string // one-line description of which optimisation it targets
	matchInput   string
	nomatchInput string
}

var tests = []testCase{
	{
		// Counted chain: AKIA + [A-Z0-9]{16}. 17-state linear chain — textbook Opt 2.
		// Expected once Opt 2 lands: likely-match faster on match-input; no effect on
		// no-match (Teddy frontend never fires there).
		name:         "secrets-aws",
		pattern:      `AKIA[A-Z0-9]{16}`,
		mode:         modeFind,
		notes:        "17-state counted chain after literal — Opt 2 target",
		matchInput:   configInput([]string{"export AWS_ACCESS_KEY_ID=AKIAIOSFODNN7EXAMPLE"}),
		nomatchInput: configInput(nil),
	},
	{
		// Counted chain: ghp_ + [A-Za-z0-9]{36}. 37-state chain — Opt 2 target.
		name:         "secrets-github",
		pattern:      `ghp_[A-Za-z0-9]{36}`,
		mode:         modeFind,
		notes:        "37-state counted chain after literal — Opt 2 target",
		matchInput:   configInput([]string{"ghp_AbCdEfGhIjKlMnOpQrStUvWxYz0123456789Ab"}),
		nomatchInput: configInput(nil),
	},
	{
		// Long synthetic counted chain — amplifies Opt 2's win as N grows.
		// 65-state chain after a 4-byte literal.
		name:         "long-counted-chain",
		pattern:      `KEYX[A-Z0-9]{64}`,
		mode:         modeFind,
		notes:        "65-state counted chain — Opt 2 amplification",
		matchInput:   configInput([]string{"KEYXABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789ABCDEFGHIJKLMNOPQRSTUVWX1234"}),
		nomatchInput: configInput(nil),
	},
	{
		// Alternation of two counted chains. AC frontend buckets by literal prefix,
		// then each bucket dispatches to its own counted-chain verifier.
		name:         "secrets-combined",
		pattern:      `AKIA[A-Z0-9]{16}|ghp_[A-Za-z0-9]{36}`,
		mode:         modeFind,
		notes:        "alternation of two counted chains — Opt 2 via bucket dispatch",
		matchInput:   configInput([]string{"AKIAIOSFODNN7EXAMPLE", "ghp_AbCdEfGhIjKlMnOpQrStUvWxYz0123456789Ab"}),
		nomatchInput: configInput(nil),
	},
	{
		// Word-boundary anchored lit-chain — canonical secret-detection idiom.
		// Tests start \b + end \b on the single-pattern find path.
		name:         "secrets-github-bounded",
		pattern:      `\bghp_[A-Za-z0-9]{36}\b`,
		mode:         modeFind,
		notes:        "ghp_ secret with \\b at both ends — anchor support target",
		matchInput:   configInput([]string{"see ghp_AbCdEfGhIjKlMnOpQrStUvWxYz0123456789 here"}),
		nomatchInput: configInput([]string{"Xghp_AbCdEfGhIjKlMnOpQrStUvWxYz0123456789Y"}),
	},
	{
		// Strict alternation of two word-boundary anchored secrets. Exercises
		// the anchor checks in buildLitChainAltFindBody.
		name:    "secrets-combined-bounded",
		pattern: `\bAKIA[A-Z0-9]{16}\b|\bghp_[A-Za-z0-9]{36}\b`,
		mode:    modeFind,
		notes:   "alternation of two \\b-bounded counted chains — strict-alt anchor target",
		matchInput: configInput([]string{
			"see AKIAIOSFODNN7EXAMPLE here",
			"and ghp_AbCdEfGhIjKlMnOpQrStUvWxYz0123456789Ab next",
		}),
		nomatchInput: configInput([]string{
			"XAKIAIOSFODNN7EXAMPLEY",
			"Xghp_AbCdEfGhIjKlMnOpQrStUvWxYz0123456789Y",
		}),
	},
	{
		// Mixed-shape alternation: one branch is lit-chain shape (ghp_...{36}),
		// the other is NOT (has \s* between literal segments). Under strict
		// alternation detection (current behaviour) this falls through to the
		// DFA entirely — none of the 3 modes will diverge. Under lenient
		// alternation (Phase 2.5, not yet implemented) the ghp_ branch would
		// use lit-chain SIMD verify while the aws_secret_access_key branch
		// would fall back to a per-branch DFA verifier inside the bucket
		// dispatch. Test case here to document the gap.
		name:    "secrets-mixed-alt",
		pattern: `ghp_[A-Za-z0-9]{36}|aws_secret_access_key\s*=\s*[0-9a-zA-Z/+]{40}`,
		mode:    modeFind,
		notes:   "mixed alternation: lit-chain branch + non-lit-chain branch — needs lenient mode",
		matchInput: configInput([]string{
			"ghp_AbCdEfGhIjKlMnOpQrStUvWxYz0123456789Ab",
			"aws_secret_access_key = wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY12",
		}),
		nomatchInput: configInput(nil),
	},
	{
		// Pure dominant self-loop after a literal prefix: [^\n]+ self-loops on
		// 255/256 byte classes — Opt 1 should bulk-skip those bytes via SIMD.
		// Match input has many comment lines; no-match has none.
		name:         "comment-line",
		pattern:      `//[^\n]+`,
		mode:         modeFind,
		notes:        "dominant-self-loop suffix [^\\n]+ — Opt 1 target",
		matchInput:   sourceInput(true),
		nomatchInput: sourceInput(false),
	},
	{
		// URL find: [^\s]+ self-loop after https?://. Slightly less dominant
		// than [^\n]+ but still ~250/256 transitions self-loop.
		name:         "url-suffix",
		pattern:      `https?://[^\s]+`,
		mode:         modeFind,
		notes:        "self-loop suffix [^\\s]+ after literal — Opt 1 target",
		matchInput:   proseInput([]string{"https://example.com/path/to/resource?x=1", "http://api.internal/v2/users/42"}),
		nomatchInput: proseInput(nil),
	},
	{
		// Mixed: comment-line OR block-comment. Both branches have self-loop
		// suffix states; block comment can be hundreds of bytes long. Stresses
		// both Opt 1 (self-loop bulk skip) and Teddy frontend.
		name:    "comments-mixed",
		pattern: `//[^\n]+|/\*(?s:.*?)\*/`,
		mode:    modeFind,
		notes:   "two dominant self-loop states — Opt 1 target (mixed)",
		matchInput: sourceWithBlockComments(true,
			"/*\n * Copyright 2026 Example Corp.\n * Licensed under the Apache License, Version 2.0.\n */",
			"/* TODO: replace with proper error handling once the new\n   error framework is merged into main branch */"),
		nomatchInput: sourceWithBlockComments(false),
	},
}

// --------------------------------------------------------------------------
// Input generators

// configInput returns ~10KB of env-config-style text. Secrets are spread
// evenly through the file if provided; otherwise the output contains none.
func configInput(secrets []string) string {
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
export SESSION_SECRET=change_me_in_production
export GITHUB_ORG=example-org
export AWS_REGION=us-east-1
export AWS_S3_BUCKET=example-data-bucket
`
	base := strings.Repeat(block, (10*1024)/len(block))
	return spread(base, secrets, "\n")
}

// sourceInput returns ~10KB of C-style source code, with optional `// comment` lines.
func sourceInput(withComments bool) string {
	const block = `int processRequest(Request *req, Response *resp) {
    if (req == NULL || resp == NULL) return ERR_INVALID_ARG;
    int status = validateHeaders(req->headers, req->headerCount);
    if (status != OK) { resp->statusCode = 400; return status; }
    Connection *conn = poolAcquire(globalPool, POOL_TIMEOUT_MS);
    if (conn == NULL) { resp->statusCode = 503; return ERR_NO_CONNECTION; }
    QueryResult result = executeQuery(conn, req->path, req->params);
    poolRelease(globalPool, conn);
    resp->statusCode = 200;
    resp->body = result.data;
    return OK;
}

`
	base := strings.Repeat(block, (10*1024)/len(block))
	if !withComments {
		return base
	}
	comments := []string{
		"// initialise connection pool",
		"// retry with exponential backoff",
		"// validate request parameters",
		"// guard against null pointer access",
		"// release pooled connection back to the manager",
	}
	return spread(base, comments, "\n")
}

// sourceWithBlockComments returns ~10KB of C-style source code with optional
// `// comments` and optional `/* block comments */`.
func sourceWithBlockComments(withMatches bool, blockComments ...string) string {
	const block = `int processRequest(Request *req, Response *resp) {
    if (req == NULL || resp == NULL) return ERR_INVALID_ARG;
    int status = validateHeaders(req->headers, req->headerCount);
    if (status != OK) { resp->statusCode = 400; return status; }
    Connection *conn = poolAcquire(globalPool, POOL_TIMEOUT_MS);
    if (conn == NULL) { resp->statusCode = 503; return ERR_NO_CONNECTION; }
    QueryResult result = executeQuery(conn, req->path, req->params);
    poolRelease(globalPool, conn);
    resp->statusCode = 200;
    return OK;
}

`
	base := strings.Repeat(block, (10*1024)/len(block))
	if !withMatches {
		return base
	}
	all := []string{
		"// initialise connection pool",
		"// retry with exponential backoff",
		"// validate request parameters",
	}
	all = append(all, blockComments...)
	return spread(base, all, "\n")
}

// proseInput returns ~10KB of natural-language prose, optionally interleaved with URLs.
func proseInput(urls []string) string {
	const block = `The application encountered an error while processing the request from the
client. The server returned status code four hundred and three, indicating that
the user does not have permission to access the requested resource. Please
contact your system administrator if you believe this is a mistake. The event
has been logged for review by the security team. Timestamp of the failure was
recorded along with the originating address and the affected service name.
`
	base := strings.Repeat(block, (10*1024)/len(block))
	if len(urls) == 0 {
		return base
	}
	wrapped := make([]string, len(urls))
	for i, u := range urls {
		wrapped[i] = "See " + u + " for details."
	}
	return spread(base, wrapped, "\n")
}

// spread inserts `items` evenly through `base`, separated by `sep`.
func spread(base string, items []string, sep string) string {
	if len(items) == 0 {
		return base
	}
	result := []byte(base)
	step := len(result) / (len(items) + 1)
	offset := 0
	for i, it := range items {
		pos := (i+1)*step + offset
		if pos > len(result) {
			pos = len(result)
		}
		line := []byte(it + sep)
		result = append(result[:pos], append(line, result[pos:]...)...)
		offset += len(line)
	}
	return string(result)
}

// --------------------------------------------------------------------------
// Bench shim WASM modules (reuse perftest's shim builders)

var (
	matchBenchShim = buildMatchBenchShim()
	findBenchShim  = buildFindBenchShim()
)

// --------------------------------------------------------------------------
// Per-cell measurement

type cell struct {
	// p50 over the shim's 10k inner timing samples — already statistically tight.
	timeP50 time.Duration
	fuel    uint64
	size    int
}

// compileMode compiles tc.pattern under the given LikelyMode and returns the WASM bytes.
func compileMode(tc testCase, mode compile.LikelyMode) ([]byte, error) {
	re := config.RegexEntry{Pattern: tc.pattern}
	switch tc.mode {
	case modeAnchored:
		re.MatchFunc = "match"
	case modeFind:
		re.FindFunc = "find"
	}
	opts := compile.CompileOptions{LikelyMode: mode}
	wasm, _, err := compile.Compile([]config.RegexEntry{re}, tableBase, true, opts)
	return wasm, err
}

// benchTime times benchIters calls via the WASM shim and returns the p50 of
// those 10k internal samples — already statistically tight.
func benchTime(wasmBytes []byte, tc testCase, input string, engine *wasmtime.Engine) (time.Duration, error) {
	mod, err := wasmtime.NewModule(engine, wasmBytes)
	if err != nil {
		return 0, fmt.Errorf("module: %w", err)
	}
	store := wasmtime.NewStore(engine)
	store.SetWasi(wasmtime.NewWasiConfig())
	inst, err := wasmtime.NewInstance(store, mod, []wasmtime.AsExtern{})
	if err != nil {
		return 0, fmt.Errorf("instance: %w", err)
	}
	var fnExport string
	switch tc.mode {
	case modeAnchored:
		fnExport = "match"
	case modeFind:
		fnExport = "find"
	}
	mem := inst.GetExport(store, "memory").Memory()
	rpdFn := inst.GetFunc(store, fnExport)
	if rpdFn == nil || mem == nil {
		return 0, fmt.Errorf("missing exports")
	}

	var shimBytes []byte
	switch tc.mode {
	case modeAnchored:
		shimBytes = matchBenchShim
	case modeFind:
		shimBytes = findBenchShim
	}
	shimMod, err := wasmtime.NewModule(engine, shimBytes)
	if err != nil {
		return 0, fmt.Errorf("shim module: %w", err)
	}
	linker := wasmtime.NewLinker(engine)
	if err := linker.DefineWasi(); err != nil {
		return 0, fmt.Errorf("linker wasi: %w", err)
	}
	if err := linker.Define(store, "regexped", fnExport, rpdFn); err != nil {
		return 0, fmt.Errorf("linker define: %w", err)
	}
	shimInst, err := linker.Instantiate(store, shimMod)
	if err != nil {
		return 0, fmt.Errorf("shim instantiate: %w", err)
	}
	shimMem := shimInst.GetExport(store, "memory").Memory()
	benchFn := shimInst.GetFunc(store, "bench")

	buf := mem.UnsafeData(store)
	copy(buf[inputBase:], []byte(input))
	inputLen := int32(len(input))

	// 50 ms warmup.
	warmupEnd := time.Now().Add(50 * time.Millisecond)
	for time.Now().Before(warmupEnd) {
		benchFn.Call(store, inputBase, inputLen, int32(benchIters)) //nolint:errcheck
	}

	if _, err := benchFn.Call(store, inputBase, inputLen, int32(benchIters)); err != nil {
		return 0, fmt.Errorf("bench call: %w", err)
	}
	shimBuf := shimMem.UnsafeData(store)
	return computeStat(shimBuf[:timingsBytes], 50), nil
}

// benchFuel measures fuel for a single call.
func benchFuel(wasmBytes []byte, tc testCase, input string, fuelEngine *wasmtime.Engine) (uint64, error) {
	mod, err := wasmtime.NewModule(fuelEngine, wasmBytes)
	if err != nil {
		return 0, err
	}
	store := wasmtime.NewStore(fuelEngine)
	if err := store.SetFuel(fuelBudget); err != nil {
		return 0, err
	}
	inst, err := wasmtime.NewInstance(store, mod, []wasmtime.AsExtern{})
	if err != nil {
		return 0, err
	}
	var fnExport string
	switch tc.mode {
	case modeAnchored:
		fnExport = "match"
	case modeFind:
		fnExport = "find"
	}
	mem := inst.GetExport(store, "memory").Memory()
	fn := inst.GetFunc(store, fnExport)
	buf := mem.UnsafeData(store)
	copy(buf[inputBase:], []byte(input))
	inputLen := int32(len(input))

	before, _ := store.GetFuel()
	if _, err := fn.Call(store, inputBase, inputLen); err != nil {
		return 0, err
	}
	after, _ := store.GetFuel()
	return before - after, nil
}

// measure compiles + runs (tc, mode, input) and returns one cell.
func measure(tc testCase, mode compile.LikelyMode, input string, engine, fuelEngine *wasmtime.Engine) (cell, error) {
	wasm, err := compileMode(tc, mode)
	if err != nil {
		return cell{}, fmt.Errorf("compile %s: %w", mode, err)
	}
	t, err := benchTime(wasm, tc, input, engine)
	if err != nil {
		return cell{}, fmt.Errorf("bench time %s: %w", mode, err)
	}
	f, err := benchFuel(wasm, tc, input, fuelEngine)
	if err != nil {
		return cell{}, fmt.Errorf("bench fuel %s: %w", mode, err)
	}
	return cell{timeP50: t, fuel: f, size: len(wasm)}, nil
}

// --------------------------------------------------------------------------
// Formatting

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

func fmtFuel(n uint64) string {
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

// gain returns "  —" for the baseline row, or a signed percentage like "-23%"/"+8%".
// Negative = faster/cheaper than neutral; positive = slower/more expensive.
func gain(cur, base float64) string {
	if base == 0 {
		return "   —"
	}
	pct := (cur - base) / base * 100
	if pct > -0.5 && pct < 0.5 {
		return "  0%"
	}
	return fmt.Sprintf("%+4.0f%%", pct)
}


// printMatrix prints the 3x{2 inputs × 2 metrics} table for one pattern.
// rows: neutral, likely-match, likely-nomatch.
func printMatrix(tc testCase, rows [3]cell, rowsNo [3]cell) {
	fmt.Printf("\n=== %s  [%s, %q] ===\n", tc.name, tc.mode, tc.pattern)
	fmt.Printf("  %s\n", tc.notes)
	fmt.Printf("  match input: %d bytes, no-match input: %d bytes\n", len(tc.matchInput), len(tc.nomatchInput))
	fmt.Printf("  wasm size:  neutral=%d B  likely-match=%d B  likely-nomatch=%d B\n",
		rows[0].size, rows[1].size, rows[2].size)

	modes := [3]string{"neutral", "likely-match", "likely-nomatch"}
	header := fmt.Sprintf("  %-16s  %18s %5s  %14s %5s   %18s %5s  %14s %5s",
		"mode",
		"time(match)", "Δ%", "fuel(match)", "Δ%",
		"time(no-m)", "Δ%", "fuel(no-m)", "Δ%")
	fmt.Println(header)
	fmt.Println("  " + strings.Repeat("─", len(header)-2))

	baseT, baseF := float64(rows[0].timeP50), float64(rows[0].fuel)
	baseTn, baseFn := float64(rowsNo[0].timeP50), float64(rowsNo[0].fuel)

	for i := 0; i < 3; i++ {
		rT, rF := float64(rows[i].timeP50), float64(rows[i].fuel)
		nT, nF := float64(rowsNo[i].timeP50), float64(rowsNo[i].fuel)
		gT, gF := "   —", "   —"
		gTn, gFn := "   —", "   —"
		if i > 0 {
			gT, gF = gain(rT, baseT), gain(rF, baseF)
			gTn, gFn = gain(nT, baseTn), gain(nF, baseFn)
		}
		fmt.Printf("  %-16s  %12s %5s  %14s %5s   %12s %5s  %14s %5s\n",
			modes[i],
			fmtDur(rows[i].timeP50), gT,
			fmtFuel(rows[i].fuel), gF,
			fmtDur(rowsNo[i].timeP50), gTn,
			fmtFuel(rowsNo[i].fuel), gFn,
		)
	}
}

// --------------------------------------------------------------------------
// Warmup (matches perftest's behaviour)

var minimalWASM = []byte{0x00, 0x61, 0x73, 0x6d, 0x01, 0x00, 0x00, 0x00}

func warmup(engine *wasmtime.Engine) {
	mod, err := wasmtime.NewModule(engine, minimalWASM)
	if err != nil {
		return
	}
	store := wasmtime.NewStore(engine)
	_, _ = wasmtime.NewInstance(store, mod, []wasmtime.AsExtern{})
}

// --------------------------------------------------------------------------
// Main

func main() {
	// Silence regexped's slog output.
	slog.SetDefault(slog.New(slog.NewTextHandler(io.Discard, nil)))

	engine := wasmtime.NewEngine()
	warmup(engine)

	fuelCfg := wasmtime.NewConfig()
	fuelCfg.SetConsumeFuel(true)
	fuelEngine := wasmtime.NewEngineWithConfig(fuelCfg)

	modes := [3]compile.LikelyMode{compile.LikelyNeutral, compile.LikelyMatch, compile.LikelyNoMatch}

	fmt.Println("likelytest — LikelyMode 3x3 matrix (p50 over 10k inner iterations per cell)")

	for _, tc := range tests {
		fmt.Fprintf(os.Stderr, "==> %s\n", tc.name)
		var rowsMatch, rowsNoMatch [3]cell
		for i, m := range modes {
			c, err := measure(tc, m, tc.matchInput, engine, fuelEngine)
			if err != nil {
				fmt.Fprintf(os.Stderr, "  measure %s match: %v\n", m, err)
				continue
			}
			rowsMatch[i] = c
			c, err = measure(tc, m, tc.nomatchInput, engine, fuelEngine)
			if err != nil {
				fmt.Fprintf(os.Stderr, "  measure %s no-match: %v\n", m, err)
				continue
			}
			rowsNoMatch[i] = c
		}
		printMatrix(tc, rowsMatch, rowsNoMatch)
	}
	fmt.Println()
}
