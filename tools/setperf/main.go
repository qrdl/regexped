// Command setperf compares every regexped set capability against
// `regex-automata`, the layer underneath the `regex` crate's facade.
//
// # Why a separate tool from perftest
//
// `perftest --sets` compares against `RegexSet::matches` plus a per-pattern
// rescan, because `RegexSet` deliberately reports *which* patterns match and
// never *where*. That two-pass composite is a fair model of what a `regex`
// user would write, but an unfair model of the engine — we benchmark against
// an emulation, which flatters us. `regex-automata` maps onto the new set API
// almost one-to-one: `Input::span` IS the `from` parameter, `PatternSet` is
// our bitmask plus pattern ids, and `MatchKind::LeftmostFirst` is its default,
// so we are not comparing against leftmost-longest by accident.
//
// It is a separate TOOL because perftest's committed baselines are the
// standing regression signal for everything else in the project; churning
// them through set work would entangle the two. The methodology — p50
// sampling, wasmtime fuel metering, module size, exact-fuel gating — is
// copied deliberately rather than reinvented.
//
// # Reading the numbers
//
// Fuel is EXACT and deterministic within one engine, and is the gating metric
// for our own regressions. ACROSS engines it is indicative only: it counts
// WASM instructions, and Rust→WASM codegen differs structurally from our
// hand-emitted WASM. Track the ratio over time; a single absolute number
// means nothing. The two kinds of fuel are labelled differently for that
// reason.
//
// Wall-clock on this machine is instruction-placement noise; compare the
// ratio, averaged over several runs, or don't compare it at all.
//
// Usage:
//
//	go run .                  # the full matrix
//	go run . -fuel            # our fuel only (deterministic; the regression gate)
//	go run . -size            # module sizes, ours vs theirs
//	go run . -verify          # cross-engine correctness on the honest pairings
//	go run . -compare-fuel baseline_fuel.txt
package main

import (
	"encoding/binary"
	"errors"
	"flag"
	"fmt"
	"os"
	"path/filepath"
	"runtime"
	"sort"
	"strconv"
	"strings"
	"time"

	wasmtime "github.com/bytecodealliance/wasmtime-go/v48"
	"github.com/qrdl/regexped/compile"
	"github.com/qrdl/regexped/config"
	"github.com/qrdl/regexped/internal/utils"
)

const (
	pageSize   = 65536
	fuelBudget = 4_000_000_000
	benchIters = 2000

	// callBoundFuel is the fuel below which a wall-clock ratio describes the
	// two HARNESSES rather than the two engines, so the ratio column is
	// suppressed.
	//
	// Our side times one Go→wasmtime Func.Call per sample; theirs loops
	// `iters` times INSIDE WASM and reports per-iteration nanoseconds. That
	// call costs ~4-7 us (measured independently), which is fixed
	// per row. Every anchored row spends 52-58 WASM instructions — work that
	// cannot take 4 us — and duly printed "~0.02x", reading as a 50x loss on
	// capabilities where we are in fact spending almost nothing.
	//
	// 10,000 was chosen so the suppressed band is the one where the call
	// dominates: at roughly a nanosecond per instruction, 10K fuel is ~10 us
	// of real work, i.e. the first point at which the ~4-7 us call is a
	// minority of the sample. Rows above it print a ratio; rows below print
	// "call-bound" and still show both raw times.
	callBoundFuel = 10_000

	// overlappingTimedCap bounds the INPUT for the timed find(overlapping)
	// row only.
	//
	// That body is the deliberate every-start-position enumeration,
	// so on a set with no mandatory literal it is O(n^2): greedy-3 over 50,000
	// 'a's is ~1.25 BILLION DFA steps for ONE exhaustion, and measureTime
	// wants benchIters of them. The default matrix therefore could not be run
	// to completion — which is the mechanical reason the cross-engine
	// numbers went unrecorded for the whole project.
	//
	// Only the timed path is bounded. Fuel rows keep the full input: they do
	// one exhaustion, which completes, and bounding them would silently
	// change the committed fuel baselines. The consequence is that for a
	// capped row the fuel column and the time column describe different input
	// lengths, so the row is labelled to say so rather than quietly mixing
	// them.
	overlappingTimedCap = 2048

	// timedFuelCap is the fuel above which the TIMED run switches to the
	// shortened input (see overlappingTimedCap). benchIters samples of a row
	// this expensive is minutes to hours of wall time.
	//
	// An earlier note blamed the unrunnable matrix on find(overlapping) alone. That was
	// the row it happened to be killed in; measuring showed the property is
	// not specific to that capability but to "must visit every start position
	// on a set with no mandatory literal", which on greedy-3 over 50,000 'a's
	// makes scan_all and find quadratic too — all three exhaust even the fuel
	// budget. Keying the bound on measured cost rather than on a capability
	// name covers whichever rows actually turn out to be quadratic.
	timedFuelCap = 50_000_000

	// fuelExhausted marks a row whose single measurement ran out of fuel.
	// Distinct from any real count, which is bounded by fuelBudget.
	fuelExhausted = ^uint64(0)
)

// capability names the exports, in a fixed order.
//
// `match` and `scan` are gone: retired them, since
// `match_any(...) >= 0` and `scan_any(...) >= 0` are exactly what they
// returned.
type capability string

const (
	capMatchAny capability = "match_any"
	capMatchAll capability = "match_all"
	capScanAny  capability = "scan_any"
	capScanAll  capability = "scan_all"
	capFind     capability = "find"
	// capFindBatch is the multi-position find, now requested with
	// `hints: [batch-find]` rather than declared (decision (11)). It is the row that makes the
	// `find` comparison an honest one: ra_bench_find_gated runs its WHOLE
	// enumeration inside ONE wasm call, while our `find` crosses the host
	// boundary once per position. find_batch crosses once per BUFFERFUL, so
	// the two sides finally differ by engine work rather than by call count.
	capFindBatch capability = "find_batch"
	// capFindOverlapping is the ungated `find`. regex-automata has no
	// equivalent — per-start-position enumeration is not a search it can
	// express — so it is measured but never compared.
	capFindOverlapping capability = "find(overlapping)"
	// capFindBatchOverlapping is the batching entry of an overlapping set.
	// Added while investigating a batching sweep and KEPT after that
	// stage was reverted: before this row, overlapping sets were measured
	// through the lazy `find` alone, so the batching entry — the one a stub
	// user actually gets under `hints: [batch-find]` — had no number at all.
	// That blind spot is why stage B's 19.6x regression was invisible until
	// the row existed. Do not remove it with the feature it was added for.
	capFindBatchOverlapping capability = "find_batch(overlapping)"
)

var allCaps = []capability{
	capMatchAny, capMatchAll,
	capScanAny, capScanAll,
	capFind, capFindBatch, capFindOverlapping, capFindBatchOverlapping,
}

// batchCap is the tuple buffer the find_batch row is driven with, in matches.
// It is the default the generated stubs pick, so the row measures what a stub
// user actually gets rather than a best case tuned for the benchmark.
const batchCap = 256

// exportName is the WASM export each capability is compiled under.
func exportName(c capability) string {
	switch c {
	case capFindOverlapping:
		return "cap_find"
	case capFindBatchOverlapping:
		return config.SetBatchExportName("cap_find")
	case capFindBatch:
		// Synthesized from `find`'s name under the hint, not declared, so it
		// is derived through the same function the compiler and the six
		// generators use.
		return config.SetBatchExportName("cap_find")
	}
	return "cap_" + string(c)
}

// raPairing names the regex-automata export a capability is compared against,
// or "" when the pairing would be dishonest.
func raPairing(c capability) string {
	switch c {
	case capScanAny:
		return "ra_bench_scan_any"
	case capScanAll:
		return "ra_bench_scan_all"
	case capMatchAny:
		return "ra_bench_match"
	case capMatchAll:
		return "ra_bench_match_all"
	case capFind:
		// Per-pattern find_iter merged — the same construction the
		// gated-find oracle uses. regex-automata's own multi-pattern
		// find_iter is SET-WIDE non-overlapping while our gated find is
		// PER-PATTERN; pairing those directly would be confidently wrong.
		return "ra_bench_find_gated"
	case capFindBatch:
		// The same pairing as `find`, and the fair one: both sides now make
		// O(matches / buffer) host crossings instead of one side making O(1)
		// and the other O(matches).
		return "ra_bench_find_gated"
	}
	return ""
}

// timedRatioIsAPIShape reports whether a capability's TIMED ratio would
// measure the shape of the two APIs rather than the two engines.
//
// Only bare `find` qualifies, and the tool half-knew it already: raPairing's
// comment on capFindBatch calls that pairing "the fair one", because there
// both sides make O(matches/buffer) host crossings. Bare `find` is the same
// pairing with our side making one crossing PER MATCH and theirs making one in
// total, so its ratio was never an engine comparison. The FUEL ratio is unaffected and stays printed: a Go->wasmtime call
// executes no wasm instructions, so that column has no crossing term to
// distort.
//
// Scope note, so the label is not over-read: the crossings are not a defect.
// Batching is built (item 19) and closes the gap on the same rows, and for
// C/Go/Rust/AS there are no crossings at all — wasm-merge makes a stub call
// intra-module, which is why TestSetBatchFindIsJSTSOnly pins batching as
// JS/TS-only.
//
// One caveat on the row itself: compileCase always sets `hints: [batch-find]`,
// so what this measures is the BATCHING set's `find` — the forwarding wrapper
// over the shared per-position worker (decision (11a)) — not a hint-less
// module's own bucket code. The two differ by one call per position. Measuring
// a hint-less module instead would be the truer model of un-hinted JS/TS, but
// it changes every `find` fuel and size value and so forces a rebaseline of
// files that are gitignored and unrecoverable; that is the owner's call.
func timedRatioIsAPIShape(c capability) bool {
	return c == capFind
}

// raFuelPairing is raPairing for the FUEL comparison: the same task, but the
// harness's ONE-SHOT export rather than its `ra_bench_*` timing wrapper.
//
// The bench exports loop `iters` times inside wasm and take timestamps, so
// metering them would count the loop, the clock calls and the timings writes
// along with the engine work. The one-shot exports do exactly one whole-input
// operation — they are what `--verify` already calls — and their bodies are
// the same code the bench wrappers loop over. That makes them the honest fuel
// target, and it is why no new Rust entry point was needed for any of this.
func raFuelPairing(c capability) string {
	switch c {
	case capScanAny:
		return "ra_scan_any"
	case capScanAll:
		return "ra_scan_all"
	case capMatchAny:
		return "ra_match"
	case capMatchAll:
		return "ra_match_all"
	case capFind, capFindBatch:
		// Same pairing rule as raPairing: the per-pattern merged enumeration.
		// One call walks the whole input for every pattern, which is what one
		// exhausted drive is on our side.
		return "ra_find_gated"
	}
	return ""
}

// raFuelArgs returns the argument list for the one-shot export, whose arity
// differs by capability: the anchored pair takes only a length, everything
// else also takes `from`.
func raFuelArgs(c capability, inputLen int32) []interface{} {
	switch c {
	case capMatchAny, capMatchAll:
		return []interface{}{inputLen}
	default:
		return []interface{}{inputLen, int32(0)}
	}
}

// setCase is one (set, input) row of the matrix.
type setCase struct {
	name     string
	patterns []string
	input    string
	inputLbl string
}

func main() {
	fuelOnly := flag.Bool("fuel", false, "print our fuel only (deterministic)")
	fuelCross := flag.Bool("fuel-cross", false, "our fuel vs regex-automata's, both metered (deterministic; no timing)")
	sizeOnly := flag.Bool("size", false, "print module sizes only")
	verify := flag.Bool("verify", false, "cross-engine correctness on the honest pairings")
	compareFuel := flag.String("compare-fuel", "", "compare our fuel against a baseline file; exit 1 on any change")
	compareSize := flag.String("compare-size", "", "compare module sizes against a baseline file; exit 1 on any change")
	flag.Parse()

	cases := buildMatrix()

	switch {
	case *compareFuel != "":
		os.Exit(runCompare(*compareFuel, cases, measureFuelRow, "fuel"))
	case *compareSize != "":
		os.Exit(runCompare(*compareSize, cases, measureSizeRow, "size"))
	case *fuelOnly:
		printRows(cases, measureFuelRow, "fuel")
		return
	case *fuelCross:
		runFuelCross(cases)
		return
	case *sizeOnly:
		printRows(cases, measureSizeRow, "bytes")
		return
	case *verify:
		os.Exit(runVerify(cases))
	}
	runFullMatrix(cases)
}

// --------------------------------------------------------------------------
// The matrix.
//
// Set sizes cross the structural thresholds: 2 (trivial), 8, 32 (the
// per-bucket bitmask width), 64 and 128 (the <=64 / >64 `_all` split).

func buildMatrix() []setCase {
	var out []setCase
	for _, n := range []int{2, 8, 32, 64, 128} {
		pats := keywordPatterns(n)
		out = append(out,
			setCase{fmt.Sprintf("keywords-%d", n), pats, corpusNoMatch(), "no-match 100KB"},
			setCase{fmt.Sprintf("keywords-%d", n), pats, corpusSparse(pats), "sparse 100KB"},
			setCase{fmt.Sprintf("keywords-%d", n), pats, corpusDense(pats), "dense 100KB"},
		)
	}
	// A literal-anchored set, the shape that wants the "~1x from gating"
	// claim measured on.
	secrets := []string{
		`AKIA[A-Z0-9]{16}`,
		`ghp_[A-Za-z0-9]{36}`,
		`sk_live_[A-Za-z0-9]{24}`,
		`eyJ[A-Za-z0-9_-]{20,}`,
	}
	out = append(out,
		setCase{"secrets-4", secrets, corpusNoMatch(), "no-match 100KB"},
		setCase{"secrets-4", secrets, corpusSparse(secrets), "sparse 100KB"},
	)
	// A set whose literals share NO first byte. Every keywords-* literal
	// starts 'k', so before this the matrix could not see the AC frontend's
	// first-byte prefilter at all: moving that prefilter from a per-byte
	// compare chain to Shufti cut this shape's scan fuel by 28% and moved
	// not one of the 146 committed rows. Prefix sharing
	// is also what decides AC's node count, so this is the shape that governs
	// the table budget too.
	diverse := make([]string, 32)
	for i := range diverse {
		diverse[i] = fmt.Sprintf("%cQ%03d[0-9a-z]{3}", "abcdefghijklmnopqrstuvwxyz0123456789"[i%36], i)
	}
	out = append(out,
		setCase{"diverse-32", diverse, corpusNoMatch(), "no-match 100KB"},
		setCase{"diverse-32", diverse, corpusSparse(diverse), "sparse 100KB"},
	)
	// A set whose patterns share one SUFFIX behind distinct literals. Every
	// other set here has a counted-class-chain suffix ([0-9a-z]{3} and
	// friends), which genSuffixWASM answers with SIMD and no table at all —
	// so nothing in the matrix built a suffix table to begin with, and
	// suffix-table dedup moved zero rows despite cutting these shapes'
	// modules by ~70%. An alternation suffix does build a
	// table, which is what makes this case load-bearing.
	shared := make([]string, 32)
	for i := range shared {
		shared[i] = fmt.Sprintf("kw%03d(?:alpha|beta|gamma)", i)
	}
	out = append(out,
		setCase{"sharedsuffix-32", shared, corpusNoMatch(), "no-match 100KB"},
		setCase{"sharedsuffix-32", shared, corpusSparse(shared), "sparse 100KB"},
	)
	// Sets whose patterns all share ONE mandatory literal — the WAF shape, and
	// the only one here that exercises multi-bucket dispatch behind a single
	// literal. Every other set has distinct literals, so it gets
	// one bucket per literal and the bucket-count factor G17 attacks never
	// appears at all.
	//
	// TWO sizes on purpose. 32 patterns is ONE bucket and 128 is FOUR (the
	// 32-pattern bitmask width), so the pair measures the factor directly
	// rather than asserting it: the cost of the 128 row should track four
	// suffix-DFA calls per candidate against the 32 row's one.
	//
	// The distinct part must be NON-LITERAL or the shape silently stops
	// sharing: mandatory-literal extraction takes the LONGEST literal, so
	// `unionkw000` would give each pattern its own literal AND its own bucket.
	// Verified: 128 distinct patterns, one literal `union`, four buckets of 32.
	//
	// The DENSE corpus is the load-bearing one: per-candidate cost only
	// exists where the literal actually hits, and the no-match row is expected
	// to stay flat between the two sizes for exactly that reason.
	sharedLitPatterns := func(n int) []string {
		out := make([]string, n)
		for i := range out {
			out[i] = fmt.Sprintf(`union[ \t]+[a-z]{%d}[0-9]{%d}`, 1+i/16, 1+i%16)
		}
		return out
	}
	for _, n := range []int{32, 128} {
		pats := sharedLitPatterns(n)
		out = append(out,
			setCase{fmt.Sprintf("sharedlit-%d", n), pats, corpusNoMatch(), "no-match 100KB"},
			setCase{fmt.Sprintf("sharedlit-%d", n), pats, corpusDense(pats), "dense 100KB"},
		)
	}
	// Sets with NO mandatory literal that are also large enough to split on the
	// 32-bit accept mask — the fallback packer's version of the sharedlit pair
	// above, and the shape G17's promotion was extended to cover.
	//
	// A fallback bucket has no literal gating it, so each of the ceil(N/32)
	// suffix walks runs at EVERY input position rather than only where a
	// literal hit. That makes the no-match corpus load-bearing here, where the
	// sharedlit pair needed a dense one: with nothing to skip, the whole input
	// pays the bucket-count factor.
	//
	// These rows also cover the ANCHORED packer, since setperf drives match_any
	// and match_all: 128 of these merge to one anchored bucket where they used
	// to make four. The sharedlit patterns do NOT — their full-pattern merge
	// crosses 256 states into u16 cells and misses the 64 KB byte budget, so
	// promoteSparseBuckets refuses it. That asymmetry is the reason this family
	// is here rather than a bigger sharedlit row.
	classChainPatterns := func(n int) []string {
		out := make([]string, n)
		for i := range out {
			out[i] = fmt.Sprintf(`[a-z]{%d}[0-9]{%d}`, 1+i/16, 1+i%16)
		}
		return out
	}
	for _, n := range []int{32, 128} {
		pats := classChainPatterns(n)
		out = append(out,
			setCase{fmt.Sprintf("classchain-%d", n), pats, corpusNoMatch(), "no-match 100KB"},
			setCase{fmt.Sprintf("classchain-%d", n), pats, corpusDense(pats), "dense 100KB"},
		)
	}
	// A set with no mandatory literal at all: every position is visited, so
	// this is where gating has the most to recover.
	greedy := []string{`a+`, `[^\n]*ERROR`, `x?y`}
	out = append(out,
		// The shape stage A's preflight cannot touch: the never-dying pattern
		// IS present, so it can never be retired, and every start position
		// walks to it. One ERROR at the far end of newline-free filler makes
		// that walk as long as it gets. This is the one row that isolates
		// "never-dying and PRESENT" from "never-dying and absent", and it is
		// over the 4e9 budget today — still open,
		// which stage B was built for and failed to close.
		setCase{"greedy-3", greedy, corpusNoMatch()[:100*1024-5] + "ERROR", "late ERROR 100KB"},
		setCase{"greedy-3", greedy, strings.Repeat("a", 50000), "50K a's"},
		// The complement of the row above: the never-dying pattern's literal
		// is ABSENT, so the preflight can retire it. NOT a no-match row —
		// corpusNoMatch's filler contains "a" and "y", which `a+` and `x?y`
		// match ~1,830 times each per 100 KB — which is why it is labelled
		// for the letter it lacks rather than for matching nothing.
		setCase{"greedy-3", greedy, corpusNoMatch(), "no-ERROR 100KB"},
	)
	return out
}

func keywordPatterns(n int) []string {
	pats := make([]string, n)
	for i := 0; i < n; i++ {
		pats[i] = fmt.Sprintf("kw%03d[0-9a-z]{3}", i)
	}
	return pats
}

// corpusNoMatch is 100KB of filler none of the LITERAL-BEARING patterns can
// match.
//
// The name is a promise it can only keep for a set whose patterns carry a
// mandatory literal. greedy-3 is the exception: its `a+` matches the "a" in
// "lazy", its `x?y` matches every "y", and there are ~1,830 of each per 100 KB.
// Those rows are therefore labelled "no-ERROR 100KB" rather than "no-match":
// what they isolate is the ABSENCE of the never-dying pattern's literal, not
// an absence of matches. Any new caller on a literal-less set owes itself the
// same check before using the word "no-match".
func corpusNoMatch() string {
	var b strings.Builder
	line := "the quick brown fox jumps over the lazy dog 0123456789 "
	for b.Len() < 100*1024 {
		b.WriteString(line)
	}
	return b.String()
}

// corpusSparse plants a handful of matches in otherwise inert filler.
func corpusSparse(pats []string) string {
	base := corpusNoMatch()
	needles := sampleNeedles(pats, 5)
	step := len(base) / (len(needles) + 1)
	var b strings.Builder
	for i, nd := range needles {
		b.WriteString(base[i*step : (i+1)*step])
		b.WriteString(nd)
	}
	b.WriteString(base[len(needles)*step:])
	return b.String()
}

// corpusDense plants a match roughly every 40 bytes.
func corpusDense(pats []string) string {
	needles := sampleNeedles(pats, len(pats))
	filler := "..... filler ..... "
	var b strings.Builder
	for i := 0; b.Len() < 100*1024; i++ {
		b.WriteString(filler)
		b.WriteString(needles[i%len(needles)])
		b.WriteString(" ")
	}
	return b.String()
}

// sampleNeedles produces a concrete matching string for each of up to k
// patterns. It only understands the shapes buildMatrix uses.
func sampleNeedles(pats []string, k int) []string {
	if k > len(pats) {
		k = len(pats)
	}
	out := make([]string, 0, k)
	for i := 0; i < k; i++ {
		switch p := pats[i]; {
		case strings.HasPrefix(p, "kw") && strings.Contains(p, "(?:alpha|beta|gamma)"):
			// sharedsuffix: `kw%03d(?:alpha|beta|gamma)`. It shares the "kw"
			// prefix with the keywords-* family, so it used to take the arm
			// below and get the needle `kw000abc` — which does not match, so
			// its "sparse" corpus was a second no-match corpus and the ONLY
			// shape in the matrix that builds a suffix TABLE never had its
			// successful-match path measured at all.
			out = append(out, p[:5]+"alpha")
		case strings.HasPrefix(p, "kw"):
			out = append(out, p[:5]+"abc")
		case len(p) > 2 && p[1] == 'Q' && strings.Contains(p, "[0-9a-z]{3}"):
			// diverse: `%cQ%03d[0-9a-z]{3}` — no arm matched it at all, so it
			// fell through to the default "xy" and its "sparse" corpus matched
			// nothing either.
			out = append(out, p[:5]+"abc")
		case strings.HasPrefix(p, "AKIA"):
			out = append(out, "AKIAIOSFODNN7EXAMPLE")
		case strings.HasPrefix(p, "ghp_"):
			out = append(out, "ghp_"+strings.Repeat("A", 36))
		case strings.HasPrefix(p, "sk_live_"):
			out = append(out, "sk_live_"+strings.Repeat("B", 24))
		case strings.HasPrefix(p, "eyJ"):
			out = append(out, "eyJ"+strings.Repeat("C", 24))
		case strings.HasPrefix(p, "union"):
			// `union[ \t]+[a-z]{A}[0-9]{B}` — rebuild a matching needle from
			// the pattern's own two counts so the sparse corpus really hits.
			var a, b int
			fmt.Sscanf(p, `union[ \t]+[a-z]{%d}[0-9]{%d}`, &a, &b)
			out = append(out, "union "+strings.Repeat("q", a)+strings.Repeat("7", b))
		case strings.HasPrefix(p, "[a-z]{"):
			// classchain: `[a-z]{A}[0-9]{B}`, same rebuild as the union arm.
			// Before this arm existed the patterns fell through to the default
			// needle "xy" — which contains no digit, so classchain's "dense"
			// corpus matched NOTHING and its dense rows were a second no-match
			// corpus with different byte statistics (see the notes above,
			// instrument fix; the tell was dense fuel == no-match fuel to the
			// digit).
			var a, b int
			fmt.Sscanf(p, `[a-z]{%d}[0-9]{%d}`, &a, &b)
			out = append(out, strings.Repeat("q", a)+strings.Repeat("7", b))
		case p == `a+`:
			out = append(out, "aaaa")
		case strings.Contains(p, "ERROR"):
			out = append(out, "ERROR")
		default:
			// A HARD ERROR, not a fallback. Three separate incidents —
			// classchain, sharedsuffix and diverse
			// — were all the same cause: a pattern shape
			// with no arm silently got a needle that does not match, turning
			// its "dense"/"sparse" corpus into a second no-match corpus under
			// a wrong label. A benchmark measuring the wrong thing quietly is
			// worse than one that refuses to run.
			fmt.Fprintf(os.Stderr, "sampleNeedles: no needle arm for pattern %q — add one\n", p)
			os.Exit(1)
		}
	}
	return out
}

// --------------------------------------------------------------------------
// regexped side.

// compileCase compiles one set exporting every capability. `overlapping`
// selects which find body is emitted; the other six are unaffected.
func compileCase(c setCase, overlapping bool) ([]byte, error) {
	entries := make([]config.RegexEntry, len(c.patterns))
	names := make([]string, len(c.patterns))
	for i, p := range c.patterns {
		names[i] = fmt.Sprintf("p%d", i)
		entries[i] = config.RegexEntry{Name: names[i], Pattern: p}
	}
	sets := []config.SetConfig{{
		Name:        "s",
		MatchAny:    "cap_match_any",
		MatchAll:    "cap_match_all",
		ScanAny:     "cap_scan_any",
		ScanAll:     "cap_scan_all",
		Find:        "cap_find",
		Hints:       []string{"batch-find"},
		Overlapping: overlapping,
		Patterns:    config.PatternSelector{Names: names},
	}}
	w, _, err := compile.CompileFile(config.BuildConfig{Regexps: entries, Sets: sets}, "")
	return w, err
}

// rxInstance is an instantiated regexped module with its memory layout.
type rxInstance struct {
	store    *wasmtime.Store
	inst     *wasmtime.Instance
	mem      *wasmtime.Memory
	inBase   int32
	outPtr   int32
	gatePtr  int32
	bitmapPt int32
	batchPtr int32
	// cachePtr/cacheLen are the OVERLAPPING answer cache (see the
	// stage C). Offered only to the overlapping batch entry, which is what a
	// generated JS/TS iterator does: every other capability is handed 0, 0
	// and takes the ordinary per-position walk.
	cachePtr int32
	cacheLen int32
	npat     int32
	inLen    int32
	// fnCache holds resolved exports. Resolving inside the timed loop meant
	// every measured operation paid a string-keyed export lookup that is
	// neither engine work nor the wasmtime crossing — pure harness cost, and
	// it inflated every one of our rows.
	fnCache map[capability]*wasmtime.Func
}

// fnFor resolves a capability's export once and caches it.
func (r *rxInstance) fnFor(c capability) *wasmtime.Func {
	if r.fnCache == nil {
		r.fnCache = make(map[capability]*wasmtime.Func, len(allCaps))
	}
	if fn, ok := r.fnCache[c]; ok {
		return fn
	}
	fn := r.inst.GetFunc(r.store, exportName(c))
	r.fnCache[c] = fn
	return fn
}

func newRxInstance(engine *wasmtime.Engine, wasm []byte, c setCase, withFuel bool) (*rxInstance, error) {
	mod, err := wasmtime.NewModule(engine, wasm)
	if err != nil {
		return nil, err
	}
	store := wasmtime.NewStore(engine)
	store.SetWasi(wasmtime.NewWasiConfig())
	if withFuel {
		if err := store.SetFuel(fuelBudget); err != nil {
			return nil, err
		}
	}
	inst, err := wasmtime.NewInstance(store, mod, []wasmtime.AsExtern{})
	if err != nil {
		return nil, err
	}
	exp := inst.GetExport(store, "memory")
	if exp == nil {
		return nil, fmt.Errorf("module has no memory export")
	}
	mem := exp.Memory()

	dataTop, err := utils.ParseDataSectionBytes(wasm)
	if err != nil {
		return nil, err
	}
	npat := int32(len(c.patterns))
	inBase := int32((dataTop + pageSize - 1) / pageSize * pageSize)
	span := int32((len(c.input) + pageSize - 1) / pageSize * pageSize)
	if span < pageSize {
		span = pageSize
	}
	outPtr := inBase + span
	gatePtr := outPtr + npat*12
	bitmapPt := gatePtr + npat*4
	// The batch buffer sits above the bitmap, 4 KB clear of it.
	batchPtr := bitmapPt + int32(npat)/8 + 4096
	cachePtr := (batchPtr + int32(batchCap)*12 + 4096 + 7) &^ 7
	cacheLen := int32(config.SetOverlapCacheBytes(len(c.input), int(npat)))
	top := int64(cachePtr) + int64(cacheLen) + 4096
	needed := uint64((top + pageSize - 1) / pageSize)
	if cur := mem.Size(store); needed > cur {
		if _, err := mem.Grow(store, needed-cur); err != nil {
			return nil, err
		}
	}
	copy(mem.UnsafeData(store)[inBase:], c.input)
	runtime.KeepAlive(store)
	return &rxInstance{
		store: store, inst: inst, mem: mem,
		inBase: inBase, outPtr: outPtr, gatePtr: gatePtr, bitmapPt: bitmapPt,
		batchPtr: batchPtr,
		cachePtr: cachePtr, cacheLen: cacheLen,
		npat: npat, inLen: int32(len(c.input)),
	}, nil
}

// zeroBitmap clears the >64-pattern bitmap before a wide `_all` call.
//
// The wide body only ORs hit bits in and counts 0->1 transitions, so it
// REQUIRES an all-zero bitmap on entry — every generated stub zeroes one
// (Rust [0u8; N], JS .fill(0), Go a fresh slice, C = {0}). Measuring without
// zeroing meant the warm-up call set every bit and each measured call then
// skipped the store-and-count branch for every already-set pattern, so the
// recorded fuel described a code path no real caller executes.
func (r *rxInstance) zeroBitmap() {
	buf := r.mem.UnsafeData(r.store)
	n := (r.npat + 7) / 8
	for i := int32(0); i < n; i++ {
		buf[r.bitmapPt+i] = 0
	}
}

// call runs one whole-input operation for the given capability, exactly as a
// caller would — the `_all` pair once, the `_any` pair once, `find` driven to
// exhaustion — and returns how many Go→wasmtime crossings that took.
//
// The count is what lets measureTime subtract the harness boundary cost: every
// crossing carries a fixed ~4 us that has nothing to do with the engine, and
// `find` pays one per match.
func (r *rxInstance) call(c capability, wide bool) (int, error) {
	fn := r.fnFor(c)
	if fn == nil {
		return 0, fmt.Errorf("missing export %s", exportName(c))
	}
	switch c {
	case capMatchAny:
		_, err := wcall(fn, r.store, r.inBase, r.inLen)
		return 1, err
	case capMatchAll:
		if wide {
			r.zeroBitmap()
			_, err := wcall(fn, r.store, r.inBase, r.inLen, r.bitmapPt)
			return 1, err
		}
		_, err := wcall(fn, r.store, r.inBase, r.inLen)
		return 1, err
	case capScanAny:
		_, err := wcall(fn, r.store, r.inBase, r.inLen, int32(0))
		return 1, err
	case capScanAll:
		if wide {
			r.zeroBitmap()
			_, err := wcall(fn, r.store, r.inBase, r.inLen, int32(0), r.bitmapPt)
			return 1, err
		}
		_, err := wcall(fn, r.store, r.inBase, r.inLen, int32(0))
		return 1, err
	case capFind:
		return r.exhaustFind(fn, true)
	case capFindBatch:
		return r.exhaustFindBatch(fn, true)
	case capFindOverlapping:
		return r.exhaustFind(fn, false)
	case capFindBatchOverlapping:
		return r.exhaustFindBatch(fn, false)
	}
	return 0, fmt.Errorf("unknown capability %q", c)
}

// isFuelExhausted reports whether err is the fuel budget running out rather
// than a defect in the harness.
//
// wasmtime surfaces budget exhaustion as a TRAP, and everything the harness
// can get wrong itself — a wrong argument count, a missing export, an
// out-of-bounds region — as an ordinary Go error. So the distinction is
// exactly the one that matters, and it is worth making: without it a harness
// that had fallen behind an export's signature reported as an engine too slow
// to finish.
func isFuelExhausted(err error) bool {
	var trap *wasmtime.Trap
	return errors.As(err, &trap)
}

// exhaustFind drives `find` to exhaustion the way a generated iterator does.
func (r *rxInstance) exhaustFind(fn *wasmtime.Func, gated bool) (int, error) {
	// Zeroed for BOTH flavours: the overlapping body
	// takes the array too, not for match gates but as the per-drive home of
	// its preflight verdict, and zeroing it is what declares a fresh drive.
	// Doing it once here rather than per call is the point of the change —
	// the per-call form is what the attempt log measured and rejected.
	buf := r.mem.UnsafeData(r.store)
	for i := int32(0); i < r.npat*4; i++ {
		buf[r.gatePtr+i] = 0
	}
	runtime.KeepAlive(r.store)
	from := int32(0)
	calls := 0
	for {
		var res interface{}
		var err error
		calls++
		res, err = wcall(fn, r.store, r.inBase, r.inLen, from, r.gatePtr, r.outPtr, r.npat)
		if err != nil {
			return calls, err
		}
		if res.(int32) <= 0 {
			return calls, nil
		}
		buf := r.mem.UnsafeData(r.store)
		start := int32(binary.LittleEndian.Uint32(buf[int(r.outPtr)+4:]))
		runtime.KeepAlive(r.store)
		from = start + 1
	}
}

// exhaustFindBatch drives `find_batch` to exhaustion the way a generated batch
// iterator does: start from cursor 0, hand the previous return value back
// unchanged, stop when its top 32 bits are all ones.
//
// The count field is not decoded here. The driver only needs to know when to
// stop, and reading the tuples would add harness work to a timed loop that is
// meant to measure the engine.
func (r *rxInstance) exhaustFindBatch(fn *wasmtime.Func, gated bool) (int, error) {
	buf := r.mem.UnsafeData(r.store)
	for i := int32(0); i < r.npat*4; i++ {
		buf[r.gatePtr+i] = 0
	}
	// The answer cache goes to the OVERLAPPING drive only, which is what a
	// generated JS/TS iterator does: it is the one policy whose drive the
	// backward sweep can answer. A gated drive is handed 0, 0 and walks, so
	// this row keeps measuring what it measured before the cache existed.
	cachePtr, cacheLen := int32(0), int32(0)
	if !gated {
		cachePtr, cacheLen = r.cachePtr, r.cacheLen
		for i := int32(0); i < config.SetOverlapCacheHeaderBytes; i++ {
			buf[cachePtr+i] = 0
		}
	}
	runtime.KeepAlive(r.store)
	cursor := int64(0)
	calls := 0
	for {
		var res interface{}
		var err error
		calls++
		res, err = wcall(fn, r.store, r.inBase, r.inLen, cursor, r.gatePtr, r.batchPtr, int32(batchCap), cachePtr, cacheLen)
		if err != nil {
			return calls, err
		}
		packed := res.(int64)
		if uint32(packed>>32) == 0xFFFFFFFF {
			return calls, nil
		}
		// A cursor that does not advance is a hang, not a slow row, and this
		// loop has no other bound.
		if packed == cursor {
			return calls, fmt.Errorf("find_batch returned its own cursor %#016x unchanged after %d calls", uint64(cursor), calls)
		}
		cursor = packed
	}
}

// --------------------------------------------------------------------------
// Measurement.

type row struct {
	key   string
	value uint64
}

func rowKey(c setCase, cap capability) string {
	return c.name + "|" + c.inputLbl + "|" + string(cap)
}

func measureFuelRow(c setCase) []row {
	cfg := wasmtime.NewConfig()
	cfg.SetConsumeFuel(true)
	engine := newWatchedEngine(cfg)
	var out []row
	for _, cap := range allCaps {
		overlapping := cap == capFindOverlapping || cap == capFindBatchOverlapping
		wasm, err := compileCase(c, overlapping)
		if err != nil {
			// A HARD error, matching the call-error policy below: silently
			// dropping the row removed it from the board AND from the
			// baseline gate, so a regression that made a set fail to compile
			// printed "All fuel baselines match exactly."
			fmt.Fprintf(os.Stderr, "HARNESS ERROR %s: compile: %v\n", rowKey(c, cap), err)
			os.Exit(1)
		}
		r, err := newRxInstance(engine, wasm, c, true)
		if err != nil {
			fmt.Fprintf(os.Stderr, "HARNESS ERROR %s: instantiate: %v\n", rowKey(c, cap), err)
			os.Exit(1)
		}
		wide := r.npat > 64
		// Warm-up call, uncounted: the first call pays lazy compilation — and
		// it runs on a RE-ARMED budget, so a case whose warm-up is itself
		// expensive cannot leave the measured call starting from a partly
		// spent one.
		if err := r.store.SetFuel(fuelBudget); err != nil {
			fmt.Fprintf(os.Stderr, "HARNESS ERROR %s: SetFuel: %v\n", rowKey(c, cap), err)
			os.Exit(1)
		}
		_, _ = r.call(cap, wide)
		if err := r.store.SetFuel(fuelBudget); err != nil {
			fmt.Fprintf(os.Stderr, "HARNESS ERROR %s: SetFuel: %v\n", rowKey(c, cap), err)
			os.Exit(1)
		}
		before, _ := r.store.GetFuel()
		if _, err := r.call(cap, wide); err != nil {
			// Record budget exhaustion as a SENTINEL rather than dropping the
			// row: a bare `continue` here is why greedy-3's
			// scan_all/find/find(overlapping) had no fuel number anywhere —
			// the map lookup then yielded 0, and the matrix printed "0 fuel"
			// for the three most expensive rows it has. printRows filters
			// sentinels back out so the baseline files keep their
			// exact-equality format.
			//
			// But ONLY budget exhaustion. This arm used to absorb every error
			// on the grounds that it was "almost always" the budget, and it
			// duly reported an ARITY MISMATCH — the harness calling an export
			// whose signature had grown — as eight rows of "exceeded the fuel
			// budget". A broken harness must not be readable as a slow
			// engine.
			if !isFuelExhausted(err) {
				fmt.Fprintf(os.Stderr, "HARNESS ERROR %s: %v\n", rowKey(c, cap), err)
				os.Exit(1)
			}
			out = append(out, row{rowKey(c, cap), fuelExhausted})
			continue
		}
		after, _ := r.store.GetFuel()
		out = append(out, row{rowKey(c, cap), before - after})
	}
	return out
}

func measureSizeRow(c setCase) []row {
	var out []row
	for _, overlapping := range []bool{false, true} {
		wasm, err := compileCase(c, overlapping)
		if err != nil {
			continue
		}
		label := "module(gated)"
		if overlapping {
			label = "module(overlapping)"
		}
		out = append(out, row{rowKey(c, capability(label)), uint64(len(wasm))})
	}
	return out
}

// timedCase returns the case to use for the TIMED measurement of cap, and
// whether the input was shortened.
//
// ourFuel is the measured fuel for this row, or fuelExhausted when the single
// measurement could not even complete. Rows are shortened on measured cost —
// see timedFuelCap for why capability name is the wrong key.
func timedCase(c setCase, cap capability, ourFuel uint64) (setCase, bool) {
	quadratic := ourFuel == fuelExhausted || ourFuel > timedFuelCap
	if !quadratic || len(c.input) <= overlappingTimedCap {
		return c, false
	}
	c.input = c.input[:overlappingTimedCap]
	return c, true
}

// measureTime returns the p50 of benchIters whole-input operations, together
// with the number of Go→wasmtime crossings one operation costs.
//
// The crossing count is not incidental: it is the correction term that makes
// this side comparable with the regex-automata side at all. Our sample
// brackets a host call; theirs is taken by the Rust
// harness INSIDE wasm, around the engine work alone. Subtracting
// crossings × callFloor from our p50 puts both on the same footing.
func measureTime(engine *wasmtime.Engine, c setCase, cap capability, ourFuel uint64) (time.Duration, int, time.Duration, error) {
	c, _ = timedCase(c, cap, ourFuel)
	wasm, err := compileCase(c, cap == capFindOverlapping || cap == capFindBatchOverlapping)
	if err != nil {
		return 0, 0, 0, err
	}
	r, err := newRxInstance(engine, wasm, c, false)
	if err != nil {
		return 0, 0, 0, err
	}
	floor := measureInstanceFloor(r)
	wide := r.npat > 64
	calls := 0
	for end := time.Now().Add(50 * time.Millisecond); time.Now().Before(end); {
		if calls, err = r.call(cap, wide); err != nil {
			return 0, 0, 0, err
		}
	}
	samples := make([]time.Duration, benchIters)
	for i := range samples {
		t0 := time.Now()
		n, err := r.call(cap, wide)
		if err != nil {
			return 0, 0, 0, err
		}
		samples[i] = time.Since(t0)
		calls = n
	}
	sort.Slice(samples, func(i, j int) bool { return samples[i] < samples[j] })
	return samples[len(samples)/2], calls, floor, nil
}

// --------------------------------------------------------------------------
// The harness-boundary correction.

// measureInstanceFloor times a call into THIS module that does essentially no
// work: `cap_match` on a zero-length input, which enters the anchored probe
// and returns within a couple of instructions.
//
// Measuring the boundary on the real module rather than on a synthetic empty
// one matters. A hand-built noop module measured 2.0-3.0 us here with no
// ordering by arity — i.e. dominated by noise — and it under-reported: the
// cheapest real row in the matrix (greedy-3 / 50K a's / scan, 48 fuel, so
// arithmetically no work at all) samples at 3.8 us. Module size, memory
// footprint and the number of exports all move the crossing cost, so the
// floor is taken per instance, against the very module being timed.
//
// The floor uses the SAME estimator as the rows it corrects — p50 over
// benchIters samples, after an equal warm-up. That symmetry is the point: a
// min-of-rounds floor is biased low, and subtracting a low-biased floor from
// an unbiased p50 leaves a residual that looks like engine work but is not.
// Calibration check: with matched estimators the anchored rows, which do
// 54-60 fuel of work, correct to approximately zero.
func measureInstanceFloor(r *rxInstance) time.Duration {
	fn := r.fnFor(capMatchAny)
	if fn == nil {
		return 0
	}
	for end := time.Now().Add(50 * time.Millisecond); time.Now().Before(end); {
		if _, err := wcall(fn, r.store, r.inBase, int32(0)); err != nil {
			return 0
		}
	}
	samples := make([]time.Duration, benchIters)
	for i := range samples {
		t0 := time.Now()
		if _, err := wcall(fn, r.store, r.inBase, int32(0)); err != nil {
			return 0
		}
		samples[i] = time.Since(t0)
	}
	sort.Slice(samples, func(i, j int) bool { return samples[i] < samples[j] })
	return samples[len(samples)/2]
}

// engineTime strips the harness boundary from a raw sample: one crossing per
// call the operation made. Clamped at zero — when the correction exceeds the
// sample the row was pure boundary, which is what call-bound means.
func engineTime(raw time.Duration, calls int, floor time.Duration) time.Duration {
	corrected := raw - time.Duration(calls)*floor
	if corrected < 0 {
		return 0
	}
	return corrected
}

// --------------------------------------------------------------------------
// regex-automata side.

type raHarness struct {
	store    *wasmtime.Store
	inst     *wasmtime.Instance
	mem      *wasmtime.Memory
	inputPtr int32
	timings  int32
	outPtr   int32
}

func newRaHarness(engine *wasmtime.Engine, wasm []byte, c setCase) (*raHarness, error) {
	return newRaHarnessFuel(engine, wasm, c, false)
}

// newRaHarnessFuel is newRaHarness with a switch for a fuel-metering engine.
//
// A metered store traps on the FIRST call if it has no fuel, and this
// constructor makes several (the pointer getters, ra_set_init) before anything
// is measured — so the budget has to be in place before setup, not just before
// the measured call. Every measurement re-arms it anyway.
func newRaHarnessFuel(engine *wasmtime.Engine, wasm []byte, c setCase, metered bool) (*raHarness, error) {
	mod, err := wasmtime.NewModule(engine, wasm)
	if err != nil {
		return nil, err
	}
	store := wasmtime.NewStore(engine)
	if metered {
		if err := store.SetFuel(fuelBudget); err != nil {
			return nil, err
		}
	}
	store.SetWasi(wasmtime.NewWasiConfig())
	linker := wasmtime.NewLinker(engine)
	if err := linker.DefineWasi(); err != nil {
		return nil, err
	}
	inst, err := linker.Instantiate(store, mod)
	if err != nil {
		return nil, err
	}
	mem := inst.GetExport(store, "memory").Memory()

	get := func(name string) (int32, error) {
		fn := inst.GetFunc(store, name)
		if fn == nil {
			return 0, fmt.Errorf("harness missing %s", name)
		}
		v, err := wcall(fn, store)
		if err != nil {
			return 0, err
		}
		return v.(int32), nil
	}
	patPtr, err := get("get_set_patterns_ptr")
	if err != nil {
		return nil, err
	}
	inputPtr, err := get("get_input_ptr")
	if err != nil {
		return nil, err
	}
	timings, err := get("get_timings_ptr")
	if err != nil {
		return nil, err
	}
	outPtr, err := get("ra_out_ptr")
	if err != nil {
		return nil, err
	}

	joined := strings.Join(c.patterns, "\n")
	buf := mem.UnsafeData(store)
	copy(buf[patPtr:], joined)
	copy(buf[inputPtr:], c.input)
	runtime.KeepAlive(store)

	initFn := inst.GetFunc(store, "ra_set_init")
	if initFn == nil {
		return nil, fmt.Errorf("harness missing ra_set_init")
	}
	res, err := wcall(initFn, store, int32(len(joined)))
	if err != nil {
		return nil, err
	}
	if res.(int32) == 0 {
		return nil, fmt.Errorf("regex-automata rejected the pattern set")
	}
	return &raHarness{store: store, inst: inst, mem: mem, inputPtr: inputPtr, timings: timings, outPtr: outPtr}, nil
}

// fuelOf meters ONE whole-input operation of the regex-automata harness, the
// same way measureFuelRow meters one of ours: a warm-up call first (the first
// call through a function pays lazy compilation and one-time lazy-DFA cache
// fills, neither of which is per-operation work), then re-arm the budget and
// bracket a single call.
//
// Returns fuelExhausted when the budget runs out, for the same reason our side
// does: dropping the row would make a too-expensive engine read as a missing
// number, and 0 fuel would read as a free one.
//
// truncated reports that `ra_find_gated` filled RA_OUT_BUF and stopped early,
// which would make their fuel describe LESS work than ours. It has never
// fired on this matrix — the buffer holds 65,536 tuples and the densest row
// produces a few thousand — but an unnoticed truncation would read as a large
// unearned win for them, so it is checked rather than assumed.
func (h *raHarness) fuelOf(cap capability, inputLen int32) (fuel uint64, truncated bool, err error) {
	name := raFuelPairing(cap)
	if name == "" {
		return 0, false, fmt.Errorf("no fuel pairing for %s", cap)
	}
	fn := h.inst.GetFunc(h.store, name)
	if fn == nil {
		return 0, false, fmt.Errorf("harness missing %s", name)
	}
	args := raFuelArgs(cap, inputLen)
	// The WARM-UP gets its own budget. It used to run on whatever the previous
	// capability had left, so an expensive earlier row could make this one
	// report fuelExhausted for a call that fits the budget comfortably.
	if err := h.store.SetFuel(fuelBudget); err != nil {
		return 0, false, err
	}
	if _, err := wcall(fn, h.store, args...); err != nil {
		if isFuelExhausted(err) {
			return fuelExhausted, false, nil
		}
		return 0, false, err
	}
	if err := h.store.SetFuel(fuelBudget); err != nil {
		return 0, false, err
	}
	before, _ := h.store.GetFuel()
	res, err := wcall(fn, h.store, args...)
	if err != nil {
		if isFuelExhausted(err) {
			return fuelExhausted, false, nil
		}
		return 0, false, err
	}
	after, _ := h.store.GetFuel()
	if cap == capFind || cap == capFindBatch {
		if n, ok := res.(int32); ok && int(n) >= raOutTuples {
			truncated = true
		}
	}
	return before - after, truncated, nil
}

// bench runs the named regex-automata bench export and returns its p50.
// benchLazyFind drives ra_find_next ONE MATCH PER CALL from Go and times the
// whole drive here, in the host — the mirror image of measureTime on our side.
//
// Every other pairing in this file times the Rust
// side INSIDE wasm, which is right for a bulk entry point and wrong for a lazy
// one: our bare `find` returns to the host at every matching position, so the
// only fair comparison is one where their driver crosses the boundary just as
// often. Here it does, and neither side's number is crossing-corrected —
// BOTH carry N crossings, which is the point, so subtracting them would
// remove the very term being compared.
//
// The resume rule is the same one our engine uses, so the two drives visit the same
// positions: continue at start+1, and stop when the scan reports nothing.
// Returns the p50 of the whole drive plus the call count that produced it.
func (h *raHarness) benchLazyFind(inputLen int) (time.Duration, int, error) {
	fn := h.inst.GetFunc(h.store, "ra_find_next")
	if fn == nil {
		return 0, 0, fmt.Errorf("harness missing ra_find_next")
	}
	drive := func() (int, error) {
		calls, from := 0, int32(0)
		for {
			v, err := wcall(fn, h.store, int32(inputLen), from)
			calls++
			if err != nil {
				return calls, err
			}
			packed := v.(int64)
			if packed < 0 {
				return calls, nil
			}
			start := int32(packed >> 32)
			from = start + 1
			if int(from) > inputLen {
				return calls, nil
			}
		}
	}
	for end := time.Now().Add(50 * time.Millisecond); time.Now().Before(end); {
		if _, err := drive(); err != nil {
			return 0, 0, err
		}
	}
	// Far fewer iterations than bench()'s 2000: one sample is a whole drive,
	// which on a dense corpus is thousands of host crossings.
	const iters = 15
	samples := make([]time.Duration, iters)
	calls := 0
	for i := range samples {
		t0 := time.Now()
		n, err := drive()
		if err != nil {
			return 0, 0, err
		}
		samples[i] = time.Since(t0)
		calls = n
	}
	sort.Slice(samples, func(i, j int) bool { return samples[i] < samples[j] })
	return samples[len(samples)/2], calls, nil
}

func (h *raHarness) bench(name string, inputLen int) (time.Duration, error) {
	fn := h.inst.GetFunc(h.store, name)
	if fn == nil {
		return 0, fmt.Errorf("harness missing %s", name)
	}
	// The harness times each iteration internally and writes ns to TIMINGS_BUF.
	const iters = 2000
	if _, err := wcall(fn, h.store, int32(inputLen), int32(200)); err != nil {
		return 0, err // warm-up
	}
	if _, err := wcall(fn, h.store, int32(inputLen), int32(iters)); err != nil {
		return 0, err
	}
	buf := h.mem.UnsafeData(h.store)
	vals := make([]uint32, iters)
	for i := range vals {
		vals[i] = binary.LittleEndian.Uint32(buf[int(h.timings)+i*4:])
	}
	runtime.KeepAlive(h.store)
	sort.Slice(vals, func(i, j int) bool { return vals[i] < vals[j] })
	return time.Duration(vals[len(vals)/2]), nil
}

// --------------------------------------------------------------------------
// Output.

func harnessPath() string {
	dir, err := os.Getwd()
	if err != nil {
		// Swallowed, this produced a path relative to nothing and a
		// "cannot read the harness" message blaming the build.
		fmt.Fprintf(os.Stderr, "cannot determine the working directory: %v\n", err)
		os.Exit(1)
	}
	return filepath.Join(dir, "..", "perftest", "regex_bench", "target", "wasm32-wasip1", "release", "regex_bench.wasm")
}

func runFullMatrix(cases []setCase) {
	raBytes, err := os.ReadFile(harnessPath())
	if err != nil {
		fmt.Fprintf(os.Stderr, "cannot read the regex-automata harness (run 'make harnesses' in ../perftest): %v\n", err)
		os.Exit(1)
	}
	engine := newWatchedEngine(nil)
	fuelCfg := wasmtime.NewConfig()
	fuelCfg.SetConsumeFuel(true)
	fuelEngine := newWatchedEngine(fuelCfg)

	fmt.Println("setperf — regexped set capabilities vs regex-automata")
	fmt.Println(strings.Repeat("─", 96))
	fmt.Println("TWO ratios per row, and they answer different questions.")
	fmt.Println()
	fmt.Println("`fuel x` is theirs/ours in WASM instructions EXECUTED, both sides metered by")
	fmt.Println("wasmtime over one whole-input operation. It is deterministic — same number")
	fmt.Println("every run, on any machine — and it has no host-crossing term, because a")
	fmt.Println("Go->wasmtime call executes no wasm instructions. So it is the only column")
	fmt.Println("that answers the small rows the timed one has to withhold as call-bound.")
	fmt.Println("Its bias: our WASM is hand-emitted, theirs is rustc/LLVM output, so their")
	fmt.Println("count carries bounds checks, spills and panic paths ours never emits. That")
	fmt.Println("is real work their engine does, not an artefact — but it means `fuel x` is")
	fmt.Println("a measure of instructions, not of nanoseconds. Read a 1.1x as parity.")
	fmt.Println()
	fmt.Println("`time x` is theirs/ours in wall-clock, crossing-corrected. It is what a")
	fmt.Println("caller feels, and on this machine it is also instruction-placement noise —")
	fmt.Println("compare it over several runs or not at all.")
	fmt.Println()
	fmt.Println("When the two disagree, they are usually both right and measuring different")
	fmt.Println("things: fuel says who does less work, time says whose work the CPU likes.")
	fmt.Println()
	fmt.Println("BOTH SIDES ARE WASM: regex-automata is built for wasm32-wasip1 and runs in the")
	fmt.Println("same wasmtime engine. What differs is where the clock sits. Our sample")
	fmt.Println("brackets a Go→wasmtime call; the Rust harness times itself INSIDE wasm. So our")
	fmt.Println("raw p50 carries one crossing per call — and `find` makes one call per match.")
	fmt.Println("`our engine` subtracts calls × the measured crossing cost for that arity, and")
	fmt.Println("the ratio is computed from it, so both columns describe engine work alone.")
	fmt.Printf("Ratios are still withheld below %d fuel (\"call-bound\"): once the correction\n", callBoundFuel)
	fmt.Println("is the bulk of the sample, what remains is measurement noise, not a result.")
	fmt.Println()
	fmt.Println("`find` shows \"api-shape\" instead of a time ratio, and that is not a missing")
	fmt.Println("measurement. It compares OUR LAZY API against THEIR BULK ENUMERATION: we")
	fmt.Println("return to the host at every matching position while ra_bench_find_gated loops")
	fmt.Println("inside wasm and returns once, so the crossing correction is an estimate that")
	fmt.Println("grows until it swallows the sample. Read that row from `fuel x`, which has no")
	fmt.Println("crossing term at all, or from the find_batch row below it, where both sides")
	fmt.Println("make O(matches/buffer) crossings. The \"↳ lazy pairing\" line under it is the")
	fmt.Println("third view: ra_find_next driven one match per call, both sides paying N")
	fmt.Println("crossings, uncorrected — lazy API against lazy API.")
	fmt.Printf("find(overlapping) is timed on at most %d bytes: it is the every-start-position\n", overlappingTimedCap)
	fmt.Println("enumeration, quadratic on literal-less sets, and blocks the matrix otherwise.")
	fmt.Println()

	for _, c := range cases {
		wcallCase = c.name + "/" + c.inputLbl
		fmt.Printf("\n=== %s / %s (%d patterns, %d bytes) ===\n", c.name, c.inputLbl, len(c.patterns), len(c.input))
		gated, err := compileCase(c, false)
		if err != nil {
			fmt.Printf("  compile failed: %v\n", err)
			continue
		}
		over, _ := compileCase(c, true)
		fmt.Printf("  module: gated %d B, overlapping %d B, regex-automata harness %d B (whole engine)\n",
			len(gated), len(over), len(raBytes))

		ra, raErr := newRaHarness(engine, raBytes, c)
		// A SECOND harness on the fuel-metered engine. Separate because
		// metering is an engine-level setting and the timed harness must not
		// carry it: fuel accounting is per-instruction overhead, and a timed
		// row measured under it would report the meter, not the engine.
		raFuel, raFuelErr := newRaHarnessFuel(fuelEngine, raBytes, c, true)
		fuel := map[string]uint64{}
		for _, r := range measureFuelRow(c) {
			fuel[r.key] = r.value
		}

		fmt.Printf("  %-18s %12s %12s %7s %11s %7s %11s %11s %7s  %s\n",
			"capability", "our fuel", "theirs fuel", "fuel x", "our p50", "calls", "our engine", "theirs p50", "time x", "note")
		fmt.Println("  " + strings.Repeat("─", 118))
		for _, cap := range allCaps {
			ourFuel := fuel[rowKey(c, cap)]
			// The FUEL comparison, computed first because it is deterministic
			// and does not depend on any timing. It is also the only
			// cross-engine number on this row that does not need the host
			// crossing corrected away: fuel counts instructions executed
			// INSIDE wasm, and a Go->wasmtime call contributes none of them.
			// That is why a row can be "call-bound" for time and still carry a
			// real fuel ratio.
			theirFuel, fuelTrunc, tfErr := uint64(0), false, error(nil)
			if raFuelErr != nil {
				tfErr = raFuelErr
			} else if raFuelPairing(cap) == "" {
				tfErr = errNoPairing
			} else {
				theirFuel, fuelTrunc, tfErr = raFuel.fuelOf(cap, int32(len(c.input)))
			}
			tf, fx := fmtTheirFuel(theirFuel, tfErr)
			if tfErr == nil {
				fx = fmtFuelRatio(ourFuel, theirFuel)
			}

			ours, calls, floor, err := measureTime(engine, c, cap, ourFuel)
			if err != nil {
				fmt.Printf("  %-18s %12s %12s %7s %11s %7s %11s %11s %7s  %s\n",
					cap, "-", tf, fx, "error", "-", "-", "-", "-", "")
				continue
			}
			ourEng := engineTime(ours, calls, floor)
			f := fmtFuel(ourFuel)
			if fuelTrunc {
				// Their side stopped filling its output buffer, so its fuel
				// describes less work than ours. Withhold rather than divide.
				fx = "truncated"
			}
			// F4: say so when the timed input was shortened, because then this
			// row's fuel and time describe different input lengths.
			var note string
			if _, capped := timedCase(c, cap, ourFuel); capped {
				note = fmt.Sprintf("time on %dB input; fuel on %dB", overlappingTimedCap, len(c.input))
			}
			if ourFuel == fuelExhausted {
				f = "exhausted"
				note = fmt.Sprintf("one call exceeds the %s fuel budget; time on %dB input", fmtFuel(fuelBudget), overlappingTimedCap)
			}
			pairing := raPairing(cap)
			if pairing == "" || raErr != nil {
				reason := "no comparison"
				if raErr != nil {
					reason = "harness error"
				}
				fmt.Printf("  %-18s %12s %12s %7s %11s %7d %11s %11s %7s  %s\n",
					cap, f, tf, fx, fmtDur(ours), calls, fmtDur(ourEng), reason, "-", note)
				continue
			}
			theirs, err := ra.bench(pairing, len(c.input))
			if err != nil {
				fmt.Printf("  %-18s %12s %12s %7s %11s %7d %11s %11s %7s  %s\n",
					cap, f, tf, fx, fmtDur(ours), calls, fmtDur(ourEng), "error", "-", note)
				continue
			}
			// A ratio is printed only when both sides did comparable work.
			// F3: below callBoundFuel the sample is dominated by our harness's
			// per-call cost. F4: a shortened timed input means our time covers
			// a fraction of the bytes theirs does. Both print the raw times
			// and withhold only the ratio.
			_, capped := timedCase(c, cap, ourFuel)
			ratio := "-"
			switch {
			case capped:
				ratio = "input differs"
			case timedRatioIsAPIShape(cap):
				// This row compares OUR LAZY API
				// against THEIR BULK ENUMERATION and cannot be made fair by
				// correcting for the crossing: we return to the host once per
				// matching position (3,659 calls on a dense 100 KB corpus)
				// while ra_bench_find_gated loops every pattern's find_iter
				// INSIDE wasm and returns once. The correction is an estimate
				// that grows until it swallows the sample, which is what the
				// "boundary" label below was already admitting on the worst of
				// these rows.
				//
				// The number it produced was not an engine result and was read
				// as one: on the 2026-08-28 board these rows were five of the
				// eight reported losses, including a headline 0.10x, while the
				// SAME rows are 1.15x-18.70x in our favour on fuel.
				//
				// The verdicts for this row come from `fuel x` beside it, which
				// has no crossing term at all, and from the find_batch row
				// below it, where both sides make O(matches/buffer) crossings.
				ratio = "api-shape"
				if note == "" {
					note = fmt.Sprintf("lazy API vs bulk enumeration over %d call(s); read `fuel x`, or the find_batch row", calls)
				}
			case ourFuel > 0 && ourFuel < callBoundFuel:
				ratio = "call-bound"
				if note == "" {
					note = fmt.Sprintf("our work is %s fuel; ratio would measure harness call overhead", f)
				}
			case ourEng > 0 && theirs > 0:
				// Engine-vs-engine: both sides now exclude the host boundary.
				ratio = fmt.Sprintf("%.2fx", float64(theirs)/float64(ourEng))
			case ours > 0 && theirs > 0:
				// The correction consumed the whole sample — the row was
				// boundary, not engine. Say so rather than dividing by zero.
				ratio = "boundary"
				if note == "" {
					note = fmt.Sprintf("%d call(s) x %s crossing >= the %s sample",
						calls, fmtDur(floor), fmtDur(ours))
				}
			}
			fmt.Printf("  %-18s %12s %12s %7s %11s %7d %11s %11s %7s  %s\n",
				cap, f, tf, fx, fmtDur(ours), calls, fmtDur(ourEng), fmtDur(theirs), ratio, note)

			// The LAZY pairing, printed beside the bulk one because the two
			// answer different questions. Here both sides
			// resume per match and pay N host crossings, so neither number is
			// crossing-corrected and the ratio is over the RAW p50s — the
			// crossings are the term under comparison, not an artefact to
			// subtract. This is the only row on the board where our bare
			// `find` is compared against a like-shaped API.
			if timedRatioIsAPIShape(cap) && !capped && ourFuel != fuelExhausted {
				theirsLazy, theirCalls, lerr := ra.benchLazyFind(len(c.input))
				switch {
				case lerr != nil:
					fmt.Printf("  %-18s %12s %12s %7s %11s %7s %11s %11s %7s  %s\n",
						"  ↳ lazy pairing", "-", "-", "-", "-", "-", "-", "error", "-", lerr)
				case ours > 0 && theirsLazy > 0:
					fmt.Printf("  %-18s %12s %12s %7s %11s %7d %11s %11s %6.2fx  %s\n",
						"  ↳ lazy pairing", "-", "-", "-", fmtDur(ours), calls, "uncorrected",
						fmtDur(theirsLazy), float64(theirsLazy)/float64(ours),
						fmt.Sprintf("ra_find_next, %d their call(s): both sides resume per match", theirCalls))
				}
			}
		}
	}
}

// errNoPairing marks a capability regex-automata has no equivalent for — the
// overlapping find pair. Distinct from a harness failure, and printed
// differently, because "they cannot do this" and "we could not measure it" are
// not the same statement.
var errNoPairing = errors.New("no regex-automata pairing")

// fmtTheirFuel renders the harness's fuel cell and the placeholder for the
// ratio beside it.
func fmtTheirFuel(f uint64, err error) (cell, ratio string) {
	switch {
	case errors.Is(err, errNoPairing):
		return "-", "-"
	case err != nil:
		return "error", "-"
	case f == fuelExhausted:
		return "exhausted", "-"
	}
	return fmtFuel(f), "-"
}

// fmtFuelRatio is theirs/ours, so >1 means we execute fewer WASM instructions
// — the same orientation as the time ratio beside it.
//
// It is withheld when either side is missing or exhausted. It is NOT withheld
// for small work: unlike the timed ratio, a fuel ratio has no host-crossing
// term to swamp it, so a 60-fuel row divides just as honestly as a 2M-fuel one.
// That is the whole reason this column exists — it answers the 73 rows the
// timed column has to report as "call-bound".
func fmtFuelRatio(ours, theirs uint64) string {
	if ours == 0 || theirs == 0 || ours == fuelExhausted || theirs == fuelExhausted {
		return "-"
	}
	return fmt.Sprintf("%.2fx", float64(theirs)/float64(ours))
}

// runFuelCross prints the cross-engine FUEL table and nothing else.
//
// Separate from the full matrix because it is a different kind of measurement:
// deterministic, machine-independent, and fast (no 50 ms warm-up and no 2,000
// timed iterations per row). It is the mode to use when the question is "who
// does less work", and the one to quote in a plan, because two runs of it on
// two machines produce identical numbers.
//
// It deliberately does NOT feed a baseline file. `-fuel`'s output is the
// committed regression gate and its format is compared for exact equality;
// adding a second engine's numbers to that contract would make our gate fail
// whenever the Rust toolchain changed under it.
func runFuelCross(cases []setCase) {
	raBytes, err := os.ReadFile(harnessPath())
	if err != nil {
		fmt.Fprintf(os.Stderr, "cannot read the regex-automata harness (run 'make harnesses' in ../perftest): %v\n", err)
		os.Exit(1)
	}
	cfg := wasmtime.NewConfig()
	cfg.SetConsumeFuel(true)
	engine := newWatchedEngine(cfg)

	fmt.Println("setperf — cross-engine FUEL (WASM instructions executed, one whole-input operation)")
	fmt.Println(strings.Repeat("─", 96))
	fmt.Println("Both sides metered by wasmtime. Deterministic: same numbers on any machine.")
	fmt.Println("ratio is theirs/ours, so >1 means we execute fewer instructions.")
	fmt.Println("BIAS: their WASM is rustc/LLVM output and carries bounds checks, spills and")
	fmt.Println("panic paths our hand-emitted WASM does not. That is work their engine really")
	fmt.Println("does, but it means this measures INSTRUCTIONS, not nanoseconds — read ~1.1x")
	fmt.Println("as parity and use the full matrix's `time x` for what a caller feels.")
	fmt.Println()

	var wins, losses, drawn int
	for _, c := range cases {
		wcallCase = c.name + "/" + c.inputLbl
		fmt.Printf("\n=== %s / %s (%d patterns, %d bytes) ===\n", c.name, c.inputLbl, len(c.patterns), len(c.input))
		h, err := newRaHarnessFuel(engine, raBytes, c, true)
		if err != nil {
			fmt.Printf("  harness error: %v\n", err)
			continue
		}
		fuel := map[string]uint64{}
		for _, r := range measureFuelRow(c) {
			fuel[r.key] = r.value
		}
		fmt.Printf("  %-18s %14s %14s %9s  %s\n", "capability", "our fuel", "theirs fuel", "ratio", "note")
		fmt.Println("  " + strings.Repeat("─", 76))
		for _, cap := range allCaps {
			ourFuel := fuel[rowKey(c, cap)]
			if raFuelPairing(cap) == "" {
				fmt.Printf("  %-18s %14s %14s %9s  %s\n",
					cap, fmtFuel(ourFuel), "-", "-", "regex-automata has no equivalent")
				continue
			}
			theirFuel, trunc, err := h.fuelOf(cap, int32(len(c.input)))
			if err != nil {
				fmt.Printf("  %-18s %14s %14s %9s  %s\n", cap, fmtFuel(ourFuel), "error", "-", err)
				continue
			}
			note := ""
			ratio := fmtFuelRatio(ourFuel, theirFuel)
			if trunc {
				ratio, note = "truncated", "their output buffer filled; their fuel covers less work than ours"
			}
			if ourFuel == fuelExhausted || theirFuel == fuelExhausted {
				note = fmt.Sprintf("one side exceeded the %s budget", fmtFuel(fuelBudget))
			}
			// `find` COUNTS here, unlike in the timed matrix where item 22
			// the bare-find row withholds its ratio as "api-shape". The distinction is
			// the whole reason this column exists: a Go->wasmtime call
			// executes no wasm instructions, so the crossings that make the
			// timed row a comparison of API shapes leave this one untouched.
			if r := ratio; strings.HasSuffix(r, "x") {
				v := 0.0
				fmt.Sscanf(r, "%fx", &v)
				switch {
				case v >= 1.1:
					wins++
				case v <= 0.9:
					losses++
				default:
					drawn++
				}
			}
			fmt.Printf("  %-18s %14s %14s %9s  %s\n",
				cap, fmtFuel(ourFuel), fmtFuel(theirFuel), ratio, note)
		}
	}
	fmt.Printf("\n%d comparable rows: %d ours by >1.1x, %d theirs by >1.1x, %d within 0.9-1.1x.\n",
		wins+losses+drawn, wins, losses, drawn)
}

func printRows(cases []setCase, measure func(setCase) []row, unit string) {
	for _, c := range cases {
		wcallCase = c.name + "/" + c.inputLbl
		for _, r := range measure(c) {
			if r.value == fuelExhausted {
				// Not a number, so it cannot join an exact-equality baseline.
				// Announced on stderr so `make baseline` (which redirects
				// stdout only) still shows the gap rather than hiding it.
				fmt.Fprintf(os.Stderr, "note: %s exceeded the %d fuel budget — no baseline row\n", r.key, uint64(fuelBudget))
				continue
			}
			fmt.Printf("%s = %d %s\n", r.key, r.value, unit)
		}
	}
}

// runCompare checks every measured row against a baseline file. Both fuel and
// module size are deterministic, so the comparison is EXACT: a change is a
// change, and it must be attributed rather than absorbed into a tolerance.
func runCompare(path string, cases []setCase, measure func(setCase) []row, unit string) int {
	data, err := os.ReadFile(path)
	if err != nil {
		fmt.Fprintf(os.Stderr, "cannot read baseline %s: %v\n", path, err)
		return 1
	}
	base := map[string]uint64{}
	for _, line := range strings.Split(string(data), "\n") {
		i := strings.Index(line, " = ")
		if i < 0 {
			continue
		}
		key := line[:i]
		rest := strings.Fields(line[i+3:])
		if len(rest) == 0 {
			continue
		}
		v, err := strconv.ParseUint(rest[0], 10, 64)
		if err != nil {
			continue
		}
		base[key] = v
	}
	bad := 0
	// Rows that VANISH are the other half of the gate. runCompare iterates the
	// rows it measured, so a regression that made a set fail to compile
	// removed its rows entirely and the run printed "All fuel baselines match
	// exactly." over a board that had lost them.
	visited := map[string]bool{}
	for _, c := range cases {
		wcallCase = c.name + "/" + c.inputLbl
		for _, r := range measure(c) {
			visited[r.key] = true
			want, ok := base[r.key]
			if !ok {
				if r.value == fuelExhausted {
					// printRows deliberately emits no line for a row over the
					// budget, so its absence is the expected state and not a
					// gap in coverage.
					fmt.Fprintf(os.Stderr, "  %s: exceeds the fuel budget, no baseline (expected)\n", r.key)
					continue
				}
				// Any other missing row IS a failure. This gate exists to
				// prove every measured row is unchanged; a row with nothing to
				// compare against was not checked, and letting it pass meant
				// an empty or stale baseline file could report success while
				// checking almost nothing.
				fmt.Fprintf(os.Stderr, "UNCHECKED %s: no baseline row (current=%d %s); re-run `make baseline` if the row is new\n",
					r.key, r.value, unit)
				bad++
				continue
			}
			if r.value == fuelExhausted {
				// Was measurable when the baseline was taken and is not now:
				// a real regression, but printing the sentinel as a number
				// would just look like corruption.
				fmt.Fprintf(os.Stderr, "REGRESSION %s: baseline=%d current=exceeds the %d %s budget\n", r.key, want, uint64(fuelBudget), unit)
				bad++
				continue
			}
			if want != r.value {
				fmt.Fprintf(os.Stderr, "REGRESSION %s: baseline=%d current=%d %s\n", r.key, want, r.value, unit)
				bad++
			}
		}
	}
	var missing []string
	for key := range base {
		if !visited[key] {
			missing = append(missing, key)
		}
	}
	sort.Strings(missing)
	for _, key := range missing {
		fmt.Fprintf(os.Stderr, "MISSING %s: the baseline has this row and this run produced none (baseline=%d %s)\n",
			key, base[key], unit)
		bad++
	}
	if bad > 0 {
		return 1
	}
	fmt.Printf("All %s baselines match exactly.\n", unit)
	return 0
}

// --------------------------------------------------------------------------
// Cross-engine correctness (the secondary mode).
//
// On the pairings marked honest, running both engines over the same inputs
// yields a THIRD independent implementation to check against — strengthening
// the union-oracle story for multi-pattern interleaving, which Go's FindAllIndex
// union covers by construction rather than by an independent engine. It is a
// separate mode from the perf path so a semantic mismatch can never quietly
// corrupt the numbers.

func runVerify(cases []setCase) int {
	raBytes, err := os.ReadFile(harnessPath())
	if err != nil {
		fmt.Fprintf(os.Stderr, "cannot read the regex-automata harness (run 'make harnesses' in ../perftest): %v\n", err)
		return 1
	}
	engine := newWatchedEngine(nil)
	bad := 0
	for _, c := range cases {
		wcallCase = c.name + "/" + c.inputLbl
		ra, err := newRaHarness(engine, raBytes, c)
		if err != nil {
			fmt.Printf("SKIP %s/%s: %v\n", c.name, c.inputLbl, err)
			continue
		}
		wasm, err := compileCase(c, false)
		if err != nil {
			fmt.Fprintf(os.Stderr, "HARNESS ERROR %s/%s: compile: %v\n", c.name, c.inputLbl, err)
			os.Exit(1)
		}
		r, err := newRxInstance(engine, wasm, c, false)
		if err != nil {
			fmt.Fprintf(os.Stderr, "HARNESS ERROR %s/%s: instantiate: %v\n", c.name, c.inputLbl, err)
			os.Exit(1)
		}
		wide := r.npat > 64

		// The anchored trio. regex-automata's Anchored::Yes over the whole
		// haystack is exactly our `match` contract, and Anchored::Pattern(k)
		// per pattern is exactly `match_all`'s, so both are honest pairings —
		// they were simply never wired up here, which left four of the seven
		// capabilities resting on `make sets` alone.
		//
		// Driven at several PREFIX LENGTHS rather than only at the full input.
		// Both sides take the haystack length as a parameter, so this costs no
		// restaging — and it is what makes the check bite. The corpora are
		// 100 KB scan haystacks, so "does a pattern match the whole thing" is
		// no on 22 of the 23 rows; comparing only that would be a check that
		// agrees because both sides say no, which is the failure mode this
		// whole block exists to fix. Short prefixes reach the anchored
		// automaton's real answers, and length 0 covers the empty input.
		anchoredMatches := 0
		for _, n := range anchoredLens(len(c.input)) {
			// `match` is retired (decision (2)); regex-automata's boolean is
			// still the oracle, now compared against match_any's sign.
			theirMatch := raCallI32(ra, "ra_match", int32(n))
			if theirMatch != 0 {
				anchoredMatches++
			}

			// match_all: exact set equality, and the oracle for match_any.
			theirMatchIDs := raAllIDs(ra, "ra_match_all", int32(n))
			ourMatchIDs := rxAllIDs(r, wide, "cap_match_all", int32(n))
			if !sameIDs(theirMatchIDs, ourMatchIDs) {
				fmt.Printf("MISMATCH %s/%s match_all@%d: ours=%v theirs=%v\n", c.name, c.inputLbl, n, ourMatchIDs, theirMatchIDs)
				bad++
			}

			// match_any: which id you get is unspecified when several patterns
			// match the whole input, so presence is the hard contract — but
			// unlike scan_any the id DOES have an oracle here, since
			// match_all's set is every legal answer.
			ourMatchAny := rxCallI32(r, "cap_match_any", r.inBase, int32(n))
			if (ourMatchAny >= 0) != (theirMatch != 0) {
				fmt.Printf("MISMATCH %s/%s match_any@%d presence: ours=%d theirs=%d\n", c.name, c.inputLbl, n, ourMatchAny, theirMatch)
				bad++
			} else if ourMatchAny >= 0 && !containsID(theirMatchIDs, int(ourMatchAny)) {
				fmt.Printf("MISMATCH %s/%s match_any@%d id: ours=%d, not in theirs=%v\n", c.name, c.inputLbl, n, ourMatchAny, theirMatchIDs)
				bad++
			}
		}

		// scan_any: PRESENCE only. removed the
		// start it used to report, and the id is unspecified when several
		// patterns match, so agreement on "did anything match" is the whole
		// contract this tool can check. regex-automata still returns a span,
		// so only the sign of its answer is comparable.
		theirAny := raCallI64(ra, "ra_scan_any", int32(len(c.input)), 0)
		ourAny := int64(rxCallI32(r, "cap_scan_any", r.inBase, r.inLen, 0))
		if (theirAny < 0) != (ourAny < 0) {
			fmt.Printf("MISMATCH %s/%s scan_any presence: ours=%d theirs=%d\n", c.name, c.inputLbl, ourAny, theirAny)
			bad++
		}

		// scan_all: exact set equality. Driven at several `from` values, not
		// only 0 — `from` is the one parameter the scan pair takes, and
		// checking it at 0 alone leaves the entry-state rule (which start
		// state a nonzero `from` enters) unchecked.
		for _, from := range scanFromValues(len(c.input)) {
			theirIDs := raAllIDs(ra, "ra_scan_all", int32(len(c.input)), int32(from))
			ourIDs := rxAllIDs(r, wide, "cap_scan_all", r.inLen, int32(from))
			if !sameIDs(theirIDs, ourIDs) {
				fmt.Printf("MISMATCH %s/%s scan_all@from=%d: ours=%v theirs=%v\n", c.name, c.inputLbl, from, ourIDs, theirIDs)
				bad++
			}
			// The id scan_any reports is unspecified, but it must NAME A
			// PATTERN THAT MATCHES — and scan_all's set at the same `from` is
			// exactly the set of legal answers. Presence alone let an emitter
			// return an id belonging to no matching pattern.
			ourScanAny := rxCallI32(r, "cap_scan_any", r.inBase, r.inLen, int32(from))
			switch {
			case ourScanAny < 0 && len(ourIDs) != 0:
				fmt.Printf("MISMATCH %s/%s scan_any@from=%d: reported no match, but scan_all found %v\n",
					c.name, c.inputLbl, from, ourIDs)
				bad++
			case ourScanAny >= 0 && !containsID(ourIDs, int(ourScanAny)):
				fmt.Printf("MISMATCH %s/%s scan_any@from=%d: reported id %d, which is not in scan_all's %v\n",
					c.name, c.inputLbl, from, ourScanAny, ourIDs)
				bad++
			}
		}

		// find (gated, the default body): ra_find_gated is the per-pattern
		// merged find_iter — the same construction the gated-find oracle
		// uses, and the one raPairing already trusts for the fuel rows. This
		// is the only capability here whose EXTENTS are checked, not just its
		// ids, which is why leaving it out mattered.
		ourFind := rxCollectFind(r)
		if theirFind, complete := raFindGated(ra, int32(len(c.input))); !complete {
			// The harness buffer is fixed, and ra_find_gated truncates rather
			// than growing it. A truncated list is not a smaller answer, so
			// comparing it would manufacture a mismatch.
			fmt.Printf("SKIP %s/%s find: regex-automata output buffer full at %d tuples\n",
				c.name, c.inputLbl, len(theirFind))
		} else if !sameMatches(theirFind, ourFind) {
			fmt.Printf("MISMATCH %s/%s find: ours=%d matches, theirs=%d\n",
				c.name, c.inputLbl, len(ourFind), len(theirFind))
			bad++
		}

		// find vs find_batch: the two are independent bodies over shared
		// suffix functions and must report the identical multiset. The
		// regex-automata pairing above bounds `find` itself; this one is
		// internal because there is no pairing for the BATCHED shape, and it
		// is what exercises the split-position resume, since batchCap is
		// deliberately not "big enough for one call".
		ourBatch := rxCollectFindBatch(r)
		if !sameMatches(ourFind, ourBatch) {
			fmt.Printf("MISMATCH %s/%s find vs find_batch: find=%d matches, batch=%d\n",
				c.name, c.inputLbl, len(ourFind), len(ourBatch))
			bad++
		}

		// The OVERLAPPING module, which nothing else in --verify builds. It
		// is the only one whose find_batch reads the answer cache, so the
		// backward sweep had no correctness check at all — the engine-
		// independent find-vs-find_batch cross-check is applied to it here.
		if n := verifyOverlapping(engine, c); n > 0 {
			bad += n
		}

		// The anchored hit count is printed, not just tallied: a row where no
		// prefix matches proves only that both engines said no, and that is
		// worth seeing rather than hiding behind "ok".
		fmt.Printf("ok   %s/%s (anchored: %d/%d prefixes match, find: %d matches)\n",
			c.name, c.inputLbl, anchoredMatches, len(anchoredLens(len(c.input))), len(ourFind))
	}
	if bad > 0 {
		fmt.Printf("\n%d mismatch(es)\n", bad)
		return 1
	}
	fmt.Println("\nregex-automata agrees on every honest pairing.")
	return 0
}

// verifyOverlapping compiles the OVERLAPPING module for one case and holds its
// `find` against its own `find_batch`.
//
// regex-automata has no every-start-position enumeration to compare against,
// so this is an internal cross-check rather than a cross-engine one — but the
// two bodies are independent implementations of the same answer, and the batch
// one is the only consumer of the backward sweep. Without it nothing in
// --verify ever built an overlapping module.
func verifyOverlapping(engine *wasmtime.Engine, c setCase) int {
	wasm, err := compileCase(c, true)
	if err != nil {
		fmt.Fprintf(os.Stderr, "HARNESS ERROR: compiling the overlapping module for %s/%s: %v\n", c.name, c.inputLbl, err)
		os.Exit(1)
	}
	r, err := newRxInstance(engine, wasm, c, false)
	if err != nil {
		fmt.Fprintf(os.Stderr, "HARNESS ERROR: instantiating the overlapping module for %s/%s: %v\n", c.name, c.inputLbl, err)
		os.Exit(1)
	}
	ourFind := rxCollectFind(r)
	ourBatch := rxCollectFindBatch(r)
	if !sameMatches(ourFind, ourBatch) {
		fmt.Printf("MISMATCH %s/%s overlapping find vs find_batch: find=%d matches, batch=%d\n",
			c.name, c.inputLbl, len(ourFind), len(ourBatch))
		return 1
	}
	return 0
}

// scanFromValues picks the `from` positions the scan pair is verified at: the
// ends, the middle, and a couple of small offsets that land inside a SIMD
// block rather than on one.
func scanFromValues(n int) []int {
	out := []int{0}
	for _, v := range []int{1, 17, n / 2, n - 1, n} {
		if v > 0 && v <= n {
			out = append(out, v)
		}
	}
	return out
}

// setTuple is one (pattern id, start, end) triple read back from a find or
// find_batch buffer.
type setTuple struct{ id, start, end int32 }

// rxCollectFind drives the gated `find` to exhaustion and returns every tuple.
func rxCollectFind(r *rxInstance) []setTuple {
	fn := r.inst.GetFunc(r.store, "cap_find")
	if fn == nil {
		// Not `return nil`: two nils compare equal, so a missing export used
		// to VERIFY CLEAN.
		fmt.Fprintln(os.Stderr, "HARNESS ERROR: our module has no export \"cap_find\"")
		os.Exit(1)
	}
	buf := r.mem.UnsafeData(r.store)
	for i := int32(0); i < r.npat*4; i++ {
		buf[r.gatePtr+i] = 0
	}
	runtime.KeepAlive(r.store)
	var out []setTuple
	from := int32(0)
	for {
		res, err := wcall(fn, r.store, r.inBase, r.inLen, from, r.gatePtr, r.outPtr, r.npat)
		if err != nil {
			return out
		}
		n := res.(int32)
		if n <= 0 {
			return out
		}
		buf := r.mem.UnsafeData(r.store)
		for i := int32(0); i < n && i < r.npat; i++ {
			base := int(r.outPtr) + int(i)*12
			out = append(out, setTuple{
				int32(binary.LittleEndian.Uint32(buf[base:])),
				int32(binary.LittleEndian.Uint32(buf[base+4:])),
				int32(binary.LittleEndian.Uint32(buf[base+8:])),
			})
		}
		start := int32(binary.LittleEndian.Uint32(buf[int(r.outPtr)+4:]))
		runtime.KeepAlive(r.store)
		from = start + 1
	}
}

// rxCollectFindBatch drives `find_batch` to exhaustion and returns every tuple.
func rxCollectFindBatch(r *rxInstance) []setTuple {
	fn := r.inst.GetFunc(r.store, "cap_find_batch")
	if fn == nil {
		fmt.Fprintln(os.Stderr, "HARNESS ERROR: our module has no export \"cap_find_batch\"")
		os.Exit(1)
	}
	buf := r.mem.UnsafeData(r.store)
	for i := int32(0); i < r.npat*4; i++ {
		buf[r.gatePtr+i] = 0
	}
	// Offered unconditionally here, unlike the fuel drive.
	//
	// NOTE what this does and does not cover. Offering the cache to a GATED
	// module puts nothing under check: the backward sweep is read only by the
	// overlapping body, and the gated one ignores the pointer entirely
	// (compile/set_batch.go). The sweep is exercised by the overlapping
	// module verifyOverlapping builds below, which is what this comment used
	// to claim for itself.
	cachePtr, cacheLen := r.cachePtr, r.cacheLen
	for i := int32(0); i < config.SetOverlapCacheHeaderBytes; i++ {
		buf[cachePtr+i] = 0
	}
	runtime.KeepAlive(r.store)
	countMask := int64(1)<<uint(config.SetCursorCountBits(int(r.npat))) - 1
	var out []setTuple
	cursor := int64(0)
	for {
		res, err := wcall(fn, r.store, r.inBase, r.inLen, cursor, r.gatePtr, r.batchPtr, int32(batchCap), cachePtr, cacheLen)
		if err != nil {
			return out
		}
		packed := res.(int64)
		n := int32(packed & countMask)
		buf := r.mem.UnsafeData(r.store)
		for i := int32(0); i < n; i++ {
			base := int(r.batchPtr) + int(i)*12
			out = append(out, setTuple{
				int32(binary.LittleEndian.Uint32(buf[base:])),
				int32(binary.LittleEndian.Uint32(buf[base+4:])),
				int32(binary.LittleEndian.Uint32(buf[base+8:])),
			})
		}
		runtime.KeepAlive(r.store)
		if uint32(packed>>32) == 0xFFFFFFFF || n == 0 {
			return out
		}
		cursor = packed
	}
}

// sameMatches compares two tuple lists as multisets. Within-call tuple order
// is unspecified, so order must not be part of the test.
func sameMatches(a, b []setTuple) bool {
	if len(a) != len(b) {
		return false
	}
	key := func(v []setTuple) []setTuple {
		c := append([]setTuple(nil), v...)
		sort.Slice(c, func(i, j int) bool {
			if c[i].id != c[j].id {
				return c[i].id < c[j].id
			}
			if c[i].start != c[j].start {
				return c[i].start < c[j].start
			}
			return c[i].end < c[j].end
		})
		return c
	}
	x, y := key(a), key(b)
	for i := range x {
		if x[i] != y[i] {
			return false
		}
	}
	return true
}

// raCallI32/raCallI64 abort for the same reason rxCallI32 does: -1 is a legal
// answer, so folding a broken call into it makes an unusable comparison look
// like agreement.
func raCallI32(h *raHarness, name string, args ...interface{}) int32 {
	fn := h.inst.GetFunc(h.store, name)
	if fn == nil {
		fmt.Fprintf(os.Stderr, "HARNESS ERROR: the regex-automata harness has no export %q (run 'make harnesses' in ../perftest)\n", name)
		os.Exit(1)
	}
	v, err := wcall(fn, h.store, args...)
	if err != nil {
		fmt.Fprintf(os.Stderr, "HARNESS ERROR: calling regex-automata %q: %v\n", name, err)
		os.Exit(1)
	}
	return v.(int32)
}

func raCallI64(h *raHarness, name string, args ...interface{}) int64 {
	fn := h.inst.GetFunc(h.store, name)
	if fn == nil {
		fmt.Fprintf(os.Stderr, "HARNESS ERROR: the regex-automata harness has no export %q (run 'make harnesses' in ../perftest)\n", name)
		os.Exit(1)
	}
	v, err := wcall(fn, h.store, args...)
	if err != nil {
		fmt.Fprintf(os.Stderr, "HARNESS ERROR: calling regex-automata %q: %v\n", name, err)
		os.Exit(1)
	}
	return v.(int64)
}

// rxCallI32/rxCallI64 abort the run on a missing export or a failed call.
//
// They used to return -1, which is a LEGAL "no match" answer for every `_any`
// capability — so an ABI drift (an export renamed, a signature grown) verified
// clean on every no-match row instead of failing. A harness that cannot make
// the call has not checked anything.
func rxCallI32(r *rxInstance, name string, args ...interface{}) int32 {
	fn := r.inst.GetFunc(r.store, name)
	if fn == nil {
		fmt.Fprintf(os.Stderr, "HARNESS ERROR: our module has no export %q\n", name)
		os.Exit(1)
	}
	v, err := wcall(fn, r.store, args...)
	if err != nil {
		fmt.Fprintf(os.Stderr, "HARNESS ERROR: calling our %q: %v\n", name, err)
		os.Exit(1)
	}
	return v.(int32)
}

func rxCallI64(r *rxInstance, name string, args ...interface{}) int64 {
	fn := r.inst.GetFunc(r.store, name)
	if fn == nil {
		fmt.Fprintf(os.Stderr, "HARNESS ERROR: our module has no export %q\n", name)
		os.Exit(1)
	}
	v, err := wcall(fn, r.store, args...)
	if err != nil {
		fmt.Fprintf(os.Stderr, "HARNESS ERROR: calling our %q: %v\n", name, err)
		os.Exit(1)
	}
	return v.(int64)
}

// raAllIDs decodes an `_all` answer from the regex-automata harness, which
// writes ids to RA_OUT_BUF and returns the count. `export` is "ra_scan_all"
// (which takes a `from`, passed in extra) or "ra_match_all" (which does not).
func raAllIDs(h *raHarness, export string, args ...interface{}) []int {
	n := raCallI32(h, export, args...)
	if n < 0 {
		// `make([]int, 0, n)` with a negative capacity PANICS. Cannot happen
		// now that raCallI32 aborts on a failed call, but the panic was one
		// arity change away.
		fmt.Fprintf(os.Stderr, "HARNESS ERROR: regex-automata %q returned a negative count %d\n", export, n)
		os.Exit(1)
	}
	buf := h.mem.UnsafeData(h.store)
	out := make([]int, 0, n)
	for i := int32(0); i < n; i++ {
		out = append(out, int(int32(binary.LittleEndian.Uint32(buf[int(h.outPtr)+int(i)*4:]))))
	}
	runtime.KeepAlive(h.store)
	sort.Ints(out)
	return out
}

// rxAllIDs decodes one of our `_all` capabilities into an ascending id list.
// `export` is "cap_scan_all" (whose `from` goes in extra) or "cap_match_all".
// Both ABI forms are handled: an i64 bitmask return, or the >64-id out_ptr
// bitmap, which the caller must zero because the module only sets bits.
func rxAllIDs(r *rxInstance, wide bool, export string, inLen int32, extra ...interface{}) []int {
	args := append([]interface{}{r.inBase, inLen}, extra...)
	var out []int
	if wide {
		buf := r.mem.UnsafeData(r.store)
		for i := int32(0); i <= r.npat/8; i++ {
			buf[r.bitmapPt+i] = 0
		}
		runtime.KeepAlive(r.store)
		rxCallI32(r, export, append(args, r.bitmapPt)...)
		buf = r.mem.UnsafeData(r.store)
		for k := int32(0); k < r.npat; k++ {
			if buf[int(r.bitmapPt)+int(k)/8]&(1<<uint(k%8)) != 0 {
				out = append(out, int(k))
			}
		}
		runtime.KeepAlive(r.store)
		return out
	}
	mask := uint64(rxCallI64(r, export, args...))
	for k := int32(0); k < r.npat && k < 64; k++ {
		if mask&(1<<uint(k)) != 0 {
			out = append(out, int(k))
		}
	}
	return out
}

// raOutTuples is how many (id, start, end) triples RA_OUT_BUF holds. Keep it in
// step with automata.rs — ra_find_gated silently stops filling at this count
// rather than growing, so a returned count of exactly this is "at least this
// many", not "this many".
const raOutTuples = 65536

// raFindGated collects regex-automata's per-pattern merged enumeration, the
// pairing for our default gated `find`. complete is false when the harness
// buffer filled, in which case the tuples are a prefix and cannot be compared.
func raFindGated(h *raHarness, inputLen int32) (tuples []setTuple, complete bool) {
	n := raCallI32(h, "ra_find_gated", inputLen, int32(0))
	buf := h.mem.UnsafeData(h.store)
	out := make([]setTuple, 0, n)
	for i := int32(0); i < n; i++ {
		base := int(h.outPtr) + int(i)*12
		out = append(out, setTuple{
			int32(binary.LittleEndian.Uint32(buf[base:])),
			int32(binary.LittleEndian.Uint32(buf[base+4:])),
			int32(binary.LittleEndian.Uint32(buf[base+8:])),
		})
	}
	runtime.KeepAlive(h.store)
	return out, n < raOutTuples
}

// anchoredLens returns the prefix lengths the anchored trio is compared at.
//
// Small lengths first, because "the whole input matches" is what the anchored
// capabilities answer and a 100 KB scan corpus is not that: the short prefixes
// are where the anchored automaton actually returns yes, and 0 covers the empty
// input. The tail lengths keep the full-input case and one interior point.
func anchoredLens(n int) []int {
	var out []int
	for _, k := range []int{0, 1, 2, 3, 4, 5, 6, 7, 8, 12, 16, 32, 64, n / 2, n} {
		if k >= 0 && k <= n && (len(out) == 0 || k != out[len(out)-1]) {
			out = append(out, k)
		}
	}
	return out
}

// containsID reports whether an ascending id list holds id.
func containsID(ids []int, id int) bool {
	for _, v := range ids {
		if v == id {
			return true
		}
	}
	return false
}

func sameIDs(a, b []int) bool {
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

// --------------------------------------------------------------------------

func fmtDur(d time.Duration) string {
	switch {
	case d == 0:
		return "n/a"
	case d >= time.Millisecond:
		return fmt.Sprintf("%.2f ms", float64(d)/float64(time.Millisecond))
	case d >= time.Microsecond:
		return fmt.Sprintf("%.1f µs", float64(d)/float64(time.Microsecond))
	default:
		return fmt.Sprintf("%d ns", d.Nanoseconds())
	}
}

func fmtFuel(v uint64) string {
	if v == 0 {
		return "-"
	}
	s := strconv.FormatUint(v, 10)
	var parts []string
	for len(s) > 3 {
		parts = append([]string{s[len(s)-3:]}, parts...)
		s = s[:len(s)-3]
	}
	return strings.Join(append([]string{s}, parts...), ",")
}
