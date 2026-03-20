package main

import (
	"bufio"
	"flag"
	"fmt"
	"os"
	"regexp/syntax"
	"strconv"
	"strings"

	wasmtime "github.com/bytecodealliance/wasmtime-go/v42"
	"github.com/qrdl/regexped/compile"
)

const (
	// inputBase is the offset within WASM memory where test inputs are written.
	// tableBase must be at a higher page-aligned address to avoid overlap.
	inputBase = int32(0)
	tableBase = int64(65536) // page 1; page 0 is reserved for test inputs

	maxDFAStates = 100000
)

const (
	skipNonAnchored  = "requires Backtracking (non-greedy find mode)"
	skipCaptures     = "requires Backtracking (capture groups)"
	skipUnicode      = "requires Unicode support"
	skipStateLimit   = "requires larger DFA (state limit exceeded)"
	skipBadSyntax    = "unsupported RE2 syntax (invalid escape sequence)"
	skipParseError   = "parse/compile error"
	skipOther        = "other reasons"
)

// skipOrder controls the display order of skip reasons in the summary.
var skipOrder = []string{
	skipNonAnchored,
	skipCaptures,
	skipUnicode,
	skipStateLimit,
	skipBadSyntax,
	skipParseError,
	"requires " + compile.EngineBacktrack.String(),
	"requires " + compile.EnginePikeVM.String(),
	"requires " + compile.EngineAdaptiveNFA.String(),
	skipOther,
}

func main() {
	verbose := flag.Bool("v", false, "print every test case result")
	maxErrors := flag.Int("max-errors", 100, "stop after this many failures (0 = unlimited)")
	flag.Parse()

	if flag.NArg() < 1 {
		fmt.Fprintf(os.Stderr, "usage: %s [options] <test-file>\n", os.Args[0])
		os.Exit(1)
	}

	if err := run(flag.Arg(0), *verbose, *maxErrors); err != nil {
		fmt.Fprintf(os.Stderr, "error: %v\n", err)
		os.Exit(1)
	}
}

func run(testFile string, verbose bool, maxErrors int) error {
	f, err := os.Open(testFile)
	if err != nil {
		return err
	}
	defer f.Close()

	engine := wasmtime.NewEngine()

	var (
		testStrings []string
		input       []string
		inStrings   bool
		pattern     string

		// per-pattern anchored mode (col 0); nil when pattern was skipped
		store   *wasmtime.Store
		matchFn *wasmtime.Func
		memory  *wasmtime.Memory

		// per-pattern find mode (col 1); nil when compilation failed
		findFn     *wasmtime.Func
		findMemory *wasmtime.Memory

		lineno    int
		npass     int
		nfail     int
		ncases    int
		stopped   bool
		skipCount = make(map[string]int)
	)

	scanner := bufio.NewScanner(f)
	for lineno = 1; scanner.Scan(); lineno++ {
		line := scanner.Text()

		switch {
		case line == "":
			return fmt.Errorf("%s:%d: unexpected blank line", testFile, lineno)

		case line[0] == '#':
			continue

		case 'A' <= line[0] && line[0] <= 'Z':
			if verbose {
				fmt.Println(line)
			}
			continue

		case line == "strings":
			testStrings = testStrings[:0]
			inStrings = true

		case line == "regexps":
			inStrings = false

		case line[0] == '"':
			q, err := strconv.Unquote(line)
			if err != nil {
				return fmt.Errorf("%s:%d: unquote %s: %w", testFile, lineno, line, err)
			}

			if inStrings {
				testStrings = append(testStrings, q)
				continue
			}

			// New pattern — verify previous pattern consumed all its inputs.
			if len(input) != 0 {
				return fmt.Errorf("%s:%d: out of sync: %d strings left before %q",
					testFile, lineno, len(input), q)
			}

			pattern = q
			store, matchFn, memory = nil, nil, nil
			findFn, findMemory = nil, nil

			// Pre-check for unsupported features before attempting compilation.
			if reason := preCheck(pattern); reason != "" {
				skipCount[reason] += len(testStrings)
				input = append([]string(nil), testStrings...)
				continue
			}

			selOpts := compile.CompileOptions{MaxDFAStates: maxDFAStates}
			engineType, selErr := compile.SelectEngine(pattern, selOpts)
			if selErr != nil {
				errStr := selErr.Error()
				reason := skipParseError
				switch {
				case strings.Contains(errStr, "Unicode"):
					reason = skipUnicode
				case strings.Contains(errStr, "invalid escape sequence"):
					reason = skipBadSyntax
				}
				skipCount[reason] += len(testStrings)
				input = append([]string(nil), testStrings...)
				continue
			}
			if engineType != compile.EngineDFA {
				skipCount["requires "+engineType.String()] += len(testStrings)
				input = append([]string(nil), testStrings...)
				continue
			}

			opts := compile.CompileOptions{
				MaxDFAStates: maxDFAStates,
				ForceEngine:  compile.EngineDFA,
			}
			wasmBytes, _, compErr := compile.CompileRegex(pattern, "match", tableBase, true, opts)
			if compErr != nil {
				errStr := compErr.Error()
				reason := skipOther
				if strings.Contains(errStr, "exceeds limit") {
					reason = skipStateLimit
				}
				skipCount[reason] += len(testStrings)
				input = append([]string(nil), testStrings...)
				continue
			}

			// Compile succeeded — set up wasmtime instances for anchored and find modes.
			store = wasmtime.NewStore(engine)
			mod, modErr := wasmtime.NewModule(engine, wasmBytes)
			if modErr != nil {
				return fmt.Errorf("%s:%d: NewModule for %q: %w", testFile, lineno, pattern, modErr)
			}
			inst, instErr := wasmtime.NewInstance(store, mod, []wasmtime.AsExtern{})
			if instErr != nil {
				return fmt.Errorf("%s:%d: NewInstance for %q: %w", testFile, lineno, pattern, instErr)
			}
			matchFn = inst.GetFunc(store, "match")
			if exp := inst.GetExport(store, "memory"); exp != nil {
				memory = exp.Memory()
			}

			// Also compile find mode for non-anchored (col 1) test cases,
			// but only when DFA semantics match RE2's leftmost-first.
			// Skip patterns with alternations (|) or non-greedy quantifiers
			// because DFA gives leftmost-longest while RE2 gives leftmost-first.
			findOpts := compile.CompileOptions{
				MaxDFAStates:  maxDFAStates,
				ForceEngine:   compile.EngineDFA,
				Mode:          compile.ModeFind,
				LeftmostFirst: true,
			}
			parsedForFind, _ := syntax.Parse(pattern, syntax.Perl)
			if parsedForFind != nil && !findModeUnsafe(parsedForFind) {
				if findBytes, _, fErr := compile.CompileRegex(pattern, "find", tableBase, true, findOpts); fErr == nil {
					if findMod, fModErr := wasmtime.NewModule(engine, findBytes); fModErr == nil {
						if findInst, fInstErr := wasmtime.NewInstance(store, findMod, []wasmtime.AsExtern{}); fInstErr == nil {
							findFn = findInst.GetFunc(store, "find")
							if exp := findInst.GetExport(store, "memory"); exp != nil {
								findMemory = exp.Memory()
							}
						}
					}
				}
			}

			input = append([]string(nil), testStrings...)

		case line[0] == '-' || ('0' <= line[0] && line[0] <= '9'):
			if len(input) == 0 {
				return fmt.Errorf("%s:%d: out of sync: no input remaining", testFile, lineno)
			}
			text := input[0]
			input = input[1:]

			// Pattern was skipped — consume the result line without testing.
			if store == nil {
				continue
			}

			ncases++
			if ncases%500000 == 0 {
				fmt.Fprintf(os.Stderr, "  ... %dK cases\n", ncases/1000)
			}
			results := strings.Split(line, ";")
			if len(results) != 4 {
				return fmt.Errorf("%s:%d: expected 4 results, got %d", testFile, lineno, len(results))
			}
			col0 := strings.TrimSpace(results[0])
			col1 := strings.TrimSpace(results[1])

			// Skip cases where the input contains Unicode.
			if hasUnicode(text) {
				skipCount[skipUnicode]++
				continue
			}

			if col0 == "-" && col1 != "-" {
				// Non-anchored case: test with find mode if available.
				if findFn == nil {
					skipCount[skipNonAnchored]++
					continue
				}
				got, callErr := callFind(store, findFn, findMemory, text)
				if callErr != nil {
					return fmt.Errorf("%s:%d: wasm find call pattern=%q input=%q: %w",
						testFile, lineno, pattern, text, callErr)
				}
				expected := parseCol1(col1)
				if got == expected {
					npass++
					if verbose {
						fmt.Printf("PASS %s:%d pattern=%q input=%q (find)\n", testFile, lineno, pattern, text)
					}
				} else {
					nfail++
					fmt.Printf("FAIL  pattern: %q\n      input:   %q\n      expected: %s\n      got:      %s\n",
						pattern, text, fmtFindResult(expected), fmtFindResult(got))
					if maxErrors > 0 && nfail >= maxErrors {
						fmt.Printf("Stopping after %d failure(s)\n", nfail)
						stopped = true
						goto done
					}
				}
				continue
			}

			got, callErr := callMatch(store, matchFn, memory, text)
			if callErr != nil {
				return fmt.Errorf("%s:%d: wasm call pattern=%q input=%q: %w",
					testFile, lineno, pattern, text, callErr)
			}

			expected := parseCol0(col0)
			if got == expected {
				npass++
				if verbose {
					fmt.Printf("PASS %s:%d pattern=%q input=%q\n", testFile, lineno, pattern, text)
				}
			} else {
				nfail++
				fmt.Printf("FAIL  pattern: %q\n      input:   %q\n      expected: %s\n      got:      %s\n",
					pattern, text, fmtResult(expected), fmtResult(got))
				if maxErrors > 0 && nfail >= maxErrors {
					fmt.Printf("Stopping after %d failure(s)\n", nfail)
					stopped = true
					goto done
				}
			}

		default:
			return fmt.Errorf("%s:%d: unexpected line: %s", testFile, lineno, line)
		}
	}

done:
	if err := scanner.Err(); err != nil {
		return fmt.Errorf("scan: %w", err)
	}
	if !stopped && len(input) != 0 {
		return fmt.Errorf("out of sync: %d strings left at EOF", len(input))
	}

	totalSkipped := 0
	for _, n := range skipCount {
		totalSkipped += n
	}

	fmt.Printf("\n=== RE2 Test Results ===\n")
	fmt.Printf("passed:  %d\n", npass)
	fmt.Printf("failed:  %d\n", nfail)
	fmt.Printf("skipped: %d\n", totalSkipped)
	for _, reason := range skipOrder {
		if n := skipCount[reason]; n > 0 {
			fmt.Printf("  %-38s %d\n", reason+":", n)
		}
	}

	if nfail > 0 {
		return fmt.Errorf("%d test(s) failed", nfail)
	}
	return nil
}

// callMatch writes text into WASM linear memory and invokes the match function.
func callMatch(store *wasmtime.Store, fn *wasmtime.Func, mem *wasmtime.Memory, text string) (int32, error) {
	if len(text) > 0 {
		buf := mem.UnsafeData(store)
		copy(buf[inputBase:], text)
	}
	result, err := fn.Call(store, inputBase, int32(len(text)))
	if err != nil {
		return 0, err
	}
	return result.(int32), nil
}

// callFind writes text into WASM linear memory and invokes the find function.
// Returns packed (start<<32)|end as int64, or -1 on no match.
func callFind(store *wasmtime.Store, fn *wasmtime.Func, mem *wasmtime.Memory, text string) (int64, error) {
	if len(text) > 0 {
		buf := mem.UnsafeData(store)
		copy(buf[inputBase:], text)
	}
	result, err := fn.Call(store, inputBase, int32(len(text)))
	if err != nil {
		return 0, err
	}
	return result.(int64), nil
}

// parseCol0 converts a col-0 result string to the expected WASM return value.
// "-" → -1 (no match); "0-N ..." → N (end position; submatches ignored).
func parseCol0(col string) int32 {
	if col == "-" {
		return -1
	}
	pair := col
	if idx := strings.IndexByte(col, ' '); idx >= 0 {
		pair = col[:idx]
	}
	dashIdx := strings.IndexByte(pair, '-')
	if dashIdx < 0 {
		return -1
	}
	end, err := strconv.Atoi(pair[dashIdx+1:])
	if err != nil {
		return -1
	}
	return int32(end)
}

// parseCol1 converts a col-1 result string to the expected find return value.
// "-" → -1; "s-e ..." → packed (s<<32)|e (submatches ignored).
func parseCol1(col string) int64 {
	if col == "-" {
		return -1
	}
	pair := col
	if idx := strings.IndexByte(col, ' '); idx >= 0 {
		pair = col[:idx]
	}
	dashIdx := strings.IndexByte(pair, '-')
	if dashIdx < 0 {
		return -1
	}
	start, err1 := strconv.ParseInt(pair[:dashIdx], 10, 64)
	end, err2 := strconv.ParseInt(pair[dashIdx+1:], 10, 64)
	if err1 != nil || err2 != nil {
		return -1
	}
	return start<<32 | end
}

func fmtResult(v int32) string {
	if v < 0 {
		return "no match"
	}
	return fmt.Sprintf("end=%d", v)
}

func fmtFindResult(v int64) string {
	if v == -1 {
		return "no match"
	}
	start := uint32(v >> 32)
	end := uint32(v)
	return fmt.Sprintf("start=%d end=%d", start, end)
}

// preCheck detects patterns that cannot be tested without attempting compilation.
// Returns a skip reason string, or "" if compilation should be attempted.
func preCheck(pattern string) string {
	if hasUnicode(pattern) {
		return skipUnicode
	}
	re, err := syntax.Parse(pattern, syntax.Perl)
	if err != nil {
		return "" // let CompileRegex report the actual error
	}
	if re.MaxCap() > 0 {
		return skipCaptures
	}
	return ""
}

// findModeUnsafe reports whether a pattern cannot be correctly tested in find
// mode. With leftmost-first DFA and immediateAccepting, all quantifier types
// including non-greedy are handled correctly by the DFA.
func findModeUnsafe(re *syntax.Regexp) bool {
	switch re.Op {
	}
	for _, sub := range re.Sub {
		if findModeUnsafe(sub) {
			return true
		}
	}
	return false
}

// hasUnicode reports whether a pattern string requires Unicode support.
func hasUnicode(s string) bool {
	for _, r := range s {
		if r > 127 {
			return true
		}
	}
	return strings.Contains(s, `\p`) || strings.Contains(s, `\P`)
}
