package main

import (
	"bufio"
	"flag"
	"fmt"
	"os"
	"regexp"
	"regexp/syntax"
	"strconv"
	"strings"
	"time"

	wasmtime "github.com/bytecodealliance/wasmtime-go/v42"
	"github.com/qrdl/regexped/compile"
	"github.com/qrdl/regexped/config"
)

const (
	// inputBase is the offset within WASM memory where test inputs are written.
	// tableBase must be at a higher page-aligned address to avoid overlap.
	inputBase = int32(0)
	tableBase = int64(65536) // page 1; page 0 is reserved for test inputs

	maxDFAStates = 100000
)

const (
	skipNonAnchored = "requires Backtracking (non-greedy find mode)"
	skipCaptures    = "requires Backtracking (capture groups)"
	skipUnicode     = "requires Unicode support"
	skipStateLimit  = "requires larger DFA (state limit exceeded)"
	skipBadSyntax   = "unsupported RE2 syntax (invalid escape sequence)"
	skipParseError  = "parse/compile error"
	skipOther       = "other reasons"
	skipTimeout     = "timeout (exponential backtracking)"
)

// skipOrder controls the display order of skip reasons in the summary.
var skipOrder = []string{
	skipNonAnchored,
	skipCaptures,
	skipUnicode,
	skipStateLimit,
	skipBadSyntax,
	skipParseError,
	skipTimeout,
	"requires " + compile.EngineBacktrack.String(),
	skipOther,
}

func main() {
	verbose := flag.Bool("v", false, "print every test case result")
	maxErrors := flag.Int("max-errors", 100, "stop after this many failures (0 = unlimited)")
	validateGo := flag.Bool("validate-go", false, "validate test expectations against Go stdlib regexp (reports data errors, skips WASM testing)")
	validateGroups := flag.Bool("validate-groups", false, "enable col0 capture groups validation against Go stdlib and WASM (off by default for re2-exhaustive.txt compatibility)")
	forceBacktrack := flag.Bool("force-backtrack", false, "force Backtracking engine for match/find (sets MaxDFAStates=1 so DFA always overflows to BT)")
	flag.Parse()

	if flag.NArg() < 1 {
		fmt.Fprintf(os.Stderr, "usage: %s [options] <test-file>\n", os.Args[0])
		os.Exit(1)
	}

	if err := run(flag.Arg(0), *verbose, *maxErrors, *validateGo, *validateGroups, *forceBacktrack); err != nil {
		fmt.Fprintf(os.Stderr, "error: %v\n", err)
		os.Exit(1)
	}
}

func run(testFile string, verbose bool, maxErrors int, validateGo bool, validateGroups bool, forceBacktrack bool) error {
	f, err := os.Open(testFile)
	if err != nil {
		return err
	}
	defer f.Close()

	cfg := wasmtime.NewConfig()
	cfg.SetEpochInterruption(true)
	engine := wasmtime.NewEngineWithConfig(cfg)
	wd := newWatchdog(engine)

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

		// per-pattern groups mode (col 0 captures); nil when not applicable
		groupsStore       *wasmtime.Store
		groupsFn          *wasmtime.Func
		groupsMemory      *wasmtime.Memory
		numGroups         int
		groupsIsBacktrack bool // true when backtracking engine is used
		isCompiledDFA     bool // true when compiled DFA engine is used

		lineno           int
		npass            int
		nfail            int
		nDataErrors      int
		ncases           int
		stopped          bool
		npassDFA         int
		npassCompiledDFA int
		npassTDFA        int
		npassBacktrack   int
		npassBTMatchFind int // BT match/find (--force-backtrack)
		skipCount        = make(map[string]int)
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
			groupsStore, groupsFn, groupsMemory, numGroups, groupsIsBacktrack = nil, nil, nil, 0, false
			isCompiledDFA = false

			// Pre-check for unsupported features before attempting compilation.
			if reason := preCheck(pattern); reason != "" {
				skipCount[reason] += len(testStrings)
				input = append([]string(nil), testStrings...)
				continue
			}

			var engineType compile.EngineType
			if forceBacktrack {
				engineType = compile.EngineBacktrack
			} else {
				selOpts := compile.CompileOptions{MaxDFAStates: maxDFAStates}
				var selErr error
				engineType, selErr = compile.SelectEngine(pattern, selOpts)
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
				if engineType != compile.EngineDFA && engineType != compile.EngineCompiledDFA && engineType != compile.EngineBacktrack && engineType != compile.EngineTDFA {
					skipCount["requires "+engineType.String()] += len(testStrings)
					input = append([]string(nil), testStrings...)
					continue
				}
			}

			// Compile a single standalone WASM module containing all functions.
			re := config.RegexEntry{
				Pattern:   pattern,
				MatchFunc: "match",
				FindFunc:  "find",
			}
			if !forceBacktrack && (engineType == compile.EngineBacktrack || engineType == compile.EngineTDFA) {
				re.GroupsFunc = "groups"
			}
			var compileOpts compile.CompileOptions
			if forceBacktrack {
				compileOpts.ForceEngine = compile.EngineBacktrack
			}
			wasmBytes, _, compErr := compile.Compile([]config.RegexEntry{re}, tableBase, true, compileOpts)
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

			// Load single module — all functions share one memory.
			store = wasmtime.NewStore(engine)
			store.SetEpochDeadline(1)
			mod, modErr := wasmtime.NewModule(engine, wasmBytes)
			if modErr != nil {
				return fmt.Errorf("%s:%d: NewModule for %q: %w", testFile, lineno, pattern, modErr)
			}
			inst, instErr := wasmtime.NewInstance(store, mod, []wasmtime.AsExtern{})
			if instErr != nil {
				return fmt.Errorf("%s:%d: NewInstance for %q: %w", testFile, lineno, pattern, instErr)
			}
			matchFn = inst.GetFunc(store, "match")
			findFn = inst.GetFunc(store, "find")
			if exp := inst.GetExport(store, "memory"); exp != nil {
				memory = exp.Memory()
			}
			findMemory = memory
			isCompiledDFA = !forceBacktrack && (engineType == compile.EngineCompiledDFA)

			if re.GroupsFunc != "" {
				groupsFn = inst.GetFunc(store, "groups")
				groupsStore = store
				groupsMemory = memory
				groupsIsBacktrack = (engineType == compile.EngineBacktrack)
				if p2, p2Err := syntax.Parse(pattern, syntax.Perl); p2Err == nil {
					numGroups = p2.MaxCap() + 1
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
			if store == nil && groupsStore == nil && !validateGo {
				continue
			}

			ncases++
			if ncases%500000 == 0 {
				fmt.Fprintf(os.Stderr, "  ... %dK cases\n", ncases/1000)
			}
			results := strings.Split(line, ";")
			if len(results) < 4 {
				return fmt.Errorf("%s:%d: expected at least 4 results, got %d", testFile, lineno, len(results))
			}
			col0 := strings.TrimSpace(results[0])
			col1 := strings.TrimSpace(results[1])
			var col4, col5 string
			if len(results) >= 5 {
				col4 = strings.TrimSpace(results[4])
			}
			if len(results) >= 6 {
				col5 = strings.TrimSpace(results[5])
			}

			// Skip cases where the input contains Unicode.
			if hasUnicode(text) {
				skipCount[skipUnicode]++
				continue
			}

			// --validate-go: check expectations against Go stdlib before WASM testing.
			if validateGo {
				re, reErr := regexp.Compile(pattern)
				if reErr != nil {
					// Pattern not supported by Go stdlib (e.g. \C) — skip validation.
					continue
				}
				// col0 (anchored groups): only when --validate-groups is on.
				if validateGroups && col0 != "-" {
					goSub0 := re.FindStringSubmatchIndex(text)
					expSlots0 := parseCaptures(col0, re.NumSubexp()+1)
					goAnchored := len(goSub0) >= 2 && goSub0[0] == 0 && goSub0[1] == len(text)
					if !goAnchored {
						goSub0 = nil
					}
					if !slotsEqualGo(goSub0, expSlots0) {
						nDataErrors++
						fmt.Printf("DATA  pattern: %q\n      input:   %q\n      col0 expected: %s\n      col0 go:       %s\n",
							pattern, text, fmtSlots(expSlots0), fmtGoSub(goSub0))
					}
				}
				// col1 (find): Go uses leftmost-first, same as our find DFA.
				goM := re.FindStringIndex(text)
				var goFind int64 = -1
				if goM != nil {
					goFind = int64(goM[0])<<32 | int64(goM[1])
				}
				if exp1 := parseCol1(col1); goFind != exp1 {
					nDataErrors++
					fmt.Printf("DATA  pattern: %q\n      input:   %q\n      col1 expected: %s\n      col1 go:       %s\n",
						pattern, text, fmtFindResult(exp1), fmtFindResult(goFind))
				}
				// col4 (all matches): validate if present.
				// We simulate our own iteration loop (call FindStringIndex repeatedly with
				// advancing offset) rather than using FindAllStringIndex. This matches the
				// behavior of the WASM iteration loop: after a zero-length match at position p
				// we advance to p+1 and DO include the empty match, whereas Go's
				// FindAllStringIndex skips empty matches adjacent to the previous match.
				if col4 != "" && col4 != "-" {
					var goAll [][]int
					off := 0
					for off <= len(text) {
						m := re.FindStringIndex(text[off:])
						if m == nil {
							break
						}
						s := m[0] + off
						e := m[1] + off
						goAll = append(goAll, []int{s, e})
						if e > s {
							off = e
						} else {
							off = s + 1
						}
					}
					expAll := parseCol4(col4)
					if !col4Equal(goAll, expAll) {
						nDataErrors++
						fmt.Printf("DATA  pattern: %q\n      input:   %q\n      col4 expected: %s\n      col4 go:       %s\n",
							pattern, text, fmtCol4(expAll), fmtCol4GoAll(goAll))
					}
				}
				// col5 (non-anchored find with captures): validate if present.
				if col5 != "" && col5 != "-" {
					goSub := re.FindStringSubmatchIndex(text)
					expSlots := parseCaptures(col5, re.NumSubexp()+1)
					if !slotsEqualGo(goSub, expSlots) {
						nDataErrors++
						fmt.Printf("DATA  pattern: %q\n      input:   %q\n      col5 expected: %s\n      col5 go:       %s\n",
							pattern, text, fmtSlots(expSlots), fmtGoSub(goSub))
					}
				}
			}

			if !validateGo {
				// col1: non-anchored find (only when no anchored result expected, matching RE2 test convention).
				if col0 == "-" && col1 != "-" {
					if findFn == nil {
						skipCount[skipNonAnchored]++
						// Fall through to col4/col5 tests below.
					} else {
						got, callErr := callFind(wd, store, findFn, findMemory, text)
						if callErr != nil {
							if isTimeout(callErr) {
								if forceBacktrack {
									store, matchFn, memory = nil, nil, nil
									findFn, findMemory = nil, nil
									skipCount[skipTimeout]++
									continue
								}
								return fmt.Errorf("TIMEOUT: find pattern=%q input=%q", pattern, text)
							}
							return fmt.Errorf("%s:%d: wasm find call pattern=%q input=%q: %w",
								testFile, lineno, pattern, text, callErr)
						}
						expected := parseCol1(col1)
						if got == expected {
							npass++
							if forceBacktrack {
								npassBTMatchFind++
							} else if isCompiledDFA {
								npassCompiledDFA++
							} else {
								npassDFA++
							}
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
					}
				} else if groupsFn != nil && validateGroups {
					// col0: anchored match with captures (only when --validate-groups is on).
					// groups is now non-anchored; treat as no match if result doesn't start at 0.
					endPos, slots, callErr := callGroups(wd, groupsStore, groupsFn, groupsMemory, text, numGroups)
					if callErr != nil {
						if isTimeout(callErr) {
							if forceBacktrack {
								groupsStore, groupsFn, groupsMemory = nil, nil, nil
								skipCount[skipTimeout]++
								continue
							}
							return fmt.Errorf("TIMEOUT: groups pattern=%q input=%q", pattern, text)
						}
						return fmt.Errorf("%s:%d: wasm groups call pattern=%q input=%q: %w",
							testFile, lineno, pattern, text, callErr)
					}
					// Non-anchored groups: if match doesn't start at 0, treat as no match for col0.
					if endPos >= 0 && len(slots) > 0 && slots[0] != 0 {
						endPos = -1
						slots = nil
					}
					expectedEnd := parseCol0(col0)
					expectedSlots := parseCaptures(col0, numGroups)
					endMatch := endPos == expectedEnd
					slotsMatch := true
					if expectedSlots != nil && slots != nil {
						for i := range expectedSlots {
							if i < len(slots) && slots[i] != expectedSlots[i] {
								slotsMatch = false
								break
							}
						}
					} else if (expectedSlots == nil) != (slots == nil) {
						slotsMatch = false
					}
					if endMatch && slotsMatch {
						npass++
						if groupsIsBacktrack {
							npassBacktrack++
						} else {
							npassTDFA++
						}
						if verbose {
							fmt.Printf("PASS %s:%d pattern=%q input=%q (groups)\n", testFile, lineno, pattern, text)
						}
					} else {
						nfail++
						fmt.Printf("FAIL  pattern: %q\n      input:   %q\n      expected: end=%d slots=%s\n      got:      end=%d slots=%s\n",
							pattern, text, expectedEnd, fmtSlots(expectedSlots), endPos, fmtSlots(slots))
						if maxErrors > 0 && nfail >= maxErrors {
							fmt.Printf("Stopping after %d failure(s)\n", nfail)
							stopped = true
							goto done
						}
					}
				} else if matchFn != nil {
					// col0: anchored match (no captures).
					got, callErr := callMatch(wd, store, matchFn, memory, text)
					if callErr != nil {
						if isTimeout(callErr) {
							if forceBacktrack {
								store, matchFn, memory = nil, nil, nil
								findFn, findMemory = nil, nil
								skipCount[skipTimeout]++
								continue
							}
							return fmt.Errorf("TIMEOUT: match pattern=%q input=%q", pattern, text)
						}
						return fmt.Errorf("%s:%d: wasm call pattern=%q input=%q: %w",
							testFile, lineno, pattern, text, callErr)
					}
					expected := parseCol0(col0)
					if got == expected {
						npass++
						if forceBacktrack {
							npassBTMatchFind++
						} else if isCompiledDFA {
							npassCompiledDFA++
						} else {
							npassDFA++
						}
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
				}

				// col4: find iteration (all matches).
				if col4 != "" && col4 != "-" && findFn != nil {
					expAll := parseCol4(col4)
					var gotAll [][2]int
					offset := 0
					for offset <= len(text) {
						r, callErr := callFind(wd, store, findFn, findMemory, text[offset:])
						if callErr != nil {
							if isTimeout(callErr) {
								if forceBacktrack {
									store, matchFn, memory = nil, nil, nil
									findFn, findMemory = nil, nil
									skipCount[skipTimeout]++
									goto nextResultLine
								}
								return fmt.Errorf("TIMEOUT: find-iter pattern=%q input=%q", pattern, text)
							}
							return fmt.Errorf("%s:%d: wasm find-iter call pattern=%q input=%q: %w",
								testFile, lineno, pattern, text, callErr)
						}
						if r == -1 {
							break
						}
						s := int(r>>32) + offset
						e := int(uint32(r)) + offset
						gotAll = append(gotAll, [2]int{s, e})
						if e > s {
							offset = e
						} else {
							offset = s + 1
						}
					}
					if !col4WasmEqual(gotAll, expAll) {
						nfail++
						fmt.Printf("FAIL  pattern: %q\n      input:   %q\n      col4 expected: %s\n      col4 got:      %s\n",
							pattern, text, fmtCol4(expAll), fmtCol4Wasm(gotAll))
						if maxErrors > 0 && nfail >= maxErrors {
							fmt.Printf("Stopping after %d failure(s)\n", nfail)
							stopped = true
							goto done
						}
					} else {
						npass++
						if forceBacktrack {
							npassBTMatchFind++
						} else if isCompiledDFA {
							npassCompiledDFA++
						} else {
							npassDFA++
						}
					}
				}

				// col5: non-anchored find with captures.
				if col5 != "" && col5 != "-" && groupsFn != nil {
					endPos, slots, callErr := callGroups(wd, groupsStore, groupsFn, groupsMemory, text, numGroups)
					if callErr != nil {
						if isTimeout(callErr) {
							if forceBacktrack {
								groupsStore, groupsFn, groupsMemory = nil, nil, nil
								skipCount[skipTimeout]++
								goto nextResultLine
							}
							return fmt.Errorf("TIMEOUT: groups-find pattern=%q input=%q", pattern, text)
						}
						return fmt.Errorf("%s:%d: wasm groups-find call pattern=%q input=%q: %w",
							testFile, lineno, pattern, text, callErr)
					}
					expectedEnd := parseCol0(col5)
					expectedSlots := parseCaptures(col5, numGroups)
					endMatch := endPos == expectedEnd
					slotsMatch := true
					if expectedSlots != nil && slots != nil {
						for i := range expectedSlots {
							if i < len(slots) && slots[i] != expectedSlots[i] {
								slotsMatch = false
								break
							}
						}
					} else if (expectedSlots == nil) != (slots == nil) {
						slotsMatch = false
					}
					if endMatch && slotsMatch {
						npass++
						if groupsIsBacktrack {
							npassBacktrack++
						} else {
							npassTDFA++
						}
						if verbose {
							fmt.Printf("PASS %s:%d pattern=%q input=%q (groups-find)\n", testFile, lineno, pattern, text)
						}
					} else {
						nfail++
						fmt.Printf("FAIL  pattern: %q\n      input:   %q\n      col5 expected: end=%d slots=%s\n      col5 got:      end=%d slots=%s\n",
							pattern, text, expectedEnd, fmtSlots(expectedSlots), endPos, fmtSlots(slots))
						if maxErrors > 0 && nfail >= maxErrors {
							fmt.Printf("Stopping after %d failure(s)\n", nfail)
							stopped = true
							goto done
						}
					}
				}
			nextResultLine:
			} // end !validateGo
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
	fmt.Printf("  %-38s %d\n", "DFA:", npassDFA)
	fmt.Printf("  %-38s %d\n", "Compiled DFA:", npassCompiledDFA)
	fmt.Printf("  %-38s %d\n", "TDFA:", npassTDFA)
	fmt.Printf("  %-38s %d\n", "Backtrack:", npassBacktrack)
	if npassBTMatchFind > 0 {
		fmt.Printf("  %-38s %d\n", "Backtrack (match/find):", npassBTMatchFind)
	}
	fmt.Printf("failed:  %d\n", nfail)
	if nDataErrors > 0 {
		fmt.Printf("data errors (--validate-go): %d\n", nDataErrors)
	}
	fmt.Printf("skipped: %d\n", totalSkipped)
	for _, reason := range skipOrder {
		if n := skipCount[reason]; n > 0 {
			fmt.Printf("  %-38s %d\n", reason+":", n)
		}
	}

	if nDataErrors > 0 {
		return fmt.Errorf("%d data error(s) — fix test file expectations", nDataErrors)
	}
	if nfail > 0 {
		return fmt.Errorf("%d test(s) failed", nfail)
	}
	return nil
}

const wasmCallTimeout = 2 * time.Second

// watchdog manages a single reusable timeout goroutine.
// Arm before a WASM call; Disarm when it completes normally.
// If the timeout fires before Disarm, the engine epoch is incremented.
type watchdog struct {
	arm    chan *wasmtime.Store
	disarm chan struct{}
}

func newWatchdog(eng *wasmtime.Engine) *watchdog {
	w := &watchdog{
		arm:    make(chan *wasmtime.Store),
		disarm: make(chan struct{}),
	}
	go func() {
		for store := range w.arm {
			store.SetEpochDeadline(1)
			select {
			case <-time.After(wasmCallTimeout):
				eng.IncrementEpoch()
				<-w.disarm // consume the disarm that will arrive after interrupt
			case <-w.disarm:
				// call completed before timeout — nothing to do
			}
		}
	}()
	return w
}

func (w *watchdog) Arm(store *wasmtime.Store) { w.arm <- store }
func (w *watchdog) Disarm()                   { w.disarm <- struct{}{} }

// isTimeout reports whether a wasmtime error is an epoch interruption.
func isTimeout(err error) bool {
	return err != nil && strings.Contains(err.Error(), "interrupt")
}

// callMatch writes text into WASM linear memory and invokes the match function.
func callMatch(wd *watchdog, store *wasmtime.Store, fn *wasmtime.Func, mem *wasmtime.Memory, text string) (int32, error) {
	wd.Arm(store)
	defer wd.Disarm()
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
func callFind(wd *watchdog, store *wasmtime.Store, fn *wasmtime.Func, mem *wasmtime.Memory, text string) (int64, error) {
	wd.Arm(store)
	defer wd.Disarm()
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

// slotsBase is the WASM memory address used for the groups output buffer.
const slotsBase = int32(512)

// callGroups writes text into WASM memory and invokes the groups function.
// Returns (endPos, slots) where slots[i*2],slots[i*2+1] = start,end for group i.
func callGroups(wd *watchdog, store *wasmtime.Store, fn *wasmtime.Func, mem *wasmtime.Memory, text string, numGroups int) (int32, []int32, error) {
	buf := mem.UnsafeData(store)
	if len(text) > 0 {
		copy(buf[inputBase:], text)
	}
	// Pre-initialize slots to -1.
	for i := 0; i < numGroups*2; i++ {
		off := slotsBase + int32(i*4)
		buf[off] = 0xFF
		buf[off+1] = 0xFF
		buf[off+2] = 0xFF
		buf[off+3] = 0xFF
	}
	wd.Arm(store)
	defer wd.Disarm()
	result, err := fn.Call(store, inputBase, int32(len(text)), slotsBase)
	if err != nil {
		return 0, nil, err
	}
	endPos := result.(int32)
	if endPos < 0 {
		return -1, nil, nil
	}
	slots := make([]int32, numGroups*2)
	for i := range slots {
		off := slotsBase + int32(i*4)
		slots[i] = int32(buf[off]) | int32(buf[off+1])<<8 | int32(buf[off+2])<<16 | int32(buf[off+3])<<24
	}
	return endPos, slots, nil
}

// parseCaptures parses a col-0 result string that may include submatches.
// Returns nil if no match. Otherwise returns []int32{start0,end0,start1,end1,...}
// with -1,-1 for unmatched groups.
func parseCaptures(col string, numGroups int) []int32 {
	if col == "-" {
		return nil
	}
	parts := strings.Fields(col)
	slots := make([]int32, numGroups*2)
	for i := range slots {
		slots[i] = -1
	}
	for i, p := range parts {
		if i >= numGroups {
			break
		}
		if p == "-" {
			slots[i*2] = -1
			slots[i*2+1] = -1
			continue
		}
		dash := strings.IndexByte(p, '-')
		if dash < 0 {
			continue
		}
		s, err1 := strconv.Atoi(p[:dash])
		e, err2 := strconv.Atoi(p[dash+1:])
		if err1 != nil || err2 != nil {
			continue
		}
		slots[i*2] = int32(s)
		slots[i*2+1] = int32(e)
	}
	return slots
}

func fmtSlots(slots []int32) string {
	if slots == nil {
		return "no match"
	}
	var parts []string
	for i := 0; i < len(slots); i += 2 {
		if slots[i] < 0 {
			parts = append(parts, "-")
		} else {
			parts = append(parts, fmt.Sprintf("%d-%d", slots[i], slots[i+1]))
		}
	}
	return strings.Join(parts, " ")
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
	_, err := syntax.Parse(pattern, syntax.Perl)
	if err != nil {
		return "" // let CompileRegex report the actual error
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

// parseCol4 parses a col4 string like "0-1,3-5,7-8" into pairs, or nil for "-"/empty.
func parseCol4(col string) [][2]int {
	if col == "" || col == "-" {
		return nil
	}
	var pairs [][2]int
	for _, part := range strings.Split(col, ",") {
		part = strings.TrimSpace(part)
		dash := strings.IndexByte(part, '-')
		if dash < 0 {
			continue
		}
		s, err1 := strconv.Atoi(part[:dash])
		e, err2 := strconv.Atoi(part[dash+1:])
		if err1 != nil || err2 != nil {
			continue
		}
		pairs = append(pairs, [2]int{s, e})
	}
	return pairs
}

// col4Equal compares Go FindAllStringIndex results against parsed col4 pairs.
func col4Equal(goAll [][]int, exp [][2]int) bool {
	if len(goAll) != len(exp) {
		return false
	}
	for i, m := range goAll {
		if m[0] != exp[i][0] || m[1] != exp[i][1] {
			return false
		}
	}
	return true
}

// col4WasmEqual compares WASM iteration results against parsed col4 pairs.
func col4WasmEqual(got [][2]int, exp [][2]int) bool {
	if len(got) != len(exp) {
		return false
	}
	for i := range got {
		if got[i] != exp[i] {
			return false
		}
	}
	return true
}

func fmtCol4(pairs [][2]int) string {
	if pairs == nil {
		return "no matches"
	}
	var parts []string
	for _, p := range pairs {
		parts = append(parts, fmt.Sprintf("%d-%d", p[0], p[1]))
	}
	return strings.Join(parts, ",")
}

func fmtCol4GoAll(goAll [][]int) string {
	if goAll == nil {
		return "no matches"
	}
	var parts []string
	for _, m := range goAll {
		parts = append(parts, fmt.Sprintf("%d-%d", m[0], m[1]))
	}
	return strings.Join(parts, ",")
}

func fmtCol4Wasm(pairs [][2]int) string {
	return fmtCol4(pairs)
}

// slotsEqualGo compares Go FindStringSubmatchIndex against expected slot pairs.
func slotsEqualGo(goSub []int, exp []int32) bool {
	if len(goSub) == 0 && exp == nil {
		return true
	}
	if len(goSub) == 0 || exp == nil {
		return false
	}
	n := len(goSub)
	if n > len(exp) {
		n = len(exp)
	}
	for i := 0; i < n; i++ {
		if int32(goSub[i]) != exp[i] {
			return false
		}
	}
	return true
}

func fmtGoSub(goSub []int) string {
	if len(goSub) == 0 {
		return "no match"
	}
	var parts []string
	for i := 0; i+1 < len(goSub); i += 2 {
		if goSub[i] < 0 {
			parts = append(parts, "-")
		} else {
			parts = append(parts, fmt.Sprintf("%d-%d", goSub[i], goSub[i+1]))
		}
	}
	return strings.Join(parts, " ")
}
