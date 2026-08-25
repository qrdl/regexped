package main

import (
	"bufio"
	"flag"
	"fmt"
	"os"
	"regexp"
	"regexp/syntax"
	"sort"
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
	forceBacktrack := flag.Bool("force-backtrack", false, "force Backtracking engine for match/find/groups (sets MaxDFAStates=-1 so DFA/TDFA always overflow to BT)")
	setsMode := flag.Bool("sets", false, "test the set capabilities: compile each regexps block's patterns as sets and verify every declared capability against a live Go oracle")
	setBatch := flag.Bool("set-batch", false, "with --sets, drive `find_batch` ONLY at a buffer capacity of one, so every multi-match position splits and every §19 resume path is taken (default drives capacity 1 and capacity=pattern-count)")
	setChunk := flag.Int("set-chunk", 32, "with --sets, patterns per compiled set (0 = one set per corpus block, which is what --sets did before §22). The RE2 corpus has 27 blocks of 132..7020 patterns, so without chunking the frontend and id-space thresholds (packed-pair <=16, Teddy <=64, AC >16, wide `_all` >64) are never crossed from below")
	setShuffle := flag.Bool("set-shuffle", false, "with --sets, deterministically permute a block's patterns before chunking, so a set holds unrelated patterns instead of variations of one generator family")
	setBT := flag.Int("set-bt", 0, "with --sets, force set members onto the Backtracking fallback engine by capping max_fallback_states at this many DFA states (0 = off, 1 = force everything BT can take). SETS_PLAN item 20: patterns over the limit used to be DROPPED from the set entirely, so this is the only way to exercise BT-backed buckets at corpus scale")
	setSampleN := flag.Int("sample", 1, "with --sets, test only every Nth chunk (1 = all). This is what separates the sampled gate from the exhaustive run")
	setSubsetF := flag.Bool("set-subset", false, "with --sets, make each set select a NAMED SUBSET of the chunk's patterns (every second one, from index 1) instead of `patterns: all`; this is the only configuration in which PATTERN_COUNT and ID_SPACE differ, which is what sizes the gate array and the `_all` bitmap")
	setProfiles := flag.String("set-profiles", "all", "with --sets, comma-separated capability profiles to compile per chunk: all, anchored, scan, scan-any, find, find-ov, batch, batch-ov — or all-profiles")
	likelyMatch := flag.Bool("likelymatch", false, "compile every pattern with LikelyMode=LikelyMatch to exercise the lit-chain Opt 2 emission path on the full corpus")
	likelyNoMatch := flag.Bool("likelynomatch", false, "compile every pattern with LikelyMode=LikelyNoMatch to exercise the Opt 1 dominant-self-loop bulk-skip emission path on the full corpus")
	groupsOnly := flag.Bool("groups-only", false, "compile patterns with only groups_func set (omit match_func/find_func); surfaces lit-chain capture path bugs that depend on the narrow gate")
	matchOnly := flag.Bool("match-only", false, "compile non-capturing patterns with only match_func set (omit find_func); reaches the needMatch && !needFind call sites (e.g. analyseLitChainAltLenient's Gap B lenient path) that match+find-together dispatch never exercises")
	findOnly := flag.Bool("find-only", false, "compile non-capturing patterns with only find_func set (omit match_func); reaches the needFind && !needMatch call sites — the Gap E alt-prefixed find body, the Gap C alt-range find body and the strict/lenient alt find bodies — which match+find-together dispatch never exercises")
	flag.Parse()

	if flag.NArg() < 1 {
		fmt.Fprintf(os.Stderr, "usage: %s [options] <test-file>\n", os.Args[0])
		os.Exit(1)
	}

	// The set-mode switches are package-level rather than further parameters on
	// run()/testSetBlock(): they change only what the set path COMPILES and
	// DRIVES, and threading eight more through would double the width of two
	// already-overlong signatures.
	setBatchCap1Only = *setBatch
	setSubset = *setSubsetF
	setChunkSize = *setChunk
	setShufflePats = *setShuffle
	setSample = *setSampleN
	setMaxPrint = *maxErrors
	setBTFallback = *setBT
	if *setSampleN < 1 {
		fmt.Fprintln(os.Stderr, "--sample must be >= 1")
		os.Exit(1)
	}
	for _, f := range []struct {
		set  bool
		name string
	}{{*setBatch, "--set-batch"}, {*setChunk != 32, "--set-chunk"}, {*setShuffle, "--set-shuffle"},
		{*setSampleN != 1, "--sample"}, {*setProfiles != "all", "--set-profiles"},
		{*setSubsetF, "--set-subset"}} {
		if f.set && !*setsMode {
			fmt.Fprintf(os.Stderr, "%s requires --sets\n", f.name)
			os.Exit(1)
		}
	}
	if *setsMode {
		profs, err := resolveSetProfiles(*setProfiles)
		if err != nil {
			fmt.Fprintf(os.Stderr, "%v\n", err)
			os.Exit(1)
		}
		activeSetProfiles = profs
	}
	if err := run(flag.Arg(0), *verbose, *maxErrors, *validateGo, *validateGroups, *forceBacktrack, *setsMode, *likelyMatch, *likelyNoMatch, *groupsOnly, *matchOnly, *findOnly); err != nil {
		fmt.Fprintf(os.Stderr, "error: %v\n", err)
		os.Exit(1)
	}
}

func run(testFile string, verbose bool, maxErrors int, validateGo bool, validateGroups bool, forceBacktrack bool, setsMode bool, likelyMatch bool, likelyNoMatch bool, groupsOnly bool, matchOnly bool, findOnly bool) error {
	f, err := os.Open(testFile)
	if err != nil {
		return err
	}
	defer f.Close()

	cfg := wasmtime.NewConfig()
	cfg.SetEpochInterruption(true)
	engine := wasmtime.NewEngineWithConfig(cfg)
	wd := newWatchdog(engine)

	// Set-mode state: collect eligible patterns per regexps block, test at block boundaries.
	var (
		setBlockEntries []setBlockEntry // eligible patterns for current block
		setBlockStrings []string        // testStrings saved when "regexps" was seen
		setCurrentEntry *setBlockEntry  // entry being populated (nil = ineligible pattern)
		npassSet        int
		nfailSet        int
	)

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
			if setsMode && !inStrings && len(setBlockEntries) >= 2 {
				p, f, setStats, testErr := testSetBlock(setBlockEntries, setBlockStrings, engine, wd, verbose, likelyMatch, likelyNoMatch)
				prevPassSet := npassSet
				npassSet += p
				nfailSet += f
				skipCount[skipTimeout] += setStats.nTimeout
				if testErr != nil {
					return testErr
				}
				if (prevPassSet / 500000) != (npassSet / 500000) {
					fmt.Fprintf(os.Stderr, "  ... %dK set cases\n", npassSet/1000)
				}
				if maxErrors > 0 && nfailSet >= maxErrors {
					fmt.Printf("Stopping after %d set failure(s)\n", nfailSet)
					stopped = true
					goto done
				}
			}
			testStrings = testStrings[:0]
			inStrings = true
			if setsMode {
				setBlockEntries = setBlockEntries[:0]
				setCurrentEntry = nil
			}

		case line == "regexps":
			inStrings = false
			if setsMode {
				setBlockStrings = append([]string(nil), testStrings...)
			}

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
			if setsMode {
				if preCheck(q) == "" {
					setBlockEntries = append(setBlockEntries, setBlockEntry{pattern: q})
					setCurrentEntry = &setBlockEntries[len(setBlockEntries)-1]
				} else {
					setCurrentEntry = nil
				}
				input = append([]string(nil), testStrings...)
				continue // skip single-pattern compilation in sets mode
			}
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

			// Always determine the naturally-selected engine, even under
			// --force-backtrack: it's still needed to decide whether this
			// pattern has genuinely-reachable capture groups (drives the
			// groupsFn/matchFn dispatch below) and for the passed-test engine
			// accounting further down. The actual compiled engine is forced
			// separately, via compileOpts below.
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
			if engineType != compile.EngineDFA && engineType != compile.EngineCompiledDFA && engineType != compile.EngineBacktrack && engineType != compile.EngineTDFA {
				skipCount["requires "+engineType.String()] += len(testStrings)
				input = append([]string(nil), testStrings...)
				continue
			}

			// Compile a single standalone WASM module containing all functions.
			// --groups-only applies only to patterns that actually have captures;
			// other patterns retain the usual match+find setup.
			patternHasCaptures := false
			if groupsOnly {
				if parsed, perr := syntax.Parse(pattern, syntax.Perl); perr == nil && parsed.MaxCap() > 0 {
					patternHasCaptures = true
				}
			}
			re := config.RegexEntry{
				Pattern: pattern,
			}
			if !patternHasCaptures {
				if !findOnly {
					re.MatchFunc = "match"
				}
				if !matchOnly {
					re.FindFunc = "find"
				}
			}
			if patternHasCaptures || engineType == compile.EngineBacktrack || engineType == compile.EngineTDFA {
				re.GroupsFunc = "groups"
			}
			var compileOpts compile.CompileOptions
			var forceGroupsEngine compile.EngineType
			if forceBacktrack {
				// Captures: force the groups engine for real, via
				// CompileForced's forceGroupsEngine parameter (compile.go's
				// compilePattern reads this directly to override
				// selectBestEngine's TDFA-vs-Backtrack choice — no size
				// limits involved).
				forceGroupsEngine = compile.EngineBacktrack
				// Match/find: there is no engine-selection axis to force —
				// compilePattern's needMatch/needFindBody paths are always
				// DFA, with Backtracking only as an overflow fallback when
				// the DFA exceeds MaxDFAStates/MaxDFAMemory. MaxDFAStates: -1
				// is the documented, tested way to make that fallback trigger
				// unconditionally (resolveMaxDFAStates treats negative as 0,
				// so any real DFA "overflows"; see compile_test.go's
				// match_dfa_overflow/find_dfa_overflow cases for the same
				// mechanism in production tests).
				compileOpts.MaxDFAStates = -1
			}
			if likelyMatch {
				compileOpts.LikelyMode = compile.LikelyMatch
			}
			if likelyNoMatch {
				compileOpts.LikelyMode = compile.LikelyNoMatch
			}
			wasmBytes, _, compErr := compile.CompileForced([]config.RegexEntry{re}, tableBase, true, forceGroupsEngine, compileOpts)
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
				groupsIsBacktrack = forceBacktrack || (engineType == compile.EngineBacktrack)
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

			// Collect result line for set mode.
			if setsMode && setCurrentEntry != nil {
				setCurrentEntry.results = append(setCurrentEntry.results, line)
			}

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
			var col4, col5, col6 string
			if len(results) >= 5 {
				col4 = strings.TrimSpace(results[4])
			}
			if len(results) >= 6 {
				col5 = strings.TrimSpace(results[5])
			}
			if len(results) >= 7 {
				col6 = strings.TrimSpace(results[6])
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
				//
				// The oracle must be FULL-CONSUMPTION — \A(?:pat)\z — not a
				// leftmost-first find that is then checked for having spanned
				// the input. Those differ whenever an earlier alternative
				// matches a prefix while a later one would consume everything:
				// `a|ab` on "ab" finds `a`, spans 0-1, and the span check calls
				// it "no match", when the anchored answer is a match at 0-2.
				// That mistake reported 167 false disagreements here, and is
				// the same trap plans/TODO.md task 54 records costing a
				// 2026-08-19 sweep 96 false positives.
				//
				// Wrapping in (?: ) leaves capture-group numbering untouched,
				// so the submatch slots line up with col0's slots as before.
				if validateGroups && col0 != "-" {
					// col0 is produced by TWO different exports, with two
					// different contracts, and the oracle has to match whichever
					// one this row exercises (see the col0 test sites below):
					//
					//   captures  → the groups export: anchored at 0, and NOT
					//               full-consumption; it reports wherever the
					//               match ends.
					//   no captures → the match export: full-consumption.
					//
					// Using one oracle for both is what produced most of the
					// noise here. `(.*?)([0-9]+)` on "x123y" is col0 = 0-4,
					// which a \z oracle calls "no match"; `a|ab` on "ab" is
					// col0 = 0-2, which an un-anchored-end oracle calls 0-1.
					anchor := `\A(?:` + pattern + `)`
					if re.NumSubexp() == 0 {
						anchor += `\z`
					}
					reAnchored, anchErr := regexp.Compile(anchor)
					if anchErr != nil {
						continue
					}
					goSub0 := reAnchored.FindStringSubmatchIndex(text)
					expSlots0 := parseCaptures(col0, re.NumSubexp()+1)
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
				//
				// TODO task 54 step 1: this is a plain whole-input
				// FindAllStringIndex — Go's own answer, and the project's
				// stated oracle.
				//
				// It USED to re-implement the WASM iteration loop instead:
				// FindStringIndex repeatedly over text[off:], advancing by one
				// after an empty match. That oracle carried the two defects the
				// expectations were supposed to catch, so WASM and oracle
				// agreed by being wrong the same way (FABLE T7):
				//
				//   (A) the narrowed slice hides the byte before `off`, so \b,
				//       \B, (?m:^) and (?m:$) are judged against the slice edge;
				//   (B) Go SUPPRESSES an empty match beginning where the
				//       previous match ended, and the hand-rolled loop did not.
				//
				// Every DATA line this now reports names a row whose
				// expectation encodes (A) or (B).
				if col4 != "" && col4 != "-" {
					goAll := re.FindAllStringIndex(text, -1)
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
				// col6 (groups exhaustive re-entry): validate if present.
				// Mirrors the GroupsIter/generator advance-by-matchEnd
				// convention — see tools/likelytest's expectedGroupsAll.
				if col6 != "" && col6 != "-" {
					goAll := expectedGroupsAllGo(re, text)
					expAll := parseCol6(col6, re.NumSubexp()+1)
					if !col6Equal(goAll, expAll) {
						nDataErrors++
						fmt.Printf("DATA  pattern: %q\n      input:   %q\n      col6 expected: %s\n      col6 go:       %s\n",
							pattern, text, fmtCol6(expAll), fmtCol6(goAll))
					}
				}
			}

			if !validateGo {
				// col1: non-anchored find. Tested for every row with a findFn,
				// regardless of col0 — a pattern's anchored match succeeding
				// does not mean find() was ever exercised, and col1 is the
				// correct find oracle either way. Previously gated behind
				// `col0 == "-"`, which left find() completely unchecked for any
				// row whose anchored match also succeeds, hiding real find-mode
				// bugs (e.g. `a$00|^0` and `\b0|` vs "0").
				if findFn == nil {
					skipCount[skipNonAnchored]++
				} else {
					got, callErr := callFind(wd, store, findFn, findMemory, text, 0)
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

				if groupsFn != nil && validateGroups {
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
				} else if matchFn != nil && groupsFn == nil {
					// col0: anchored match (no captures). Skipped for capturing
					// patterns (groupsFn != nil) even when --validate-groups is
					// off: col0 is written for groupsFn's non-full-consumption
					// contract, not matchFn's full-consumption one.
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
					prevEnd := -1
					for offset <= len(text) {
						r, callErr := callFind(wd, store, findFn, findMemory, text, offset)
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
						s := int(r >> 32)
						e := int(uint32(r))
						// Go's FindAllIndex rule: suppress an EMPTY match
						// beginning exactly where the previous reported match
						// ended. This harness re-implements the stub iterator
						// loop rather than driving a stub, so the rule has to
						// live here too — moving the emitters alone would make
						// this loop disagree with them and misattribute the
						// difference to the engine.
						if !(s == e && s == prevEnd) {
							gotAll = append(gotAll, [2]int{s, e})
							prevEnd = e
						}
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

				// col6: groups exhaustive re-entry — repeatedly call groups(),
				// advancing by the reported match's own relative end. This is
				// the shape col5 never exercises (col5 always calls groups()
				// at ptr=0): every generated stub's GroupsIter/generator
				// re-enters at a nonzero ptr after the first match, and a bug
				// in that composition (task 50: the whole-pattern
				// single-capture shortcut left edgeScratchOff at its zero
				// value instead of -1, so the groups wrapper scribbled an
				// (origPtr,origEnd) scratch pair over table-memory offset 0
				// on every call, corrupting the DFA table read by the next
				// find()) is invisible to col0/col5 and only surfaces here.
				if col6 != "" && col6 != "-" && groupsFn != nil {
					expAll := parseCol6(col6, numGroups)
					// Write the full text once; re-entry advances ptr into
					// this same buffer rather than re-copying a substring to
					// address 0 the way callGroups does — see callGroupsAt's
					// doc comment for why that distinction is load-bearing
					// here.
					buf := groupsMemory.UnsafeData(groupsStore)
					copy(buf[inputBase:], text)
					var gotAll [][]int32
					offset := int32(0)
					prevEnd := int32(-1)
					textLen := int32(len(text))
					for offset <= textLen {
						endPos, slots, callErr := callGroupsAt(wd, groupsStore, groupsFn, groupsMemory, inputBase, textLen, offset, numGroups)
						if callErr != nil {
							if isTimeout(callErr) {
								if forceBacktrack {
									groupsStore, groupsFn, groupsMemory = nil, nil, nil
									skipCount[skipTimeout]++
									goto nextResultLine
								}
								return fmt.Errorf("TIMEOUT: groups-exhaust pattern=%q input=%q", pattern, text)
							}
							return fmt.Errorf("%s:%d: wasm groups-exhaust call pattern=%q input=%q: %w",
								testFile, lineno, pattern, text, callErr)
						}
						if endPos < 0 {
							break
						}
						// Slots are absolute already.
						shifted := make([]int32, len(slots))
						copy(shifted, slots)
						// Go's FindAllSubmatchIndex rule, as in the col4 loop
						// above: suppress an EMPTY match beginning exactly
						// where the previous reported match ended.
						absStart, absEnd := shifted[0], shifted[1]
						if !(absStart == absEnd && absStart == prevEnd) {
							gotAll = append(gotAll, shifted)
							prevEnd = absEnd
						}
						if absEnd > absStart {
							offset = absEnd
						} else {
							offset = absStart + 1
						}
					}
					if !col6Equal(gotAll, expAll) {
						nfail++
						fmt.Printf("FAIL  pattern: %q\n      input:   %q\n      col6 expected: %s\n      col6 got:      %s\n",
							pattern, text, fmtCol6(expAll), fmtCol6(gotAll))
						if maxErrors > 0 && nfail >= maxErrors {
							fmt.Printf("Stopping after %d failure(s)\n", nfail)
							stopped = true
							goto done
						}
					} else {
						npass++
						if groupsIsBacktrack {
							npassBacktrack++
						} else {
							npassTDFA++
						}
						if verbose {
							fmt.Printf("PASS %s:%d pattern=%q input=%q (groups-exhaust)\n", testFile, lineno, pattern, text)
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

	// Test the final block (not triggered by a "strings" line).
	if setsMode && !stopped && !inStrings && len(setBlockEntries) >= 2 {
		p, f, setStats, testErr := testSetBlock(setBlockEntries, setBlockStrings, engine, wd, verbose, likelyMatch, likelyNoMatch)
		prevPassSet := npassSet
		npassSet += p
		nfailSet += f
		skipCount[skipTimeout] += setStats.nTimeout
		if testErr != nil {
			return testErr
		}
		if (prevPassSet / 500000) != (npassSet / 500000) {
			fmt.Fprintf(os.Stderr, "  ... %dK set cases\n", npassSet/1000)
		}
		if maxErrors > 0 && nfailSet >= maxErrors {
			fmt.Printf("Stopping after %d set failure(s)\n", nfailSet)
		}
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

	if setsMode {
		fmt.Printf("\n=== Set Mode Results (all driven capabilities) ===\n")
		fmt.Printf("passed:  %d\n", npassSet)
		fmt.Printf("failed:  %d\n", nfailSet)
		setStats.report()
		// nfailSet is already the same total, taken as a delta per block; this
		// makes the exit status independent of that bookkeeping.
		nfailSet = setStats.totalFail()
		nDataErrors += setStats.dataErrs
	}

	if nDataErrors > 0 {
		return fmt.Errorf("%d data error(s) — fix test file expectations", nDataErrors)
	}
	if nfail > 0 {
		return fmt.Errorf("%d test(s) failed", nfail)
	}
	if nfailSet > 0 {
		return fmt.Errorf("%d set test(s) failed", nfailSet)
	}
	return nil
}

// setBlockEntry holds one eligible pattern from a regexps block plus its result lines.
type setBlockEntry struct {
	pattern string
	results []string // one result line per testString
}

const setOutTupleBytes = 12 // (pattern_id i32, start i32, end i32)

// testSetBlockStats carries diagnostic counters from testSetBlock.
type testSetBlockStats struct {
	hasNonGreedy bool // at least one eligible pattern has a non-greedy quantifier
	ran          bool // block compiled and ran (not silently skipped)
	nTimeout     int  // number of test strings where find_all timed out
}

// testSetBlock drives every declared set capability over one corpus block.
//
// The block's eligible patterns are split into chunks (--set-chunk), each
// chunk is compiled once per selected capability profile (--set-profiles), and
// every capability that profile declares is checked against a Go oracle built
// once per chunk. See the header of setcaps.go.
//
// The returned counts are this block's contribution to the run total, taken as
// a delta of setStats so they cover every capability the profiles drove. The
// per-capability breakdown is setStats' own summary table.
func testSetBlock(
	entries []setBlockEntry,
	testStrings []string,
	engine *wasmtime.Engine,
	wd *watchdog,
	verbose bool,
	likelyMatch bool,
	likelyNoMatch bool,
) (npass, nfail int, stats testSetBlockStats, err error) {
	var (
		pats []string
		orig []int
		cols [][]string
	)
	for i, e := range entries {
		if preCheck(e.pattern) != "" {
			continue // skip unicode etc.
		}
		if _, perr := syntax.Parse(e.pattern, syntax.Perl); perr != nil {
			continue // skip unsupported syntax (\C etc.)
		}
		// The oracle is Go's own regexp, so a pattern Go will not compile
		// cannot be given an expectation. syntax.Parse accepting it makes this
		// unreachable in practice; it is here so a future divergence skips the
		// pattern instead of panicking inside the oracle.
		if _, cerr := regexp.Compile(e.pattern); cerr != nil {
			continue
		}
		pats = append(pats, e.pattern)
		orig = append(orig, i)
		cols = append(cols, e.results)
		if strings.Contains(e.pattern, "+?") || strings.Contains(e.pattern, "*?") || strings.Contains(e.pattern, "??") {
			stats.hasNonGreedy = true
		}
	}
	if len(pats) < 2 {
		return // not enough patterns to form a set
	}

	var hints []string
	if likelyMatch {
		hints = []string{"prefer-match"}
	} else if likelyNoMatch {
		hints = []string{"prefer-no-match"}
	}

	profiles := activeSetProfiles
	if len(profiles) == 0 {
		p, _ := lookupSetProfile("all")
		profiles = []setProfile{p}
	}
	var needAnchored, needSPM, needFindAll bool
	for _, p := range profiles {
		a, s, f := p.needs()
		needAnchored = needAnchored || a
		needSPM = needSPM || s
		needFindAll = needFindAll || f
	}
	// The col4 cross-check below needs Go's FindAll even when no selected
	// profile drives a gated find, and it is cheap next to the start-position
	// map. Keeping it on means every run re-validates the corpus column that
	// --sets compared against before §22, rather than quietly dropping it.
	needFindAll = true

	timeoutsBefore := setStats.timeouts
	passBefore, failBefore := setStats.totalPass(), setStats.totalFail()
	for ci, chunk := range setChunksOf(pats, orig, cols) {
		if ci%setSample != 0 {
			setStats.skipped++
			continue
		}
		setStats.chunks++
		orc, oerr := buildSetOracle(chunk.pats, testStrings, needAnchored, needSPM, needFindAll)
		if oerr != nil {
			return npass, nfail, stats, oerr
		}
		crossCheckCol4(chunk, testStrings, orc)
		for _, prof := range profiles {
			if perr := runSetProfile(engine, wd, chunk, testStrings, orc, prof, hints, verbose); perr != nil {
				return npass, nfail, stats, perr
			}
			stats.ran = true
		}
	}
	stats.nTimeout = setStats.timeouts - timeoutsBefore
	npass = setStats.totalPass() - passBefore
	nfail = setStats.totalFail() - failBefore
	return
}

// crossCheckCol4 compares the live Go oracle against the corpus's own col4
// column wherever the corpus has one.
//
// This is §22.4's discipline made mechanical. The pre-§22 --sets run compared
// the engine against col4; this file computes expectations from Go instead. If
// the two ever disagree, one of them is wrong and the run must say so — a
// silent switch of oracle would be exactly the FABLE B42 mistake, where the
// comparison and its oracle were narrowed the same way and agreed while both
// were wrong.
func crossCheckCol4(chunk setChunk, strs []string, orc *setOracle) {
	if orc.findAllByStr == nil {
		return
	}
	for pi := range chunk.pats {
		lines := chunk.cols[pi]
		for si, text := range strs {
			if si >= len(lines) || hasUnicode(text) {
				continue
			}
			c := strings.Split(lines[si], ";")
			if len(c) < 5 {
				continue
			}
			col4 := strings.TrimSpace(c[4])
			if col4 == "" {
				continue
			}
			want := parseCol4(col4)
			got := orc.findAllByStr[pi][si]
			if !col4WasmEqual(got, want) {
				setStats.dataErrs++
				setFailf("DATA  set oracle disagrees with col4: pattern %q input %q\n      col4: %s\n      Go:   %s\n",
					chunk.pats[pi], text, fmtCol4(want), fmtCol4(got))
			}
		}
	}
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
//
// from is where the SEARCH starts; the whole of text is always visible to the
// engine, so a leading \b, \B or (?m:^) at from > 0 is judged against the
// real preceding byte. Positions come back absolute.
func callFind(wd *watchdog, store *wasmtime.Store, fn *wasmtime.Func, mem *wasmtime.Memory, text string, from int) (int64, error) {
	wd.Arm(store)
	defer wd.Disarm()
	if len(text) > 0 {
		buf := mem.UnsafeData(store)
		copy(buf[inputBase:], text)
	}
	result, err := fn.Call(store, inputBase, int32(len(text)), int32(from))
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
	result, err := fn.Call(store, inputBase, int32(len(text)), slotsBase, int32(0))
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

// callGroupsAt invokes the groups function at an explicit (ptr,len) into
// memory the caller has already populated — unlike callGroups, it does NOT
// copy any text to inputBase first. This distinction matters for exhaustive
// re-entry (col6): the real GroupsIter/generator convention every generated
// stub uses (generate/js_stub.go's genJSGroupsFunc, generate/rust_stub.go's
// iterator, etc.) calls groups() at successive nonzero ptr values into the
// SAME underlying buffer — it never re-writes a substring back to address 0
// between calls. callGroups' per-call re-copy makes every call start from a
// pristine buffer, which is exactly what hides an earlier task's bug class
// (a wrapper-composition bug that corrupts memory at address 0 as a side
// effect of one call, only visible on the NEXT call into the same,
// un-rewritten buffer).
// from bounds where the SEARCH starts; ptr/length always describe the whole
// input, so a leading \b, \B or (?m:^) is judged against the real preceding
// byte. Returned slots are absolute.
func callGroupsAt(wd *watchdog, store *wasmtime.Store, fn *wasmtime.Func, mem *wasmtime.Memory, ptr, length, from int32, numGroups int) (int32, []int32, error) {
	buf := mem.UnsafeData(store)
	for i := 0; i < numGroups*2; i++ {
		off := slotsBase + int32(i*4)
		buf[off] = 0xFF
		buf[off+1] = 0xFF
		buf[off+2] = 0xFF
		buf[off+3] = 0xFF
	}
	wd.Arm(store)
	defer wd.Disarm()
	result, err := fn.Call(store, ptr, length, slotsBase, from)
	if err != nil {
		return 0, nil, err
	}
	endPos := result.(int32)
	if endPos < 0 {
		return -1, nil, nil
	}
	buf = mem.UnsafeData(store)
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
		s, err1 := strconv.ParseInt(p[:dash], 10, 32)
		e, err2 := strconv.ParseInt(p[dash+1:], 10, 32)
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
	end, err := strconv.ParseInt(pair[dashIdx+1:], 10, 32)
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
		return "" // let the compiler report the actual error
	}
	return ""
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
// sortSpanPairs orders spans by (start, end) so a multiset comparison can be
// done element-wise: the order of the tuples within one `find` call is
// unspecified by the set ABI.
func sortSpanPairs(v [][2]int) {
	sort.Slice(v, func(i, j int) bool {
		if v[i][0] != v[j][0] {
			return v[i][0] < v[j][0]
		}
		return v[i][1] < v[j][1]
	})
}

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

// parseCol6 parses a col6 string like "0-3 0-3|4-9 4-9" (matches separated by
// "|", each match's per-group spans space-separated like col5) into a slice
// of per-match slot arrays, or nil for "-"/empty.
func parseCol6(col string, numGroups int) [][]int32 {
	if col == "" || col == "-" {
		return nil
	}
	var all [][]int32
	for _, part := range strings.Split(col, "|") {
		all = append(all, parseCaptures(strings.TrimSpace(part), numGroups))
	}
	return all
}

// col6Equal compares two groups-exhaust match sequences — used for both the
// Go-oracle validation (--validate-go) and the WASM-vs-expected check.
func col6Equal(got [][]int32, exp [][]int32) bool {
	if len(got) != len(exp) {
		return false
	}
	for i := range got {
		if len(got[i]) != len(exp[i]) {
			return false
		}
		for j := range got[i] {
			if got[i][j] != exp[i][j] {
				return false
			}
		}
	}
	return true
}

func fmtCol6(all [][]int32) string {
	if all == nil {
		return "no matches"
	}
	var parts []string
	for _, m := range all {
		parts = append(parts, fmtSlots(m))
	}
	return strings.Join(parts, "|")
}

// expectedGroupsAllGo is the Go-stdlib oracle for col6: mirrors the
// GroupsIter/generator advance-by-matchEnd convention (advance by the
// match's own relative end, or off++ if that's zero) rather than Go's
// FindAllStringSubmatchIndex, which skips empty matches adjacent to the
// previous one. Matches tools/likelytest's expectedGroupsAll.
// expectedGroupsAllGo is col6's oracle: Go's own FindAllStringSubmatchIndex
// over the WHOLE input.
//
// TODO task 54 step 1. It used to re-implement the stub iterators' loop over
// text[off:], which made it carry the same two defects as the code it was
// meant to check — see the col4 oracle above for what (A) and (B) are.
func expectedGroupsAllGo(re *regexp.Regexp, text string) [][]int32 {
	subs := re.FindAllStringSubmatchIndex(text, -1)
	all := make([][]int32, 0, len(subs))
	for _, sub := range subs {
		row := make([]int32, len(sub))
		for i, v := range sub {
			if v < 0 {
				row[i] = -1
			} else {
				row[i] = int32(v)
			}
		}
		all = append(all, row)
	}
	return all
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
