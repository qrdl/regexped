// advbench drives one entry point over a generated input at doubling sizes and
// reports fuel, the growth ratio per doubling, calls, matches and memory pages.
//
// Its question is "is this drive linear?": a drive is what a stub does — call
// `find`, `groups`, a set `find` or its batch entry until the input is
// exhausted — and its cost per doubling of the input is ×2 when it is linear
// and ×4 when it is quadratic. Fuel counts WASM instructions, so the ratio is
// exact and independent of machine load.
//
// Two ways to run it:
//
//	advbench -pattern 'a*b|a' -fn find -gen rep:a -sizes 4096,8192,16384
//	advbench -suite [-only SUBSTR] [-list]
//
// The first drives one pattern or one set config. The second runs the row
// table in rows.go: rows expected LINEAR fail the run when their last ratio
// exceeds maxLinearRatio, or a ratio rises past maxRisingRatio; rows expected
// QUADRATIC are known open drives,
// reported with their ratio so a fix shows up as a change in the report;
// REPORT rows (memory, correctness) are printed only.
package main

import (
	"flag"
	"fmt"
	"os"
	"regexp/syntax"
	"strconv"
	"strings"
	"time"

	wasmtime "github.com/bytecodealliance/wasmtime-go/v48"
	"github.com/qrdl/regexped/compile"
	"github.com/qrdl/regexped/config"
	"github.com/qrdl/regexped/internal/abi"
	"github.com/qrdl/regexped/internal/searchblock"
)

var (
	pattern  = flag.String("pattern", "", "single pattern")
	fn       = flag.String("fn", "find", "find|match|groups|batchgroups (single) or find|batch|scan_any|scan_all|match_any|match_all (set)")
	cfgPath  = flag.String("config", "", "YAML config for a set")
	setName  = flag.String("set", "", "set name (default: first)")
	gen      = flag.String("gen", "rep:a", "input generator: segments pre:P, rep:STR, suf:S joined by |, or file:PATH")
	sizes    = flag.String("sizes", "4096,8192,16384", "input sizes, comma-separated")
	cache    = flag.Bool("cache", true, "offer the overlapping answer cache (sets)")
	outCap   = flag.Int("cap", 0, "set find out_cap (0 = pattern count)")
	fuelMax  = flag.Uint64("fuelmax", 20_000_000_000, "fuel budget per size; exceeding it aborts the size")
	timeout  = flag.Duration("timeout", 60*time.Second, "wall timeout per size")
	byteMode = flag.Bool("bytemode", false, "byte_mode")
	drive    = flag.Bool("drive", true, "drive with the stub advance rule (false: one call from 0)")
	forceBT  = flag.Bool("bt", false, "force Backtracking for groups")
	maxDFA   = flag.Int("maxdfa", 0, "MaxDFAStates override")
	ngroups  = flag.Int("ngroups", 1, "groups per batchgroups record, INCLUDING group 0 (record = 8 + 8 × this)")
	dump     = flag.String("dump", "", "write the compiled module to this path")

	noBlock = flag.Bool("noblock", false, "drive without a per-search block (the search global left at 0)")

	suite = flag.Bool("suite", false, "run the row table (rows.go)")
	only  = flag.String("only", "", "with -suite: run only rows whose name contains this")
	list  = flag.Bool("list", false, "with -suite: list the rows and exit")
)

// spec is one drive: what to compile, what to call, over which input.
type spec struct {
	Pattern  string
	Config   string
	Set      string
	Fn       string
	Gen      string
	Sizes    []int
	NoCache  bool
	Cap      int
	MaxDFA   int
	BT       bool
	NGroups  int
	ByteMode bool
	OneCall  bool
	NoBlock  bool
}

// sizeResult is one input size of a drive.
type sizeResult struct {
	N          int
	Fuel       uint64
	Calls      int
	Matches    int
	Sum        uint64
	StartPages uint64
	Pages      uint64
	Wall       time.Duration
	Err        string
	Note       string
	Armed      bool // the search armed (its notes were allocated)
}

func (r sizeResult) fuelPerByte() float64 { return float64(r.Fuel) / float64(max(r.N, 1)) }

// unicodeFlag puts every compile of this run in Unicode mode
// (CompileOptions.Unicode, and a loaded config's `unicode:` keys); without it
// every compile is forced to byte mode (ForceByteMode, `unicode: false`), so
// no run is ever in a mode it did not ask for.
var unicodeFlag = flag.Bool("unicode", false, "compile in Unicode mode (CompileOptions.Unicode); without it, byte mode (ForceByteMode)")

// withMode sets the mode -unicode asks for on o.
func withMode(o compile.CompileOptions) compile.CompileOptions {
	if *unicodeFlag {
		o.Unicode = true
	} else {
		o.ForceByteMode = true
	}
	return o
}

// withConfigMode is withMode for a loaded config, which CompileFile compiles
// without options: it sets the `unicode:` key of every set and every pattern.
func withConfigMode(cfg *config.BuildConfig) {
	u := *unicodeFlag
	for i := range cfg.Sets {
		cfg.Sets[i].Unicode = &u
	}
	for i := range cfg.Regexps {
		cfg.Regexps[i].Unicode = &u
	}
}

func main() {
	flag.Parse()
	if *suite {
		os.Exit(runSuite())
	}
	sp := spec{
		Pattern: *pattern, Config: *cfgPath, Set: *setName, Fn: *fn, Gen: *gen,
		NoCache: !*cache, Cap: *outCap, MaxDFA: *maxDFA, BT: *forceBT,
		NGroups: *ngroups, ByteMode: *byteMode, OneCall: !*drive, NoBlock: *noBlock,
	}
	for _, s := range strings.Split(*sizes, ",") {
		n, err := strconv.Atoi(strings.TrimSpace(s))
		if err != nil {
			fmt.Println("bad size:", s)
			os.Exit(2)
		}
		sp.Sizes = append(sp.Sizes, n)
	}
	res, info, err := runSpec(sp)
	if err != nil {
		fmt.Println(err)
		os.Exit(1)
	}
	fmt.Println(info)
	var prev uint64
	for _, r := range res {
		ratio := ""
		if prev > 0 {
			ratio = fmt.Sprintf("x%.2f", float64(r.Fuel)/float64(prev))
		}
		prev = r.Fuel
		armed := ""
		if r.Armed {
			armed = " armed"
		}
		fmt.Printf("n=%-8d fuel=%-14d %-7s fuel/byte=%-10.2f calls=%-7d matches=%-8d sum=%016x pages=%d(+%d) wall=%v%s%s%s\n",
			r.N, r.Fuel, ratio, r.fuelPerByte(), r.Calls, r.Matches, r.Sum, r.Pages, r.Pages-r.StartPages,
			r.Wall.Round(time.Millisecond), armed, r.Note, r.Err)
	}
}

func genInput(spec string, n int) ([]byte, error) {
	if strings.HasPrefix(spec, "file:") {
		b, err := os.ReadFile(spec[5:])
		if err != nil {
			return nil, err
		}
		if len(b) > n {
			b = b[:n]
		}
		return b, nil
	}
	var pre, rep, suf string
	for _, seg := range strings.Split(spec, "|") {
		switch {
		case strings.HasPrefix(seg, "pre:"):
			pre = unescape(seg[4:])
		case strings.HasPrefix(seg, "rep:"):
			rep = unescape(seg[4:])
		case strings.HasPrefix(seg, "suf:"):
			suf = unescape(seg[4:])
		default:
			return nil, fmt.Errorf("bad generator segment %q", seg)
		}
	}
	body := max(n-len(pre)-len(suf), 0)
	var sb strings.Builder
	sb.WriteString(pre)
	for rep != "" && sb.Len() < len(pre)+body {
		sb.WriteString(rep)
	}
	s := sb.String()
	if len(s) > len(pre)+body {
		s = s[:len(pre)+body]
	}
	return []byte(s + suf), nil
}

func unescape(s string) string {
	s = strings.ReplaceAll(s, `\n`, "\n")
	s = strings.ReplaceAll(s, `\t`, "\t")
	s = strings.ReplaceAll(s, `\s`, " ")
	s = strings.ReplaceAll(s, `\p`, "|")
	return s
}

// Single patterns: input at 0, tables at 8 MiB, so an input may not exceed
// 8 MiB minus the scratch the drive places after it.
const tableBase = int64(8 << 20)

// runSpec compiles sp once and drives it at every size on a fresh instance.
func runSpec(sp spec) ([]sizeResult, string, error) {
	var wasmBytes []byte
	var top int64
	var err error
	var cfg config.BuildConfig
	var sizes map[string]compile.SearchSize
	isSet := sp.Config != ""
	var sc config.SetConfig
	if isSet {
		cfg, err = config.LoadConfig(sp.Config)
		if err != nil {
			return nil, "", fmt.Errorf("load: %w", err)
		}
		withConfigMode(&cfg)
		found := false
		for _, s := range cfg.Sets {
			if sp.Set == "" || s.Name == sp.Set {
				sc, found = s, true
				break
			}
		}
		if !found {
			return nil, "", fmt.Errorf("no set %q in %s", sp.Set, sp.Config)
		}
		wasmBytes, top, err = compile.CompileFile(cfg, "")
		if err == nil {
			sizes, err = compile.SearchSizes(cfg)
		}
	} else {
		e := config.RegexEntry{Pattern: sp.Pattern, ByteMode: sp.ByteMode}
		switch sp.Fn {
		case "find":
			e.FindFunc = "find"
		case "match":
			e.MatchFunc = "match"
		case "groups", "batchgroups":
			e.GroupsFunc = "groups"
		default:
			return nil, "", fmt.Errorf("bad -fn %q for a single pattern", sp.Fn)
		}
		if sp.Fn == "batchgroups" {
			e.Hints = []string{"batch-find"}
		}
		opts := withMode(compile.CompileOptions{MaxDFAStates: sp.MaxDFA})
		var force compile.EngineType
		if sp.BT {
			force = compile.EngineBacktrack
		}
		wasmBytes, top, sizes, err = compile.CompileWithSearchSizes([]config.RegexEntry{e}, tableBase, true, force, opts)
	}
	if err != nil {
		return nil, "", fmt.Errorf("compile: %w", err)
	}
	if *dump != "" {
		_ = os.WriteFile(*dump, wasmBytes, 0o644)
	}
	info := fmt.Sprintf("module %d bytes, tables top %d", len(wasmBytes), top)

	wcfg := wasmtime.NewConfig()
	wcfg.SetConsumeFuel(true)
	wcfg.SetWasmSIMD(true)
	wcfg.SetEpochInterruption(true)
	engine := wasmtime.NewEngineWithConfig(wcfg)
	mod, err := wasmtime.NewModule(engine, wasmBytes)
	if err != nil {
		return nil, "", fmt.Errorf("module: %w", err)
	}
	var out []sizeResult
	for _, n := range sp.Sizes {
		input, err := genInput(sp.Gen, n)
		if err != nil {
			return nil, "", err
		}
		if !isSet && int64(len(input))+(1<<20) > tableBase {
			return nil, "", fmt.Errorf("input of %d bytes does not fit below the tables", len(input))
		}
		r, err := driveOnce(engine, mod, sp, isSet, cfg, sc, top, input, sizes)
		if err != nil {
			return nil, "", err
		}
		r.N = len(input) // what was driven: file: may be shorter, pre:/suf: longer
		out = append(out, r)
		if r.Err != "" {
			break // a size that ran out of fuel or time: larger ones will too
		}
	}
	return out, info, nil
}

func driveOnce(engine *wasmtime.Engine, mod *wasmtime.Module, sp spec, isSet bool,
	cfg config.BuildConfig, sc config.SetConfig, top int64, input []byte, sizes map[string]compile.SearchSize) (sizeResult, error) {
	var r sizeResult
	store := wasmtime.NewStore(engine)
	defer store.Close()
	if err := store.SetFuel(*fuelMax); err != nil {
		return r, err
	}
	store.SetEpochDeadline(1)
	inst, err := wasmtime.NewInstance(store, mod, nil)
	if err != nil {
		return r, fmt.Errorf("instance: %w", err)
	}
	mem := inst.GetExport(store, "memory").Memory()
	r.StartPages = mem.Size(store)
	var inBase int64
	if isSet {
		inBase = pageAlign(top)
	}
	idSpace := len(cfg.Regexps)
	capN := sp.Cap
	if capN == 0 {
		capN = idSpace
	}
	// The output area holds whatever a call may write: a set `find` asked
	// for more than capN is retried with that many, at most one tuple per
	// pattern, so the area is sized for the larger of the two.
	outRoom := int64(max(capN, idSpace)) * abi.SetMatchTupleBytes
	useCache := isSet && !sp.NoCache && sc.Overlapping
	extra := int64(1 << 20)
	var cacheBytes, cacheStride int
	if useCache {
		if b, stride, err := compile.SetOverlapCacheSizing(sc, cfg, len(input)); err == nil && b > 0 {
			cacheBytes, cacheStride = b, stride
			extra += int64(b) + int64(idSpace)*16
		}
	}
	need := inBase + int64(len(input)) + extra + outRoom + 16
	for int64(mem.DataSize(store)) < need {
		if _, err := mem.Grow(store, uint64((need-int64(mem.DataSize(store)))/65536+1)); err != nil {
			return r, fmt.Errorf("grow: %w", err)
		}
	}
	buf := mem.UnsafeData(store)
	copy(buf[inBase:], input)
	scratchTop := (inBase + int64(len(input)) + 15) &^ 15

	// A set's find takes a scratch descriptor: magic, gate array, answer cache.
	var scratchPtr, outPtr, cachePtr int64
	// A set's split members keep a search block each, behind the gate array.
	var setBlocks []compile.SearchSize
	var blocksPtr int64
	if isSet && !sp.NoBlock {
		setBlocks = sizes[sc.Find].Blocks
	}
	if isSet {
		scratchPtr = scratchTop
		gatePtr := scratchPtr + abi.FindScratchBytes
		if len(setBlocks) > 0 {
			gatePtr = scratchPtr + abi.FindScratchBlocksBytes
		}
		outPtr = gatePtr + int64(idSpace*4+16)
		if len(setBlocks) > 0 {
			blocksPtr = (outPtr + abi.SearchBlockAlign - 1) &^ (abi.SearchBlockAlign - 1)
			outPtr = blocksPtr + int64(len(setBlocks)*abi.SearchBlockBytes) + 16
			clear(buf[gatePtr:outPtr])
		}
		cachePtr = outPtr + outRoom + 16
		if cacheBytes > 0 {
			clear(buf[cachePtr : cachePtr+config.SetOverlapCheckpointHeaderBytes])
			putU32(buf, cachePtr+config.SetOverlapHdrStrideOff, uint32(cacheStride))
		}
		scratchTop = cachePtr + int64(cacheBytes) + 16
		// The cache fields name a region only when one is offered: a non-zero
		// pointer with no region is a cache the sweep refuses, not a drive
		// with none (which routes to the no-cache companion).
		offered := int32(0)
		if cacheBytes > 0 {
			offered = int32(cachePtr)
		}
		abi.WriteFindScratch(buf, int32(scratchPtr), int32(gatePtr), offered, int32(cacheBytes))
		if len(setBlocks) > 0 {
			abi.WriteFindScratchBlocks(buf, int32(scratchPtr), int32(gatePtr), offered, int32(cacheBytes),
				int32(blocksPtr), int32(len(setBlocks)))
		}
	} else {
		outPtr = scratchTop
		scratchTop += 256*(8+8*int64(max(sp.NGroups, 1))) + 4096
	}
	// The per-search block, as a generated stub keeps one per iterator,
	// through the shared helper (internal/searchblock): zeroed here, handed
	// over before every call, notes allocated when it arms and a memo when its
	// Backtracking budget trips — at the end of memory, with the scratch base
	// raised above them, as a host that owns everything above the tables must.
	var blk int64
	searchG := inst.GetExport(store, abi.SearchExport)
	var sz compile.SearchSize
	if !isSet {
		sz = sizes[map[bool]string{true: "groups", false: "find"}[sp.Fn == "groups" || sp.Fn == "batchgroups"]]
	}
	useBlock := !sp.NoBlock && searchG != nil && searchG.Global() != nil && sz.Block()
	if useBlock {
		blk = (scratchTop + abi.SearchBlockAlign - 1) &^ (abi.SearchBlockAlign - 1)
		scratchTop = blk + abi.SearchBlockBytes
	}
	scratchTop = pageAlign(scratchTop)
	scratchG := inst.GetExport(store, abi.ScratchBaseExport)
	setScratch := func(v int64) error {
		if scratchG != nil && scratchG.Global() != nil {
			return scratchG.Global().Set(store, wasmtime.ValI32(int32(v)))
		}
		return nil
	}
	if err := setScratch(scratchTop); err != nil {
		return r, err
	}
	grow := func(n int64) (int32, error) {
		at := pageAlign(int64(mem.DataSize(store)))
		if _, err := mem.Grow(store, uint64((n+65535)/65536)); err != nil {
			return 0, fmt.Errorf("grow block region: %w", err)
		}
		r.Armed = true
		return int32(at), setScratch(pageAlign(at + n))
	}
	var blocks *searchblock.Blocks
	switch {
	case useBlock:
		blocks = &searchblock.Blocks{At: int32(blk), Sizes: searchblock.Of(sz), Mode: searchblock.Fresh, Alloc: grow}
	case len(setBlocks) > 0:
		blocks = &searchblock.Blocks{At: int32(blocksPtr), Sizes: searchblock.Of(compile.SearchSize{Blocks: setBlocks}),
			Mode: searchblock.Fresh, Alloc: grow}
	}
	data := func() []byte { return mem.UnsafeData(store) }
	begin := blocks.Begin
	if sp.Fn == "batch" || sp.Fn == "batchgroups" {
		// A batching iterator's blocks get their notes up front.
		begin = blocks.BeginBatch
	}
	if err := begin(data, len(input)); err != nil {
		return r, err
	}
	beforeCall := func() {
		if useBlock {
			_ = searchG.Global().Set(store, wasmtime.ValI32(int32(blk)))
		}
	}
	afterCall := func() error { return blocks.After(data) }

	var name string
	if isSet {
		switch sp.Fn {
		case "find":
			name = sc.Find
		case "batch":
			name = config.SetBatchExportName(sc.Find)
		case "scan_any":
			name = sc.ScanAny
		case "scan_all":
			name = sc.ScanAll
		case "match_any":
			name = sc.MatchAny
		case "match_all":
			name = sc.MatchAll
		}
	} else {
		name = sp.Fn
		if name == "batchgroups" {
			name = "groups_batch"
		}
	}
	f := inst.GetFunc(store, name)
	if f == nil {
		return r, fmt.Errorf("no export %q", name)
	}

	sum := uint64(14695981039346656037)
	mix := func(v uint32) {
		for i := 0; i < 4; i++ {
			sum ^= uint64(byte(v >> (8 * i)))
			sum *= 1099511628211
		}
	}
	before, _ := store.GetFuel()
	t0 := time.Now()
	deadline := time.AfterFunc(*timeout, func() { engine.IncrementEpoch() })
	var callErr error
	L := int32(len(input))
	ib := int32(inBase)
	advance := func(s, e int32) int32 {
		if e > s {
			return e
		}
		return s + 1
	}
	switch {
	case !isSet && sp.Fn == "match":
		res, e := f.Call(store, ib, L)
		r.Calls++
		callErr = e
		if e == nil && res.(int32) >= 0 {
			r.Matches++
		}
	case !isSet && sp.Fn == "find":
		for from := int32(0); from <= L; {
			beforeCall()
			res, e := f.Call(store, ib, L, from)
			r.Calls++
			if e != nil {
				callErr = e
				break
			}
			v := res.(int64)
			if v < 0 {
				if v != -1 {
					r.Err = fmt.Sprintf(" BAD: ret %d", v)
				}
				break
			}
			if e := afterCall(); e != nil {
				callErr = e
				break
			}
			r.Matches++
			s, en := int32(uint32(v>>32)), int32(uint32(v))
			mix(uint32(s))
			mix(uint32(en))
			if sp.OneCall {
				break
			}
			from = advance(s, en)
		}
	case !isSet && sp.Fn == "groups":
		nGroups := 1 // the slots the export writes: group 0 and every capture
		if re, err := syntax.Parse(sp.Pattern, syntax.Perl); err == nil {
			nGroups = re.MaxCap() + 1
		}
		for from := int32(0); from <= L; {
			beforeCall()
			res, e := f.Call(store, ib, L, int32(outPtr), from)
			r.Calls++
			if e != nil {
				callErr = e
				break
			}
			v := res.(int32)
			if v < 0 {
				if v != -1 {
					r.Err = fmt.Sprintf(" BAD: ret %d", v)
				}
				break
			}
			if e := afterCall(); e != nil {
				callErr = e
				break
			}
			r.Matches++
			buf = mem.UnsafeData(store)
			s, en := int32(getU32(buf, outPtr)), int32(getU32(buf, outPtr+4))
			for k := int64(0); k < 2*int64(nGroups); k++ { // every slot
				mix(getU32(buf, outPtr+4*k))
			}
			if sp.OneCall {
				break
			}
			from = advance(s, en)
		}
	case !isSet && sp.Fn == "batchgroups":
		// (ptr, len, out_ptr, out_cap, start_pos) -> count; records of 8+8*G bytes
		recSize := int64(8 + 8*max(sp.NGroups, 1))
		for pos := int32(0); pos <= L; {
			beforeCall()
			res, e := f.Call(store, ib, L, int32(outPtr), int32(256), pos)
			r.Calls++
			if e != nil {
				callErr = e
				break
			}
			v := res.(int32)
			if v < 0 {
				r.Err = fmt.Sprintf(" BAD: ret %d", v)
				break
			}
			if v == 0 {
				break
			}
			if e := afterCall(); e != nil {
				callErr = e
				break
			}
			r.Matches += int(v)
			buf = mem.UnsafeData(store)
			for k := int64(0); k < int64(v)*recSize; k += 4 { // every record, every slot
				mix(getU32(buf, outPtr+k))
			}
			last := outPtr + int64(v-1)*recSize
			s, en := int32(getU32(buf, last)), int32(getU32(buf, last+4))
			pos = advance(s, en)
		}
	case isSet && sp.Fn == "find":
		for from := int32(0); from <= L; {
			res, e := f.Call(store, ib, L, from, int32(scratchPtr), int32(outPtr), int32(capN))
			r.Calls++
			if e != nil {
				callErr = e
				break
			}
			if e := afterCall(); e != nil {
				callErr = e
				break
			}
			v := res.(int32)
			if v <= 0 {
				if v != 0 {
					r.Err = fmt.Sprintf(" BAD: ret %d", v)
				}
				break
			}
			if int(v) > capN {
				// the transactional overflow rule: nothing was written, retry bigger
				capN = int(v)
				continue
			}
			r.Matches += int(v)
			buf = mem.UnsafeData(store)
			s := int32(getU32(buf, outPtr+4))
			// order-independent within one call: tuples are (id, start, end)
			var callSum uint64
			for i := int64(0); i < int64(v); i++ {
				h := uint64(14695981039346656037)
				for k := int64(0); k < 12; k++ {
					h ^= uint64(buf[outPtr+i*12+k])
					h *= 1099511628211
				}
				callSum += h
			}
			mix(uint32(callSum))
			mix(uint32(callSum >> 32))
			if sp.OneCall {
				break
			}
			from = s + 1
		}
	case isSet && sp.Fn == "batch":
		kBits := 0
		for (1 << kBits) <= idSpace {
			kBits++
		}
		cursor := int64(0)
		for {
			res, e := f.Call(store, ib, L, cursor, int32(scratchPtr), int32(outPtr), int32(capN))
			r.Calls++
			if e != nil {
				callErr = e
				break
			}
			if e := afterCall(); e != nil {
				callErr = e
				break
			}
			v := res.(int64)
			pos := uint32(v >> 32)
			if pos >= 0xFFFFFFFC && pos != 0xFFFFFFFF {
				r.Err = fmt.Sprintf(" BAD: pos word %x", pos)
				break
			}
			cnt := uint32(v) & ((1 << (32 - kBits)) - 1)
			r.Matches += int(cnt)
			mix(uint32(v))
			mix(pos)
			// Every tuple written, order-independent within the call, as the
			// find case hashes them.
			buf = mem.UnsafeData(store)
			var callSum uint64
			for i := int64(0); i < int64(cnt) && i < int64(capN); i++ {
				h := uint64(14695981039346656037)
				for k := int64(0); k < abi.SetMatchTupleBytes; k++ {
					h ^= uint64(buf[outPtr+i*abi.SetMatchTupleBytes+k])
					h *= 1099511628211
				}
				callSum += h
			}
			mix(uint32(callSum))
			mix(uint32(callSum >> 32))
			if pos == 0xFFFFFFFF {
				break
			}
			cursor = v
		}
	case isSet && (sp.Fn == "scan_any" || sp.Fn == "scan_all"):
		var res interface{}
		var e error
		if len(f.Type(store).Params()) == 4 {
			res, e = f.Call(store, ib, L, int32(0), int32(outPtr))
		} else {
			res, e = f.Call(store, ib, L, int32(0))
		}
		r.Calls++
		callErr = e
		if e == nil {
			switch v := res.(type) {
			case int32:
				mix(uint32(v))
			case int64:
				mix(uint32(v))
				mix(uint32(v >> 32))
			}
		}
	case isSet && (sp.Fn == "match_any" || sp.Fn == "match_all"):
		var e error
		// The wide `_all` form takes the bitmap pointer: read it off the
		// export's type, since a Backtracking member selects it at any width.
		if len(f.Type(store).Params()) == 3 {
			_, e = f.Call(store, ib, L, int32(outPtr))
		} else {
			_, e = f.Call(store, ib, L)
		}
		r.Calls++
		callErr = e
	default:
		deadline.Stop()
		return r, fmt.Errorf("bad -fn %q", sp.Fn)
	}
	deadline.Stop()
	after, _ := store.GetFuel()
	r.Fuel = before - after
	r.Wall = time.Since(t0)
	r.Sum = sum
	r.Pages = mem.Size(store)
	if callErr != nil {
		r.Err += " ERR: " + strings.ReplaceAll(callErr.Error(), "\n", " | ")
	}
	if cacheBytes > 0 {
		buf = mem.UnsafeData(store)
		r.Note = fmt.Sprintf(" cache=%dB ready=%d", cacheBytes, int32(getU32(buf, cachePtr+config.SetOverlapHdrReadyOff)))
	}
	return r, nil
}

func pageAlign(x int64) int64 { return (x + 65535) &^ 65535 }

func putU32(b []byte, at int64, v uint32) {
	b[at], b[at+1], b[at+2], b[at+3] = byte(v), byte(v>>8), byte(v>>16), byte(v>>24)
}

func getU32(b []byte, at int64) uint32 {
	return uint32(b[at]) | uint32(b[at+1])<<8 | uint32(b[at+2])<<16 | uint32(b[at+3])<<24
}
