package fuzz

import (
	"encoding/binary"
	"fmt"
	"regexp"
	"strings"
	"testing"

	wasmtime "github.com/bytecodealliance/wasmtime-go/v48"
	"github.com/qrdl/regexped/compile"
	"github.com/qrdl/regexped/config"
	"github.com/qrdl/regexped/internal/abi"
	"github.com/qrdl/regexped/internal/utils"
)

// ---------------------------------------------------------------------------
// Regression: the no-capture Backtracking FIND body must cost time LINEAR in
// input length, not quadratic.
//
// The BitState memo is a bitset of N*(len+1) bits, sized from the whole input.
// Until 2026-09-06 it was re-zeroed with one memory.fill at the head of every
// ATTEMPT — every candidate start position the find loop tries — which makes
// the search O(N*len^2). wasmtime charges memory.fill about 1 fuel per byte, so
// the memset alone dominated everything else the engine did:
//
//	len          64      128      256      512     1024     2048     4096
//	per-attempt x---    x3.86    x3.93    x3.96    x3.98    x3.99    x4.00
//	per-call    x---    x1.98    x1.99    x1.99    x2.00    x2.00    x2.00
//
// x4.00 per doubling is quadratic. At 4,096 bytes that was 1,796,155,500 fuel
// against 1,696,356 — a factor of 1,059, growing with length.
//
// The fix hoists the fill to once per CALL. It is sound in this body and only
// this body: it tracks no captures, so its entire NFA state is (pc, pos), and a
// pair marked during a failed attempt has no accepting continuation regardless
// of which start position reached it. The CAPTURE body keeps its per-attempt
// fill — its state includes the capture registers, so the same (pc, pos) can
// carry a different answer.
//
// This test pins the COMPLEXITY rather than any fuel number, so it keeps
// working when the constants move: re-introducing a per-attempt fill sends the
// growth ratio back to ~4 and fails it, while ordinary tuning does not.

// TestBTFindMemoIsLinearInInputLength doubles the input and requires the fuel
// to roughly double with it.
func TestBTFindMemoIsLinearInInputLength(t *testing.T) {
	cfg := wasmtime.NewConfig()
	cfg.SetConsumeFuel(true)
	cfg.SetWasmSIMD(true)
	engine := wasmtime.NewEngineWithConfig(cfg)

	// Needs all three: a non-greedy loop with an empty-matchable body (so
	// needsBitState fires), a DFA squeezed past its limit (so the pattern
	// reaches Backtracking for find at all), and a no-match input (so every
	// start position is attempted).
	entry := config.RegexEntry{Pattern: `(?:a?)+?xyz`, FindFunc: "find"}
	opts := compile.CompileOptions{MaxDFAStates: 1}
	w, _, err := compile.Compile([]config.RegexEntry{entry}, pathsTableBase, true, opts)
	if err != nil {
		t.Fatalf("compile: %v", err)
	}
	mod, err := wasmtime.NewModule(engine, w)
	if err != nil {
		t.Fatalf("module: %v", err)
	}
	defer mod.Close()

	fuelAt := func(n int) uint64 {
		store := wasmtime.NewStore(engine)
		defer store.Close()
		if err := store.SetFuel(1 << 62); err != nil {
			t.Fatal(err)
		}
		inst, err := wasmtime.NewInstance(store, mod, []wasmtime.AsExtern{})
		if err != nil {
			t.Fatal(err)
		}
		mem := inst.GetExport(store, "memory").Memory()
		copy(mem.UnsafeData(store)[pathsInputBase:], strings.Repeat("a", n))
		fn := inst.GetFunc(store, "find")
		before, _ := store.GetFuel()
		if _, err := fn.Call(store, pathsInputBase, int32(n), int32(0)); err != nil {
			t.Fatalf("len=%d: %v", n, err)
		}
		after, _ := store.GetFuel()
		return before - after
	}

	// 3.0 sits well clear of both regimes — linear measures ~2.00, the
	// quadratic form measured 3.86 at the first doubling and rose from there.
	const maxRatio = 3.0

	var prev uint64
	var report strings.Builder
	for _, n := range []int{256, 512, 1024, 2048, 4096} {
		f := fuelAt(n)
		if prev > 0 {
			r := float64(f) / float64(prev)
			fmt.Fprintf(&report, "  len=%-6d fuel=%-12d x%.2f vs half\n", n, f, r)
			if r > maxRatio {
				t.Errorf("fuel grew x%.2f from len=%d to len=%d, want <= x%.1f "+
					"— the BitState memo fill looks per-attempt again, which makes "+
					"this search quadratic\n%s", r, n/2, n, maxRatio, report.String())
			}
		}
		prev = f
	}
	t.Logf("growth per doubling:\n%s", report.String())
}

// ---------------------------------------------------------------------------
// The same property for a SET's Backtracking bucket, which the hoist above
// does NOT cover.
//
// A set BT bucket is a suffix function called once per CANDIDATE position, and
// each call ran one memory.fill over the whole remaining window — so the drive
// was O(N*len^2) with the memset again the entire quadratic term. Measured on
// the case below, before the position-major memo layout and its lazy clear:
//
//	len          256      512     1024     2048     4096     8192    16384    32768
//	per-call   x---    x2.27    x2.47    x2.75    x3.09    x3.41    x3.65    x3.81
//	lazy       x---    x2.01    x2.00    x2.00    x2.00    x2.00    x2.00    x2.00
//
// 247,139,555 fuel against 12,483,789 at 32 KB — a factor of 19.8, growing
// with length. Neutralising the fill entirely measured 12,238,053, so what
// remains of the clear is 2.0% rather than 95% of the call.
//
// The fix is not the find body's hoist: this memo is the ORDINARY body's
// compile-time region, shared by every member, and its marks are not carried
// across candidate calls. Instead the memo is indexed POSITION-major, which
// makes the bytes one attempt dirties a contiguous run from the base, and each
// call clears exactly the run the previous call recorded in the memo header
// word. (A member's FALLBACK body does carry its marks across candidates, per
// host call — TestSetBTHostCallIsLinear.)
func TestSetBTMemoIsLinearInInputLength(t *testing.T) {
	// Needs all of: a member forced onto BT (max_fallback_states = 1), a
	// non-greedy loop with an empty-matchable body (needsBitState), a rare
	// leading byte so most positions are candidates that FAIL fast, and a
	// match at the very end so the drive scans the whole input.
	cfg := config.BuildConfig{
		Regexps: []config.RegexEntry{{Name: "p0", Pattern: `q(?:a?)+?z`}},
		Sets: []config.SetConfig{{
			Name: "s", Find: "set_find",
			Patterns: config.PatternSelector{Names: []string{"p0"}},
		}},
		MaxFallbackStates: 1,
	}
	w, _, diags, err := compile.CompileFileDiag(cfg, "")
	if err != nil {
		t.Fatalf("compile: %v", err)
	}
	if d := droppedFromSet(diags); len(d) > 0 {
		t.Fatalf("the pattern was dropped from the set: %v", d)
	}

	wcfg := wasmtime.NewConfig()
	wcfg.SetConsumeFuel(true)
	wcfg.SetWasmSIMD(true)
	eng := wasmtime.NewEngineWithConfig(wcfg)
	mod, err := wasmtime.NewModule(eng, w)
	if err != nil {
		t.Fatalf("module: %v", err)
	}
	defer mod.Close()

	const pageSize = 65536
	dataTop, dtErr := utils.ParseDataSectionBytes(w)
	if dtErr != nil {
		t.Fatalf("parse data section: %v", dtErr)
	}
	inBase := int32((dataTop + pageSize - 1) / pageSize * pageSize)

	fuelAt := func(n int) uint64 {
		store := wasmtime.NewStore(eng)
		defer store.Close()
		if err := store.SetFuel(1 << 62); err != nil {
			t.Fatal(err)
		}
		inst, err := wasmtime.NewInstance(store, mod, []wasmtime.AsExtern{})
		if err != nil {
			t.Fatal(err)
		}
		mem := inst.GetExport(store, "memory").Memory()
		inputSpan := int32((n + pageSize - 1) / pageSize * pageSize)
		gateBase := inBase + inputSpan
		outBase := gateBase + pageSize
		need := uint64((int64(outBase) + pageSize + pageSize - 1) / pageSize)
		if cur := mem.Size(store); need > cur {
			if _, gErr := mem.Grow(store, need-cur); gErr != nil {
				t.Fatal(gErr)
			}
		}
		in := strings.Repeat("qa", n/2-2) + "qaz"
		for len(in) < n {
			in = "a" + in
		}
		copy(mem.UnsafeData(store)[inBase:], in[:n])
		fn := inst.GetFunc(store, "set_find")
		before, _ := store.GetFuel()
		scratchBase := gateBase + 64
		abi.WriteFindScratch(mem.UnsafeData(store), scratchBase, gateBase, 0, 0)
		res, callErr := fn.Call(store, inBase, int32(n), int32(0), scratchBase, outBase, int32(1))
		if callErr != nil {
			t.Fatalf("len=%d: %v", n, callErr)
		}
		if got := res.(int32); got != 1 {
			t.Fatalf("len=%d: set_find returned %d, want 1 tuple — the drive is not "+
				"scanning the whole input and the growth curve means nothing", n, got)
		}
		after, _ := store.GetFuel()
		return before - after
	}

	const maxRatio = 3.0

	var prev uint64
	var report strings.Builder
	for _, n := range []int{2048, 4096, 8192, 16384, 32768} {
		f := fuelAt(n)
		if prev > 0 {
			r := float64(f) / float64(prev)
			fmt.Fprintf(&report, "  len=%-6d fuel=%-12d x%.2f vs half\n", n, f, r)
			if r > maxRatio {
				t.Errorf("fuel grew x%.2f from len=%d to len=%d, want <= x%.1f "+
					"— the set BT bucket's memo clear looks input-sized again, which "+
					"makes this drive quadratic\n%s", r, n/2, n, maxRatio, report.String())
			}
		}
		prev = f
	}
	t.Logf("growth per doubling:\n%s", report.String())
}

// TestBTZeroWidthCycleProgramsMatchGo is the regression for a Backtracking
// ORDINARY body that was wrong on a whole class of programs: those with a cycle
// that consumes no byte. `(a*?)*?b` over "aab" reported group 1 as [1,2) where
// Go reports [0,2) — the outer loop's zero-width iteration re-entered the inner
// star's alternation at position 1 and pushed a second retry frame above the
// first, which Go's visited set drops. A differential found the ordinary body
// wrong on 306 of 3,072 systematic nestings and 159 of 12,000 random nested
// patterns, every one with such a cycle. Such programs now run the memoised
// fallback body alone (compile's planBT); these shapes, drawn from both
// differentials, must agree with Go in every slot.
//
// The control proves the shapes still reach the class: the ordinary body alone
// (BTWorkBudgetOff) must be wrong on at least one of them.
func TestBTZeroWidthCycleProgramsMatchGo(t *testing.T) {
	shapes := []string{
		`(a*?)*?b`,
		`(?:(a*?)?)+?b`,
		`(?:((a|b)*?)+?)+?ab`,
		`(?:((a*?|b))*)+?$`,
		`(?:(a*?|b))*(b*)b`,
		`(?:((b|(?m:^)){2}|b|a)*)ab`,
		`((($|\B)+?)|b(?:)*?)*b`,
		`(?:(\b|ab)?|(\b|(a){1,}?)+?)*b`,
		`((?:(a)*?|(a)+)+|([ab]b|(b|$)+))+b`,
	}
	var inputs []string
	for n := 0; n <= 5; n++ {
		for bits := 0; bits < 1<<n; bits++ {
			var b strings.Builder
			for i := 0; i < n; i++ {
				b.WriteByte("ab"[bits>>i&1])
			}
			inputs = append(inputs, b.String())
		}
	}

	ordinaryWrong := 0
	for _, pat := range shapes {
		if cyc, err := compile.BacktrackHasZeroWidthCycle(pat); err != nil || !cyc {
			t.Fatalf("%s: BacktrackHasZeroWidthCycle = %v, %v — the shape no longer has the cycle this test is about", pat, cyc, err)
		}
		re := regexp.MustCompile(pat)
		numGroups := re.NumSubexp() + 1
		shipped, err := compileGroupsBudget(pat, 0)
		if err != nil {
			t.Fatalf("%s: compile: %v", pat, err)
		}
		ordinary, err := compileGroupsBudget(pat, compile.BTWorkBudgetOff)
		if err != nil {
			t.Fatalf("%s: compile with the budget off: %v", pat, err)
		}
		cases := inputs
		if pat == `(a*?)*?b` {
			cases = append(cases, strings.Repeat("a", 9000)+"b")
		}
		for _, in := range cases {
			want := re.FindStringSubmatchIndex(in)
			got, ok, hang, err := runWasmGroupsPath(shipped, in, numGroups)
			if err != nil || hang {
				t.Fatalf("%s over %q: err=%v hang=%v", pat, in, err, hang)
			}
			if msg := compareSlots(want, got, ok); msg != "" {
				t.Errorf("%s over %q (%s): got %v, want %v", pat, in, msg, got, want)
			}
			if got, ok, hang, err := runWasmGroupsPath(ordinary, in, numGroups); err == nil && !hang && compareSlots(want, got, ok) != "" {
				ordinaryWrong++
			}
		}
	}
	if ordinaryWrong == 0 {
		t.Errorf("the ordinary body alone answered every case correctly — these shapes no longer exercise the class the routing exists for")
	}
	t.Logf("the ordinary body alone was wrong on %d cases the shipped build answers correctly", ordinaryWrong)
}

// exportBTDriveMember returns a copy of a set module with the first
// Backtracking member's call-scoped globals exported (compile/bt_scratch.go,
// btDrive / btDriveMember), so a test can see where the member's memo went.
//
// Found by structure, not by a fixed index: the call epoch is the one i64
// global initialised to 1, the set's scratch top follows its scratch epoch, and
// the first member's seven globals follow that — i64 ×3, then i32 memo base,
// origin, end and watermark. A module whose globals do not have that shape
// fails the test rather than exporting the wrong ones.
func exportBTDriveMember(t *testing.T, w []byte) []byte {
	t.Helper()
	type section struct {
		id      byte
		payload []byte
	}
	var sections []section
	for off := 8; off < len(w); {
		id := w[off]
		size, n := binary.Uvarint(w[off+1:])
		start := off + 1 + n
		sections = append(sections, section{id, w[start : start+int(size)]})
		off = start + int(size)
	}
	var kinds []byte // 0x7F i32, 0x7E i64
	var inits []int64
	for _, sec := range sections {
		if sec.id != 6 {
			continue
		}
		p := sec.payload
		count, n := binary.Uvarint(p)
		p = p[n:]
		for i := uint64(0); i < count; i++ {
			kind := p[0]
			p = p[2:] // valtype, mutability
			v, n := readSLEB(p[1:])
			p = p[1+n+1:] // const opcode, value, end
			kinds = append(kinds, kind)
			inits = append(inits, v)
		}
	}
	epoch := -1
	for i := range kinds {
		if kinds[i] == 0x7E && inits[i] == 1 {
			if epoch >= 0 {
				t.Fatal("two i64 globals initialised to 1: not one set with a Backtracking drive")
			}
			epoch = i
		}
	}
	want := []byte{0x7E, 0x7E, 0x7F, 0x7E, 0x7E, 0x7E, 0x7F, 0x7F, 0x7F, 0x7F}
	if epoch < 0 || epoch+len(want) > len(kinds) {
		t.Fatalf("no call-epoch global followed by a member's globals (globals %v)", kinds)
	}
	for k, kind := range want {
		if kinds[epoch+k] != kind {
			t.Fatalf("globals after the call epoch are %v, want the drive/member shape %v", kinds[epoch:epoch+len(want)], want)
		}
	}
	names := []struct {
		name string
		idx  int
	}{{"zz_scratch_top", epoch + 2}, {"zz_memo_base", epoch + 6}, {"zz_memo_origin", epoch + 7}}
	var out []byte
	out = append(out, w[:8]...)
	for _, sec := range sections {
		payload := sec.payload
		if sec.id == 7 {
			count, n := binary.Uvarint(payload)
			var np []byte
			np = binary.AppendUvarint(np, count+uint64(len(names)))
			np = append(np, payload[n:]...)
			for _, e := range names {
				np = binary.AppendUvarint(np, uint64(len(e.name)))
				np = append(np, e.name...)
				np = append(np, 0x03) // global
				np = binary.AppendUvarint(np, uint64(e.idx))
			}
			payload = np
		}
		out = append(out, sec.id)
		out = binary.AppendUvarint(out, uint64(len(payload)))
		out = append(out, payload...)
	}
	return out
}

func readSLEB(b []byte) (int64, int) {
	var v int64
	var shift uint
	for i, c := range b {
		v |= int64(c&0x7F) << shift
		shift += 7
		if c&0x80 == 0 {
			if shift < 64 && c&0x40 != 0 {
				v |= -1 << shift
			}
			return v, i + 1
		}
	}
	return v, len(b)
}

// TestSetBTMemberRegionReplacedBelowOrigin pins the arm of
// emitBTScratchInitMember that places a member's memo AGAIN when a call's window
// starts below the region's first row. `find_batch` resumes its walk at a
// delivered position's start + 1, and the per-position worker may already have
// driven a member — and tripped its budget — at a position past that start, so
// the next pass calls the member below the region's origin. Without the arm
// that call addresses rows below the region: it wrote two visited bits under
// the member's memo while the answer stayed right, so only the memory shows it.
//
// The shape: `[a-z]{63}key` is found through its literal, far past its start,
// while the Backtracking member `(aa|a)*b` is driven with a budget of k = 1
// along the way. The host keeps a canary page directly below the scratch base,
// so a bit written under the first region lands in it.
func TestSetBTMemberRegionReplacedBelowOrigin(t *testing.T) {
	pats := []string{`[a-z]{63}key`, `(aa|a)*b`}
	names := []string{"p0", "p1"}
	cfg := config.BuildConfig{
		MaxFallbackStates: 1,
		Regexps:           []config.RegexEntry{{Name: "p0", Pattern: pats[0]}, {Name: "p1", Pattern: pats[1]}},
		Sets: []config.SetConfig{{
			Name: "s", Find: "set_find", Hints: []string{"batch-find"},
			Patterns: config.PatternSelector{Names: names},
		}},
	}
	w, _, diags, err := compile.CompileFileOpts(cfg, "", compile.CompileSetOptions{BTWorkBudget: 1})
	if err != nil {
		t.Fatalf("compile: %v", err)
	}
	if d := droppedFromSet(diags); len(d) > 0 {
		t.Fatalf("patterns were dropped from the set: %v", d)
	}
	w = exportBTDriveMember(t, w)

	engine, wd := sharedEngine()
	mod, err := wasmtime.NewModule(engine, w)
	if err != nil {
		t.Fatalf("module: %v", err)
	}
	defer mod.Close()
	store := wasmtime.NewStore(engine)
	defer store.Close()
	store.SetEpochDeadline(1)
	inst, err := wasmtime.NewInstance(store, mod, nil)
	if err != nil {
		t.Fatalf("instantiate: %v", err)
	}
	mem := inst.GetExport(store, "memory").Memory()
	global := func(name string) int32 {
		return inst.GetExport(store, name).Global().Get(store).I32()
	}

	input := "aac" + strings.Repeat("a", 60) + "key" + "zb"
	const pageSize = 65536
	dataTop, err := utils.ParseDataSectionBytes(w)
	if err != nil {
		t.Fatal(err)
	}
	inBase := int32((dataTop + pageSize - 1) / pageSize * pageSize)
	gate := inBase + pageSize
	out := gate + pageSize
	canary := out + pageSize
	base := canary + pageSize // the scratch base; the canary page lies right below it
	if need, cur := uint64(base/pageSize+1), mem.Size(store); need > cur {
		if _, err := mem.Grow(store, need-cur); err != nil {
			t.Fatal(err)
		}
	}
	if err := inst.GetExport(store, abi.ScratchBaseExport).Global().Set(store, wasmtime.ValI32(base)); err != nil {
		t.Fatal(err)
	}
	buf := mem.UnsafeData(store)
	copy(buf[inBase:], input)
	// Zero, not a pattern: what lands here is a visited BIT, and a pattern
	// byte already carrying that bit would hide it.
	for i := int32(0); i < pageSize; i++ {
		buf[canary+i] = 0
	}
	desc := gate + 64
	abi.WriteFindScratch(buf, desc, gate, 0, 0)

	const outCap = 3
	countMask := int64(1)<<uint(config.SetCursorCountBits(len(pats))) - 1
	fn := inst.GetFunc(store, "set_find_batch")
	var got []setMatch
	replaced := false
	cursor := int64(0)
	for calls := 0; ; calls++ {
		if calls > 1000 {
			t.Fatal("find_batch did not terminate")
		}
		wd.Arm(store)
		res, err := fn.Call(store, inBase, int32(len(input)), cursor, desc, out, int32(outCap))
		wd.Disarm()
		if err != nil {
			t.Fatalf("find_batch: %v", err)
		}
		// The member's region this call ended on, against where the first one
		// goes: at the scratch base itself (4-aligned by construction).
		if global("zz_memo_base") > base {
			replaced = true
		}
		packed := res.(int64)
		buf = mem.UnsafeData(store)
		for i := int32(0); i < int32(packed&countMask); i++ {
			o := out + i*12
			got = append(got, setMatch{
				PatternID: int(int32(binary.LittleEndian.Uint32(buf[o:]))),
				Start:     int(int32(binary.LittleEndian.Uint32(buf[o+4:]))),
				End:       int(int32(binary.LittleEndian.Uint32(buf[o+8:]))),
			})
		}
		if uint32(packed>>32) == 0xFFFFFFFF {
			break
		}
		cursor = packed
	}

	want := gatedOracle(pats, input)
	if !sameTuples(got, want) {
		t.Errorf("find_batch over %q: got %v, want %v", input, got, want)
	}
	if !replaced {
		t.Errorf("the member's memo was never placed a second time (memo base stayed %d, scratch top %d): "+
			"the shape no longer reaches the arm this test pins", global("zz_memo_base"), global("zz_scratch_top"))
	}
	buf = mem.UnsafeData(store)
	for i := int32(0); i < pageSize; i++ {
		if buf[canary+i] != 0 {
			t.Fatalf("byte %d below the scratch base was overwritten (%#x): a call addressed memo rows below its region",
				pageSize-i, buf[canary+i])
		}
	}
}

// TestSetBTHostCallIsLinear pins what a set's Backtracking members share across
// the candidate calls of one host call (compile/bt_scratch.go, btDriveMember):
// one work budget per member, one scratch region per member, and the visited
// set in it.
//
// Before, each candidate burned a budget sized over the rest of the input and
// then placed and cleared a fresh memo there, so one `find` over a×n was
// quadratic — measured ×4.00 per doubling, 110,272,726,505 fuel at a×4000
// where this build measures 58,597,434 — and with the host global at 0 each
// candidate's fallback took fresh pages: 7,984 pages grown in ONE call over
// a×4000.
//
// The members are `(\w*|)*c` (a loop whose body can match empty),
// `(aa|a)*b` (overlapping branches) and `bar[0-9]+`, all on Backtracking
// through max_fallback_states: 1. The input matches none of them, so every
// position is a candidate and one host call covers the whole input.
func TestSetBTHostCallIsLinear(t *testing.T) {
	names := []string{"p0", "p1", "p2"}
	cfg := config.BuildConfig{
		MaxFallbackStates: 1,
		Regexps: []config.RegexEntry{
			{Name: "p0", Pattern: `(\w*|)*c`},
			{Name: "p1", Pattern: `bar[0-9]+`},
			{Name: "p2", Pattern: `(aa|a)*b`},
		},
		Sets: []config.SetConfig{{
			Name: "s", Find: "set_find", ScanAll: "set_scan_all",
			Patterns: config.PatternSelector{Names: names},
		}},
	}
	w, _, diags, err := compile.CompileFileDiag(cfg, "")
	if err != nil {
		t.Fatalf("compile: %v", err)
	}
	if d := droppedFromSet(diags); len(d) > 0 {
		t.Fatalf("patterns were dropped from the set: %v", d)
	}

	wcfg := wasmtime.NewConfig()
	wcfg.SetConsumeFuel(true)
	wcfg.SetWasmSIMD(true)
	eng := wasmtime.NewEngineWithConfig(wcfg)
	mod, err := wasmtime.NewModule(eng, w)
	if err != nil {
		t.Fatalf("module: %v", err)
	}
	defer mod.Close()
	const pageSize = 65536
	dataTop, err := utils.ParseDataSectionBytes(w)
	if err != nil {
		t.Fatalf("parse data section: %v", err)
	}
	inBase := int32((dataTop + pageSize - 1) / pageSize * pageSize)

	// run drives one `find` host call and one `scan_all` host call over a×n,
	// returning each call's fuel and how many pages each grew memory by.
	run := func(n int, globalZero bool) (findFuel, scanFuel uint64, findGrew, scanGrew uint64) {
		store := wasmtime.NewStore(eng)
		defer store.Close()
		if err := store.SetFuel(1 << 62); err != nil {
			t.Fatal(err)
		}
		inst, err := wasmtime.NewInstance(store, mod, []wasmtime.AsExtern{})
		if err != nil {
			t.Fatal(err)
		}
		mem := inst.GetExport(store, "memory").Memory()
		gate := inBase + int32((n+pageSize)/pageSize*pageSize)
		out := gate + pageSize
		top := int64(out) + pageSize
		if need, cur := uint64(top/pageSize), mem.Size(store); need > cur {
			if _, err := mem.Grow(store, need-cur); err != nil {
				t.Fatal(err)
			}
		}
		if !globalZero {
			if err := inst.GetExport(store, abi.ScratchBaseExport).Global().Set(store, wasmtime.ValI32(int32(top))); err != nil {
				t.Fatal(err)
			}
		}
		copy(mem.UnsafeData(store)[inBase:], strings.Repeat("a", n))
		scratch := gate + 64
		abi.WriteFindScratch(mem.UnsafeData(store), scratch, gate, 0, 0)

		p0 := mem.Size(store)
		f0, _ := store.GetFuel()
		res, err := inst.GetFunc(store, "set_find").Call(store, inBase, int32(n), int32(0), scratch, out, int32(len(names)))
		if err != nil {
			t.Fatalf("a×%d: find: %v", n, err)
		}
		if got := res.(int32); got != 0 {
			t.Fatalf("a×%d: find answered %d, want 0 (no pattern matches)", n, got)
		}
		f1, _ := store.GetFuel()
		p1 := mem.Size(store)
		res, err = inst.GetFunc(store, "set_scan_all").Call(store, inBase, int32(n), int32(0), out)
		if err != nil {
			t.Fatalf("a×%d: scan_all: %v", n, err)
		}
		if got := res.(int32); got != 0 {
			t.Fatalf("a×%d: scan_all answered %d, want 0 (no pattern matches)", n, got)
		}
		f2, _ := store.GetFuel()
		return f0 - f1, f1 - f2, p1 - p0, mem.Size(store) - p1
	}

	const maxRatio = 2.2
	var prevFind, prevScan uint64
	var report strings.Builder
	for _, n := range []int{1000, 2000, 4000, 8000} {
		ff, sf, _, _ := run(n, false)
		fmt.Fprintf(&report, "  a×%-5d find=%-11d scan_all=%d\n", n, ff, sf)
		if prevFind > 0 {
			if r := float64(ff) / float64(prevFind); r > maxRatio {
				t.Errorf("find fuel grew x%.2f from a×%d to a×%d, want <= x%.1f", r, n/2, n, maxRatio)
			}
			if r := float64(sf) / float64(prevScan); r > maxRatio {
				t.Errorf("scan_all fuel grew x%.2f from a×%d to a×%d, want <= x%.1f", r, n/2, n, maxRatio)
			}
		}
		prevFind, prevScan = ff, sf
	}
	t.Logf("fuel per host call:\n%s", report.String())

	// With the host global at 0 each host call takes fresh pages, but ONE per
	// call, not one per candidate: the growth must not scale with the input.
	_, _, smallFind, smallScan := run(500, true)
	_, _, bigFind, bigScan := run(4000, true)
	for _, c := range []struct {
		what       string
		small, big uint64
	}{{"find", smallFind, bigFind}, {"scan_all", smallScan, bigScan}} {
		if c.big > 4 || c.big > c.small+2 {
			t.Errorf("%s with the host global at 0 grew memory %d pages over a×500 and %d over a×4000 — "+
				"each candidate is taking its own pages again", c.what, c.small, c.big)
		}
	}
}

// ---------------------------------------------------------------------------
// Regression: the Backtracking engine's BitState memo is a bitset of
// N*(len+1) bits zeroed by one memory.fill at the head of every attempt, but
// the region reserved for it is sized from a COMPILE-TIME ceiling
// (memoBudget*8/N - 1, compile.go's memoMaxLen). Until 2026-09-05 that ceiling
// was computed and never emitted: the fill's length came straight from the
// runtime `len` with nothing clamping it.
//
// The memo is the LAST reservation in a module that declares exactly
// PageAlign(tableEnd) pages, so the overrun has no slack to land in. What it
// does depends on the memory layout, and every outcome is bad:
//
//   - standalone, input at page 0 (this harness, and tools/re2test): the fill
//     runs off the end of declared memory and TRAPS.
//   - the JS/TS stubs' layout, input staged AFTER the tables
//     (generate/js_stub.go): the fill zeroes the caller's own input and the
//     call then answers NoMatch for an input that matches — silent, and a
//     wrong answer rather than a crash.
//   - embedded or multi-pattern: it lands in the next pattern's tables
//     (compile.go chains them), corrupting an unrelated matcher.
//
// The guard is emitted in every body that fills a memo — the capture body
// (buildBacktrackBody, which set BT buckets also use), the no-capture match
// body, and BOTH branches of the no-capture find body (mandatory-literal and
// general scan).
//
// These tests assert the CONTRACT, not the threshold: at every length the call
// must return either the answer Go gives or abi.BTStackOverflow, and must never
// trap. That way they keep working when memoBudget, N, or the frame budget
// move, none of which are pinned here.

// btMemoCall is btRawCall's variant that surfaces a trap instead of failing the
// test on it — the trap IS the regression, so it has to be observable.
func btMemoCall(t *testing.T, wasmBytes []byte, export, input string, extraArgs ...int32) (int64, error) {
	t.Helper()
	store, inst, mem, release, err := instantiate(wasmBytes)
	defer release()
	if err != nil {
		t.Fatalf("instantiate: %v", err)
	}
	fn := inst.GetFunc(store, export)
	if fn == nil {
		t.Fatalf("module has no %q export", export)
	}
	buf := mem.UnsafeData(store)
	if len(input) > int(pathsOutBase-pathsInputBase) {
		t.Fatalf("input of %d bytes runs into the output window at %d", len(input), pathsOutBase)
	}
	copy(buf[pathsInputBase:], input)
	args := []any{any(pathsInputBase), any(int32(len(input)))}
	for _, a := range extraArgs {
		args = append(args, any(a))
	}
	_, wd := sharedEngine()
	wd.Arm(store)
	res, callErr := fn.Call(store, args...)
	wd.Disarm()
	if callErr != nil {
		return 0, callErr
	}
	switch v := res.(type) {
	case int32:
		return int64(v), nil
	case int64:
		return v, nil
	default:
		t.Fatalf("%s returned unexpected type %T", export, res)
		return 0, nil
	}
}

// btMemoPatterns covers every body that fills a memo. All four need
// needsBitState (a non-greedy loop whose body can match empty); the no-capture
// ones additionally need the DFA squeezed past its limit or they never reach
// Backtracking at all.
//
// MemoBudget is deliberately SMALL on three of them: it moves the ceiling down
// to a few thousand bytes so the sweep crosses it in milliseconds. htmlTags
// keeps the default budget and reproduces the original report exactly — its
// ceiling sits at a 41,942-byte extent.
const htmlTagsPattern = `<(?P<tag>\w+)(?:\s*(?P<attr>\w+)?(?:="(?P<val>[^"]*)")?)*?>`

func TestBTMemoOverflowIsGuarded(t *testing.T) {
	small := compile.CompileOptions{MemoBudget: 4096}
	squeezedSmall := compile.CompileOptions{MaxDFAStates: 1, MemoBudget: 4096}

	cases := []struct {
		name   string
		entry  config.RegexEntry
		opts   []compile.CompileOptions
		export string
		extra  []int32
		// wrap turns a run of n 'a's into the actual input.
		wrap func(string) string
		// answer maps a Go match to the raw i64 the export returns, so a
		// non-sentinel result can be checked rather than merely accepted.
		answer func(in string, loc []int) int64
	}{
		{
			// buildBacktrackBody — the capture body, shared with set BT buckets.
			name:   "groups/html-tags/default-budget",
			entry:  config.RegexEntry{Pattern: htmlTagsPattern, GroupsFunc: "groups"},
			export: "groups", extra: []int32{pathsOutBase, 0},
			wrap:   func(a string) string { return "<" + a + ">" },
			answer: func(_ string, loc []int) int64 { return int64(loc[1]) },
		},
		{
			name:   "groups/small-budget",
			entry:  config.RegexEntry{Pattern: htmlTagsPattern, GroupsFunc: "groups"},
			opts:   []compile.CompileOptions{small},
			export: "groups", extra: []int32{pathsOutBase, 0},
			wrap:   func(a string) string { return "<" + a + ">" },
			answer: func(_ string, loc []int) int64 { return int64(loc[1]) },
		},
		{
			// buildBTMatchBody.
			name:   "match",
			entry:  config.RegexEntry{Pattern: `(?:a?)+?b`, MatchFunc: "match"},
			opts:   []compile.CompileOptions{squeezedSmall},
			export: "match",
			wrap:   func(a string) string { return a + "b" },
			answer: func(in string, _ []int) int64 { return int64(len(in)) },
		},
		{
			// buildBTFindBody, general-scan branch.
			name:   "find/general-scan",
			entry:  config.RegexEntry{Pattern: `(?:a?)+?`, FindFunc: "find"},
			opts:   []compile.CompileOptions{squeezedSmall},
			export: "find", extra: []int32{0},
			wrap:   func(a string) string { return a },
			answer: func(_ string, loc []int) int64 { return int64(loc[0])<<32 | int64(loc[1]) },
		},
		{
			// buildBTFindBody, mandatory-literal branch — a separate emission
			// site with its own copy of the fill.
			name:   "find/mandatory-literal",
			entry:  config.RegexEntry{Pattern: `(?:a?)+?xyz`, FindFunc: "find"},
			opts:   []compile.CompileOptions{squeezedSmall},
			export: "find", extra: []int32{0},
			wrap:   func(a string) string { return a + "xyz" },
			answer: func(_ string, loc []int) int64 { return int64(loc[0])<<32 | int64(loc[1]) },
		},
	}

	// Spans every ceiling above: 4096-byte budgets put it in the low
	// thousands, the default budget puts it at 41,942.
	lengths := []int{0, 1, 100, 4095, 4096, 4097, 20000, 41940, 41941, 41942, 41943, 60000, 120000}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			w, _, err := compile.Compile([]config.RegexEntry{tc.entry}, pathsTableBase, true, tc.opts...)
			if err != nil {
				t.Fatalf("compile: %v", err)
			}
			re := regexp.MustCompile(tc.entry.Pattern)

			answered := 0
			for _, n := range lengths {
				in := tc.wrap(strings.Repeat("a", n))
				if len(in) > int(pathsOutBase-pathsInputBase) {
					continue
				}
				got, err := btMemoCall(t, w, tc.export, in, tc.extra...)
				if err != nil {
					t.Fatalf("len=%d: %v\nthe memo fill ran past its reservation — "+
						"the guard is missing from this body", len(in), err)
				}
				if got == abi.BTStackOverflow {
					continue // a resource ceiling; the answer is unknown, which is allowed
				}
				loc := re.FindStringIndex(in)
				var want int64 = abi.NoMatch
				if loc != nil {
					want = tc.answer(in, loc)
				}
				if got != want {
					t.Fatalf("len=%d: got %d, want %d (or BTStackOverflow)", len(in), got, want)
				}
				answered++
			}
			// Guards that reject everything would satisfy the loop above
			// vacuously; at least the short inputs must still get real answers.
			if answered == 0 {
				t.Fatalf("every length returned BTStackOverflow — the guard has "+
					"replaced all results rather than bounding them (%d lengths tried)", len(lengths))
			}
		})
	}
}

// The memo's length guard REFUSES: past the ceiling the body returns
// abi.BTStackOverflow, which means "the answer is unknown". Emitted at the head
// of a call, that verdict was reached before the find body had looked at the
// input at all — so a long input whose prefilter finds no candidate anywhere
// was told "unknown" when the engine could have answered "no match" for free,
// without ever touching the memo.
//
// The guard and the clear now sit at the head of the first ATTEMPT instead, so
// a call that never attempts never pays and never refuses.
//
// The test drives ONE pattern at ONE length over two inputs that differ only in
// which byte they repeat, and requires the two arms to differ:
//
//	quiet — no byte can begin a match, so no attempt runs → NoMatch
//	busy  — every position is a candidate, attempts run, the memo is filled
//	        past its ceiling → BTStackOverflow
//
// Both arms matter. Without the busy one the test would pass just as well
// against a build with no memo at all, or one whose ceiling was never reached,
// and would stop being evidence for anything.
//
// The static memo ceiling answers -2 only in a body compiled with
// compile.BTWorkBudgetOff, so that is what the two arms are measured on. A body
// with the budget hands a call past the ceiling to its fallback, which sizes
// its memo from the input — the SHIPPED build is checked for that answer last.
func TestBTMemoGuardDoesNotRefuseWhatThePrefilterAnswers(t *testing.T) {
	// MaxDFAStates squeezes the pattern onto Backtracking; the small budget
	// puts the memo ceiling in the low thousands so a 60 KB input is well past
	// it either way.
	opts := compile.CompileOptions{MaxDFAStates: 1, MemoBudget: 4096, BTWorkBudget: compile.BTWorkBudgetOff}

	// Leading `Z` gives the prefilter something to reject on; `(?:a?)+?` is
	// what makes needsBitState fire.
	const pattern = `Z(?:a?)+?xyz`
	const length = 60000

	entry := config.RegexEntry{Pattern: pattern, FindFunc: "find"}
	w, _, err := compile.Compile([]config.RegexEntry{entry}, pathsTableBase, true, opts)
	if err != nil {
		t.Fatalf("compile: %v", err)
	}

	quiet := strings.Repeat("m", length) // no `Z`: nothing can begin a match
	busy := strings.Repeat("Z", length)  // every position is a candidate

	if regexp.MustCompile(pattern).MatchString(quiet) ||
		regexp.MustCompile(pattern).MatchString(busy) {
		t.Fatal("an input matches after all — the case is not testing what it claims")
	}

	got, err := btMemoCall(t, w, "find", quiet, 0)
	if err != nil {
		t.Fatalf("quiet: %v", err)
	}
	if got != abi.NoMatch {
		t.Errorf("quiet input of %d bytes: got %d, want NoMatch(%d) — the memo guard is "+
			"refusing a call the prefilter answers without ever touching the memo",
			length, got, abi.NoMatch)
	}

	got, err = btMemoCall(t, w, "find", busy, 0)
	if err != nil {
		t.Fatalf("busy: %v", err)
	}
	if got != abi.BTStackOverflow {
		t.Errorf("busy input of %d bytes: got %d, want BTStackOverflow(%d) — this arm is "+
			"what proves the memo path is reached at all, so the quiet arm above is "+
			"evidence of a moved guard rather than of an absent one",
			length, got, abi.BTStackOverflow)
	}

	// Shipped: past the ceiling, the fallback answers.
	opts.BTWorkBudget = 0
	w, _, err = compile.Compile([]config.RegexEntry{entry}, pathsTableBase, true, opts)
	if err != nil {
		t.Fatalf("compile (budget on): %v", err)
	}
	if got, err = btMemoCall(t, w, "find", busy, 0); err != nil || got != abi.NoMatch {
		t.Errorf("budget on, busy input of %d bytes: got %d (%v), want NoMatch(%d) from the fallback",
			length, got, err, abi.NoMatch)
	}
}

// The memo is REBASED onto the call's `from`: bit index 0 stands for that
// position, not for position 0. No attempt in a call ever starts before `from`
// — attempt_start is seeded from it and only advances — so the bitset a call
// needs covers the REMAINDER it is searching, and the ceiling is checked
// against that rather than against the whole buffer.
//
// Without the rebase a host walking a long buffer got BTStackOverflow from
// every call in the walk, including the ones with only a handful of bytes left
// to search, because each was measured against the buffer's full length.
//
// Both arms again: `from` at 0 must still refuse (the remainder really is past
// the ceiling), and a late `from` must answer. A build that simply lost its
// ceiling would pass the second arm and fail the first.
//
// Measured with compile.BTWorkBudgetOff, where the ceiling still refuses; with
// the budget on, the refusal hands the call to the fallback, checked last.
func TestBTMemoCeilingAppliesToTheRemainder(t *testing.T) {
	opts := compile.CompileOptions{MaxDFAStates: 1, MemoBudget: 4096, BTWorkBudget: compile.BTWorkBudgetOff}
	const pattern = `Z(?:a?)+?xyz`
	const length = 60000

	entry := config.RegexEntry{Pattern: pattern, FindFunc: "find"}
	w, _, err := compile.Compile([]config.RegexEntry{entry}, pathsTableBase, true, opts)
	if err != nil {
		t.Fatalf("compile: %v", err)
	}
	// Every position is a candidate, so every call reaches an attempt and the
	// memo is genuinely used.
	input := strings.Repeat("Z", length)
	if regexp.MustCompile(pattern).MatchString(input) {
		t.Fatal("the input matches after all — the case is not testing what it claims")
	}

	got, err := btMemoCall(t, w, "find", input, 0)
	if err != nil {
		t.Fatalf("from=0: %v", err)
	}
	if got != abi.BTStackOverflow {
		t.Errorf("from=0: got %d, want BTStackOverflow(%d) — the whole %d-byte remainder "+
			"is past the memo ceiling, so this call must still refuse",
			got, abi.BTStackOverflow, length)
	}

	// Only 100 bytes remain to search, which fits the memo comfortably.
	const late = length - 100
	got, err = btMemoCall(t, w, "find", input, int32(late))
	if err != nil {
		t.Fatalf("from=%d: %v", late, err)
	}
	if got != abi.NoMatch {
		t.Errorf("from=%d: got %d, want NoMatch(%d) — only %d bytes remain, so the memo "+
			"ceiling must be measured against those and not against the whole buffer",
			late, got, abi.NoMatch, length-late)
	}

	opts.BTWorkBudget = 0
	w, _, err = compile.Compile([]config.RegexEntry{entry}, pathsTableBase, true, opts)
	if err != nil {
		t.Fatalf("compile (budget on): %v", err)
	}
	if got, err = btMemoCall(t, w, "find", input, 0); err != nil || got != abi.NoMatch {
		t.Errorf("budget on, from=0: got %d (%v), want NoMatch(%d) from the fallback", got, err, abi.NoMatch)
	}
}

// ---------------------------------------------------------------------------
// Regression: the Backtracking engine's frame stack is sized
// from a compile-time constant (btAllocSizes: numAlts*4096 frames) while the
// real requirement scales with input length. Exhausting it used to return
// abi.NoMatch, i.e. a false negative that switches on somewhere past
// numAlts*4096 bytes and is indistinguishable from a genuine no-match at every
// layer above. It must return abi.BTStackOverflow instead.
//
// These tests are deliberately written against the raw WASM return code rather
// than through a helper that folds negatives into an ok bool — the whole point
// is that the two negatives stay distinguishable, so a helper that erases the
// difference cannot be the thing under test.
//
// Pattern-shape notes, which are the fiddly part of reproducing this at all:
//
//   - The pattern must push a backtrack frame that STAYS live as input is
//     consumed. A non-greedy loop alone does not: its preferred branch (exit
//     the loop) fails immediately against the next byte, so the frame is pushed
//     and popped straight back. What accumulates is an untried *alternation*
//     branch — after `ab` matches, the frame holding "try `cd` here instead"
//     is still live.
//   - The alternation must survive regexp/syntax's simplification. `a|b`
//     becomes the char class `[ab]` and `aa|ab` is factored to `a[ab]`; neither
//     leaves an Alt instruction, so neither overflows. Branches with no common
//     prefix (`ab|cd`) do.
//   - For the no-capture paths the DFA has to be pushed over its state limit
//     first, or they never reach Backtracking at all — hence MaxDFAStates and
//     a literal tail long enough to blow it.
const (
	// btCapturePattern reaches BT via the capture path (the selector rejects
	// TDFA for the non-greedy quantifier). numAlts = 2 → 8192 frames, and the
	// inner (a)|(b) leaves one live frame per input byte.
	btCapturePattern = `(?:(a)|(b))*?c`
	btCaptureGroups  = 3 // whole match + 2 groups

	// btNoCapturePattern reaches BT for match/find once the DFA state limit is
	// squeezed. Each iteration consumes 2 bytes and leaves one live frame.
	btNoCapturePattern = `(?:ab|cd)*?xyzuvw`
)

// btRawCall calls export with (ptr, len, extraArgs...) and returns its raw
// result widened to int64, so an i32 -2 and an i64 -2 compare the same way.
func btRawCall(t *testing.T, wasmBytes []byte, export, input string, extraArgs ...int32) int64 {
	t.Helper()
	store, inst, mem, release, err := instantiate(wasmBytes)
	defer release()
	if err != nil {
		t.Fatalf("instantiate: %v", err)
	}
	fn := inst.GetFunc(store, export)
	if fn == nil {
		t.Fatalf("module has no %q export", export)
	}
	buf := mem.UnsafeData(store)
	if len(input) > int(pathsOutBase-pathsInputBase) {
		t.Fatalf("input of %d bytes would run into the output window at %d", len(input), pathsOutBase)
	}
	copy(buf[pathsInputBase:], input)
	// Poison the output window so a stale read cannot masquerade as a result.
	for i := 0; i < 1024; i++ {
		binary.LittleEndian.PutUint32(buf[int(pathsOutBase)+i*4:], 0xFFFFFFFF)
	}

	args := []any{any(pathsInputBase), any(int32(len(input)))}
	for _, a := range extraArgs {
		args = append(args, any(a))
	}
	_, wd := sharedEngine()
	wd.Arm(store)
	res, callErr := fn.Call(store, args...)
	wd.Disarm()
	if callErr != nil {
		t.Fatalf("call %s: %v", export, callErr)
	}
	switch v := res.(type) {
	case int32:
		return int64(v)
	case int64:
		return v
	default:
		t.Fatalf("%s returned unexpected type %T", export, res)
		return 0
	}
}

// TestBTStackOverflowIsDistinguishable is the core assertion: on an input
// past the frame ceiling every BT-hosting export reports BTStackOverflow, and
// critically NOT NoMatch — while the same pattern on a shorter input still
// answers correctly, so the sentinel has not simply replaced all results.
//
// The frame ceiling answers -2 only with compile.BTWorkBudgetOff. With the
// budget on — what ships — an overflow hands the call to the fallback, whose
// stack grows with the input, so the same blown input must then get the real
// answer (wantBlown). Both builds are driven.
func TestBTStackOverflowIsDistinguishable(t *testing.T) {
	if eng, err := compile.SelectEngine(btCapturePattern, compile.CompileOptions{}); err != nil {
		t.Fatalf("SelectEngine: %v", err)
	} else if eng != compile.EngineBacktrack {
		t.Fatalf("%s selects %v, not Backtracking — this test no longer exercises the BT capture path",
			btCapturePattern, eng)
	}

	capIn := func(n int) string { return strings.Repeat("a", n) + "c" }
	noCapIn := func(n int) string { return strings.Repeat("ab", n) + "xyzuvw" }
	squeezed := compile.CompileOptions{MaxDFAStates: 2}
	off := compile.CompileOptions{BTWorkBudget: compile.BTWorkBudgetOff}
	squeezedOff := squeezed
	squeezedOff.BTWorkBudget = compile.BTWorkBudgetOff

	cases := []struct {
		name      string
		entry     config.RegexEntry
		opts      []compile.CompileOptions
		export    string
		extra     []int32
		ok        string // input the engine can still answer
		wantOK    int64  // its expected result
		blown     string // input past the frame ceiling
		wantBlown int64  // its answer once the fallback takes the call
		offOpts   []compile.CompileOptions
		numCaps   int
	}{
		{
			name:      "groups",
			entry:     config.RegexEntry{Pattern: btCapturePattern, GroupsFunc: "groups"},
			export:    "groups",
			extra:     []int32{pathsOutBase, 0}, // out_ptr, from
			ok:        capIn(8191),
			wantOK:    8192, // match end position
			blown:     capIn(8192),
			wantBlown: 8193,
			offOpts:   []compile.CompileOptions{off},
			numCaps:   btCaptureGroups,
		},
		{
			name:      "groups_batch",
			entry:     config.RegexEntry{Pattern: btCapturePattern, GroupsFunc: "groups", Hints: []string{"batch-find"}},
			export:    "groups_batch",
			extra:     []int32{pathsOutBase, 16, 0},
			ok:        capIn(8191),
			wantOK:    1, // one match collected
			blown:     capIn(8192),
			wantBlown: 1,
			offOpts:   []compile.CompileOptions{off},
		},
		{
			name:      "match",
			entry:     config.RegexEntry{Pattern: btNoCapturePattern, MatchFunc: "match"},
			opts:      []compile.CompileOptions{squeezed},
			export:    "match",
			ok:        noCapIn(4000),
			wantOK:    8006,
			blown:     noCapIn(8192),
			wantBlown: 16390,
			offOpts:   []compile.CompileOptions{squeezedOff},
		},
		{
			name:      "find",
			entry:     config.RegexEntry{Pattern: btNoCapturePattern, FindFunc: "find"},
			opts:      []compile.CompileOptions{squeezed},
			export:    "find",
			extra:     []int32{0}, // `from` — find is (ptr, len, from)
			ok:        noCapIn(4000),
			wantOK:    8006, // packed 0<<32|8006
			blown:     noCapIn(8192),
			wantBlown: 16390,
			offOpts:   []compile.CompileOptions{squeezedOff},
		},
		{
			name:      "find_batch",
			entry:     config.RegexEntry{Pattern: btNoCapturePattern, FindFunc: "find", Hints: []string{"batch-find"}},
			opts:      []compile.CompileOptions{squeezed},
			export:    "find_batch",
			extra:     []int32{pathsOutBase, 16, 0},
			ok:        noCapIn(4000),
			wantOK:    1,
			blown:     noCapIn(8192),
			wantBlown: 1,
			offOpts:   []compile.CompileOptions{squeezedOff},
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			w, _, err := compile.Compile([]config.RegexEntry{tc.entry}, pathsTableBase, true, tc.offOpts...)
			if err != nil {
				t.Fatalf("compile: %v", err)
			}

			// Both inputs genuinely match, so NoMatch is the wrong answer for
			// either one — which is what made the old behaviour a false
			// negative rather than a merely imprecise one.
			re := regexp.MustCompile(tc.entry.Pattern)
			for _, in := range []string{tc.ok, tc.blown} {
				if !re.MatchString(in) {
					t.Fatalf("test input of %d bytes does not match %s — fixture is wrong",
						len(in), tc.entry.Pattern)
				}
			}

			if got := btRawCall(t, w, tc.export, tc.ok, tc.extra...); got != tc.wantOK {
				t.Errorf("%s on %d-byte input = %d, want %d (below the frame ceiling it must still answer)",
					tc.export, len(tc.ok), got, tc.wantOK)
			}
			got := btRawCall(t, w, tc.export, tc.blown, tc.extra...)
			if got == abi.NoMatch {
				t.Errorf("%s on %d-byte input = %d (NoMatch) — regression: "+
					"stack overflow reported as a definite no-match",
					tc.export, len(tc.blown), got)
			}
			if got != abi.BTStackOverflow {
				t.Errorf("%s on %d-byte input = %d, want %d (BTStackOverflow)",
					tc.export, len(tc.blown), got, abi.BTStackOverflow)
			}

			// Shipped: the overflow hands the call to the fallback.
			w, _, err = compile.Compile([]config.RegexEntry{tc.entry}, pathsTableBase, true, tc.opts...)
			if err != nil {
				t.Fatalf("compile (budget on): %v", err)
			}
			if got := btRawCall(t, w, tc.export, tc.blown, tc.extra...); got != tc.wantBlown {
				t.Errorf("budget on: %s on %d-byte input = %d, want %d from the fallback",
					tc.export, len(tc.blown), got, tc.wantBlown)
			}
		})
	}
}

// TestBTStackOverflowThreshold pins the ceiling to numAlts*4096 frames. If a
// future change to btAllocSizes moves it, this fails loudly rather than
// silently shifting the input size at which callers start seeing errors — with
// the budget on, the input size at which calls start paying for the fallback.
// Measured with compile.BTWorkBudgetOff, the one build where it answers -2.
func TestBTStackOverflowThreshold(t *testing.T) {
	w, _, err := compile.Compile(
		[]config.RegexEntry{{Pattern: btCapturePattern, GroupsFunc: "groups"}},
		pathsTableBase, true, compile.CompileOptions{BTWorkBudget: compile.BTWorkBudgetOff})
	if err != nil {
		t.Fatalf("compile: %v", err)
	}
	const wantLast = 8191 // numAlts(2) * 4096 == 8192 frames, one per input byte
	if got := btRawCall(t, w, "groups", strings.Repeat("a", wantLast)+"c", pathsOutBase, 0); got < 0 {
		t.Errorf("%d-byte input already overflows (= %d); ceiling moved down", wantLast+1, got)
	}
	if got := btRawCall(t, w, "groups", strings.Repeat("a", wantLast+1)+"c", pathsOutBase, 0); got != abi.BTStackOverflow {
		t.Errorf("%d-byte input = %d, want BTStackOverflow; ceiling moved up", wantLast+2, got)
	}
}

// ---------------------------------------------------------------------------
// Regression: the Backtracking engine dropped every input byte >= 0x80 from a
// rune RANGE, so a capture pattern over a negated class silently failed to
// match input containing such a byte.
//
// `.` and negated classes consuming ONE BYTE is documented byte semantics
// (docs/engines.md, "Bytes, not codepoints"), so `[^>]` must match 0xE9. The
// DFA agrees: nfaBuildInputMap SATURATES a range at 0xFF. Backtracking
// TRUNCATED at 0x7F instead — `if lo > 0x7F { continue }` in btCheckRuneRanges
// and btEmitSingleRange — and nfaFirstBytes gated its scan prefilter the same
// way, so a match STARTING with a high byte was skipped outright.
//
// Backtracking is a hybrid: the DFA finds the match extent, the NFA fills the
// captures. That is why the defect showed only through `groups` — `find` took
// the DFA's answer and was right, then `groups` re-walked the same input with
// the truncated ranges and reported no match at all.
//
// The affected family is precisely the one the engine-selection gate exists to
// route here: `<([^>]+)>`, `([^,]+),`, `KEY=([^&]+)&` (see CLAUDE.md's
// load-bearing gates section). An inverted class is what sends a capture
// pattern to Backtracking, and an inverted class is what carries the high
// bytes.
//
// ORACLE. An isomorphism, for the same reason single_pattern_test.go uses
// one: Go reads its input as UTF-8, so it cannot be asked about a raw 0xE9. A
// byte engine treats 0xE9 exactly like any other byte absent from the pattern,
// so mapping it to an ASCII stand-in that also appears nowhere gives a
// question Go can answer. That is an independent oracle, not a transcript of
// engine output.
//
// NOTE ON COVERAGE. tools/re2test cannot host this case: it skips every input
// containing a byte above 127 (hasUnicode), so no corpus row ever feeds a high
// byte to any engine. That blind spot is why this survived.

const (
	btHiByte   = "\xe9"
	btHiStandI = "Q"
)

func TestBTHighByteInRanges(t *testing.T) {
	shapes := []struct {
		name, pat, input string
		groups           int
	}{
		// The canonical Backtracking family, high byte INSIDE the match.
		{"angle", `<([^>]+)>`, "<caf\xe9>", 1},
		{"comma", `([^,]+),`, "caf\xe9,", 1},
		{"kv", `KEY=([^&]+)&`, "KEY=caf\xe9&", 1},
		{"quoted", `"([^"]*)"`, "\"caf\xe9\"", 1},
		{"nonspace", `(\S+)!`, "caf\xe9!", 1},
		{"two-groups", `<([^>]+)>=([^;]+);`, "<caf\xe9>=va\xe9l;", 2},

		// High byte at the START of the match — the nfaFirstBytes prefilter.
		{"first-byte", `([^,]+),`, "\xe9ab,", 1},
		{"first-byte-only", `([^,]+),`, "\xe9,", 1},

		// High byte at both ends.
		{"both-ends", `([^,]+),`, "\xe9a\xe9,", 1},

		// Pure-ASCII controls: these must not change.
		{"ascii-angle", `<([^>]+)>`, "<cafe>", 1},
		{"ascii-comma", `([^,]+),`, "cafe,", 1},
	}

	for _, sh := range shapes {
		t.Run(sh.name, func(t *testing.T) {
			eng, serr := compile.SelectEngine(sh.pat, compile.CompileOptions{})
			if serr != nil {
				t.Fatalf("select: %v", serr)
			}
			entry := config.RegexEntry{Pattern: sh.pat, GroupsFunc: "groups"}
			w, _, err := compile.Compile([]config.RegexEntry{entry}, pathsTableBase, true)
			if err != nil {
				t.Fatalf("compile: %v", err)
			}
			store, inst, mem, release, err := instantiate(w)
			defer release()
			if err != nil {
				t.Fatalf("instantiate: %v", err)
			}
			copy(mem.UnsafeData(store)[pathsInputBase:], sh.input)
			res, cerr := inst.GetFunc(store, "groups").Call(store,
				pathsInputBase, int32(len(sh.input)), pathsOutBase, int32(0))
			if cerr != nil {
				t.Fatalf("groups call: %v", cerr)
			}

			// The isomorphic twin: 0xE9 -> 'Q' in the input only. No shape
			// here names a high byte in the PATTERN.
			oracleIn := strings.ReplaceAll(sh.input, btHiByte, btHiStandI)
			re := regexp.MustCompile(`(?s)` + sh.pat)
			want := re.FindStringSubmatchIndex(oracleIn)

			got := res.(int32)
			if want == nil {
				if got >= 0 {
					t.Errorf("engine %v: pattern %q over %q matched, want no match", eng, sh.pat, sh.input)
				}
				return
			}
			if got < 0 {
				t.Fatalf("engine %v: pattern %q over %q returned %d (no match), want spans %v\n"+
					"  a negated class must match a byte >= 0x80: `.` and negated classes "+
					"consume ONE BYTE (docs/engines.md)", eng, sh.pat, sh.input, got, want)
			}

			buf := mem.UnsafeData(store)
			slots := (sh.groups + 1) * 2
			for i := 0; i < slots; i++ {
				v := int32(binary.LittleEndian.Uint32(buf[int(pathsOutBase)+i*4:]))
				wantV := int32(want[i])
				if v != wantV {
					t.Errorf("engine %v: pattern %q over %q slot %d: got %d, want %d (all spans %v)",
						eng, sh.pat, sh.input, i, v, wantV, want)
				}
			}
		})
	}
}

// The same defect under byte_mode, where the pattern names the high bytes
// itself rather than admitting them through a negated class.
func TestBTHighByteByteMode(t *testing.T) {
	shapes := []struct{ name, pat, input string }{
		{"hi-class-plus", `([\x80-\xff]+)x`, "\xe9\xeax"},
		{"hi-class-one", `a([\x80-\xff])b`, "a\xe9b"},
		{"hi-range-mixed", `([a-\xff]+)!`, "ca\xe9!"},
	}
	for _, sh := range shapes {
		t.Run(sh.name, func(t *testing.T) {
			entry := config.RegexEntry{Pattern: sh.pat, GroupsFunc: "groups", ByteMode: true}
			// Forced, because auto-selection sends these to TDFA today. The
			// clamp is Backtracking's, so Backtracking is what must be asked.
			w, _, err := compile.CompileForced([]config.RegexEntry{entry},
				pathsTableBase, true, compile.EngineBacktrack)
			if err != nil {
				t.Fatalf("compile: %v", err)
			}
			store, inst, mem, release, err := instantiate(w)
			defer release()
			if err != nil {
				t.Fatalf("instantiate: %v", err)
			}
			copy(mem.UnsafeData(store)[pathsInputBase:], sh.input)
			res, cerr := inst.GetFunc(store, "groups").Call(store,
				pathsInputBase, int32(len(sh.input)), pathsOutBase, int32(0))
			if cerr != nil {
				t.Fatalf("groups call: %v", cerr)
			}
			if got := res.(int32); got < 0 {
				t.Errorf("Backtracking: pattern %q over %q returned %d, want a match\n"+
					"  byte_mode declares runes 0x80-0xFF to mean those BYTES",
					sh.pat, sh.input, got)
			}
		})
	}
}

// compileFindBT compiles with MaxDFAStates = -1, which makes every DFA
// overflow so find is emitted by the BACKTRACKING engine — the same mechanism
// re2test's --force-backtrack uses. Nothing else in this package reaches
// appendBTFindCodeEntry's find path, so without this the BT find emitter has
// no iteration coverage at all.
func compileFindBT(pat string) ([]byte, error) {
	w, _, err := compile.Compile([]config.RegexEntry{{Pattern: pat, FindFunc: "find"}},
		tableBase, true, compile.CompileOptions{MaxDFAStates: -1})
	return w, err
}

// btIterSeeds are shapes with a LEADING zero-width assertion, driven through
// the BT find emitter. A pattern without one answers the same whether the
// engine sees the whole buffer or a narrowed slice, so only these can show
// whether BT is reading real left context.
var btIterSeeds = []struct{ pat, input string }{
	{`\bfoo`, "foofoo"},
	{`\Bfoo`, "xfoofoo"},
	{`\Ba`, "aaa"},
	{`(?m:^)a`, "a\naa"},
	{`\B|a+b`, "1112"},
	{`a+`, "xaayaaa"}, // no assertion: guards against the conversion
	{`a*`, "bab"},     // breaking the ordinary cases
	{`(?:cat|car)`, "the cat in a car"},
}

func TestBTFindIterationMatchesGo(t *testing.T) {
	for _, c := range btIterSeeds {
		t.Run(c.pat+"/"+c.input, func(t *testing.T) {
			re, err := regexp.Compile(c.pat)
			if err != nil {
				// btIterSeeds are hardcoded and valid, so Go cannot reject one.
				// If it does, something is wrong that a skip would hide behind
				// a green test.
				t.Fatalf("Go rejects %q: %v", c.pat, err)
			}
			w, err := compileFindBT(c.pat)
			if err != nil {
				// btIterSeeds are fixed shapes chosen to exercise the forced-BT
				// path, and nothing else in this package reaches it. A skip
				// here would let an emitter regression pass by deleting the
				// only coverage of the path under test.
				t.Fatalf("compile %q: %v", c.pat, err)
			}
			got, ok := wasmFindIter(t, w, c.input)
			if !ok {
				t.Skip("watchdog or BT overflow")
			}
			want := goFindAll(re, c.input)
			if fmtSpans(got) != fmtSpans(want) {
				t.Errorf("BT find iteration over %q:\n  got  %s\n  want %s",
					c.input, fmtSpans(got), fmtSpans(want))
			}
		})
	}
}
