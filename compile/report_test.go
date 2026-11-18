package compile

import (
	"bytes"
	"encoding/json"
	"errors"
	"path/filepath"
	"reflect"
	"sort"
	"strings"
	"testing"

	"github.com/qrdl/regexped/config"
	"github.com/qrdl/regexped/internal/abi"
	"github.com/qrdl/regexped/internal/utils"
)

// jsonFields lists every JSON field name t marshals to, recursively, as
// "Type.field" — the shape TestReportSchemaFields pins.
func jsonFields(t reflect.Type, seen map[reflect.Type]bool, out *[]string) {
	for t.Kind() == reflect.Pointer || t.Kind() == reflect.Slice || t.Kind() == reflect.Map {
		t = t.Elem()
	}
	if t.Kind() != reflect.Struct || seen[t] {
		return
	}
	seen[t] = true
	for i := 0; i < t.NumField(); i++ {
		f := t.Field(i)
		if f.Anonymous {
			jsonFields(f.Type, seen, out)
			continue
		}
		tag := strings.Split(f.Tag.Get("json"), ",")[0]
		if tag == "-" || !f.IsExported() {
			continue
		}
		*out = append(*out, t.Name()+"."+tag)
		jsonFields(f.Type, seen, out)
	}
}

// TestReportSchemaFields pins the JSON report's fields. A field renamed or
// removed is a BREAKING change: bump ReportSchema, then update this list. A
// field added only extends the list. docs/cli.md states the rule.
func TestReportSchemaFields(t *testing.T) {
	if ReportSchema != 1 {
		t.Fatalf("ReportSchema is %d: update the pinned list below with it", ReportSchema)
	}
	var got []string
	jsonFields(reflect.TypeOf(Report{}), map[reflect.Type]bool{}, &got)
	sort.Strings(got)
	want := []string{
		"ACTableDiag.byte_classes", "ACTableDiag.bytes", "ACTableDiag.compressed", "ACTableDiag.nodes",
		"ACTableDiag.probe_columns", "ACTableDiag.stride", "ACTableDiag.verify_column",
		"AnchoredUnionDiag.num_classes", "AnchoredUnionDiag.refused", "AnchoredUnionDiag.state_width",
		"AnchoredUnionDiag.states", "AnchoredUnionDiag.used", "AnchoredUnionDiag.wide",
		"BucketDiag.accept_kind", "BucketDiag.id", "BucketDiag.literal", "BucketDiag.member_skip_char_states",
		"BucketDiag.member_skip_sets", "BucketDiag.member_skip_states", "BucketDiag.patterns",
		"BucketDiag.suffix_states", "BucketDiag.table_bytes", "BucketDiag.type",
		"ConflictDiag.candidate_bucket", "ConflictDiag.detail", "ConflictDiag.pattern", "ConflictDiag.reason",
		"FrontendDemotionDiag.detail", "FrontendDemotionDiag.from", "FrontendDemotionDiag.reason", "FrontendDemotionDiag.to",
		"PatternRef.id", "PatternRef.name",
		"Report.level", "Report.module", "Report.patterns", "Report.schema", "Report.sets", "ReportCacheFit.inputs",
		"ReportCeiling.bytes", "ReportCeiling.exports", "ReportCeiling.formula", "ReportCeiling.memory",
		"ReportCeiling.what", "ReportCeiling.when",
		"ReportModule.bytes", "ReportModule.in_set", "ReportModule.kind", "ReportModule.max_memory",
		"ReportModule.patterns_total", "ReportModule.prefix_dedup_pool_size", "ReportModule.static_bytes",
		"ReportPattern.code_bytes", "ReportPattern.engine", "ReportPattern.engine_reason", "ReportPattern.expanded",
		"ReportPattern.exports", "ReportPattern.find", "ReportPattern.find_reason", "ReportPattern.limits",
		"ReportPattern.max_input", "ReportPattern.memory", "ReportPattern.memory_ceilings", "ReportPattern.mode",
		"ReportPattern.name", "ReportPattern.opts", "ReportPattern.regexp", "ReportPattern.scan",
		"ReportPattern.scan_detail", "ReportPattern.switch_to", "ReportPattern.table_bytes",
		"ReportRange.from", "ReportRange.to", "ReportSet.answer_cache",
		"ReportSet.bucket_count", "ReportSet.capabilities", "ReportSet.code_bytes", "ReportSet.frontend",
		"ReportSet.max_input", "ReportSet.memory", "ReportSet.memory_ceilings", "ReportSet.members",
		"ReportSet.name", "ReportSet.split_out",
		"ReportSizes.16MiB", "ReportSizes.1KiB", "ReportSizes.1MiB", "ReportSizes.64KiB",
		"ScanUnionDiag.counter", "ScanUnionDiag.direct", "ScanUnionDiag.states", "ScanUnionDiag.wide",
		"SetDiag.anchored_backtracking", "SetDiag.anchored_union", "SetDiag.ac_table", "SetDiag.bare_body_shape",
		"SetDiag.buckets", "SetDiag.cache_bytes_per_byte", "SetDiag.capabilities", "SetDiag.conflicts",
		"SetDiag.frontend", "SetDiag.frontend_demotion", "SetDiag.id_space_size", "SetDiag.in_call_counter",
		"SetDiag.kept_cache", "SetDiag.max_lookback", "SetDiag.mode", "SetDiag.name",
		"SetDiag.no_cache_split_backtracking", "SetDiag.no_cache_split_members", "SetDiag.overlapping",
		"SetDiag.scan_union", "SetDiag.search_blocks", "SetDiag.search_blocks_bt_memo",
		"SetDiag.sparse_split_members", "SetDiag.split_backtracking", "SetDiag.split_members",
		"SetDiag.union_scan", "SetDiag.whole_set_sweep",
		"UnionScanDiag.mask_words", "UnionScanDiag.phase2", "UnionScanDiag.refused", "UnionScanDiag.states",
		"UnionScanDiag.used", "UnionScanDiag.wide",
		"WholeSetSweepDiag.cells", "WholeSetSweepDiag.states",
	}
	sort.Strings(want)
	if !reflect.DeepEqual(got, want) {
		t.Errorf("the report's fields changed — a rename or removal must bump ReportSchema:\ngot  %q\nwant %q", got, want)
	}
}

// TestParseVerbose: the values the two flags take, and what they refuse.
func TestParseVerbose(t *testing.T) {
	for in, want := range map[string]VerboseLevel{"": VerboseBrief, "true": VerboseBrief, "brief": VerboseBrief, "full": VerboseFull} {
		if got, err := ParseVerboseLevel(in); err != nil || got != want {
			t.Errorf("ParseVerboseLevel(%q) = %q, %v", in, got, err)
		}
	}
	for in, want := range map[string]VerboseFormat{"": VerbosePlain, "plain": VerbosePlain, "json": VerboseJSON} {
		if got, err := ParseVerboseFormat(in); err != nil || got != want {
			t.Errorf("ParseVerboseFormat(%q) = %q, %v", in, got, err)
		}
	}
	if _, err := ParseVerboseLevel("false"); err == nil {
		t.Error("--verbose=false was accepted")
	}
	if _, err := ParseVerboseFormat("yaml"); err == nil {
		t.Error("--verbose-format=yaml was accepted")
	}
}

// reportOf compiles cfg and returns its full report.
func reportOf(t *testing.T, cfg config.BuildConfig) Report {
	t.Helper()
	rep := &Reporter{}
	if _, err := CompileModule(cfg, rep); err != nil {
		t.Fatalf("CompileModule: %v", err)
	}
	return rep.Report(VerboseFull)
}

// TestReportPlainAndJSONAgree: the text and the JSON are two renderings of one
// Report, so every value the text shows is in the JSON.
func TestReportPlainAndJSONAgree(t *testing.T) {
	cfg := config.BuildConfig{ImportModule: "m", MaxMemory: mustMemorySize(t, "16MiB"),
		Patterns: []config.PatternEntry{
			{Name: "word", Regexp: `[a-z]+ing\b`, FindFunc: "wf"},
			{Name: "kv", Regexp: `(\w+)=(a+|ab)c`, GroupsFunc: "kg"},
		},
		Sets: []config.SetConfig{{Name: "s", Find: "sf", Patterns: config.PatternSelector{All: true}}}}
	rep := &Reporter{}
	if _, err := CompileModule(cfg, rep); err != nil {
		t.Fatal(err)
	}
	var text, js bytes.Buffer
	if err := rep.Write(&text, VerboseFull, VerbosePlain); err != nil {
		t.Fatal(err)
	}
	if err := rep.Write(&js, VerboseFull, VerboseJSON); err != nil {
		t.Fatal(err)
	}
	var r Report
	if err := json.Unmarshal(js.Bytes(), &r); err != nil {
		t.Fatal(err)
	}
	for _, p := range r.Patterns {
		for _, v := range []string{p.Name, p.Engine, p.Find, p.SwitchTo, p.Scan, p.Memory} {
			if !strings.Contains(text.String(), v) {
				t.Errorf("the text lacks %q, which the JSON carries", v)
			}
		}
		for _, c := range p.Ceilings {
			if !strings.Contains(text.String(), c.What) || !strings.Contains(text.String(), c.Formula) {
				t.Errorf("the text lacks the ceiling %q %q", c.What, c.Formula)
			}
		}
		if len(p.MaxInput) == 0 {
			t.Errorf("%s: no max_input under max_memory", p.Name)
		}
	}
}

// TestReportHelpers: the units the renderers and the max-input search stand
// on, at each of their branches.
func TestReportHelpers(t *testing.T) {
	for n, want := range map[int64]string{512: "512 B", 2048: "2.0 KiB", 3 << 20: "3.0 MiB", 5 << 30: "5.0 GiB"} {
		if got := humanBytes(n); got != want {
			t.Errorf("humanBytes(%d) = %q, want %q", n, got, want)
		}
	}
	if wideNote(true) != ", wide accept" || wideNote(false) != "" {
		t.Error("wideNote")
	}
	linear := memTerm{what: "x", exports: []string{"find"}, size: func(n int64) int64 { return 100 * n }}
	fixed := memTerm{what: "y", exports: []string{"find"}, module: true, size: func(int64) int64 { return 1 << 20 }}
	m := moduleReport{standalone: true, staticBytes: 1 << 20, maxMemory: 8 << 20}
	if got := maxInputs([]string{"find"}, []memTerm{linear}, moduleReport{}); got != nil {
		t.Errorf("no max_memory: %v, want nil", got)
	}
	got := maxInputs([]string{"find", "match"}, []memTerm{linear}, m)
	// static 1 MiB + one page + pageAlign(100 n) <= 8 MiB.
	if n := got["find"]; n <= 0 || 1<<20+65536+((100*n+65535)&^65535) > 8<<20 || got["match"] != -1 {
		t.Errorf("max inputs %v", got)
	}
	if got := maxInputs([]string{"find"}, []memTerm{fixed}, moduleReport{staticBytes: 8 << 20, maxMemory: 8 << 20}); got["find"] != 0 {
		t.Errorf("nothing fits: %v, want 0", got)
	}
	if got := maxInputs([]string{"find"}, []memTerm{linear}, moduleReport{staticBytes: 1 << 20, maxMemory: 8 << 20}); got["find"] != -1 {
		t.Errorf("a caller term in an embedded module does not count: %v, want -1", got)
	}

	// A scan recorded in a body that is then replaced goes with its note.
	r := &Reporter{}
	r.Begin("p", "x")
	r.Note("kept")
	mark := r.noteMark()
	r.scan("Teddy", "prefix scan: 1-byte Teddy")
	r.truncateNotes(mark)
	r.End()
	if p := r.Patterns[0]; len(p.scans) != 0 || len(p.Notes) != 1 {
		t.Errorf("truncate left %+v", p)
	}
	// An assembly-time body reports to an ended pattern.
	r.scanFor(1, "SIMD literal", "prefix scan: hybrid SIMD, 3-byte prefix")
	if p := r.Patterns[0]; len(p.scans) != 1 || p.scans[0].kind != "SIMD literal" {
		t.Errorf("scanFor: %+v", p)
	}
	(*Reporter)(nil).scanFor(1, "", "")
	(*Reporter)(nil).NoteCompile(config.BuildConfig{}, nil, false)
	(*Reporter)(nil).truncateNotes(0)
}

// TestReportSetRendering: every part of a set's composition the full text
// shows.
func TestReportSetRendering(t *testing.T) {
	r := &Reporter{Sets: []SetDiag{{
		Name: "s", Frontend: "ac", Capabilities: []string{"match_any", "scan_any", "find"}, MaxLookback: 3,
		Buckets:       []BucketDiag{{ID: 0, Literal: "foo", AcceptKind: "sparse", Type: "sparse-set", MemberSkipStates: 2, MemberSkipSets: 1}},
		ACTable:       &ACTableDiag{Nodes: 9, Bytes: 900, Compressed: true, ByteClasses: 7},
		UnionScan:     &UnionScanDiag{Used: true, States: 5, Wide: true},
		AnchoredUnion: &AnchoredUnionDiag{Refused: "construction"},
		KeptCache:     true, SparseSplitMembers: []int{2},
	}, {
		Name: "t", Frontend: "scalar", Capabilities: []string{"match_all", "scan_all"},
		UnionScan:     &UnionScanDiag{Refused: "id_space"},
		AnchoredUnion: &AnchoredUnionDiag{Used: true, States: 4},
	}}}
	var b bytes.Buffer
	r.Render(&b)
	for _, want := range []string{
		"max lookback: 3", "member skip 2 states / 1 sets", "Aho-Corasick: 9 nodes, 900 bytes, 7 byte classes",
		"scan pair: union automaton, 5 states, wide accept", "match pair: per-bucket probes (union automaton refused: construction)",
		"the kept members' own set reads the answer cache", "sparse counter's split copy serves: #2 (start-anywhere)",
		"scan pair: per-position walk (union automaton refused: id_space)", "match pair: union automaton, 4 states\n",
	} {
		if !strings.Contains(b.String(), want) {
			t.Errorf("missing %q:\n%s", want, b.String())
		}
	}
}

// TestReportSetBacktrackingMembers: a set whose members run on Backtracking —
// in a bucket for find and the scan pair, and as an anchored probe for the
// match pair — reports each one's scratch, in an embedded module.
func TestReportSetBacktrackingMembers(t *testing.T) {
	huge := `(?:a|b)*a(?:a|b){12}c`
	cfg := config.BuildConfig{ImportModule: "m", Output: "merged.wasm", MaxMemory: mustMemorySize(t, "64MiB"),
		Patterns: []config.PatternEntry{{Name: "huge", Regexp: huge}, {Name: "foo", Regexp: `foo`}},
		Sets: []config.SetConfig{{Name: "s", Find: "sf", ScanAny: "sa", MatchAny: "ma",
			Patterns: config.PatternSelector{All: true}}}}
	r := reportOf(t, cfg)
	if r.Module.Kind != "embedded module" {
		t.Errorf("kind %q", r.Module.Kind)
	}
	s := r.Sets[0]
	var stack, anchored bool
	for _, c := range s.Ceilings {
		stack = stack || strings.HasPrefix(c.What, "Backtracking frame stack (split member huge)")
		anchored = anchored || strings.HasPrefix(c.What, "Backtracking frame stack (member huge, anchored)")
		if c.What == "input copy" {
			t.Error("an embedded module's report counts an input copy")
		}
	}
	if !stack || !anchored {
		t.Errorf("the members' scratch is missing: %+v", s.Ceilings)
	}

	// max_dfa_states: 0 keeps every member in a Backtracking BUCKET.
	off := config.BuildConfig{ImportModule: "m", MaxDFAStates: config.LimitOff,
		Patterns: []config.PatternEntry{{Name: "d", Regexp: `foo\d+`}, {Name: "e", Regexp: `[a-z]+@x`}},
		Sets:     []config.SetConfig{{Name: "s", Find: "f", ScanAny: "sa", Patterns: config.PatternSelector{All: true}}}}
	found := false
	for _, c := range reportOf(t, off).Sets[0].Ceilings {
		found = found || c.What == "Backtracking frame stack (member d)"
	}
	if !found {
		t.Error("a Backtracking bucket member's scratch is missing")
	}
	if s.MaxInput["match"] <= 0 || s.MaxInput["scan"] <= 0 || s.MaxInput["find"] <= 0 {
		t.Errorf("max_input %v", s.MaxInput)
	}
}

type failingWriter struct{}

func (failingWriter) Write([]byte) (int, error) { return 0, errors.New("disk full") }

// TestReportWriteFails: a report that cannot be written fails the command,
// and a prefix too long for the SIMD scan is reported as the scalar one.
func TestReportWriteFails(t *testing.T) {
	cfg := config.BuildConfig{Patterns: []config.PatternEntry{{Regexp: `abc`, FindFunc: "f"}}}
	err := CmdCompileReport(cfg, filepath.Join(t.TempDir(), "o.wasm"), failingWriter{}, VerboseBrief, VerbosePlain)
	if err == nil || !strings.Contains(err.Error(), "write the report: disk full") {
		t.Errorf("err = %v", err)
	}
	if kind, _ := (prefixScanParams{Prefix: []byte("ééééééééé"), UTF8Text: true}).strategyNote(); kind != "scalar literal" {
		t.Errorf("a 17-byte prefix: %q", kind)
	}
}

// TestReportSearchKindsAndFixedStack: a groups-only pattern that can only
// match at 0 reports the capture body as its whole search, a Backtracking
// find names the refusal that sent it there, and a Backtracking body with no
// Alt — which pushes no frame — keeps a fixed stack that neither grows nor
// bounds max_input.
func TestReportSearchKindsAndFixedStack(t *testing.T) {
	cfg := config.BuildConfig{ImportModule: "m", Output: "merged.wasm", MaxMemory: mustMemorySize(t, "8MiB"),
		Patterns: []config.PatternEntry{
			{Name: "date", Regexp: `^(\d{4})-(\d{2})`, GroupsFunc: "dg"},
			{Name: "amb", Regexp: `(\b|0*)0`, FindFunc: "af"},
			{Name: "time", Regexp: `\b(\d\d):(\d\d)\b`, GroupsFunc: "tg"},
		}}
	byName := map[string]ReportPattern{}
	for _, p := range reportOf(t, cfg).Patterns {
		byName[p.Name] = p
	}
	if p := byName["date"]; p.Find != findKindAnchored || p.Scan != "anchored at 0" {
		t.Errorf("date: search %q (%s), scan %q; want %q, anchored at 0", p.Find, p.FindReason, p.Scan, findKindAnchored)
	}
	if p := byName["amb"]; p.Find != findKindBacktrack || !strings.Contains(p.FindReason, "ambiguous word-boundary target") ||
		strings.Contains(p.FindReason, "over the limits") {
		t.Errorf("amb: search %q, reason %q", p.Find, p.FindReason)
	}
	p := byName["time"]
	if p.Engine != "Backtracking" {
		t.Fatalf("time: engine %q, the test needs Backtracking", p.Engine)
	}
	if p.Memory != "constant" || p.MaxInput["groups"] != -1 {
		t.Errorf("time: memory %q, max_input %v; want constant and -1", p.Memory, p.MaxInput)
	}
	for _, c := range p.Ceilings {
		if strings.HasPrefix(c.What, "Backtracking frame stack") && (c.Bytes.KiB1 != c.Bytes.MiB16 || c.Formula != "65536 B") {
			t.Errorf("time: the stack grows: %+v", c)
		}
	}
}

// TestReportSetCompanionsAndForwardedScan: a set whose scan pair forwards to
// a split copy reports max_input for scan, files the copy's Backtracking
// scratch under scan rather than find, and counts every companion's code as
// the set's.
func TestReportSetCompanionsAndForwardedScan(t *testing.T) {
	cfg := config.BuildConfig{ImportModule: "m", MaxMemory: mustMemorySize(t, "64MiB"),
		Patterns: []config.PatternEntry{
			{Name: "a", Regexp: `foo\w+`},
			{Name: "b", Regexp: `a[ab]{12}c[a-z]*z`},
			{Name: "c", Regexp: `\bbar\b`},
		},
		Sets: []config.SetConfig{{Name: "s", Find: "f", ScanAll: "sa", Overlapping: true,
			Patterns: config.PatternSelector{All: true}}}}
	rep := &Reporter{}
	if _, err := CompileModule(cfg, rep); err != nil {
		t.Fatal(err)
	}
	for name := range rep.mod.setCode {
		if strings.IndexByte(name, 0) >= 0 {
			t.Errorf("code counted under the internal name %q", name)
		}
	}
	s := rep.Report(VerboseFull).Sets[0]
	if _, ok := s.MaxInput["scan"]; !ok {
		t.Errorf("max_input %v has no scan", s.MaxInput)
	}
	if s.CodeBytes != rep.mod.setCode["s"] || s.CodeBytes == 0 {
		t.Errorf("code_bytes %d, counted %d", s.CodeBytes, rep.mod.setCode["s"])
	}
	var scanBT bool
	for _, c := range s.Ceilings {
		if strings.Contains(c.What, "split member b") && reflect.DeepEqual(c.Exports, []string{"scan"}) {
			scanBT = true
		}
	}
	if !scanBT {
		t.Errorf("the scan copy's Backtracking member is not filed under scan: %+v", s.Ceilings)
	}
}

// TestReportSetBuffersAndComponentBlocks: the buffers a set's exports take
// beside the input count against max_memory, and in a component every
// caller-memory region is a power-of-two block with an 8-byte header.
func TestReportSetBuffersAndComponentBlocks(t *testing.T) {
	// One pattern selected, id 19,999: the gate array alone is 80,000 bytes.
	sm := setMemReport{find: true, members: 1, idSpace: 20000}
	js := moduleReport{standalone: true, staticBytes: 1 << 16, maxMemory: 4 << 20}
	buf := setBufferTerms(sm, js)
	if len(buf) != 1 || buf[0].size(0) != 12+80000+16+2500 || !buf[0].fixed {
		t.Fatalf("JS set buffers %+v", buf)
	}
	terms := append([]memTerm{inputTerm([]string{"find"})}, buf...)
	n := maxInputs([]string{"find"}, terms, js)["find"]
	if js.staticBytes+65536+((n+65535)&^65535)+131072 > js.maxMemory {
		t.Errorf("max_input %d leaves no room for the buffers", n)
	}
	if setBufferTerms(sm, moduleReport{}) != nil {
		t.Error("an embedded module's set buffers are the host's")
	}
	comp := moduleReport{standalone: true, component: true, staticBytes: 1 << 16, maxMemory: 4 << 20}
	if b := setBufferTerms(sm, comp)[0]; b.size(0) != componentBlock(repBytesBlocks)+componentBlock(80000)+componentBlock(12)+componentBlock(areaSetAll) {
		t.Errorf("component set buffers %d", b.size(0))
	}
	// With an answer cache its header is reserved too; batching widens the
	// tuple buffer to the default batch, overlapping aligns the gate region.
	sh := OverlapCacheShape{Eligible: true, Cells: 6, Patterns: 2}
	cached := setMemReport{find: true, members: 1, idSpace: 20000, cache: &sh}
	if got := setBufferTerms(cached, comp)[0].size(0) - setBufferTerms(sm, comp)[0].size(0); got != componentBlock(config.SetOverlapCheckpointHeaderBytes) {
		t.Errorf("component cache header %d", got)
	}
	batched := setMemReport{find: true, match: true, members: 1, idSpace: 3, batch: 256, overlapping: true, cache: &sh}
	bt := setBufferTerms(batched, js)
	if len(bt) != 2 || bt[1].size(0) != 12*256+((4*3+16+1+7)&^7)+config.SetOverlapCheckpointHeaderBytes ||
		bt[0].size(0) != 12+4*3+16+1 {
		t.Errorf("batched JS buffers %d, %d", bt[0].size(0), bt[1].size(0))
	}
	// Split members' search blocks, and a component `_all`'s id list.
	blocked := setMemReport{find: true, match: true, members: 100, idSpace: 100, blocks: make([]SearchSize, 3)}
	nb := setBufferTerms(blocked, js)
	plainSet := setMemReport{find: true, match: true, members: 100, idSpace: 100}
	if got := nb[1].size(0) - setBufferTerms(plainSet, js)[1].size(0); got != 24+3*abi.SearchBlockBytes {
		t.Errorf("JS search blocks %d", got)
	}
	cb := setBufferTerms(blocked, comp)
	if got := cb[1].size(0) - setBufferTerms(plainSet, comp)[1].size(0); got != componentBlock(3*abi.SearchBlockBytes) {
		t.Errorf("component search blocks %d", got)
	}
	if got := cb[0].size(0); got != componentBlock(areaSetAll)+componentBlock(16)+componentBlock(400) {
		t.Errorf("component _all buffers %d", got)
	}
	r := &Reporter{}
	r.NoteCompile(config.BuildConfig{}, nil, true)
	if !r.mod.component || !r.mod.standalone || r.mod.kind != "component core module" {
		t.Errorf("component module %+v", r.mod)
	}

	for in, want := range map[int64]int64{0: 16, 8: 16, 9: 32, 832 << 10: 1 << 20, 1<<20 - 8: 1 << 20, 1<<20 - 7: 2 << 20} {
		if got := componentBlock(in); got != want {
			t.Errorf("componentBlock(%d) = %d, want %d", in, got, want)
		}
	}
	// 832 KiB is a 1 MiB block: under a 1 MiB cap it cannot be lowered.
	capped := moduleReport{standalone: true, component: true, staticBytes: 1 << 16, maxMemory: 1 << 20}
	if n := maxInputs([]string{"find"}, []memTerm{inputTerm([]string{"find"})}, capped)["find"]; n >= 832<<10 || n <= 0 {
		t.Errorf("component max_input %d under 1 MiB", n)
	}
	c := ceilings([]memTerm{inputTerm([]string{"find"})}, capped)[0]
	if c.Bytes.KiB1 != 2048 || !strings.Contains(c.Formula, "power of two") {
		t.Errorf("component input ceiling %+v", c)
	}
}

// TestReportPatternBuffers: the buffers a pattern's exports take beside the
// input count against max_memory — a JS/TS batch buffer of 256 records, a
// groups call's slots, a component resource and its per-call lists.
func TestReportPatternBuffers(t *testing.T) {
	js := moduleReport{standalone: true, staticBytes: 1 << 16, maxMemory: 4 << 20}
	size := func(p PatternReport, m moduleReport) map[string]int64 {
		out := map[string]int64{}
		for _, b := range patternBufferTerms(p, m) {
			if !b.fixed || len(b.exports) != 1 {
				t.Fatalf("buffer term %+v", b)
			}
			out[b.exports[0]] = b.size(0)
		}
		return out
	}
	// 41 groups, batched: 256 × (8 + 8 × 41) = 86,016 bytes, over the one
	// page of slack exportTotal allows.
	wide := PatternReport{Exports: []string{"find", "groups"}, groups: 41, batch: true}
	if got := size(wide, js); got["groups"] != 86016 || got["find"] != 256*8 {
		t.Errorf("batched JS buffers %v", got)
	}
	terms := append([]memTerm{inputTerm(wide.Exports)}, patternBufferTerms(wide, js)...)
	if got := exportTotal("groups", terms, js)(0); got != js.staticBytes+65536+utils.PageAlign(86016) {
		t.Errorf("groups total at 0 bytes: %d", got)
	}
	if got := size(PatternReport{Exports: []string{"find", "groups"}, groups: 3}, js); got["groups"] != 24 || len(got) != 1 {
		t.Errorf("plain JS buffers %v", got)
	}
	if patternBufferTerms(wide, moduleReport{}) != nil {
		t.Error("an embedded module's buffers are the host's")
	}
	comp := moduleReport{standalone: true, component: true, staticBytes: 1 << 16, maxMemory: 4 << 20}
	plain := PatternReport{Exports: []string{"match", "find", "groups"}, groups: 3, batch: true}
	got := size(plain, comp)
	if got["match"] != componentBlock(areaMatch) ||
		got["find"] != componentBlock(int64(patRepSize(false, 0)))+componentBlock(areaFind) ||
		got["groups"] != componentBlock(int64(patRepSize(true, 3)))+componentBlock(areaSetAll)+componentBlock(3*groupElemLen) {
		t.Errorf("component buffers %v", got)
	}
	plain.Search = SearchSize{NotesBytes: 1}
	if got := size(plain, comp)["groups"]; got != componentBlock(int64(patRepBlockOff(3))+abi.SearchBlockBytes)+componentBlock(areaSetAll)+componentBlock(3*groupElemLen) {
		t.Errorf("component groups with a search block %d", got)
	}

	// The real compile records the group count and the batch hint.
	cfg := config.BuildConfig{ImportModule: "m", MaxMemory: mustMemorySize(t, "8MiB"),
		Patterns: []config.PatternEntry{{Regexp: `(a+)(b)`, GroupsFunc: "g", FindFunc: "f", Hints: []string{"batch-find"}}}}
	var found bool
	for _, c := range reportOf(t, cfg).Patterns[0].Ceilings {
		if c.What == "output buffers (groups)" && c.Formula == "8192 B" {
			found = true
		}
	}
	if !found {
		t.Errorf("no 8,192-byte groups buffer: %+v", reportOf(t, cfg).Patterns[0].Ceilings)
	}
}

// TestReportAnswerCacheFit: the answer cache is not part of max_input — the
// find walks without it — and where it fits is not one range, because its
// region shrinks where it starts checkpointing.
func TestReportAnswerCacheFit(t *testing.T) {
	sh := OverlapCacheShape{Eligible: true, Cells: 6, Patterns: 2}
	m := moduleReport{standalone: true, staticBytes: 1 << 16, maxMemory: 6 << 20}
	sm := setMemReport{find: true, members: 2, idSpace: 2, cache: &sh}
	terms := setTerms(sm, m)
	n := maxInputs([]string{"find"}, terms, m)["find"]
	if n < 6_000_000 {
		t.Errorf("max_input %d: the cache bounds it", n)
	}
	fit := cacheFit(sh, terms, m)
	if fit == nil || len(fit.Inputs) != 2 || fit.Inputs[0].From != 0 {
		t.Fatalf("cache fit %+v", fit)
	}
	base := exportTotal("find", terms, m)
	fits := func(n int64) bool {
		b, _ := sh.Sizing(int(n))
		return base(n)+utils.PageAlign(int64(b)) <= m.maxMemory
	}
	for _, r := range fit.Inputs {
		if !fits(r.From) || !fits(r.To) || fits(r.To+1) || r.From > 0 && fits(r.From-1) {
			t.Errorf("range %+v is not a maximal fitting stretch", r)
		}
	}
	// The checkpointed stretch: 5.8 MB fits with its cache, 1 MB does not.
	if r := fit.Inputs[1]; r.From > 5_800_000 || r.To < 5_800_000 || fit.Inputs[0].To >= 1_000_000 {
		t.Errorf("cache fit %+v", fit.Inputs)
	}
	if got := cacheFitText(fit.Inputs); !strings.Contains(got, " – ") || !strings.Contains(got, "walks") {
		t.Errorf("text %q", got)
	}
	if cacheFitText(nil) != "never — the find walks at every length" ||
		cacheFitText([]ReportRange{{0, maxInputSearchCap}}) != "every length" ||
		!strings.Contains(cacheFitText([]ReportRange{{5, maxInputSearchCap}}), "and longer") {
		t.Error("cacheFitText edge cases")
	}
	if cacheFit(sh, terms, moduleReport{}) != nil {
		t.Error("no max_memory, still a cache fit")
	}
	// Room for everything: the stretches either side of the switch join.
	big := moduleReport{standalone: true, staticBytes: 1 << 16, maxMemory: 1 << 40}
	if got := cacheFit(sh, setTerms(sm, big), big); len(got.Inputs) != 1 || cacheFitText(got.Inputs) != "every length" {
		t.Errorf("unbounded cache fit %+v", got.Inputs)
	}
	// Inside a checkpointed regime the region shrinks by a few bytes where
	// the stride steps up: 50,803,198 bytes take a 262,148-byte cache (5
	// pages), 50,803,199 a 262,132-byte one (4). Under a cap that fits 4
	// pages there, the ranges are exactly the lengths that fit.
	edge := int64(50_803_199)
	if b, _ := sh.Sizing(int(edge)); b != 262_132 {
		t.Fatalf("the cache at %d is %d bytes; pick the stride step again", edge, b)
	}
	tight := moduleReport{standalone: true, staticBytes: 1 << 16}
	tight.maxMemory = exportTotal("find", setTerms(sm, tight), tight)(edge) + 4*65536
	tterms := setTerms(sm, tight)
	tbase := exportTotal("find", tterms, tight)
	tfits := func(n int64) bool {
		b, _ := sh.Sizing(int(n))
		return tbase(n)+utils.PageAlign(int64(b)) <= tight.maxMemory
	}
	if !tfits(edge) || tfits(edge-1) {
		t.Fatalf("the cap does not single out %d", edge)
	}
	tfit := cacheFit(sh, tterms, tight)
	in := func(n int64) bool {
		for _, r := range tfit.Inputs {
			if r.From <= n && n <= r.To {
				return true
			}
		}
		return false
	}
	for n := edge - 200_000; n <= edge+200_000; n++ {
		if in(n) != tfits(n) {
			t.Fatalf("length %d: reported %v, fits %v (ranges %+v)", n, in(n), tfits(n), tfit.Inputs)
		}
	}
	// A program sweep's part has a regime of its own.
	sw := OverlapCacheShape{Eligible: true, Cells: 6, Patterns: 2, SweepCells: 4, SweepRow: 4}
	if sw.sizingRegime(0) != 0 || sw.sizingRegime(1<<30)&2 == 0 {
		t.Errorf("sweep regimes %d, %d", sw.sizingRegime(0), sw.sizingRegime(1<<30))
	}
	// A 1 MiB row: at 1 GiB of input even the checkpointed part is over the
	// budget, and drops out.
	wide := OverlapCacheShape{SweepCells: 4, SweepRow: 1 << 20}
	if wide.sizingRegime(0) != 0 || wide.sizingRegime(1<<30) != 2|4 {
		t.Errorf("wide sweep regimes %d, %d", wide.sizingRegime(0), wide.sizingRegime(1<<30))
	}

	// The real compile: a batching overlapping set with a cache, rendered.
	cfg := config.BuildConfig{ImportModule: "m", MaxMemory: mustMemorySize(t, "6MiB"),
		Patterns: []config.PatternEntry{{Name: "p1", Regexp: `[a-z]+x`}, {Name: "p2", Regexp: `[a-z]*y`}},
		Sets: []config.SetConfig{{Name: "s", Find: "sf", Overlapping: true, Hints: []string{"batch-find"},
			Patterns: config.PatternSelector{All: true}}}}
	rep := &Reporter{}
	if _, err := CompileModule(cfg, rep); err != nil {
		t.Fatal(err)
	}
	if rep.setMem["s"].batch != config.SetDefaultBatchCap(2) {
		t.Errorf("batch %d", rep.setMem["s"].batch)
	}
	var b bytes.Buffer
	if err := rep.Write(&b, VerboseFull, VerbosePlain); err != nil || !strings.Contains(b.String(), "answer cache under max_memory: inputs of 0 B – ") {
		t.Errorf("err %v, report:\n%s", err, b.String())
	}
}
