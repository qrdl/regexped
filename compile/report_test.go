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
		"Report.level", "Report.module", "Report.patterns", "Report.schema", "Report.sets",
		"ReportCeiling.bytes", "ReportCeiling.exports", "ReportCeiling.formula", "ReportCeiling.memory",
		"ReportCeiling.what", "ReportCeiling.when",
		"ReportModule.bytes", "ReportModule.in_set", "ReportModule.kind", "ReportModule.max_memory",
		"ReportModule.patterns_total", "ReportModule.prefix_dedup_pool_size", "ReportModule.static_bytes",
		"ReportPattern.code_bytes", "ReportPattern.engine", "ReportPattern.engine_reason", "ReportPattern.expanded",
		"ReportPattern.exports", "ReportPattern.find", "ReportPattern.find_reason", "ReportPattern.limits",
		"ReportPattern.max_input", "ReportPattern.memory", "ReportPattern.memory_ceilings", "ReportPattern.mode",
		"ReportPattern.name", "ReportPattern.opts", "ReportPattern.regexp", "ReportPattern.scan",
		"ReportPattern.scan_detail", "ReportPattern.switch_to", "ReportPattern.table_bytes",
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
