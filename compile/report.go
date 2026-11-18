package compile

import (
	"bytes"
	"encoding/json"
	"fmt"
	"io"
	"regexp/syntax"
	"sort"
	"strconv"
	"strings"

	"github.com/qrdl/regexped/config"
	"github.com/qrdl/regexped/internal/utils"
)

// ── The --verbose report ───────────────────────────────────────────────────
//
// ONE structure, filled by the compile that builds the module (the Reporter's
// recorders, each called where the emitter that decides it runs), and
// rendered twice: as text and as JSON, at two levels. The renderers read only
// the Report built here, so the two formats cannot carry different
// information — and nothing re-runs a compile to describe it, which is how the
// old --diag-json once described a NEUTRAL set for a hinted config.

// ReportSchema is the JSON report's version. It is bumped on a BREAKING
// change only — a field renamed or removed, or a field's meaning or value set
// changed; a new field does not bump it. TestReportSchemaFields pins the field
// set, so a change that should have bumped it fails there.
const ReportSchema = 1

// VerboseLevel is how much the report says: one line per pattern and set, or
// everything.
type VerboseLevel string

// VerboseFormat is how the report is written.
type VerboseFormat string

const (
	VerboseBrief VerboseLevel  = "brief"
	VerboseFull  VerboseLevel  = "full"
	VerbosePlain VerboseFormat = "plain"
	VerboseJSON  VerboseFormat = "json"
)

// ParseVerboseLevel reads a --verbose value; "true" is what a bare flag sets.
func ParseVerboseLevel(s string) (VerboseLevel, error) {
	switch s {
	case "", "true", string(VerboseBrief):
		return VerboseBrief, nil
	case string(VerboseFull):
		return VerboseFull, nil
	}
	return "", fmt.Errorf("--verbose=%q: want brief or full", s)
}

// ParseVerboseFormat reads a --verbose-format value.
func ParseVerboseFormat(s string) (VerboseFormat, error) {
	switch s {
	case "", string(VerbosePlain):
		return VerbosePlain, nil
	case string(VerboseJSON):
		return VerboseJSON, nil
	}
	return "", fmt.Errorf("--verbose-format=%q: want plain or json", s)
}

// Report is the --verbose report. At the brief level only the brief fields
// are set; full adds the rest, in the same structure, so a script written
// against brief keeps working on full.
type Report struct {
	Schema   int             `json:"schema"`
	Level    VerboseLevel    `json:"level"`
	Module   *ReportModule   `json:"module,omitempty"`
	Patterns []ReportPattern `json:"patterns"`
	Sets     []ReportSet     `json:"sets"`
}

// ReportModule is the module as a whole (full only).
type ReportModule struct {
	// Kind is "standalone module", "embedded module" or "component core
	// module"; Bytes its size.
	Kind  string `json:"kind"`
	Bytes int    `json:"bytes"`
	// StaticBytes is the memory the module declares at load: its tables,
	// page-aligned. MaxMemory is the max_memory cap in bytes (rounded down to
	// whole pages, as the module declares it); 0 when unset.
	StaticBytes int64 `json:"static_bytes"`
	MaxMemory   int64 `json:"max_memory,omitempty"`
	// PatternsTotal counts patterns: entries, InSet the members of all sets,
	// PrefixDedupPoolSize the prefix tables the sets share.
	PatternsTotal       int `json:"patterns_total"`
	InSet               int `json:"in_set"`
	PrefixDedupPoolSize int `json:"prefix_dedup_pool_size"`
}

// ReportPattern is one pattern.
type ReportPattern struct {
	Name string `json:"name"`
	// Exports are the export kinds: match, find, groups.
	Exports []string `json:"exports"`
	// Engine is the engine, or what replaced one ("specialised body", or
	// "none" for an entry that exports nothing).
	Engine string `json:"engine"`
	// Find is the kind of search behind find and groups: "linear",
	// "switch", "start-anywhere", "suffix", "unswitched", "specialised",
	// "Backtracking"; SwitchTo what a switch hands over to.
	Find     string `json:"find,omitempty"`
	SwitchTo string `json:"switch_to,omitempty"`
	// Scan is how the search finds candidate starts ("none" when it tries
	// every position).
	Scan string `json:"scan,omitempty"`
	// Memory is "constant", or "grows with input: <what>".
	Memory string `json:"memory"`

	// Full only.
	Regexp       string           `json:"regexp,omitempty"`
	Expanded     string           `json:"expanded,omitempty"`
	Mode         string           `json:"mode,omitempty"`
	EngineReason string           `json:"engine_reason,omitempty"`
	FindReason   string           `json:"find_reason,omitempty"`
	ScanDetail   string           `json:"scan_detail,omitempty"`
	Limits       []string         `json:"limits,omitempty"`
	Opts         []string         `json:"opts,omitempty"`
	TableBytes   int64            `json:"table_bytes,omitempty"`
	CodeBytes    int              `json:"code_bytes,omitempty"`
	Ceilings     []ReportCeiling  `json:"memory_ceilings,omitempty"`
	MaxInput     map[string]int64 `json:"max_input,omitempty"`
}

// ReportSet is one set. The embedded SetDiag (full only) carries everything
// the set's composition decided; a field of the same name here (name,
// capabilities, frontend) hides SetDiag's, and holds the same value.
type ReportSet struct {
	Name         string   `json:"name"`
	Capabilities []string `json:"capabilities"`
	Members      int      `json:"members"`
	Frontend     string   `json:"frontend"`
	BucketCount  int      `json:"bucket_count"`
	SplitOut     int      `json:"split_out"`
	Memory       string   `json:"memory"`

	*SetDiag
	// CodeBytes is the set's function bodies' bytes, its members'
	// Backtracking bodies included (full only).
	CodeBytes int              `json:"code_bytes,omitempty"`
	Ceilings  []ReportCeiling  `json:"memory_ceilings,omitempty"`
	MaxInput  map[string]int64 `json:"max_input,omitempty"`
}

// ReportCeiling is one region whose size depends on the input: the most it
// can take for an input of len bytes, as a formula and at fixed lengths. A
// ceiling, not what a given input uses.
type ReportCeiling struct {
	What string `json:"what"`
	// Exports are the exports that can need it.
	Exports []string `json:"exports"`
	// Memory is whose memory it is in: "module" (counts against max_memory),
	// or "caller" — the stub's or host's allocation, which is in the module's
	// memory, and counts, for a standalone module or a component, and in the
	// host's own for an embedded one.
	Memory  string      `json:"memory"`
	When    string      `json:"when"`
	Formula string      `json:"formula"`
	Bytes   ReportSizes `json:"bytes"`
}

// ReportSizes is a ceiling's value at four input lengths.
type ReportSizes struct {
	KiB1  int64 `json:"1KiB"`
	KiB64 int64 `json:"64KiB"`
	MiB1  int64 `json:"1MiB"`
	MiB16 int64 `json:"16MiB"`
}

// ── Recorded facts ─────────────────────────────────────────────────────────

// Find kinds (ReportPattern.Find).
const (
	findKindLinear      = "linear"
	findKindSwitch      = "switch"
	findKindStartAny    = "start-anywhere"
	findKindSuffix      = "suffix"
	findKindUnswitched  = "unswitched"
	findKindSpecialised = "specialised"
	findKindBacktrack   = "Backtracking"
)

// scanRecord is one scan strategy a find body chose: a short kind for the
// brief report, and the note that says it in full.
type scanRecord struct {
	note int // index of its note in PatternReport.Notes
	kind string
}

// btBodyReport is one Backtracking body: what its run-time scratch
// (bt_scratch.go) can grow to.
type btBodyReport struct {
	body    string   // "match", "find", "capture", "member"
	exports []string // the exports that run it
	// alts bounds the frames the current path holds per position
	// (epsAltDepth); frame is a frame's bytes.
	alts, frame int
	// rowBytes is one fallback memo row; start the ordinary stack's first
	// allocation.
	rowBytes, start int
	fallback, force bool
}

// moduleReport is what the report says about the whole module.
type moduleReport struct {
	kind                  string
	bytes                 int
	staticBytes           int64
	standalone, component bool
	maxMemory             int64
	patternsTotal, inSet  int
	prefixPool            int
	set                   bool // filled by a compile
	setMembers            map[string]int
	setCode               map[string]int
}

// setMemReport is one set's memory.
type setMemReport struct {
	name string
	// find, scan, match: the capabilities, by family.
	find, scan, match bool
	// blocks are the find's per-search blocks.
	blocks []SearchSize
	// cache is the overlapping find's answer cache, nil without one.
	cache *OverlapCacheShape
	// bt are the Backtracking bodies one call of the set can run, each with
	// its own fallback memo (a set member's lasts the host call).
	bt []btBodyReport
}

// Exports records the export kinds the open pattern declares.
func (r *Reporter) setExports(re config.PatternEntry) {
	if r == nil || r.cur == nil {
		return
	}
	r.cur.Exports = nil
	if re.MatchFunc != "" {
		r.cur.Exports = append(r.cur.Exports, "match")
	}
	if re.FindFunc != "" {
		r.cur.Exports = append(r.cur.Exports, "find")
	}
	if re.CaptureStubsRequested() {
		r.cur.Exports = append(r.cur.Exports, "groups")
	}
}

// findKind records the open pattern's find kind and the classifier's reason.
func (r *Reporter) findKind(kind, why string) {
	if r == nil || r.cur == nil {
		return
	}
	r.cur.Find, r.cur.FindWhy = kind, why
}

// switchTo records what the open pattern's switch hands over to.
func (r *Reporter) switchTo(target string) {
	if r == nil || r.cur == nil {
		return
	}
	r.cur.SwitchTo = target
}

// scan records a find body's scan strategy: kind for the brief report, note
// (a full sentence) as one of the pattern's notes.
func (r *Reporter) scan(kind, note string) {
	if r == nil || r.cur == nil {
		return
	}
	r.cur.Notes = append(r.cur.Notes, note)
	r.cur.scans = append(r.cur.scans, scanRecord{note: len(r.cur.Notes) - 1, kind: kind})
}

// scanFor is scan for the pattern at index idx-1 of r.Patterns, or the open
// scope when idx is 0 — for an emitter that runs at assembly.
func (r *Reporter) scanFor(idx int, kind, note string) {
	if r == nil {
		return
	}
	if idx == 0 {
		r.scan(kind, note)
		return
	}
	p := &r.Patterns[idx-1]
	p.Notes = append(p.Notes, note)
	p.scans = append(p.scans, scanRecord{note: len(p.Notes) - 1, kind: kind})
}

// openIndex is the index the open scope will have in r.Patterns once it
// ends.
func (r *Reporter) openIndex() int {
	if r == nil {
		return 0
	}
	return len(r.Patterns)
}

// searchSize records what one search of the open pattern keeps.
func (r *Reporter) searchSize(s SearchSize) {
	if r == nil || r.cur == nil {
		return
	}
	r.cur.Search = s
}

// btBody records one of the open pattern's Backtracking bodies.
func (r *Reporter) btBody(b btBodyReport) {
	if r == nil || r.cur == nil {
		return
	}
	if b.exports == nil {
		// A find body serves find and groups alike.
		for _, e := range r.cur.Exports {
			if e != "match" {
				b.exports = append(b.exports, e)
			}
		}
	}
	r.cur.bt = append(r.cur.bt, b)
}

// tableRange records the open pattern's table range.
func (r *Reporter) tableRange(start, end int64) {
	if r == nil || r.cur == nil {
		return
	}
	r.cur.tableStart, r.cur.tableEnd = start, end
}

// newBTBodyReport describes a Backtracking body of bt under plan.
func newBTBodyReport(body string, exports []string, bt *backtrack, plan btPlan, frame, start int) btBodyReport {
	return btBodyReport{
		body: body, exports: exports, alts: epsAltDepth(bt.prog), frame: frame,
		rowBytes: bt.memoRowBytes(), start: start, fallback: plan.fallback, force: plan.force,
	}
}

// epsAltDepth bounds the frames the current path can hold at one position: the
// most Alt instructions on any path that consumes nothing. A path between two
// consumed bytes is such a path, and a frame is pushed only at an Alt on it (a
// first-byte dispatch pushes, at a chain's head, one frame per Alt the chain
// would have taken). A program with a cycle that consumes nothing — the
// fallback alone runs it, and its memo lets each (pc, position) in once —
// gets every Alt it has.
func epsAltDepth(prog *syntax.Prog) int {
	const unseen, onPath = -1, -2
	depth := make([]int, len(prog.Inst))
	for i := range depth {
		depth[i] = unseen
	}
	cyclic := false
	var walk func(pc uint32) int
	walk = func(pc uint32) int {
		switch depth[pc] {
		case onPath:
			cyclic = true
			return 0
		case unseen:
		default:
			return depth[pc]
		}
		depth[pc] = onPath
		in := prog.Inst[pc]
		d := 0
		switch in.Op {
		case syntax.InstAlt, syntax.InstAltMatch:
			d = 1 + max(walk(in.Out), walk(in.Arg))
		case syntax.InstCapture, syntax.InstNop, syntax.InstEmptyWidth:
			d = walk(in.Out)
		}
		depth[pc] = d
		return d
	}
	most := 0
	for pc := range prog.Inst {
		most = max(most, walk(uint32(pc))) //nolint:gosec // a program counter
	}
	if cyclic {
		n := 0
		for _, in := range prog.Inst {
			if in.Op == syntax.InstAlt || in.Op == syntax.InstAltMatch {
				n++
			}
		}
		return n
	}
	return most
}

// NoteCompile records what the report says about the module cfg compiled
// to: the kind of output, its size and static memory, and the counts.
// component: wasm is a component's core module.
func (r *Reporter) NoteCompile(cfg config.BuildConfig, wasm []byte, component bool) {
	if r == nil {
		return
	}
	m := &r.mod
	m.set = true
	m.bytes = len(wasm)
	m.component = component
	m.standalone = cfg.Output == "" || component
	switch {
	case component:
		m.kind = "component core module"
	case m.standalone:
		m.kind = "standalone module"
	default:
		m.kind = "embedded module"
	}
	if cfg.MaxMemory.IsSet() {
		pages, _ := cfg.MaxMemory.Pages()
		m.maxMemory = int64(pages) * 65536
	}
	if mem := sectionContent(wasm, 5); mem != nil {
		m.staticBytes, _ = utils.ParseMemorySection(mem)
	}
	m.patternsTotal = len(cfg.Patterns)
	m.setMembers = map[string]int{}
	for _, s := range cfg.Sets {
		m.setMembers[s.Name] = len(s.Members(cfg))
	}
}

// noteCode records each pattern's and set's function-body bytes, from the
// owner marks the assembler left (funcsize.go): a pattern's own bodies, and a
// set's with its members' Backtracking bodies. Wrappers and adapters, marked
// with no owner, are nobody's.
func (r *Reporter) noteCode(wasm []byte, owners codeOwners) {
	if r == nil {
		return
	}
	// The module was assembled a moment ago, so it is well formed.
	code := sectionContent(wasm, 10)
	n, k, _ := utils.DecodeULEB128(code)
	perMark := make([]int, len(owners))
	p := k
	for i := uint64(0); i < n; i++ {
		size, k, _ := utils.DecodeULEB128(code[p:])
		at := -1
		for j, o := range owners {
			if o.at > p {
				break
			}
			at = j
		}
		if at >= 0 {
			perMark[at] += int(size)
		}
		p += k + int(size)
	}
	r.End()
	r.noteData(sectionContent(wasm, 11))
	next := 0
	r.mod.setCode = map[string]int{}
	for j, o := range owners {
		var name, set string
		switch {
		case strings.HasPrefix(o.name, "pattern "):
			name, _ = strconv.Unquote(o.name[len("pattern "):])
		case strings.HasPrefix(o.name, "set "):
			set, _ = strconv.Unquote(o.name[len("set "):])
		case strings.HasPrefix(o.name, "member "):
			if i := strings.LastIndex(o.name, " of set "); i >= 0 {
				set, _ = strconv.Unquote(o.name[i+len(" of set "):])
			}
		}
		switch {
		case set != "":
			r.mod.setCode[set] += perMark[j]
		case o.name != "":
			for q := next; q < len(r.Patterns); q++ {
				if pp := &r.Patterns[q]; pp.displayName() == name {
					pp.CodeBytes += perMark[j]
					next = q + 1
					break
				}
			}
		}
	}
}

// noteData adds each data segment's bytes to the pattern whose table range
// holds its offset. A set's tables are in its buckets' rows instead.
func (r *Reporter) noteData(data []byte) {
	// Every segment is the compiler's own: active, at an i32.const offset,
	// with a memory index (0x02) in an embedded module.
	n, p, _ := utils.DecodeULEB128(data)
	for i := uint64(0); i < n; i++ {
		flags := data[p]
		p++
		if flags == 0x02 {
			_, k, _ := utils.DecodeULEB128(data[p:])
			p += k
		}
		off, k, _ := utils.DecodeSLEB128(data[p+1:])
		p += 1 + k + 1 // i32.const, the offset, end
		size, k, _ := utils.DecodeULEB128(data[p:])
		p += k + int(size)
		for q := range r.Patterns {
			if pp := &r.Patterns[q]; off >= pp.tableStart && off < pp.tableEnd {
				pp.TableBytes += int64(size)
				break
			}
		}
	}
}

// displayName is the name the assembler marks the pattern's bodies with
// (config.PatternEntry.DisplayName).
func (p PatternReport) displayName() string {
	if p.Name != "" {
		return p.Name
	}
	return p.Pattern
}

// ── Memory ceilings ────────────────────────────────────────────────────────

// memTerm is one input-dependent region of one export.
type memTerm struct {
	what    string
	exports []string
	module  bool // in the module's memory whatever the output kind
	when    string
	formula string
	size    func(n int64) int64
}

// counts reports whether the term counts against max_memory in this module.
func (t memTerm) counts(m moduleReport) bool { return t.module || m.standalone }

func perPos(bytes int) func(int64) int64 {
	return func(n int64) int64 { return (n + 1) * int64(bytes) }
}

// btTerms are a Backtracking body's run-time scratch: its frame stack, and
// its fallback's memo. The frames are the choice points of the current path,
// at most b.alts per position (epsAltDepth); the stack is allocated by
// doubling, so it can reach twice that, and the ordinary body's starts at
// b.start.
func btTerms(b btBodyReport) []memTerm {
	var out []memTerm
	depth := int64(max(b.alts, 1)) * int64(b.frame)
	start := int64(b.start)
	if b.force {
		start = int64(b.frame)
	}
	out = append(out, memTerm{
		what: "Backtracking frame stack (" + b.body + ")", exports: b.exports, module: true,
		when:    "during a call",
		formula: fmt.Sprintf("max(%d, 2 × (len + 1) × %d) B", start, depth),
		size:    func(n int64) int64 { return max(start, 2*(n+1)*depth) },
	})
	if b.fallback {
		when := "once its work budget trips"
		if b.force {
			when = "every call (a zero-width cycle gives it no ordinary body)"
		}
		out = append(out, memTerm{
			what: "Backtracking fallback memo (" + b.body + ")", exports: b.exports, module: true,
			when: when, formula: fmt.Sprintf("(len + 1) × %d B", b.rowBytes), size: perPos(b.rowBytes),
		})
	}
	return out
}

// searchTerms are what a search keeps in the caller's block.
func searchTerms(s SearchSize, exports []string, label string) []memTerm {
	var out []memTerm
	if s.NotesBytes > 0 {
		out = append(out, memTerm{
			what: "per-search notes" + label, exports: exports, when: "once a search arms",
			formula: fmt.Sprintf("(len + 1) × %d B", s.NotesBytes), size: perPos(s.NotesBytes),
		})
	}
	if s.BTMemoBytes > 0 {
		out = append(out, memTerm{
			what: "Backtracking search memo" + label, exports: exports, when: "once a search trips its work budget",
			formula: fmt.Sprintf("(len + 1) × %d B", s.BTMemoBytes), size: perPos(s.BTMemoBytes),
		})
	}
	return out
}

// inputTerm is the copy of the input a standalone module's stub (or a
// component) makes in the module's memory.
func inputTerm(exports []string) memTerm {
	return memTerm{
		what: "input copy", exports: exports, when: "every call",
		formula: "len B", size: func(n int64) int64 { return n },
	}
}

// patternTerms are every input-dependent region of p's exports.
func patternTerms(p PatternReport, m moduleReport) []memTerm {
	var out []memTerm
	var searching []string
	for _, e := range p.Exports {
		if e == "find" || e == "groups" {
			searching = append(searching, e)
		}
	}
	if len(p.Exports) > 0 && m.standalone {
		out = append(out, inputTerm(p.Exports))
	}
	out = append(out, searchTerms(p.Search, searching, "")...)
	for _, b := range p.bt {
		out = append(out, btTerms(b)...)
	}
	return out
}

// setTerms are every input-dependent region of a set's capabilities.
func setTerms(s setMemReport, m moduleReport) []memTerm {
	var out []memTerm
	var all, find []string
	if s.match {
		all = append(all, "match")
	}
	if s.scan {
		all = append(all, "scan")
	}
	if s.find {
		all = append(all, "find")
		find = []string{"find"}
	}
	if len(all) > 0 && m.standalone {
		out = append(out, inputTerm(all))
	}
	for k, b := range s.blocks {
		out = append(out, searchTerms(b, find, fmt.Sprintf(" (block %d)", k))...)
	}
	if sh := s.cache; sh != nil {
		shape := *sh
		bpb := shape.bytesPerByte()
		out = append(out, memTerm{
			what: "answer cache", exports: find, when: "once the overlapping find sweeps",
			formula: fmt.Sprintf("about len × %d B up to 64 MiB, then a checkpointed region growing with the square root of len", bpb),
			size: func(n int64) int64 {
				b, _ := shape.Sizing(int(min(n, 1<<31-1)))
				return int64(b)
			},
		})
	}
	for _, b := range s.bt {
		out = append(out, btTerms(b)...)
	}
	return out
}

// grows names what of terms grows with the input, for the brief report.
func grows(terms []memTerm) string {
	var what []string
	seen := map[string]bool{}
	for _, t := range terms {
		w := t.what
		if i := strings.Index(w, " ("); i >= 0 {
			w = w[:i]
		}
		if w == "input copy" || seen[w] {
			continue
		}
		seen[w] = true
		what = append(what, w)
	}
	if len(what) == 0 {
		return "constant"
	}
	return "grows with input: " + strings.Join(what, ", ")
}

// ceilings renders terms for the report.
func ceilings(terms []memTerm, m moduleReport) []ReportCeiling {
	out := make([]ReportCeiling, 0, len(terms))
	for _, t := range terms {
		whose := "caller"
		if t.module {
			whose = "module"
		}
		c := ReportCeiling{What: t.what, Exports: t.exports, Memory: whose, When: t.when, Formula: t.formula}
		c.Bytes = ReportSizes{t.size(1 << 10), t.size(64 << 10), t.size(1 << 20), t.size(16 << 20)}
		out = append(out, c)
	}
	return out
}

// maxInputSearchCap is the longest input the search for max_input considers:
// an i32 offset.
const maxInputSearchCap = int64(1)<<31 - 1

// maxInputs is, per export, the longest input whose ceilings — each rounded
// up to whole pages, plus the module's static memory and one page — fit
// under max_memory; -1 when no input reaches it (nothing that counts grows),
// and nil when max_memory is unset.
func maxInputs(exports []string, terms []memTerm, m moduleReport) map[string]int64 {
	if m.maxMemory == 0 || len(exports) == 0 {
		return nil
	}
	out := map[string]int64{}
	for _, e := range exports {
		var mine []memTerm
		for _, t := range terms {
			if t.counts(m) && contains(t.exports, e) {
				mine = append(mine, t)
			}
		}
		// Each region is rounded up to whole pages — memory grows by pages,
		// and each is placed and grown on its own — plus one page for the
		// per-search block a search takes.
		total := func(n int64) int64 {
			sum := m.staticBytes
			if len(mine) > 0 {
				sum += 65536
			}
			for _, t := range mine {
				sum += utils.PageAlign(t.size(n))
			}
			return sum
		}
		switch {
		case total(0) > m.maxMemory:
			out[e] = 0
		case total(maxInputSearchCap) <= m.maxMemory:
			out[e] = -1
		default:
			lo, hi := int64(0), maxInputSearchCap // total(lo) fits, total(hi) does not
			for hi-lo > 1 {
				mid := lo + (hi-lo)/2
				if total(mid) <= m.maxMemory {
					lo = mid
				} else {
					hi = mid
				}
			}
			out[e] = lo
		}
	}
	return out
}

func contains(xs []string, x string) bool {
	for _, y := range xs {
		if y == x {
			return true
		}
	}
	return false
}

// ── Building the report ────────────────────────────────────────────────────

// Report builds the report at level.
func (r *Reporter) Report(level VerboseLevel) Report {
	rep := Report{Schema: ReportSchema, Level: level, Patterns: []ReportPattern{}, Sets: []ReportSet{}}
	if r == nil {
		return rep
	}
	r.End()
	full := level == VerboseFull
	m := r.mod
	if full && m.set {
		rep.Module = &ReportModule{
			Kind: m.kind, Bytes: m.bytes, StaticBytes: m.staticBytes, MaxMemory: m.maxMemory,
			PatternsTotal: m.patternsTotal, InSet: m.inSet, PrefixDedupPoolSize: m.prefixPool,
		}
	}
	for _, p := range r.Patterns {
		rep.Patterns = append(rep.Patterns, buildPatternReport(p, m, full))
	}
	for i := range r.Sets {
		d := r.Sets[i]
		sm := r.setMem[d.Name]
		rep.Sets = append(rep.Sets, buildSetReport(&d, sm, m, full))
	}
	return rep
}

func buildPatternReport(p PatternReport, m moduleReport, full bool) ReportPattern {
	name := p.Name
	if name == "" {
		name = p.Pattern
	}
	out := ReportPattern{Name: name, Exports: p.Exports}
	if out.Exports == nil {
		out.Exports = []string{}
	}
	switch {
	case p.Engine != 0:
		out.Engine = p.Engine.String()
	case strings.HasPrefix(p.Reason, "specialised body"):
		out.Engine = "specialised body"
	case strings.HasPrefix(p.Reason, "refused"), strings.HasPrefix(p.Reason, "failed"):
		out.Engine = "refused"
	default:
		out.Engine = "none"
	}
	searches := contains(p.Exports, "find") || contains(p.Exports, "groups")
	if searches {
		out.Find, out.SwitchTo = p.Find, p.SwitchTo
		out.Scan = "none"
		if n := len(p.scans); n > 0 {
			out.Scan = p.scans[n-1].kind
		}
	}
	terms := patternTerms(p, m)
	out.Memory = grows(terms)
	if !full {
		return out
	}
	out.Regexp, out.Expanded, out.Mode = p.Pattern, p.Expanded, p.Mode
	out.EngineReason = p.Reason
	if searches {
		out.FindReason = p.FindWhy
		if n := len(p.scans); n > 0 {
			out.ScanDetail = p.Notes[p.scans[n-1].note]
		}
	}
	out.Limits = p.Limits
	// The notes but those the scan line says.
	isScan := map[int]bool{}
	for _, sc := range p.scans {
		isScan[sc.note] = true
	}
	for i, n := range p.Notes {
		if !isScan[i] {
			out.Opts = append(out.Opts, n)
		}
	}
	sort.Strings(out.Opts)
	out.TableBytes, out.CodeBytes = p.TableBytes, p.CodeBytes
	out.Ceilings = ceilings(terms, m)
	out.MaxInput = maxInputs(p.Exports, terms, m)
	return out
}

func buildSetReport(d *SetDiag, sm setMemReport, m moduleReport, full bool) ReportSet {
	caps := d.Capabilities
	if caps == nil {
		caps = []string{}
	}
	out := ReportSet{
		Name: d.Name, Capabilities: caps, Members: m.setMembers[d.Name], Frontend: d.Frontend,
		BucketCount: len(d.Buckets), SplitOut: len(d.SplitMembers),
	}
	terms := setTerms(sm, m)
	out.Memory = grows(terms)
	if !full {
		return out
	}
	out.SetDiag = d
	out.CodeBytes = m.setCode[d.Name]
	out.Ceilings = ceilings(terms, m)
	var exports []string
	for _, e := range []string{"match", "scan", "find"} {
		if (e == "match" && sm.match) || (e == "scan" && sm.scan) || (e == "find" && sm.find) {
			exports = append(exports, e)
		}
	}
	out.MaxInput = maxInputs(exports, terms, m)
	return out
}

// ── Rendering ──────────────────────────────────────────────────────────────

// Write renders the report at level in format to w.
func (r *Reporter) Write(w io.Writer, level VerboseLevel, format VerboseFormat) error {
	if w == nil {
		return nil
	}
	rep := r.Report(level)
	if format == VerboseJSON {
		data, _ := json.MarshalIndent(rep, "", "  ") // plain structs: cannot fail
		_, err := w.Write(append(data, '\n'))
		return err
	}
	var b bytes.Buffer
	if level == VerboseFull {
		writeFull(&b, rep)
	} else {
		writeBrief(&b, rep)
	}
	_, err := w.Write(b.Bytes())
	return err
}

// Render writes the full report as text.
func (r *Reporter) Render(w io.Writer) {
	if r == nil || w == nil {
		return
	}
	_ = r.Write(w, VerboseFull, VerbosePlain)
}

func dash(s string) string {
	if s == "" {
		return "—"
	}
	return s
}

// writeBrief is one line per pattern and per set, in aligned columns.
func writeBrief(w io.Writer, rep Report) {
	var rows [][]string
	for _, p := range rep.Patterns {
		find := p.Find
		if p.SwitchTo != "" {
			find += " → " + p.SwitchTo
		}
		scan := ""
		if p.Scan != "" {
			scan = "scan: " + p.Scan
		}
		rows = append(rows, []string{truncate(p.Name, 24), dash(strings.Join(p.Exports, ",")), p.Engine,
			dash(find), dash(scan), "memory: " + p.Memory})
	}
	for _, s := range rep.Sets {
		rows = append(rows, []string{"set " + truncate(s.Name, 20), strings.Join(s.Capabilities, ","),
			fmt.Sprintf("%d members", s.Members), "frontend " + s.Frontend,
			fmt.Sprintf("%d buckets, %d split out", s.BucketCount, s.SplitOut), "memory: " + s.Memory})
	}
	writeColumns(w, rows)
}

// writeColumns writes rows with every column but the last padded to its
// widest cell.
func writeColumns(w io.Writer, rows [][]string) {
	var width []int
	for _, row := range rows {
		for i, c := range row {
			if i >= len(width) {
				width = append(width, 0)
			}
			width[i] = max(width[i], len([]rune(c)))
		}
	}
	for _, row := range rows {
		var b strings.Builder
		for i, c := range row {
			if i == len(row)-1 {
				b.WriteString(c)
				break
			}
			b.WriteString(c)
			b.WriteString(strings.Repeat(" ", width[i]-len([]rune(c))+2))
		}
		fmt.Fprintln(w, strings.TrimRight(b.String(), " "))
	}
}

// writeFull is everything, a block per pattern and per set.
func writeFull(w io.Writer, rep Report) {
	if m := rep.Module; m != nil {
		fmt.Fprintf(w, "Module: %s, %d bytes, %s of tables", m.Kind, m.Bytes, humanBytes(m.StaticBytes))
		if m.MaxMemory > 0 {
			fmt.Fprintf(w, ", max_memory %s", humanBytes(m.MaxMemory))
		}
		fmt.Fprintln(w)
	}
	if len(rep.Patterns) > 0 {
		fmt.Fprintf(w, "\nPatterns (%d)\n", len(rep.Patterns))
		for _, p := range rep.Patterns {
			name := p.Name
			if name == p.Regexp {
				name = "(unnamed)"
			}
			fmt.Fprintf(w, "  %-20s %s\n", name, truncate(p.Regexp, 60))
			if p.Expanded != "" {
				fmt.Fprintln(w, "    expanded: "+p.Expanded)
			}
			if p.Mode != "" {
				fmt.Fprintln(w, "    mode:   "+p.Mode)
			}
			if len(p.Exports) > 0 {
				fmt.Fprintln(w, "    exports: "+strings.Join(p.Exports, ", "))
			}
			line := "    engine: " + p.Engine
			switch {
			case p.Engine == "none" || p.Engine == "specialised body" || p.Engine == "refused":
				if p.EngineReason != "" {
					line = "    engine: " + p.EngineReason
				}
			case p.EngineReason != "":
				line += " — " + p.EngineReason
			}
			fmt.Fprintln(w, line)
			if p.Find != "" {
				l := "    search: " + p.Find
				if p.SwitchTo != "" {
					l += " → " + p.SwitchTo
				}
				if p.FindReason != "" {
					l += " — " + p.FindReason
				}
				fmt.Fprintln(w, l)
			}
			if p.Scan != "" {
				l := "    scan:   " + p.Scan
				if p.ScanDetail != "" {
					l += " — " + p.ScanDetail
				}
				fmt.Fprintln(w, l)
			}
			for _, l := range p.Limits {
				fmt.Fprintf(w, "    limit:  %s\n", l)
			}
			if p.TableBytes > 0 || p.CodeBytes > 0 {
				fmt.Fprintf(w, "    size:   tables %d B, code %d B\n", p.TableBytes, p.CodeBytes)
			}
			writeMemory(w, "    ", p.Memory, p.Ceilings, p.MaxInput)
			if len(p.Opts) > 0 {
				fmt.Fprintf(w, "    opts:   %s\n", strings.Join(p.Opts, ", "))
			}
		}
	}
	for _, s := range rep.Sets {
		writeSetFull(w, s)
	}
}

// writeMemory writes a memory class, its ceilings and the max inputs.
func writeMemory(w io.Writer, indent, class string, cs []ReportCeiling, maxIn map[string]int64) {
	fmt.Fprintf(w, "%smemory: %s\n", indent, class)
	for _, c := range cs {
		fmt.Fprintf(w, "%s  %s [%s, %s memory] %s, %s — 1KiB %s, 64KiB %s, 1MiB %s, 16MiB %s\n",
			indent, c.What, strings.Join(c.Exports, ","), c.Memory, c.Formula, c.When,
			humanBytes(c.Bytes.KiB1), humanBytes(c.Bytes.KiB64), humanBytes(c.Bytes.MiB1), humanBytes(c.Bytes.MiB16))
	}
	if len(maxIn) > 0 {
		keys := make([]string, 0, len(maxIn))
		for k := range maxIn {
			keys = append(keys, k)
		}
		sort.Strings(keys)
		parts := make([]string, len(keys))
		for i, k := range keys {
			v := "unlimited"
			if maxIn[k] >= 0 {
				v = humanBytes(maxIn[k])
			}
			parts[i] = k + " " + v
		}
		fmt.Fprintf(w, "%s  largest input under max_memory: %s\n", indent, strings.Join(parts, ", "))
	}
}

// humanBytes is n in the largest binary unit that keeps it at least 1.
func humanBytes(n int64) string {
	switch {
	case n >= 1<<30:
		return fmt.Sprintf("%.1f GiB", float64(n)/(1<<30))
	case n >= 1<<20:
		return fmt.Sprintf("%.1f MiB", float64(n)/(1<<20))
	case n >= 1<<10:
		return fmt.Sprintf("%.1f KiB", float64(n)/(1<<10))
	}
	return fmt.Sprintf("%d B", n)
}

func writeSetFull(w io.Writer, s ReportSet) {
	d := s.SetDiag
	fmt.Fprintf(w, "\nSet %q\n", s.Name)
	if s.Members > 0 {
		fmt.Fprintf(w, "  members:    %d\n", s.Members)
	}
	if d.Mode != "" {
		fmt.Fprintf(w, "  mode:       %s\n", d.Mode)
	}
	fmt.Fprintf(w, "  frontend:   %s\n", d.Frontend)
	if len(d.Capabilities) > 0 {
		fmt.Fprintf(w, "  capabilities: %s\n", strings.Join(d.Capabilities, ", "))
	}
	if d.Overlapping {
		fmt.Fprintln(w, "  overlapping: true")
	}
	if d.MaxLookback > 0 {
		fmt.Fprintf(w, "  max lookback: %d\n", d.MaxLookback)
	}
	fmt.Fprintf(w, "  buckets:    %d\n", len(d.Buckets))
	for _, b := range d.Buckets {
		lit := b.Literal
		if lit == "" {
			lit = "(fallback — no literal)"
		}
		// The engine is printed because a Backtracking bucket otherwise
		// reads exactly like a DFA fallback bucket here, and the switch is
		// not free: one such member measured up to 2.2x the fuel of a
		// 16-pattern set's scan_any, scan_all and find (docs/sets.md). It
		// also moves the set's _all pair to the out_ptr form.
		engine := "DFA"
		if b.Type == "bt-fallback" {
			engine = "Backtracking"
		}
		line := fmt.Sprintf("    #%-3d %-24s %-8s %-12s %2d pattern(s)  %d states  %d bytes",
			b.ID, truncate(lit, 24), b.AcceptKind, engine, len(b.Patterns), b.SuffixStates, b.TableBytes)
		if b.MemberSkipStates > 0 {
			line += fmt.Sprintf("  member skip %d states / %d sets", b.MemberSkipStates, b.MemberSkipSets)
		}
		fmt.Fprintln(w, line)
	}
	// A member whose anchored pair runs on Backtracking costs every
	// match_any / match_all call a probe after the DFA part.
	reportDrops(w, "match_any/match_all on Backtracking (anchored DFA over the limits)", d.AnchoredBacktracking)
	if d.IDSpaceSize != len(d.Buckets) && d.IDSpaceSize > 0 {
		fmt.Fprintf(w, "  id space:   %d\n", d.IDSpaceSize)
	}
	if fd := d.FrontendDemotion; fd != nil {
		fmt.Fprintf(w, "  DOWNGRADED frontend: %s → %s (%s)\n", fd.From, fd.To, fd.Reason)
	}
	if a := d.ACTable; a != nil {
		fmt.Fprintf(w, "  Aho-Corasick: %d nodes, %d bytes", a.Nodes, a.Bytes)
		if a.Compressed {
			fmt.Fprintf(w, ", %d byte classes", a.ByteClasses)
		}
		fmt.Fprintln(w)
	}
	if u := d.UnionScan; u != nil && (contains(d.Capabilities, "scan_any") || contains(d.Capabilities, "scan_all")) {
		if u.Used {
			fmt.Fprintf(w, "  scan pair: union automaton, %d states%s\n", u.States, wideNote(u.Wide))
		} else {
			fmt.Fprintf(w, "  scan pair: per-position walk (union automaton refused: %s)\n", u.Refused)
		}
	}
	if u := d.AnchoredUnion; u != nil && (contains(d.Capabilities, "match_any") || contains(d.Capabilities, "match_all")) {
		if u.Used {
			fmt.Fprintf(w, "  match pair: union automaton, %d states%s\n", u.States, wideNote(u.Wide))
		} else {
			fmt.Fprintf(w, "  match pair: per-bucket probes (union automaton refused: %s)\n", u.Refused)
		}
	}
	// Members served outside the buckets, and the work counters: each
	// changes the set's cost by large factors and shows nowhere else.
	if len(d.SplitMembers) > 0 {
		fmt.Fprintf(w, "  split out (not provably linear; own linear search): %s\n", memberSearches(d.SplitMembers, d.SplitBacktracking))
	}
	if u := d.ScanUnion; u != nil {
		switch {
		case u.Direct:
			fmt.Fprintf(w, "  scan pair: one union automaton over every member (%d states)\n", u.States)
		case u.Counter:
			fmt.Fprintf(w, "  scan pair: work counter switching to a union automaton (%d states)\n", u.States)
		}
	}
	if d.InCallCounter {
		fmt.Fprintf(w, "  overlapping find: in-call counter sweeps the answer cache\n")
	}
	if d.KeptCache {
		fmt.Fprintf(w, "  overlapping find: the kept members' own set reads the answer cache\n")
	}
	if ws := d.WholeSetSweep; ws != nil {
		fmt.Fprintf(w, "  overlapping find: the answer cache sweeps a whole-set automaton (%d states, %d cells)\n", ws.States, ws.Cells)
	}
	if len(d.NoCacheSplitMembers) > 0 {
		fmt.Fprintf(w, "  overlapping find without a usable cache: companion splits out %s\n", memberSearches(d.NoCacheSplitMembers, d.NoCacheSplitBacktracking))
	}
	if len(d.SparseSplitMembers) > 0 {
		fmt.Fprintf(w, "  sparse counter's split copy serves: %s\n", memberSearches(d.SparseSplitMembers, nil))
	}
	writeMemory(w, "  ", s.Memory, s.Ceilings, s.MaxInput)
}

func wideNote(wide bool) string {
	if wide {
		return ", wide accept"
	}
	return ""
}

// memberSearches lists member ids with the search each runs: the
// start-anywhere find, or the Backtracking find for those in bt.
func memberSearches(ids, bt []int) string {
	isBT := map[int]bool{}
	for _, id := range bt {
		isBT[id] = true
	}
	out := make([]string, len(ids))
	for i, id := range ids {
		search := "start-anywhere"
		if isBT[id] {
			search = "Backtracking"
		}
		out[i] = fmt.Sprintf("#%d (%s)", id, search)
	}
	return strings.Join(out, ", ")
}

// noteSet records what one top-level set keeps per call and per search, read
// off the compiled set and the internal sets it carries.
func (r *Reporter) noteSet(sc config.SetConfig, cs *compiledSet, members int) {
	if r == nil {
		return
	}
	if r.setMem == nil {
		r.setMem = map[string]setMemReport{}
	}
	r.mod.inSet += members
	sm := setMemReport{
		name:  sc.Name,
		find:  cs.find != "",
		scan:  cs.scanAny != "" || cs.scanAll != "",
		match: cs.matchAny != "" || cs.matchAll != "",
	}
	sm.blocks = cs.searchBlocks()
	if sh := overlapShapeOf(cs); sh.bytesPerByte() > 0 {
		sm.cache = &sh
	}
	var walk []string
	if sm.scan {
		walk = append(walk, "scan")
	}
	if sm.find {
		walk = append(walk, "find")
	}
	seen := map[*compiledSet]bool{}
	var visit func(c *compiledSet)
	visit = func(c *compiledSet) {
		if c == nil || seen[c] {
			return
		}
		seen[c] = true
		for _, b := range c.buckets {
			if b.btFallback != nil {
				bt := b.btFallback.bt
				sm.bt = append(sm.bt, newBTBodyReport("member "+patternRefFor(b.patterns[0]).Name, walk, bt,
					planBT(bt, c.btWorkBudget), btNoCaptureFrameSize, int(btStackStart(c.btStackStart, btNoCaptureFrameSize))))
			}
		}
		for _, b := range c.anchoredBT {
			bt := b.btFallback.bt
			sm.bt = append(sm.bt, newBTBodyReport("member "+patternRefFor(b.patterns[0]).Name+", anchored", []string{"match"}, bt,
				planBT(bt, c.btWorkBudget), btNoCaptureFrameSize, int(btStackStart(c.btStackStart, btNoCaptureFrameSize))))
		}
		for _, m := range c.split {
			if m.bt != nil {
				b := m.bt.report
				b.body, b.exports = "split member "+m.name, walk
				sm.bt = append(sm.bt, b)
			}
		}
		visit(c.companion)
		visit(c.scanComp)
		visit(c.keptCache)
	}
	visit(cs)
	r.setMem[sc.Name] = sm
}
