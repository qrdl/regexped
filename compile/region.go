package compile

import "fmt"

// ── Set table-region allocation ────────────────────────
//
// CompileSet lays a set's tables into one address space in nine sequential
// blocks — id mapping, prefix metadata, suffix DFAs, prefix functions, the
// literal frontend, Backtracking regions, anchored packing, union/startable/DP
// layout — each claiming a region and advancing a cursor.
//
// That cursor used to be a chain of differently-named locals: `tableOffset`
// became `prefixTableOffset` became `setTablesEnd`, from which
// `anchoredTableBase`, `unionBase` and `p2Base` were each derived and then
// folded back with `if x.tableEnd > setTablesEnd { setTablesEnd = x.tableEnd }`.
// Twenty-four references to `setTablesEnd` alone. What kept two blocks from
// claiming the same bytes was PROSE — "before building suffix DFAs", "after
// suffix data, to avoid address overlap", "laid out above every other table
// this set owns".
//
// Overlap is not a compile error and not a WASM validation error. It is a
// module that reads one table through another's bytes, and it has shipped
// before (FABLE_REVIEW B1). This type makes the frontier the only source of a
// base address, so a block cannot lay a table at an address computed from a
// stale cursor, and it refuses a commit that moves backwards.
//
// It is deliberately NOT a general allocator. The blocks are sequential and
// bump-allocated, exactly as before, so the addresses it hands out are the ones
// the cursor chain produced — which is what lets the conversion be proved by
// byte identity against compile/testdata/byteident/set_*.
type regionAlloc struct {
	frontier int32
	claims   []regionClaim
	// pending is the name of a Reserve awaiting its Commit. Only one region is
	// ever in flight: every block reserves a base, hands it to the builder that
	// fills it, then commits the extent that builder reports.
	pending string
	// pendingBase is the aligned address Reserve handed out. Reserve does NOT
	// move the frontier — a reserved-then-Skipped region must leave the address
	// space exactly as it found it, including any alignment padding, which is
	// what the union-scan and phase-2 blocks rely on when their builder
	// declines.
	pendingBase int32
}

type regionClaim struct {
	name       string
	start, end int32
}

func newRegionAlloc(base int32) *regionAlloc {
	return &regionAlloc{frontier: base}
}

// Reserve returns the base address for the next region, aligned up to `align`
// (1 for no alignment). Nothing is committed: the caller hands this base to
// whatever builds the table, then calls Commit with the address that builder
// reports as its end.
//
// Two-step because most of these regions are laid out by a CALLEE — the base
// goes in, a `tableEnd` comes back — so the extent is not knowable at the point
// the base is needed.
func (r *regionAlloc) Reserve(name string, align int32) int32 {
	if r.pending != "" {
		panic(fmt.Sprintf("compile: region %q reserved while %q is still uncommitted — "+
			"every Reserve must be followed by its Commit before the next", name, r.pending))
	}
	base := r.frontier
	if align > 1 {
		base = (base + align - 1) &^ (align - 1)
	}
	r.pending, r.pendingBase = name, base
	return base
}

// Commit records that the pending region ends at `end`, advancing the frontier.
//
// An `end` below the frontier is refused rather than clamped: it means the
// builder laid its table somewhere other than where it was told to, and
// silently keeping the higher frontier would leave a region nobody owns while
// hiding the discrepancy.
func (r *regionAlloc) Commit(end int32) {
	if r.pending == "" {
		panic("compile: region Commit with no Reserve outstanding")
	}
	if end < r.pendingBase {
		panic(fmt.Sprintf("compile: region %q ends at %d, below the base %d it was "+
			"reserved at — the builder did not lay its table where it was told",
			r.pending, end, r.pendingBase))
	}
	r.claims = append(r.claims, regionClaim{name: r.pending, start: r.pendingBase, end: end})
	r.frontier = end
	r.pending = ""
}

// Bump reserves and commits `size` bytes in one step, for regions this function
// lays out itself rather than delegating.
func (r *regionAlloc) Bump(name string, size, align int32) int32 {
	base := r.Reserve(name, align)
	r.Commit(base + size)
	return base
}

// Skip releases a region that was reserved but turned out not to be needed,
// leaving the frontier exactly where it was — alignment padding included.
func (r *regionAlloc) Skip() {
	if r.pending == "" {
		panic("compile: region Skip with no Reserve outstanding")
	}
	r.pending = ""
}

// End is the first free address after every region claimed so far — the value
// the old code carried in `setTablesEnd`.
func (r *regionAlloc) End() int32 {
	if r.pending != "" {
		panic(fmt.Sprintf("compile: region End while %q is still uncommitted", r.pending))
	}
	return r.frontier
}
