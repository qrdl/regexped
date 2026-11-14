package generate

import (
	"fmt"
	"os"
	"strconv"
	"strings"

	"github.com/qrdl/regexped/compile"
	"github.com/qrdl/regexped/config"
	"github.com/qrdl/regexped/internal/abi"
)

// jsStub generates a JS ES module stub file for all regexp entries and sets in cfg.
// out is the full output path or "-" for stdout.
func jsStub(cfg config.BuildConfig, out string) error {
	content, err := genJSStubFile(cfg)
	if err != nil {
		return fmt.Errorf("generate JS stub: %w", err)
	}
	// Applied BEFORE the stdout/file branch, not on the file branch alone:
	// a user piping `-o -` into a build must get the same symbols the file
	// output has.
	content = applyNamespace(cfg, "js", content)
	if out == "-" {
		_, err := os.Stdout.WriteString(content)
		return err
	}
	return writeStub(out, []byte(content))
}

// genJSSetSection returns JS set wrappers appended to the module body.
// Called from genJSStubFile's inner builder when cfg.Sets is non-empty.
func genJSSetSection(cfg config.BuildConfig, sizes map[string]compile.SearchSize) string {
	if !hasSetExports(cfg) {
		return ""
	}
	var out strings.Builder
	out.WriteString("\n// ---- set composition wrappers ----\n")
	out.WriteString("//\n")
	out.WriteString("// Return types are called out on every function because JavaScript cannot\n")
	out.WriteString("// catch the predicate-versus-list misreading `_any`/`_all` invite: an empty\n")
	out.WriteString("// array is truthy, so `if (setScanAll(x))` is ALWAYS true.\n")
	out.WriteString("//\n")
	out.WriteString("// Calling other stub functions while an iterator is suspended is SAFE: each\n")
	out.WriteString("// live iterator owns its input and scratch region for its whole lifetime,\n")
	out.WriteString("// the same guarantee the Rust and Go stubs get from passing a host pointer.\n")
	out.WriteString("\n")
	shapes := newSetShapes(cfg)
	if shapes.anyWantsCache() {
		out.WriteString(jsLazyFunc(false))
	}
	for setIdx, s := range cfg.Sets {
		n := patternsInSet(s, cfg)
		konst := camelSet(s.Name) + "PatternCount"
		idN := idSpaceSize(s, cfg)
		idKonst := camelSet(s.Name) + "IdSpace"
		wide := shapes.wideAll(setIdx)
		// Standalone layout, all above _outBase: the tuple buffer
		// (12 bytes x pattern count), then the gate array (4 bytes x ID
		// SPACE), then the >64-pattern bitmap (ceil(idSpace/8)). The two
		// counts differ for a set that selects a named subset — see
		// idSpaceSize.
		// … then the SCRATCH DESCRIPTOR the find exports take in place of a
		// bare gate pointer: four u32s holding a magic word, the gate pointer
		// and the answer cache (internal/abi).
		reserve := 12*n + 4*idN + scratchDescriptorBytes + bitmapBytes(s, cfg)
		gateBase := fmt.Sprintf("_outBase + 12*%s", konst)
		scratchBase := fmt.Sprintf("_outBase + 12*%s + 4*%s", konst, idKonst)
		bitmapBase := fmt.Sprintf("_outBase + 12*%s + 4*%s + %d", konst, idKonst, scratchDescriptorBytes)

		// Argument ORDER comes from the shared descriptor, not from the templates
		// below — the one place the compiler's ABI is written down
		//. Only the SPELLING of each parameter is decided
		// here; `args` names the list for one capability.
		caps := setCapabilities(s, cfg, wide)
		spell := jsArgSpelling{
			inPtr: "_inBase", inLen: "len", from: "from",
			gate: "scratchBase", bitmap: "bitmapBase",
			tuple: "_outBase", outCap: konst, cursor: "cursor",
		}
		args := func(kind string) string { return spellJSArgs(capByKind(caps, kind), spell) }

		fmt.Fprintf(&out, "// Number of patterns in set %q. Sizes the match buffer: the find generator\n// can receive at most this many matches at one position.\nexport const %s = %d;\n\n", s.Name, konst, n)
		fmt.Fprintf(&out, "// One past the largest pattern id set %q can report. Pattern ids index\n// patterns: (then the set's own regexps:), so a set holding a few late-declared patterns has a\n// small count and a large id space. Everything indexed BY an id \u2014 the gate\n// array, the _all bitmask \u2014 is sized from this.\nexport const %s = %d;\n\n", s.Name, idKonst, idN)

		if s.BatchFind() {
			fmt.Fprintf(&out, "// Largest batchSize %s accepts for set %q. It is the cursor layout's\n// limit, not a policy: one i64 carries the resume position in its top 32\n// bits and splits the low 32 between the intra-position index and the count.\n// It never binds in practice — this many tuples is a multi-megabyte buffer.\nexport const %s = %d;\n\n",
				s.Find, s.Name, camelSet(s.Name)+"BatchMaxSize", cursorMaxCount(s, cfg))
		}

		if s.MatchAny != "" {
			fmt.Fprintf(&out, `// -> number | null   (a pattern id, NOT a boolean)
export function %s(input) {
    const [_inBase, _outBase, len] = _stage(input, 0);
    const id = _exp['%s'](%s);
    // Tested EXACTLY, not as "negative": -1 is a real answer (nothing matched)
    // and the sentinel means the engine gave up. Folding the two — which this
    // did — turns "unknown" into a confident null.
    if (id === %d) throw new Error("%s");
    return id < 0 ? null : id;
}
`, s.MatchAny, s.MatchAny, args("match_any"), btOverflow, btOverflowMsg(s.MatchAny))
		}
		if s.MatchAll != "" {
			if wide {
				fmt.Fprintf(&out, `// -> number[]   (pattern ids, NOT a boolean)
export function %s(input) {
    const [_inBase, _outBase, len] = _stage(input, %d);
    const bitmapBase = %s;
    new Uint8Array(_exp.memory.buffer, bitmapBase, (%s+7)>>3).fill(0);
    const n = _exp['%s'](%s);
    // -2 is UNKNOWN, not "nothing matched": a member's Backtracking probe
    // gave up.
    if (n === %d) throw new Error("%s");
    const bits = new Uint8Array(_exp.memory.buffer, bitmapBase, (%s+7)>>3);
    const out = [];
    for (let k = 0; k < %s; k++) if (bits[k>>3] & (1 << (k & 7))) out.push(k);
    return out;
}
`, s.MatchAll, reserve, bitmapBase, idKonst, s.MatchAll, args("match_all"), btOverflow, btOverflowMsg(s.MatchAll), idKonst, idKonst)
			} else {
				fmt.Fprintf(&out, `// -> number[]   (pattern ids, NOT a boolean)
export function %s(input) {
    const [_inBase, _outBase, len] = _stage(input, 0);
    // The export returns an i64, which surfaces as a BigInt; it is decomposed
    // here and never reaches the caller.
    let mask = _exp['%s'](%s);
    // NO overflow sentinel here: the narrow form's return IS the bitmask, so
    // every 64-bit value is a legal answer. -2n means ids 1..63 matched and id
    // 0 did not, which a sentinel test would report as an engine failure. The
    // real sentinel cannot reach this form — a Backtracking member forces the
    // wide one.
    const out = [];
    for (let k = 0; k < %s; k++) if ((mask >> BigInt(k)) & 1n) out.push(k);
    return out;
}
`, s.MatchAll, s.MatchAll, args("match_all"), idKonst)
			}
		}
		if s.ScanAny != "" {
			fmt.Fprintf(&out, `// -> pattern id | null   (NOT a boolean, and NO position)
export function %s(input, from = 0) {
    const [_inBase, _outBase, len] = _stage(input, 0);
    const id = _exp['%s'](%s);
    // -2 is the Backtracking engine giving up: the result is UNKNOWN, not "no
    // match". Compared exactly, since -1 — a real no-match — is next door.
    if (id === %d) throw new Error("%s");
    return id < 0 ? null : id;
}
`, s.ScanAny, s.ScanAny, args("scan_any"), btOverflow, btOverflowMsg(s.ScanAny))
		}
		if s.ScanAll != "" {
			if wide {
				fmt.Fprintf(&out, `// -> number[]   (pattern ids, NOT a boolean)
export function %s(input, from = 0) {
    const [_inBase, _outBase, len] = _stage(input, %d);
    const bitmapBase = %s;
    new Uint8Array(_exp.memory.buffer, bitmapBase, (%s+7)>>3).fill(0);
    const n = _exp['%s'](%s);
    // -2 is UNKNOWN, not an empty result: a Backtracking member gave up. The
    // narrow form has no room to say this — its i64 return IS the bitmask — so
    // a BT member is exactly what forces this wide form.
    if (n === %d) throw new Error("%s");
    const bits = new Uint8Array(_exp.memory.buffer, bitmapBase, (%s+7)>>3);
    const out = [];
    for (let k = 0; k < %s; k++) if (bits[k>>3] & (1 << (k & 7))) out.push(k);
    return out;
}
`, s.ScanAll, reserve, bitmapBase, idKonst, s.ScanAll, args("scan_all"), btOverflow, btOverflowMsg(s.ScanAll), idKonst, idKonst)
			} else {
				fmt.Fprintf(&out, `// -> number[]   (pattern ids, NOT a boolean)
export function %s(input, from = 0) {
    const [_inBase, _outBase, len] = _stage(input, 0);
    let mask = _exp['%s'](%s);
    // NO overflow sentinel here: the narrow form's return IS the bitmask, so
    // every 64-bit value is a legal answer. -2n means ids 1..63 matched and id
    // 0 did not, which a sentinel test would report as an engine failure. The
    // real sentinel cannot reach this form — a Backtracking member forces the
    // wide one.
    const out = [];
    for (let k = 0; k < %s; k++) if ((mask >> BigInt(k)) & 1n) out.push(k);
    return out;
}
`, s.ScanAll, s.ScanAll, args("scan_all"), idKonst)
			}
		}
		if s.Find != "" {
			// Every set with `find` owns a gate array, overlapping included
			//, so this is unconditional.
			//
			// So is the ANSWER CACHE, and that is not a detail: the cache is
			// read by the plain `find` exactly as it is by the batch entry —
			// an overlapping set whose shape qualifies emits the sweep whether
			// or not it batches. Building it only under the batching hint left
			// JS and TS the two languages whose plain overlapping find stayed
			// quadratic, against a documented promise that every generated
			// stub reserves one.
			plainGateRegion := jsFindGateRegion(s, cfg, idN)
			plainCachePre, plainCacheDest, plainCacheReserve, plainCachePost, plainCacheArgs :=
				jsOverlapCacheBlock(s, shapes.cacheShape(setIdx), plainGateRegion)
			// The find region is sized from the SAME span the cache offset is
			// taken from, alignment padding included. `reserve` above omits
			// that padding, and the cache would then begin a few bytes past
			// the end of what _open handed out.
			findReserve := 12*n + plainGateRegion
			gateSetup := fmt.Sprintf(`    const gateBase = %s;
    new Uint32Array(_exp.memory.buffer, gateBase, %s).fill(0);
`, gateBase, idKonst) + plainCachePost + fmt.Sprintf(`    // The scratch descriptor: magic, the gate pointer, and the cache.
    const scratchBase = %s;
    new Uint32Array(_exp.memory.buffer, scratchBase, 4).set([%d, gateBase, %s]);
`, scratchBase, abi.FindScratchMagic, plainCacheArgs)
			gateArg := "scratchBase, "
			gateDoc := "// The generator owns the gate array for its lifetime: dropping it and\n" +
				"// creating a new one restarts the scan with clean gates.\n"
			if !s.BatchFind() {
				// No `batch-find` hint: no batchSize parameter at all, so TS
				// rejects find(input, 0, 64) at build time and JS ignores it
				// the way it ignores any extra argument. One WASM call per
				// matching position.
				fmt.Fprintf(&out, `// -> Generator yielding { patternId, start, end }
%sexport function* %s(input, offset = 0) {
%s    // The region is this iterator's own for its whole lifetime, so another
    // stub call cannot land on its input, its tuple buffer or its gates.
    const [_inBase, _outBase, len%s] = _open(input, %d%s);
    try {
%s    let pos = offset;
    // Hoisted rather than rebuilt per position, which allocated one typed
    // array per matching position. _att re-attaches it if an interleaved
    // call grew memory while this generator was suspended.
    let buf = new Int32Array(_exp.memory.buffer, _outBase, 3*%s);
    while (true) {
        // The buffer is sized at the set's pattern count, the exact worst case
        // for a single position, so n can never exceed it.
        const n = _exp['%s'](%s);
%s        // -2 is UNKNOWN, not a count: a Backtracking member gave up here. It
        // has to be tested before the break below, which reads every
        // non-positive n as a clean end of scan.
        if (n === %d) throw new Error("%s");
        // -4 is the other unknowable answer: the overlapping answer cache's
        // header contradicts itself, so this drive is not finished — the
        // engine cannot say what is left.
        if (n === %d) throw new Error("%s");
        // -6: the offset went below where the answer cache was built. This
        // generator never moves backwards, so only shared state produces it.
        if (n === %d) throw new Error("%s");
        if (n <= 0) break;
        buf = _att(buf, Int32Array, _outBase, 3*%s);
        // Every tuple in one call shares a start; resume one past it.
        const next = buf[1] + 1;
        for (let i = 0; i < n; i++) {
            // Re-checked each step: the yield below hands control back, and
            // whatever runs there may grow memory and detach this view.
            buf = _att(buf, Int32Array, _outBase, 3*%s);
            yield { patternId: buf[i*3], start: buf[i*3+1], end: buf[i*3+2] };
        }
        pos = next;
    }
    } finally { %s_close(_inBase); }
}
`, gateDoc, s.Find, plainCachePre, plainCacheDest, findReserve, plainCacheReserve, gateSetup, konst, s.Find,
					spellJSArgs(capByKind(caps, "find"), jsArgSpelling{
						inPtr: "_inBase", inLen: "len", from: "pos",
						gate: "scratchBase", tuple: "_outBase", outCap: konst,
					}),
					jsLazyWanted(plainCacheArgs, "n === "+strconv.Itoa(abi.OverlapCacheWanted)),
					btOverflow, btOverflowMsg(s.Find),
					malformedCache, malformedCacheMsg(s.Find),
					outOfOrder, outOfOrderMsg(s.Find), konst, konst, jsLazyFinally(plainCacheArgs))
			} else {
				// `hints: [batch-find]`: the same matches in the same order,
				// but batchSize positions of work per host crossing. That is
				// the ONLY difference, which is why it is a parameter rather
				// than a second function — and why it is opt-in, since a
				// caller who stops early has paid for matches never looked at.
				// The BATCH entry's argument order stays spelled out here:
				// setCapabilities describes the five DECLARED capabilities,
				// and batching is a hint rather than one, so it has no
				// descriptor entry to derive from. Its
				// signature is pinned instead by
				// compile/set_emit.go's setTypeBatchGated and the goldens.
				batchGateSetup := fmt.Sprintf(`    const gateBase = _outBase + 12*batchSize;
    new Uint32Array(_exp.memory.buffer, gateBase, %s).fill(0);
`, idKonst)
				// The scratch descriptor sits above the gate array and below
				// the bitmap, and is written AFTER the cache is sized: the
				// cache pointer is one of its fields.
				batchScratchBase := fmt.Sprintf("gateBase + 4*%s", idKonst)
				// The overlapping answer cache. An OVERLAPPING drive reports
				// every start position, so a pattern whose automaton never
				// dies is quadratic: each position walks to the end of the
				// input. Handing the engine a cache lets it sweep once,
				// backwards, and serve every later call by copying out of it.
				//
				// Offered only for `overlapping: true`, because that is the
				// only policy whose drive the sweep can answer. The engine
				// may still decline — the sweep refuses shapes it cannot
				// reproduce exactly — and declining costs nothing but speed.
				batchGateRegion := jsFindGateRegion(s, cfg, idN)
				cachePre, cacheDest, cacheReserve, cachePost, cacheArgs := jsOverlapCacheBlock(s, shapes.cacheShape(setIdx), batchGateRegion)
				// The descriptor, written last: it carries the cache pointer,
				// which the block above may have declined.
				cachePost += fmt.Sprintf(`    const scratchBase = %s;
    new Uint32Array(_exp.memory.buffer, scratchBase, 4).set([%d, gateBase, %s]);
`, batchScratchBase, abi.FindScratchMagic, cacheArgs)
				batchFinally := jsLazyFinally(cacheArgs)
				// The wanted word comes back with nothing delivered and is not a
				// cursor: the call is made again with the cursor it was given.
				if w := jsLazyWanted(cacheArgs, fmt.Sprintf("(BigInt.asUintN(64, packed) >> 32n) === 0x%Xn", config.SetCursorCacheWantedPos)); w != "" {
					cacheArgs = "\n" + strings.TrimSuffix(w, "\n")
				} else {
					cacheArgs = ""
				}
				fmt.Fprintf(&out, `// -> Generator yielding { patternId, start, end }
//
// batchSize is how many tuples one WASM call may fill: 1 is a call per
// matching position, larger values amortise the host crossing over a
// bufferful. Clamped into [1, %s].
%sexport function* %s(input, offset = 0, batchSize = %d) {
    batchSize = Math.min(Math.max(batchSize | 0, 1), %s);
%s    // This iterator's own region, held until it finishes — see _open.
    const [_inBase, _outBase, len%s] = _open(input, 12*batchSize + %d%s);
    try {
%s%s    let cursor = BigInt(offset) << 32n;
    // Hoisted for the same reason the per-position shape hoists its view, and
    // re-attached by _att when an interleaved call grows memory.
    let buf = new Int32Array(_exp.memory.buffer, _outBase, 3*batchSize);
    while (true) {
        const packed = _exp['%s'](_inBase, len, cursor, %s_outBase, batchSize);%s
        // The cursor is opaque: hand it back unchanged. Only its top 32 bits
        // are public — all ones means the scan is finished, and that arrives
        // on the same call as the last matches.
        const n = Number(packed & %dn);
        // The position word can also carry 0x%X: not a resume point but
        // UNKNOWN — a Backtracking member gave up, and this call reported
        // nothing. Tested beside the done word so it cannot pass for a finish.
        if ((BigInt.asUintN(64, packed) >> 32n) === 0x%Xn) throw new Error("%s");
        // And 0x%X, the second reserved word: the answer cache's header is
        // malformed. All reserved words are tested before the done word, since
        // every one of them has the high bit set.
        if ((BigInt.asUintN(64, packed) >> 32n) === 0x%Xn) throw new Error("%s");
        // And 0x%X, the third: the cursor resumed below where the answer cache
        // was built, a scan that went backwards.
        if ((BigInt.asUintN(64, packed) >> 32n) === 0x%Xn) throw new Error("%s");
        const done = (BigInt.asUintN(64, packed) >> 32n) === 0xFFFFFFFFn;
        for (let i = 0; i < n; i++) {
            // Re-checked each step: the yield hands control back, and whatever
            // runs there may grow memory and detach this view.
            buf = _att(buf, Int32Array, _outBase, 3*batchSize);
            yield { patternId: buf[i*3], start: buf[i*3+1], end: buf[i*3+2] };
        }
        // A call reports at least one match unless the scan is over.
        if (done || n === 0) break;
        cursor = packed;
    }
    } finally { %s_close(_inBase); }
}
`, camelSet(s.Name)+"BatchMaxSize", gateDoc, s.Find, defaultBatchCap(s, cfg),
					camelSet(s.Name)+"BatchMaxSize", cachePre, cacheDest, batchGateRegion, cacheReserve,
					batchGateSetup, cachePost,
					config.SetBatchExportName(s.Find), gateArg, cacheArgs, cursorCountMask(s, cfg),
					config.SetCursorOverflowPos, config.SetCursorOverflowPos, btOverflowMsg(s.Find),
					config.SetCursorMalformedPos, config.SetCursorMalformedPos, malformedCacheMsg(s.Find),
					config.SetCursorOutOfOrderPos, config.SetCursorOutOfOrderPos, outOfOrderMsg(s.Find), batchFinally)
			}
		}
		out.WriteString("\n")
	}
	out.WriteString(jsPatternNameFns(cfg, "js", "id", ""))
	// Split members' search blocks (search_stub.go).
	section := out.String()
	for _, s := range cfg.Sets {
		if s.Find != "" {
			section = jsSetWithBlocks(section, s.Find, sizes[s.Find].Blocks, false)
		}
	}
	return section
}

// jsPatternNameFns is every `emit_name_map: true` lookup, one per set, in the
// JS family's shared syntax: lang picks the name, param and ret the types
// (none for JS, number / i32 and string for TS / AssemblyScript).
func jsPatternNameFns(cfg config.BuildConfig, lang, param, ret string) string {
	var out strings.Builder
	for _, s := range nameMapSets(cfg) {
		fn := config.SetPatternNameFunc(s.Name, lang)
		fmt.Fprintf(&out, "/** `%s` %s */\n", fn, nameMapDoc(s))
		fmt.Fprintf(&out, "export function %s(%s)%s {\n", fn, param, ret)
		if named := namedMembers(s, cfg); len(named) > 0 {
			out.WriteString("  switch (id) {\n")
			for _, m := range named {
				fmt.Fprintf(&out, "    case %d: return %q;\n", m.ID, m.Entry.Name)
			}
			out.WriteString("  }\n")
		}
		out.WriteString("  return '';\n}\n")
	}
	return out.String()
}

// genJSStubFile generates the content of an ES module JS stub that exports
// wrapper functions for every regexp entry in cfg.  The caller is responsible
// for loading the WASM file and passing the bytes (or a WebAssembly.Module)
// to the exported init() function before calling any matcher.
func genJSStubFile(cfg config.BuildConfig) (string, error) {
	// A config with no exports gets NO FILE, matching the other four
	// generators. It used to get a module of dead `_align`/`_grow`/`_stage`
	// helpers and nothing to call them.
	if !anyStubExport(cfg) {
		return "", nil
	}
	// Determine whether any entry needs a slots buffer (groups/named_groups).
	var sb strings.Builder
	sb.WriteString(lineCommentHeader + "\n")

	sb.WriteString("let _exp, _mem;\n")
	sb.WriteString("let _staticTop = 0; // first byte after the module's own table pages\n")
	sb.WriteString("let _bump = 0;      // next free byte; regions are carved from here up\n")
	// Only generators keep regions; a stub with none would declare it unused.
	if hasSuspendableExports(cfg) {
		sb.WriteString("const _regs = [];   // live iterator regions, in allocation order\n")
	}
	sb.WriteString("const _enc = new TextEncoder();\n")
	sb.WriteString("\n")

	// init() accepts a BufferSource (ArrayBuffer / Buffer / Uint8Array) or a
	// pre-compiled WebAssembly.Module — any value accepted by
	// WebAssembly.instantiate().  The caller chooses how to load the file:
	//
	//   Browser:            await init(await fetch('./merged.wasm').then(r => r.arrayBuffer()))
	//   Node.js:            await init(readFileSync('./merged.wasm'))
	//   Cloudflare Workers: import wasm from './merged.wasm'; await init(wasm)
	sb.WriteString("export async function init(wasm) {\n")
	sb.WriteString("    const r = await WebAssembly.instantiate(wasm);\n")
	sb.WriteString("    const instance = r instanceof WebAssembly.Instance ? r : r.instance;\n")
	sb.WriteString("    _exp = instance.exports;\n")
	sb.WriteString("    const _m = _exp.memory;\n")
	sb.WriteString("    _staticTop = _m.buffer.byteLength; // first byte after DFA table pages\n")
	sb.WriteString("    _bump = _staticTop;\n")
	sb.WriteString("    _m.grow(2);                       // 1 page for input, 1 page for output/slots\n")
	sb.WriteString("    _mem = new Uint8Array(_m.buffer); // re-acquire after grow\n")
	sb.WriteString("}\n\n")

	// ── Regions ─────────────────────────────────────────────────────────────
	//
	// Standalone WASM cannot read the JS heap, so an input must be COPIED into
	// linear memory. Copying is not the hazard; SHARING one staging address is.
	// A generator stages its input, yields, and resumes — and anything the
	// caller ran in between had written its own input over the top, so the scan
	// continued across another string's bytes and reported offsets against it.
	// Silently: no exception, plausible output.
	//
	// The merged-mode targets never had this. Rust passes `input.as_ptr()` and
	// Go `unsafe.SliceData(input)`, so each live input already sits at its own
	// address and nothing relocates it. That — distinct, stable addresses — is
	// what makes them safe, not the absence of a copy. So this reproduces it:
	// every call carves its OWN region and keeps it, which gives JS the same
	// contract with a copy still in the middle.
	//
	// A bump allocator over a STACK of regions, one per live iterator. A
	// finished iterator marks its region free, and every free region at the
	// top is given back, so the arena resets when the last iterator finishes —
	// between every loop, for ordinary code. An iterator that is never
	// finished (started with next() and dropped, neither run to its end nor
	// return()ed) keeps ITS region and nothing else: the ones above it are
	// still given back as they finish. A live-iterator COUNT was used before,
	// and one such iterator kept the count above zero for good, so every later
	// iterator's region leaked too and, under max_memory, the instance died.
	sb.WriteString("function _align(x) { return (x + 7) & ~7; }\n\n")
	sb.WriteString(jsGrowFunc(false))
	// lib.dom.d.ts declares TextEncoderEncodeIntoResult.read/written as
	// optional, so strict TypeScript needs the non-null assertions; both are
	// always present at runtime per the Encoding spec.
	sb.WriteString(`function _write(input, at) {
    // Writes the input at ` + "`at`" + `, growing memory for it as it goes, and
    // returns the bytes it took. encodeInto writes straight into WASM memory,
    // avoiding both the array TextEncoder.encode allocates and the copy
    // _mem.set would then make. A string reserves its length in UTF-16 units —
    // every ASCII string's exact size — and grows by the worst case of what is
    // left (3 bytes a unit) only when that did not fit: reserving 3 per unit
    // up front refused, under max_memory, a 1.5 MB ASCII string whose bytes fit.
    if (typeof input !== 'string') {
        _grow(at + input.length);
        _mem.set(input, at);
        return input.length;
    }
    _grow(at + input.length);
    const r = _enc.encodeInto(input, _mem.subarray(at));
    let written = r.written;
    if (r.read < input.length) {
        // encodeInto never splits a surrogate pair, so the rest starts on one.
        const rest = input.slice(r.read);
        _grow(at + written + rest.length * 3);
        written += _enc.encodeInto(rest, _mem.subarray(at + written)).written;
    }
    return written;
}

`)
	// Emitted only when something uses them: a stub is a file the caller
	// compiles, and TypeScript under --noUnusedLocals rejects a declared
	// helper nothing calls. A match-only config has no generator, and a
	// generator-only config has no one-shot call.
	if hasOneShotExports(cfg) {
		sb.WriteString("function _stage(input, outBytes) {\n")
		sb.WriteString("    // For calls that CANNOT suspend. They run to completion before anything\n")
		sb.WriteString("    // else can allocate, so they may reuse the space above the bump without\n")
		sb.WriteString("    // reserving it — which is what stops a one-shot call inside a loop over a\n")
		sb.WriteString("    // live iterator from allocating a region per iteration.\n")
		sb.WriteString("    const at = _bump, len = _write(input, at), out = _align(at + len);\n")
		sb.WriteString("    _grow(out + (outBytes > 0 ? outBytes : 65536));\n")
		sb.WriteString("    return [at, out, len];\n")
		sb.WriteString("}\n\n")
	}
	hdrBytes := strconv.Itoa(config.SetOverlapCheckpointHeaderBytes)
	if hasSuspendableExports(cfg) {
		sb.WriteString(`function _open(input, outBytes, cacheFor) {
    // For generators, which DO suspend. The region is reserved for the
    // iterator's whole lifetime, so no other call can land on its input or
    // its scratch. Release with _close() from a finally.
    //
    // Nothing is reserved until every grow has succeeded. A grow that throws
    // leaves _bump and _regs as they were, so the instance stays usable; when
    // _bump moved first, a grow refused under a memory ceiling left it past the
    // end of memory with no iterator alive to reset it, and every later call
    // threw.
    //
    // The answer cache is sized by cacheFor from the bytes the input actually
    // took, and only its HEADER is reserved here: the region itself is
    // reserved by _lazy when the module asks for it, and most scans never do.
    // Under a ceiling a refused grow only DECLINES the cache: a zero-length
    // cache is the documented "walk" signal, so the drive is slower instead of
    // failing. The size returned is the whole region's.
    const at = _bump, len = _write(input, at), out = _align(at + len);
    // outBytes is what the iterator writes there — a batch buffer, a groups
    // call's slots, a set's gates and tuples — and nothing more: a find that
    // writes nothing reserves nothing.
    const top = out + outBytes;
    _grow(top);
    let k = 0, cache = 0;
    if (cacheFor) {
        [k, cache] = cacheFor(len);
        if (cache > 0) {
            try { _grow(top + ` + hdrBytes + `); } catch (e) { if (!(e instanceof RangeError)) throw e; cache = 0; }
        }
    }
    _bump = top + (cache > 0 ? ` + hdrBytes + ` : 0);
    _regs.push({ at, top: _bump, free: false });
    return [at, out, len, cache, k];
}

`)
		sb.WriteString("function _close(at) {\n" +
			"    // Frees the region _open placed at `at`, then gives back every free\n" +
			"    // region at the top of the stack.\n" +
			"    for (let i = _regs.length - 1; i >= 0; i--) if (_regs[i].at === at) { _regs[i].free = true; break; }\n" +
			"    while (_regs.length > 0 && _regs[_regs.length - 1].free) _regs.pop();\n" +
			"    _bump = _regs.length > 0 ? _regs[_regs.length - 1].top : _staticTop;\n" +
			"}\n\n")
		sb.WriteString("function _att(view, Ctor, at, len) {\n")
		sb.WriteString("    // A view survives its own iterator's lifetime EXCEPT across a grow, which\n")
		sb.WriteString("    // detaches every view in the module no matter whose region it points at —\n")
		sb.WriteString("    // the one hazard the merged-mode targets have no analogue for, since they\n")
		sb.WriteString("    // hold native pointers rather than views. A detached view reports\n")
		sb.WriteString("    // length 0 and reads as undefined SILENTLY, so re-attach on that. The\n")
		sb.WriteString("    // offset is still ours, so rebuilding at the same place is correct.\n")
		sb.WriteString("    return view.length === 0 ? new Ctor(_exp.memory.buffer, at, len) : view;\n")
		sb.WriteString("}\n\n")

	}
	// Each find/groups export's per-search block, if its pattern keeps notes
	// (search_stub.go).
	sizes := searchSizesFor(cfg)
	if hasSuspendableExports(cfg) && anySearchBlock(sizes) {
		sb.WriteString(jsSearchHelpers(false, sizes))
	}
	for _, re := range cfg.Patterns {
		if re.MatchFunc != "" {
			sb.WriteString(genJSMatchFunc(re.MatchFunc))
		}
		if re.FindFunc != "" {
			sb.WriteString(jsWithSearch(genJSFindFunc(re.FindFunc), re.FindFunc, sizes[re.FindFunc], false, false, 0))
		}
		if re.GroupsFunc != "" {
			numGroups, namedGroups, err := extractGroupInfo(re.Regexp)
			if err != nil {
				return "", fmt.Errorf("pattern %q: %w", re.Written(), err)
			}
			sb.WriteString(jsWithSearch(genJSGroupsFunc(re.GroupsFunc, numGroups), re.GroupsFunc,
				sizes[re.GroupsFunc], false, true, numGroups*2*4))
			sb.WriteString(genJSGroupIndices(re.GroupsFunc, numGroups, namedGroups))
		}
	}

	sb.WriteString(genJSSetSection(cfg, sizes))
	return sb.String(), nil
}

// jsGrowFunc emits `_grow`, shared by the JS and TS stubs (ts adds the casts).
//
// It does three things, and the last two exist because a call INTO the module
// can grow memory as well: a Backtracking fallback sizes its frame stack and
// memo from the input at call time.
//
//   - grows memory until `top` fits;
//   - re-acquires `_mem` whenever the buffer changed, whoever grew it — a grow
//     detaches every view of the old buffer, and _write reads through `_mem`;
//   - keeps the module's scratch-base global (abi.ScratchBaseExport) at the
//     highest byte this stub has ever handed out, so that scratch lands above
//     every live region. Raised only, never lowered: a suspended iterator's
//     region stays live after `_bump` resets. Read unsigned, because an i32
//     global reads back negative past 2 GiB. Absent when the module has no
//     Backtracking program.
func jsGrowFunc(ts bool) string {
	sig, mem, global := "function _grow(top) {", "_exp.memory", "_exp['"+abi.ScratchBaseExport+"']"
	if ts {
		sig = "function _grow(top: number): void {"
		mem = "(_exp.memory as WebAssembly.Memory)"
		global = "(_exp['" + abi.ScratchBaseExport + "'] as WebAssembly.Global | undefined)"
	}
	return sig + "\n" +
		"    const m = " + mem + ";\n" +
		"    if (top > m.buffer.byteLength) m.grow(Math.ceil((top - m.buffer.byteLength) / 65536));\n" +
		"    if (_mem.buffer !== m.buffer) _mem = new Uint8Array(m.buffer); // a grow DETACHES the old view\n" +
		"    const sb = " + global + ";\n" +
		"    if (sb !== undefined && top > (sb.value >>> 0)) sb.value = top;\n" +
		"}\n\n"
}

// genJSMatchFunc generates a JS export for an anchored match.
// The generated function returns the end position, or null if no match — the
// doc here used to say `[endPos, true]` / `[0, false]`, a tuple shape the code
// has never produced.
func genJSMatchFunc(funcName string) string {
	return fmt.Sprintf(`// %s — anchored match; returns the end position, or null if no match.
export function %s(input) {
    const [_inBase, _outBase, len] = _stage(input, 0);
    const r = _exp['%s'](_inBase, len);
    if (r === %d) throw new Error("%s");
    return r < 0 ? null : r;
}

`, funcName, funcName, funcName, btOverflow, btOverflowMsg(funcName))
}

// lm2BatchCap is the per-refill match capacity used by the JS/TS find/groups
// generators' batch path, whose trigger is the "batch-find" hint. Not
// user-configurable
// in v1 — see set stubs' batchSize for the analogous, config-driven sizing
// used by sets.
const lm2BatchCap = 256

// genJSFindFunc generates a JS generator for non-anchored find.
// Yields [start, end] absolute byte positions for each non-overlapping match.
//
// Prefers the batch export (funcName+"_batch", requested via the "batch-find"
// hint) when the loaded WASM provides one — draining
// lm2BatchCap matches per host call instead of one — and falls back to the
// standard one-call-per-match loop otherwise. The feature-detect (typeof
// check, once per generator invocation) makes this stub work unmodified
// whether or not the pattern's hints requested a batch export, so it doesn't
// need to replicate the compiler's hint-resolution logic.
func genJSFindFunc(funcName string) string {
	return fmt.Sprintf(`// %[1]s — yields [start, end] for each non-overlapping match.
export function* %[1]s(input, offset = 0) {
    const _batched = typeof _exp['%[1]s_batch'] === 'function';
    // One region for whichever path runs, held for this iterator's lifetime so
    // an interleaved stub call cannot overwrite the staged input mid-scan.
    const [_inBase, _outBase, len] = _open(input, _batched ? %[2]d * 8 : 0);
    try {
    if (_batched) {
        let outBuf = new Uint32Array(_exp.memory.buffer, _outBase, %[2]d * 2);
        let startPos = offset;
        let prevEnd = -1;
        while (true) {
            const n = _exp['%[1]s_batch'](_inBase, len, _outBase, %[2]d, startPos);
            if (n === %[3]d) throw new Error("%[4]s");
            if (n <= 0) break;
            for (let i = 0; i < n; i++) {
                // Re-attached each step: the yield below hands control back,
                // and a grow there detaches every view in the module.
                outBuf = _att(outBuf, Uint32Array, _outBase, %[2]d * 2);
                const s = outBuf[i * 2], e = outBuf[i * 2 + 1];
                // Go's FindAllIndex rule: suppress an EMPTY match beginning
                // exactly where the previous reported match ended.
                if (s === e && s === prevEnd) continue;
                prevEnd = e;
                yield [s, e];
            }
            if (n < %[2]d) break;
            outBuf = _att(outBuf, Uint32Array, _outBase, %[2]d * 2);
            const lastStart = outBuf[(n - 1) * 2], lastEnd = outBuf[(n - 1) * 2 + 1];
            startPos = lastEnd > lastStart ? lastEnd : lastStart + 1;
        }
        return;
    }
    let off = offset;
    let prevEnd2 = -1;
    while (off <= len) {
        // Whole input plus a start position: offset bounds where the search
        // begins, it does not truncate what the engine sees behind it.
        const r = _exp['%[1]s'](_inBase, len, off);
        if (r === %[3]dn) throw new Error("%[4]s");
        if (r < 0n) break;
        const absStart = Number(r >> 32n);
        const absEnd   = Number(r & 0xFFFFFFFFn);
        const relStart = absStart - off, relEnd = absEnd - off;
        // See the batch path: Go suppresses an empty match adjacent to the
        // previous one. The advance below is unchanged.
        if (!(absStart === absEnd && absStart === prevEnd2)) {
            prevEnd2 = absEnd;
            yield [absStart, absEnd];
        }
        off += relEnd > relStart ? relEnd : relStart + 1;
    }
    } finally { _close(_inBase); }
}

`, funcName, lm2BatchCap, btOverflow, btOverflowMsg(funcName))
}

// genJSGroupsFunc generates a JS generator for indexed capture groups.
// Yields an array per match; each element is [start, end] or null for
// unmatched groups. Index 0 is the full match.
//
// Prefers the batch export (funcName+"_batch") the same way
// genJSFindFunc does — see its doc comment. The batch record layout is
// [start, end, group0_start, group0_end, ...] (recSize ints; group 0
// duplicates start/end — see buildBatchGroupsWrapperBody's doc comment in
// compile/compile.go).
func genJSGroupsFunc(funcName string, numGroups int) string {
	slotCount := numGroups * 2
	recSize := 2 + slotCount // ints per batch record
	recBytes := recSize * 4  // bytes per batch record
	return fmt.Sprintf(`// %[1]s — yields capture group arrays per match.
// Each element is [start, end] (absolute) or null for unmatched groups.
// Index 0 is the full match.
export function* %[1]s(input, offset = 0) {
    const _batched = typeof _exp['%[1]s_batch'] === 'function';
    // One region for whichever path runs, held for this iterator's lifetime so
    // an interleaved stub call cannot overwrite the staged input mid-scan.
    const [_inBase, _outBase, len] = _open(input, _batched ? %[2]d * %[4]d : %[9]d);
    try {
    if (_batched) {
        let outBuf = new Int32Array(_exp.memory.buffer, _outBase, %[2]d * %[3]d);
        let startPos = offset;
        // Kept ACROSS calls, exactly as the find batch loop does. The in-WASM
        // wrapper suppresses empty-adjacent matches only within one call, so a
        // batch that fills ending on a non-empty match at p resumes at p and
        // would report an empty match at p that Go suppresses.
        let prevEnd = -1;
        while (true) {
            const n = _exp['%[1]s_batch'](_inBase, len, _outBase, %[2]d, startPos);
            if (n === %[7]d) throw new Error("%[8]s");
            if (n <= 0) break;
            for (let i = 0; i < n; i++) {
                // Re-attached each step: the yield below hands control back,
                // and a grow there detaches every view in the module.
                outBuf = _att(outBuf, Int32Array, _outBase, %[2]d * %[3]d);
                const base = i * %[3]d;
                const ms = outBuf[base], me = outBuf[base + 1];
                if (ms === me && ms === prevEnd) continue;
                prevEnd = me;
                const result = [];
                for (let g = 0; g < %[5]d; g++) {
                    const s = outBuf[base + 2 + g * 2], e = outBuf[base + 2 + g * 2 + 1];
                    result.push(s < 0 ? null : [s, e]);
                }
                yield result;
            }
            if (n < %[2]d) break;
            outBuf = _att(outBuf, Int32Array, _outBase, %[2]d * %[3]d);
            const lastBase = (n - 1) * %[3]d;
            const lastStart = outBuf[lastBase], lastEnd = outBuf[lastBase + 1];
            startPos = lastEnd > lastStart ? lastEnd : lastStart + 1;
        }
        return;
    }
    // Hoisted out of the loop rather than rebuilt per match, and re-attached
    // by _att when an interleaved call grew memory while suspended.
    let slots = new Int32Array(_exp.memory.buffer, _outBase, %[6]d);
    let off = offset;
    let prevEnd = -1;
    while (off <= len) {
        slots = _att(slots, Int32Array, _outBase, %[6]d);
        slots.fill(-1);
        const r = _exp['%[1]s'](_inBase, len, _outBase, off);
        if (r === %[7]d) throw new Error("%[8]s");
        // The call itself may have grown memory — a Backtracking fallback
        // sizes its scratch from the input — which detaches this view.
        slots = _att(slots, Int32Array, _outBase, %[6]d);
        if (r < 0) {
            // Terminal, not "try the next position": the groups
            // export has SCAN-FROM semantics in both wrapper arms, so a
            // negative result means there is no match at or after off. The
            // advance-by-one retry this replaced re-scanned the tail once per
            // remaining byte.
            break;
        }
        const matchEnd = slots[1] >= 0 ? slots[1] : slots[0];
        const result = [];
        for (let i = 0; i < %[5]d; i++) {
            const s = slots[i * 2], e = slots[i * 2 + 1];
            result.push(s < 0 ? null : [s, e]); // absolute already
        }
        const absStart = slots[0], absEnd = matchEnd;
        off = absEnd > absStart ? absEnd : absStart + 1;
        // Go's FindAllSubmatchIndex rule: suppress an EMPTY match beginning
        // exactly where the previous reported match ended. The advance above
        // is unchanged.
        if (absStart === absEnd && absStart === prevEnd) continue;
        prevEnd = absEnd;
        yield result;
    }
    } finally { _close(_inBase); }
}

`, funcName, lm2BatchCap, recSize, recBytes, numGroups, slotCount, btOverflow, btOverflowMsg(funcName), (slotCount*4+7)&^7)
}

// genJSGroupIndices emits the name→index object for a groups function.
// Replaces the retired `named_groups_func`.
//
// One frozen object rather than loose constants: that is how modern JS groups
// related values, `Object.keys` then covers name enumeration, and it needs no
// second lookup helper. The name carries an `indices` suffix because the
// object is the only derived symbol with no suffix of its own — without one
// its name would be the generator function's and the two would collide.
func genJSGroupIndices(funcName string, numGroups int, namedGroups map[string]int) string {
	if len(namedGroups) == 0 {
		return ""
	}
	names := groupNameSlots(numGroups, namedGroups)

	var out strings.Builder
	fmt.Fprintf(&out, `// Index of each NAMED capture group of %s. Index 0 is the whole match;
// unnamed groups are absent and are addressed by number. Object.keys() gives
// you the names, and the yielded array's length is always %d whether or not a
// group participated.
export const %s = Object.freeze({
`, funcName, numGroups, derivedConstName(funcName, "indices"))
	for idx, name := range names {
		if name == "" {
			continue
		}
		// QUOTED. Go's regexp/syntax accepts digit-leading group names —
		// `(?<1a>x)` parses — and a bare `1a:` key is a SyntaxError that
		// takes the whole generated module down with it. %q is valid for
		// every key, keeps Object.keys() behaviour, and leaves TS's `as const`
		// literal types intact.
		fmt.Fprintf(&out, "    %q: %d,\n", name, idx)
	}
	out.WriteString("});\n\n")
	return out.String()
}

// jsFindGateRegion is the byte span between a `find` region's tuple buffer and
// its answer cache: the gate array, the scratch descriptor and, for a wide set,
// the id bitmap.
//
// Rounded up to 8 for an overlapping set because the bitmap's width is
// ceil(ID_SPACE/8) and need not be a multiple of 4, while the cache header is
// read through a Uint32Array — and a typed-array view whose byte offset is not
// a multiple of its element size THROWS.
func jsFindGateRegion(s config.SetConfig, cfg config.BuildConfig, idN int) int {
	r := 4*idN + scratchDescriptorBytes + bitmapBytes(s, cfg)
	if s.Overlapping {
		r = (r + 7) &^ 7
	}
	return r
}

// jsOverlapCacheBlock emits the answer cache's sizing, reservation and header
// seeding — the three pieces BOTH of a set's `find` shapes need.
//
// ONE emitter, because the plain and batching generators are otherwise
// independent and drifted: the batching one built a cache and the plain one
// wrote a descriptor saying there was none, so a JS or TS caller iterating an
// overlapping set without the hint got the quadratic walk the cache exists to
// retire.
//
// The arithmetic MUST match config.SetOverlapCheckpoint* exactly: the sweep
// validates the stride it is handed and reports a header it cannot parse.
// Below the budget the stride is the WHOLE SPAN, which is a single block: one
// sweep, nothing re-swept. Above it the stride falls to the square-root
// optimum and the region becomes sqrt-sized, at the cost of sweeping each
// position twice.
//
// The returned strings are, in order: the prelude defining _cacheFor (before
// _open, which calls it once the input is written and its byte count known),
// the names to add to _open's destructuring, the argument to append to _open's
// call, the post-open seeding, and the descriptor's cache arguments.
func jsOverlapCacheBlock(s config.SetConfig, sh cacheShape, gateRegion int) (pre, dest, reserve, post, args string) {
	args = "0, 0"
	if !s.Overlapping || !sh.Offered() {
		return pre, dest, reserve, post, args
	}
	// The sweep column's width comes from the compiler — the set is recompiled
	// to learn it — and is baked in as a constant; everything else is
	// arithmetic on the input length, which only exists at call time.
	k := overlapCacheConstsFor(sh)
	if sh.Eligible {
		pre = fmt.Sprintf(`    // [stride, bytes] of the answer cache for an input of _len bytes; _open
    // calls it with the count the input actually took.
    const _cacheFor = (_len) => {
        const _m = _len + 1;
        const _row = %[1]d;
        const _cell = %[2]d;
        const _single = %[3]d + _m * _row;
        let _k;
        if (_single > 0 && _single <= %[4]d) {
            _k = _m;
        } else {
            _k = Math.floor(Math.sqrt(_m * %[5]d * 4 / _row));
            if (_k < 16) _k = 16;
            if (_k > _m) _k = _m;
        }
        const _nb = Math.ceil(_m / _k);
        const cacheNeeded = %[6]d + _nb * _cell + 4 + _k * _row;
`, k.Row, k.Cell, k.Base, k.Max, k.Cells, k.Hdr)
	} else {
		// No answer cache, only the program sweep's part: the cache's is its
		// bare header.
		pre = fmt.Sprintf(`    // [stride, bytes] of the region for an input of _len bytes; _open calls it
    // with the count the input actually took.
    const _cacheFor = (_len) => {
        const _m = _len + 1;
        const _k = 1;
        const cacheNeeded = %d;
`, k.Hdr)
	}
	if sh.SweepCells == 0 {
		pre += fmt.Sprintf(`        const cacheBytes = cacheNeeded <= %[1]d ? cacheNeeded : 0;
        return [_k, cacheBytes];
    };
`, k.Max)
	} else {
		// The program sweep's part, after the cache's, checkpointed by the
		// same formula over its own geometry.
		pre += fmt.Sprintf(`        if (cacheNeeded > %[2]d) return [_k, 0];
        let _sk = _m;
        if (%[1]d + %[4]d + 4 + _m * %[3]d > %[2]d) {
            _sk = Math.floor(Math.sqrt(_m * %[5]d * 4 / %[3]d));
            if (_sk < 16) _sk = 16;
            if (_sk > _m) _sk = _m;
        }
        const _sb = %[1]d + Math.ceil(_m / _sk) * %[4]d + 4 + _sk * %[3]d;
        return [_k, _sb <= %[2]d ? Math.ceil(cacheNeeded / 8) * 8 + _sb : cacheNeeded];
    };
`, k.Hdr, k.Max, sh.SweepRow, sh.SweepCells*4+4, sh.SweepCells)
	}
	// _open returns the region's size — 0 when a memory ceiling refused even
	// its header — and the stride it was sized with.
	dest = ", cacheBytes, _k"
	reserve = ", _cacheFor"
	// The header is zeroed and then the STRIDE written into it: it is the one
	// field the caller owns, because the caller is what sized the allocation
	// from it. And the LAZY word: the descriptor carries the header alone until
	// the module asks for the region (_lazy).
	pre += "    let _cacheAt = 0;\n"
	post = fmt.Sprintf(`    const cacheBase = cacheBytes > 0 ? gateBase + %d : 0;
    if (cacheBase !== 0) {
        const _hdr = new Uint32Array(_exp.memory.buffer, cacheBase, %d);
        _hdr.fill(0);
        _hdr[%d] = _k;
        _hdr[%d] = %d;
    }
`, gateRegion, config.SetOverlapCheckpointHeaderBytes/4, config.SetOverlapHdrStrideOff/4,
		config.SetOverlapHdrLazyOff/4, uint32(abi.OverlapCacheLazy))
	args = fmt.Sprintf("cacheBase, cacheBase !== 0 ? %d : 0", config.SetOverlapCheckpointHeaderBytes)
	return pre, dest, reserve, post, args
}

// jsLazyArgs is what jsOverlapCacheBlock returns as a cache-carrying
// descriptor's arguments; anything else carries no cache.
var jsLazyArgs = fmt.Sprintf("cacheBase, cacheBase !== 0 ? %d : 0", config.SetOverlapCheckpointHeaderBytes)

// jsLazyWanted is a find shape's answer to the module asking for the answer
// cache's region — test is the shape's own spelling of "it asked" — or "" for
// a find that carries no cache (args from jsOverlapCacheBlock).
func jsLazyWanted(args, test string) string {
	if args != jsLazyArgs {
		return ""
	}
	return fmt.Sprintf(`        // The module would start using the answer cache now and delivered
        // nothing: hand the region over, or none, and call again. It never
        // asks twice.
        if (%s) { _cacheAt = _lazy(cacheBase, cacheBytes, scratchBase); continue; }
`, test)
}

// jsLazyFinally frees the region _lazy reserved, before the iterator's own.
func jsLazyFinally(args string) string {
	if args != jsLazyArgs {
		return ""
	}
	return "if (_cacheAt) _close(_cacheAt); "
}

// jsLazyFunc is `_lazy`, which reserves the answer cache's region when the
// module asks for it: a region of its own on the stack _open keeps, freed by
// the iterator's finally. The header is copied over, its lazy word cleared,
// and the descriptor pointed at it. A grow refused under a memory ceiling
// clears the lazy word in place instead, and the module walks.
func jsLazyFunc(ts bool) string {
	sig, mem := "function _lazy(hdr, bytes, desc) {", "_exp.memory.buffer"
	if ts {
		sig, mem = "function _lazy(hdr: number, bytes: number, desc: number): number {", "(_exp.memory as WebAssembly.Memory).buffer"
	}
	return fmt.Sprintf(`%[1]s
    // The module asks for the answer cache's region: reserve it as a region of
    // its own, copy the header over and point the descriptor at it. A grow
    // refused under a memory ceiling hands none over — the lazy word is
    // cleared, and the module walks: the same answers, slower.
    const at = _align(_bump);
    try {
        _grow(at + bytes);
    } catch (e) {
        if (!(e instanceof RangeError)) throw e;
        new Uint32Array(%[2]s, hdr, %[3]d)[%[4]d] = 0;
        return 0;
    }
    _bump = at + bytes;
    _regs.push({ at, top: _bump, free: false });
    const c = new Uint32Array(%[2]s, at, %[3]d);
    c.set(new Uint32Array(%[2]s, hdr, %[3]d));
    c[%[4]d] = 0;
    new Uint32Array(%[2]s, desc + %[5]d, 2).set([at, bytes]);
    return at;
}

`, sig, mem, config.SetOverlapCheckpointHeaderBytes/4, config.SetOverlapHdrLazyOff/4, abi.FindScratchCacheOff)
}
