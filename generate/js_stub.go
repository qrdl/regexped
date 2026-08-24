package generate

import (
	"fmt"
	"os"
	"sort"
	"strings"

	"github.com/qrdl/regexped/config"
)

// jsStub generates a JS ES module stub file for all regexp entries and sets in cfg.
// out is the full output path or "-" for stdout.
func jsStub(cfg config.BuildConfig, out string) error {
	content, err := genJSStubFile(cfg)
	if err != nil {
		return fmt.Errorf("generate JS stub: %w", err)
	}
	if out == "-" {
		_, err := os.Stdout.WriteString(content)
		return err
	}
	return writeStub(out, []byte(content))
}

// genJSSetSection returns JS set wrappers appended to the module body.
// Called from genJSStubFile's inner builder when cfg.Sets is non-empty.
func genJSSetSection(cfg config.BuildConfig) string {
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
	out.WriteString("// Do not call other stub functions while an iterator is suspended: the\n")
	out.WriteString("// staged input and the shared output region belong to whichever call ran\n")
	out.WriteString("// last (see docs/js-api.md).\n\n")
	for _, s := range cfg.Sets {
		n := patternsInSet(s, cfg)
		konst := camelSet(s.Name) + "PatternCount"
		idN := idSpaceSize(s, cfg)
		idKonst := camelSet(s.Name) + "IdSpace"
		wide := wideAllForm(s, cfg)
		// §4.9 standalone layout, all above _outBase: the tuple buffer
		// (12 bytes x pattern count), then the gate array (4 bytes x ID
		// SPACE), then the >64-pattern bitmap (ceil(idSpace/8)). The two
		// counts differ for a set that selects a named subset — see
		// idSpaceSize.
		reserve := 12*n + 4*idN + bitmapBytes(s, cfg)
		gateBase := fmt.Sprintf("_outBase + 12*%s", konst)
		bitmapBase := fmt.Sprintf("_outBase + 12*%s + 4*%s", konst, idKonst)

		fmt.Fprintf(&out, "// Number of patterns in set %q. Sizes the match buffer: the find generator\n// can receive at most this many matches at one position.\nexport const %s = %d;\n\n", s.Name, konst, n)
		fmt.Fprintf(&out, "// One past the largest pattern id set %q can report. Pattern ids are global\n// indices into regexps:, so a set holding a few late-declared patterns has a\n// small count and a large id space. Everything indexed BY an id \u2014 the gate\n// array, the _all bitmask \u2014 is sized from this.\nexport const %s = %d;\n\n", s.Name, idKonst, idN)

		if s.BatchFind() {
			fmt.Fprintf(&out, "// Largest batchSize %s accepts for set %q. It is the cursor layout's\n// limit, not a policy: one i64 carries the resume position in its top 32\n// bits and splits the low 32 between the intra-position index and the count.\n// It never binds in practice — this many tuples is a multi-megabyte buffer.\nexport const %s = %d;\n\n",
				s.Find, s.Name, camelSet(s.Name)+"BatchMaxSize", cursorMaxCount(s, cfg))
		}

		if s.MatchAny != "" {
			fmt.Fprintf(&out, `// -> number | null   (a pattern id, NOT a boolean)
export function %s(input) {
    const len = _w(input);
    const id = _exp['%s'](_inBase, len);
    return id < 0 ? null : id;
}
`, s.MatchAny, s.MatchAny)
		}
		if s.MatchAll != "" {
			if wide {
				fmt.Fprintf(&out, `// -> number[]   (pattern ids, NOT a boolean)
export function %s(input) {
    const len = _w(input, %d);
    const bitmapBase = %s;
    new Uint8Array(_mem.buffer, bitmapBase, (%s+7)>>3).fill(0);
    _exp['%s'](_inBase, len, bitmapBase);
    const bits = new Uint8Array(_mem.buffer, bitmapBase, (%s+7)>>3);
    const out = [];
    for (let k = 0; k < %s; k++) if (bits[k>>3] & (1 << (k & 7))) out.push(k);
    return out;
}
`, s.MatchAll, reserve, bitmapBase, idKonst, s.MatchAll, idKonst, idKonst)
			} else {
				fmt.Fprintf(&out, `// -> number[]   (pattern ids, NOT a boolean)
export function %s(input) {
    const len = _w(input);
    // The export returns an i64, which surfaces as a BigInt; it is decomposed
    // here and never reaches the caller.
    let mask = _exp['%s'](_inBase, len);
    const out = [];
    for (let k = 0; k < %s; k++) if ((mask >> BigInt(k)) & 1n) out.push(k);
    return out;
}
`, s.MatchAll, s.MatchAll, idKonst)
			}
		}
		if s.ScanAny != "" {
			fmt.Fprintf(&out, `// -> pattern id | null   (NOT a boolean, and NO position)
export function %s(input, from = 0) {
    const len = _w(input);
    const id = _exp['%s'](_inBase, len, from);
    return id < 0 ? null : id;
}
`, s.ScanAny, s.ScanAny)
		}
		if s.ScanAll != "" {
			if wide {
				fmt.Fprintf(&out, `// -> number[]   (pattern ids, NOT a boolean)
export function %s(input, from = 0) {
    const len = _w(input, %d);
    const bitmapBase = %s;
    new Uint8Array(_mem.buffer, bitmapBase, (%s+7)>>3).fill(0);
    _exp['%s'](_inBase, len, from, bitmapBase);
    const bits = new Uint8Array(_mem.buffer, bitmapBase, (%s+7)>>3);
    const out = [];
    for (let k = 0; k < %s; k++) if (bits[k>>3] & (1 << (k & 7))) out.push(k);
    return out;
}
`, s.ScanAll, reserve, bitmapBase, idKonst, s.ScanAll, idKonst, idKonst)
			} else {
				fmt.Fprintf(&out, `// -> number[]   (pattern ids, NOT a boolean)
export function %s(input, from = 0) {
    const len = _w(input);
    let mask = _exp['%s'](_inBase, len, from);
    const out = [];
    for (let k = 0; k < %s; k++) if ((mask >> BigInt(k)) & 1n) out.push(k);
    return out;
}
`, s.ScanAll, s.ScanAll, idKonst)
			}
		}
		if s.Find != "" {
			gateSetup, gateArg, gateDoc := "", "", ""
			if gatedFind(s) {
				gateSetup = fmt.Sprintf(`    const gateBase = %s;
    new Uint32Array(_mem.buffer, gateBase, %s).fill(0);
`, gateBase, idKonst)
				gateArg = "gateBase, "
				gateDoc = "// The generator owns the gate array for its lifetime: dropping it and\n" +
					"// creating a new one restarts the scan with clean gates.\n"
			}
			if !s.BatchFind() {
				// No `batch-find` hint: no batchSize parameter at all, so TS
				// rejects find(input, 0, 64) at build time and JS ignores it
				// the way it ignores any extra argument. One WASM call per
				// matching position.
				fmt.Fprintf(&out, `// -> Generator yielding { patternId, start, end }
%sexport function* %s(input, offset = 0) {
    const len = _w(input, %d);
%s    let pos = offset;
    // Hoisted: _mem.buffer and _outBase are loop-invariant, and the input is
    // staged once above, so nothing can detach this view mid-scan. Building it
    // per call allocated one typed array per matching position.
    const buf = new Int32Array(_mem.buffer, _outBase, 3*%s);
    while (true) {
        // The buffer is sized at the set's pattern count, the exact worst case
        // for a single position, so n can never exceed it.
        const n = _exp['%s'](_inBase, len, pos, %s_outBase, %s);
        if (n <= 0) break;
        // Every tuple in one call shares a start; resume one past it.
        const next = buf[1] + 1;
        for (let i = 0; i < n; i++) {
            yield { patternId: buf[i*3], start: buf[i*3+1], end: buf[i*3+2] };
        }
        pos = next;
    }
}
`, gateDoc, s.Find, reserve, gateSetup, konst, s.Find, gateArg, konst)
			} else {
				// `hints: [batch-find]`: the same matches in the same order,
				// but batchSize positions of work per host crossing. That is
				// the ONLY difference, which is why it is a parameter rather
				// than a second function — and why it is opt-in, since a
				// caller who stops early has paid for matches never looked at.
				batchGateSetup := ""
				if gatedFind(s) {
					batchGateSetup = fmt.Sprintf(`    const gateBase = _outBase + 12*batchSize;
    new Uint32Array(_mem.buffer, gateBase, %s).fill(0);
`, idKonst)
				}
				fmt.Fprintf(&out, `// -> Generator yielding { patternId, start, end }
//
// batchSize is how many tuples one WASM call may fill: 1 is a call per
// matching position, larger values amortise the host crossing over a
// bufferful. Clamped into [1, %s].
%sexport function* %s(input, offset = 0, batchSize = %d) {
    batchSize = Math.min(Math.max(batchSize | 0, 1), %s);
    const len = _w(input, 12*batchSize + %d);
%s    let cursor = BigInt(offset) << 32n;
    // Hoisted for the same reason the per-position shape hoists its view:
    // _mem.buffer and _outBase are loop-invariant once the input is staged.
    const buf = new Int32Array(_mem.buffer, _outBase, 3*batchSize);
    while (true) {
        const packed = _exp['%s'](_inBase, len, cursor, %s_outBase, batchSize);
        // The cursor is opaque: hand it back unchanged. Only its top 32 bits
        // are public — all ones means the scan is finished, and that arrives
        // on the same call as the last matches.
        const n = Number(packed & %dn);
        const done = (BigInt.asUintN(64, packed) >> 32n) === 0xFFFFFFFFn;
        for (let i = 0; i < n; i++) {
            yield { patternId: buf[i*3], start: buf[i*3+1], end: buf[i*3+2] };
        }
        // A call reports at least one match unless the scan is over.
        if (done || n === 0) break;
        cursor = packed;
    }
}
`, camelSet(s.Name)+"BatchMaxSize", gateDoc, s.Find, defaultBatchCap(s, cfg),
					camelSet(s.Name)+"BatchMaxSize", 4*idN+bitmapBytes(s, cfg), batchGateSetup,
					config.SetBatchExportName(s.Find), gateArg, cursorCountMask(s, cfg))
			}
		}
		out.WriteString("\n")
	}
	if hasEmitNameMap(cfg) {
		out.WriteString("const _patternNames = [")
		for i, re := range cfg.Regexps {
			if i > 0 {
				out.WriteString(", ")
			}
			fmt.Fprintf(&out, "%q", re.Name)
		}
		out.WriteString("];\nexport function patternName(id) { return _patternNames[id] ?? ''; }\n")
	}
	return out.String()
}

// genJSStubFile generates the content of an ES module JS stub that exports
// wrapper functions for every regexp entry in cfg.  The caller is responsible
// for loading the WASM file and passing the bytes (or a WebAssembly.Module)
// to the exported init() function before calling any matcher.
func genJSStubFile(cfg config.BuildConfig) (string, error) {
	// Determine whether any entry needs a slots buffer (groups/named_groups).
	var sb strings.Builder
	sb.WriteString("// Auto-generated by regexped. Do not edit.\n\n")

	sb.WriteString("let _exp, _mem;\n")
	sb.WriteString("let _inBase = 0;  // byte offset where input is written (after DFA table pages)\n")
	sb.WriteString("let _outBase = 0; // byte offset for output buffers and capture slots\n")
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
	sb.WriteString("    _inBase = _m.buffer.byteLength; // first byte after DFA table pages\n")
	sb.WriteString("    _m.grow(2);                     // 1 page for input, 1 page for output/slots\n")
	sb.WriteString("    _outBase = _inBase + 65536;\n")
	sb.WriteString("    _mem = new Uint8Array(_m.buffer); // re-acquire after grow\n")
	sb.WriteString("}\n\n")

	sb.WriteString("function _w(input, outBytes) {\n")
	sb.WriteString("    // Writes input into WASM memory at _inBase; returns its byte length.\n")
	sb.WriteString("    // Strings are encoded straight into WASM memory with encodeInto, which\n")
	sb.WriteString("    // avoids both the intermediate Uint8Array TextEncoder.encode allocates and\n")
	sb.WriteString("    // the second copy _mem.set would then make. The reservation is the\n")
	sb.WriteString("    // worst-case UTF-8 expansion of a JS string: 3 bytes per UTF-16 code unit\n")
	sb.WriteString("    // (an astral char is 2 units and encodes to 4 bytes, so 3x still bounds\n")
	sb.WriteString("    // it), so encodeInto cannot truncate.\n")
	sb.WriteString("    if (typeof input === 'string') {\n")
	sb.WriteString("        _resize(input.length * 3, outBytes);\n")
	sb.WriteString("        return _enc.encodeInto(input, _mem.subarray(_inBase)).written;\n")
	sb.WriteString("    }\n")
	sb.WriteString("    _resize(input.length, outBytes);\n")
	sb.WriteString("    _mem.set(input, _inBase);\n")
	sb.WriteString("    return input.length;\n")
	sb.WriteString("}\n\n")
	sb.WriteString("function _resize(inputLen, outBytes) {\n")
	sb.WriteString("    const ob = outBytes && outBytes > 65536 ? outBytes : 65536;\n")
	sb.WriteString("    _outBase = _inBase + Math.max(1, Math.ceil(inputLen / 65536)) * 65536;\n")
	sb.WriteString("    const needed = _outBase + ob;\n")
	sb.WriteString("    if (needed > _mem.buffer.byteLength) {\n")
	sb.WriteString("        _exp.memory.grow(Math.ceil((needed - _mem.buffer.byteLength) / 65536));\n")
	sb.WriteString("        _mem = new Uint8Array(_exp.memory.buffer);\n")
	sb.WriteString("    }\n")
	sb.WriteString("}\n\n")

	for _, re := range cfg.Regexps {
		if re.MatchFunc != "" {
			sb.WriteString(genJSMatchFunc(re.MatchFunc))
		}
		if re.FindFunc != "" {
			sb.WriteString(genJSFindFunc(re.FindFunc))
		}
		if re.GroupsFunc != "" {
			numGroups, _, err := extractGroupInfo(re.Pattern)
			if err != nil {
				return "", fmt.Errorf("pattern %q: %w", re.Pattern, err)
			}
			sb.WriteString(genJSGroupsFunc(re.GroupsFunc, numGroups))
		}
		if re.NamedGroupsFunc != "" {
			numGroups, namedGroups, err := extractGroupInfo(re.Pattern)
			if err != nil {
				return "", fmt.Errorf("pattern %q: %w", re.Pattern, err)
			}
			sb.WriteString(genJSNamedGroupsFunc(re.NamedGroupsFunc, re.GroupsExportName(), numGroups, namedGroups))
		}
	}

	sb.WriteString(genJSSetSection(cfg))
	return sb.String(), nil
}

// genJSMatchFunc generates a JS export for an anchored match.
// Returns [endPos, true] on match, or [0, false] if no match.
func genJSMatchFunc(funcName string) string {
	return fmt.Sprintf(`// %s — anchored match; returns the end position, or null if no match.
export function %s(input) {
    const len = _w(input);
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
    if (typeof _exp['%[1]s_batch'] === 'function') {
        const len = _w(input, %[2]d * 8);
        const outBuf = new Uint32Array(_mem.buffer, _outBase, %[2]d * 2);
        let startPos = offset;
        let prevEnd = -1;
        while (true) {
            const n = _exp['%[1]s_batch'](_inBase, len, _outBase, %[2]d, startPos);
            if (n === %[3]d) throw new Error("%[4]s");
            if (n <= 0) break;
            for (let i = 0; i < n; i++) {
                const s = outBuf[i * 2], e = outBuf[i * 2 + 1];
                // Go's FindAllIndex rule: suppress an EMPTY match beginning
                // exactly where the previous reported match ended.
                if (s === e && s === prevEnd) continue;
                prevEnd = e;
                yield [s, e];
            }
            if (n < %[2]d) break;
            const lastStart = outBuf[(n - 1) * 2], lastEnd = outBuf[(n - 1) * 2 + 1];
            startPos = lastEnd > lastStart ? lastEnd : lastStart + 1;
        }
        return;
    }
    const len = _w(input);
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
}

`, funcName, lm2BatchCap, btOverflow, btOverflowMsg(funcName))
}

// genJSGroupsFunc generates a JS generator for indexed capture groups.
// Yields an array per match; each element is [start, end] or null for
// unmatched groups. Index 0 is the full match.
//
// Prefers the LM-2 batch export (funcName+"_batch") the same way
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
    if (typeof _exp['%[1]s_batch'] === 'function') {
        const len = _w(input, %[2]d * %[4]d);
        const outBuf = new Int32Array(_mem.buffer, _outBase, %[2]d * %[3]d);
        let startPos = offset;
        while (true) {
            const n = _exp['%[1]s_batch'](_inBase, len, _outBase, %[2]d, startPos);
            if (n === %[7]d) throw new Error("%[8]s");
            if (n <= 0) break;
            for (let i = 0; i < n; i++) {
                const base = i * %[3]d;
                const result = [];
                for (let g = 0; g < %[5]d; g++) {
                    const s = outBuf[base + 2 + g * 2], e = outBuf[base + 2 + g * 2 + 1];
                    result.push(s < 0 ? null : [s, e]);
                }
                yield result;
            }
            if (n < %[2]d) break;
            const lastBase = (n - 1) * %[3]d;
            const lastStart = outBuf[lastBase], lastEnd = outBuf[lastBase + 1];
            startPos = lastEnd > lastStart ? lastEnd : lastStart + 1;
        }
        return;
    }
    const len = _w(input);
    // Hoisted out of the loop: _mem.buffer and _outBase are both loop-invariant
    // (_resize already ran, and nothing inside the loop grows the memory), so
    // constructing the view per match was pure overhead.
    const slots = new Int32Array(_mem.buffer, _outBase, %[6]d);
    let off = offset;
    let prevEnd = -1;
    while (off <= len) {
        slots.fill(-1);
        const r = _exp['%[1]s'](_inBase, len, _outBase, off);
        if (r === %[7]d) throw new Error("%[8]s");
        if (r < 0) {
            if (off === len) break;
            off++;
            continue;
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
}

`, funcName, lm2BatchCap, recSize, recBytes, numGroups, slotCount, btOverflow, btOverflowMsg(funcName))
}

// genJSNamedGroupsFunc generates a JS generator for named capture groups.
// Yields a plain object per match with name → [start, end] entries.
// Only groups that participated in the match are included.
//
// Prefers the batch export (exportName+"_batch", requested via the
// "batch-find" hint) when the loaded WASM provides one, same as
// genJSGroupsFunc. Feature-detection and the record layout are
// keyed on exportName — the WASM export this pattern's groups_func and
// named_groups_func share (config.RegexEntry.GroupsExportName) — not on
// funcName, so a named_groups_func-only pattern (no groups_func) still finds
// its batch export, and a pattern requesting both gets one batch export
// consumed by two independent generators.
func genJSNamedGroupsFunc(funcName, exportName string, numGroups int, namedGroups map[string]int) string {
	slotCount := numGroups * 2
	recSize := 2 + slotCount // ints per batch record
	recBytes := recSize * 4  // bytes per batch record

	type entry struct {
		name  string
		index int
	}
	var entries []entry
	for name, idx := range namedGroups {
		entries = append(entries, entry{name, idx})
	}
	sort.Slice(entries, func(i, j int) bool { return entries[i].index < entries[j].index })

	var inserts strings.Builder
	for _, e := range entries {
		fmt.Fprintf(&inserts,
			"        if (slots[%d] >= 0) result['%s'] = [slots[%d], slots[%d]];\n",
			e.index*2, e.name, e.index*2, e.index*2+1)
	}

	var batchInserts strings.Builder
	for _, e := range entries {
		fmt.Fprintf(&batchInserts,
			"                if (outBuf[base + 2 + %d] >= 0) result['%s'] = [outBuf[base + 2 + %d], outBuf[base + 2 + %d]];\n",
			e.index*2, e.name, e.index*2, e.index*2+1)
	}

	return fmt.Sprintf(`// %[1]s — yields named capture group objects per match.
// Each object maps name → [start, end] (absolute) for participating groups.
export function* %[1]s(input, offset = 0) {
    if (typeof _exp['%[2]s_batch'] === 'function') {
        const len = _w(input, %[3]d * %[4]d);
        const outBuf = new Int32Array(_mem.buffer, _outBase, %[3]d * %[5]d);
        let startPos = offset;
        while (true) {
            const n = _exp['%[2]s_batch'](_inBase, len, _outBase, %[3]d, startPos);
            if (n === %[9]d) throw new Error("%[10]s");
            if (n <= 0) break;
            for (let i = 0; i < n; i++) {
                const base = i * %[5]d;
                const result = {};
%[6]s                yield result;
            }
            if (n < %[3]d) break;
            const lastBase = (n - 1) * %[5]d;
            const lastStart = outBuf[lastBase], lastEnd = outBuf[lastBase + 1];
            startPos = lastEnd > lastStart ? lastEnd : lastStart + 1;
        }
        return;
    }
    const len = _w(input);
    // Hoisted out of the loop: _mem.buffer and _outBase are both loop-invariant
    // (_resize already ran, and nothing inside the loop grows the memory), so
    // constructing the view per match was pure overhead.
    const slots = new Int32Array(_mem.buffer, _outBase, %[7]d);
    let off = offset;
    let prevEnd = -1;
    while (off <= len) {
        slots.fill(-1);
        const r = _exp['%[2]s'](_inBase, len, _outBase, off);
        if (r === %[9]d) throw new Error("%[10]s");
        if (r < 0) {
            if (off === len) break;
            off++;
            continue;
        }
        const matchEnd = slots[1] >= 0 ? slots[1] : slots[0];
        const result = {};
%[8]s        const absStart = slots[0], absEnd = matchEnd;
        off = absEnd > absStart ? absEnd : absStart + 1;
        // Go's FindAllSubmatchIndex rule: suppress an EMPTY match beginning
        // exactly where the previous reported match ended. The advance above
        // is unchanged.
        if (absStart === absEnd && absStart === prevEnd) continue;
        prevEnd = absEnd;
        yield result;
    }
}

`, funcName, exportName, lm2BatchCap, recBytes, recSize, batchInserts.String(), slotCount, inserts.String(), btOverflow, btOverflowMsg(funcName))
}
