package generate

import (
	"fmt"
	"strings"

	"github.com/qrdl/regexped/config"
)

// The Rust COMPONENT stub for sets.
//
// Its public API is the module stub's, function for function and type for type —
// `SetMatch` comes from the same generator (rustSetMatchType), the constants have
// the same names and values, and `find` returns an iterator of
// `Result<SetMatch>`. Switching `wasm_format` changes no calling code.
//
// What differs is underneath. The module stub calls the raw exports and owns the
// gate array and tuple buffer itself; here the gate array lives inside the
// regexp component, reached through a `resource`, and the `_all` pair gets a
// list of ids rather than a bitmask to walk.
//
// One consequence worth stating: the iterator keeps its `<'a>` lifetime
// parameter even though it no longer borrows the input — the resource copied it.
// The parameter is part of the public type, so dropping it would change the API
// this file exists to keep identical.

// genRustComponentSetInner emits the set half of the component stub, for
// placement inside `pub mod <rust_module>`.
//
// `wsets` is the ALREADY VALIDATED WIT view of cfg.Sets, in the same order, so
// every name used below is one the WIT document also contains and nothing here
// can fail — the naming rules are enforced once, in witParts.
func genRustComponentSetInner(cfg config.BuildConfig, wsets []witSet) string {
	if len(wsets) == 0 {
		return ""
	}
	var out strings.Builder
	out.WriteString(rustSetMatchType())

	for si, s := range cfg.Sets {
		ws := wsets[si]
		n := patternsInSet(s, cfg)
		konst := screamingCase(s.Name) + "_PATTERN_COUNT"
		idKonst := screamingCase(s.Name) + "_ID_SPACE"
		idN := idSpaceSize(s, cfg)

		// The same constants the module stub emits, with the same doc text: a
		// caller may well be using them to size something of its own.
		fmt.Fprintf(&out, "/// Number of patterns in set %q. `find` can report at most this many\n/// matches at one position.\npub const %s: usize = %d;\n\n", s.Name, konst, n)
		fmt.Fprintf(&out, "/// One past the largest pattern id set %q can report. Pattern ids are\n/// global indices into `regexps:`, so a set holding a few late-declared\n/// patterns has a small count and a large id space.\npub const %s: usize = %d;\n\n", s.Name, idKonst, idN)

		for _, c := range s.Capabilities() {
			kebab := witSetKebab(ws, c)
			switch c.Field {
			case "match_any", "scan_any":
				out.WriteString(genRustComponentSetAny(c.Field, c.Name, rustWitFuncName(kebab)))
			case "match_all", "scan_all":
				out.WriteString(genRustComponentSetAll(c.Field, c.Name, rustWitFuncName(kebab)))
			case "find":
				out.WriteString(genRustComponentSetFind(c.Name, rustResourceType(kebab)))
			}
		}
	}
	if hasEmitNameMap(cfg) {
		out.WriteString(rustPatternNameFn(cfg))
	}
	return out.String()
}

// rustWitFuncName is the snake_case name wit-bindgen gives a WIT function: it
// lowercases the kebab identifier and joins with underscores.
func rustWitFuncName(kebab string) string {
	return strings.ReplaceAll(kebab, "-", "_")
}

// rustResourceType is the UpperCamel type wit-bindgen gives an imported
// resource: `scan-it` becomes `ScanIt`.
func rustResourceType(kebab string) string {
	var b strings.Builder
	for _, word := range strings.Split(kebab, "-") {
		b.WriteString(strings.ToUpper(word[:1]))
		b.WriteString(word[1:])
	}
	return b.String()
}

func genRustComponentSetAny(field, funcName, witName string) string {
	if field == "match_any" {
		return fmt.Sprintf(`/// Returns the id of SOME pattern matching the whole input, or None.
/// A set is unordered, so which id you get is unspecified when several match.
///
/// # Errors
/// Err(Error::BacktrackOverflow) if a member pattern compiled to the
/// Backtracking engine and the input exhausted its frame budget: the engine
/// cannot tell whether the input matches, so Ok(None) — a definite "no" —
/// would be a lie.
pub fn %s(input: &[u8]) -> Result<Option<i32>> {
    match sets::%s(input) {
        Ok(Some(id)) => Ok(Some(id as i32)),
        Ok(None) => Ok(None),
        Err(sets::ErrorCode::BacktrackOverflow) => Err(Error::BacktrackOverflow),
    }
}

`, funcName, witName)
	}
	return fmt.Sprintf(`/// Returns one pattern id that matches somewhere at or after `+"`offset`"+`, or
/// None. Which id you get is unspecified when several patterns match; it
/// names a genuinely matching pattern, and no position is reported.
///
/// # Errors
/// Err(Error::BacktrackOverflow) if a member pattern compiled to the
/// Backtracking engine and the input exhausted its frame budget: the
/// engine cannot tell whether the input matches, so Ok(None) — a definite
/// "no" — would be a lie.
pub fn %s(input: &[u8], offset: usize) -> Result<Option<i32>> {
    match sets::%s(input, offset as u32) {
        Ok(Some(id)) => Ok(Some(id as i32)),
        Ok(None) => Ok(None),
        Err(sets::ErrorCode::BacktrackOverflow) => Err(Error::BacktrackOverflow),
    }
}

`, funcName, witName)
}

// genRustComponentSetAll wraps the `_all` pair.
//
// The signature is the module stub's — `Result<impl Iterator<Item = i32> + '_>` —
// but nothing is lazy here and it cannot be: the interface hands over a finished
// list of ids. The module stub's laziness came from having a bitmask to walk, and
// walking it in the consumer is exactly what the component interface avoids
// (measured: the id list beat handing the bitmap over in all twelve shapes
// tried). So the iterator is over an owned Vec, and a caller who stops early
// simply stops reading it.
func genRustComponentSetAll(field, funcName, witName string) string {
	if field == "match_all" {
		return fmt.Sprintf(`/// Yields the id of every pattern matching the whole input, ascending.
///
/// An iterator rather than a `+"`Vec`"+`, to match the module-format stub's
/// signature exactly. Here the ids arrive as a finished list, so `+"`.collect()`"+`
/// costs nothing extra.
pub fn %s(input: &[u8]) -> Result<impl Iterator<Item = i32> + '_> {
    match sets::%s(input) {
        Ok(ids) => Ok(ids.into_iter().map(|id| id as i32)),
        Err(sets::ErrorCode::BacktrackOverflow) => Err(Error::BacktrackOverflow),
    }
}

`, funcName, witName)
	}
	return fmt.Sprintf(`/// Yields the id of every pattern matching somewhere at or after `+"`offset`"+`,
/// ascending. See match_all for why this is an iterator.
pub fn %s(input: &[u8], offset: usize) -> Result<impl Iterator<Item = i32> + '_> {
    match sets::%s(input, offset as u32) {
        Ok(ids) => Ok(ids.into_iter().map(|id| id as i32)),
        Err(sets::ErrorCode::BacktrackOverflow) => Err(Error::BacktrackOverflow),
    }
}

`, funcName, witName)
}

// genRustComponentSetFind wraps the scanner resource as the module stub's
// iterator.
//
// The resource is entirely hidden: it is created by the constructor below and
// dropped with the iterator, so a caller never sees a handle and cannot leak
// one. That is the Rust half of the parity decision — C cannot hide it, because
// its scanner has no destructor to hang the drop on, and so gains an explicit
// `<func>_free` in BOTH formats.
func genRustComponentSetFind(funcName, resType string) string {
	iterName := iterTypeName(funcName)
	return fmt.Sprintf(`/// Iterator over the set's matches. It holds a scan in progress inside the
/// regexp component, yields one position's matches at a time, and advances when
/// they run out. Dropping it ends the scan and releases what the component held
/// for it; dropping and re-creating restarts from the beginning.
pub struct %[1]s<'a> {
    inner: sets::%[2]s,
    done: bool,
    buf: std::vec::IntoIter<sets::SetMatch>,
    /// The iterator no longer borrows the input — the scan copied it in — but
    /// the lifetime is part of the public type in the module-format stub, so it
    /// stays.
    _input: core::marker::PhantomData<&'a [u8]>,
}

impl Iterator for %[1]s<'_> {
    type Item = Result<SetMatch>;
    fn next(&mut self) -> Option<Result<SetMatch>> {
        loop {
            if let Some(m) = self.buf.next() {
                return Some(Ok(SetMatch {
                    pattern_id: m.id as i32,
                    start: m.start as usize,
                    end: m.end as usize,
                }));
            }
            if self.done { return None; }
            match self.inner.next() {
                // Before the finished test: the engine gave up and does not
                // know, so ending iteration here would report success.
                Err(sets::ErrorCode::BacktrackOverflow) => {
                    self.done = true;
                    return Some(Err(Error::BacktrackOverflow));
                }
                Ok(batch) => {
                    if batch.is_empty() { self.done = true; return None; }
                    self.buf = batch.into_iter();
                }
            }
        }
    }
}

impl std::iter::FusedIterator for %[1]s<'_> {}

/// Starts a scan at `+"`offset`"+`. Each step yields one match.
///
/// # Errors
/// An item is Err(Error::BacktrackOverflow) if a member pattern compiled to
/// the Backtracking engine and the input exhausted its frame budget: the
/// engine cannot tell whether more matches exist, so simply ending
/// iteration would be a lie. The iterator is fused, so it yields nothing
/// after that.
pub fn %[3]s(input: &[u8], offset: usize) -> %[1]s<'_> {
    %[1]s {
        inner: sets::%[2]s::new(input, offset as u32),
        done: false,
        buf: Vec::new().into_iter(),
        _input: core::marker::PhantomData,
    }
}

`, iterName, resType, funcName)
}
