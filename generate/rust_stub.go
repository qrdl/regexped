package generate

import (
	"fmt"
	"sort"
	"strings"
)

func genRustMatchStub(pattern, importModule, funcName string) string {
	// "match" is a Rust keyword, so we use #[link_name] to bind the WASM export
	// "match" to a Rust-legal FFI name.
	ffiName := "ffi_match"
	return fmt.Sprintf(`#[link(wasm_import_module = "%s")]
unsafe extern "C" {
    #[link_name = "match"]
    fn %s(ptr: *const u8, len: usize) -> i32;
}

/// Returns the end position of the match (exclusive), or None if no match.
/// The match is anchored: it starts at the beginning of input.
pub fn %s(input: &[u8]) -> Option<usize> {
    match unsafe { %s(input.as_ptr(), input.len()) } {
        n if n >= 0 => Some(n as usize),
        _ => None,
    }
}

`, importModule, ffiName, funcName, ffiName)
}

func genRustFindStubs(pattern, importModule, funcName string) string {
	exportName := "find"
	return fmt.Sprintf(`#[link(wasm_import_module = "%s")]
unsafe extern "C" {
    fn %s(ptr: *const u8, len: usize) -> i64;
}

/// Returns (start, end) of the leftmost-longest match, or None if no match.
pub fn %s(input: &[u8]) -> Option<(usize, usize)> {
    match unsafe { %s(input.as_ptr(), input.len()) } {
        -1 => None,
        n  => Some(((n as u64 >> 32) as usize, (n as u32) as usize)),
    }
}

`, importModule, exportName, funcName, exportName)
}

// genRustGroupsStub generates a stub returning all capture groups as a Vec.
// Group 0 = full match. Unmatched groups are None.
func genRustGroupsStub(pattern, importModule, funcName string, numGroups int) string {
	exportName := "groups"
	slotCount := numGroups * 2
	return fmt.Sprintf(`#[link(wasm_import_module = "%s")]
unsafe extern "C" {
    fn %s(ptr: *const u8, len: usize, out: *mut i32) -> i32;
}

/// Returns capture group positions as (start, end) pairs, or None if no match.
/// Index 0 is the full match; subsequent indices are capture groups.
/// A group that did not participate in the match is None.
pub fn %s(input: &[u8]) -> Option<Vec<Option<(usize, usize)>>> {
    let mut slots = [-1i32; %d];
    if unsafe { %s(input.as_ptr(), input.len(), slots.as_mut_ptr()) } < 0 {
        return None;
    }
    let mut groups = Vec::with_capacity(%d);
    for i in 0..%d {
        let start = slots[i * 2];
        let end   = slots[i * 2 + 1];
        groups.push(if start < 0 { None } else { Some((start as usize, end as usize)) });
    }
    Some(groups)
}

`, importModule, exportName, funcName, slotCount, exportName, numGroups, numGroups)
}

// genRustNamedGroupsStub generates a stub returning named capture groups as a HashMap.
// Only groups that participated in the match are included.
func genRustNamedGroupsStub(pattern, importModule, funcName string, numGroups int, namedGroups map[string]int) string {
	exportName := "groups"
	slotCount := numGroups * 2

	// Build sorted insert lines for deterministic output.
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
		fmt.Fprintf(&inserts, "    if slots[%d] >= 0 { map.insert(\"%s\", (slots[%d] as usize, slots[%d] as usize)); }\n",
			e.index*2, e.name, e.index*2, e.index*2+1)
	}

	return fmt.Sprintf(`#[link(wasm_import_module = "%s")]
unsafe extern "C" {
    fn %s(ptr: *const u8, len: usize, out: *mut i32) -> i32;
}

/// Returns named capture groups as a map of name → (start, end), or None if no match.
/// Only groups that participated in the match are included.
pub fn %s(input: &[u8]) -> Option<std::collections::HashMap<&'static str, (usize, usize)>> {
    let mut slots = [-1i32; %d];
    if unsafe { %s(input.as_ptr(), input.len(), slots.as_mut_ptr()) } < 0 {
        return None;
    }
    let mut map = std::collections::HashMap::new();
%s    Some(map)
}

`, importModule, exportName, funcName, slotCount, exportName, inserts.String())
}
