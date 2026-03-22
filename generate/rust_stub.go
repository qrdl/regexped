package generate

import (
	"fmt"
	"sort"
	"strings"
)

// genRustMatchStub generates an anchored-match stub.
// The WASM export is named funcName; the internal FFI binding uses the ffi_ prefix
// to avoid a name collision with the public Rust wrapper.
func genRustMatchStub(importModule, funcName string) string {
	ffiName := "ffi_" + funcName
	return fmt.Sprintf(`#[link(wasm_import_module = "%s")]
unsafe extern "C" {
    #[link_name = "%s"]
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

`, importModule, funcName, ffiName, funcName, ffiName)
}

// genRustFindIterStub generates a find iterator.
// The WASM export is named funcName; ffi_ prefix avoids collision with the
// public constructor of the same name.
func genRustFindIterStub(importModule, funcName string) string {
	ffiName := "ffi_" + funcName
	return fmt.Sprintf(`#[link(wasm_import_module = "%s")]
unsafe extern "C" {
    #[link_name = "%s"]
    fn %s(ptr: *const u8, len: usize) -> i64;
}

pub struct FindIter<'a> {
    input: &'a [u8],
    offset: usize,
}

impl<'a> Iterator for FindIter<'a> {
    type Item = (usize, usize);

    fn next(&mut self) -> Option<(usize, usize)> {
        if self.offset > self.input.len() {
            return None;
        }
        let remaining = &self.input[self.offset..];
        match unsafe { %s(remaining.as_ptr(), remaining.len()) } {
            -1 => None,
            n  => {
                let start = (n as u64 >> 32) as usize;
                let end   = (n as u32) as usize;
                let abs_start = self.offset + start;
                let abs_end   = self.offset + end;
                self.offset += if end > start { end } else { start + 1 };
                Some((abs_start, abs_end))
            }
        }
    }
}

/// Returns an iterator over all non-overlapping matches in input.
/// Each item is an absolute (start, end) byte range.
/// Use .next() to get only the first match.
pub fn %s(input: &[u8]) -> FindIter<'_> {
    FindIter { input, offset: 0 }
}

`, importModule, funcName, ffiName, ffiName, funcName)
}

// genRustGroupsIterStub generates a capture-groups iterator.
// exportName is the actual WASM export (= funcName unless named_groups_func
// shares the same WASM export, in which case exportName = groups_func value).
// declareFFI controls whether the extern "C" block is emitted; pass false when
// a sibling named-groups stub in the same file already declared it.
func genRustGroupsIterStub(importModule, funcName, exportName string, declareFFI bool, numGroups int) string {
	ffiName := "ffi_" + exportName
	slotCount := numGroups * 2

	var ffiDecl string
	if declareFFI {
		ffiDecl = fmt.Sprintf(`#[link(wasm_import_module = "%s")]
unsafe extern "C" {
    #[link_name = "%s"]
    fn %s(ptr: *const u8, len: usize, out: *mut i32) -> i32;
}

`, importModule, exportName, ffiName)
	}

	return ffiDecl + fmt.Sprintf(`pub struct GroupsIter<'a> {
    input: &'a [u8],
    offset: usize,
}

impl<'a> Iterator for GroupsIter<'a> {
    type Item = Vec<Option<(usize, usize)>>;

    fn next(&mut self) -> Option<Vec<Option<(usize, usize)>>> {
        loop {
            if self.offset > self.input.len() {
                return None;
            }
            let remaining = &self.input[self.offset..];
            let mut slots = [-1i32; %d];
            if unsafe { %s(remaining.as_ptr(), remaining.len(), slots.as_mut_ptr()) } < 0 {
                if self.offset == self.input.len() {
                    return None;
                }
                self.offset += 1;
                continue;
            }
            let off = self.offset;
            let match_end = if slots[1] >= 0 { slots[1] as usize } else { 0 };
            self.offset += if match_end > 0 { match_end } else { 1 };
            let mut result = Vec::with_capacity(%d);
            for i in 0..%d {
                let start = slots[i * 2];
                let end   = slots[i * 2 + 1];
                result.push(if start < 0 { None } else { Some((start as usize + off, end as usize + off)) });
            }
            return Some(result);
        }
    }
}

/// Returns an iterator over all non-overlapping capture matches in input.
/// Group positions are absolute byte offsets. Index 0 is the full match.
/// Use .next() to get only the first match.
pub fn %s(input: &[u8]) -> GroupsIter<'_> {
    GroupsIter { input, offset: 0 }
}

`, slotCount, ffiName, numGroups, numGroups, funcName)
}

// genRustNamedGroupsIterStub generates a named-capture-groups iterator.
// exportName is the actual WASM export name.
// declareFFI controls whether the extern "C" block is emitted; pass false when
// a sibling groups stub in the same file already declared it.
func genRustNamedGroupsIterStub(importModule, funcName, exportName string, declareFFI bool, numGroups int, namedGroups map[string]int) string {
	ffiName := "ffi_" + exportName
	slotCount := numGroups * 2

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
			"            if slots[%d] >= 0 { map.insert(\"%s\", (slots[%d] as usize + off, slots[%d] as usize + off)); }\n",
			e.index*2, e.name, e.index*2, e.index*2+1)
	}

	var ffiDecl string
	if declareFFI {
		ffiDecl = fmt.Sprintf(`#[link(wasm_import_module = "%s")]
unsafe extern "C" {
    #[link_name = "%s"]
    fn %s(ptr: *const u8, len: usize, out: *mut i32) -> i32;
}

`, importModule, exportName, ffiName)
	}

	return ffiDecl + fmt.Sprintf(`pub struct NamedGroupsIter<'a> {
    input: &'a [u8],
    offset: usize,
}

impl<'a> Iterator for NamedGroupsIter<'a> {
    type Item = std::collections::HashMap<&'static str, (usize, usize)>;

    fn next(&mut self) -> Option<std::collections::HashMap<&'static str, (usize, usize)>> {
        loop {
            if self.offset > self.input.len() {
                return None;
            }
            let remaining = &self.input[self.offset..];
            let mut slots = [-1i32; %d];
            if unsafe { %s(remaining.as_ptr(), remaining.len(), slots.as_mut_ptr()) } < 0 {
                if self.offset == self.input.len() {
                    return None;
                }
                self.offset += 1;
                continue;
            }
            let off = self.offset;
            let match_end = if slots[1] >= 0 { slots[1] as usize } else { 0 };
            self.offset += if match_end > 0 { match_end } else { 1 };
            let mut map = std::collections::HashMap::new();
%s            return Some(map);
        }
    }
}

/// Returns an iterator over all non-overlapping named-capture matches in input.
/// Group positions are absolute byte offsets.
/// Use .next() to get only the first match.
pub fn %s(input: &[u8]) -> NamedGroupsIter<'_> {
    NamedGroupsIter { input, offset: 0 }
}

`, slotCount, ffiName, inserts.String(), funcName)
}
