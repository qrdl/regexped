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

// genRustFindIterStub generates a FindIter struct and a constructor named funcName
// that yields all non-overlapping matches as absolute (start, end) pairs.
func genRustFindIterStub(funcName, importModule string) string {
	return fmt.Sprintf(`#[link(wasm_import_module = "%s")]
unsafe extern "C" {
    fn find(ptr: *const u8, len: usize) -> i64;
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
        match unsafe { find(remaining.as_ptr(), remaining.len()) } {
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

`, importModule, funcName)
}

// genRustGroupsIterStub generates a GroupsIter struct and a constructor named funcName
// that yields all non-overlapping anchored capture matches in the input.
// Returned group positions are absolute offsets into the original input.
func genRustGroupsIterStub(funcName, importModule string, numGroups int) string {
	slotCount := numGroups * 2
	return fmt.Sprintf(`#[link(wasm_import_module = "%s")]
unsafe extern "C" {
    fn groups(ptr: *const u8, len: usize, out: *mut i32) -> i32;
}

pub struct GroupsIter<'a> {
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
            if unsafe { groups(remaining.as_ptr(), remaining.len(), slots.as_mut_ptr()) } < 0 {
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

`, importModule, slotCount, numGroups, numGroups, funcName)
}

// genRustNamedGroupsIterStub generates a NamedGroupsIter struct and a constructor
// named funcName that yields all non-overlapping anchored capture matches in the input.
// Returned positions are absolute offsets into the original input.
func genRustNamedGroupsIterStub(funcName, importModule string, numGroups int, namedGroups map[string]int) string {
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

	return fmt.Sprintf(`#[link(wasm_import_module = "%s")]
unsafe extern "C" {
    fn groups(ptr: *const u8, len: usize, out: *mut i32) -> i32;
}

pub struct NamedGroupsIter<'a> {
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
            if unsafe { groups(remaining.as_ptr(), remaining.len(), slots.as_mut_ptr()) } < 0 {
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

`, importModule, slotCount, inserts.String(), funcName)
}
