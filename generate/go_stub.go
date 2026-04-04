package generate

import (
	"fmt"
	"path/filepath"
	"sort"
	"strings"

	"github.com/qrdl/regexped/config"
)

// goStub generates a Go stub file (//go:build wasip1) for all regex entries in cfg.
// out is the full output path for stub.go, or "-" for stdout.
// The Go package name is set to cfg.ImportModule when the stub is placed in a
// subdirectory named after the import module; otherwise "main" is used.
func goStub(cfg config.BuildConfig, out string) error {
	pkgName := cfg.ImportModule
	if filepath.Base(filepath.Dir(out)) != cfg.ImportModule {
		pkgName = "main"
	}
	content, err := genGoStubFile(cfg.Regexes, cfg.ImportModule, pkgName)
	if err != nil {
		return fmt.Errorf("generate Go stub: %w", err)
	}
	if content == "" {
		return nil
	}
	if out == "-" {
		_, err := fmt.Print(content)
		return err
	}
	return writeStub(out, []byte(content))
}

// goPublicName converts a snake_case function name to a PascalCase Go identifier.
// "url_match" → "UrlMatch", "find_github_token" → "FindGithubToken"
func goPublicName(s string) string {
	var b strings.Builder
	upper := true
	for _, c := range s {
		if c == '_' {
			upper = true
			continue
		}
		if upper {
			if c >= 'a' && c <= 'z' {
				c -= 'a' - 'A'
			}
			upper = false
		}
		b.WriteRune(c)
	}
	return b.String()
}

// genGoMatchStub generates an anchored-match stub.
func genGoMatchStub(importModule, funcName string) string {
	ffi := "ffi_" + funcName
	pub := goPublicName(funcName)
	return fmt.Sprintf(`//go:wasmimport %s %s
//go:noescape
func %s(ptr unsafe.Pointer, length uint32) int32

// %s returns the end position of the match (exclusive), or (0, false) if no match.
// The match is anchored: it starts at the beginning of input.
func %s(input []byte) (int, bool) {
	var ptr unsafe.Pointer
	if len(input) > 0 {
		ptr = unsafe.Pointer(&input[0])
	}
	r := %s(ptr, uint32(len(input)))
	if r < 0 {
		return 0, false
	}
	return int(r), true
}

`, importModule, funcName, ffi, pub, pub, ffi)
}

// genGoFindStub generates a find iterator returning iter.Seq2[int,int].
func genGoFindStub(importModule, funcName string) string {
	ffi := "ffi_" + funcName
	pub := goPublicName(funcName)
	return fmt.Sprintf(`//go:wasmimport %s %s
//go:noescape
func %s(ptr unsafe.Pointer, length uint32) int64

// %s returns an iterator over all non-overlapping matches in input.
// Each iteration yields (start, end) absolute byte positions.
func %s(input []byte) iter.Seq2[int, int] {
	return func(yield func(int, int) bool) {
		pos := 0
		for pos <= len(input) {
			var ptr unsafe.Pointer
			if pos < len(input) {
				ptr = unsafe.Pointer(&input[pos])
			}
			r := %s(ptr, uint32(len(input)-pos))
			if r < 0 {
				break
			}
			start := pos + int(uint64(r)>>32)
			end := pos + int(uint32(r))
			if !yield(start, end) {
				break
			}
			if end > pos {
				pos = end
			} else {
				pos++
			}
		}
	}
}

`, importModule, funcName, ffi, pub, pub, ffi)
}

// genGoGroupsStub generates a groups iterator returning iter.Seq2[[][]int, bool].
// Each iteration yields a slice of [start, end] pairs (nil if the group didn't participate).
// declareFFI controls whether the //go:wasmimport block is emitted; pass false when
// a sibling named-groups stub in the same file already declared it.
func genGoGroupsStub(importModule, funcName, exportName string, declareFFI bool, numGroups int) string {
	ffi := "ffi_" + exportName
	pub := goPublicName(funcName)
	slotCount := numGroups * 2

	var ffiDecl string
	if declareFFI {
		ffiDecl = fmt.Sprintf(`//go:wasmimport %s %s
//go:noescape
func %s(ptr unsafe.Pointer, length uint32, outPtr unsafe.Pointer) int32

`, importModule, exportName, ffi)
	}

	return ffiDecl + fmt.Sprintf(`// %s returns an iterator over capture groups of all non-overlapping matches.
// Each iteration yields a slice of numGroups [start,end] pairs; nil means the group didn't participate.
// Index 0 is the full match. Positions are absolute byte offsets.
func %s(input []byte) iter.Seq[[][]int] {
	return func(yield func([][]int) bool) {
		pos := 0
		for pos <= len(input) {
			var ptr unsafe.Pointer
			if pos < len(input) {
				ptr = unsafe.Pointer(&input[pos])
			}
			buf := make([]int32, %d)
			r := %s(ptr, uint32(len(input)-pos), unsafe.Pointer(&buf[0]))
			if r < 0 {
				if pos == len(input) {
					break
				}
				pos++
				continue
			}
			groups := make([][]int, %d)
			for i := range groups {
				s, e := buf[i*2], buf[i*2+1]
				if s < 0 {
					groups[i] = nil
				} else {
					groups[i] = []int{int(s) + pos, int(e) + pos}
				}
			}
			matchEnd := 0
			if buf[1] >= 0 {
				matchEnd = int(buf[1])
			}
			if matchEnd > 0 {
				pos += matchEnd
			} else {
				pos++
			}
			if !yield(groups) {
				break
			}
		}
	}
}

`, pub, pub, slotCount, ffi, numGroups)
}

// genGoNamedGroupsStub generates a named-groups iterator that calls the FFI export directly.
// declareFFI controls whether the //go:wasmimport block is emitted; pass false when a
// sibling groups stub in the same file already declared it.
func genGoNamedGroupsStub(importModule, funcName, exportName string, declareFFI bool, numGroups int, namedGroups map[string]int) string {
	ffi := "ffi_" + exportName
	pub := goPublicName(funcName)
	slotCount := numGroups * 2

	var ffiDecl string
	if declareFFI {
		ffiDecl = fmt.Sprintf(`//go:wasmimport %s %s
//go:noescape
func %s(ptr unsafe.Pointer, length uint32, outPtr unsafe.Pointer) int32

`, importModule, exportName, ffi)
	}

	type entry struct {
		name  string
		index int
	}
	var entries []entry
	for name, idx := range namedGroups {
		entries = append(entries, entry{name, idx})
	}
	sort.Slice(entries, func(i, j int) bool { return entries[i].index < entries[j].index })

	var assigns strings.Builder
	for _, e := range entries {
		fmt.Fprintf(&assigns,
			"\t\t\tif buf[%d] >= 0 { named[\"%s\"] = []int{int(buf[%d]) + pos, int(buf[%d]) + pos} }\n",
			e.index*2, e.name, e.index*2, e.index*2+1)
	}

	return ffiDecl + fmt.Sprintf(`// %s returns an iterator over named capture groups of all non-overlapping matches.
// Each iteration yields a map of group name → [start,end] absolute byte offsets.
func %s(input []byte) iter.Seq[map[string][]int] {
	return func(yield func(map[string][]int) bool) {
		pos := 0
		for pos <= len(input) {
			var ptr unsafe.Pointer
			if pos < len(input) {
				ptr = unsafe.Pointer(&input[pos])
			}
			buf := make([]int32, %d)
			r := %s(ptr, uint32(len(input)-pos), unsafe.Pointer(&buf[0]))
			if r < 0 {
				if pos == len(input) {
					break
				}
				pos++
				continue
			}
			named := make(map[string][]int, %d)
%s			matchEnd := 0
			if buf[1] >= 0 {
				matchEnd = int(buf[1])
			}
			if matchEnd > 0 {
				pos += matchEnd
			} else {
				pos++
			}
			if !yield(named) {
				break
			}
		}
	}
}

`, pub, pub, slotCount, ffi, len(entries), assigns.String())
}

// genGoStubFile generates the full Go stub file content for a slice of entries.
// importModule is the WASM module name used in //go:wasmimport declarations.
// pkgName is the Go package name written to the file header.
func genGoStubFile(entries []config.RegexEntry, importModule, pkgName string) (string, error) {
	if len(entries) == 0 {
		return "", nil
	}

	var parts []string
	needsIter := false
	for _, re := range entries {
		part, err := genGoStubsForEntry(re, importModule)
		if err != nil {
			return "", err
		}
		if part != "" {
			parts = append(parts, part)
			if re.FindFunc != "" || re.GroupsFunc != "" || re.NamedGroupsFunc != "" {
				needsIter = true
			}
		}
	}
	if len(parts) == 0 {
		return "", nil
	}

	var sb strings.Builder
	sb.WriteString("// Auto-generated by regexped. Do not edit.\n\n")
	sb.WriteString("//go:build wasip1\n\n")
	fmt.Fprintf(&sb, "package %s\n\n", pkgName)
	if needsIter {
		sb.WriteString("import (\n\t\"iter\"\n\t\"unsafe\"\n)\n\n")
	} else {
		sb.WriteString("import \"unsafe\"\n\n")
	}

	sb.WriteString(strings.Join(parts, ""))
	return sb.String(), nil
}

// genGoStubsForEntry generates the Go stub content for a single regex entry.
func genGoStubsForEntry(re config.RegexEntry, importModule string) (string, error) {
	var out string
	written := false

	if re.MatchFunc != "" {
		out += genGoMatchStub(importModule, re.MatchFunc)
		written = true
	}
	if re.FindFunc != "" {
		out += genGoFindStub(importModule, re.FindFunc)
		written = true
	}
	if re.GroupsFunc != "" || re.NamedGroupsFunc != "" {
		numGroups, namedGroups, err := extractGroupInfo(re.Pattern)
		if err != nil {
			return "", err
		}
		exportName := re.GroupsExportName()
		if re.GroupsFunc != "" {
			out += genGoGroupsStub(importModule, re.GroupsFunc, exportName, true, numGroups)
			written = true
		}
		if re.NamedGroupsFunc != "" {
			declareFFI := re.GroupsFunc == ""
			out += genGoNamedGroupsStub(importModule, re.NamedGroupsFunc, exportName, declareFFI, numGroups, namedGroups)
			written = true
		}
	}

	if !written {
		return "", nil
	}
	return out, nil
}
