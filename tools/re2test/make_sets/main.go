// Command make_sets regenerates the expectation columns of custom-sets.txt.
//
// The set `find` capability's DEFAULT body is gated: per-pattern
// non-overlapping output, which is exactly Go FindAllIndex's rule.
// So col4 — the "all matches" column --sets compares
// against — is regenerated straight from Go's FindAllStringIndex, and col1
// from FindStringIndex. That is §9.6.1's union oracle applied ahead of time
// rather than at run time, and it is why the file needed regenerating when
// the old every-start-position enumeration was retired.
//
// The remaining columns (col0 anchored, col2/col3 unused by set mode) are
// preserved verbatim.
//
// Usage: go run ./make_sets custom-sets.txt
package main

import (
	"bufio"
	"fmt"
	"os"
	"regexp"
	"strconv"
	"strings"
)

func main() {
	if len(os.Args) != 2 {
		fmt.Fprintln(os.Stderr, "usage: make_sets <custom-sets.txt>")
		os.Exit(1)
	}
	path := os.Args[1]
	f, err := os.Open(path)
	if err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}
	var out []string
	var strs []string
	var curPattern string
	strIdx := 0
	section := ""

	sc := bufio.NewScanner(f)
	sc.Buffer(make([]byte, 1024*1024), 1024*1024)
	for sc.Scan() {
		line := sc.Text()
		trimmed := strings.TrimSpace(line)
		switch {
		case trimmed == "" || strings.HasPrefix(trimmed, "#"):
			out = append(out, line)
			continue
		case trimmed == "strings":
			section = "strings"
			strs = strs[:0]
			out = append(out, line)
			continue
		case trimmed == "regexps":
			section = "regexps"
			curPattern = ""
			out = append(out, line)
			continue
		}
		if section == "strings" {
			strs = append(strs, mustUnquote(trimmed))
			out = append(out, line)
			continue
		}
		if section == "regexps" {
			if strings.HasPrefix(trimmed, `"`) {
				curPattern = mustUnquote(trimmed)
				strIdx = 0
				out = append(out, line)
				continue
			}
			if !strings.Contains(trimmed, ";") {
				// A new block name: expectation rows always carry ';'.
				section = ""
				out = append(out, line)
				continue
			}
			// An expectation row for strs[strIdx].
			cols := strings.Split(trimmed, ";")
			for len(cols) < 5 {
				cols = append(cols, "-")
			}
			if strIdx < len(strs) {
				re, err := regexp.Compile(curPattern)
				if err != nil {
					fmt.Fprintf(os.Stderr, "pattern %q: %v\n", curPattern, err)
					os.Exit(1)
				}
				cols[1] = fmtFirst(re, strs[strIdx])
				cols[4] = fmtAll(re, strs[strIdx])
			}
			strIdx++
			out = append(out, strings.Join(cols, ";"))
			continue
		}
		// Block name or anything else: pass through.
		out = append(out, line)
		section = ""
	}
	// Check the scanner BEFORE rewriting the corpus. Scan() stops on error
	// (a line over the buffer limit gives bufio.ErrTooLong) by returning
	// false, which is indistinguishable from a clean EOF at the loop — so
	// without this the write below would truncate custom-sets.txt to whatever
	// had been read and exit 0, silently gutting the oracle the whole set
	// regression net depends on.
	if err := sc.Err(); err != nil {
		fmt.Fprintf(os.Stderr, "read %s: %v (corpus NOT rewritten)\n", path, err)
		f.Close()
		os.Exit(1)
	}
	f.Close()
	// Write via a temp file + rename so an interrupted write cannot leave a
	// half-destroyed corpus either.
	tmp := path + ".tmp"
	if err := os.WriteFile(tmp, []byte(strings.Join(out, "\n")+"\n"), 0644); err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}
	if err := os.Rename(tmp, path); err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}
}

func fmtFirst(re *regexp.Regexp, s string) string {
	m := re.FindStringIndex(s)
	if m == nil {
		return "-"
	}
	return strconv.Itoa(m[0]) + "-" + strconv.Itoa(m[1])
}

func fmtAll(re *regexp.Regexp, s string) string {
	ms := re.FindAllStringIndex(s, -1)
	if len(ms) == 0 {
		return "-"
	}
	var parts []string
	for _, m := range ms {
		parts = append(parts, strconv.Itoa(m[0])+"-"+strconv.Itoa(m[1]))
	}
	return strings.Join(parts, ",")
}

func mustUnquote(s string) string {
	v, err := strconv.Unquote(s)
	if err != nil {
		fmt.Fprintf(os.Stderr, "cannot unquote %q: %v\n", s, err)
		os.Exit(1)
	}
	return v
}
