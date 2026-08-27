//go:build wasip1

package main

import (
	"fmt"
	"io"
	"os"
)

func main() {
	input, err := io.ReadAll(os.Stdin)
	if err != nil {
		fmt.Fprintln(os.Stderr, "error reading input:", err)
		os.Exit(1)
	}

	// Count all rows that have 3 columns (including those with invalid emails).
	total := 0
	rowIter := find_csv_row(input, 0)
	for range rowIter.Matches() {
		total++
	}
	// Check Err() after every loop: an engine that gave up ends iteration the
	// same way exhausting the input does, and skipping this check would report
	// a partial answer as a complete one.
	if err := rowIter.Err(); err != nil {
		fmt.Fprintln(os.Stderr, "find_csv_row:", err)
		os.Exit(2)
	}

	// Parse rows that also have a valid email; extract id, name, email.
	//
	// Groups are addressed by the generated index constants rather than by a
	// map: one capability, one export, and no per-match allocation.
	valid := 0
	fieldIter := parse_csv_row(input, 0)
	for match := range fieldIter.Matches() {
		id := match[parse_csv_row_id]
		name := match[parse_csv_row_name]
		email := match[parse_csv_row_email]
		fmt.Printf("id=%-8s  name=%-30s  email=%s\n",
			input[id.Start:id.End], input[name.Start:name.End], input[email.Start:email.End])
		valid++
	}
	if err := fieldIter.Err(); err != nil {
		fmt.Fprintln(os.Stderr, "parse_csv_row:", err)
		os.Exit(2)
	}

	fmt.Printf("\n%d rows total, %d valid, %d with invalid email\n", total, valid, total-valid)
}
