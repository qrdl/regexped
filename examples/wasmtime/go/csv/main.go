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
	for range FindCsvRow(input) {
		total++
	}

	// Parse rows that also have a valid email; extract id, name, email.
	valid := 0
	for fields := range ParseCsvRow(input) {
		id := string(input[fields["id"][0]:fields["id"][1]])
		name := string(input[fields["name"][0]:fields["name"][1]])
		email := string(input[fields["email"][0]:fields["email"][1]])
		fmt.Printf("id=%-8s  name=%-30s  email=%s\n", id, name, email)
		valid++
	}

	fmt.Printf("\n%d rows total, %d valid, %d with invalid email\n", total, valid, total-valid)
}
