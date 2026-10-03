//go:build wasip1

package main

import (
	"errors"
	"fmt"
	"os"
	"strings"
)

// Individual SQL parameter values to check with is_sqli (anchored match).
var values = []string{
	"42",
	"alice",
	"OR '1'='1",
	"UNION ALL SELECT username, password FROM admin",
	"DROP TABLE users",
	"INSERT INTO evil VALUES('payload')",
	"DELETE FROM sessions",
	"shipped",
}

// Application log with embedded injection attempts to scan with find_sqli and parse_sqli.
var appLog = strings.Join([]string{
	"[req-001] SELECT * FROM products WHERE category = 'electronics' AND price < 1000",
	"[req-002] SELECT * FROM users WHERE username = 'admin' OR '1'='1 AND password = 'x'",
	"[req-003] SELECT * FROM orders WHERE order_id = 42",
	"[req-004] UNION ALL SELECT username, password FROM admin_accounts",
	"[req-005] SELECT * FROM sessions WHERE token = 'abc123'",
	"[req-006] DELETE FROM temp WHERE age > 30",
}, "\n")

func main() {
	fmt.Println("=== is_sqli: anchored match (is this value a SQL injection?) ===")
	for _, value := range values {
		_, matched, err := is_sqli([]byte(value))
		if err != nil {
			// The engine could not decide — NOT the same as "clean".
			fmt.Fprintln(os.Stderr, "is_sqli:", err)
			os.Exit(2)
		}
		label := "clean    "
		if matched {
			label = "INJECTION"
		}
		fmt.Printf("  [%s] %s\n", label, value)
	}

	fmt.Println("\n=== find_sqli: find injection byte ranges in application log ===")
	findIter := find_sqli([]byte(appLog), 0)
	for start, end := range findIter.Matches() {
		snippet := appLog[start:end]
		if len(snippet) > 60 {
			snippet = snippet[:60] + "..."
		}
		fmt.Printf("  [%d:%d] %s\n", start, end, snippet)
	}
	if err := findIter.Err(); err != nil {
		fmt.Fprintln(os.Stderr, "find_sqli:", err)
		os.Exit(2)
	}

	fmt.Println("\n=== parse_sqli: extract injection type and payload ===")
	// Named groups are generated index constants now, not a per-match map.
	parseIter := parse_sqli([]byte(appLog), 0)
	for match := range parseIter.Matches() {
		injectionType := match[parse_sqli_type]
		payloadSpan := match[parse_sqli_payload]
		payload := strings.TrimSpace(appLog[payloadSpan.Start:payloadSpan.End])
		fmt.Printf("  type=%-35s  payload=%s\n", appLog[injectionType.Start:injectionType.End], payload)
	}
	if err := parseIter.Err(); err != nil {
		fmt.Fprintln(os.Stderr, "parse_sqli:", err)
		os.Exit(2)
	}

	fmt.Println("\n=== max_memory: a hostile value the cap stops ===")
	// "UNION", 64 KiB of spaces, and no SELECT. `\s+` takes every space and
	// then gives them back one at a time looking for SELECT, so the
	// Backtracking engine needs a frame per space: past the stack the module
	// reserves (about 50 KiB of spaces here) it grows memory for a frame stack
	// and memo sized from the value — and the config's max_memory, 1 MiB, is
	// barely above the module's own tables. The engine then stops and answers
	// "unknown" instead of growing the module's memory further, and the stub
	// reports that as ErrBacktrackOverflow. Unknown is NOT clean: a checker
	// should reject such a value.
	hostile := "UNION" + strings.Repeat(" ", 64<<10)
	if _, _, err := is_sqli([]byte(hostile)); errors.Is(err, ErrBacktrackOverflow) {
		fmt.Printf("  [unknown  ] %d-byte value: rejected, the search needed more than max_memory\n", len(hostile))
	} else {
		fmt.Fprintf(os.Stderr, "is_sqli: the hostile value was answered (err = %v); is max_memory set?\n", err)
		os.Exit(2)
	}
	// The instance is unharmed: every search that fits still answers.
	if _, matched, err := is_sqli([]byte("OR '1'='1")); err != nil || !matched {
		fmt.Fprintln(os.Stderr, "is_sqli after the hostile value:", matched, err)
		os.Exit(2)
	}
	fmt.Println("  [INJECTION] OR '1'='1   (the next search answers as before)")
}
