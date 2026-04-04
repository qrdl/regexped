//go:build wasip1

package main

import (
	"fmt"
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
	for _, v := range values {
		_, matched := IsSqli([]byte(v))
		label := "clean    "
		if matched {
			label = "INJECTION"
		}
		fmt.Printf("  [%s] %s\n", label, v)
	}

	fmt.Println("\n=== find_sqli: find injection byte ranges in application log ===")
	for start, end := range FindSqli([]byte(appLog)) {
		snippet := appLog[start:end]
		if len(snippet) > 60 {
			snippet = snippet[:60] + "..."
		}
		fmt.Printf("  [%d:%d] %s\n", start, end, snippet)
	}

	fmt.Println("\n=== parse_sqli: extract injection type and payload ===")
	for fields := range ParseSqli([]byte(appLog)) {
		typeName := appLog[fields["type"][0]:fields["type"][1]]
		payload := strings.TrimSpace(appLog[fields["payload"][0]:fields["payload"][1]])
		fmt.Printf("  type=%-35s  payload=%s\n", typeName, payload)
	}
}
