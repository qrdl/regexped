# node/sql-validator — SQL statement syntax validation

Reads SQL statements from stdin (one per line) and checks each one for valid
syntax using a **pattern set**. A single `validate_sql` WASM call both validates
the statement and identifies its type (SELECT, INSERT, UPDATE, DELETE).

## Prerequisites

- `regexped` binary (run `make` in the repo root)
- Node.js 22+ (for `--experimental-strip-types`) or `tsx` (`npm install -g tsx`)

## Run

```sh
make run
```

Expected output:
```
[VALID SELECT] SELECT * FROM users WHERE id = 1
[INVALID] SELECT FROM users
[VALID SELECT] SELECT id, name FROM accounts WHERE active = 1
[VALID INSERT] INSERT INTO logs (msg) VALUES ("hello")
[INVALID] INSERT users VALUES (1)
[VALID UPDATE] UPDATE users SET active = 0 WHERE id = 1
[INVALID] UPDATE users active = 0
[VALID DELETE] DELETE FROM users WHERE id = 1
[INVALID] DELETE users
```

## Build pipeline

```
regexped compile    →  compile 4-pattern set to WASM (validate_sql + name map)
regexped generate   →  generate TypeScript ES module stub
```

## How it works

Four patterns (`select`, `insert`, `update`, `delete`) are compiled into a set
with `match: validate_sql` and `emit_name_map: true`. The generated stub exports
`validate_sql(input)` which returns `{ patternId, start, end }` or `null`, and
`patternName(id)` which maps the pattern ID to its name. One WASM call per
statement validates syntax and identifies the statement type.

Patterns check required structural keywords (FROM for SELECT, INTO+VALUES for
INSERT, SET for UPDATE, FROM for DELETE). Statements with missing required
clauses are rejected. Optional trailing clauses (WHERE, ORDER BY, etc.) are
accepted. Note: patterns are case-sensitive — SQL keywords must be uppercase.
