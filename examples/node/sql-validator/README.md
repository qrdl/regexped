# node/sql-validator — SQL statement syntax validation

Reads SQL statements from stdin (one per line) and checks each one for valid
syntax using a **pattern set**. A single `validate_sql` WASM call both validates
the statement and identifies its type (SELECT, INSERT, UPDATE, DELETE).

## Prerequisites

The Makefile installs nothing. Install these first:

| Tool | How to install |
|---|---|
| `regexped` | run `make` in the repo root |
| [Node.js](https://nodejs.org) with `npm` | from nodejs.org or your OS package manager |
| TypeScript's `tsc` | `npm install -g typescript` |
| Node type definitions | `npm install -g @types/node` |

What each target needs:

| Target | What it does | Needs |
|---|---|---|
| `make` | compiles the patterns, generates `stubs.ts`, then type-checks and compiles to `dist/` with `tsc` | `regexped`, `tsc`, the type definitions, and `npm` (used only to locate them) |
| `make run` | builds if needed, then runs `node dist/main.js` on sample input | the above, plus Node.js |
| `make clean` | removes the build outputs | — |

`make` checks for `tsc` and the type definitions (and for `npm`, which it uses to
find them) before compiling, and says which one is missing. Point it elsewhere
with `make TSC=/path/to/tsc NODE_TYPE_ROOTS=/path/to/@types`.

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
tsc                 →  type-check (strict) and compile main.ts and the stub to dist/
node dist/main.js   →  run
```

## How it works

Four patterns (`select`, `insert`, `update`, `delete`) are compiled into a set
with `match_any: validate_sql` and `emit_name_map: true`. The generated stub
exports `validate_sql(input)`, which returns the id of a pattern matching the
whole input or `null`, and `patternName(id)`, which maps that id to its name. One WASM call per
statement validates syntax and identifies the statement type.

Patterns check required structural keywords (FROM for SELECT, INTO+VALUES for
INSERT, SET for UPDATE, FROM for DELETE). Statements with missing required
clauses are rejected. Optional trailing clauses (WHERE, ORDER BY, etc.) are
accepted. Note: patterns are case-sensitive — SQL keywords must be uppercase.
