# Generated C API

Regexped generates a pair of C stub files (`.h` and `.c`) that declare and implement
wrapper functions for compiled WASM regexp modules. No libc or sysroot is required;
the stubs compile cleanly with `--target=wasm32-wasi -nostdlib`.

## Including stubs in your project

The generator produces two files derived from `stub_file` in the config:

| File | Contents |
|---|---|
| `stub.h` | Type definitions, group name constants (`extern`), function prototypes |
| `stub.c` | WASM FFI declarations, group name constant definitions, wrapper function bodies |

Compile both alongside your application:

```sh
clang --target=wasm32-wasi -nostdlib -Wl,--no-entry -o main.wasm main.c stub.c
```

Include only the header in your application code:

```c
#include "stub.h"
```

---

## Shared types

Defined once (guarded by `REGEXPED_TYPES_DEFINED`) so multiple stub headers can be
included without conflicts:

```c
#include <stddef.h>   /* size_t, ptrdiff_t -- freestanding-required, no libc */

typedef struct { ptrdiff_t start, end; } rx_match_t;
typedef struct { ptrdiff_t start, end; const char *name; } rx_group_t;
typedef struct { int pattern_id; ptrdiff_t start, end; } rx_set_match_t;
```

`rx_set_match_t` is always emitted alongside the other two, even when the
config has no `sets:` block — see [Sets](#sets) below.

**The type choices.** `size_t` for lengths, offsets and capacities and ONLY
those: it means "can hold the size of any object", which a pattern id is not.
`ptrdiff_t` for positions coming back, because `-1` is the sentinel for "no
match" / "group absent" and an unsigned type has no room for it — the same
pairing `read()` uses. `int` for pattern ids and counts, which keeps a negative
slot free for a future failure and avoids the signed/unsigned warning in
`for (int i = 0; i < n; i++)`. And `const char *` for input, not
`const unsigned char *`: callers hold `char *` (argv, literals, read buffers),
and the old signatures forced a cast at every call site.

---

## Generated functions by config field

### `match_func` — anchored match

```c
ptrdiff_t <func>(const char *input, size_t len);
```

Returns the end position of the match (`>= 0`) if the pattern matches at the start
of `input`, or `-1` if no match. The match is anchored at position 0; `len` is the
byte length of the input.

```c
int end = url_match(input, len);
if (end >= 0) {
    /* matched bytes [0, end) */
}
```

---

### `find_func` — non-anchored find

```c
rx_match_t <func>(const char *input, size_t len, size_t offset);
```

Scans for the next match at or after `offset`. The whole input stays visible to
the engine — `offset` bounds where the search starts, it does not truncate the
left context a leading `\b`, `\B` or `(?m:^)` is judged against. Returns
absolute byte positions
`{start, end}`, or `{-1, -1}` if not found.

To iterate all non-overlapping matches:

```c
unsigned int off = 0;
ptrdiff_t prev_end = -1;
while (off <= len) {
    rx_match_t m = find_token(input, len, off);
    if (m.start < 0) break;
    off = (unsigned int)(m.end > m.start ? m.end : m.start + 1);
    /* Go's FindAllIndex rule: an empty match beginning exactly where the
       previous reported match ended is not reported. Skip it AFTER
       advancing, or the loop stalls. */
    if (m.start == m.end && m.start == prev_end) continue;
    prev_end = m.end;
    /* use m.start, m.end */
}
```

---

### `groups_func` — capture groups

```c
const rx_group_t *<func>(const char *input, size_t len, size_t offset, rx_group_t *out);
```

Returns a pointer to a **static array** of `<FUNC_UPPER>_GROUPS` entries. The array is
valid until the next call to the same function. `groups[0]` is the full match;
subsequent entries are capture groups in order.

All entries have `start == -1` and `end == -1` when no match is found starting from
`offset`.

> **Note:** `named_groups_func` is **not supported** for C stubs — the generator will
> return an error. Use `groups_func` and identify groups by their index constants
> (`<FUNC_UPPER>_GROUP_<NAME>`) instead.

**Group name constants** are declared as `extern const char * const <FUNC_UPPER>_GROUP_<NAME>`
(a pointer variable, not an array) and defined in `stub.c`. Use `==` (pointer identity) for fast group name comparison:

```c
for (int i = 0; i < PARSE_URL_GROUPS; i++) {
    if (groups[i].name == PARSE_URL_GROUP_HOST && groups[i].start >= 0) {
        /* host matched */
    }
}
```

To iterate non-overlapping matches:

```c
unsigned int off = 0;
ptrdiff_t prev_end = -1;
while (off <= len) {
    const rx_group_t *groups = parse_url(input, len, off);
    if (groups[0].start < 0) break;
    off = (unsigned int)(groups[0].end > groups[0].start
                         ? groups[0].end : groups[0].start + 1);
    /* Go's FindAllSubmatchIndex rule: an empty match beginning exactly where
       the previous reported match ended is not reported. Skip it AFTER
       advancing, or the loop stalls. */
    if (groups[0].start == groups[0].end && groups[0].start == prev_end) continue;
    prev_end = groups[0].end;
    /* process groups[] */
}
```

---

## Summary table

| Config field | Generated function | Returns |
|---|---|---|
| `match_func` | `int <func>(input, len)` | end position `>=0`, or `-1` |
| `find_func` | `rx_match_t <func>(input, len, offset)` | `{start, end}` absolute, or `{-1,-1}` |
| `groups_func` | `const rx_group_t *<func>(input, len, offset)` | static array of `rx_group_t` |
| `named_groups_func` | **not supported** — generator returns an error | — |

---

## Sets

When the config has a `sets:` block, the generator also emits, per set (see
[sets.md](sets.md) for the full config schema and wire format):

```c
#define <SET>_PATTERN_COUNT 12   /* patterns in the set */
#define <SET>_ID_SPACE      12   /* largest reportable pattern id + 1 */

/* anchored: the pattern must match the WHOLE input */
int <match_any>(const char *in, size_t len);                         /* id or -1 */
int <match_all>(const char *in, size_t len,
                int patterns[static <SET>_PATTERN_COUNT]);           /* count    */

/* non-anchored: each takes an offset bounding the search */
int <scan_any>(const char *in, size_t len, size_t offset);           /* id or -1 */
int <scan_all>(const char *in, size_t len, size_t offset,
               int patterns[static <SET>_PATTERN_COUNT]);            /* count    */

/* find: a caller-owned scanner struct — reentrant, header-only. It holds the
   INPUT as well as the position; you pass the buffer per call. */
typedef struct {
    const char *input;
    size_t len, offset;
    int done;
    unsigned gates[<SET>_ID_SPACE];        /* every set with find, either policy */
} rx_<set>_scanner_t;

int <find>_init(rx_<set>_scanner_t *s, const char *input, size_t len, size_t offset);
int <find>(rx_<set>_scanner_t *s, rx_set_match_t *buf, size_t cap);

/* only if any set in the config sets emit_name_map: true */
const char *pattern_name(int id);
```

```c
rx_set_match_t buf[<SET>_PATTERN_COUNT];
rx_<set>_scanner_t s;
if (<find>_init(&s, input, len, 0) != 0) { /* RX_ERR_* */ }
for (int n; (n = <find>(&s, buf, <SET>_PATTERN_COUNT)) > 0; )
    for (int i = 0; i < n; i++)
        printf("%d %td..%td\n", buf[i].pattern_id, buf[i].start, buf[i].end);
```

**`find` is fill-and-count, not an iterator.** C has no iterator protocol, and
the raw ABI already fills a buffer and returns a count — which is also the C
idiom (`read`, `getdents`, `recv`). One call reports every match at the FIRST
position at or after the scanner's offset (they all share that start) and
returns how many. `0` means the scan is finished.

The return is the position's TOTAL, which may exceed `cap`: the underlying call
is transactional, so it writes `min(total, cap)`, records no gate and does not
advance, and `n > cap` means "grow and call again, same position". Sizing `cap`
at `<SET>_PATTERN_COUNT` — one position's worst case, since every pattern can
report once at a single start — makes overflow impossible.

**The scanner holds the input** (not just the position). The input never
changes during a scan while the position changes every step, so the old split
was backwards, and it let a caller pass a DIFFERENT buffer on a later step with
the stored position silently indexing into it.

**`_init` returns `int`**: `0` on success, a negative `RX_ERR_*` otherwise —
the dominant C convention for operation status (`pthread_*`, `close`,
`fclose`). It validates the pointers and that `len`, `offset` and `cap` fit
INT32_MAX, since the FFI imports are i32. It does NOT reject `len == 0` (an
empty input is a legitimate scan — `a*`, `(?:)`, `x?`, `\A\z` all match it) and
it does NOT reject `offset > len`, which the ABI defines as "nothing found".

Scanner state is **caller-owned**, so two scans can be in flight at once and
re-initialising the struct restarts one. The `gates` array stays inside the
struct: its length is a size the compiler knows, not one you pick.

**The `_all` arrays carry their size in the type.** `int patterns[static
<SET>_PATTERN_COUNT]` is C99 for "the caller must pass at least this many
elements": GCC and Clang diagnose a smaller array at the call site, it rules
out `NULL`, and it self-documents. The size is `<SET>_PATTERN_COUNT` and not
`<SET>_ID_SPACE` because the body appends one entry per set bit and only
patterns IN the set have bits — `ID_SPACE` remains correct for everything
indexed BY an id, and this is a list of ids rather than an id-indexed array.

**Re-entrancy is not thread-safety.** Removing the last mutable static makes
these calls re-entrant, but the Backtracking engine keeps its stack and its
BitState memo at fixed addresses inside the module, so BT-compiled patterns
stay non-reentrant at the WASM level.

The two constants differ for a named subset: `<SET>_PATTERN_COUNT` counts the
set's patterns and sizes the tuple buffer, while `<SET>_ID_SPACE` is one past
the largest id the set can report and sizes everything indexed *by* an id — the
`gates` array and the `_all` bitmap. A set holding two late-declared
patterns has a count of 2 and a much larger id space.

`pattern_name` is a single shared lookup across every set in the config
that requested `emit_name_map: true`, not one per set.

---

### Batching is a JS/TS-only hint

`hints: [batch-find]` is a **no-op for C**, as it is for Go, Rust and
AssemblyScript. Batching amortises host-boundary crossings and nothing else,
and a C stub is compiled to wasm and merged, so its call into the module is a
direct call inside one module with no boundary to amortise. There is no
`find_batch` function and no batch scanner type; `find` is the whole positional
surface.

## Notes

- The static array returned by a groups function is **not thread-safe** and is
  **overwritten on each call**. Copy results before calling again.
- Group name pointer comparison (`==`) is valid because all calls return pointers into
  the same static name table defined in `stub.c`. Do not compare by string value.
- The `#define <FUNC_UPPER>_GROUPS` constant gives the total number of groups
  including group 0 (full match). Use it to size loops or slot arrays.
- No heap allocation or libc is required. The stubs are self-contained and suitable
  for embedded WASM environments.
- The `batch-find` hint ([`hints:`](cli.md#hints--likelymode-and-batch-find-compile-hints)) is a no-op for C: it's effective for the JS and TS generators only. Setting it does not change the generated header or its performance.

---

## Backtracking stack overflow

Patterns compiled to the Backtracking engine have a backtrack-frame budget fixed at compile time, while the number of frames actually needed can grow with input length. When an input exhausts the budget, the engine has abandoned part of the search space and cannot say whether the input matches, so the WASM returns a distinct `-2` sentinel rather than "no match".

C has no unwinding, so the sentinel is returned to the caller instead. The header defines it:

```c
#define RX_ERR_BT_OVERFLOW (-2)
```

| Function shape | Value on overflow |
|---|---|
| anchored match (`int`) | `RX_ERR_BT_OVERFLOW` |
| find (`rx_match_t`) | `{RX_ERR_BT_OVERFLOW, RX_ERR_BT_OVERFLOW}` |
| groups (`const rx_group_t *`) | `NULL` — never returned otherwise |

Check for it wherever you currently check for `-1` / `{-1, -1}`: a plain `< 0` or `.start < 0` test silently treats overflow as "no match", which is the exact failure the sentinel exists to prevent.

This is rare: it needs a pattern that keeps an untried alternation branch live as input is consumed (for example `(?:ab|cd)*?x`), and an input long enough to pass the budget. But when it happens the honest answer is "unknown", and treating it as "no match" would be an input-length-dependent false negative. See [engines.md](engines.md) for the budget formula and which pattern shapes can reach it.
