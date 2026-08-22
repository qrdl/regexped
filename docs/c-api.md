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
typedef struct { int start; int end; } rx_match_t;
typedef struct { int start; int end; const char *name; } rx_group_t;
typedef struct { int pattern_id; int start; int end; } rx_set_match_t;
typedef struct { int pattern_id; int end; } rx_set_anchor_t;
```

The last two are always emitted alongside the first two, even when the
config has no `sets:` block — see [Sets](#sets) below.

---

## Generated functions by config field

### `match_func` — anchored match

```c
int <func>(const unsigned char *input, unsigned int len);
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
rx_match_t <func>(const unsigned char *input, unsigned int len, unsigned int offset);
```

Scans `input[offset..len]` for the next match. Returns absolute byte positions
`{start, end}`, or `{-1, -1}` if not found.

To iterate all non-overlapping matches:

```c
unsigned int off = 0;
while (off <= len) {
    rx_match_t m = find_token(input, len, off);
    if (m.start < 0) break;
    /* use m.start, m.end */
    off = (unsigned int)(m.end > m.start ? m.end : m.start + 1);
}
```

---

### `groups_func` — capture groups

```c
const rx_group_t *<func>(const unsigned char *input, unsigned int len, unsigned int offset);
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
while (off <= len) {
    const rx_group_t *groups = parse_url(input, len, off);
    if (groups[0].start < 0) break;
    /* process groups[] */
    off = (unsigned int)(groups[0].end > groups[0].start
                         ? groups[0].end : groups[0].start + 1);
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
typedef struct { int pattern_id; int start; int end; } rx_set_match_t;

/* anchored: the pattern must match the WHOLE input */
int <match>    (const char *in, int len);                        /* 0 | 1    */
int <match_any>(const char *in, int len);                        /* id or -1 */
int <match_all>(const char *in, int len, int *out_ids);          /* count    */

/* non-anchored: each takes a `from` position */
int <scan>    (const char *in, int len, int from);               /* 0 | 1    */
int <scan_any>(const char *in, int len, int from, int *start);   /* id or -1 */
int <scan_all>(const char *in, int len, int from, int *out_ids); /* count    */

/* find: a caller-owned scanner struct — reentrant, header-only */
typedef struct {
    int from;
    int done;
    unsigned gates[<SET>_ID_SPACE];        /* non-overlapping sets only */
    int buf[<SET>_PATTERN_COUNT * 3];
    int n, i;
} rx_<set>_scanner_t;

void <find>_init(rx_<set>_scanner_t *s, int from);
int  <find>_next(rx_<set>_scanner_t *s, const char *in, int len, rx_set_match_t *out);

/* find_batch: the same matches, a bufferful per call. You own the buffer —
   3 ints per match, cap matches — so declare it once and reuse it. There is no
   capacity constant in the header. */
void <find_batch>_init(rx_<set>_batch_scanner_t *s, int from, int *buf, int cap);
int  <find_batch>_next(rx_<set>_batch_scanner_t *s, const char *in, int len, rx_set_match_t *out);

/* only if any set in the config sets emit_name_map: true */
const char *pattern_name(int id);
```

```c
rx_<set>_scanner_t s;
<find>_init(&s, 0);
rx_set_match_t m;
while (<find>_next(&s, input, len, &m))
    printf("%d %d..%d\n", m.pattern_id, m.start, m.end);
```

Scanner state is **caller-owned**, so two scans can be in flight at once and
re-initialising the struct restarts one. The `out_ids` arrays for
`<match_all>`/`<scan_all>` must hold `<SET>_ID_SPACE` ints.

The two constants differ for a named subset: `<SET>_PATTERN_COUNT` counts the
set's patterns and sizes the tuple buffer, while `<SET>_ID_SPACE` is one past
the largest id the set can report and sizes everything indexed *by* an id — the
`gates` array and the `out_ids` arrays above. A set holding two late-declared
patterns has a count of 2 and a much larger id space.

`pattern_name` is a single shared lookup across every set in the config
that requested `emit_name_map: true`, not one per set.

---

### `find_batch` — the same matches, a bufferful per call

`find` crosses the host boundary once per matching position. `find_batch`
reports the same matches in the same order but fills **your** buffer with as
many consecutive positions as fit, so a caller who will consume the whole scan
crosses once per bufferful instead. Use `find` when you may stop early — a
batch call does the work for matches you never look at.

The two are independent capabilities; declare either, both, or neither.

You own the buffer: allocate one and reuse it for every scan, so batched
iteration allocates nothing in the steady state. Its length is the batch size,
capped at `<SET>_BATCH_MAX_COUNT`; a zero-length buffer yields nothing. Any
length of 1 or more makes progress — a position whose matches do not all fit is
delivered in part and resumed inside. Because of that, group by the match's
`start` field rather than by call boundary if you need per-position grouping.

The gate array and the resume cursor stay stub-owned and never appear in the
public surface; only the buffer is yours, because only its size is your choice.

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
