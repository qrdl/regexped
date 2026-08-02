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
/* find_all: streaming iterator over a static result buffer */
int <find_all>_next(const char *input, int len, rx_set_match_t *out);
void <find_all>_reset(void);

/* find_any: single result, or a struct with start<0 if no match */
int <find_any>(const char *input, int len, rx_set_match_t *out);

/* match: anchored at position 0 */
int <match>(const char *input, int len, rx_set_anchor_t *out);

/* only if any set in the config sets emit_name_map: true */
const char *pattern_name(int id);
```

`<find_all>_next` returns non-overlapping matches one at a time from an
internal static buffer, refilling it from WASM as needed; call
`<find_all>_reset()` before starting a new scan over different input.
`pattern_name` is a single shared lookup across every set in the config
that requested `emit_name_map: true`, not one per set.

---

## Notes

- The static array returned by a groups function is **not thread-safe** and is
  **overwritten on each call**. Copy results before calling again.
- Group name pointer comparison (`==`) is valid because all calls return pointers into
  the same static name table defined in `stub.c`. Do not compare by string value.
- The `#define <FUNC_UPPER>_GROUPS` constant gives the total number of groups
  including group 0 (full match). Use it to size loops or slot arrays.
- No heap allocation or libc is required. The stubs are self-contained and suitable
  for embedded WASM environments.
