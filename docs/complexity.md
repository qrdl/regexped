# Keeping time and memory linear

A regexp engine can be linear in every single call and still take quadratic
time over a scan, or bounded in time and still ask for memory without limit.
This page collects every mechanism regexped uses to keep both in check: what
input shape each one defeats, what it costs, and what is still not linear. The
details live with each engine and capability; this is the map.

Two words are used throughout:

- a **call** is one invocation of an export — one `match`, one `find` from
  `from`, one set `scan_any`;
- a **drive** is what a generated stub does with an iterating export: call
  `find`, `groups`, a set's `find` or its batch entry, resume past the answer,
  and call again until the input is exhausted. A call can be linear while the
  drive is quadratic, because the next call reads the same bytes again.

"Linear" means time proportional to the input length for a fixed config, and
memory that grows by at most a known number of bytes per input byte. The
pattern's size is a constant factor, not a bound: a Backtracking call is
bounded by program size × input length.

## At a glance

| Shape that would be quadratic or worse | Mechanism | Where |
|---|---|---|
| a backtracker splitting the same input many ways (`^(aa\|a)*b`) | work budget, then a memoised fallback body | [Backtracking calls](#backtracking-calls) |
| a `find` attempt that walks far and fails, from every start (`a*b` over `a`×N) | start-anywhere find, behind a work counter | [One find call](#one-find-call) |
| a drive whose calls read past their match (`a*b\|a` over `a`×N) | per-search notes | [Drives](#drives) |
| a Backtracking drive whose every call burns its budget | budget per search, kept memo | [Drives](#drives) |
| a raw caller that hands no state over | the module's default state (standalone) | [Callers that hand nothing over](#callers-that-hand-nothing-over) |
| set members walking on together after the wanted ones died | liveness exits, the sparse counter | [Sets](#sets) |
| a set member that is not provably linear in the set's bodies | split out, merge wrapper with lower bounds | [Sets](#sets) |
| a set's scan pair over such members | work counter, then a union automaton | [Sets](#sets) |
| `overlapping: true` over long overlapping matches | the answer cache, the program sweep | [Overlapping sets](#overlapping-sets) |
| unbounded memory for any of the above | sizes per byte, call-time growth, square-root regions, `max_memory`, declining | [Memory](#memory) |

## Engines: one call

**DFA and Compiled DFA** (`match_func`, and `find_func` without captures): one
transition per byte, O(n) per call, no stack. The table is built at compile
time and bounded by `max_dfa_states`; a pattern over the bound takes another
engine rather than a larger table.

**TDFA** (`groups_func` where it qualifies): a tagged DFA, also one transition
per byte plus register copies; O(n) per call.

### Backtracking calls

A backtracker without memoisation is exponential whenever a loop can split the
same input more than one way. Every Backtracking program is emitted as two
bodies ([engines.md](engines.md#work-budget-and-the-fallback-body)):

- the **fast body** with a pop counter of `(span + 1) × instructions`;
- the **fallback body**, which it tail-calls when the counter runs out or its
  frame stack is full: the same program with a `(pc, pos)` visited bitset at
  every alternation, Go's bitstate discipline. Each `(pc, pos)` is entered at
  most once per call, so the call is O(instructions × n).

A program with a zero-width cycle (`^(\w*|)*c`, `(a*?)*?b`) has no fast body:
the fallback answers every call, since the fast body has no loop guard.

Cost: nothing on a call that never backtracks; the budget multiplier is 1
because normal text never came near it (124 patterns, 160 real drives) while
adversarial drives were 41-85% cheaper than at 8.

### One find call

A `find` that tries start positions one at a time is quadratic in ONE call
when a long run keeps an attempt alive without matching: `a*b` over `a`×N,
`\w+@\w+` over one long word. The **start-anywhere find** (RE2's method) is
linear on every input: a forward pass over `(?s:.)*?(?:pat)` finds the end of
the leftmost-first match, a backward pass over the reversed pattern finds its
start ([engines.md](engines.md#which-find-a-pattern-gets-linear-on-every-input)).
It costs about 29 instructions per byte (1.6-4 where the SIMD bulk skip
crosses a looping state, up to 52 on input that defeats the skip), where the
ordinary find costs 1-8 on text it can skip, so the compiler picks per pattern:

- **provably linear** patterns — a failed attempt walks a bounded number of
  bytes, or the shape detectors or literal clause prove it — keep the ordinary
  find, unchanged;
- a leading word-class repeat with no literal gets the start-anywhere find
  alone;
- everything else gets the **switch**: the ordinary find plus a counter over
  the bytes walked by attempts that FAILED. Past `4 × (bytes advanced) + 64`
  the call hands over to the start-anywhere find. A failed walk of 32 bytes or
  fewer is not charged, and the counter is checked before a walk is added, so
  one long failed walk does not trip it. Ordinary text never trips it: 0-6%.

Where the start-anywhere automata cannot be built (over `max_dfa_states`, the
memory bound, or an assertion they cannot represent exactly), the switch hands
over to the **Backtracking find** instead, linear per call by its fallback.

## Drives

### Per-search notes

`a*b|a` over `a`×N matches at every byte, but each call must read to the end of
the run before it may answer `[p, p+1)`, and the next call reads the run again:
N matches cost N²/2 bytes. Go's `regexp` does the same (0.63 s at 8 KB, 10.3 s
at 32 KB).

A walk that runs past its last accept and dies has proved, for every (state,
position) after that accept, that no match lies ahead. That is a fact about
the text, so it is kept as a NOTE in a block the caller owns for the search,
and a later call that reaches a noted point stops there. Each point is noted
once and read once ([engines.md](engines.md#linear-drives-notes-kept-for-one-search),
[wasm.md](wasm.md#the-search-block)).

Only a search that has gone bad pays. A pattern with a **cycle state** (a
non-accepting state on a non-accepting cycle — the only place a long walk can
sit) carries two copies of its find: the ordinary one with a waste counter
(bytes read past each reported match, plus re-read bytes of failed reads over
32 bytes), and a marked copy. Past `4 × progress + 64` the search ARMS, the
stub allocates the notes, and the marked copy serves the rest of it. A pattern
with no cycle state has no notes code at all. The start-anywhere forward pass
and the literal-anchored and alternation verifies keep notes too, in one body
chosen at entry. Cost: none on 85 of 151 real drives, a median of +0.1% on the
rest, +5.2% at worst; the bad drives 130-382 instructions per byte, linear.

**Batched drives** run many finds in one call, so a search that arms inside the
call would re-read until the call ends. The stubs allocate notes for a batched
drive before its first call.

### The Backtracking budget per search

A budget that lasts one call leaves a drive quadratic when every call burns it
before the fallback answers. With the caller's search block the budget lasts
the SEARCH; once it runs out the search is **tripped**, every later call goes
straight to the fallback, and the stub gives the search one **memo** —
`(len + 1) × ⌈instructions / 8⌉` bytes — kept for the rest of it, so a
`(state, position)` one call ruled out stays ruled out. The marks on a reported
match's path are cleared before the call returns, because they are not
failures. A merged build, whose fallback scratch is in the module's own memory,
carries a second fallback body that reads the memo from the host's memory, so
it keeps the memo too. A program anchored at 0 answers a search from any later
position at once. A `groups` drive keeps only the tripped flag: its windows
already add up to the input. Measured: `(?:a|b)*a(?:a|b){12}c|a` over `a`×N,
`find` 12,808 instructions per byte, `groups` 13,390, linear.

### Callers that hand nothing over

The notes, the memo and a set's answer cache all live in memory the caller
hands over — every generated stub does. A **standalone** module also keeps a
**default state** of its own for a caller that hands nothing over (search
global 0, a set descriptor with the plain magic or no cache): a block, notes,
memo, set blocks and cache, grown in its own memory on first use and reused
([wasm.md](wasm.md#the-search-block)). The state carries over only while each
call continues the previous one — the same text, `from` inside the last
answer's window (a set: the same gate array, `from` advanced) — and is reset
otherwise. `a*b|a` over `a`×8 K costs 474 instructions per byte that way,
against 135,303 before. A caller that does hand its state over pays ~1-9
instructions per call for the check.

## Sets

A set runs its members through shared bucket bodies, which is where shapes
that are linear alone can stop being linear together.

**Provably linear members.** A member is linear in the set's bodies when a
failed walk is bounded (as for a single pattern) or, in a literal bucket, when
the part after the literal cannot read the literal without accepting
(`union[ \t]+k00\w+` qualifies, `foo[a-z]+bar` does not). A set whose members
all qualify compiles with none of the machinery below
([sets.md](sets.md#members-that-are-not-provably-linear)).

**Liveness exits.** Members sharing a literal bucket walk one merged automaton,
so `foo\w+` keeps the walk going over `foo`×N long after `foo[0-9]` died. A
bucket stops a walk as soon as no member still wanted can accept, tested only
when the walk enters a new state (on setperf's overlap-shape-3 that test costs
+3.8%, against +10.5% tested on every byte).

**The sparse counter.** A bucket of more than 32 members keeps per-state
accept lists and cannot use the exit. Where one of its members can keep a walk
going across unboundedly many candidates, gated `find` counts the bytes each
long walk ran past the farthest end it delivered, and past
`4 × progress + 64` hands the call and the rest of the drive to a copy of the
set with those members split out.

**Split members.** A member that is not provably linear is served by its own
linear search — its start-anywhere find, or the Backtracking find — and `find`
becomes a **merge wrapper**. The merge keeps, in the caller's gate array, a
lower bound on each split member's next start and on the buckets' next answer,
so neither is searched again before the drive reaches it. A split member that
keeps notes or a Backtracking budget gets its own search block. Measured at
64 KB on single-shape and mixed sets: on ordinary text a split member's `find`
ranges from 17× faster to 14× slower than the bucket's; on the runs that were
quadratic it is 19,000-66,000× faster.

**The scan pair.** `scan_any` / `scan_all` over a literal frontend carry a
work counter over the probes' walks that hands the call to a start-anywhere
union automaton over the whole set; where none can be built, the members are
split out as for `find`.

**Backtracking bucket members** keep their budget and visited set for one host
call — their walks are bounded, so that suffices; a Backtracking member that
is split keeps the full per-search budget and memo.

### Overlapping sets

`overlapping: true` reports every member's match at every start, so a member
whose automaton never dies (`[^\n]*ERROR` on newline-free input) walks to the
end from every start: quadratic in the drive, and in one call when nothing
matches.

- **The preflight verdict.** A member that matches nowhere in the rest of the
  input is retired from the walk once, and the verdict is kept in the gate
  array for the drive.
- **The answer cache.** Given a region, the engine sweeps the input right to
  left and computes every `(start, member, end)` in one pass, then answers the
  rest of the drive from it ([wasm.md](wasm.md#the-overlapping-answer-cache)).
  It engages ADAPTIVELY: the drive walks, counting bytes matched and walked,
  and sweeps once that passes a sixteenth of a sweep's per-byte cost plus a
  start-up allowance of eight bytes at the full rate — ordinary text stays
  11-134× under the line, a wide set no longer walks two sweeps' worth first
  (96 members: 281,595 → 108,705 instructions per byte), and inputs of a few
  bytes stay on the walk. An **in-call counter** does the same inside the one
  call a no-match input makes.
- **The column**, narrowed: union states whose per-member behaviour is the
  same share a cell (a Moore partition): 1.7-3.3× fewer cells measured, the
  ratio growing with the state count.
- **The whole-set automaton.** A set the sweep cannot run over directly
  (literal or several buckets) is swept over an automaton of every member,
  built only where a drive can have arbitrarily many walks alive at once —
  otherwise every drive is linear already.
- **Checkpointing.** Up to 64 MiB the region holds every answer. Above it the
  region keeps a column snapshot every `stride` positions and rebuilds one
  block at a time: each position is swept at most twice, and the region is the
  square root of the input.
- **The no-cache companion.** A drive with no usable region goes to a copy of
  the set with the members that need it split out.
- **Kept members.** A set that splits a member keeps the cache for the rest:
  they become an internal set the merge reads (`{foo\w+, a[a-z]*?z}` over
  `foo`×N: 90,354 → 542 instructions per byte).
- **The program sweep.** A split member's own search gives the leftmost match
  from a position, not one per start, so over `a`×N + `z` a non-greedy or
  Backtracking member re-reads the tail from every start. The program sweep
  is one backward pass over the member's compiled program, one column per
  position: for every start, the end of its leftmost-first match. It runs once
  the member's searches have walked `4 × len + 64` bytes, lives in the same
  region after the cache, and is checkpointed the same way. Measured:
  131,456 → 795 instructions per byte (non-greedy), 124,939 → 1,052
  (Backtracking).

## Memory

Every mechanism above that needs memory per input byte names its size, takes
it at call time rather than at load, and declines rather than fails when it
cannot have it.

| Memory | Size | When |
|---|---|---|
| notes | `(len + 1) × ⌈R / 8⌉` (R = noted states, usually 1 byte per position) | once a search arms |
| Backtracking memo | `(len + 1) × ⌈instructions / 8⌉` | once a search trips (per call in the fallback otherwise) |
| Backtracking frame stack (every body, set members included) | starts at 64 KB, doubles by `memory.grow`; one scratch for the whole module | as a search deepens |
| fallback stack and bitset | sized from the input | when the fallback runs |
| answer cache | a row per position (mask + one end per member) up to 64 MiB, then the square root of the input | reserved by the stub per drive; filled only if the drive sweeps |
| program sweep | 4 bytes per position per swept member, checkpointed the same way | after the cache, same region |
| default state (standalone, raw callers) | what a stub would allocate | grown on first use, reused, regrown to at least twice the size only when a drive needs more |

- **Call-time growth.** The fallback's memory and every frame stack are placed
  at a scratch base and grown with `memory.grow` when they do not fit — nothing
  is reserved in the module, so memory is the largest any one search needed,
  not a sum over patterns and sets. Inside a set, a stack starts above the
  fallback memos the set's members keep for the host call. A
  standalone module learns the free region from the host through the exported
  `regexped:scratch_base` global; a component uses its allocator's heap top.
  Memo rows are cleared lazily as the search reaches them.
- **`max_memory`** is declared as the memory's maximum, so the engine refuses
  every grow past it ([cli.md](cli.md#max_memory--a-cap-on-the-modules-memory)).
  Backtracking's frame stacks and fallback memo are the memory an adversarial
  input can grow, so `regexped compile` warns when a module carries
  Backtracking code and sets no cap. `examples/wasmtime/go/sql-injection`
  shows a cap stopping a hostile value.
- **Required vs optional.** Memory a call cannot answer without — the
  fallback's stack and bitset, a frame stack — makes the call answer `-2`
  ("unknown", never "no match") when it cannot be had; a JS/TS input that does
  not fit throws a `RangeError` before any search runs. Memory that only buys
  speed — a set's cache, a component's notes and memo, the default state — is
  declined instead: the answer is the same, only slower. A stub that cannot
  allocate notes or a memo for a search reports it the way it reports `-2`
  (JS/TS throw, Rust `Err`, C `RX_ERR_BT_OVERFLOW`); a Go or AssemblyScript
  allocation failure is fatal, as every allocation there is.
- **The module checks every caller-sized region** against its declared size
  (`notes_cap`, `bt_memo_cap`, `cache_len`), so a wrong size costs speed, never
  memory safety.

## What is still not linear

- **A merged build driven without its stubs' memory.** A raw caller of a merged
  module that hands over no search block, notes, memo or cache gets each call
  exactly as described under [Engines](#engines-one-call): linear per call,
  quadratic over the drive on the shapes above. A C build with
  `-DRX_SET_CACHE=0` is in the same place until it hands buffers over with
  `<find>_set_cache` and `<func>_set_notes` ([c-api.md](c-api.md)).
- **Interleaved raw drives over one standalone instance.** One default state
  serves one drive at a time; two drives alternating calls keep resetting it.
  The answers are right; each call starts fresh.
- **Overlapping sets past the sweeps' limits**: kept members whose automaton
  is over `max_fallback_states` or whose projected column is over 16,383 cells,
  and split members whose programs exceed the program sweep's 4,096 roots or
  65,536 closure items, keep their walks.
- **A `from` that goes backwards** within a drive is unsupported: notes and
  caches describe ground already covered.
- **The pattern's size.** Every bound is linear in the input for a fixed
  config; a Backtracking call is bounded by instructions × input, and a large
  set's split members each walk their own search.

`tools/advbench` measures each of these drives at doubling input sizes (×2 per
doubling is linear, ×4 quadratic), and every shape named on this page has a row
there.
