# browser/homoglyph — homoglyph and hidden-character detection

A page that marks, as you type, what makes text look like something it is not:

| Finding | Example | Pattern |
|---|---|---|
| Mixed scripts | `pаypal.com` — the `а` is Cyrillic U+0430 | `mixed_script`: a token (letters, digits, `. _ @ -`) mixing Latin letters with Cyrillic or Greek ones |
| Lookalike letter | the `а` above, shown as "reads as paypal.com" | `lookalike`: one Cyrillic or Greek letter that looks Latin, shown only inside a mixed-script token |
| Invisible | `pay​pal.com` — a zero-width space | `invisible`: zero-width space, non-joiner, joiner, word joiner, BOM, soft hyphen |
| Text direction | `"user‮ ⁦// Check if admin⁩ ⁦"` — the "Trojan Source" attack | `bidi_control`: the bidirectional controls, which reorder how text is displayed |
| Styled letters | `𝐩𝐚𝐲𝐩𝐚𝐥`, `ｐａｙｐａｌ` | `styled`: mathematical, fullwidth and circled letters and digits |

The view under the text box shows the text with every finding marked, and with
invisible and text-direction characters replaced by labels, so it shows the
characters in their real order. The text box itself displays them the way an
attacker intends: try the "Trojan Source" example.

It runs entirely in the browser, on compiled WASM — no JS regexp engine.

## Unicode mode

Every pattern in [regexped.yaml](regexped.yaml) names a Unicode script class
(`\p{Latin}`, `\p{Cyrillic}`, `\p{Greek}`) or a character above U+007F, so each
compiles in **Unicode mode**: a class reads a whole UTF-8 character, never one
byte of it. The five patterns are one set with a `find` capability, so one pass
reports every finding with its position.

Positions are **byte offsets into the input's UTF-8 encoding**, while a JS
string indexes UTF-16 code units. `codeUnitIndex` in [index.html](index.html)
maps one to the other; `input.slice(start, end)` on the raw offsets would cut
characters apart.

## Prerequisites

The Makefile installs nothing. Install these first:

| Tool | How to install |
|---|---|
| `regexped` | run `make` in the repo root |
| `python3` (`make run` only) | your OS package manager, or [python.org](https://www.python.org/downloads/) |

What each target needs:

| Target | What it does | Needs |
|---|---|---|
| `make` | compiles the patterns to `regexps.wasm` and generates `regexp.js` | `regexped` |
| `make run` | builds if needed, then serves this directory on port 8080 until you stop it. `make run` in `../` serves both browser examples together | `regexped`, `python3` |
| `make clean` | removes the build outputs | — |

## Run

```sh
make run
# Open http://localhost:8080 in a browser
```

## Usage in your own page

```js
import { init, scan_text, patternName } from './regexp.js';
await init(await fetch('./regexps.wasm').then(r => r.arrayBuffer()));

for (const m of scan_text('pаypal.com')) {
  console.log(patternName(m.patternId), m.start, m.end);   // byte offsets
}
// mixed_script 0 11
// lookalike 1 3
```
