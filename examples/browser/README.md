# browser — two browser examples

| Directory | What it shows |
|---|---|
| [validate](validate) | Email and URL validation as you type: two patterns, anchored match |
| [homoglyph](homoglyph) | Lookalike letters, invisible and text-direction characters: Unicode-mode patterns in one `find` set |

`make` builds both, and `make run` serves this directory on port 8080, where
`index.html` links to both pages. Each directory also builds and serves on its
own. `python3` is needed for `make run`; see each README for the rest.
