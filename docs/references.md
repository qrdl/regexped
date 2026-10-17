# Pattern references

A regexp can use another pattern of the same config by name, so a piece that
several patterns share is written once. An e-mail address and a URL both carry
a host name:

```yaml
patterns:
  - name: hostname
    regexp: '[a-zA-Z0-9-]+(?:\.[a-zA-Z0-9-]+)*'

  - name: email
    regexp: '[a-zA-Z0-9._%+-]+@(?&hostname)'
    match_func: email_match

  - name: url
    regexp: 'https?://(?<&hostname>)(?::\d+)?(?:/[^\s]*)?'
    groups_func: url_groups
```

`(?&hostname)` inserts the regexp of the pattern named `hostname`. In `url`,
`(?<&hostname>)` inserts it and also captures it, as the group `hostname`.

References cost nothing at run time. They are expanded when the config is
loaded, and a pattern written with them compiles to exactly the module the same
pattern written out by hand compiles to.

## The three forms

| You write | It means | Expands to |
|---|---|---|
| `(?<name>…)` | an ordinary named capture group, body written in place | itself |
| `(?&name)` | the regexp of pattern `name`, not captured | `(?:…)` |
| `(?<&name>)` | the regexp of pattern `name`, captured as group `name` | `(?<name>…)` |

A reference takes no body. Anything between the name and the closing
parenthesis is an error: `(?<&hostname>(?::\d+)?)` and `(?&hostname\.com)`
are refused. To capture more than the piece, give the group a name of its own:

```yaml
regexp: '(?<host>(?&hostname)(?::\d+)?)'
```

The spelling borrows PCRE's subroutine call, `(?&name)`, but not its meaning.
In PCRE it calls a group defined inside the same regexp and may recurse. Here
the piece is another pattern of the config, and a reference cycle is an error.

Go's own parser rejects both `(?&` and `(?<&`, so no regexp that compiles
without references changes meaning. For the same reason, text that Go reads as
something else is never a reference: inside a character class (`[(?&x)]` is a
class of five characters), inside `\Q…\E`, or after a backslash.

## Pieces are ordinary patterns

A piece is any named entry of `patterns:`. A piece that has no `*_func` compiles
to nothing of its own. It is still a top-level pattern, though, so a set that
selects `patterns: all` holds it as a member. List the names a set needs
when the config also holds pieces:

```yaml
sets:
  - name: links
    find: links_find
    patterns: [url, email]     # not `all`: `hostname` alone matches every word
```

A name a reference uses is ASCII letters, digits and `_`, the same rule as a
capture group's name. A pattern with any other name (`Norwegian/Danish`) is
still valid, but cannot be referenced.

Pieces can use pieces. A set's own `regexps:` can use them too:

```yaml
sets:
  - name: links
    find: links_find
    regexps: ['ftp://(?&hostname)']
```

## What a reference takes from the piece

Only its `regexp:`. Everything else on the referenced entry applies only where
that entry is compiled itself:

| Key on the referenced entry | When it is referenced |
|---|---|
| `name` | how the reference finds it |
| `regexp` | inserted |
| `byte_mode`, `unicode` | ignored: the pattern that uses the piece decides the mode |
| `hints` | ignored: the pattern that uses the piece has its own |
| `match_func`, `find_func`, `groups_func` | ignored: they export the piece itself, not the pattern using it |

**Mode.** A pattern that uses pieces runs in one mode. Its own `byte_mode:` /
`unicode:` decide it, or, without them, the guess from its expanded text: a
piece that names a character above U+007F makes the pattern Unicode. A piece's
own mode keys are not carried over, so the same text can mean something else:

```yaml
- name: highbytes
  regexp: '[\x80-\xff]+'
  byte_mode: true            # raw bytes 0x80..0xFF, here
- name: blob
  regexp: 'X(?&highbytes)'   # no mode key: Unicode, where [\x80-\xff] means
  find_func: blob_find       #   the characters U+0080..U+00FF
```

Give `blob` `byte_mode: true` too, to keep the bytes.

**Flags.** The inserted text is a group, so a flag written inside the piece,
such as `(?i)`, stays inside it. A flag on the using pattern reaches into the
piece, as it reaches into any group: with a lowercase-only
`hostname: '[a-z0-9-]+(?:\.[a-z0-9-]+)*'`, `(?i)https?://(?&hostname)` matches
`HTTP://EXAMPLE.COM`.

**Capture groups.** A piece's own groups come along wherever it is used. A
pattern with `groups_func` may not name two groups alike, so a capturing piece
used twice is refused, with the reference that brought each copy in:

```
pattern "u": capture group name "email" is used more than once; …; it comes from (?<&email>), (?<&email>)
```

Name them apart: `from (?<sender>(?&email)) to (?<rcpt>(?&email))`.

## Errors

An error found in a piece names the piece and who used it:

```
pattern "octet" (used by "ipv4"): error parsing regexp: unexpected ): `25[0-5]|2[0-4]\d|1?\d?\d)`
compile pattern "login", piece "cyrname" (used by "login"): pattern contains the rune U+0430, above U+00FF, …
```

A pattern written with references is named as written, with its references,
not as the text it expands to.

## Seeing the expansion

`compile --verbose` prints a pattern written with references as written, then
the full expanded text:

```
  url                  https?://(?<&hostname>)(?::\d+)?(?:/[^\s]*)?
    expanded: https?://(?<hostname>[a-zA-Z0-9-]+(?:\.[a-zA-Z0-9-]+)*)(?::\d+)?(?:/[^\s]*)?
    mode:   byte
```

A set's own regexps are listed with the patterns, as `<set>: regexps[<i>]`.

## Named group spelling

These docs write a named group `(?<name>…)`, Perl's spelling, which PCRE, .NET,
Java, JavaScript and Ruby share. `(?P<name>…)`, Python's spelling, means the
same and is accepted too, but is not the preferred one. regexped accepts every
spelling Go's `regexp` package accepts.
