// Package clilog is the slog handler the regexped command reports through
// when --debug is not given: plain text a person reads, not key=value records.
//
// slog's TextHandler quotes a message that holds a newline or a quote, so a
// YAML excerpt with its caret, or an error listing several names, reached the
// terminal as one line of \n and \" escapes — the first thing a new user saw.
// Here an error is `regexped: <message>` and a warning `regexped: warning:
// <message>`, the message as written, and each attribute follows on its own
// indented line. Records below WARN are not printed; --debug installs slog's
// own TextHandler instead, with everything.
//
// A record printed once is not printed again: `compile --diag-json` and
// `generate` compile the config more than once, and every set warning used to
// arrive twice.
package clilog

import (
	"context"
	"fmt"
	"io"
	"log/slog"
	"strings"
	"sync"
)

// Handler writes WARN and ERROR records to w as plain text.
type Handler struct {
	mu     *sync.Mutex
	seen   map[string]bool // every record written, as written
	w      io.Writer
	attrs  []boundAttr
	prefix string // the groups WithGroup opened, as "a.b."
}

// boundAttr is an attribute WithAttrs bound, with the groups open when it was
// bound: it is printed through the same walk as a record's own, so an
// anonymous group inlines and an empty attribute is dropped the same way.
type boundAttr struct {
	prefix string
	attr   slog.Attr
}

// New is a Handler writing to w.
func New(w io.Writer) *Handler { return &Handler{mu: &sync.Mutex{}, seen: map[string]bool{}, w: w} }

// Enabled reports WARN and above.
func (h *Handler) Enabled(_ context.Context, l slog.Level) bool { return l >= slog.LevelWarn }

// Handle writes one record: the message after its prefix, then each
// attribute, `    key: value`, a multi-line value's later lines indented
// under its first.
func (h *Handler) Handle(_ context.Context, r slog.Record) error {
	var b strings.Builder
	b.WriteString("regexped: ")
	if r.Level < slog.LevelError {
		b.WriteString("warning: ")
	}
	b.WriteString(r.Message)
	b.WriteByte('\n')
	write := func(key string, v slog.Value) {
		val := strings.ReplaceAll(v.String(), "\n", "\n      ")
		fmt.Fprintf(&b, "    %s: %s\n", key, val)
	}
	var walk func(prefix string, a slog.Attr)
	walk = func(prefix string, a slog.Attr) {
		v := a.Value.Resolve()
		if v.Kind() == slog.KindGroup {
			p := prefix
			if a.Key != "" {
				p += a.Key + "."
			}
			for _, g := range v.Group() {
				walk(p, g)
			}
			return
		}
		if a.Key == "" {
			return
		}
		write(prefix+a.Key, v)
	}
	for _, a := range h.attrs {
		walk(a.prefix, a.attr)
	}
	r.Attrs(func(a slog.Attr) bool {
		walk(h.prefix, a)
		return true
	})
	h.mu.Lock()
	defer h.mu.Unlock()
	if h.seen[b.String()] {
		return nil
	}
	h.seen[b.String()] = true
	_, err := io.WriteString(h.w, b.String())
	return err
}

// WithAttrs returns a Handler that prints attrs with every record.
func (h *Handler) WithAttrs(attrs []slog.Attr) slog.Handler {
	c := *h
	c.attrs = append([]boundAttr(nil), h.attrs...)
	for _, a := range attrs {
		c.attrs = append(c.attrs, boundAttr{h.prefix, a})
	}
	return &c
}

// WithGroup returns a Handler that qualifies later attributes with name.
func (h *Handler) WithGroup(name string) slog.Handler {
	if name == "" {
		return h
	}
	c := *h
	c.prefix += name + "."
	return &c
}
