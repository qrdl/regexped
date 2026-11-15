package clilog

import (
	"bytes"
	"context"
	"errors"
	"log/slog"
	"testing"
	"time"
)

func TestHandler(t *testing.T) {
	var buf bytes.Buffer
	l := slog.New(New(&buf))
	l.Info("not shown")
	l.Debug("not shown either")
	l.Warn("Set member runs on Backtracking", "pattern", "bt0", "id", 0, "effect", "line one\nline two")
	l.Warn("Set member runs on Backtracking", "pattern", "bt0", "id", 0, "effect", "line one\nline two") // once only
	l.Error("config c.yaml:3: bad regexp\n   3 | - regexp: 'a('\n     |           ^")
	l.With("set", "s").WithGroup("g").With("k", 1).WithGroup("").Warn("grouped", "x", true, slog.Group("inner", "y", "z"), slog.Group("", "flat", 2), "", "skipped")
	want := "regexped: warning: Set member runs on Backtracking\n" +
		"    pattern: bt0\n    id: 0\n    effect: line one\n      line two\n" +
		"regexped: config c.yaml:3: bad regexp\n   3 | - regexp: 'a('\n     |           ^\n" +
		"regexped: warning: grouped\n    set: s\n    g.k: 1\n    g.x: true\n    g.inner.y: z\n    g.flat: 2\n"
	if buf.String() != want {
		t.Errorf("got:\n%s\nwant:\n%s", buf.String(), want)
	}
}

type failWriter struct{}

func (failWriter) Write([]byte) (int, error) { return 0, errors.New("closed") }

func TestHandlerWriteError(t *testing.T) {
	h := New(failWriter{})
	if h.WithGroup("") != slog.Handler(h) {
		t.Fatal("WithGroup(\"\") is not the handler itself")
	}
	if !h.Enabled(context.Background(), slog.LevelWarn) || h.Enabled(context.Background(), slog.LevelInfo) {
		t.Fatal("Enabled: want WARN and above only")
	}
	if err := h.Handle(context.Background(), slog.NewRecord(time.Time{}, slog.LevelError, "m", 0)); err == nil {
		t.Fatal("a failed write is not reported")
	}
}
