package main

import (
	"context"
	"github.com/DataDog/dd-trace-go/v2/ddtrace/tracer"
	"log/slog"
	"os"
)

type ContextHandler struct {
	slog.Handler
}

func (h ContextHandler) Handle(ctx context.Context, r slog.Record) error {
	r.AddAttrs(h.addTraceFromContext(ctx)...)
	return h.Handler.Handle(ctx, r)
}

func (h ContextHandler) WithAttrs(attrs []slog.Attr) slog.Handler {
	return ContextHandler{h.Handler.WithAttrs(attrs)}
}

func (h ContextHandler) WithGroup(name string) slog.Handler {
	return ContextHandler{h.Handler.WithGroup(name)}
}

func (h ContextHandler) addTraceFromContext(ctx context.Context) (as []slog.Attr) {
	span, ok := tracer.SpanFromContext(ctx)
	if ok {
		traceID := span.Context().TraceID()
		ddgroup := slog.Group("dd", slog.String("trace_id", traceID))
		as = append(as, ddgroup)
	}
	return
}

func initialiseLogging() *slog.Logger {
	jsonHandler := slog.NewJSONHandler(os.Stdout, nil)
	ctxHandler := ContextHandler{jsonHandler}

	ddvars := slog.Group("dd",
		slog.String("env", os.Getenv("DD_ENV")),
		slog.String("service", os.Getenv("DD_SERVICE")),
		slog.String("version", os.Getenv("DD_VERSION")),
		slog.String("source", "go"),
	)

	logger := slog.New(ctxHandler).With(ddvars)
	slog.SetDefault(logger)
	return logger
}
