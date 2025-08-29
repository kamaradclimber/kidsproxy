package main

import (
	"context"
	"fmt"
	"io"
	"log/slog"
	"net"
	"net/http"
	"net/http/httputil"
	"net/url"
	"os"
	"time"

	"github.com/gobwas/glob"

	httptrace "github.com/DataDog/dd-trace-go/contrib/net/http/v2"
	"github.com/DataDog/dd-trace-go/v2/ddtrace/tracer"
)

type AllowListPattern struct {
	Host glob.Glob
}

func (p *AllowListPattern) Match(u *url.URL) bool {
	return p.Host.Match(u.Hostname())
}

var allowed_patterns = []AllowListPattern{
	{Host: glob.MustCompile("*")}, // FIXME: for now allowing everything

	{Host: glob.MustCompile("detectportal.firefox.com", '.')},
	{Host: glob.MustCompile("*.wikipedia.org", '.')},
	{Host: glob.MustCompile("*.wikimedia.org", '.')},
	{Host: glob.MustCompile("*.radioswissclassic.ch", '.')},
}

var logger = initialiseLogging()

func main() {
	logger.Info("Starting kidsproxy!")
	tracer.Start()
	defer tracer.Stop()

	httpProxy := &httputil.ReverseProxy{
		Rewrite: func(r *httputil.ProxyRequest) {
		},
	}

	handler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if !checkUrlAllowed(w, r) {
			return
		}
		if r.Method == http.MethodConnect {
			logger.InfoContext(r.Context(), fmt.Sprintf("received CONNECT (https traffic): %s", r.RequestURI))
			tunnel(w, r)
		} else {
			logger.InfoContext(r.Context(), fmt.Sprintf("received http traffic: %s", r.RequestURI))
			httpProxy.ServeHTTP(w, r)
		}
	})

	wrappedHandler := httptrace.WrapHandler(handler, "proxy-server42", "resource-name42")

	server := &http.Server{
		Addr:    ":8080",
		Handler: wrappedHandler,
	}

	// Start the HTTP server
	logger.Info("Now starting listening on :8080")
	err := server.ListenAndServe()
	if err != nil {
		logger.Error("error while serving", err)
	}
}

// returns true if the URL has been allowed. If false, request treatment should stop immediately
func checkUrlAllowed(w http.ResponseWriter, r *http.Request) bool {
	for _, p := range allowed_patterns {
		if p.Match(r.URL) {
			logger.InfoContext(r.Context(), fmt.Sprintf("%s allowed because of %v", r.RequestURI, p))
			return true
		}
	}
	serveError(w, r, fmt.Errorf("URL %s is not allowed because no pattern allow it", r.RequestURI))
	return false
}

func serveError(w http.ResponseWriter, r *http.Request, err error) {
	logger.Error(err.Error())
	err = fmt.Errorf("an error occured: %w", err)

	http.Error(w, err.Error(), http.StatusForbidden)
}

// creating transparent tunnel between source and destination
func tunnel(w http.ResponseWriter, r *http.Request) {
	logger.InfoContext(r.Context(), fmt.Sprintf("received tunneling request for %s", r.Host))
	server_connection, err := net.DialTimeout("tcp", r.Host, 10*time.Second)
	if err != nil {
		http.Error(w, err.Error(), http.StatusServiceUnavailable)
		return
	}
	w.WriteHeader(http.StatusOK)
	hijacker, ok := w.(http.Hijacker)
	if !ok {
		http.Error(w, "Hijacking not supported", http.StatusInternalServerError)
		return
	}
	client_connection, _, err := hijacker.Hijack()
	if err != nil {
		http.Error(w, err.Error(), http.StatusServiceUnavailable)
	}
	go transfer(server_connection, client_connection)
	go transfer(client_connection, server_connection)
}

// operate (transparent) transfer between source and destination
func transfer(destination io.WriteCloser, source io.ReadCloser) {
	defer destination.Close()
	defer source.Close()
	io.Copy(destination, source)
}

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
