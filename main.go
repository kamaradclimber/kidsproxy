package main

import (
	"encoding/base64"
	"fmt"
	"io"
	"log/slog"
	"net"
	"net/http"
	"net/http/httputil"
	"net/url"
	"os"
	"strings"
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

var globally_allowed_patterns = []AllowListPattern{
	{Host: glob.MustCompile("*")}, // FIXME: for now allowing everything

	{Host: glob.MustCompile("detectportal.firefox.com", '.')},
	{Host: glob.MustCompile("*.wikipedia.org", '.')},
	{Host: glob.MustCompile("*.wikimedia.org", '.')},
	{Host: glob.MustCompile("*.radioswissclassic.ch", '.')},
}

type User string

var per_user_allowed_patterns map[User][]AllowListPattern

func main() {
	logger := initialiseLogging()
	logger.Info("Starting kidsproxy!")
	tracer.Start()
	defer tracer.Stop()

	httpProxy := &httputil.ReverseProxy{
		Rewrite: func(r *httputil.ProxyRequest) {
		},
	}

	handler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		logger := logger.With(slog.Group("request",
			slog.String("hostname", r.URL.Hostname()),
			slog.String("port", r.URL.Port()),
			slog.String("path", r.URL.Path),
			slog.String("method", r.Method),
		))
		if !ensureProxyAuth(logger, w, r) {
			// ensureProxyAuth updates the response automatically
			return
		}
		// at this point, we know user is valid
		user, _ := checkUser(logger, r)
		logger = logger.With(slog.Any("user", user))
		if !checkUrlAllowed(logger, w, r, user) {
			blockRequest(logger, w, r)
			return
		}
		// after this point we try to proxy the request as well possible (without interferring with traffic)
		logger = logger.With(slog.Bool("blocked", false))
		if r.Method == http.MethodConnect {
			logger.InfoContext(r.Context(), fmt.Sprintf("received CONNECT (https traffic): %s", r.RequestURI))
			tunnel(logger, w, r)
		} else {
			logger.InfoContext(r.Context(), fmt.Sprintf("received http traffic: %s", r.RequestURI))
			httpProxy.ServeHTTP(w, r)
		}
	})

	wrappedHandler := httptrace.WrapHandler(handler, os.Getenv("DD_SERVICE"), "resource-name42")

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
func checkUrlAllowed(logger *slog.Logger, w http.ResponseWriter, r *http.Request, user User) bool {
	patterns := globally_allowed_patterns
	if user_specific_patterns, found := per_user_allowed_patterns[user]; found {
		patterns = append(patterns, user_specific_patterns...)
	}
	for _, p := range patterns {
		if p.Match(r.URL) {
			logger.InfoContext(r.Context(), fmt.Sprintf("%s allowed because of %v", r.RequestURI, p))
			return true
		}
	}

	return false
}

func blockRequest(logger *slog.Logger, w http.ResponseWriter, r *http.Request) {
	logger.WarnContext(r.Context(), "request is not present in the allowlist, blocking", slog.Bool("blocked", true))
	err := fmt.Errorf("blocked")

	http.Error(w, err.Error(), http.StatusForbidden)
}

// creating transparent tunnel between source and destination
func tunnel(logger *slog.Logger, w http.ResponseWriter, r *http.Request) {
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

// ensureProxyAuth returns true if the request is properly authenticated
// this method takes care of the response
func ensureProxyAuth(logger *slog.Logger, w http.ResponseWriter, r *http.Request) bool {
	_, err := checkUser(logger, r)
	if err != nil {
		if err == MissingProxyHeaderError {
			logger.WarnContext(r.Context(), err.Error())
			var realm string
			var present bool
			if realm, present = os.LookupEnv("KIDSPROXY_REALM"); !present {
				realm = "dev"
			}
			w.Header()["Proxy-Authenticate"] = []string{
				fmt.Sprintf("Basic realm=\"%s\", charset=\"UTF-8\"", realm),
			}
			w.Header()["Content-Type"] = []string{"text/plain; charset=utf-8"}
			w.WriteHeader(http.StatusProxyAuthRequired)
			fmt.Fprintln(w, "authentication header missing")
		} else {
			logger.ErrorContext(r.Context(), err.Error())
			http.Error(w, err.Error(), http.StatusBadRequest)
		}
		return false
	}
	return true
}

type ProxyAuthError struct {
	error
}

var MissingProxyHeaderError = ProxyAuthError{fmt.Errorf("authentication header missing")}

func checkUser(logger *slog.Logger, r *http.Request) (User, error) {
	values, found := r.Header["Proxy-Authorization"]
	if !found {
		return "", MissingProxyHeaderError
	}
	if len(values) == 0 {
		return "", ProxyAuthError{fmt.Errorf("authentication header present but no value")}
	}
	// then we take only the first value
	auth := values[0]

	// always assume basic auth for now
	words := strings.SplitN(auth, " ", 2)
	if len(words) != 2 {
		return "", ProxyAuthError{fmt.Errorf("auth header is not a valid basic auth")}
	}

	decoded, err := base64.StdEncoding.DecodeString(words[1])
	if err != nil {
		return "", ProxyAuthError{fmt.Errorf("could not decode auth as base64")}
	}
	decodedString := string(decoded)
	parts := strings.SplitN(decodedString, ":", 2)
	if len(parts) != 2 {
		return "", ProxyAuthError{fmt.Errorf("could not decode auth as <username:password>")}
	}

	user := User(parts[0])

	// FIXME: implement auth verification
	logger.WarnContext(r.Context(), "auth accepted but not checked", slog.Any("user", user))
	return user, nil
}
