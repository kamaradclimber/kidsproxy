package main

import (
	"encoding/base64"
	"fmt"
	"io"
	"log/slog"
	"net"
	"net/http"
	"os"
	"strings"
	"time"
)

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
			w.Header().Add("Proxy-Authenticate", fmt.Sprintf("Basic realm=\"%s\", charset=\"UTF-8\"", realm))

			w.Header().Add("Content-Type", "text/plain; charset=utf-8")
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
	if forced_account := os.Getenv("KIDSPROXY_FORCE_ACCOUNT"); forced_account != "" {
		user := User(forced_account)
		logger.WarnContext(r.Context(), "auth forced via environment variable", slog.Any("user", user))
		return user, nil
	}
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
