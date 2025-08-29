package main

import (
	"fmt"
	"io"
	"log"
	"net"
	"net/http"
	"net/http/httputil"
	"net/url"
	"time"
)

type AllowListPattern struct {
	Host string // TODO: should be a regexp instead
	Path string // TODO: should be a regexp instead
}

func (p *AllowListPattern) Match(u *url.URL) bool {
	return p.Host == u.Hostname()
}

var allowed_patterns = []AllowListPattern{
	{Host: "www.google.com"},
	{Host: "pkg.go.dev"},
}

func main() {
	log.Println("Starting kidsproxy!")

	httpProxy := &httputil.ReverseProxy{
		Rewrite: func(r *httputil.ProxyRequest) {
		},
	}

	server := &http.Server{
		Addr: ":8080",
		Handler: http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			if !checkUrlAllowed(w, r) {
					return
				}
			if r.Method == http.MethodConnect {
				log.Printf("received CONNECT (https traffic): %s", r.RequestURI)
				tunnel(w, r)
			} else {
				log.Printf("received http traffic: %s", r.RequestURI)
				httpProxy.ServeHTTP(w, r)
			}
		}),
	}

	// Start the HTTP server
	log.Println("Now starting listering on :8080")
	err := server.ListenAndServe()
	if err != nil {
		log.Fatal(fmt.Errorf("error while serving: %w", err))
	}
}

// returns true if the URL has been allowed. If false, request treatment should stop immediately
func checkUrlAllowed(w http.ResponseWriter, r *http.Request) bool {
	for _, p := range allowed_patterns {
		if p.Match(r.URL) {
			log.Printf("%s allowed because of %v", r.RequestURI, p)
			return true
		}
	}
	serveError(w, r, fmt.Errorf("URL %s is not allowed because no pattern allow it", r.RequestURI))
	return false
}

func serveError(w http.ResponseWriter, r *http.Request, err error) {
	log.Println(err.Error())
	err = fmt.Errorf("an error occured: %w", err)

	// TODO: for now we return 200 OK because that's the only way to make https request being displayed (instead of showing firefox error that we have no control on)
	// but TBH, since we are not responding with a TLS reply (for TLS requests) the browser does not display the response
	http.Error(w, err.Error(), http.StatusOK)
}

// creating transparent tunnel between source and destination
func tunnel(w http.ResponseWriter, r *http.Request) {
	log.Printf("received tunneling request for %s", r.Host)
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
