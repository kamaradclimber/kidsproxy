package main

import (
	"fmt"
	"io"
	"log"
	"net"
	"net/http"
	"net/http/httputil"
	"time"
)

func main() {
	log.Println("Starting kidsproxy!")

	proxy := &httputil.ReverseProxy{
		Rewrite: func(r *httputil.ProxyRequest) {
			log.Println(fmt.Sprintf("%+v", r))
		},
	}

	server := &http.Server{
		Addr: ":8080",
		Handler: http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			if r.Method == http.MethodConnect {
				log.Println("received CONNECT (https traffic)")
				tunnel(w, r)
			} else {
				log.Println("received http traffic")
				proxy.ServeHTTP(w, r)
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

func tunnel(w http.ResponseWriter, r *http.Request) {
	log.Println(fmt.Sprintf("received request for %s", r.Host))
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

func transfer(destination io.WriteCloser, source io.ReadCloser) {
	defer destination.Close()
	defer source.Close()
	io.Copy(destination, source)
}
