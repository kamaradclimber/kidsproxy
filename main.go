package main

import (
	"fmt"
	"log/slog"
	"net/http"
	"net/http/httputil"
	"os"

	httptrace "github.com/DataDog/dd-trace-go/contrib/net/http/v2"
	"github.com/DataDog/dd-trace-go/v2/ddtrace/tracer"
)

func main() {
	logger := initialiseLogging()
	logger.Info("Starting kidsproxy!")
	tracer.Start()
	defer tracer.Stop()

	var configFilePath string
	var configFileOptionPresent bool
	if configFilePath, configFileOptionPresent = os.LookupEnv("KIDSPROXY_CONFIG_FILE"); !configFileOptionPresent {
		configFilePath = "/etc/kidsproxy/config.yaml"
	}
	logger.Info(fmt.Sprintf("will use config file located in %s", configFilePath))

	var config Config
	err := ReadConfig(configFilePath, &config)
	if err != nil {
		logger.Error("error while loading config file", err)
		panic(err)
	}
	patternsPerUser := ParseRules(config)

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
		if !checkUrlAllowed(logger, w, r, user, patternsPerUser) {
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

	wrappedHandler := httptrace.WrapHandler(handler, os.Getenv("DD_SERVICE"), "proxy-service")

	var port string
	var present bool
	if port, present = os.LookupEnv("KIDSPROXY_PORT"); !present {
		port = "8080"
	}

	server := &http.Server{
		Addr:    fmt.Sprintf(":%s", port),
		Handler: wrappedHandler,
	}

	// Start the HTTP server
	logger.Info(fmt.Sprintf("Now starting listening on :%s", port))
	err = server.ListenAndServe()
	if err != nil {
		logger.Error("error while serving", err)
	}
}
