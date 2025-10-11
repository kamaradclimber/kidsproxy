package main

import (
	"fmt"
	"log/slog"
	"net/http"
	"net/url"
	"regexp"

	"github.com/gobwas/glob"
)

type AllowListPattern struct {
	Host      glob.Glob
	HostRegex regexp.Regexp
}

func (p *AllowListPattern) Match(u *url.URL) bool {
	if p.Host != nil {
		return p.Host.Match(u.Hostname())
	} else {
		return p.HostRegex.Match([]byte(u.Hostname()))
	}
}

// returns true if the URL has been allowed. If false, request treatment should stop immediately
func checkUrlAllowed(logger *slog.Logger, w http.ResponseWriter, r *http.Request, user User, patternsPerUser PatternsPerUser) bool {
	var patterns []AllowListPattern
	if global_patterns, found := patternsPerUser[User("global")]; found {
		patterns = append(patterns, global_patterns...)
	}
	if user_specific_patterns, found := patternsPerUser[user]; found {
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
