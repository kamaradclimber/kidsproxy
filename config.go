package main

import (
	"fmt"
	"github.com/gobwas/glob"
	"gopkg.in/yaml.v3"
	"os"
	"regexp"
	"strings"
)

type Config struct {
	Rules map[string][]string `yaml:"rules"`
}

func ReadConfig(filename string, out interface{}) error {
	data, err := os.ReadFile(filename)
	if err != nil {
		return fmt.Errorf("failed to read file: %w", err)
	}

	if err := yaml.Unmarshal(data, out); err != nil {
		return fmt.Errorf("failed to unmarshal YAML: %w", err)
	}

	return nil
}

func ParseRules(config Config) PatternsPerUser {
	var rules PatternsPerUser = make(PatternsPerUser)
	for username, patterns := range config.Rules {
		user := User(username)
		for _, pattern := range patterns {
			rules[user] = append(rules[user], parsePattern(pattern))
		}
	}
	return rules
}

func parsePattern(pattern string) AllowListPattern {
	parts := strings.SplitN(pattern, ":", 2)
	patternType := parts[0]
	switch patternType {
	case "glob":
		return AllowListPattern{Host: glob.MustCompile(parts[1], '.')}
	case "regexp":
		return AllowListPattern{HostRegex: *regexp.MustCompile(parts[1])}
	default:
		panic(fmt.Sprintf("unable to read this pattern %s", pattern))
	}
}

type User string
type PatternsPerUser map[User][]AllowListPattern
