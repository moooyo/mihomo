package engine

import "testing"

func TestHostMatchersUseSingleLabelWildcards(t *testing.T) {
	tests := []struct {
		name    string
		pattern string
		host    string
		want    bool
	}{
		{name: "exact", pattern: "api.example.com", host: "api.example.com", want: true},
		{name: "different exact", pattern: "api.example.com", host: "www.example.com", want: false},
		{name: "one label", pattern: "*.example.com", host: "api.example.com", want: true},
		{name: "apex", pattern: "*.example.com", host: "example.com", want: false},
		{name: "two labels", pattern: "*.example.com", host: "v1.api.example.com", want: false},
		{name: "different suffix", pattern: "*.example.com", host: "api.example.net", want: false},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			if got := matchHostPattern(test.pattern, test.host); got != test.want {
				t.Errorf("matchHostPattern(%q, %q) = %v, want %v", test.pattern, test.host, got, test.want)
			}
			matcher := newCompiledHostMatcher([]string{test.pattern})
			if got := matcher.Match(test.host); got != test.want {
				t.Errorf("compiled matcher for %q with %q = %v, want %v", test.pattern, test.host, got, test.want)
			}
		})
	}
}

func TestHostPatternCoverageUsesSingleLabelWildcards(t *testing.T) {
	tests := []struct {
		name      string
		allowed   string
		candidate string
		want      bool
	}{
		{name: "same exact", allowed: "api.example.com", candidate: "api.example.com", want: true},
		{name: "same wildcard", allowed: "*.example.com", candidate: "*.example.com", want: true},
		{name: "immediate exact", allowed: "*.example.com", candidate: "api.example.com", want: true},
		{name: "apex", allowed: "*.example.com", candidate: "example.com", want: false},
		{name: "deep exact", allowed: "*.example.com", candidate: "v1.api.example.com", want: false},
		{name: "nested wildcard", allowed: "*.example.com", candidate: "*.api.example.com", want: false},
		{name: "wildcard outside exact", allowed: "api.example.com", candidate: "*.example.com", want: false},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			if got := hostPatternCovers(test.allowed, test.candidate); got != test.want {
				t.Fatalf("hostPatternCovers(%q, %q) = %v, want %v", test.allowed, test.candidate, got, test.want)
			}
		})
	}
}

func TestHostPatternValidationRejectsPublicSuffixWildcards(t *testing.T) {
	tests := []struct {
		name    string
		pattern string
		want    bool
	}{
		{name: "registrable domain wildcard", pattern: "*.example.com", want: true},
		{name: "test domain wildcard", pattern: "*.first.example", want: true},
		{name: "ICANN public suffix wildcard", pattern: "*.co.uk", want: false},
		{name: "private public suffix wildcard", pattern: "*.github.io", want: false},
		{name: "exact public suffix", pattern: "co.uk", want: true},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			if got := validHostPattern(test.pattern); got != test.want {
				t.Fatalf("validHostPattern(%q) = %v, want %v", test.pattern, got, test.want)
			}
		})
	}
}
