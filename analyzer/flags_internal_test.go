package analyzer

import (
	"flag"
	"slices"
	"strings"
	"testing"
)

// TestFlagsReachMatcher verifies that every registered flag reaches the matcher
// built by the "sensitive" analyzer of NewFlagAnalyzers.
// It fails when a flag is registered under one name but wired to another Config field,
// which the New(Config{...}) based tests cannot detect.
func TestFlagsReachMatcher(t *testing.T) {
	t.Parallel()

	tests := []struct {
		flag, value string
		check       func(m matcher) bool
	}{
		{"types", "example.com/a.T, example.com/b", func(m matcher) bool {
			return m.types[packageType{Pkg: "example.com/a", Name: "T"}] && m.packages["example.com/b"]
		}},
		{"public", "example.com/a.T.F, example.com/a.T.G", func(m matcher) bool {
			return m.err == nil && slices.Equal(m.public["example.com/a.T"], []string{"F", "G"})
		}},
		{"no-default-types", "true", func(m matcher) bool {
			return !m.packages["github.com/powerman/sensitive"]
		}},
		{"skip-tests", "true", func(m matcher) bool { return m.skipTests }},
		{"skip-generated", "true", func(m matcher) bool { return m.skipGenerated }},
		{"debug", "true", func(m matcher) bool { return m.debug }},
		{"require-marshal-json", "true", func(m matcher) bool { return m.requireMarshalJSON }},
		{"require-marshal-text", "true", func(m matcher) bool { return m.requireMarshalText }},
		{"require-format", "true", func(m matcher) bool { return m.requireFormat }},
		{"require-gostring", "true", func(m matcher) bool { return m.requireGoString }},
		{"require-string", "true", func(m matcher) bool { return m.requireString }},
	}

	covered := make(map[string]bool)
	for _, tc := range tests {
		covered[tc.flag] = true
		t.Run(tc.flag, func(t *testing.T) {
			t.Parallel()

			fa := NewFlagAnalyzers()[0]
			if fa.Flags.Lookup(tc.flag) == nil {
				t.Fatalf("flag %q is not registered", tc.flag)
			}
			err := fa.Flags.Set(tc.flag, tc.value)
			if err != nil {
				t.Fatal(err)
			}
			res, err := fa.Run(nil)
			if err != nil {
				t.Fatal(err)
			}
			m, ok := res.(matcher)
			if !ok {
				t.Fatalf("result is %T, want matcher", res)
			}
			if !tc.check(m) {
				t.Errorf("setting -%s=%s did not reach the matcher", tc.flag, tc.value)
			}
		})
	}

	NewFlagAnalyzers()[0].Flags.VisitAll(func(f *flag.Flag) {
		if !covered[f.Name] {
			t.Errorf("flag %q is not covered by TestFlagsReachMatcher", f.Name)
		}
	})
}

// TestFlagsInvalidPublic verifies that a malformed -sensitive.public entry is an error.
func TestFlagsInvalidPublic(t *testing.T) {
	t.Parallel()

	fa := NewFlagAnalyzers()[0]
	err := fa.Flags.Set("public", "example.com/a.T")
	if err != nil {
		t.Fatal(err)
	}
	_, err = fa.Run(nil)
	if err == nil || !strings.Contains(err.Error(), `invalid -sensitive.public entry "example.com/a.T"`) {
		t.Errorf("Run() error = %v, want invalid -sensitive.public entry", err)
	}
}
