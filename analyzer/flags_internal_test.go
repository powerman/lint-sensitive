package analyzer

import (
	"flag"
	"testing"
)

// TestRunFlag verifies that every registered flag reaches the matcher built by runFlag.
// It fails when a flag is registered under one name but wired to another Config field,
// which the New(Config{...}) based tests cannot detect.
//
// The test mutates the shared FlagAnalyzer.Flags (TestMain also sets -types there),
// so it must not run in parallel and restores each flag it changes.
func TestRunFlag(t *testing.T) { //nolint:paralleltest // Mutates the shared FlagAnalyzer.Flags.
	tests := []struct {
		flag, value string
		check       func(m matcher) bool
	}{
		{"types", "example.com/a.T, example.com/b", func(m matcher) bool {
			return m.types[packageType{Pkg: "example.com/a", Name: "T"}] && m.packages["example.com/b"]
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
	for _, tc := range tests { //nolint:paralleltest // Same reason as above.
		covered[tc.flag] = true
		t.Run(tc.flag, func(t *testing.T) {
			f := FlagAnalyzer.Flags.Lookup(tc.flag)
			if f == nil {
				t.Fatalf("flag %q is not registered", tc.flag)
			}
			orig := f.Value.String()
			t.Cleanup(func() { _ = FlagAnalyzer.Flags.Set(tc.flag, orig) })

			err := FlagAnalyzer.Flags.Set(tc.flag, tc.value)
			if err != nil {
				t.Fatal(err)
			}
			res, err := runFlag(nil)
			if err != nil {
				t.Fatal(err)
			}
			if !tc.check(res.(matcher)) {
				t.Errorf("setting -%s=%s did not reach the matcher", tc.flag, tc.value)
			}
		})
	}

	FlagAnalyzer.Flags.VisitAll(func(f *flag.Flag) {
		if !covered[f.Name] {
			t.Errorf("flag %q is not covered by TestRunFlag", f.Name)
		}
	})
}
