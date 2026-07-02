package main

import (
	"context"
	"errors"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
)

func TestFlagsExposeSensitiveTypes(t *testing.T) {
	t.Parallel()

	binary := buildBinary(t)

	cmd := exec.CommandContext(context.Background(), binary, "-flags")
	out, err := cmd.Output()
	if err != nil {
		t.Fatalf("binary -flags: %v\n%s", err, out)
	}

	if !strings.Contains(string(out), "sensitive.types") {
		t.Fatalf("-flags JSON does not contain sensitive.types\nGot:\n%s", out)
	}
}

func TestExampleEndToEnd(t *testing.T) {
	t.Parallel()

	binary := buildBinary(t)
	exampleDir := filepath.Join(repoRoot(t), "example")

	cmd := exec.CommandContext(context.Background(), binary,
		"-sensitive.types=github.com/powerman/lint-sensitive/example.Secret",
		".",
	)
	cmd.Dir = exampleDir
	cmd.Env = os.Environ()
	out, err := cmd.CombinedOutput()

	outStr := string(out)
	if err != nil {
		var exitErr *exec.ExitError
		if !errors.As(err, &exitErr) {
			t.Fatalf("binary failed: %v\n%s", err, outStr)
		}
		if exitErr.ExitCode() != 3 {
			t.Fatalf("binary exited with code %d, want 3\nOutput:\n%s", exitErr.ExitCode(), outStr)
		}
	}

	// Check total diagnostic count and each unique type's count.
	// This avoids the "presence not count" bug from duplicated Contains checks.
	type diagCheck struct {
		fragment string
		want     int
	}
	checks := []diagCheck{
		// sensitivefields: 7 diagnostics:
		//   - 5 sensitive fields in leakDemo (unexported field leak)
		//   - 1 in innerStruct (reached via exported pointer dereference)
		//   - 1 for the exported pointer itself (non-Formatter pointer to compound)
		{fragment: `sensitive field "powerman"`, want: 1},
		{fragment: `sensitive field "playground"`, want: 1},
		{fragment: `sensitive field "secrecy"`, want: 1},
		{fragment: `sensitive field "logfusc"`, want: 1},
		{fragment: `sensitive field "secret"`, want: 2},
		{fragment: `sensitive field "P"`, want: 1},
		// sensitiveprint: 6 diagnostics (3 print + 3 println).
		// Use trailing space to distinguish "print " from "println".
		{fragment: `sensitive value passed to builtin print `, want: 3},
		{fragment: `sensitive value passed to builtin println`, want: 3},
	}
	totalWant := 0
	for _, c := range checks {
		totalWant += c.want
		got := strings.Count(outStr, c.fragment)
		if got != c.want {
			t.Errorf("%q: got %d occurrences, want %d", c.fragment, got, c.want)
		}
	}

	// Also verify total line count matches.
	// Each diagnostic is one line in the output.
	lines := strings.Split(strings.TrimSpace(outStr), "\n")
	var diagLines int
	for _, l := range lines {
		if strings.Contains(l, "sensitive") {
			diagLines++
		}
	}
	if diagLines != totalWant {
		t.Errorf("total diagnostics: got %d lines, want %d\nOutput:\n%s", diagLines, totalWant, outStr)
	}
}

func TestVersionFlag(t *testing.T) {
	t.Parallel()

	binary := buildBinary(t)

	// -V=full must succeed and print "<progname> version <token> buildID=<hex>".
	out, err := exec.CommandContext(context.Background(), binary, "-V=full").CombinedOutput()
	if err != nil {
		t.Fatalf("binary -V=full: %v\n%s", err, out)
	}
	got := strings.TrimSpace(string(out))
	// Expect at least: name, "version", a non-empty version token.
	fields := strings.Fields(got)
	if len(fields) < 3 || fields[1] != "version" || fields[2] == "" {
		t.Fatalf("-V=full unexpected output: %q", got)
	}
	if !strings.HasPrefix(got, "lint-sensitive ") {
		t.Fatalf("-V=full progname missing: %q", got)
	}

	// -V with an unsupported value must fail, not panic.
	out, err = exec.CommandContext(context.Background(), binary, "-V=bogus").CombinedOutput()
	if err == nil {
		t.Fatalf("-V=bogus expected non-zero exit, got success:\n%s", out)
	}
	if !strings.Contains(string(out), "use -V=full") {
		t.Fatalf("-V=bogus missing hint 'use -V=full':\n%s", out)
	}
}

func buildBinary(t *testing.T) string {
	t.Helper()

	dir := repoRoot(t)
	binary := filepath.Join(t.TempDir(), "lint-sensitive")
	if runtime.GOOS == "windows" {
		binary += ".exe"
	}
	cmd := exec.CommandContext(context.Background(), "go", "build", "-o", binary, ".")
	cmd.Dir = dir
	cmd.Stderr = os.Stderr
	err := cmd.Run()
	if err != nil {
		t.Fatalf("go build: %v", err)
	}
	return binary
}

func repoRoot(t *testing.T) string {
	t.Helper()

	wd, err := os.Getwd()
	if err != nil {
		t.Fatal(err)
	}
	for dir := wd; dir != "/"; dir = filepath.Dir(dir) {
		gomod := filepath.Join(dir, "go.mod")
		_, err := os.Stat(gomod)
		if err == nil {
			return dir
		}
	}
	t.Fatalf("could not find repo root from %s", wd)
	return ""
}
