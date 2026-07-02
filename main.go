// Command lint-sensitive detects sensitive value leaks via fmt reflection
// and builtin print/println.
package main

import (
	"crypto/sha256"
	"errors"
	"flag"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"runtime/debug"

	"golang.org/x/tools/go/analysis/multichecker"

	"github.com/powerman/lint-sensitive/analyzer"
)

const unknown = "unknown"

var errUnsupportedV = errors.New("use -V=full")

func main() {
	// Register -V before multichecker so the framework's stub (which always
	// prints "devel") is not installed; we print the VCS-stamped version instead.
	// analysisflags.addVersionFlag registers -V only when flag.Lookup("V") == nil.
	flag.Var(versionFlag{}, "V", "print version and exit")

	multichecker.Main(
		analyzer.FlagAnalyzer,
		analyzer.FieldsAnalyzer,
		analyzer.PrintAnalyzer,
	)
}

// versionFlag implements the -V=full protocol required by `go vet`.
type versionFlag struct{}

func (versionFlag) IsBoolFlag() bool { return true }
func (versionFlag) Get() any         { return nil }
func (versionFlag) String() string   { return "" }

func (versionFlag) Set(s string) error {
	if s != "full" {
		return fmt.Errorf("-V=%s: %w", s, errUnsupportedV)
	}
	progname := filepath.Base(os.Args[0])
	fmt.Printf("%s version %s buildID=%s\n", progname, resolveVersion(), buildID())
	os.Exit(0) //nolint:revive // -V=full protocol: terminate after printing version, same as the framework
	return nil
}

// resolveVersion returns the module version stamped by the Go toolchain.
// Go 1.24+ derives Main.Version from VCS — the exact tag for a clean checkout
// sitting on it, or a pseudo-version otherwise — so no -ldflags -X is needed:
// the release builds from a tag checkout. Falls back to "(unknown)" only when
// build info is entirely unavailable.
func resolveVersion() string {
	bi, ok := debug.ReadBuildInfo()
	if !ok {
		return "(unknown)"
	}
	return bi.Main.Version
}

// buildID returns a content hash of the running executable, mirroring the
// framework's -V=full output so `go vet -vettool=` change-detection keeps working.
func buildID() string {
	exe, err := os.Executable()
	if err != nil {
		return unknown
	}
	f, err := os.Open(exe) //nolint:gosec // exe comes from os.Executable(), not user input
	if err != nil {
		return unknown
	}
	defer f.Close() //nolint:errcheck // read-only; close error is not actionable
	h := sha256.New()
	_, err = io.Copy(h, f)
	if err != nil {
		return unknown
	}
	return fmt.Sprintf("%02x", h.Sum(nil))
}
