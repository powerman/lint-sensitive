// Command lint-sensitive detects sensitive value leaks via fmt reflection
// and builtin print/println.
package main

import (
	"golang.org/x/tools/go/analysis/multichecker"

	"github.com/powerman/lint-sensitive/analyzer"
)

func main() {
	multichecker.Main(
		analyzer.FlagAnalyzer,
		analyzer.FieldsAnalyzer,
		analyzer.PrintAnalyzer,
	)
}
