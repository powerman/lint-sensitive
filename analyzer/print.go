package analyzer

import (
	"go/ast"
	"go/types"

	"golang.org/x/tools/go/analysis"
	"golang.org/x/tools/go/analysis/passes/inspect"
	"golang.org/x/tools/go/ast/inspector"
)

// newPrintAnalyzer creates a print analyzer with the given dependencies and matcher provider.
func newPrintAnalyzer(requires []*analysis.Analyzer, get matcherFunc) *analysis.Analyzer {
	return &analysis.Analyzer{
		Name:     "sensitiveprint",
		Doc:      "detect builtin print/println calls with basic-kind sensitive arguments",
		Requires: requires,
		Run: func(pass *analysis.Pass) (any, error) {
			return runPrint(pass, get(pass))
		},
	}
}

// runPrint is the shared core used by both flag-driven and New()-based print analyzers.
func runPrint(pass *analysis.Pass, m matcher) (any, error) {
	inspectResult := pass.ResultOf[inspect.Analyzer].(*inspector.Inspector)
	shouldCheck := m.newShouldCheck(pass)

	for call := range inspector.All[*ast.CallExpr](inspectResult) {
		ident, ok := call.Fun.(*ast.Ident)
		if !ok {
			continue
		}

		builtin, ok := pass.TypesInfo.Uses[ident].(*types.Builtin)
		if !ok || (builtin.Name() != "print" && builtin.Name() != "println") {
			continue
		}

		if !shouldCheck(call.Pos()) {
			continue
		}

		for _, arg := range call.Args {
			argType := pass.TypesInfo.TypeOf(arg)
			if argType == nil {
				continue
			}
			if m.isSensitiveBasic(argType) {
				pass.Reportf(call.Pos(),
					"sensitive value passed to builtin %s leaks raw value (it bypasses redaction); use a redacting printer",
					builtin.Name())
				break
			}
		}
	}

	//nolint:nilnil // Returning nil, nil is standard for go/analysis analyzers.
	return nil, nil
}
