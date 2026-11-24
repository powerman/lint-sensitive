package analyzer

import (
	"go/ast"
	"go/types"
	"slices"

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
			m, err := get(pass)
			if err != nil {
				return nil, err
			}
			return runPrint(pass, m)
		},
	}
}

// runPrint is the shared core used by both flag-driven and New()-based print analyzers.
func runPrint(pass *analysis.Pass, m matcher) (any, error) {
	inspectResult := pass.ResultOf[inspect.Analyzer].(*inspector.Inspector)
	shouldCheck := m.newShouldCheck(pass)

	for call := range inspector.All[*ast.CallExpr](inspectResult) {
		name := printBuiltin(pass, call)
		if name == "" || !shouldCheck(call.Pos()) {
			continue
		}
		hasSensitive := slices.ContainsFunc(call.Args, func(arg ast.Expr) bool {
			t := pass.TypesInfo.TypeOf(arg)
			return t != nil && m.isSensitiveBasic(t)
		})
		if hasSensitive {
			pass.Reportf(call.Pos(),
				"sensitive value passed to builtin %s leaks raw value (it bypasses redaction); use a redacting printer",
				name)
		}
	}

	//nolint:nilnil // Returning nil, nil is standard for go/analysis analyzers.
	return nil, nil
}

// printBuiltin returns the name of the builtin print or println which call calls,
// or an empty string for any other call.
func printBuiltin(pass *analysis.Pass, call *ast.CallExpr) string {
	ident, ok := call.Fun.(*ast.Ident)
	if !ok {
		return ""
	}
	builtin, ok := pass.TypesInfo.Uses[ident].(*types.Builtin)
	if !ok || builtin.Name() != "print" && builtin.Name() != "println" {
		return ""
	}
	return builtin.Name()
}
