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

	nodeFilter := []ast.Node{(*ast.CallExpr)(nil)}
	inspectResult.Preorder(nodeFilter, func(n ast.Node) {
		call := n.(*ast.CallExpr)

		ident, ok := call.Fun.(*ast.Ident)
		if !ok {
			return
		}

		obj := pass.TypesInfo.Uses[ident]
		if obj == nil {
			return
		}

		builtin, ok := obj.(*types.Builtin)
		if !ok {
			return
		}

		if builtin.Name() != "print" && builtin.Name() != "println" {
			return
		}

		if !m.shouldCheck(pass, call.Pos()) {
			return
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
	})

	//nolint:nilnil // Returning nil, nil is standard for go/analysis analyzers.
	return nil, nil
}
