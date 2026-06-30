package analyzer

import (
	"go/ast"
	"go/types"

	"golang.org/x/tools/go/analysis"
	"golang.org/x/tools/go/analysis/passes/inspect"
	"golang.org/x/tools/go/ast/inspector"
)

// newFieldsAnalyzer creates a fields analyzer with the given dependencies and matcher provider.
func newFieldsAnalyzer(requires []*analysis.Analyzer, get matcherFunc) *analysis.Analyzer {
	return &analysis.Analyzer{
		Name:     "sensitivefields",
		Doc:      "detect unexported struct fields whose type contains sensitive values",
		Requires: requires,
		Run: func(pass *analysis.Pass) (any, error) {
			m, err := get(pass)
			if err != nil {
				return nil, err
			}
			return runFields(pass, m)
		},
	}
}

// runFields is the shared core used by both flag-driven and New()-based fields analyzers.
func runFields(pass *analysis.Pass, m matcher) (any, error) {
	inspectResult := pass.ResultOf[inspect.Analyzer].(*inspector.Inspector)

	nodeFilter := []ast.Node{(*ast.StructType)(nil)}
	inspectResult.Preorder(nodeFilter, func(n ast.Node) {
		st, ok := n.(*ast.StructType)
		if !ok {
			return
		}
		typ := pass.TypesInfo.TypeOf(st)
		if typ == nil {
			return
		}
		st2, ok := typ.Underlying().(*types.Struct)
		if !ok {
			return
		}
		for f := range st2.Fields() {
			if f.Exported() {
				continue
			}
			if !m.shouldCheck(pass, f.Pos()) {
				continue
			}
			if m.containsSensitive(f.Type(), make(map[types.Type]bool)) {
				pass.Reportf(f.Pos(),
					"sensitive value in unexported field %q is leaked by fmt: reflection bypasses its redaction",
					f.Name())
			}
		}
	})

	//nolint:nilnil // Returning nil, nil is standard for go/analysis analyzers.
	return nil, nil
}
