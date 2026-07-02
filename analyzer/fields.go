package analyzer

import (
	"fmt"
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

// formatDiagnostic builds the diagnostic message for a field that leaks
// through a disabled Formatter/Stringer/GoStringer path.
func formatDiagnostic(field *types.Var, factor *disableFactor) string {
	var behind string
	switch factor.kind {
	case factorUnexportedField:
		behind = fmt.Sprintf("unexported field %q", factor.name)
	case factorNonFormatterPointer:
		behind = fmt.Sprintf("non-Formatter pointer to %s", factor.name)
	default:
		behind = factor.kind
	}
	return fmt.Sprintf(
		"sensitive field %q is reachable behind a %s; "+
			"the safe type's fmt.Formatter/Stringer/GoStringer then does not fire "+
			"and the field is not structurally protected "+
			"— fmt can print its secret content",
		field.Name(), behind)
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
			if !m.shouldCheck(pass, f.Pos()) {
				continue
			}
			var factor disableFactor
			fd := !f.Exported()
			if fd {
				factor = disableFactor{kind: "unexportedField", name: f.Name()}
			}
			if m.walk(f.Type(), fd, false, make(map[types.Type]bool), &factor) {
				msg := formatDiagnostic(f, &factor)
				pass.Report(analysis.Diagnostic{Pos: f.Pos(), Message: msg})
			}
		}
	})

	m.runReliabilityLevels(pass)

	//nolint:nilnil // Returning nil, nil is standard for go/analysis analyzers.
	return nil, nil
}
