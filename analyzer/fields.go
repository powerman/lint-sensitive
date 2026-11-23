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
	var via string
	switch factor.kind {
	case factorUnexportedField:
		via = fmt.Sprintf("an unexported field %q", factor.name)
	case factorNonFormatterPointer:
		via = fmt.Sprintf("a non-Formatter pointer to %s", factor.name)
	default:
		via = factor.kind
	}
	return fmt.Sprintf(
		"sensitive field %q is reachable through %s; "+
			"the safe type's fmt.Formatter/Stringer/GoStringer then does not fire "+
			"and the field is not structurally protected "+
			"— fmt can print its secret content",
		field.Name(), via)
}

// formatterStructs returns struct types written inside the declaration of a named type
// which implements [fmt.Formatter], including anonymous structs nested in it.
// Their fields are not checked:
// such a type is a safe terminal wherever fmt can reach it with interfaces enabled,
// and the cases where it cannot are reported at the field which holds the type.
func (m matcher) formatterStructs(pass *analysis.Pass, in *inspector.Inspector) map[*ast.StructType]bool {
	res := make(map[*ast.StructType]bool)
	in.Preorder([]ast.Node{(*ast.TypeSpec)(nil)}, func(n ast.Node) {
		ts := n.(*ast.TypeSpec) //nolint:forcetypeassert // Guaranteed by the node filter.
		obj := pass.TypesInfo.Defs[ts.Name]
		if obj == nil || !m.hasMethod(obj.Type(), methodFormat) {
			return
		}
		ast.Inspect(ts.Type, func(n ast.Node) bool {
			if st, ok := n.(*ast.StructType); ok {
				res[st] = true
			}
			return true
		})
	})
	return res
}

// runFields is the shared core used by both flag-driven and New()-based fields analyzers.
func runFields(pass *analysis.Pass, m matcher) (any, error) {
	inspectResult := pass.ResultOf[inspect.Analyzer].(*inspector.Inspector)

	formatterStructs := m.formatterStructs(pass, inspectResult)

	nodeFilter := []ast.Node{(*ast.StructType)(nil)}
	inspectResult.Preorder(nodeFilter, func(n ast.Node) {
		st, ok := n.(*ast.StructType)
		if !ok || formatterStructs[st] {
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
			if m.walk(f.Type(), fd, false, make(map[walkKey]bool), &factor) {
				msg := formatDiagnostic(f, &factor)
				pass.Report(analysis.Diagnostic{Pos: f.Pos(), Message: msg})
			}
		}
	})

	m.runReliabilityLevels(pass)

	//nolint:nilnil // Returning nil, nil is standard for go/analysis analyzers.
	return nil, nil
}
