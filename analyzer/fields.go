package analyzer

import (
	"fmt"
	"go/ast"
	"go/token"
	"go/types"
	"slices"

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
			return runFields(pass, get(pass))
		},
	}
}

// formatDiagnostic builds the diagnostic message for a field that leaks
// through a disabled Formatter/Stringer/GoStringer path.
func formatDiagnostic(field *types.Var, factor *disableFactor) string {
	via := fmt.Sprintf("a non-Formatter pointer to %s", factor.name)
	if factor.kind == factorUnexportedField {
		via = fmt.Sprintf("an unexported field %q", factor.name)
	}
	return fmt.Sprintf(
		"sensitive field %q is reachable through %s; "+
			"the safe type's fmt.Formatter/Stringer/GoStringer then does not fire "+
			"and the field is not structurally protected "+
			"— fmt can print its secret content",
		field.Name(), via)
}

// relatedInformation converts the path found by [matcher.walk] into diagnostic's related entries.
// Entries go from the outermost hop (right below the reported field) to the safe type.
// Hops without a resolvable position are dropped:
// positions of types from other packages are not always available.
func relatedInformation(fset *token.FileSet, path []walkStep) []analysis.RelatedInformation {
	var related []analysis.RelatedInformation
	for _, s := range slices.Backward(path) {
		if posn := fset.Position(s.pos); !posn.IsValid() {
			continue
		}
		related = append(related, analysis.RelatedInformation{Pos: s.pos, Message: s.desc})
	}
	return related
}

// formatterStructs returns struct types written inside the declaration of a named type
// which implements [fmt.Formatter], including anonymous structs nested in it.
// Their fields are not checked:
// such a type is a safe terminal wherever fmt can reach it with interfaces enabled,
// and the cases where it cannot are reported at the field which holds the type.
func (m matcher) formatterStructs(pass *analysis.Pass, in *inspector.Inspector) map[*ast.StructType]bool {
	res := make(map[*ast.StructType]bool)
	for ts := range inspector.All[*ast.TypeSpec](in) {
		obj := pass.TypesInfo.Defs[ts.Name]
		if obj == nil || !m.hasMethod(obj.Type(), methodFormat) {
			continue
		}
		for n := range ast.Preorder(ts.Type) {
			if st, ok := n.(*ast.StructType); ok {
				res[st] = true
			}
		}
	}
	return res
}

// runFields is the shared core used by both flag-driven and New()-based fields analyzers.
func runFields(pass *analysis.Pass, m matcher) (any, error) {
	inspectResult := pass.ResultOf[inspect.Analyzer].(*inspector.Inspector)

	formatterStructs := m.formatterStructs(pass, inspectResult)
	shouldCheck := m.newShouldCheck(pass)

	for st := range inspector.All[*ast.StructType](inspectResult) {
		if formatterStructs[st] {
			continue
		}
		typ, ok := pass.TypesInfo.TypeOf(st).(*types.Struct)
		if !ok {
			continue
		}
		for f := range typ.Fields() {
			if !shouldCheck(f.Pos()) {
				continue
			}
			var factor disableFactor
			fd := !f.Exported()
			if fd {
				factor = disableFactor{kind: factorUnexportedField, name: f.Name()}
			}
			var path []walkStep
			if m.walk(f.Type(), fd, false, make(map[walkKey]bool), &factor, &path) {
				pass.Report(analysis.Diagnostic{
					Pos:     f.Pos(),
					Message: formatDiagnostic(f, &factor),
					Related: relatedInformation(pass.Fset, path),
				})
			}
		}
	}

	m.runReliabilityLevels(pass, shouldCheck)

	//nolint:nilnil // Returning nil, nil is standard for go/analysis analyzers.
	return nil, nil
}
