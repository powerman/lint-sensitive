package analyzer_test

import (
	"go/ast"
	"go/token"
	"slices"
	"strings"
	"testing"

	"golang.org/x/tools/go/analysis"
	"golang.org/x/tools/go/analysis/analysistest"

	"github.com/powerman/lint-sensitive/analyzer"
)

const testTypes = "fakesensitive,fakeplayground,fakelogfusc,fakesecrecy.Secret,fakeconceal.Text,fakeconceal.Bytes"

func TestMain(m *testing.M) {
	err := analyzer.FlagAnalyzer.Flags.Set("types", testTypes)
	if err != nil {
		panic("failed to set -types flag: " + err.Error())
	}
	m.Run()
}

func TestFieldsAnalyzer(t *testing.T) {
	t.Parallel()
	analysistest.Run(t, analysistest.TestData(), analyzer.FieldsAnalyzer, "fields")
}

func TestPrintAnalyzer(t *testing.T) {
	t.Parallel()
	analysistest.Run(t, analysistest.TestData(), analyzer.PrintAnalyzer, "printcheck")
}

// runNew runs the analyzer with the given name from analyzer.New(cfg) on the testdata package pkg.
func runNew(t *testing.T, cfg analyzer.Config, name, pkg string) {
	t.Helper()

	analyzers := analyzer.New(cfg)
	i := slices.IndexFunc(analyzers, func(a *analysis.Analyzer) bool { return a.Name == name })
	if i < 0 {
		t.Fatalf("%s not found in New() result", name)
	}
	analysistest.Run(t, analysistest.TestData(), analyzers[i], pkg)
}

func TestNewFieldsAnalyzer(t *testing.T) {
	t.Parallel()
	runNew(t, analyzer.Config{Types: strings.Split(testTypes, ",")}, "sensitivefields", "fields")
}

func TestNewPrintAnalyzer(t *testing.T) {
	t.Parallel()
	runNew(t, analyzer.Config{Types: strings.Split(testTypes, ",")}, "sensitiveprint", "printcheck")
}

// TestFieldsRelatedInformation verifies the hops attached to a diagnostic:
// they go from the reported field's type down to the safe type,
// each with a resolvable position.
func TestFieldsRelatedInformation(t *testing.T) {
	t.Parallel()

	want := map[string][]string{
		// A direct field has only the safe type behind it.
		"renamedImport.y": {"safe type fakesensitive.String"},
		// Two hops of fields, then the safe type.
		"nestedTransitive.inner": {
			`unexported field "secret" of type fakesensitive.String`,
			"safe type fakesensitive.String",
		},
		// A pointer is a hop too.
		"StarInnerExported.M": {
			"non-Formatter pointer to fields.inner",
			`unexported field "secret" of type fakesensitive.String`,
			"safe type fakesensitive.String",
		},
		// A Formatter pointer which does not fire is not called "non-Formatter".
		"UnexportedPtrFmtWrapper.p": {
			"pointer to fields.ptrFmtWrapper",
			`unexported field "secret" of type fakesensitive.String`,
			"safe type fakesensitive.String",
		},
		"exposerField.e": {"safe type fields.exposer"},
		// A pointer directly to a safe type is a hop too.
		"ptrConcealUnexported.x": {
			"non-Formatter pointer to fakeconceal.Text",
			"safe type fakeconceal.Text",
		},
	}

	results := analysistest.Run(t, analysistest.TestData(), analyzer.FieldsAnalyzer, "fields")
	got := make(map[string][]string)
	for _, r := range results {
		fieldAt := make(map[token.Pos]string)
		for _, f := range r.Pass.Files {
			ast.Inspect(f, func(n ast.Node) bool {
				ts, ok := n.(*ast.TypeSpec)
				if !ok {
					return true
				}
				if st, isStruct := ts.Type.(*ast.StructType); isStruct {
					for _, field := range st.Fields.List {
						for _, name := range field.Names {
							fieldAt[name.Pos()] = ts.Name.Name + "." + name.Name
						}
					}
				}
				return true
			})
		}
		for _, d := range r.Diagnostics {
			hops := make([]string, 0, len(d.Related))
			for _, rel := range d.Related {
				if posn := r.Pass.Fset.Position(rel.Pos); !posn.IsValid() {
					t.Errorf("%s: related %q has no valid position", fieldAt[d.Pos], rel.Message)
				}
				hops = append(hops, rel.Message)
			}
			got[fieldAt[d.Pos]] = hops
		}
	}
	for field, hops := range want {
		if !slices.Equal(got[field], hops) {
			t.Errorf("%s: related = %q, want %q", field, got[field], hops)
		}
	}
}
