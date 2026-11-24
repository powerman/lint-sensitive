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

const testTypes = "fakesensitive,fakeplayground,fakelogfusc,fakesecrecy.Secret,fakeconceal.Text,fakeconceal.Bytes,fakecamo"

// fmtTypes are the safe types of the sensitivefmt tests.
const fmtTypes = "fakesensitive.String,fakeconceal.Text,fakestringer"

// flagAnalyzer returns the analyzer with the given name from a fresh analyzer.NewFlagAnalyzers()
// whose -sensitive.types flag is set to testTypes.
func flagAnalyzer(t *testing.T, name string) *analysis.Analyzer {
	t.Helper()

	return flagAnalyzerTypes(t, name, testTypes)
}

// flagAnalyzerTypes is like flagAnalyzer with the given -sensitive.types.
func flagAnalyzerTypes(t *testing.T, name, types string) *analysis.Analyzer {
	t.Helper()

	analyzers := analyzer.NewFlagAnalyzers()
	err := analyzers[0].Flags.Set("types", types)
	if err != nil {
		t.Fatalf("set -types flag: %v", err)
	}
	i := slices.IndexFunc(analyzers, func(a *analysis.Analyzer) bool { return a.Name == name })
	if i < 0 {
		t.Fatalf("%s not found in NewFlagAnalyzers() result", name)
	}
	return analyzers[i]
}

func TestFieldsAnalyzer(t *testing.T) {
	t.Parallel()
	analysistest.Run(t, analysistest.TestData(), flagAnalyzer(t, "sensitivefields"), "fields")
}

func TestPrintAnalyzer(t *testing.T) {
	t.Parallel()
	analysistest.Run(t, analysistest.TestData(), flagAnalyzer(t, "sensitiveprint"), "printcheck")
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
		// A defined pointer type is named in its hop.
		"NamedPtrToConceal.X": {
			"non-Formatter pointer type fields.ptrToConceal to fakeconceal.Text",
			"safe type fakeconceal.Text",
		},
	}

	results := analysistest.Run(t, analysistest.TestData(), flagAnalyzer(t, "sensitivefields"), "fields")
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

// TestPublicFieldsConfig verifies that a field declared public
// does not break the structural protection and the opacity of its type.
func TestPublicFieldsConfig(t *testing.T) {
	t.Parallel()

	cfg := analyzer.Config{
		Types:              reliabilityTypes,
		RequireMarshalJSON: true,
		RequireMarshalText: true,
	}
	t.Run("not declared", func(t *testing.T) {
		t.Parallel()
		runNew(t, cfg, "sensitivefields", "public_off")
	})
	t.Run("declared", func(t *testing.T) {
		t.Parallel()
		cfg := cfg
		cfg.PublicFields = []string{"fakesensitive.Credential.ID"}
		runNew(t, cfg, "sensitivefields", "public_on")
	})
}

// TestInvalidPublicFields verifies that a malformed entry makes every analyzer fail.
func TestInvalidPublicFields(t *testing.T) {
	t.Parallel()

	for _, a := range analyzer.New(analyzer.Config{PublicFields: []string{"fakesensitive.Credential"}}) {
		t.Run(a.Name, func(t *testing.T) {
			t.Parallel()
			_, err := a.Run(&analysis.Pass{})
			if err == nil || !strings.Contains(err.Error(), `invalid -sensitive.public entry "fakesensitive.Credential"`) {
				t.Errorf("Run() error = %v, want invalid -sensitive.public entry", err)
			}
		})
	}
}

func TestFormatAnalyzer(t *testing.T) {
	t.Parallel()
	analysistest.Run(t, analysistest.TestData(), flagAnalyzerTypes(t, "sensitivefmt", fmtTypes), "fmtcall")
}

func TestNewFormatAnalyzer(t *testing.T) {
	t.Parallel()
	runNew(t, analyzer.Config{Types: strings.Split(fmtTypes, ",")}, "sensitivefmt", "fmtcall")
}
