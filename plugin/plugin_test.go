package plugin_test

import (
	"slices"
	"testing"

	"github.com/golangci/plugin-module-register/register"
	"golang.org/x/tools/go/analysis"
	"golang.org/x/tools/go/analysis/analysistest"

	_ "github.com/powerman/lint-sensitive/plugin"
)

func newPlugin(t *testing.T, settings any) register.LinterPlugin {
	t.Helper()

	newFn, err := register.GetPlugin("sensitive")
	if err != nil {
		t.Fatal(err)
	}
	p, err := newFn(settings)
	if err != nil {
		t.Fatal(err)
	}
	return p
}

func TestPlugin(t *testing.T) {
	t.Parallel()

	p := newPlugin(t, map[string]any{
		"types":            []any{"fakeplugin.Secret"},
		"require-gostring": true,
	})
	if got, want := p.GetLoadMode(), register.LoadModeTypesInfo; got != want {
		t.Errorf("GetLoadMode() = %q, want %q", got, want)
	}
	analyzers, err := p.BuildAnalyzers()
	if err != nil {
		t.Fatal(err)
	}
	names := make([]string, len(analyzers))
	for i, a := range analyzers {
		names[i] = a.Name
	}
	slices.Sort(names)
	if want := []string{"sensitivefields", "sensitiveprint"}; !slices.Equal(names, want) {
		t.Fatalf("analyzers = %v, want %v", names, want)
	}

	// The settings reach the analyzer: the diagnostic in plugintest needs both of them.
	i := slices.IndexFunc(analyzers, func(a *analysis.Analyzer) bool { return a.Name == "sensitivefields" })
	analysistest.Run(t, analysistest.TestData(), analyzers[i], "plugintest")
}

func TestPluginUnknownSetting(t *testing.T) {
	t.Parallel()

	newFn, err := register.GetPlugin("sensitive")
	if err != nil {
		t.Fatal(err)
	}
	_, err = newFn(map[string]any{"skip-tests": true})
	if err == nil {
		t.Error("New() with an unknown setting succeeded, want error")
	}
}
