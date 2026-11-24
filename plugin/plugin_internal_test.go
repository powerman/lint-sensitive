package plugin

import (
	"maps"
	"reflect"
	"slices"
	"testing"

	"github.com/powerman/lint-sensitive/analyzer"
)

// TestNewMapsEverySetting verifies that each setting reaches exactly its own analyzer.Config field.
// It fails when New swaps two fields, forgets a new setting,
// or analyzer.Config gets a field which is neither exposed nor listed as not exposed.
func TestNewMapsEverySetting(t *testing.T) {
	t.Parallel()

	configField := map[string]string{
		"types":                "Types",
		"public":               "PublicFields",
		"no-default-types":     "NoDefaultTypes",
		"detect-fields":        "DetectFields",
		"require-marshal-json": "RequireMarshalJSON",
		"require-marshal-text": "RequireMarshalText",
		"require-format":       "RequireFormat",
		"require-gostring":     "RequireGoString",
		"require-string":       "RequireString",
	}
	notExposed := []string{"SkipTests", "SkipGenerated", "Debug"}

	seen := make(map[string]bool)
	for field := range reflect.TypeFor[Settings]().Fields() {
		key := field.Tag.Get("json")
		want, ok := configField[key]
		if !ok {
			t.Errorf("setting %q has no expected analyzer.Config field", key)
			continue
		}
		seen[key] = true

		var value any = true
		if field.Type.Kind() == reflect.Slice {
			value = []any{"example.com/a.T"}
		}
		lp, err := New(map[string]any{key: value})
		if err != nil {
			t.Fatalf("New(%s) error = %v", key, err)
		}
		p, ok := lp.(*plugin)
		if !ok {
			t.Fatalf("New(%s) = %T, want *plugin", key, lp)
		}
		for f, v := range reflect.ValueOf(p.cfg).Fields() {
			if set := !v.IsZero(); set != (f.Name == want) {
				t.Errorf("setting %q: Config.%s set = %v, want %v", key, f.Name, set, f.Name == want)
			}
		}
	}
	for key := range configField {
		if !seen[key] {
			t.Errorf("setting %q is not in Settings", key)
		}
	}

	exposed := slices.Collect(maps.Values(configField))
	for f := range reflect.TypeFor[analyzer.Config]().Fields() {
		if !slices.Contains(exposed, f.Name) && !slices.Contains(notExposed, f.Name) {
			t.Errorf("analyzer.Config.%s is neither a setting nor listed as not exposed", f.Name)
		}
	}
}
