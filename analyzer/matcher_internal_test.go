package analyzer

import (
	"go/token"
	"reflect"
	"testing"

	"golang.org/x/tools/go/analysis"
)

func TestNewMatcherDefaults(t *testing.T) {
	t.Parallel()
	m := newMatcher(Config{})
	for _, p := range defaultTypes {
		if !m.packages[p] {
			t.Errorf("default package %s missing from matcher.packages", p)
		}
	}
	if len(m.types) != 0 {
		t.Errorf("expected empty matcher.types from defaults alone, got %d entries", len(m.types))
	}
}

func TestNewMatcherNoDefaults(t *testing.T) {
	t.Parallel()
	m := newMatcher(Config{NoDefaultTypes: true})
	if len(m.packages) != 0 {
		t.Errorf("expected no packages with NoDefaultTypes, got %d", len(m.packages))
	}
	if len(m.types) != 0 {
		t.Errorf("expected no types with NoDefaultTypes, got %d", len(m.types))
	}
}

func TestNewMatcherCustomTypes(t *testing.T) {
	t.Parallel()
	m := newMatcher(Config{Types: []string{"my/pkg", "other/lib.Secret"}})
	if !m.packages[defaultTypes[0]] {
		t.Error("defaults lost after merge")
	}
	if !m.packages["my/pkg"] {
		t.Error("my/pkg not in packages after merge")
	}
	if !m.types[packageType{Pkg: "other/lib", Name: "Secret"}] {
		t.Error("other/lib.Secret not in types after merge")
	}
}

func TestNewMatcherNoDefaultsWithCustom(t *testing.T) {
	t.Parallel()
	m := newMatcher(Config{NoDefaultTypes: true, Types: []string{"my/pkg"}})
	if len(m.packages) != 1 {
		t.Errorf("expected 1 package, got %d", len(m.packages))
	}
	if !m.packages["my/pkg"] {
		t.Error("my/pkg not found")
	}
}

func TestNewMatcherOverlap(t *testing.T) {
	t.Parallel()
	m := newMatcher(Config{Types: []string{defaultTypes[0]}})
	if len(m.packages) != len(defaultTypes) {
		t.Errorf("overlap with defaults grew the set: got %d packages, want %d",
			len(m.packages), len(defaultTypes))
	}
	if len(m.types) != 0 {
		t.Errorf("expected empty types, got %d entries", len(m.types))
	}
}

func TestAddEntryPackage(t *testing.T) {
	t.Parallel()
	m := newMatcher(Config{NoDefaultTypes: true})
	m.addEntry("github.com/foo")
	if !m.packages["github.com/foo"] {
		t.Error("package not in matcher.packages")
	}
	if len(m.types) != 0 {
		t.Error("package entry should not create type entries")
	}
}

func TestAddEntryType(t *testing.T) {
	t.Parallel()
	m := newMatcher(Config{NoDefaultTypes: true})
	m.addEntry("github.com/foo.Secret")
	if !m.types[packageType{Pkg: "github.com/foo", Name: "Secret"}] {
		t.Error("type not in matcher.types")
	}
	if len(m.packages) != 0 {
		t.Error("type entry should not create package entries")
	}
}

func TestAddEntryPackageTypeSyntax(t *testing.T) {
	t.Parallel()
	tests := []struct {
		entry   string
		wantPkg string // empty = no package entry expected
		wantT   packageType
		isPkg   bool
		isType  bool
	}{
		{entry: "github.com/foo", wantPkg: "github.com/foo", isPkg: true},
		{entry: "github.com/foo.String", wantT: packageType{Pkg: "github.com/foo", Name: "String"}, isType: true},
		{entry: "github.com/foo/v2", wantPkg: "github.com/foo/v2", isPkg: true},
		{entry: "github.com/foo/v2.Secret", wantT: packageType{Pkg: "github.com/foo/v2", Name: "Secret"}, isType: true},
		{entry: "my/pkg.lower", wantPkg: "my/pkg.lower", isPkg: true},
		{entry: "my/pkg.Secret", wantT: packageType{Pkg: "my/pkg", Name: "Secret"}, isType: true},
		{entry: "my/pkg.START", wantT: packageType{Pkg: "my/pkg", Name: "START"}, isType: true},
		{entry: "my/pkg._Secret", wantPkg: "my/pkg._Secret", isPkg: true}, // underscore not upper
		{entry: "Secret", wantPkg: "Secret", isPkg: true},                 // no slash, single word, lowercase = pkg
		{entry: "Secret.Type", wantT: packageType{Pkg: "Secret", Name: "Type"}, isType: true},
	}

	for _, tt := range tests {
		t.Run(tt.entry, func(t *testing.T) {
			t.Parallel()
			m := newMatcher(Config{Types: []string{tt.entry}})
			if tt.isPkg && !m.packages[tt.wantPkg] {
				t.Errorf("expected package %s in matcher.packages", tt.wantPkg)
			}
			if tt.isType && !m.types[tt.wantT] {
				t.Errorf("expected type %v in matcher.types", tt.wantT)
			}
		})
	}
}

func TestInTestFile(t *testing.T) {
	t.Parallel()
	fset := token.NewFileSet()
	_ = fset.AddFile("/path/to/foo.go", -1, 100)
	_ = fset.AddFile("/path/to/foo_test.go", -1, 100)

	// Find the test file by iterating through the fileset.
	var testFilePos token.Pos
	fset.Iterate(func(f *token.File) bool {
		if f.Name() == "/path/to/foo_test.go" {
			testFilePos = f.Pos(0)
			return false
		}
		return true
	})

	// Find the non-test file.
	var plainFilePos token.Pos
	fset.Iterate(func(f *token.File) bool {
		if f.Name() == "/path/to/foo.go" {
			plainFilePos = f.Pos(0)
			return false
		}
		return true
	})

	pass := &analysis.Pass{Fset: fset}

	if inTestFile(pass, plainFilePos) {
		t.Error("foo.go should not be reported as a test file")
	}
	if !inTestFile(pass, testFilePos) {
		t.Error("foo_test.go should be reported as a test file")
	}

	// Test with nil position (fileset lookup returns nil).
	// A position beyond all files should map to nil File.
	if inTestFile(pass, token.Pos(0)) {
		t.Error("pos 0 should not be in any file")
	}
}

func TestSplitCSV(t *testing.T) {
	t.Parallel()
	tests := []struct {
		input string
		want  []string
	}{
		{input: "", want: nil},
		{input: "pkg.A,pkg.B", want: []string{"pkg.A", "pkg.B"}},
		{input: "  pkg.A,  pkg.B  ", want: []string{"pkg.A", "pkg.B"}},
		{input: ",pkg.A,,pkg.B,", want: []string{"pkg.A", "pkg.B"}},
		{input: "single", want: []string{"single"}},
	}

	for _, tt := range tests {
		t.Run(tt.input, func(t *testing.T) {
			t.Parallel()
			got := splitCSV(tt.input)
			if !reflect.DeepEqual(got, tt.want) {
				t.Errorf("splitCSV(%q) = %v, want %v", tt.input, got, tt.want)
			}
		})
	}
}
