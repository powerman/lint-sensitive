package analyzer

import (
	"bytes"
	"go/token"
	"go/types"
	"log"
	"os"
	"reflect"
	"strings"
	"sync"
	"testing"

	"golang.org/x/tools/go/analysis"
)

// wantDefaultPackages and wantDefaultTypes are the expected classification of
// defaultTypes into package-only and type-qualified entries. They are spelled out
// independently of addEntry (rather than re-deriving them with the same parse rule)
// so the tests can catch a misclassified or malformed default entry.
// Keep in sync with defaultTypes in analyzer.go; the guard in TestNewMatcherDefaults
// fails if a default is added or removed without updating these.
var (
	wantDefaultPackages = []string{
		"github.com/powerman/sensitive",
		"github.com/go-playground/sensitive",
	}
	wantDefaultTypes = []packageType{
		{Pkg: "github.com/negrel/secrecy", Name: "Secret"},
		{Pkg: "github.com/angusgmorrison/logfusc", Name: "Secret"},
	}
)

func TestNewMatcherDefaults(t *testing.T) {
	t.Parallel()

	if len(wantDefaultPackages)+len(wantDefaultTypes) != len(defaultTypes) {
		t.Fatalf("test expectations out of sync with defaultTypes (%d entries): "+
			"update wantDefaultPackages/wantDefaultTypes", len(defaultTypes))
	}

	m := newMatcher(Config{})

	if len(m.packages) != len(wantDefaultPackages) {
		t.Errorf("got %d packages, want %d", len(m.packages), len(wantDefaultPackages))
	}
	if len(m.types) != len(wantDefaultTypes) {
		t.Errorf("got %d types, want %d", len(m.types), len(wantDefaultTypes))
	}

	for _, p := range wantDefaultPackages {
		if !m.packages[p] {
			t.Errorf("default package %q missing from matcher.packages", p)
		}
	}
	for _, pt := range wantDefaultTypes {
		if !m.types[pt] {
			t.Errorf("default type %q missing from matcher.types", pt.Pkg+"."+pt.Name)
		}
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

	// defaultTypes[0] is a package-only entry already in defaults.
	// Adding it again should not change the set at all.
	if len(m.packages) != len(wantDefaultPackages) {
		t.Errorf("overlap with defaults grew the set: got %d packages, want %d",
			len(m.packages), len(wantDefaultPackages))
	}
	if len(m.types) != len(wantDefaultTypes) {
		t.Errorf("overlap with defaults grew the set: got %d types, want %d",
			len(m.types), len(wantDefaultTypes))
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

func TestIsSensitiveNamed(t *testing.T) {
	t.Parallel()

	pkg := types.NewPackage("example.com/secret", "secret")
	obj := types.NewTypeName(token.NoPos, pkg, "Data", nil)
	namedType := types.NewNamed(obj, types.Typ[types.String], nil)

	objOther := types.NewTypeName(
		token.NoPos,
		types.NewPackage("example.com/other", "other"),
		"Other", nil,
	)
	otherType := types.NewNamed(objOther, types.Typ[types.String], nil)

	// Predeclared error type from universe scope has nil Obj().Pkg().
	errorType := types.Universe.Lookup("error").Type()

	// Interface type from the same package.
	iface := types.NewInterfaceType(nil, nil)
	iface.Complete()
	ifaceNamed := types.NewNamed(
		types.NewTypeName(token.NoPos, pkg, "Interface", nil),
		iface,
		nil,
	)

	// Unexported type from the same package.
	unexportedNamed := types.NewNamed(
		types.NewTypeName(token.NoPos, pkg, "unexported", nil),
		types.NewSlice(types.Typ[types.Int]),
		nil,
	)

	tests := []struct {
		name string
		m    matcher
		typ  types.Type
		want bool
	}{
		{
			name: "nil_pkg",
			m:    newMatcher(Config{NoDefaultTypes: true}),
			typ:  errorType,
			want: false,
		},
		{
			name: "non_matching_package",
			m:    newMatcher(Config{NoDefaultTypes: true, Types: []string{"example.com/secret"}}),
			typ:  otherType,
			want: false,
		},
		{
			name: "matching_package",
			m:    newMatcher(Config{NoDefaultTypes: true, Types: []string{"example.com/secret"}}),
			typ:  namedType,
			want: true,
		},
		{
			name: "matching_type_name",
			m:    newMatcher(Config{NoDefaultTypes: true, Types: []string{"example.com/secret.Data"}}),
			typ:  namedType,
			want: true,
		},
		{
			name: "interface_from_package_entry",
			m:    newMatcher(Config{NoDefaultTypes: true, Types: []string{"example.com/secret"}}),
			typ:  ifaceNamed,
			want: false,
		},
		{
			name: "interface_from_explicit_type_entry",
			m:    newMatcher(Config{NoDefaultTypes: true, Types: []string{"example.com/secret.Interface"}}),
			typ:  ifaceNamed,
			want: true,
		},
		{
			name: "unexported_type_from_package_entry",
			m:    newMatcher(Config{NoDefaultTypes: true, Types: []string{"example.com/secret"}}),
			typ:  unexportedNamed,
			want: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			got := tt.m.isSensitiveNamed(tt.typ)
			if got != tt.want {
				t.Errorf("isSensitiveNamed(%v) = %v, want %v", tt.typ, got, tt.want)
			}
		})
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

// TestIsQualifier covers all qualifier and non-qualifier kinds.
func TestIsQualifier(t *testing.T) {
	t.Parallel()

	pkg := types.NewPackage("test", "test")

	// Construct named types used for named-wrapper-over-qualifier tests.
	namedPtr := types.NewNamed(
		types.NewTypeName(token.NoPos, pkg, "Np", nil),
		types.NewPointer(types.Typ[types.Int]),
		nil,
	)
	iface := types.NewInterfaceType(nil, nil)
	namedIface := types.NewNamed(
		types.NewTypeName(token.NoPos, pkg, "Ni", nil),
		iface,
		nil,
	)
	iface.Complete()
	namedFunc := types.NewNamed(
		types.NewTypeName(token.NoPos, pkg, "Nf", nil),
		types.NewSignatureType(nil, nil, nil, nil, nil, false),
		nil,
	)
	namedChan := types.NewNamed(
		types.NewTypeName(token.NoPos, pkg, "Nc", nil),
		types.NewChan(types.SendRecv, types.Typ[types.Int]),
		nil,
	)
	namedUnsafePtr := types.NewNamed(
		types.NewTypeName(token.NoPos, pkg, "Nup", nil),
		types.Typ[types.UnsafePointer],
		nil,
	)
	namedStruct := types.NewNamed(
		types.NewTypeName(token.NoPos, pkg, "Ns", nil),
		types.NewStruct(nil, nil),
		nil,
	)

	// Empty interface type for *interface{} test.
	emptyIface := types.NewInterfaceType(nil, nil)
	emptyIface.Complete()

	tests := []struct {
		name string
		typ  types.Type
		want bool
		plan string
	}{
		// Qualifiers
		{name: "**T", typ: types.NewPointer(types.NewPointer(types.Typ[types.String])), want: true, plan: "*Pointer→*Pointer"},
		{name: "*interface{}", typ: types.NewPointer(emptyIface), want: true, plan: "*Pointer→*Interface"},
		{name: "*string", typ: types.NewPointer(types.Typ[types.String]), want: true, plan: "*Pointer→*Basic"},
		{name: "*int", typ: types.NewPointer(types.Typ[types.Int]), want: true, plan: "*Pointer→*Basic"},
		{name: "*bool", typ: types.NewPointer(types.Typ[types.Bool]), want: true, plan: "*Pointer→*Basic"},
		{name: "chan T", typ: types.NewChan(types.SendRecv, types.Typ[types.String]), want: true, plan: "Chan"},
		{name: "func()", typ: types.NewSignatureType(nil, nil, nil, nil, nil, false), want: true, plan: "Signature"},
		{name: "unsafe.Pointer", typ: types.Typ[types.UnsafePointer], want: true, plan: "UnsafePointer"},
		// Named wrapper over qualifier (*Pointer→*Named→qualifier-underlying)
		{name: "*Np (underlying *int)", typ: types.NewPointer(namedPtr), want: true, plan: "*Pointer→*Named→*Pointer"},
		{name: "*Ni (underlying *interface{})", typ: types.NewPointer(namedIface), want: true, plan: "*Pointer→*Named→*Interface"},
		{name: "*Nf (underlying func())", typ: types.NewPointer(namedFunc), want: true, plan: "*Pointer→*Named→*Signature"},
		{name: "*Nc (underlying chan int)", typ: types.NewPointer(namedChan), want: true, plan: "*Pointer→*Named→*Chan"},
		{name: "*Nup (underlying unsafe.Pointer)", typ: types.NewPointer(namedUnsafePtr), want: true, plan: "*Pointer→*Named→*UnsafePointer"},
		// Non-qualifiers
		{name: "*[]byte (compound)", typ: types.NewPointer(types.NewSlice(types.Typ[types.Uint8])), want: false, plan: "*Pointer→*<compound> — *[]byte is NOT a qualifier"},
		{name: "*struct{} (compound)", typ: types.NewPointer(types.NewStruct(nil, nil)), want: false, plan: "*Pointer→*<compound>"},
		{name: "*[]int (compound)", typ: types.NewPointer(types.NewSlice(types.Typ[types.Int])), want: false, plan: "*Pointer→*<compound>"},
		{name: "*map[int]int (compound)", typ: types.NewPointer(types.NewMap(types.Typ[types.Int], types.Typ[types.Int])), want: false, plan: "*Pointer→*<compound>"},
		{name: "struct{} (not a pointer)", typ: types.NewStruct(nil, nil), want: false, plan: "non-pointer → false (default)"},
		{name: "*Ns (underlying struct{})", typ: types.NewPointer(namedStruct), want: false, plan: "*Pointer→*Named→default (underlying struct) — named wrapper over non-qualifier"},
	}

	m := newMatcher(Config{NoDefaultTypes: true})
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			got := m.isQualifier(tt.typ)
			if got != tt.want {
				t.Errorf("isQualifier(%v) = %v, want %v (plan: %s)", tt.typ, got, tt.want, tt.plan)
			}
		})
	}
}

// TestIsStructurallySafe covers the isStructurallySafe function cases.
func TestIsStructurallySafe(t *testing.T) {
	t.Parallel()

	pkg := types.NewPackage("test", "test")

	// Named struct with qualifier: type R struct{ pp **int }
	namedStructQual := types.NewNamed(
		types.NewTypeName(token.NoPos, pkg, "R", nil),
		types.NewStruct(
			[]*types.Var{
				types.NewField(token.NoPos, pkg, "pp", types.NewPointer(types.NewPointer(types.Typ[types.Int])), false),
			},
			nil,
		),
		nil,
	)

	// Wrapper type for named-wrapper recursion (Handle[string] shape):
	// type Inner struct{ value *int }
	innerNamed := types.NewNamed(
		types.NewTypeName(token.NoPos, pkg, "Inner", nil),
		types.NewStruct(
			[]*types.Var{
				types.NewField(token.NoPos, pkg, "value", types.NewPointer(types.Typ[types.Int]), false),
			},
			nil,
		),
		nil,
	)

	// Recursive type cycle: type Node struct{ self Node; p **int }
	// Must use SetUnderlying after creation because the struct references Node itself.
	nodeNamed := types.NewNamed(
		types.NewTypeName(token.NoPos, pkg, "Node", nil),
		nil, nil,
	)
	nodeStruct := types.NewStruct(
		[]*types.Var{
			types.NewField(token.NoPos, pkg, "self", nodeNamed, false),
			types.NewField(token.NoPos, pkg, "p", types.NewPointer(types.NewPointer(types.Typ[types.Int])), false),
		},
		nil,
	)
	nodeNamed.SetUnderlying(nodeStruct)

	m := newMatcher(Config{NoDefaultTypes: true})
	tests := []struct {
		name string
		typ  types.Type
		want bool
		plan string
	}{
		{
			name: "plain_struct_with_qualifier",
			typ: types.NewStruct(
				[]*types.Var{
					types.NewField(token.NoPos, pkg, "p", types.NewPointer(types.NewPointer(types.Typ[types.Int])), false),
				},
				nil,
			),
			want: true,
			plan: "struct field **int is a qualifier → true",
		},
		{
			name: "plain_struct_only_non_qualifier",
			typ: types.NewStruct(
				[]*types.Var{
					types.NewField(token.NoPos, pkg, "s", types.NewSlice(types.Typ[types.Int]), false),
				},
				nil,
			),
			want: false,
			plan: "struct field []int is NOT a qualifier → false",
		},
		{
			name: "named_struct_with_qualifier",
			typ:  namedStructQual,
			want: true,
			plan: "named struct (*types.Named case) → recurse into underlying → qualifier field → true",
		},
		{
			name: "named_wrapper_recursion_handle_shape",
			typ: types.NewStruct(
				[]*types.Var{
					types.NewField(token.NoPos, pkg, "h", innerNamed, false),
				},
				nil,
			),
			want: true,
			plan: "struct field is named wrapper Inner with *int qualifier inside → recurse through named field → true (Handle[string] shape)",
		},
		{
			name: "recursive_type_cycle",
			typ:  nodeNamed,
			want: true,
			plan: "named with self-referencing struct field → visited cycle-break prevents infinite loop → true via **int qualifier",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			visited := make(map[types.Type]bool)
			got := m.isStructurallySafe(tt.typ, visited)
			if got != tt.want {
				t.Errorf("isStructurallySafe(%v) = %v, want %v (plan: %s)", tt.typ, got, tt.want, tt.plan)
			}
		})
	}
}

// TestDebugFlag verifies that -sensitive.debug outputs classification details
// when enabled and produces no output when disabled.
func TestDebugFlag(t *testing.T) {
	t.Parallel()

	testPkg := types.NewPackage("example.com/secret", "secret")
	named := types.NewNamed(
		types.NewTypeName(token.NoPos, testPkg, "Secret", nil),
		types.NewStruct(nil, nil),
		nil,
	)
	// Add a Format method so classify sets fmtFormatter = true.
	recv := types.NewVar(token.NoPos, testPkg, "", named)
	params := types.NewTuple(
		types.NewVar(token.NoPos, nil, "s", types.Typ[types.Uintptr]),
		types.NewVar(token.NoPos, nil, "v", types.Typ[types.Rune]),
	)
	formatFunc := types.NewFunc(
		token.NoPos, testPkg, "Format",
		types.NewSignatureType(recv, nil, nil, params, nil, false),
	)
	named.AddMethod(formatFunc)

	// Verify classification output appears when debug flag is enabled.
	var bufTrue bytes.Buffer
	log.SetOutput(&bufTrue)
	mTrue := newMatcher(Config{Debug: true, Types: []string{"example.com/secret.Secret"}})
	mTrue.classify(named)
	log.SetOutput(os.Stderr)

	output := bufTrue.String()
	if output == "" {
		t.Fatal("debug output expected when debug=true but got empty")
	}
	for _, want := range []string{
		"sensitive type",
		"example.com/secret.Secret",
		"Formatter=true",
		"Stringer=",
		"GoStringer=",
		"json.Marshaler=",
		"encoding.TextMarshaler=",
		"structurallySafe=",
	} {
		if !strings.Contains(output, want) {
			t.Errorf("debug output should contain %q, got:\n%s", want, output)
		}
	}

	// Verify no output appears when debug flag is disabled.
	var bufFalse bytes.Buffer
	log.SetOutput(&bufFalse)
	mFalse := newMatcher(Config{Debug: false, Types: []string{"example.com/secret.Secret"}})
	mFalse.classify(named)
	log.SetOutput(os.Stderr)

	if bufFalse.Len() > 0 {
		t.Errorf("expected no debug output when debug=false, got:\n%s", bufFalse.String())
	}

	// typeArgsString remains uncovered because there is no public go/types API
	// to set TypeArgs on a *types.Named programmatically (SetTypeArgs does not
	// exist, and TypeList has no public constructor). Covering this function
	// would require the full type-checker and a generic source file, which is
	// impractical for a unit test.
}

// TestDebugDedup verifies that classify prints at most one debug line per
// logical type, even when called with different *types.Named objects
// representing the same type (which happens when the same type is analyzed
// in different packages, each with its own *types.Named pointer).
// Not parallel — clears global debugPrinted state.
//
//nolint:paralleltest // Uses global state, cannot run in parallel.
func TestDebugDedup(t *testing.T) {
	// Clear global dedup state from any previous test run.
	debugPrinted = sync.Map{}

	testPkg := types.NewPackage("example.com/testdedup", "testdedup")

	// Create a named type to classify.
	named := types.NewNamed(
		types.NewTypeName(token.NoPos, testPkg, "MyType", nil),
		types.NewStruct(nil, nil),
		nil,
	)
	recv := types.NewVar(token.NoPos, testPkg, "", named)
	named.AddMethod(types.NewFunc(
		token.NoPos, testPkg, "Format",
		types.NewSignatureType(recv, nil, nil,
			types.NewTuple(
				types.NewVar(token.NoPos, nil, "s", types.Typ[types.Uintptr]),
				types.NewVar(token.NoPos, nil, "v", types.Typ[types.Rune]),
			), nil, false,
		),
	))

	// Create a second *types.Named with the same package and type name
	// (simulating the same type from a different package's type-checker).
	namedOther := types.NewNamed(
		types.NewTypeName(token.NoPos, testPkg, "MyType", nil),
		types.NewStruct(nil, nil),
		nil,
	)
	recvOther := types.NewVar(token.NoPos, testPkg, "", namedOther)
	namedOther.AddMethod(types.NewFunc(
		token.NoPos, testPkg, "Format",
		types.NewSignatureType(recvOther, nil, nil,
			types.NewTuple(
				types.NewVar(token.NoPos, nil, "s", types.Typ[types.Uintptr]),
				types.NewVar(token.NoPos, nil, "v", types.Typ[types.Rune]),
			), nil, false,
		),
	))

	// Collect debug output from two classify calls with different *types.Named.
	var buf bytes.Buffer
	log.SetOutput(&buf)
	m := newMatcher(Config{Debug: true, Types: []string{"example.com/testdedup.MyType"}})

	tc1 := m.classify(named)
	tc2 := m.classify(namedOther)

	log.SetOutput(os.Stderr)

	// Verify both calls returned correct classification.
	for i, tc := range []*typeClass{tc1, tc2} {
		if !tc.fmtFormatter {
			t.Errorf("classify call %d: expected Formatter=true, got false", i+1)
		}
	}

	// Verify only one debug line was printed, not two.
	output := strings.TrimSpace(buf.String())
	lines := strings.Split(output, "\n")
	var debugLines int
	for _, line := range lines {
		if strings.Contains(line, "sensitive type") {
			debugLines++
		}
	}
	if debugLines != 1 {
		t.Errorf("expected exactly 1 debug line, got %d\nfull output:\n%s", debugLines, output)
	}
}
