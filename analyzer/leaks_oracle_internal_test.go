package analyzer

import (
	"encoding/hex"
	"errors"
	"fmt"
	"go/token"
	"go/types"
	"regexp"
	"strings"
	"sync"
	"testing"

	"golang.org/x/tools/go/packages"

	"github.com/powerman/lint-sensitive/analyzer/testdata/oracle"
)

const oraclePkg = "github.com/powerman/lint-sensitive/analyzer/testdata/oracle"

// oracleVerbs are the verbs which the oracle prints every shape with.
var oracleVerbs = []fmtVerb{ // Const.
	{'v', false},
	{'v', true},
	{'s', false},
	{'q', false},
	{'x', false},
	{'X', false},
	{'d', false},
	{'p', false},
	{'T', false},
	{'y', false},
	{'t', false},
	{'c', false},
	{'U', false},
	{'e', false},
	{'f', false},
	{'b', false},
	{'o', false},
	{'w', false},
}

// pathPrefix is the part of a package path which reflect prints but go/types does not.
var pathPrefix = regexp.MustCompile(`[\w.\-]+/`)

// loadOracle type-checks the oracle package from source, once for all tests.
var loadOracle = sync.OnceValues(func() (*types.Package, error) {
	cfg := &packages.Config{Mode: packages.NeedName | packages.NeedTypes | packages.NeedImports |
		packages.NeedDeps | packages.NeedSyntax | packages.NeedTypesInfo}
	pkgs, err := packages.Load(cfg, oraclePkg)
	if err != nil {
		return nil, fmt.Errorf("load %s: %w", oraclePkg, err)
	}
	if packages.PrintErrors(pkgs) > 0 || len(pkgs) != 1 {
		return nil, fmt.Errorf("load %s: %w", oraclePkg, errOracleLoad)
	}
	return pkgs[0].Types, nil
})

var errOracleLoad = errors.New("oracle package has errors")

// oracleShapes returns every shape of every safe type.
func oracleShapes() []oracle.Shape {
	var res []oracle.Shape
	res = append(res, oracle.Shapes[oracle.Str]("Str")...)
	res = append(res, oracle.Shapes[oracle.StrFmt]("StrFmt")...)
	res = append(res, oracle.Shapes[oracle.StrGo]("StrGo")...)
	res = append(res, oracle.Shapes[oracle.StrPtr]("StrPtr")...)
	res = append(res, oracle.Shapes[oracle.StrAll]("StrAll")...)
	res = append(res, oracle.Shapes[oracle.Box]("Box")...)
	res = append(res, oracle.Shapes[oracle.Plain]("Plain")...)
	res = append(res, oracle.Shapes[oracle.PlainBox]("PlainBox")...)
	return append(res, oracle.EmbShapes()...)
}

// printedLeak reports whether fmt printed the secret of the oracle, raw or hex-encoded.
func printedLeak(out string) bool {
	secret := oracle.Secret
	return strings.Contains(out, secret) ||
		strings.Contains(out, hex.EncodeToString([]byte(secret))) ||
		strings.Contains(out, strings.ToUpper(hex.EncodeToString([]byte(secret))))
}

// oraclePrint prints v with the verb the way fmt does it for an operation of Printf or Errorf.
func oraclePrint(v any, verb fmtVerb) string {
	format := "%"
	if verb.sharp {
		format += "#"
	}
	format += string(verb.verb)
	if verb.verb == 'w' {
		return fmt.Errorf(format, v).Error() //nolint:err113 // The oracle prints, not wraps.
	}
	return fmt.Sprintf(format, v)
}

// TestLeaksAsArgMatchesFmt checks the leak decision of leaksAsArg against real fmt:
// every shape printed with every verb must leak in the analyzer if and only if it leaks in fmt.
func TestLeaksAsArgMatchesFmt(t *testing.T) {
	t.Parallel()

	pkg, err := loadOracle()
	if err != nil {
		t.Fatal(err)
	}
	cfg := Config{NoDefaultTypes: true}
	for _, name := range oracle.SafeNames {
		cfg.Types = append(cfg.Types, oraclePkg+"."+name)
	}
	c := newChecker(newMatcher(cfg))

	var mismatches, total int
	for _, shape := range oracleShapes() {
		tv, err := types.Eval(token.NewFileSet(), pkg, token.NoPos, shape.Type)
		if err != nil {
			t.Fatalf("shape %s: type %q: %v", shape.Name, shape.Type, err)
		}
		got := pathPrefix.ReplaceAllString(fmt.Sprintf("%T", shape.Value), "")
		if want := shortTypeString(tv.Type); got != want {
			t.Fatalf("shape %s: the value has type %s, the source type is %s", shape.Name, got, want)
		}

		for _, verb := range oracleVerbs {
			var path []walkStep
			want := printedLeak(oraclePrint(shape.Value, verb))
			got, _ := c.leaksAsArg(tv.Type, verb, &path)
			total++
			if got != want {
				mismatches++
				t.Errorf("%s with %%%s%c: analyzer says leak=%v, fmt printed %q",
					shape.Name, map[bool]string{true: "#", false: ""}[verb.sharp], verb.verb, got,
					oraclePrint(shape.Value, verb))
			}
		}
	}
	t.Logf("%d shape x verb combinations, %d mismatches", total, mismatches)
}
