// Command example demonstrates sensitive value leaks through fmt reflection
// and builtin print/println across all default-supported libraries and a
// custom sensitive type.
//
// Run the linter over this directory:
//
//	lint-sensitive -sensitive.types=github.com/powerman/lint-sensitive/example.Secret ./...
package main

import (
	"fmt"

	"github.com/angusgmorrison/logfusc"
	playgroundSensitive "github.com/go-playground/sensitive"
	"github.com/negrel/secrecy"
	powermanSensitive "github.com/powerman/sensitive"
)

// Secret is a project-specific sensitive string type.
type Secret string

func (s Secret) Format(f fmt.State, verb rune) { fmt.Fprint(f, "[redacted]") }

// Public is a non-sensitive type in the same package.
type Public string

// leakDemo groups all leakable types as unexported fields.
// Fields 1-5 are sensitive (caught by the linter). Field 6 is NOT sensitive
// and should NOT be flagged — demonstrating type-level granularity.
// When printed via fmt, all raw values leak because reflection on unexported
// fields bypasses Stringer/Formatter.
type leakDemo struct {
	powerman   powermanSensitive.String   // leak:
	playground playgroundSensitive.String // leak:
	secrecy    *secrecy.Secret[string]    // leak:
	logfusc    logfusc.Secret[string]     // leak:
	secret     Secret                     // leak:
	public     Public
}

func main() {
	// This shows the leak: all unexported field values are printed raw.
	fmt.Println(leakDemo{
		powerman:   "value protected by powerman/sensitive.String",
		playground: "value protected by go-playground/sensitive.String",
		secrecy:    secrecy.NewSecret("value protected by negrel/secrecy.Secret"),
		logfusc:    logfusc.NewSecret("value protected by logfusc.Secret"),
		secret:     "value protected by Secret (declared in main)",
		public:     "value protected by Public (not sensitive)",
	})

	// Builtin print/println also leak sensitive basic-kind-by-value types.
	{
		var s powermanSensitive.String = "value protected by powerman/sensitive.String"
		print(s)   // leak:
		println(s) // leak:
	}
	{
		var s playgroundSensitive.String = "value protected by go-playground/sensitive.String"
		print(s)   // leak:
		println(s) // leak:
	}
	{
		var s Secret = "value protected by Secret (declared in main)"
		print(s)   // leak:
		println(s) // leak:
	}
}
