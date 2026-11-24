package analyzer //nolint:testpackage // Must be in package analyzer to reach the unexported tables.

// The fake test types have no real import path, but they emulate known types.
func init() {
	revealingMethods["fakeconceal.Text"] = []string{methodMarshalText}
	revealingMethods["fakesensitive.RevealingString"] = []string{methodString}
	publicFields["fakecamo.Secret"] = []string{"hash"}
	publicFields["example.com/testcamo.Missing"] = []string{"nosuch"}
	publicFields["example.com/testcamo.Secret"] = []string{"hash"}
}
