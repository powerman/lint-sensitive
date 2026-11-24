package analyzer //nolint:testpackage // Must be in package analyzer to reach the unexported tables.

// The fake test types have no real import path, but they emulate known types.
func init() {
	revealingMethods["fakeconceal.Text"] = []string{methodMarshalText}
	nonSecretFields["fakecamo.Secret"] = []string{"hash"}
	nonSecretFields["example.com/testcamo.Missing"] = []string{"nosuch"}
	nonSecretFields["example.com/testcamo.Secret"] = []string{"hash"}
}
