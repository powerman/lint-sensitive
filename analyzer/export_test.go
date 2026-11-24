package analyzer //nolint:testpackage // Must be in package analyzer to reach the unexported table.

// The fake test type has no real import path, but it emulates a known type with a revealing method.
func init() { revealingMethods["fakeconceal.Text"] = []string{methodMarshalText} }
