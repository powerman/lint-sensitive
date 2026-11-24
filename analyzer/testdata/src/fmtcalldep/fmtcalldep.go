// Package fmtcalldep has a printf wrapper which fmtcall calls.
package fmtcalldep

import "fmt"

// Logf is a printf wrapper, which printf.Analyzer exports as a fact.
func Logf(format string, args ...any) {
	fmt.Printf(format, args...)
}
