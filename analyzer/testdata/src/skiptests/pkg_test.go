package skiptests

import "fakesensitive"

// TestLeak is a struct in a _test.go file.
// Without skip-tests this would be flagged, but with skip-tests enabled
// diagnostics from _test.go files are suppressed.
// No want comment: we only test the SkipTests:true scenario here.
type TestLeak struct {
	x fakesensitive.String
}
