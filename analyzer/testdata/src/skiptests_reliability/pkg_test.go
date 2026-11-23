package skiptests_reliability

import (
	"fakelogfusc"
	"fakesecrecy"
)

// With skip-tests the references in this file are ignored:
// fakelogfusc.Secret is used only here, so it is not reported at all,
// and fakesecrecy.Secret is reported at its use in pkg.go.
// No want comments: we only test the SkipTests:true scenario here.
type TestOnly struct {
	X fakelogfusc.Secret[string]
}

type TestShared struct {
	X fakesecrecy.Secret[string]
}
