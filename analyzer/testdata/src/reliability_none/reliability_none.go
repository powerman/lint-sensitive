package reliability_none

import (
	"fakelogfusc"
	"fakesecrecy"
	"fakesensitive"
)

// All fields are EXPORTED, so the field walk produces no diagnostics.
// Without reliability flags, no reliability diagnostics are produced either.

type CheckAll struct {
	S  fakesensitive.String
	Se fakesecrecy.Secret[string]
	L  fakelogfusc.Secret[string]
	R  fakesensitive.Ref[string]
}
