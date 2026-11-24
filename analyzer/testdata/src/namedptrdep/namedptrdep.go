// Package namedptrdep declares a defined pointer type to a safe type
// outside of the configured packages.
package namedptrdep

import "fakesensitive"

type PT *fakesensitive.PtrRecv

func New() PT { return fakesensitive.NewPtrRecv() }
