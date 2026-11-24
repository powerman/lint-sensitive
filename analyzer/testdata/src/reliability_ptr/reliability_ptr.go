package reliability_ptr

import "fakesensitive"

// *PtrRecv has all five methods, so the pointer form passes every check.
// The pointer form is also found in slices, maps and in an expression.

type Check struct {
	X  *fakesensitive.PtrRecv
	Xs []*fakesensitive.PtrRecv
	M  map[string]*fakesensitive.PtrRecv
}

func use() {
	c := fakesensitive.NewPtrRecv()
	_ = c
}
