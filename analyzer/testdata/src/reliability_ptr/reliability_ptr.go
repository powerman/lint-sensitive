package reliability_ptr

import "fakesensitive"

// *PtrRecv has all five methods, so the pointer form passes every check.
// The pointer form is also found in slices, maps, in an expression, and in &T{} and new(T).

type Check struct {
	X  *fakesensitive.PtrRecv
	Xs []*fakesensitive.PtrRecv
	M  map[string]*fakesensitive.PtrRecv
}

func use() {
	c := fakesensitive.NewPtrRecv()
	_ = c
	_ = new(fakesensitive.PtrRecv)
	_ = new(fakesensitive.ValuePtrRecv()) // Go 1.26+ new(expr): the value is held only as *T.
}
