package reliability_ptr_mixed

import "fakesensitive"

// A value form of the type makes it checked by the method set of T,
// whatever form is used first.

type Check struct {
	X *fakesensitive.PtrRecv
	Y fakesensitive.PtrRecv // want "does not guarantee JSON marshal safety.*MarshalJSON, MarshalText\\)" "does not guarantee text marshal safety.*MarshalText\\)" "does not guarantee format-level safety.*Format\\)" "does not guarantee GoString-level safety.*Format, GoString\\)" "does not guarantee String-level safety.*Format, String\\)"
}
