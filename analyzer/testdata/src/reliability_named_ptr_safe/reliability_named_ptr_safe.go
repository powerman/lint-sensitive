package reliability_named_ptr_safe

import "fakesensitive"

// A configured safe type which is a defined pointer type is checked itself,
// and so is its element type, which fmt prints through it.

func use() {
	_ = fakesensitive.NewDefinedPtr() // want "DefinedPtr does not guarantee JSON marshal safety" "DefinedPtr does not guarantee text marshal safety" "PtrRecv does not guarantee JSON marshal safety.*MarshalJSON, MarshalText\\)" "PtrRecv does not guarantee text marshal safety.*MarshalText\\)" "PtrRecv does not guarantee format-level safety.*Format\\)" "PtrRecv does not guarantee GoString-level safety.*Format, GoString\\)" "PtrRecv does not guarantee String-level safety.*Format, String\\)"
}
