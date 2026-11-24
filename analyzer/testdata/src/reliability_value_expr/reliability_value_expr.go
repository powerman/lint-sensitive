package reliability_value_expr

import "fakesensitive"

// The type is never named, but a value of it is used.

func use() {
	v := fakesensitive.ValuePtrRecv() // want "does not guarantee JSON marshal safety.*MarshalJSON, MarshalText\\)" "does not guarantee text marshal safety.*MarshalText\\)" "does not guarantee format-level safety.*Format\\)" "does not guarantee GoString-level safety.*Format, GoString\\)" "does not guarantee String-level safety.*Format, String\\)"
	_ = v
}
