package reliability_named_ptr_ext

import "namedptrdep"

func use() {
	_ = namedptrdep.New() // want "does not guarantee JSON marshal safety.*MarshalJSON, MarshalText\\)" "does not guarantee text marshal safety.*MarshalText\\)" "does not guarantee format-level safety.*Format\\)" "does not guarantee GoString-level safety.*Format, GoString\\)" "does not guarantee String-level safety.*Format, String\\)"
}
