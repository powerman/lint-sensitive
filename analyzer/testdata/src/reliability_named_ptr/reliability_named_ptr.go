package reliability_named_ptr

import "fakesensitive"

// A defined pointer type has no methods,
// so fmt does not call the methods of *T through it: T is checked by its own method set.
type PT *fakesensitive.PtrRecv // want "does not guarantee JSON marshal safety.*MarshalJSON, MarshalText\\)" "does not guarantee text marshal safety.*MarshalText\\)" "does not guarantee format-level safety.*Format\\)" "does not guarantee GoString-level safety.*Format, GoString\\)" "does not guarantee String-level safety.*Format, String\\)"
