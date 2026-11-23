package skipgen_reliability

import "fakesecrecy"

type Shared struct {
	X fakesecrecy.Secret[string] // want "configured safe type fakesecrecy.Secret does not guarantee JSON marshal safety"
}
