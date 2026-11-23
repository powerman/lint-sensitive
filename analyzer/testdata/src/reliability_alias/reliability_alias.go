package reliability_alias

import "fakealias"

// The safe type is referenced only through an alias declared in another package.
type CheckAlias struct {
	X fakealias.Secret // want "configured safe type fakesecrecy.Secret does not guarantee format-level safety"
}
