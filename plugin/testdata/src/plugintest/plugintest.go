package plugintest

import "fakeplugin"

// The diagnostic needs both settings:
// types makes fakeplugin.Secret a safe type, and require-gostring makes it fail the check.
type holder struct {
	Secret fakeplugin.Secret // want "configured safe type fakeplugin.Secret does not guarantee GoString-level safety"
}
