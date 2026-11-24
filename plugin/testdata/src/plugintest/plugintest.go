package plugintest

import "fakeplugin"

// The diagnostics need all three settings:
// types makes fakeplugin.Secret a safe type,
// require-gostring makes it fail the check,
// and detect-fields enables the declaration check.
type holder struct {
	Secret fakeplugin.Secret // want "configured safe type fakeplugin.Secret does not guarantee GoString-level safety"
	secret fakeplugin.Secret // want "is reachable through an unexported field"
}
