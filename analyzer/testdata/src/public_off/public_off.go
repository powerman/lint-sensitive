package public_off

import "fakesensitive"

// Credential.ID is not declared public, so the type is not structurally protected
// (disabling its String method leaks ID and the secret field)
// and it is not an opaque struct (encoding/json writes the exported ID).
// The marshal diagnostics are reported once per type, at its first use.
type holder struct {
	c fakesensitive.Credential // want "is reachable through an unexported field" "does not guarantee JSON marshal safety" "does not guarantee text marshal safety"
}
