package public_on

import "fakesensitive"

// Credential.ID is declared public, so the type is structurally protected and opaque.
type holder struct {
	c fakesensitive.Credential
}
