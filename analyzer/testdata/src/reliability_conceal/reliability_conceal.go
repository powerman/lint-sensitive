package reliability_conceal

import (
	"fakeconceal"
	"fakesensitive"
)

// The types are used only as pointers, so *T has String and GoString:
// there are no String-level and GoString-level diagnostics.
// Both types are opaque structs, so JSON and text marshal diagnostics
// come only from the revealing MarshalText of *Text.

type Check struct {
	T *fakeconceal.Text  // want "configured safe type \\*fakeconceal.Text does not guarantee JSON marshal safety: MarshalText outputs the secret$" "configured safe type \\*fakeconceal.Text does not guarantee text marshal safety: MarshalText outputs the secret$" "configured safe type \\*fakeconceal.Text does not guarantee format-level safety"
	B *fakeconceal.Bytes // want "configured safe type \\*fakeconceal.Bytes does not guarantee format-level safety"

	// RevealingString is structurally protected,
	// but its String is known to output the secret,
	// so String-level safety fails, and so does text marshal safety:
	// log/slog TextHandler prints a type without MarshalText with %+v.
	R fakesensitive.RevealingString // want "configured safe type fakesensitive.RevealingString does not guarantee text marshal safety: String outputs the secret$" "configured safe type fakesensitive.RevealingString does not guarantee String-level safety: String outputs the secret$"
}
