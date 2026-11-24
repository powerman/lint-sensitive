package reliability_conceal

import "fakeconceal"

// The types are used only as pointers, so *T has String and GoString:
// there are no String-level and GoString-level diagnostics.
// MarshalText of *Text outputs the secret, so it does not count.

type Check struct {
	T *fakeconceal.Text // want "configured safe type \\*fakeconceal.Text does not guarantee JSON marshal safety:[^(]*\\(MarshalText outputs the secret\\)$" "configured safe type \\*fakeconceal.Text does not guarantee text marshal safety:[^(]*\\(MarshalText outputs the secret\\)$" "configured safe type \\*fakeconceal.Text does not guarantee format-level safety"
	B *fakeconceal.Bytes // want "configured safe type \\*fakeconceal.Bytes does not guarantee JSON marshal safety:[^(]*$" "configured safe type \\*fakeconceal.Bytes does not guarantee text marshal safety:[^(]*$" "configured safe type \\*fakeconceal.Bytes does not guarantee format-level safety"
}
