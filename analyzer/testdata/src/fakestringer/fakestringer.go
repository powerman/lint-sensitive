// Package fakestringer provides fake sensitive types for testing the verbs of print calls.
package fakestringer

// Secret has String only.
type Secret string

func (Secret) String() string { return "[redacted]" }

// Plain has no fmt methods.
type Plain string

// Box has an unexported field and String only.
type Box struct{ value string }

func (Box) String() string { return "[redacted]" }
