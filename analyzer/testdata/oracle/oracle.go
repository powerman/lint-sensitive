// Package oracle holds the shapes of values which the runtime oracle test prints with real fmt
// to compare the result with the leak decision of the analyzer.
// The package is imported by the test binary and type-checked from source by the same test.
package oracle

import (
	"fmt"
	"strings"
)

// Secret is the content of every safe value; it must not appear in the output of fmt.
const Secret = "S3CRET"

const redacted = "REDACTED"

// Str has String only.
type Str string

func (Str) String() string { return redacted }

// StrFmt has Format only.
type StrFmt string

func (StrFmt) Format(f fmt.State, _ rune) { _, _ = f.Write([]byte(redacted)) }

// StrGo has GoString only.
type StrGo string

func (StrGo) GoString() string { return redacted }

// StrPtr has String on the pointer receiver.
type StrPtr string

func (*StrPtr) String() string { return redacted }

// StrAll has String and GoString.
type StrAll string

func (StrAll) String() string   { return redacted }
func (StrAll) GoString() string { return redacted }

// Plain has no fmt methods.
type Plain string

// PlainBox is a struct with an unexported field and no fmt methods.
type PlainBox struct{ secret string }

// Box is a struct with an unexported field, String only.
type Box struct{ secret string }

func (Box) String() string { return redacted }

// Safe lists the safe types, see SafeNames.
type Safe interface {
	Str | StrFmt | StrGo | StrPtr | StrAll | Box | Plain | PlainBox
}

// SafeNames lists the names of the safe types of this package.
var SafeNames = []string{"Str", "StrFmt", "StrGo", "StrPtr", "StrAll", "Box", "Plain", "PlainBox"} // Const.

// Make returns a safe value with the secret.
func Make[S Safe]() S {
	var s S
	switch p := any(&s).(type) {
	case *Str:
		*p = Secret
	case *StrFmt:
		*p = Secret
	case *StrGo:
		*p = Secret
	case *StrPtr:
		*p = Secret
	case *StrAll:
		*p = Secret
	case *Box:
		p.secret = Secret
	case *Plain:
		*p = Secret
	case *PlainBox:
		p.secret = Secret
	}
	return s
}

// Holders of a safe type S.
type (
	// Pub holds S in an exported field.
	Pub[S Safe] struct{ F S }
	// Priv holds S in an unexported field.
	Priv[S Safe] struct{ f S }
	// PubPtr holds *S in an exported field.
	PubPtr[S Safe] struct{ F *S }
	// PrivPtr holds *S in an unexported field.
	PrivPtr[S Safe] struct{ f *S }
	// PubPtrHolder holds a pointer to a holder.
	PubPtrHolder[S Safe] struct{ F *Pub[S] }
	// PrivPtrHolder holds a pointer to a holder in an unexported field.
	PrivPtrHolder[S Safe] struct{ f *Pub[S] }
	// PubPtrPtr holds **S.
	PubPtrPtr[S Safe] struct{ F **S }
	// EmbStr embeds Str, so it gets its String promoted.
	EmbStr struct{ Str }
	// EmbBoxPtr embeds *Box.
	EmbBoxPtr struct{ *Box }
	// Deep holds a holder of a holder.
	Deep[S Safe] struct{ F PrivPtr[S] }
	// NamedPtr is a defined pointer type, which has no methods.
	NamedPtr[S Safe] *S
	// NamedPtrHolder is a defined pointer type to a holder.
	NamedPtrHolder[S Safe] *Pub[S]
	// HolderField holds a defined pointer type.
	HolderField[S Safe] struct{ F NamedPtr[S] }
	// Cyclic holds itself through a pointer.
	Cyclic[S Safe] struct {
		F S
		P *Cyclic[S]
	}
)

// Holders with their own methods, which hide the content of S.
type (
	// WithString has String.
	WithString[S Safe] struct{ F *S }
	// WithGoString has GoString.
	WithGoString[S Safe] struct{ F *S }
	// WithFormat has Format.
	WithFormat[S Safe] struct{ F *S }
	// WithError has Error.
	WithError[S Safe] struct{ F *S }
	// WithPtrString has String on the pointer receiver.
	WithPtrString[S Safe] struct{ F *S }
	// WithPriv is like WithString but the field is unexported.
	WithPriv[S Safe] struct{ f S }
	// WithPtrFormat has Format on the pointer receiver.
	WithPtrFormat[S Safe] struct{ F S }
	// SliceString is a slice which has String.
	SliceString[S Safe] []*S
)

func (WithString[S]) String() string             { return redacted }
func (WithGoString[S]) GoString() string         { return redacted }
func (WithFormat[S]) Format(fmt.State, rune)     {}
func (WithError[S]) Error() string               { return redacted }
func (*WithPtrString[S]) String() string         { return redacted }
func (WithPriv[S]) String() string               { return redacted }
func (*WithPtrFormat[S]) Format(fmt.State, rune) {}
func (SliceString[S]) String() string            { return redacted }

// Shape is a value which the oracle prints.
type Shape struct {
	Name  string
	Type  string // The Go type of Value as an expression in the scope of this package.
	Value any
}

// EmbShapes returns the shapes which embed a safe type.
func EmbShapes() []Shape {
	box := Make[Box]()
	return []Shape{
		{Name: "EmbStr", Type: "EmbStr", Value: EmbStr{Str: Secret}},
		{Name: "*EmbStr", Type: "*EmbStr", Value: &EmbStr{Str: Secret}},
		{Name: "EmbBoxPtr", Type: "EmbBoxPtr", Value: EmbBoxPtr{Box: &box}},
		{Name: "*EmbBoxPtr", Type: "*EmbBoxPtr", Value: &EmbBoxPtr{Box: &box}},
	}
}

// Shapes returns the shapes of the safe type named name.
func Shapes[S Safe](name string) []Shape {
	s := func() S { return Make[S]() }
	ptr := func() *S { v := s(); return &v }
	ptrPtr := func() **S { p := ptr(); return &p }
	pub := func() *Pub[S] { return &Pub[S]{F: s()} }
	cyc := &Cyclic[S]{F: s()}
	cyc.P = cyc

	sh := func(typ string, v any) Shape {
		return Shape{Name: strings.ReplaceAll(typ, "$", name), Type: strings.ReplaceAll(typ, "$", name), Value: v}
	}
	return []Shape{
		sh("$", s()),
		sh("*$", ptr()),
		sh("**$", ptrPtr()),
		sh("Pub[$]", *pub()),
		sh("*Pub[$]", pub()),
		sh("Priv[$]", Priv[S]{f: s()}),
		sh("*Priv[$]", &Priv[S]{f: s()}),
		sh("PubPtr[$]", PubPtr[S]{F: ptr()}),
		sh("*PubPtr[$]", &PubPtr[S]{F: ptr()}),
		sh("PrivPtr[$]", PrivPtr[S]{f: ptr()}),
		sh("*PrivPtr[$]", &PrivPtr[S]{f: ptr()}),
		sh("PubPtrHolder[$]", PubPtrHolder[S]{F: pub()}),
		sh("*PubPtrHolder[$]", &PubPtrHolder[S]{F: pub()}),
		sh("PrivPtrHolder[$]", PrivPtrHolder[S]{f: pub()}),
		sh("PubPtrPtr[$]", PubPtrPtr[S]{F: ptrPtr()}),
		sh("*PubPtrPtr[$]", &PubPtrPtr[S]{F: ptrPtr()}),
		sh("Deep[$]", Deep[S]{F: PrivPtr[S]{f: ptr()}}),
		sh("*Deep[$]", &Deep[S]{F: PrivPtr[S]{f: ptr()}}),
		sh("NamedPtr[$]", NamedPtr[S](ptr())),
		sh("NamedPtrHolder[$]", NamedPtrHolder[S](pub())),
		sh("HolderField[$]", HolderField[S]{F: NamedPtr[S](ptr())}),
		sh("*HolderField[$]", &HolderField[S]{F: NamedPtr[S](ptr())}),
		sh("Cyclic[$]", *cyc),
		sh("*Cyclic[$]", cyc),
		sh("[]$", []S{s()}),
		sh("[]*$", []*S{ptr()}),
		sh("*[]$", &[]S{s()}),
		sh("*[]*$", &[]*S{ptr()}),
		sh("[1]$", [1]S{s()}),
		sh("[1]*$", [1]*S{ptr()}),
		sh("map[string]$", map[string]S{"k": s()}),
		sh("map[string]*$", map[string]*S{"k": ptr()}),
		sh("map[$]string", map[S]string{s(): "v"}),
		sh("*map[string]*$", &map[string]*S{"k": ptr()}),
		sh("[]Pub[$]", []Pub[S]{*pub()}),
		sh("[]*Pub[$]", []*Pub[S]{pub()}),
		sh("[]PrivPtr[$]", []PrivPtr[S]{{f: ptr()}}),
		sh("WithString[$]", WithString[S]{F: ptr()}),
		sh("*WithString[$]", &WithString[S]{F: ptr()}),
		sh("WithGoString[$]", WithGoString[S]{F: ptr()}),
		sh("*WithGoString[$]", &WithGoString[S]{F: ptr()}),
		sh("WithFormat[$]", WithFormat[S]{F: ptr()}),
		sh("*WithFormat[$]", &WithFormat[S]{F: ptr()}),
		sh("WithError[$]", WithError[S]{F: ptr()}),
		sh("*WithError[$]", &WithError[S]{F: ptr()}),
		sh("WithPtrString[$]", WithPtrString[S]{F: ptr()}),
		sh("*WithPtrString[$]", &WithPtrString[S]{F: ptr()}),
		sh("WithPriv[$]", WithPriv[S]{f: s()}),
		sh("*WithPriv[$]", &WithPriv[S]{f: s()}),
		sh("WithPtrFormat[$]", WithPtrFormat[S]{F: s()}),
		sh("*WithPtrFormat[$]", &WithPtrFormat[S]{F: s()}),
		sh("SliceString[$]", SliceString[S]{ptr()}),
		sh("[]WithString[$]", []WithString[S]{{F: ptr()}}),
		sh("[]*WithPriv[$]", []*WithPriv[S]{{f: s()}}),
	}
}
