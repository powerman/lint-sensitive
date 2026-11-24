package fmtcall

import (
	"fmt"
	"log"
	"os"
	"testing"

	"fakeconceal"
	"fakesensitive"
	"fakestringer"
	"fmtcalldep"
)

type holder struct{ S fakestringer.Secret }

type privHolder struct{ s fakestringer.Secret }

type ptrHolder struct{ B *fakestringer.Box }

type concealHolder struct{ T *fakeconceal.Text }

// The verb decides whether a method of the safe type is called.
func verbOfStringer(s fakestringer.Secret) {
	fmt.Println(s)
	fmt.Print(s)
	fmt.Printf("%v %s %q %x %X", s, s, s, s, s)
	fmt.Printf("%T", s)
	fmt.Printf("%d", s)  // want `sensitive value of type fakestringer.Secret printed with %d exposes the secret of safe type fakestringer.Secret$`
	fmt.Printf("%#v", s) // want `printed with %#v exposes`
	fmt.Printf("%p", s)  // want `printed with %p exposes`
	fmt.Printf("%y", s)  // want `printed with %y exposes`
	fmt.Printf("%s", string(s))
}

// A type without fmt methods leaks under every verb which prints its content.
func verbOfPlain(p fakestringer.Plain) {
	fmt.Println(p)      // want `printed with %v exposes`
	fmt.Printf("%s", p) // want `printed with %s exposes`
	fmt.Printf("%T", p)
	fmt.Printf("%s", string(p))
	fmt.Printf("%s", []byte(p))
}

// A safe type with Formatter serves every verb.
func formatter(s fakesensitive.String) {
	fmt.Printf("%v %d %#v %y", s, s, s, s)
}

// A pointer below the top level prints an address for some verbs only.
func nested(a holder, b privHolder, c ptrHolder, d *ptrHolder, e concealHolder) {
	fmt.Printf("%v %s %d", a, a, a.S) // want `printed with %d exposes`
	fmt.Printf("%d", a)               // want `sensitive value of type fmtcall.holder printed with %d exposes`
	fmt.Printf("%v", b)               // want `sensitive value of type fmtcall.privHolder printed with %v exposes the secret of safe type fakestringer.Secret through an unexported field "s"`
	fmt.Printf("%v %s %d %p", c, c, c, c)
	fmt.Printf("%t", c) // want `printed with %t exposes the secret of safe type fakestringer.Box through a pointer to fakestringer.Box`
	fmt.Printf("%v %d", d, d)
	fmt.Printf("%t", d) // want `printed with %t exposes`
	fmt.Printf("%v %s %x %#v", e, e, e, e)
	fmt.Printf("%d", e)
	fmt.Printf("%t", e) // want `printed with %t exposes`
}

// The pointer which is the argument itself is dereferenced for every verb.
func topLevel(c *fakeconceal.Text, d *fakestringer.Box) {
	fmt.Printf("%v %s %#v", c, c, c)
	fmt.Printf("%d", c) // want `printed with %d exposes`
	fmt.Printf("%d", d) // want `printed with %d exposes`
	fmt.Printf("%v", d)
}

// One diagnostic is reported for an argument even if several verbs leak it.
func once(s fakestringer.Secret) {
	fmt.Printf("%[1]d %[1]t", s) // want `printed with %d exposes`
}

func indexes(s fakestringer.Secret, p fakestringer.Plain) {
	fmt.Printf("%[2]s %d", s, p) // want `sensitive value of type fakestringer.Plain printed with %s exposes`
	fmt.Printf("%*d", 3, s)      // want `printed with %d exposes`
	fmt.Printf("%.*[2]s", 3, s)
	fmt.Printf("%[3]d", s)
	fmt.Printf("%d %%", 3)
}

func calls(s fakestringer.Secret, t *testing.T) {
	log.Printf("%d", s)                              // want `printed with %d exposes`
	log.Println(fakestringer.Plain("x"))             // want `printed with %v exposes`
	fmt.Fprintf(os.Stdout, "%d", s)                  // want `printed with %d exposes`
	fmt.Fprintln(os.Stdout, fakestringer.Plain("x")) // want `printed with %v exposes`
	_ = fmt.Sprintf("%d", s)                         // want `printed with %d exposes`
	_ = fmt.Errorf("%w", s)                          // want `printed with %w exposes`
	_ = fmt.Errorf("%v", s)
	t.Errorf("%d", s)              // want `printed with %d exposes`
	t.Log(fakestringer.Plain("x")) // want `printed with %v exposes`
}

func logf(format string, args ...any) {
	fmt.Printf(format, args...)
}

func wrappers(s fakestringer.Secret) {
	logf("%d", s) // want `printed with %d exposes`
	logf("%v", s)
	fmtcalldep.Logf("%d", s) // want `printed with %d exposes`
	fmtcalldep.Logf("%v", s)
}

func plainAndError() (fakestringer.Plain, error)                { return "", nil }
func twoPlain() (fakestringer.Plain, fakestringer.Plain)        { return "", "" }
func writerAndPlain() (*os.File, fakestringer.Plain)            { return os.Stdout, "" }
func formatAndPlain() (string, fakestringer.Plain)              { return "%s", "" }
func secretAndPlain() (fakestringer.Secret, fakestringer.Plain) { return "", "" }

// The results of a call which is the sole argument are printed one by one.
func tuples() {
	fmt.Println(plainAndError())   // want `sensitive value of type fakestringer.Plain printed with %v exposes`
	fmt.Println(twoPlain())        // want `printed with %v exposes` `printed with %v exposes`
	fmt.Fprintln(writerAndPlain()) // want `printed with %v exposes`
	fmt.Println(secretAndPlain())  // want `sensitive value of type fakestringer.Plain printed with %v exposes`
	fmt.Printf(formatAndPlain())   // The format is not a constant.
}

// Not checked: the dynamic type, the format, or the arguments are not known statically.
func notChecked(s fakestringer.Secret, args []any, format string) {
	var i any = s
	fmt.Printf("%d", i)
	fmt.Printf(format, s)
	fmt.Printf("%d", args...)
	fmt.Println(args...)
	fmt.Printf("%d")
	fmt.Printf("%d", fmt.Sprint(1, 2))
}

func notPrint(s fakestringer.Secret) {
	_ = fmt.Sprint
	other("%d", s)
}

func other(format string, args ...any) {}
