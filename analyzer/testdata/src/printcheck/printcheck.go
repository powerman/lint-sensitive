package printcheck

import (
	"fmt"

	"fakesensitive"
	"fakeplayground"
)

// Positive cases: basic-kind sensitive types passed by value.

func testPrintFakeSensitive() {
	var s fakesensitive.String
	print(s)   // want "sensitive value passed to builtin print leaks raw value"
	println(s) // want "sensitive value passed to builtin println leaks raw value"
}

func testPrintFakePlayground() {
	var s fakeplayground.String
	print(s)   // want "sensitive value passed to builtin print leaks raw value"
	println(s) // want "sensitive value passed to builtin println leaks raw value"
}

// Negative cases: non-sensitive args and safe sensitive args.

func testPrintNonSensitive() {
	var x int
	print(x)   // No diagnostic: non-sensitive type.
	println(x) // No diagnostic: non-sensitive type.
}

func testPrintSensitivePointer() {
	var s fakesensitive.String
	print(&s)  // No diagnostic: pointer does not leak content through print.
	println(&s)
}

func testPrintSensitiveSlice() {
	// sensitive.Bytes in production has underlying []byte — slice header,
	// not content.
	var b []fakesensitive.String
	print(b)   // No diagnostic: slice header, not content.
	println(b)
}

func testFn() {}

func testCallNonBuiltin() {
	testFn() // No diagnostic: not a builtin function.
}

func testCallNonPrintBuiltin() {
	recover() // No diagnostic: recover is a builtin but not print/println.
}

func testFmtPrint() {
	var s fakesensitive.String
	fmt.Print(s) // No diagnostic: fmt.Print uses proper formatting.
}
