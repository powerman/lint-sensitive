package analyzer

import (
	"fmt"
	"reflect"
	"strconv"
	"strings"
	"sync"
	"testing"
	"unicode/utf8"
)

// parseFormatCases are hand-written cases for every rule of doPrintf which parseFormat repeats.
var parseFormatCases = []struct { // Const.
	name   string
	format string
	want   []fmtOp
}{
	{"empty", "", nil},
	{"no verbs", "text", nil},
	{"simple", "%v", []fmtOp{{'v', false, 0}}},
	{"two", "%s and %d", []fmtOp{{'s', false, 0}, {'d', false, 1}}},
	{"percent consumes no argument", "%% %v", []fmtOp{{'v', false, 0}}},
	{"percent before verb", "%%%v", []fmtOp{{'v', false, 0}}},
	{"sharp flag", "%#v", []fmtOp{{'v', true, 0}}},
	{"sharp flag of another verb", "%#x", []fmtOp{{'x', true, 0}}},
	{"other flags", "%+v %-5s % d %05d", []fmtOp{
		{'v', false, 0}, {'s', false, 1}, {'d', false, 2}, {'d', false, 3},
	}},
	{"flags in any order", "%0#+- x", []fmtOp{{'x', true, 0}}},
	{"width and precision", "%5.2f", []fmtOp{{'f', false, 0}}},
	{"precision without number", "%.f", []fmtOp{{'f', false, 0}}},
	{"explicit index", "%[2]s", []fmtOp{{'s', false, 1}}},
	{"index continues", "%[2]s %s", []fmtOp{{'s', false, 1}, {'s', false, 2}}},
	{"index back", "%[3]s %[1]s %s", []fmtOp{{'s', false, 2}, {'s', false, 0}, {'s', false, 1}}},
	{"star width", "%*d", []fmtOp{{'d', false, 1}}},
	{"star precision", "%.*f", []fmtOp{{'f', false, 1}}},
	{"star both", "%*.*f", []fmtOp{{'f', false, 2}}},
	{"indexed star", "%[2]*d", []fmtOp{{'d', false, 2}}},
	{"indexed star and verb index", "%[2]*[1]d", []fmtOp{{'d', false, 0}}},
	{"indexed precision star", "%.[2]*[1]f", []fmtOp{{'f', false, 0}}},
	{"all indexes", "%[3]*.[2]*[1]f", []fmtOp{{'f', false, 0}}},
	{"bad index is skipped", "%[x]d %s", []fmtOp{{'s', false, 0}}},
	{"zero index is skipped", "%[0]d %s", []fmtOp{{'s', false, 0}}},
	{"unclosed index is skipped", "%[1d %s", []fmtOp{{'s', false, 0}}},
	// The index of a bad operation still moves the next argument.
	{"index with width is skipped", "%[2]3d %s", []fmtOp{{'s', false, 1}}},
	{"index with precision is skipped", "%[2].3d %s", []fmtOp{{'s', false, 1}}},
	{"width before index", "%3[2]d", []fmtOp{{'d', false, 1}}},
	{"trailing percent", "%v %", []fmtOp{{'v', false, 0}}},
	{"flags without verb", "%v %#5", []fmtOp{{'v', false, 0}}},
	{"dot is the verb at the end", "%.", []fmtOp{{'.', false, 0}}},
	{"unknown verb", "%y", []fmtOp{{'y', false, 0}}},
	{"bang verb", "%!", []fmtOp{{'!', false, 0}}},
	{"multibyte verb", "%é", []fmtOp{{'é', false, 0}}},
	{"wrap", "%w", []fmtOp{{'w', false, 0}}},
	{"type and pointer", "%T %p", []fmtOp{{'T', false, 0}, {'p', false, 1}}},
}

func TestParseFormat(t *testing.T) {
	t.Parallel()

	for _, tc := range parseFormatCases {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()

			if got := parseFormat(tc.format); !reflect.DeepEqual(got, tc.want) {
				t.Errorf("parseFormat(%q) = %v, want %v", tc.format, got, tc.want)
			}
		})
	}
}

// formatAlphabet is the set of bytes which formats are built from in the exhaustive tests.
const formatAlphabet = "%#+ []12*.dvx"

// eachFormat calls f for every string up to maxLen bytes long over formatAlphabet.
func eachFormat(maxLen int, f func(format string)) {
	var rec func(prefix []byte)
	rec = func(prefix []byte) {
		f(string(prefix))
		if len(prefix) == maxLen {
			return
		}
		for i := range len(formatAlphabet) {
			rec(append(prefix, formatAlphabet[i]))
		}
	}
	rec(nil)
}

// recorder is an argument which records how fmt calls its Format method into the output.
// It is an int, so it is a valid argument for '*' too.
type recorder int

func (r recorder) Format(f fmt.State, verb rune) {
	fmt.Fprintf(f, "\x00%d\x01%c\x01%t\x00", int(r), verb, f.Flag('#'))
}

// oracleArgs returns enough arguments for any format which passes maxOracleLen.
var oracleArgs = sync.OnceValue(func() []any {
	args := make([]any, 300)
	for i := range args {
		args[i] = recorder(i)
	}
	return args
})

// maxOracleLen is the longest format which the fmt oracle checks:
// with indexes of at most two digits the arguments never run out.
const maxOracleLen = 40

// fmtRecords returns the operations which real fmt performs on format.
func fmtRecords(format string) []fmtOp {
	// Every byte of the format consumes at most one argument after the highest index.
	out := fmt.Sprintf(format, oracleArgs()[:maxNumber(format)+len(format)+1]...)
	// Arguments which the format did not use are printed after this marker.
	out, _, _ = strings.Cut(out, "%!(EXTRA ")
	var res []fmtOp
	for i, part := range strings.Split(out, "\x00") {
		if i%2 == 0 { // Text of the format, not a record.
			continue
		}
		fields := strings.SplitN(part, "\x01", 3)
		arg, _ := strconv.Atoi(fields[0])
		verb, _ := utf8.DecodeRuneInString(fields[1])
		res = append(res, fmtOp{verb: verb, sharp: fields[2] == "true", arg: arg})
	}
	return res
}

// wantRecords returns the operations of parseFormat which call Format.
// %T and %p are handled by fmt itself, and %w is bad outside of Errorf.
func wantRecords(format string) []fmtOp {
	var res []fmtOp
	for _, op := range parseFormat(format) {
		if op.verb != 'T' && op.verb != 'p' && op.verb != 'w' {
			res = append(res, op)
		}
	}
	return res
}

// checkAgainstFmt reports a difference between parseFormat and real fmt for format.
// It is not applicable to a format which fmt cannot print by a Formatter
// (it contains a byte which separates the records) or which has a too long index.
func checkAgainstFmt(t *testing.T, format string) {
	t.Helper()

	if len(format) > maxOracleLen || strings.ContainsAny(format, "\x00\x01") || strings.Contains(format, "EXTRA") || longNumber(format) {
		return
	}
	if got, want := fmtRecords(format), wantRecords(format); !reflect.DeepEqual(got, want) {
		t.Errorf("format %q: fmt performed %v, parseFormat found %v", format, got, want)
	}
}

// maxNumber returns the largest number in format.
func maxNumber(format string) int {
	res := 0
	for _, f := range strings.FieldsFunc(format, func(r rune) bool { return r < '0' || '9' < r }) {
		n, _ := strconv.Atoi(f)
		res = max(res, n)
	}
	return res
}

// longNumber reports whether format has a number of more than two digits.
func longNumber(format string) bool {
	digits := 0
	for _, c := range format {
		if '0' <= c && c <= '9' {
			digits++
			if digits > 2 {
				return true
			}
		} else {
			digits = 0
		}
	}
	return false
}

// TestParseFormatMatchesFmt compares parseFormat with real fmt on every short format.
func TestParseFormatMatchesFmt(t *testing.T) {
	t.Parallel()

	for _, tc := range parseFormatCases {
		checkAgainstFmt(t, tc.format)
	}
	eachFormat(5, func(format string) { checkAgainstFmt(t, format) })
}

func FuzzParseFormat(f *testing.F) {
	for _, tc := range parseFormatCases {
		f.Add(tc.format)
	}
	f.Fuzz(func(t *testing.T, format string) {
		checkAgainstFmt(t, format)
	})
}
