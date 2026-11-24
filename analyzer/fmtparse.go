package analyzer

import "unicode/utf8"

// fmtOp is one operation of a format string which consumes an argument.
type fmtOp struct {
	verb  rune // 'v', 's', …; never '%'
	sharp bool // The '#' flag.
	arg   int  // Index into the variadic arguments.
}

const (
	// maxFmtNum is the largest width, precision or argument index which fmt accepts.
	maxFmtNum = 1e6
	decimal   = 10
	// minIndexLen is the length of the shortest index, "[n]".
	minIndexLen = 3
)

// parseFormat returns the operations of format in order,
// skipping width and precision '*' arguments (they consume an argument but print nothing).
// An operation whose argument index is bad (e.g. "%[x]d") is skipped.
//
// It repeats doPrintf of the fmt package for a call with enough arguments,
// so an operation whose index is beyond the arguments of a real call must be ignored by the caller.
// It is checked against fmt itself, see FuzzParseFormat.
func parseFormat(format string) []fmtOp {
	p := &fmtParser{format: format}
	var ops []fmtOp
	for {
		for p.i < len(format) && format[p.i] != '%' {
			p.i++
		}
		if p.i >= len(format) {
			return ops
		}
		p.i++
		op, hasVerb := p.operation()
		if !hasVerb {
			return ops
		}
		if op.verb != '%' && p.good {
			ops = append(ops, op)
			p.argNum++
		}
	}
}

// fmtParser is the state of parseFormat, the same as in doPrintf.
type fmtParser struct {
	format     string
	i          int  // The next byte of format.
	argNum     int  // The argument which the next operation or '*' consumes.
	afterIndex bool // The previous item of the format was an index like [3].
	good       bool // False when the argument index of the operation is bad.
}

// operation parses the operation which follows '%'.
// The second result is false when the format ends before the verb.
func (p *fmtParser) operation() (fmtOp, bool) {
	p.good = true
	sharp := p.flags()
	p.index()
	p.width()
	p.precision()
	if !p.afterIndex {
		p.index()
	}
	if p.i >= len(p.format) {
		return fmtOp{}, false
	}
	verb, size := utf8.DecodeRuneInString(p.format[p.i:])
	p.i += size
	return fmtOp{verb: verb, sharp: sharp, arg: p.argNum}, true
}

// flags skips the flags and reports whether one of them is '#'.
func (p *fmtParser) flags() (sharp bool) {
	for ; p.i < len(p.format); p.i++ {
		switch p.format[p.i] {
		case '#':
			sharp = true
		case '0', '+', '-', ' ':
		default:
			return sharp
		}
	}
	return sharp
}

// index parses an explicit argument index like [3], see fmtArgNumber.
func (p *fmtParser) index() {
	var ok bool
	p.argNum, p.i, p.afterIndex, ok = fmtArgNumber(p.format, p.i, p.argNum)
	p.good = p.good && ok
}

// star skips '*' and the argument it consumes, if the format has it at this position.
func (p *fmtParser) star() bool {
	if p.i >= len(p.format) || p.format[p.i] != '*' {
		return false
	}
	p.i++
	p.argNum++
	p.afterIndex = false
	return true
}

func (p *fmtParser) width() {
	if p.star() {
		return
	}
	var isNum bool
	_, isNum, p.i = fmtParseNum(p.format, p.i, len(p.format))
	if p.afterIndex && isNum { // "%[3]2d"
		p.good = false
	}
}

func (p *fmtParser) precision() {
	if p.i+1 >= len(p.format) || p.format[p.i] != '.' {
		return
	}
	p.i++
	if p.afterIndex { // "%[3].2d"
		p.good = false
	}
	p.index()
	if !p.star() {
		_, _, p.i = fmtParseNum(p.format, p.i, len(p.format))
	}
}

// fmtParseNum is parsenum of the fmt package.
func fmtParseNum(s string, start, end int) (num int, isNum bool, newi int) {
	if start >= end {
		return 0, false, end
	}
	for newi = start; newi < end && '0' <= s[newi] && s[newi] <= '9'; newi++ {
		if num > maxFmtNum || num < -maxFmtNum {
			return 0, false, end // Overflow; crazy long number most likely.
		}
		num = num*decimal + int(s[newi]-'0')
		isNum = true
	}
	return num, isNum, newi
}

// fmtArgNumber is argNumber of the fmt package for a call with enough arguments:
// it parses an explicit argument index at format[i:].
// found tells that the index is syntactically well-formed (even if it is out of range),
// ok is false for a bad index, which makes the operation bad.
func fmtArgNumber(format string, i, argNum int) (newArgNum, newi int, found, ok bool) {
	if len(format) <= i || format[i] != '[' {
		return argNum, i, false, true
	}
	index, wid, found := fmtParseArgNumber(format[i:])
	if found && index >= 0 {
		return index, i + wid, true, true
	}
	return argNum, i + wid, found, false
}

// fmtParseArgNumber is parseArgNumber of the fmt package.
func fmtParseArgNumber(format string) (index, wid int, ok bool) {
	// There must be at least 3 bytes: [n].
	if len(format) < minIndexLen {
		return 0, 1, false
	}
	for i := 1; i < len(format); i++ {
		if format[i] == ']' {
			width, isNum, newi := fmtParseNum(format, 1, i)
			if !isNum || newi != i {
				return 0, i + 1, false
			}
			return width - 1, i + 1, true // Argument numbers are one-indexed.
		}
	}
	return 0, 1, false
}
