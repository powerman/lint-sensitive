# lint-sensitive

[![License MIT](https://img.shields.io/badge/license-MIT-royalblue.svg)](LICENSE)
[![Go version](https://img.shields.io/github/go-mod/go-version/powerman/lint-sensitive?color=blue)](https://go.dev/)
[![Test](https://img.shields.io/github/actions/workflow/status/powerman/lint-sensitive/test.yml?label=test)](https://github.com/powerman/lint-sensitive/actions/workflows/test.yml)
[![Coverage Status](https://raw.githubusercontent.com/powerman/lint-sensitive/gh-badges/coverage.svg)](https://github.com/powerman/lint-sensitive/actions/workflows/test.yml)
[![Release](https://img.shields.io/github/v/release/powerman/lint-sensitive?color=blue)](https://github.com/powerman/lint-sensitive/releases/latest)
[![Go Reference](https://pkg.go.dev/badge/github.com/powerman/lint-sensitive.svg)](https://pkg.go.dev/github.com/powerman/lint-sensitive)

![Linux | amd64 arm64 armv7 ppc64le s390x riscv64](https://img.shields.io/badge/Linux-amd64%20arm64%20armv7%20ppc64le%20s390x%20riscv64-royalblue)
![macOS | amd64 arm64](https://img.shields.io/badge/macOS-amd64%20arm64-royalblue)
![Windows | amd64 arm64](https://img.shields.io/badge/Windows-amd64%20arm64-royalblue)

Go linter to detect sensitive value leaks via `fmt` reflection and builtin `print`/`println`,
and optionally check that safe types implement the interfaces needed to stay redacted
in JSON, text marshaling and `fmt` output.

## What this linter is for

A sensitive type
(like [`github.com/go-playground/sensitive.String`](https://pkg.go.dev/github.com/go-playground/sensitive#String))
exists to keep a secret out of your logs and error messages.
Using one sets up an expectation:
"if this value is ever printed, it shows `[REDACTED]`, not the secret."

That expectation is fragile.
A field rename, an extra wrapper struct, or an added pointer can silently disable
the redaction while the code still compiles
and the field still holds "the sensitive type."
**lint-sensitive exists to catch exactly these silent failures** —
the places where a secret you believe is protected gets printed in the clear.

Redaction can quietly stop working in several ways:

- **`fmt` reflection through an unexported field** — `fmt` reaches struct fields
  by reflection, and once the path to the secret crosses an unexported field
  `fmt` stops honouring the type's `Formatter`/`Stringer`/`GoStringer`
  and prints the **raw** underlying value.
- **A pointer on the path** — printing a struct that holds a pointer on the way
  to the safe type with a verb the value does not natively handle (say `%s`)
  makes `fmt` reflect through the pointer with those same interfaces disabled.
- **builtin `print`/`println`** — these never call any formatting interface;
  they dump the raw value directly.

There are further subtle variations, but the takeaway is always the same:
whether the secret stays redacted depends on **how** it is reached.

## How a value stays protected

A sensitive type can protect its content in two ways:

1. **Interfaces**: implementing `fmt.Formatter`, `fmt.Stringer`, or `fmt.GoStringer`.
   These are honoured by `fmt` only when the value is reachable
   through a clean (exported, non-pointer-indirect) path.
2. **Structural protection**: storing the secret behind indirections
   that `fmt` never follows (e.g. `**T` or `func() T`),
   so it prints only an address regardless of verb.

## How protection silently breaks

Whether redaction fires depends on the **path** `fmt` takes to reach the value,
not just on the value's type.
Two everyday refactors — neither of which touches the sensitive type itself —
disable it.

### An unexported field on the path

A config with an exported `go-playground/sensitive.String` prints redacted:

```go
import "github.com/go-playground/sensitive"

type Config struct {
    APIKey sensitive.String
}

fmt.Println(Config{APIKey: "s3cr3t"}) // {} — redacted, as expected
```

Wrap that same config in one **unexported** field and the redaction is gone:

```go
type Server struct {
    cfg Config // one unexported word...
}

fmt.Println(Server{cfg: Config{APIKey: "s3cr3t"}}) // {{s3cr3t}} — LEAK
```

`APIKey` is still exported and its type is unchanged;
the unexported `cfg` field alone stops `fmt` from calling methods of anything beneath it.

### A pointer to the holder

Adding a non-`Formatter` pointer to a struct that holds a secret is the second
disable factor.
Under a verb the pointer does not support (e.g. `%s` or `%q`)
`fmt` dereferences the pointer and reflects into
the fields with interface dispatch turned off:

```go
import "github.com/go-playground/sensitive"

type Credentials struct {
    Token sensitive.String
}

type Session struct {
    Creds *Credentials // exported field, but the pointer can still defeat redaction
}

fmt.Printf("%s", Session{Creds: &Credentials{Token: "s3cr3t"}})
// {%!s(*main.Credentials=&{s3cr3t})} — LEAK
```

The linter reports the `fmt` call which prints such a value,
naming the factor that disables redaction so the fix is obvious
(see the [`sensitivefmt`](#analyzers) analyzer):

```text
server.go:9:14: sensitive value of type main.Server printed with %v exposes
                the secret of safe type sensitive.String through an unexported field "cfg"
```

With [`-sensitive.detect-fields`](#detecting-fields-which-can-leak)
it also reports every field on such a path, even when nothing prints it:

```text
server.go:2:  sensitive field "cfg" is reachable through an unexported field "cfg";
              the safe type's fmt.Formatter/Stringer/GoStringer then does not fire
              and the field is not structurally protected
              — fmt can print its secret content
session.go:2: sensitive field "Creds" is reachable through a non-Formatter pointer
              to main.Credentials; the safe type's fmt.Formatter/Stringer/GoStringer
              then does not fire and the field is not structurally protected
              — fmt can print its secret content
```

### The builtin `print`/`println` channel

These bypass redaction unconditionally, no wrapper needed:

```go
import "github.com/go-playground/sensitive"

var s sensitive.String = "s3cr3t"
println(s) // s3cr3t — Stringer/Formatter is never consulted
```

### Every supported library, both channels

By default the linter recognises seven sensitive-value libraries (see below).
The [`example/`](example/) directory is a self-contained module with a runnable
program that uses every one of them:
unprotected values leak through `fmt` reflection or builtin `print`,
while structurally protected ones stay hidden and produce no findings,
so you can watch the failures and the findings side by side:

```bash
cd example
go run . # observe the leaked secrets on stdout
lint-sensitive -sensitive.types=github.com/powerman/lint-sensitive/example.Secret .
```

## What the linter can and cannot guarantee

The linter reasons about **formal, structural signs** only:
that a configured safe type implements one of the `fmt` interfaces,
or that it embeds a structurally-protected type.
It **assumes** those mechanisms exist to protect the secret
and checks only that the access path does not disable them.

It does **not** verify that a mechanism is actually wired to the secret.
A type may implement `Format` and still print the secret through a buggy method.
Such misuse is out of scope — the linter treats the presence of the interface
as intent, because any other use of it would be pointless.

Its checks surface places where the protection a developer **expects**
silently does not hold:

- **Print calls**: warn when a `fmt`-like call prints a value
  whose path to a safe type disables the type's `Formatter`/`Stringer`/`GoStringer`
  and the type has no structural protection to fall back on.
- **Struct fields** (opt-in): warn about such a path at the declaration,
  even when nothing prints the value
  (see [Detecting fields which can leak](#detecting-fields-which-can-leak)).
- **Optional reliability levels**: warn when a safe type does not protect the secret
  on the surfaces (JSON, `fmt` verbs, …) the project requires
  (see [Optional reliability levels](#optional-reliability-levels)).

## Installation

```bash
go install github.com/powerman/lint-sensitive@latest
```

Or run directly without installing:

```bash
go run github.com/powerman/lint-sensitive@latest ./...
```

## Usage

```bash
lint-sensitive ./...
```

By default, types from several sensitive-value libraries are recognized:
`github.com/powerman/sensitive`, `github.com/go-playground/sensitive`,
`github.com/negrel/secrecy.Secret`, `github.com/angusgmorrison/logfusc.Secret`,
`github.com/rsjethani/secret/v2.Text` and `/v3.Text`,
`github.com/shoenig/go-conceal.Text` and `.Bytes`,
and `github.com/rbranson/camo.Secret`.
If you use other libraries or project-specific types, extend via the `-sensitive.types` flag:

```bash
lint-sensitive -sensitive.types=github.com/example/secret ./...
```

To restrict a package to a specific named type, use `.TypeName` suffix:

```bash
lint-sensitive -sensitive.types=github.com/myorg/internal.Secret ./...
```

Multiple types are comma-separated:

```bash
lint-sensitive -sensitive.types=pkg.A,pkg.B ./...
```

To disable the built-in default type list, add `-sensitive.no-default-types`:

```bash
lint-sensitive -sensitive.no-default-types -sensitive.types=my/custom.Type ./...
```

A configured type may have a field which never holds the secret,
e.g. an ID next to a structurally protected secret.
Declare it as `import/path.TypeName.FieldName` with `-sensitive.public`
(comma-separated, only for types matched by `-sensitive.types`):

```bash
lint-sensitive -sensitive.public=example.com/app.Credential.ID ./...
```

The linter then ignores this field when it judges the type's protection.
This is not a way to suppress findings:
a wrongly declared field hides real leaks of that type.

Some files produce findings that cannot or should not be fixed:

- **Test files** (`_test.go`) often hold fake fixtures that aren't real secrets.
  Use `-sensitive.skip-tests` to suppress diagnostics in test files:

  ```bash
  lint-sensitive -sensitive.skip-tests ./...
  ```

- **Generated files** (files with a `// Code generated ... DO NOT EDIT.` header)
  cannot carry structural fixes. Use `-sensitive.skip-generated` to skip them:

  ```bash
  lint-sensitive -sensitive.skip-generated ./...
  ```

### The `analyzer` package

The linter logic lives in `github.com/powerman/lint-sensitive/analyzer`.
Use `New(Config)` for library integration:

```go
package main

import "github.com/powerman/lint-sensitive/analyzer"

analyzers := analyzer.New(analyzer.Config{
    Types:        []string{"my/project.Internal"},
    PublicFields: []string{"my/project.Internal.ID"},
})
```

## Analyzers

Three analyzers are registered in the `lint-sensitive` binary:

| Name              | Description                                                                                                                                                                                                                                                                          |
| ----------------- | ------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------ |
| `sensitivefmt`    | Detects calls of print functions (`fmt.*`, `log.*`, `testing.T.*` and their wrappers) which print the content of a sensitive value, with the verb the format string gives to the argument.                                                                                           |
| `sensitivefields` | Checks that safe types provide the interfaces required by the optional `-sensitive.require-*` flags. With `-sensitive.detect-fields` also detects struct fields (exported AND unexported) where an unexported field or a pointer on the path could disable redaction of a safe type. |
| `sensitiveprint`  | Detects calls to builtin `print`/`println` whose arguments contain sensitive values.                                                                                                                                                                                                 |

### Limitations of `sensitivefmt`

It reports what the program prints, so it checks only what it can see in the call:

- an argument of an interface type is not checked, because its dynamic type is unknown;
- a format string which is not a constant is not checked;
- arguments forwarded as `args...` are not checked;
- structured loggers without a format string (`log/slog`, zap or logrus fields) are not checked:
  they format with `%v`/`%+v`, which `-sensitive.detect-fields` covers
  (see [Detecting fields which can leak](#detecting-fields-which-can-leak)).

## Detecting fields which can leak

By default the linter reports only what the program prints:
a `fmt`-like call or a builtin `print` which exposes a safe type's secret.
`-sensitive.detect-fields` also reports every struct field
whose path to a safe type could leak with some verb,
even when no such print exists:

```bash
lint-sensitive -sensitive.detect-fields ./...
```

It is off by default because it is a detector rather than a linter:
a field may never be printed, and then the report is noise.
Turn it on for what the call-site analysis cannot see:
arguments of an interface type, non-constant format strings, `args...` forwarding,
structured loggers (`log/slog`, zap or logrus fields) which format with `%v`/`%+v`,
and library types which their users will print.

The setting is `detect-fields` in the golangci-lint plugin, `Config.DetectFields` in the library.

## Optional reliability levels

The call-site checks only guard against _weakening_ whatever protection a
type already has; they say nothing about whether that protection is enough.
Consider a safe type that implements only `GoStringer`:
it redacts under `%#v`, but a plain `%v`/`%s` prints the secret,
and an `encoding/json` marshal writes it straight into the output.
The call-site checks stay silent — nothing is being _disabled_ —
even though the secret leaks on the very first log line or API response.

**Recommended: make your expectations explicit.**
Decide which surfaces your secrets must survive (JSON, all `fmt` verbs, `%v`, …)
and turn on the matching `-sensitive.require-*` flags.
Instead of hoping every "safe" type is safe enough,
you state the requirement once and the linter reports any type that falls short.

When a flag is set, every safe type used in the analyzed package
is checked against the corresponding attack surface.
Safe types that do not meet the requirement are reported.

The five surfaces and their acceptable safeguards:

| Surface                  | Acceptable safeguards (any one)                                     |
| ------------------------ | ------------------------------------------------------------------- |
| JSON marshal             | `encoding.TextMarshaler` OR `json.Marshaler` OR opaque struct       |
| Text marshal             | `encoding.TextMarshaler` OR (opaque struct AND `%v`/`%s` safeguard) |
| All fmt verbs            | `fmt.Formatter` OR structurally-protected type                      |
| `%#v`                    | `fmt.GoStringer` OR `fmt.Formatter` OR structurally-protected type  |
| `%v`/`%s`/`%q`/`%x`/`%X` | `fmt.Stringer` OR `fmt.Formatter` OR structurally-protected type    |

An "opaque struct" has only unexported, non-embedded fields,
so JSON, XML, YAML and TOML encoders write it empty.
`log/slog` TextHandler prints such a struct with `%+v`,
hence the extra `%v`/`%s` safeguard for text marshal.

A "structurally-protected type" is a struct which stores the secret
only behind indirections that `fmt` never follows
(`**T`, `*string`, `*interface{}`, `chan T`, `func() T`, `unsafe.Pointer`, etc.).
A single other field (`int`, `string`, `any`, a pointer to a struct, etc.)
makes the whole type unprotected, because `fmt` prints that field as is.

Both definitions ignore public fields
(declared with `-sensitive.public` or built in for supported libraries).
A method which the linter knows to output the secret,
like `MarshalText` of `go-conceal.Text`, never counts as a safeguard.

### Existing library support

The table below shows which protection surfaces (`-sensitive.require-*`)
each type in the existing libraries provides (as of 2026-11-24).

| Safe type                           | JSON | Text | fmt | `%#v` | `%v`/`%s` | Structural |
| ----------------------------------- | ---- | ---- | --- | ----- | --------- | ---------- |
| `powerman/sensitive.Ref[T]`         | ✓    | ✓    | ✓   | ✓     | ✓         | ✓          |
| `powerman/sensitive.Handle[T]`      | ✓    | ✓    | ✓   | ✓     | ✓         | ✓          |
| `rsjethani/secret/v2.Text`          | ✓    | ✓    | ✓   | ✓     | ✓         | ✓          |
| `rsjethani/secret/v3.Text`          | ✓    | ✓    | ✓   | ✓     | ✓         | ✓          |
| `andrewbenton/go-secrets.Secret[T]` | ✓    | ✓    | ✓   | ✓     | ✓         | ✓          |
| `rbranson/camo.Secret[T]`           | ✓    | ✓    | ✓   | ✓     | ✓         | ✓          |
| `go-playground/sensitive.String`    | ✓    | ✓    | ✓   | ✓     | ✓         | ✗          |
| `negrel/secrecy.Secret[T]`          | ✓    | ✓    | ✗   | ✓     | ✓         | ✗          |
| `angusgmorrison/logfusc.Secret[T]`  | ✓    | ✓    | ✗   | ✓     | ✓         | ✗          |
| `shoenig/go-conceal.Bytes`          | ✓    | ✓    | ✗   | ✓     | ✓         | ✗          |
| `shoenig/go-conceal.Text`           | ✗    | ✗    | ✗   | ✓     | ✓         | ✗          |

### Flags

Diagnostics are OFF by default; enable each surface independently:

```text
-sensitive.require-marshal-json
-sensitive.require-marshal-text
-sensitive.require-format
-sensitive.require-gostring
-sensitive.require-string
```

Example:

```bash
lint-sensitive -sensitive.require-format ./...
```

When a safe type does not provide the required level of protection,
the diagnostic names the missing interface or structural property
so you know what to implement.

## Fixing findings

The linter does not offer a per-line suppression directive by design —
a `//nolint`-style annotation would silently re-open the leak if debug logging
is added later. Fix findings with one of the structural remediations below.

### Option A: Export the access path

Make every struct in the chain from the top-level exported type down to the
secret field exported. This ensures `fmt` honours the sensitive type's own
`fmt.Formatter`, `Stringer`, or `GoStringer` redaction.

```go
import "github.com/go-playground/sensitive"

type Config struct {
    APIKey sensitive.String // exported — redacted by fmt
}
```

> **Caveat**: safe only when the holder is formatted directly.
> Nested under another unexported struct field the linter recatches it,
> and nested behind an **interface** in an unexported field it leaks while
> remaining invisible to static analysis.
> Good for simple, local cases.

### Option B: Use a structurally safe type (recommended)

Store the secret in a type whose value is unreachable through `fmt` reflection.
The `sensitive.Ref[T]` type holds its value behind a double pointer (`**T`),
which `fmt` prints as an address and never dereferences.

`sensitive.Handle[T]` is also structurally safe for primitive type parameters
because it stores `*T` where `*<non-compound>` prints as an address.

```go
import "github.com/powerman/sensitive"

type config struct {
    apiKey sensitive.Ref[string] // safe — fmt cannot reach the string
}
```

### When neither option applies

- **Generated files** that cannot be edited: use `-sensitive.skip-generated`.
- **Test fixtures** that hold fake data rather than real secrets:
  use `-sensitive.skip-tests`.

## Related tools

[`nilpoona/leakhound`](https://github.com/nilpoona/leakhound) is the closest other
static analyzer, but it guards a different invariant and the two are complementary.

leakhound is a data-flow (taint) analyzer: it tags fields with `sensitive:"true"`
and tracks whether a tagged value reaches a _known_ logging sink
(`slog`, `log`, `fmt`, and — via config — `zap`/`zerolog`/`logrus`),
following assignments, parameters, and returns across functions and packages.
It catches leaks even for a plain `string` that has no redaction of its own.

lint-sensitive reasons about the _type and the access path_ instead of the sink.
It answers a question leakhound does not model at all:
"does the redaction this type relies on actually fire on this path,
or does an unexported field / non-`Formatter` pointer silently disable it?"
Consequently it also covers sinks leakhound cannot enumerate —
`fmt.Errorf` into a `%w` chain, a custom `io.Writer`,
a third-party library that logs internally, traces, and metrics.

In short: leakhound is a static, sink-oriented blocklist
(a compile-time cousin of runtime sanitizers like `masq`);
lint-sensitive verifies the structural guarantee
of self-redacting types on every path.
Running both is reasonable.
