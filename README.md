# lint-sensitive

[![License MIT](https://img.shields.io/badge/license-MIT-royalblue.svg)](LICENSE)
[![Go version](https://img.shields.io/github/go-mod/go-version/powerman/lint-sensitive?color=blue)](https://go.dev/)
[![Test](https://img.shields.io/github/actions/workflow/status/powerman/lint-sensitive/test.yml?label=test)](https://github.com/powerman/lint-sensitive/actions/workflows/test.yml)
[![Coverage Status](https://raw.githubusercontent.com/powerman/lint-sensitive/gh-badges/coverage.svg)](https://github.com/powerman/lint-sensitive/actions/workflows/test.yml)
[![Go Report Card](https://goreportcard.com/badge/github.com/powerman/lint-sensitive)](https://goreportcard.com/report/github.com/powerman/lint-sensitive)
[![Release](https://img.shields.io/github/v/release/powerman/lint-sensitive?color=blue)](https://github.com/powerman/lint-sensitive/releases/latest)
[![Go Reference](https://pkg.go.dev/badge/github.com/powerman/lint-sensitive.svg)](https://pkg.go.dev/github.com/powerman/lint-sensitive)

![Linux | amd64 arm64 armv7 ppc64le s390x riscv64](https://img.shields.io/badge/Linux-amd64%20arm64%20armv7%20ppc64le%20s390x%20riscv64-royalblue)
![macOS | amd64 arm64](https://img.shields.io/badge/macOS-amd64%20arm64-royalblue)
![Windows | amd64 arm64](https://img.shields.io/badge/Windows-amd64%20arm64-royalblue)

Go linter to detect sensitive value leaks via `fmt` reflection and builtin `print`/`println`.

## What this linter is for

A sensitive type (like `github.com/powerman/sensitive.String`) exists to keep a
secret out of your logs and error messages.
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
   that `fmt` never follows — `**T`, `*interface{}`, `chan T`, `func() T`,
   `unsafe.Pointer`, or `*<non-compound>` (`*string`, `*int`, etc.).
   These always print as an address or header regardless of verb.

## How protection silently breaks

Whether redaction fires depends on the **path** `fmt` takes to reach the value,
not just on the value's type.
Two everyday refactors — neither of which touches the sensitive type itself —
disable it.

### An unexported field on the path

A config with an exported `sensitive.String` prints redacted:

```go
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
the unexported `cfg` field alone flips `CanInterface()` to `false`
for everything beneath it.

### A pointer to the holder

Adding a non-`Formatter` pointer to a struct that holds a secret is the second
disable factor.
Under some verbs (e.g. `%#v`) `fmt` dereferences the pointer and reflects into
the fields with interface dispatch turned off:

```go
type Credentials struct {
	token sensitive.String
}

type Session struct {
	Creds *Credentials // exported field, but the pointer can still defeat redaction
}
```

The linter flags every field on such a path, naming the factor that disables
redaction so the fix is obvious:

```
server.go:2:  sensitive field "cfg" is reachable behind a unexported field "cfg";
              the safe type's fmt.Formatter/Stringer/GoStringer then does not fire
              and the field is not structurally protected
              — fmt can print its secret content
session.go:2: sensitive field "Creds" is reachable behind a non-Formatter pointer
              to main.Credentials; the safe type's fmt.Formatter/Stringer/GoStringer
              then does not fire and the field is not structurally protected
              — fmt can print its secret content
```

### The builtin `print`/`println` channel

These bypass redaction unconditionally, no wrapper needed:

```go
var s sensitive.String = "s3cr3t"
println(s) // s3cr3t — Stringer/Formatter is never consulted
```

### Every supported library, both channels

By default the linter recognises four sensitive-value libraries (see below).
The [`example/`](example/) directory is a self-contained module with a runnable
program that leaks every one of them through both channels
— `fmt` reflection and builtin `print` —
so you can watch the failures and the findings side by side:

```bash
cd example
go run .        # observe the leaked secrets on stdout
lint-sensitive -sensitive.types=github.com/powerman/lint-sensitive/example.Secret .
```

## What the linter can and cannot guarantee

The linter reasons about **formal, structural signs** only:
that a configured safe type implements one of the `fmt` interfaces,
or that it embeds a structurally-protected type.
It **assumes** those mechanisms exist to protect the secret
and checks only that the access path does not disable them.

It does **not** verify that a mechanism is actually wired to the secret.
A type may implement `Format` and still print the secret through a buggy method;
a type may embed a `**T` field that holds something other than the secret.
Such misuse is out of scope — the linter treats the presence of the mechanism
as intent, because any other use of it would be pointless.

Because of this, the two checks it performs both exist for one purpose —
to surface places where the protection a developer **expects** silently does not hold:

- **Unconditional**: warn when a safe type's `Formatter`/`Stringer`/`GoStringer`
  protection is disabled by a path-disable factor
  (unexported field or non-`Formatter` pointer),
  the type implements at least one of these interfaces,
  and the type has no structural protection to fall back on.
- **Optional reliability levels**: a config-driven check that warns when a safe
  type does not provide enough protection for a configured attack surface.
  Use it to state, per project, what "protected" must actually mean
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
`github.com/negrel/secrecy.Secret`, and `github.com/angusgmorrison/logfusc`.
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

Both flags default to `false` (diagnostics reported everywhere) and can be combined.

### The `analyzer` package

The linter logic lives in `github.com/powerman/lint-sensitive/analyzer`.
Use `New(Config)` for library integration:

```go
package main

import "github.com/powerman/lint-sensitive/analyzer"

analyzers := analyzer.New(analyzer.Config{
    Types: []string{"my/project.Internal"},
})
```

## Analyzers

Two analyzers are registered in the `lint-sensitive` binary:

| Name              | Description                                                                                                  |
| ----------------- | ------------------------------------------------------------------------------------------------------------ |
| `sensitivefields` | Detects struct fields (exported AND unexported) where a safe type is reachable behind a path-disable factor. |
| `sensitiveprint`  | Detects calls to builtin `print`/`println` whose arguments contain sensitive values.                         |

## Optional reliability levels

By default the linter only checks the **unconditional** condition:
a safe type must not leak content when its Formatter/Stringer/GoStringer
interface is disabled by a path-disable factor.

The unconditional check only guards against _weakening_ whatever protection a
type already has; it says nothing about whether that protection is enough.
Consider a safe type that implements only `GoStringer`:
it redacts under `%#v`, but a plain `%v`/`%s` prints the secret,
and an `encoding/json` marshal writes it straight into the output.
The unconditional check stays silent — nothing is being _disabled_ —
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

| Surface                    | Acceptable safeguards (any one)                                     |
| -------------------------- | ------------------------------------------------------------------- |
| JSON marshal               | `encoding.TextMarshaler` OR `json.Marshaler`                        |
| Text marshal               | `encoding.TextMarshaler`                                            |
| All fmt verbs              | `fmt.Formatter` OR structurally-protected field                     |
| `%#v`                      | `fmt.GoStringer` OR `fmt.Formatter` OR structurally-protected field |
| `%v`/`%s`/`%q`/`%x`¹/`%X`¹ | `fmt.Stringer` OR `fmt.Formatter` OR structurally-protected field   |

¹ - Works on strings, but not on float types.

A "structurally-protected field" means one of:
`**T`, `*interface{}`, `chan T`, `func() T`, `unsafe.Pointer`,
or `*<non-compound>` (`*string`, `*int`, `*bool`, etc.).
These are the types that `fmt.Printf` never dereferences —
it always prints an address or header, regardless of the verb.

### Flags

Diagnostics are OFF by default; enable each surface independently:

```
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
