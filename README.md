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

## Why

Sensitive types (like `github.com/powerman/sensitive.String`) redact themselves
via `fmt.Formatter`, `fmt.Stringer`, or `fmt.GoStringer`.
But Go's `fmt` reaches struct fields by reflection,
and a `reflect.Value` obtained from an **unexported** field has `CanInterface() == false`.
When `CanInterface()` is false, `fmt` skips `handleMethods`
and prints the **raw** underlying value — the redaction is silently bypassed,
and the secret leaks.

A sensitive type can protect its content in two ways:

1. **Interfaces**: implementing `fmt.Formatter`, `fmt.Stringer`, or `fmt.GoStringer`.
   These are honoured by `fmt` when the value is reachable
   through a clean (exported, non-pointer-indirect) path.
2. **Structural protection**: storing the secret behind indirections
   that `fmt` never follows — `**T`, `*interface{}`, `chan T`, `func() T`,
   `unsafe.Pointer`, or `*<non-compound>` (`*string`, `*int`, etc.).
   These always print as an address or header regardless of verb.

The linter uses **Formatter-termination reachability**:
it walks struct fields and flags places where a path-disable factor
(unexported field, non-Formatter pointer) would prevent the safe type's
interfaces from firing, _and_ the type has no structural protection to fall back on.

### What the linter checks

- **Unconditional**: it warns when a safe type's
  `fmt.Formatter`/`Stringer`/`GoStringer` protection
  is disabled by a path-disable factor
  (unexported field or non-Formatter pointer),
  the type implements at least one of these interfaces,
  and the type has no structural protection.
- **Optional reliability levels**: a config-driven check
  that warns when a safe type does not provide enough protection
  for the configured attack surface.

### Example

```go
package example

import "github.com/powerman/sensitive"

type Config struct {
	APIKey sensitive.String // exported — handled correctly by fmt
}

type Request struct {
	apiKey sensitive.String // unexported — LEAKS via fmt reflection
}
```

The unexported `apiKey` field's raw value is printed
when the parent struct reaches `fmt`'s reflection formatter.

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

For projects that need stronger guarantees,
five boolean flags opt in to **config-driven reliability warnings**.
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
