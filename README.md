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
via `fmt.Formatter`, `Stringer`, and `GoStringer`.
But Go's `fmt` reaches struct fields by reflection,
and a `reflect.Value` obtained from an **unexported** field has `CanInterface() == false`,
so `fmt` skips `handleMethods` and prints the **raw** underlying value.
The redaction is silently bypassed — secret leaks.

The `flagRO` (read-only) bit propagates to ALL nested values reached through an unexported field,
so even an **exported** sensitive field nested inside an unexported parent field leaks.
That's why detection must be **transitive**.

Builtin `print`/`println` also bypass redaction entirely (they never call any interface method).

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
`github.com/negrel/secrecy`, and `github.com/angusgmorrison/logfusc`.
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

| Name              | Description                                                                                                          |
| ----------------- | -------------------------------------------------------------------------------------------------------------------- |
| `sensitivefields` | Detects unexported struct fields whose type (transitively) contains sensitive values that leak via `fmt` reflection. |
| `sensitiveprint`  | Detects calls to builtin `print`/`println` whose arguments contain sensitive values.                                 |
