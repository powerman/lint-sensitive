# Architecture

This document describes how the analyzers decide what to report
and why the code is shaped the way it is.
User-facing behaviour (flags, supported libraries, how to fix a finding) is in the [README](README.md).

## Code map

| Path                     | Responsibility                                                                           |
| ------------------------ | ---------------------------------------------------------------------------------------- |
| `main.go`                | The `lint-sensitive` binary: `multichecker` over `analyzer.NewFlagAnalyzers`.            |
| `plugin/`                | The golangci-lint module plugin: `.golangci.yml` settings to `analyzer.Config`.          |
| `analyzer/analyzer.go`   | `Config`, `New`, and the data about known libraries (default types, special cases).      |
| `analyzer/flags.go`      | `NewFlagAnalyzers`: the `-sensitive.*` flags and how they reach the analyzers.           |
| `analyzer/matcher.go`    | `matcher` (the configuration) and `checker` (per-pass state), matching configured types. |
| `analyzer/methods.go`    | Method-set queries: does a type have `Format`, `String`, `GoString`, `Marshal*`.         |
| `analyzer/classify.go`   | `typeClass`: what protects one safe type; structural and opaque checks.                  |
| `analyzer/walk.go`       | The walk: does `fmt` reach the content of a safe type from a given field.                |
| `analyzer/fields.go`     | The `sensitivefields` analyzer: runs the walk for every struct field.                    |
| `analyzer/levelcheck.go` | The optional reliability levels (`-sensitive.require-*`), part of `sensitivefields`.     |
| `analyzer/print.go`      | The `sensitiveprint` analyzer: builtin `print`/`println`.                                |
| `analyzer/format.go`     | The `sensitivefmt` analyzer: finds print calls and the verb of each argument.            |
| `analyzer/fmtparse.go`   | `parseFormat`: operations of a format string, a port of `doPrintf` of the fmt package.   |
| `analyzer/verb.go`       | `fmtVerb` and `leaksAsArg`: which methods and pointers fmt uses for a verb.              |

## Protection model

The linter knows a set of safe types for secrets (configured via `-sensitive.types`).
Safe types can protect secrets through a combination of mechanisms:

- Storing the secret in an unexported field.
  This is the most reliable protection against JSON serialization etc.
- Implementing `encoding.TextMarshaler` and/or `json.Marshaler`.
  This is an alternative way to protect against JSON serialization etc.
- Storing the secret in one of the types that `fmt.Printf` never follows:
  `*Pointer` (`**T`), `*Interface` (`*any(T)`), `Chan` (`<-chan T`), `Func` (`func() T`),
  `UnsafePointer`, `*<non-compound>` (`*string`, `*int`, `*bool`, etc.).
  This is the only structural protection against `fmt.Printf`.
- Implementing `fmt.Formatter` and/or `fmt.Stringer` and/or `fmt.GoStringer`.
  These are varying degrees of protection against the `fmt.Printf` family.
  Support for these methods can be disabled depending on the path to the value.

The linter's tasks:

- Unconditional: warn about weakening the base protection level of safe types.
  Detect places where `Formatter`/`Stringer`/`GoStringer` support
  is disabled for types that implement some of these interfaces
  and are not structurally protected (see [Classification](#classification-of-a-safe-type)).
- Optional reliability-level: warn about using safe types that
  do not provide the required level of protection for the configured attack surface
  (see [Reliability levels](#reliability-levels)).

Even though a safe type having interface implementations does not guarantee
that this functionality is used specifically for secret protection,
the linter assumes it is (any other approach is useless).
Structural protection is not assumed this way:
it counts only when every field of the type is protected,
so an unrelated field (a callback, a counter, a cache) cannot fake it.

## What fmt does

For safe types implementing (`fmt.Formatter` or `fmt.Stringer` or `fmt.GoStringer`)
AND not structurally protected:

- The linter checks the path leading to these types
  for factors that disable support for these interfaces:
  1. an unexported field;
  2. a pointer type not implementing `Formatter` (may be in an exported field too).
- If such a factor is detected, it reports incorrect use of the safe type.
- A pointer directly to a safe type is not a factor on its own:
  `fmt` holds `*T`, so it is judged by the method set of `*T`,
  and on a clean path the methods of `*T` fire.
  A pointer to a holder struct is a factor, as any non-`Formatter` pointer.
- A defined pointer type (`type PT *T`) has no methods,
  so it is a non-`Formatter` pointer even when `*T` has `fmt` methods.

Rationale:

- If a safe type is structurally protected,
  disabling `Formatter`/`Stringer`/`GoStringer` only blocks replacing
  the secret value with "REDACTED" or similar,
  while instead of the secret the address of the intermediate pointer will be printed.
- The `fmt.Printf` family disables interface support in only two cases:
  1. entering an unexported field;
  2. calling `badVerb`.
- For `badVerb` the linter must consider ALL situations where `badVerb` CAN trigger
  (because the linter cannot know which verb will actually be used
  and must assume the one that triggers `badVerb`).
  The only type relevant to the linter is `Pointer`, because non-compound types
  (bool/numeric/String/Chan/Func/UnsafePointer/Invalid plus `[]byte`)
  are either themselves the safe type with `Formatter`
  or have no relation to storing secrets.
  The only exception: if this `Pointer` type itself implements `Formatter` —
  in this case it is also a terminal type and cannot cause problems
  (because `fmt` encounters this `Pointer` BEFORE calling `badVerb`,
  and if it implements `Formatter`, the `badVerb` call simply won't happen —
  `Formatter` by definition supports all verbs).
- `badVerb` reprints the value with `%v` and with methods off,
  and dereferences only the pointer which caused it,
  so pointers nested deeper in the pointee print as addresses.
- Under `badVerb` at depth 0, `fmt` dereferences a pointer only when the pointee is
  a compound kind (struct, slice, array, map).
  A pointer to a non-compound kind always prints as an address.
- An unexported field turns methods off but keeps the verb,
  so a pointer under it can still cause `badVerb`.
- A named type with `fmt.Formatter` reached with `fmt` interfaces still enabled
  redacts under every verb, so it is a safe terminal.
  Where methods are off the method may not fire, so it must not be trusted there.
  The same holds for the struct types written inside its declaration:
  their fields are not checked,
  and the cases where `fmt` cannot reach the type with interfaces enabled
  are reported at the field which holds the type.

## fmt rules for a known verb

The declaration check does not know the verb of the caller (the zero verb),
so it assumes the verb which triggers `badVerb`.
The call-site check knows it and follows `fmt` exactly (`leaksAsArg`, `analyzer/verb.go`):

- `%T` never leaks.
  `%p` prints an address for a pointer, chan, func, map, slice and unsafe.Pointer,
  and goes to `badVerb` for any other value.
- A value which has a method serving the verb is a terminal, whether it is a safe type or not:
  `Formatter` serves every verb, `GoString` serves `%#v`,
  `Error` and `String` serve `v s x X q`.
  `%w` of an error behaves like `%v`;
  `%w` of a value which is not an error is `badVerb` for the whole value.
  The method set is that of the value `fmt` holds (see [Classification](#classification-of-a-safe-type)).
- A pointer below the top level prints an address under `v p b o d x X`
  and goes to `badVerb` under any other verb.
- The pointer which is the argument itself is dereferenced under every verb
  when the pointee is a struct, array, slice or map, and the pointee is printed with the same verb.
- An argument of an interface type is not checked: its dynamic type is unknown.
- A safe type without fmt methods is a leak under a verb which prints its content,
  unlike in the declaration check, which assumes such a type is covered by the reliability levels.
  A structurally protected type is never a leak.

## The walk

`walk` (`analyzer/walk.go`) is the `Formatter`-termination walk.
It returns true when a safe type reachable through a type
would leak its secret content when `fmt` prints that type in a print state.

The print state is how `fmt` prints the values which the walk reaches:

- clean: `fmt` calls methods of the value which serve the verb of the caller
  (with the zero verb only `Formatter` is certain to fire);
- no methods: the path entered an unexported field.
  `fmt` does not call methods there, but keeps the verb of the caller,
  so a pointer may still cause `badVerb`, which dereferences it;
- erroring: `badVerb` reprints the pointer which caused it with `%v` and without methods.
  It dereferences only that pointer:
  every pointer nested in the pointee prints as an address.

Details of the contract:

- The visited set prevents infinite recursion on cyclic types.
  It is keyed by the print state (the mode and the verb) too,
  because a type is safe or leaking depending on it.
- When the walk returns true, it reports the first disable factor on the path, if any,
  and the hops of the leaking path ordered from the innermost (the safe type) to the outermost.
  Both are left unchanged when the walk returns false:
  otherwise a factor would be reported as the reason of an unrelated leak found later.
- Only `SecretExposer` interfaces (those that have an `ExposeSecret` method) are flagged,
  the convention of `github.com/powerman/sensitive.Secret[T]`
  and `github.com/negrel/secrecy.SecretExposer[T]`.
  Generic `any`/`interface{}` and all other interfaces are NOT flagged:
  the analyzer cannot know what concrete type will be stored in them,
  and flagging them causes a torrent of false positives from library internals
  (e.g. `prometheus.Metric` or `error` deep inside a metrics struct).
  A `SecretExposer` interface has no step of its own in the path,
  because the walk sees only the unnamed interface type.

## Classification of a safe type

`checker.classify` computes a `typeClass` once per type in a pass.
It records which of the `fmt`/`encoding` interfaces the type implements
and whether the type is structurally safe or opaque.

- `hasMethod` checks the signature structurally (no standard library interface resolution),
  so a same-named method with another signature is not mistaken for the interface method.
  The method set is taken as is:
  for a non-pointer `T`, methods declared on `*T` are not counted,
  because `fmt` and `encoding/json` never call them on a non-addressable value.
  Promoted value-receiver methods are part of the method set of both `T` and `*T`.
- `ptrOnly` holds the names of the methods which only `*T` has.
  They do not count as implemented for a `T` value,
  but they count when the type is used only as `*T`.
- Structural safety: every value the type can carry is printed as an address or header,
  and the type has at least one qualifier (see the list in [Protection model](#protection-model)).
  A type seen again (a recursive type, or a type shared by sibling fields) is neutral:
  its first visit already contributed to the result,
  because the results of all parts are combined with AND (safe) and OR (protected).
  Zero-size parts (`_ [0]func()`, `struct{}`) carry nothing and do not matter.
  A pointer to a type parameter is a qualifier only when its constraint excludes all compound kinds;
  with no constraint, `any` or a method-only constraint it is conservatively compound.
  `fmt` dereferences a depth-0 pointer only for compound kinds,
  so a pointer to any non-compound named type (e.g. `*MyString`) prints as an address.
- Opaque struct: reflection-based encoders such as `encoding/json` write it empty,
  because all its fields are unexported and none is embedded.
- Public fields are fields of known types which `fmt` prints but which never hold the secret
  (the built-in `publicFields` and `Config.PublicFields`).
  They are skipped by the structural and opaque checks.
  Only top-level fields of the listed type are skipped, not fields of nested types.
  A listed name which the struct does not have is not applied:
  the library changed, so the type falls back to the plain rule, which is the safe direction.
- Revealing methods are methods of known types which match an interface by signature
  but output the secret (`revealingMethods`).
  They are removed from the implemented flags and from `ptrOnly`,
  and they fail every surface they serve.
  The built-in tables apply to a matched type whether it comes from the default types or not.
- `ExposeSecret` is detected by method name only; the exact return type is not verified.

## Reliability levels

The `-sensitive.require-*` flags make `sensitivefields` also check every configured safe type
used in the analyzed package against the selected surfaces
(JSON, text marshaling, `Format`, `GoString`, `String`).
The diagnostic is reported at the use site within the analyzed package,
because the declaration of most configured safe types, the built-in defaults,
lives in an external package.

- A generic type is checked as the instance the code uses, e.g. `SinglePtr[string]`,
  and an alias is resolved to the type it stands for.
- References in files skipped by skip-tests or skip-generated are ignored,
  so a type used both there and in a regular file is reported in the regular one.
- Only the first occurrence of each type is kept,
  and the diagnostics are emitted in the order of these positions (deterministic).
- Instances of one generic type which fail for the same reason are reported once:
  the message names a generic type without type arguments,
  so they are indistinguishable, and once one is fixed the next run reports the next one.
- A type is checked by the method set of `T` if the package has any value-form use of it,
  and by the method set of `*T` only if every use is the pointer form.
  The method set of `*T` contains that of `T`,
  so a failed check of `*T` implies a failed check of `T`:
  one check per type is enough.
- A use is a type name (a declaration, a reference or an instantiation)
  or an expression whose type is `T` or `*T`.
- The pointer form is a type name which is the operand of a pointer type,
  like `*conceal.Text`, `[]*conceal.Text` or `*Secret[string]`,
  or the type in `&T{}` and `new(T)`, whose value is held only as `*T`.
  A defined pointer type, like `type PT *T`, is not the pointer form:
  its values have no methods, so `fmt` and encoders see the `T` value.
  An expression of a defined pointer type is a value-form use of its element type.
- A revealing method fails the surface whatever other safeguards the type has.
- `log/slog` `TextHandler` falls back to `%+v` when there is no `MarshalText`,
  so `String` and `Format` serve the text-marshal surface too.

## Lifecycle and configuration

- Two ways to get the configuration into the analyzers:
  `New(Config)` builds one `matcher` which all passes share,
  and `NewFlagAnalyzers` registers the flags on an extra analyzer, `sensitive`,
  whose result (a `matcher`) the others read from `pass.ResultOf`.
  `matcherFunc` hides the difference.
  An invalid `Config` is reported as an error by every analyzer run.
- Each call of `NewFlagAnalyzers` returns an independent set, so the flags are not shared between calls.
- The `matcher` is shared between passes, so it holds no per-pass state.
  The set of generated files, for example, is computed once per pass by `newShouldCheck`.
- A `checker` is the per-pass state of `sensitivefields`.
  Its caches are keyed by type identity, which is exact only within one pass,
  so a checker must not outlive its pass.
  A process-wide cache would keep the types of every pass alive in long-running drivers
  (`gopls`, golangci-lint daemons),
  and a string key cannot tell apart local types of different functions which share a name.
- With `-sensitive.debug` the classification of each safe type is printed to stderr once.
  The key is the whole line, which includes the type arguments,
  so instances of one generic type with different classification are all printed,
  while the same type seen in several packages is printed only once.
  The per-package matchers of the flag-driven path share one set of printed lines.
- The golangci-lint plugin has no skip-tests, skip-generated and debug settings:
  golangci-lint excludes tests and generated files with `linters.exclusions`,
  and writing to stderr does not fit it.
  The settings keys match the flags of the binary,
  but the lists are YAML lists instead of comma-separated strings.
