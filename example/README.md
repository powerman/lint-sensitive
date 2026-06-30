# Example project

This directory contains a standalone Go module that demonstrates
both leak channels using every default-supported library
plus a custom sensitive type declared directly in the module's main package.
Run the linter over it to verify it catches the expected lines:

```bash
lint-sensitive -sensitive.types=github.com/powerman/lint-sensitive/example.Secret .
```

The `.Secret` suffix restricts detection to only the `Secret` type in that package,
leaving other types (e.g., `Public`) unmarked.
