# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [0.8.1] - 2026-11-24

### 📚 Documentation

- **(readme)** Add AI usage section by @powerman in [49a4109]

[0.8.1]: https://github.com/powerman/lint-sensitive/compare/v0.8.0..v0.8.1
[49a4109]: https://github.com/powerman/lint-sensitive/commit/49a4109898616d78bb637428e282b088c54eb9c1

## [0.8.0] - 2026-11-24

### 🚀 Added

- **(analyzer)** Add sensitivefmt analyzer for print verbs by @powerman in [4130f8d]
- **⚠️ BREAKING!** Add golangci-lint module plugin and drop package-level state by @powerman in [add2702]

### 🔔 Changed

- **⚠️ BREAKING!** Make the sensitivefields declaration check opt-in by @powerman in [b967a85]

### 📚 Documentation

- **(readme)** Add golangci-lint plugin section by @powerman in [b6d0077]
- Move architecture notes from code comments to ARCHITECTURE.md by @powerman in [892a7b2]

[0.8.0]: https://github.com/powerman/lint-sensitive/compare/v0.7.0..v0.8.0
[add2702]: https://github.com/powerman/lint-sensitive/commit/add2702b9914c4b70203be75e99bd37a90ab2325
[892a7b2]: https://github.com/powerman/lint-sensitive/commit/892a7b28f59eac4c9e37965706229ef03a0fd6fa
[4130f8d]: https://github.com/powerman/lint-sensitive/commit/4130f8d47ce51d505410dbe5385e333b575226af
[b967a85]: https://github.com/powerman/lint-sensitive/commit/b967a85550ce6ebe4f61430552df609f179d4816
[b6d0077]: https://github.com/powerman/lint-sensitive/commit/b6d0077457bb31c181b50c68855b1de75cb308d5

## [0.7.0] - 2026-11-24

### 🚀 Added

- **(analyzer)** Add rsjethani/secret/v2.Text to default sensitive types by @powerman in [563ccb8]
- Add -sensitive.public for fields which never hold the secret by @powerman in [96bd305]

### 🔔 Changed

- **(analyzer)** Check types used only via pointer by the pointer method set by @powerman in [345b2c4]
- **(analyzer)** Ignore known secret-revealing methods by @powerman in [e84f92a]
- **(analyzer)** Ignore known non-secret fields in the structural check by @powerman in [7d15c10]
- **(analyzer)** Accept opaque structs for JSON and text marshal safety by @powerman in [0850afb]
- **(analyzer)** Recognise rsjethani/secret/v3.Text by default by @powerman in [66e123c]
- Recognise shoenig/go-conceal by default by @powerman in [7d5295d]
- Recognise rbranson/camo by default by @powerman in [311bbe4]

### 🐛 Fixed

- **(analyzer)** Ignore zero-length arrays in structural checks by @powerman in [eaa9a41]
- **(analyzer)** Judge a pointer to a safe type by the pointer's methods by @powerman in [2572f18]
- **(analyzer)** Require every field to be structurally protected by @powerman in [aef533b]
- **(analyzer)** Model fmt badVerb and defined pointer types in field walk by @powerman in [fd09fc8]
- **(analyzer)** Check defined pointer types by the element type by @powerman in [a169d45]

### 📚 Documentation

- **(README)** Clarify pointer leak example and document `require-*` check by @powerman in [bd80510]
- **(README)** Describe example as protected and unprotected values by @powerman in [654582d]
- **(README)** Name rsjethani/secret/v2 in the support table by @powerman in [04d3dd5]
- Describe optional safe-type interface check in README and package docs by @powerman in [c44bdf3]
- Align README with current structural protection rules by @powerman in [70fcb9b]

[0.7.0]: https://github.com/powerman/lint-sensitive/compare/v0.6.0..v0.7.0
[c44bdf3]: https://github.com/powerman/lint-sensitive/commit/c44bdf3868d151a81c9e77b91d3a15aaf50db48f
[bd80510]: https://github.com/powerman/lint-sensitive/commit/bd8051083dd464b60a03c1c81b2e07a4b9f31497
[eaa9a41]: https://github.com/powerman/lint-sensitive/commit/eaa9a419023be1d3e3d32bc4c8c82e20f0b6d20a
[563ccb8]: https://github.com/powerman/lint-sensitive/commit/563ccb8591f64d7d7782b2bba64b9dde27e7f33d
[654582d]: https://github.com/powerman/lint-sensitive/commit/654582da97311a5fc9c032e47de674537a45a018
[2572f18]: https://github.com/powerman/lint-sensitive/commit/2572f182e9d888d0e52a0d1d59d74892a2d994ac
[345b2c4]: https://github.com/powerman/lint-sensitive/commit/345b2c4f90fc264883b17acc2f7e01f27b934856
[e84f92a]: https://github.com/powerman/lint-sensitive/commit/e84f92af7b073483f295dd5c19124d54889de57f
[7d5295d]: https://github.com/powerman/lint-sensitive/commit/7d5295d54bc18a0fd659afb73ad8624e4459d64b
[aef533b]: https://github.com/powerman/lint-sensitive/commit/aef533b17ceb536369aa4bd246c2b472fce8848f
[7d15c10]: https://github.com/powerman/lint-sensitive/commit/7d15c1085f784b068b432f42ab47d2bc7e8b60a0
[311bbe4]: https://github.com/powerman/lint-sensitive/commit/311bbe4303880f92e0df5f083e062c14dd91ea66
[0850afb]: https://github.com/powerman/lint-sensitive/commit/0850afbfbd9491a7c1641beefde9d273627f6028
[96bd305]: https://github.com/powerman/lint-sensitive/commit/96bd305dd1d9ed5ea2a30c8b8a619543e0c865f8
[70fcb9b]: https://github.com/powerman/lint-sensitive/commit/70fcb9b2a9698eed3da2fbd15453b850627175c8
[fd09fc8]: https://github.com/powerman/lint-sensitive/commit/fd09fc8a09e3cba94e9b80456cfbf970ac8629b7
[a169d45]: https://github.com/powerman/lint-sensitive/commit/a169d45f74800a61410e52c7069c3e2742ae6258
[04d3dd5]: https://github.com/powerman/lint-sensitive/commit/04d3dd5f2788d4296926764b9eeaf1a7f75f475b
[66e123c]: https://github.com/powerman/lint-sensitive/commit/66e123c3c97b3ef7da949a99ee22ca8d359d6ecd

## [0.6.0] - 2026-11-23

### 🔔 Changed

- **(analyzer)** Hint at pointer-receiver-only methods in reliability diagnostics by @powerman in [085773d]
- **(analyzer)** Attach leak path to sensitivefields diagnostics by @powerman in [35dd1ca]
- Order tasks in mise.toml like the template by @powerman in [8d59bf4]

### 🐛 Fixed

- **(analyzer)** Wire -require-marshal-json flag to its config field by @powerman in [11efcb3]
- **(analyzer)** Honour skip-tests and skip-generated in reliability checks by @powerman in [2b27f50]
- **(analyzer)** Key walk memoization by fd/bp state by @powerman in [b7415a1]
- **(analyzer)** Treat pointer to non-compound named type as qualifier by @powerman in [903e6f0]
- **(analyzer)** Verify method signatures and ignore pointer-receiver-only methods by @powerman in [93070c0]
- **(analyzer)** Trust named types implementing fmt.Formatter as safe terminals by @powerman in [87135d5]
- **(analyzer)** Reword sensitivefields diagnostic by @powerman in [7a3a553]
- **(analyzer)** Skip anonymous structs nested in fmt.Formatter types by @powerman in [ceb162f]
- **(analyzer)** Do not label Formatter pointers as non-Formatter in leak path by @powerman in [048d3e0]
- **(analyzer)** Do not report a stale disable factor as the leak reason by @powerman in [1bbcb1c]
- **(analyzer)** Skip generated files with //line directives by @powerman in [ddaf4e3]
- **(analyzer)** Parse only exported identifiers as type entries by @powerman in [47b721c]
- **(analyzer)** Classify same-named local types separately by @powerman in [ad72bea]
- **(analyzer)** Print debug line for every generic instance by @powerman in [5fb1891]
- **(analyzer)** Check generic instances and aliases in reliability levels by @powerman in [321a7cd]
- **(analyzer)** Recognize named and nested structural protection by @powerman in [ea8f5b1]
- **(example)** Build with Go 1.27.3 by @powerman in [87937a7]
- Build with Go 1.27.3 by @powerman in [a00e9c1]
- Fail -V=full when the build ID cannot be computed by @powerman in [f62db45]

### ⚡ Performance

- **(analyzer)** Compute generated files once per pass by @powerman in [8afc870]
- **(analyzer)** Keep only the first position of each type in reliability check by @powerman in [3211d59]
- **(analyzer)** Cache method sets per pass by @powerman in [e61de45]

### 📚 Documentation

- **(analyzer)** Fix swapped debugPrinted comment by @powerman in [3d9dbf5]
- **(analyzer)** Fix stale Debug field doc by @powerman in [2348f41]
- **(analyzer)** Fix sensitivefields Doc to cover exported fields by @powerman in [581f6b2]
- **(analyzer)** Fix FlagAnalyzer doc comment by @powerman in [a53f0d6]
- Fix logfusc default type in package doc and README by @powerman in [87287a7]
- Fix semantic linefeeds in main.go comments by @powerman in [bb5db7c]

### 📦️ Dependencies

- **(deps)** Upgrade go and golangci-lint by @powerman in [eeafde6]
- **(deps)** Mise up by @powerman in [abcc21f]
- **(deps)** Upgrade go and golangci-lint by @powerman in [f97c978]
- **(deps)** Upgrade tools by @powerman in [73626a4]
- **(deps)** Upgrade go modules by @powerman in [748aeb6]
- **(deps)** Upgrade example powerman/sensitive to v0.7.0 by @powerman in [853071b]

[0.6.0]: https://github.com/powerman/lint-sensitive/compare/v0.5.0..v0.6.0
[eeafde6]: https://github.com/powerman/lint-sensitive/commit/eeafde676f71891d7f3c32166aef1e0eafd12592
[a00e9c1]: https://github.com/powerman/lint-sensitive/commit/a00e9c1290c572ea4057c41c174df61684242577
[87937a7]: https://github.com/powerman/lint-sensitive/commit/87937a7a0883c7e54e95e0a295b072666f841cdc
[abcc21f]: https://github.com/powerman/lint-sensitive/commit/abcc21f833aebe169bb61ac0f74e499b40b66f27
[8d59bf4]: https://github.com/powerman/lint-sensitive/commit/8d59bf421c86e083310ac0f829130d110a604c41
[f97c978]: https://github.com/powerman/lint-sensitive/commit/f97c978622612c5a4de12885f0f11764116d9505
[73626a4]: https://github.com/powerman/lint-sensitive/commit/73626a4ae793b304595be134b0ad23f16a78e39a
[748aeb6]: https://github.com/powerman/lint-sensitive/commit/748aeb646de4f41462d2f40ea6afbe766a1e9b1d
[11efcb3]: https://github.com/powerman/lint-sensitive/commit/11efcb39aa232adddeb0c95e4cfbc99dd25aa697
[2b27f50]: https://github.com/powerman/lint-sensitive/commit/2b27f50ea507371c5378a02fd1372b4ad82d10ca
[853071b]: https://github.com/powerman/lint-sensitive/commit/853071b1a2812d5e22bdb97ab8d3d4c6ca2ab93f
[b7415a1]: https://github.com/powerman/lint-sensitive/commit/b7415a12c2625df07a07178c269efcc322c4d19c
[903e6f0]: https://github.com/powerman/lint-sensitive/commit/903e6f0e90be9a2e0f1923f7138778e2192ff49c
[93070c0]: https://github.com/powerman/lint-sensitive/commit/93070c0519eee1362602bb61ec619c1bb0880968
[085773d]: https://github.com/powerman/lint-sensitive/commit/085773dc165d4412f7a52b51a200ff95a5927a11
[87135d5]: https://github.com/powerman/lint-sensitive/commit/87135d500af5f99c58bd68a42672653bc01e4236
[7a3a553]: https://github.com/powerman/lint-sensitive/commit/7a3a553496bb2d707c641f4eb8dc66cac9a2f6f4
[ceb162f]: https://github.com/powerman/lint-sensitive/commit/ceb162fe3ca7e8f7a0466a2f758466a4720adc26
[35dd1ca]: https://github.com/powerman/lint-sensitive/commit/35dd1ca25be2a9a36e63195c5cb214fdaf129007
[048d3e0]: https://github.com/powerman/lint-sensitive/commit/048d3e0f53025fb753780c23ac01628964b5f8cd
[3d9dbf5]: https://github.com/powerman/lint-sensitive/commit/3d9dbf5594546954ce306d0f0249dae0b47d23ed
[2348f41]: https://github.com/powerman/lint-sensitive/commit/2348f413e55c2db79d9867e52b547710cae330df
[8afc870]: https://github.com/powerman/lint-sensitive/commit/8afc8701e44d53cd29b701f21dafbac70b55a721
[3211d59]: https://github.com/powerman/lint-sensitive/commit/3211d59ebfe9ce20d28df766cf523159f3bb2745
[1bbcb1c]: https://github.com/powerman/lint-sensitive/commit/1bbcb1c23f5906a15380926628465c99d2930d00
[ddaf4e3]: https://github.com/powerman/lint-sensitive/commit/ddaf4e3f27e1a765b8e45c0805d426c9f12fabe5
[47b721c]: https://github.com/powerman/lint-sensitive/commit/47b721c6ccfebee5e8807794d883808cbef664ce
[f62db45]: https://github.com/powerman/lint-sensitive/commit/f62db45b74532eb4bbe8bad426b6a4a1f08a3f35
[ad72bea]: https://github.com/powerman/lint-sensitive/commit/ad72beaee8c88209527cb8036c01de2b8d988f79
[e61de45]: https://github.com/powerman/lint-sensitive/commit/e61de45ca9063afdda5d476e8be615dcfab2c9a2
[5fb1891]: https://github.com/powerman/lint-sensitive/commit/5fb1891867f0870f0b567461da1906d9e1a10ccd
[321a7cd]: https://github.com/powerman/lint-sensitive/commit/321a7cdaf7ebe0ac97512b7027f6223631c5b986
[ea8f5b1]: https://github.com/powerman/lint-sensitive/commit/ea8f5b16e6e44b803383f9e3d2d9097beb383068
[87287a7]: https://github.com/powerman/lint-sensitive/commit/87287a79698fb32b1e6d67aa292315606b52c862
[581f6b2]: https://github.com/powerman/lint-sensitive/commit/581f6b278acace4de98c2aa5592b80850abe3dd0
[a53f0d6]: https://github.com/powerman/lint-sensitive/commit/a53f0d64ee7d4061123c43ac6d832e64abbd1a96
[bb5db7c]: https://github.com/powerman/lint-sensitive/commit/bb5db7ce4b60af31b62a3b1d70047bf11995e8da

## [0.5.0] - 2026-10-16

### 🚀 Added

- Add Go 1.27 support by @powerman in [0dcd224]

### 📚 Documentation

- Update examples and support table for powerman/sensitive v0.6.0 by @powerman in [33168b1]

[0.5.0]: https://github.com/powerman/lint-sensitive/compare/v0.4.0..v0.5.0
[33168b1]: https://github.com/powerman/lint-sensitive/commit/33168b1bfbd5ed661179b32b79a12c270981fe94
[0dcd224]: https://github.com/powerman/lint-sensitive/commit/0dcd224be68ac6ae05407e6c6acc66e2d8a40167

## [0.4.0] - 2026-07-02

### 🔔 Changed

- Override -V=full flag to report real version instead of "devel" by @powerman in [289870c]

### 🐛 Fixed

- Handle .exe suffix in TestVersionFlag for Windows compat by @powerman in [e9f5968]

### 📚 Documentation

- Clean up footnotes in support table by @powerman in [3545780]

[0.4.0]: https://github.com/powerman/lint-sensitive/compare/v0.3.3..v0.4.0
[3545780]: https://github.com/powerman/lint-sensitive/commit/3545780da5d6e265c9c3e715beab48e8db3bd0a3
[289870c]: https://github.com/powerman/lint-sensitive/commit/289870cefa4934f64d393f26dee6a1b6bcbd85ec
[e9f5968]: https://github.com/powerman/lint-sensitive/commit/e9f5968c81b7c3820088663499aba58659856387

## [0.3.3] - 2026-07-02

### 🔔 Changed

- Update to powerman/sensitive v0.2.0 — Ref/Handle and pointer-to-compound leak by @powerman in [124a970]

### 🐛 Fixed

- Treat `*TypeParam` as qualifier when constraint excludes compound kinds by @powerman in [1cd1f8c]

### 📚 Documentation

- Add rsjethani/secret and andrewbenton/go-secrets to support table, add Related tools section by @powerman in [99ea773]

[0.3.3]: https://github.com/powerman/lint-sensitive/compare/v0.3.2..v0.3.3
[124a970]: https://github.com/powerman/lint-sensitive/commit/124a970890effade763f64c145b1fd6f8eebb2f3
[99ea773]: https://github.com/powerman/lint-sensitive/commit/99ea773a794d2d735fd7914b55df35416ba2e259
[1cd1f8c]: https://github.com/powerman/lint-sensitive/commit/1cd1f8c69ecdd173879e253d4c4f62ef8af6f711

## [0.3.2] - 2026-07-02

### 🐛 Fixed

- Only flag SecretExposer interfaces, not all interface types by @powerman in [ae4d15b]
- Eliminate duplicate -sensitive.debug output across packages by @powerman in [0a0605b]

[0.3.2]: https://github.com/powerman/lint-sensitive/compare/v0.3.1..v0.3.2
[ae4d15b]: https://github.com/powerman/lint-sensitive/commit/ae4d15b9e66e62a84212a77482218cdfe2bcbb31
[0a0605b]: https://github.com/powerman/lint-sensitive/commit/0a0605b15d6d6770c3e3643f48bb6aad0de59c8b

## [0.3.1] - 2026-07-02

### 🐛 Fixed

- Skip interface types when using package-only safe-type entries by @powerman in [beeb62f]
- Also skip unexported types in package-only safe-type entries by @powerman in [a8eb683]

[0.3.1]: https://github.com/powerman/lint-sensitive/compare/v0.3.0..v0.3.1
[beeb62f]: https://github.com/powerman/lint-sensitive/commit/beeb62f030ae21d253d5f99690febb8f9b5e5e45
[a8eb683]: https://github.com/powerman/lint-sensitive/commit/a8eb683e189579aa2b9ba44d6bf7df21d9bdfb9a

## [0.3.0] - 2026-07-02

### 🚀 Added

- Add config-driven reliability-level warnings by @powerman in [eb7e6db]

### 🔔 Changed

- Rework linter to Formatter-termination reachability model by @powerman in [92fb9b1]

### 🐛 Fixed

- Preserve disable factor through non-Formatter pointer walk by @powerman in [c2caa7e]

### 📚 Documentation

- Add existing-library-support table to reliability section by @powerman in [6f29ba0]

[0.3.0]: https://github.com/powerman/lint-sensitive/compare/v0.2.0..v0.3.0
[92fb9b1]: https://github.com/powerman/lint-sensitive/commit/92fb9b1aee0ff80a71045b004a051aa8cc452f1f
[eb7e6db]: https://github.com/powerman/lint-sensitive/commit/eb7e6dbf05d237c7c5ac0388ed75fbd6ee79af04
[c2caa7e]: https://github.com/powerman/lint-sensitive/commit/c2caa7e375d8e9909de47608e8dd3bc398dd4217
[6f29ba0]: https://github.com/powerman/lint-sensitive/commit/6f29ba00185eeb2186d0a235507078ff6a21508f

## [0.2.0] - 2026-06-30

### 🚀 Added

- Add Boxed[T] support, skip-tests and skip-generated flags by @powerman in [117852c]

[0.2.0]: https://github.com/powerman/lint-sensitive/compare/%40%7B10year%7D..v0.2.0
[117852c]: https://github.com/powerman/lint-sensitive/commit/117852cc60336abdaf701b898c71f324b803befb

<!-- generated by git-cliff -->
