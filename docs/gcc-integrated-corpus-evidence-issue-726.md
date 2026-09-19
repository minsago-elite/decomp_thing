# GCC integrated corpus evidence — issue #726

This is a small evidence record for the checked GCC 16.2.0 driver reference
corpus. It records what is retained today; it does not certify an integrated
reconstructed GCC candidate.

## Bound reference inputs

| Record | Repository path | SHA-256 or identity |
| --- | --- | --- |
| GCC source lock | `oracle/gcc/16.2.0/source-lock.json` | `e2930ecc9748b40e56d6fe09dbe88f21f735953d4e6da50403f2cc0aa5b650cc` |
| GCC source revision | `oracle/gcc/16.2.0/source-lock.json` and `build-record.json` | `releases/gcc-16.2.0` / `78d4ac73dd391005b895a6148cd9831e28e1208b` |
| Build record | `oracle/gcc/16.2.0/build-record.json` | `f91a68ffde054b9598cba8506bbf6b3b373b35b8680fddb54f76bffa9db23637` |
| Oracle manifest | `oracle/gcc/16.2.0/oracle-manifest.json` | `c9e21c5a6422c65572ee4c4de5578107b82ae92b6730536c4fc76490fe2ecad9` |
| Versioned corpus | `oracle/gcc/16.2.0/behavior-corpus.json` | `gcc-16-2-0-driver-behavior`, `bcc1a14ca8c54f94106c943f0bc5698cb9af3151b7bf20a49ae3c8828baaad0e` |
| Retained report | `oracle/gcc/16.2.0/behavior-corpus-evidence.json` | `9dcf787aea232615a1ff8721144b86bc1f5e9a2a7068fa9e9280db0bc4ad6803` |

The corpus is production-scoped for the authenticated GCC driver oracle, and
contains 14 cases with zero normalizations. The corpus retains exact argv,
environment, stdin, staged inputs, and expected observations. The report
retains exact exit, stdout, stderr, and artifact observations. All 14 retained
reference cases are reported as `passed`.

## Exact retained reference observations

The table records the report's per-case exit code, stream byte count and
SHA-256, plus each declared artifact's presence, byte count and SHA-256. A
dash means that the case declares no artifact. The full base64 bytes remain in
the retained report named above.

| Case | Exit | stdout | stderr | Artifacts |
| --- | ---: | --- | --- | --- |
| `assembly-file` | 0 | 0 `e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855` | 0 `e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855` | `assembly.o` present, 15 `e5e021333c0fd167a18f93780b1a03bc65f0aef311d0232b24e6a2d06153e9a5` |
| `compile-file` | 0 | 0 `e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855` | 0 `e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855` | `file.o` present, 15 `e5e021333c0fd167a18f93780b1a03bc65f0aef311d0232b24e6a2d06153e9a5` |
| `compile-stdin` | 0 | 0 `e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855` | 0 `e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855` | `stdin.o` present, 15 `e5e021333c0fd167a18f93780b1a03bc65f0aef311d0232b24e6a2d06153e9a5` |
| `diagnostic-invalid-input` | 1 | 0 `e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855` | 34 `fc6d35d325e7984d3b9bd91720f37631f04cac325ba8460aedd13376ec5125a8` | `missing.o` absent |
| `diagnostic-invalid-option` | 1 | 0 `e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855` | 153 `525b39acc7388841c74e1411725f7d2207b6a1f5214f691b938492cf09e1416c` | — |
| `environment-search-path` | 0 | 18 `b8a1f8e4208ed2055f683bd08a081ad8b794b7f88145b0a35d0693f18b04d178` | 48 `70330cf554b95c6419d4365bc45ea0d26cf8c83d89d8a1846c2f749a3068294a` | — |
| `help-driver` | 0 | 4082 `7a0250d66493c38ea6051e3492bf59779f6b43d516856299f73be753fc30a1b2` | 0 `e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855` | — |
| `linking` | 0 | 0 `e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855` | 0 `e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855` | `linked.bin` present, 19 `611d8ceedfe67437b495a97682eaf5818f93b4c93eedbcddf72737c24b4f303a` |
| `metadata-dumpmachine` | 0 | 20 `1c7da408e283702561a445e700b61c0f55a082230a3cfe323208841221274a6a` | 0 `e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855` | — |
| `metadata-dumpversion` | 0 | 7 `e9f8839c742db21d285464b01dfb2e572f802c366729873cdc4a296c8c3a01ea` | 0 `e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855` | — |
| `metadata-version` | 0 | 222 `dfdb19fc0bd5dcd763e010d1956430a417224539109108f61b231d1a296371ab` | 0 `e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855` | — |
| `preprocess-file` | 0 | 18 `b8a1f8e4208ed2055f683bd08a081ad8b794b7f88145b0a35d0693f18b04d178` | 0 `e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855` | — |
| `preprocess-stdin` | 0 | 18 `b8a1f8e4208ed2055f683bd08a081ad8b794b7f88145b0a35d0693f18b04d178` | 0 `e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855` | — |
| `response-file` | 0 | 0 `e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855` | 0 `e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855` | `response.o` present, 15 `e5e021333c0fd167a18f93780b1a03bc65f0aef311d0232b24e6a2d06153e9a5` |

## Qualification boundary

This record's reference denominator is 14 cases: 14 are retained and passed.
The integrated reconstructed-candidate denominator is unresolved, candidate
observations are 0, compared cases are 0, and qualification remains blocked.

The production gates unavailable in the checked repository state are:

- an accepted complete reconstructed GCC driver tree/archive;
- accepted reconstructed `cc1` and `lto1` archives with production structural
  qualification;
- an integrated candidate run retaining the required per-case lifecycle and
  artifact observations; and
- an authenticated candidate/reference comparison with explicit denominators.

The current report schema has no retained per-case signal, timeout, or
subprocess-lifecycle fields, so those observations remain unresolved here.
The checked GCC profile is a driver reference benchmark: its matching `cc1`,
assembler, and linker tree is not part of the oracle pair. This record does
not grant ACP, Ghidra, or any candidate process authority over oracle truth;
the bundled Ghidra and authenticated oracle boundaries remain unchanged.
