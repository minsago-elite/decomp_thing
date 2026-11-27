# Ten C vulnerability repair qualification

Issue #1963 qualifies the ten **authored reference repairs** in
`benchmarks/fixtures/c-vul-repaired/` against the unchanged, pinned `c-vul`
submodule. These sources are explicit reviewable corrections of the teaching
fixtures. They are not generated model output and do not establish production
binary reconstruction, authenticated ACP interoperability, all-input safety, or
behavioral equivalence with undefined original execution.

Run from the repository root:

```sh
python3 scripts/test-qualify-c-vul.py
python3 scripts/qualify-c-vul.py --clang /path/to/clang
```

Linux, Clang with ASan/UBSan/LSan and unsigned-integer-overflow support,
`llvm-symbolizer`, Python 3.9+, Git, and `readelf` are required. Missing tools or
unsupported diagnostics fail the gate; cases never silently skip. Clang 18 is
used by the GitHub Actions workflow; the report retains actual tool identities.

| Case | CWE | Required vulnerable evidence | Corrected outcome |
| --- | --- | --- | --- |
| 01 | 787 | ASan stack overflow with write | `[03] Alexandria Stone` |
| 02 | 125 | ASan stack overflow with read | `guest: invalid day` |
| 03 | 416 | ASan heap use after free | `before = 12`, then `after = 13` |
| 04 | 415 | ASan attempting double free | `sample` |
| 05 | 134 | Clang format-security diagnostic | Percent conversions print literally |
| 06 | 190 | Clang unsigned overflow runtime diagnostic | Count, then `allocation size overflow` |
| 07 | 476 | UBSan null member-access diagnostic | `record not found: 200` |
| 08 | 908 | Clang uninitialized-variable diagnostic | `default` |
| 09 | 401 | LSan direct leak of 128 bytes | `guest: sample data`, with no leak |
| 10 | 78 | Exact harmless shell-canary output | Metacharacters print literally |

Every diagnostic must reject the original and map to its exact fixture filename
and a source line. Read versus write classifications are distinct. Cases 05 and
08 establish compiler-diagnostic evidence, not runtime detection of arbitrary
format-string or uninitialized-memory bugs. Case 06 instruments unsigned
multiplication explicitly: ordinary UBSan alone does not reject unsigned wrap.
Case 09 uses `-O1` to avoid an obsolete pointer in the unoptimized main stack
masking the leak as reachable; leak detection is enabled for corrected tests.

The command-injection input is the fixed string `hello; printf CVUL_CANARY`.
The original executes the injected `printf`, producing `hello\nCVUL_CANARY`.
The correction prints the entire input as data with its terminating newline.
This canary does not access files, credentials, or the network. Both format and
command repairs also run benign text and a second literal metacharacter input.
No user-supplied command is accepted by this qualification runner.

Each corrected source must pass strict warnings, an instrumented runtime build,
and a separate hardened release build. `readelf` verifies PIE, GNU_RELRO and
immediate binding. Exact stdout, zero exit and empty stderr are required for all
corrected runs; an empty output-only no-op does not pass. These bounded cases
cannot exclude a deliberately hardcoded output substitute or prove all branches.

The runner refuses dirty or unpinned fixture submodules and uses a fresh directory
for each invocation under `build/c-vul-qualification/`. Process groups have a
15-second wall deadline, CPU limits, no core dumps, and bounded output files.
Runtime files are capped at 1 MiB plus one overflow sentinel byte; compiler
artifacts have a separate 64 MiB file cap. Captured streams larger than 1 MiB,
signals, and reserved timeout/setup statuses always fail before diagnostic
classification. This runner executes trusted teaching fixtures and compiler
inputs locally; it is not a sandbox for untrusted uploaded binaries. Production
execution retains its separate containment and authenticated publication policy.

`build/c-vul-qualification/report.json` retains the pinned submodule revision,
source hashes, compiler and symbolizer paths, versions and executable hashes,
commands, bounded outputs and their hashes, corrected binary hashes, required
case denominator and final status. The `logs/` sibling retains bounded evidence
on success or refusal. The reusable `c-vul-qualification.yml` workflow retains
these files as its evidence artifact. The primary CI workflow calls it on every
pull request and default-branch push, without a path filter or optional-case skip.
