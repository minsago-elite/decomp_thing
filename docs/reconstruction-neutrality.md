# Reconstruction neutrality regression gate

`scripts/check-generic-leakage.sh` runs the lexical gate for
[#84](https://github.com/minsago-elite/decomp_thing/issues/84). Findings are
errors, including C/Make policy that the previous shell check only warned about.

```sh
scripts/check-generic-leakage.sh
python3 -B scripts/check-generic-leakage.py --json
./gradlew --no-daemon verifyReconstructionNeutrality
python3 -B -m unittest discover -s tests -p test_generic_leakage.py -v
```

The scanner requires Python 3.9+ and Git. The standalone Gradle task runs the
scanner without compiling or executing application code. Gradle `check` and
`scripts/ci.sh` include it. Exit status is 0 for no findings, 1 for findings, and
2 for invalid policy or unreadable inputs. JSON output contains either the scan
counts and sorted findings or an `error` field. Findings include path, line,
rule, and matched text.

## Ownership and exceptions

`oracle/gcc/reconstruction-neutrality-policy.json` declares generic source surfaces and
the benchmark-owned repository/JVM namespaces. The policy resides under
`oracle/gcc` because its exact exceptions contain benchmark target literals. Benchmark version strings,
quoted target names, and recorded SHA-256 identities are checked across all
supported files outside those namespaces. The identity catalog itself lives
under `oracle/gcc`; it records known benchmark artifacts, not arbitrary hashes.

Within generic surfaces, rules detect selected C/header suffix operations,
source/include and build-output paths, Make/Ninja/compiler names, C flags, and
concrete adapter references. The benchmark-version rule also recognizes
`GCC_VERSION=` assignments, and the inventory scans Dockerfile variants such as
`Dockerfile.dev` and `Dockerfile.ci`. Each concrete adapter exemption names one
exact file with its ownership rationale. A new `GeneratedC` filename does not
acquire an exemption. Adapter ownership never exempts benchmark identity rules.

Compatibility defaults, closed adapter dispatch, and an installed compiler
runtime component use exact literal allowances with a rule, expected occurrence
count, and rationale. An allowance suppresses only matches entirely contained
in its literal fragment. Duplicate, overlapping, stale, unused, or out-of-scope
allowances fail the gate. Generic and benchmark roots must be disjoint. Missing
declared paths and unsupported policy fields also fail. Ownership changes
therefore require an explicit policy review.

## Scope and limits

The inventory includes tracked files and nonignored untracked files. Ordinary
unstaged deletions are omitted; declared policy paths must still exist. Ignore
patterns do not exempt tracked files. The scanner supports the source, script,
configuration and text suffixes listed in `TEXT_SUFFIXES`, plus Dockerfiles.
Markdown documentation is exempt under #84. Unsupported binary formats are not
decoded. This is a working-tree lexical check, not a semantic proof or an atomic
repository snapshot; comments can match and indirect policy can escape a rule.

Admission limits are 20,000 inventoried paths, 16 MiB per decoded file and
128 MiB of scanned content. Git inventory has a 30-second timeout; its output is
buffered before the path-count check. These limits do not establish a hard
whole-process memory bound. Supported inputs must be UTF-8 regular files with
ordinary directory ancestors.

## Current migration state

The initial repository run fails on remaining policy and ownership migrations.
Examples include direct Make dispatch in `ReconstructionPipeline`, Doctor/MVP
compiler assumptions, repair runtime policy, benchmark scripts/tests/workflows, and retained historical
benchmark identities in LLVM reference evidence. Retained evidence must not be
rewritten merely to satisfy the scanner.

Passing the authored scanner tests verifies its detection and exemption
behavior. It does not make the repository scan pass or complete #84. Current
scope and progress remain on the issue; the draft gate layer is not ready for
integration while these findings remain.
