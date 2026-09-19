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
scanner without compiling or executing application code. While the repository
scan still fails on remaining migrations, the draft gate stays standalone: it is
not wired into Gradle `check` or `scripts/ci.sh` until those findings are
resolved. Run the standalone task explicitly when validating the neutrality
policy. Exit status is 0 for no findings, 1 for findings, and 2 for invalid
policy or unreadable inputs. JSON output contains either the scan counts and
sorted findings or an `error` field. Findings include path, line, rule, and
matched text.

## Ownership and exceptions

`oracle/gcc/reconstruction-neutrality-policy.json` declares generic source surfaces and
the benchmark-owned repository/JVM namespaces. The policy resides under
`oracle/gcc` because its exact exceptions contain benchmark target literals. Benchmark version strings,
quoted target names, and recorded SHA-256 identities are checked across all
supported files outside those namespaces. The identity catalog itself lives
under `oracle/gcc`; it records known benchmark artifacts, not arbitrary hashes.

Within generic surfaces, rules detect selected C/header suffix operations,
source/include and build-output paths, Make/Ninja/compiler names, C flags, and
concrete adapter references. Each concrete adapter exemption names one exact
file with its ownership rationale. A new `GeneratedC` filename does not acquire
an exemption. Adapter ownership never exempts benchmark identity rules.

Compatibility defaults, closed adapter dispatch, and an installed compiler
runtime component use exact literal allowances with a rule, expected occurrence
count, and rationale. An allowance suppresses only matches entirely contained
within its declared literal.
