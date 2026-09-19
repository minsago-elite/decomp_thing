# C++ name resolution evidence v1

`cpp-name-resolution-evidence-v1.json` preserves one existing program-model
fact from `ProgramModelTest.fixtureModel`: input digest `abc123`, function
identity `fn_0000000000401020`, name `render_page`, address `0x401020`,
prototype `int render_page(void)`, and extraction status `partial`.

The `render_page` value is the current generated-C sanitation result from
`safeCName`. It is retained as a candidate only. The record stays
`cppResolution: unresolved` because `RecoveredFunction` does not carry C++
namespace, overload, or type identity. The record therefore preserves model
provenance and an unresolved state without inventing an original C++ name.

This is a contract/evidence slice, not production C++ name resolution. The
remaining production gap is a frozen identity-driven name table integrated with
emission and reference binding, including owner-scoped anonymous/local names,
sanitization collision reports, aliases and incompatible types, namespace or
module moves, and shuffled multi-module qualification.

Unavailable production gates for this slice are the authenticated oracle
mapping, a bundled-Ghidra-backed production export, and a strict clean
multi-module C++ build/replay. This record invokes neither Ghidra nor an
external `GHIDRA_HOME`/`analyzeHeadless` installation, and it grants no oracle
authority. The existing extraction status remains historical evidence rather
than a scored recovery assessment.

Sources: `src/test/kotlin/decompengine/project/ProgramModelTest.kt` and
`src/main/kotlin/decompengine/project/GeneratedCDeclarations.kt`.
