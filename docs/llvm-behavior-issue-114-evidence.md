# Issue #114 evidence record

This is a bounded evidence record for the open A-series tracker. It records
facts already authenticated by the checked LLVM 22.1.6 repository artifacts and
the Kotlin verifier; it does not promote historical evidence into production
fidelity evidence.

## Retained reference facts

`LlvmBehaviorReferenceEvidenceVerifier.verify` authenticates the raw corpus,
report, diagnostic matrix, and artifact manifest as one tuple. The checked
tuple contains 48 ordered cases and 16 diagnostic ownership records. The
corpus declares no output normalizations, so the retained observations remain
raw bytes. Its case categories include the workflows named by #114:

| Workflow fact | Cases in the checked corpus |
| --- | ---: |
| diagnostics | 16 |
| preprocessing | 11 |
| file compilation | 4 |
| code generation | 2 |
| dependency output | 1 |
| emitted artifacts | 16 |

These counts are derived from the checked
[`behavior-corpus.json`](../oracle/llvm/22.1.6/behavior-corpus.json); the
Kotlin reference verifier binds the complete case membership, expected
streams, expected artifacts, matrix policy, sandbox digest, and stripped
executable identity before returning evidence.

The corresponding Kotlin candidate assessment compares a caller-supplied
observation document against that authenticated tuple and derives persistent
case/mismatch identities. Its authority is
`non-authoritative-caller-supplied-observations-v1` and its
`releaseEligible` value is always `false`.

## Production boundary

This record does not claim that Clang or a reconstruction ran. The following
production gates remain unavailable and keep #114 open:

- The checked v1 corpus is historical. The Kotlin v2 input plan supplies input
  intent only; a fresh v2 runtime, reference executable, and repeated captured
  observations are still required.
- The candidate assessment does not execute a candidate or prove that the
  caller supplied bytes came from it. Authenticated ACP lineage and hosted
  clean-build binding remain the #140 prerequisite.
- The candidate execution admission and runtime preflight stop before `START`.
  A Kotlin-owned runner still needs bounded collection, comparison, cleanup,
  and terminal absence proof under the authenticated isolation policy.
- Repeated reference/reconstruction replay, persistent mismatch accounting,
  fidelity scoring, and the fail-closed release gate are not established by
  this record.

No Ghidra adapter or external `GHIDRA_HOME` dependency is introduced here;
bundled Ghidra isolation and the authenticated oracle boundary remain outside
this evidence slice.
