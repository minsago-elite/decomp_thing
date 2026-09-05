# Local behavior records and archival revision attribution

`BehaviorComparator` writes schema-2 records with provider
`local-revision-bound-behavior-v2`. The decoder also accepts historical schema-1
records, which do not commit file inputs. An archival comparison supplies an explicit
`BehaviorProjectContext(projectDir, profile)`. Comparisons without a project
context retain their observations, but cannot validate an archival revision.

The producer captures the original and rebuilt executable sizes and SHA-256
digests before execution. It also captures the selected bubblewrap and timeout
executables, including their locators. File identity and content are checked
before and after each execution and again before atomic report publication.
Case arguments and stdin bytes are copied before execution. A detected input
change aborts publication and preserves an existing report.

The optional `fileInputs` argument maps case IDs to maps of relative input names
and host file paths. For example, `mapOf("file-case" to mapOf("data/input.bin" to
inputPath))` requests a read-only mount at `/inputs/data/input.bin` for that case;
the caller supplies that sandbox path in argv when needed. Names must be normalized,
at most 256 characters and 16 components, and cannot conflict with parent directories.
Only declared files are admitted; directory trees are not implicitly enumerated.
The comparator copies the declarations, retains exact file bytes as lowercase hex,
and records their names, host locators, lengths and SHA-256 digests. It includes these
records in the corpus and observation commitments. A maximum of 1,024 file declarations
and 8 MiB of retained content applies across the complete case sequence, counting
repeated declarations. Missing, linked, special or oversized files fail before execution.
Declared files participate in the same pre/post execution stability checks as binaries.
The decoder recomputes content digests and read-only mount argv without reopening host
locators. Retained file bytes remain auditable after the host input files are removed.
Declarations and mount requests do not prove that a program read every declared file.

Project capture checks the schema-3 source manifest against its selected profile
and every declared file. The original executable digest must match the project
input. The successful schema-2 C/Make build contract must identify the current
source inputs and the exact `build/reconstructed` bytes selected for comparison.
Source inventory includes `Makefile` and regular files beneath `src` and `include`,
using the existing build revision encoding. Enumeration rejects symbolic links,
special files, excessive entry counts and excessive depth. The project revision
records relative file identities, manifest/build-contract identities, the source
revision and the built artifact identity. Project capture is repeated at the end.

Each record retains argv, stdin, stdout, stderr and exit values, and commits the
complete supplied case sequence separately from its observations. The report
commitment covers those values, executable identities, project revision and
execution policy. The policy records environment, working directory, requested
network isolation, a positive whole-millisecond timeout, stream limits and the
comparison output limit. The decoder checks closed field sets, JSON types,
duplicate keys, canonical lowercase byte encodings, unique case IDs, every
comparison flag, source-revision encoding and all commitments. It also reconstructs
the expected sandbox argv and checks output sizes against the recorded limits.
A rehashed contradictory report still fails validation.

The record limits are 1,024 cases, 8 MiB of stdin, 1 MiB of argument bytes and
16 MiB of comparison output. Captured input files are limited to 64 MiB each,
512 MiB in total and 10,000 tracked paths. Source enumeration has a 10,000-entry
limit and depth 32 beneath each source root. JSON has a 64 MiB input/rendering
limit, depth 32, one million nodes and a 16 MiB per-string limit.

## Archival audit behavior

The auditor inventories behavior-report paths within the archive profile's entry
and byte limits, decodes each report and compares its revision to current project
inputs and built executable. It rechecks report bytes, inventory and project
revision before publishing. Absolute executable locators in a report do not
authorize the auditor to read external files: the original input is identified
by the manifest digest, and the rebuilt file comes from the current project.

Missing, malformed, legacy, unbound, contradictory, duplicate-ID and stale reports
remain visible in `behaviorEvidenceProblems` and `unresolvedBehaviorReportIds`.
Their presence prevents an all-pass summary. A verified mismatch produces false;
otherwise incomplete evidence produces null. An empty corpus or empty report
collection cannot produce a pass. Deleted report collections produce an explicit
`no-behavior-evidence` finding.

Current module hashes are emitted as `moduleSourceRevisions`. Qualified report
paths appear separately in `projectBehaviorReportIds`. `moduleBehaviorEvidence`
stays empty and `moduleExecutionCoverage` is `not-observed`, because a project
comparison does not establish which individual modules executed.

`sandboxReported` describes a checked execution request. The audit leaves
`networkIsolationObserved` empty and states the assurance scope explicitly.
The record's legacy `networkIsolated` fields retain the requested configuration;
they do not establish a retained namespace or production containment receipt.

## Verification and remaining scope

Authored C fixtures and an explicitly authored runner shim exercise successful
record creation, current revision matching, changed source/executable rejection,
mutation during comparison, prior-report retention, unbound and absent evidence,
malformed/linked/legacy reports beside a pass, excessive source depth, and rehashed
flag/command/policy contradictions. The shim executes only the authored fixture
programs and does not qualify bubblewrap containment. Existing real-bubblewrap
integration cases require that executable on their test host.

The focused behavior/audit/archive/reconstruction/profile selection, including
the missing-sandbox and capability-probe checks, executes 42 tests with no failures
or skips. The two existing live `SandboxRunnerTest` cases fail on this host because
`/usr/bin/bwrap` is unavailable; those failures are retained separately and are not
counted as successful containment verification.

These records describe local path-stability checks. They do not retain an
execve-bound executable capability or an immutable runtime-library closure across
execution, and do not prove exclusion of same-user replace-and-restore races.
The C/Make build record is locally checked evidence, not an independent build
attestation. Implicit file-input trees and externally fixed benchmark-corpus admission
remain unimplemented. File mounts still use host paths, so retained contents and local
pre/post checks do not prove immutable mounted bytes throughout execution. Production execution, recovery and release
authority remain governed by the oracle and repair boundaries.

Consequently this checkpoint advances #36/#37 without completing their execution
provenance dependency or the A5 milestone.
