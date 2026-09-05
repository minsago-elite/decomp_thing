# Local behavior records and archival revision attribution

`BehaviorComparator` writes schema-3 records with provider
`local-revision-bound-behavior-v3`. The decoder also accepts historical schema-1
records, which do not commit file inputs, and schema-2 records, whose corpus digest
includes host file locators. An archival comparison supplies an explicit
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

Schema 3's corpus digest commits the ordered case IDs, argv, stdin and declared
file names, lengths, digests and retained bytes. It excludes only each file's host
`sourcePath`, so restoring the same corpus at another host path preserves its
identity. Observations and the full report still commit the exact host locators
and sandbox mount arguments. Changing retained file contents changes the corpus
digest, even when the programs produce identical outputs. Environment and
executable identities remain separately bound by the full report commitment.

Callers may supply `expectedCorpusSha256` to `compare` or `evaluate` to require a
previously selected schema-3 corpus identity. The comparator copies cases and file
declarations, captures declared file contents, and checks the complete corpus digest
before executing either original or rebuilt program. A missing, reordered or changed
case, argv, stdin, logical file name or file content fails admission and leaves an
existing report unchanged. The expected digest must be lowercase SHA-256. Omitting
it keeps observation-only comparison available; a report's self-computed digest does
not establish that an external corpus policy was approved. Audit consumers must
independently apply their expected-corpus policy.

`ArchivalProjectAuditor.audit(..., requiredCorpusSha256 = setOf(expectedDigest))`
applies that policy independently to current revision-bound reports. Every selected
digest must have a schema-3 report; unrelated corpora and historical schemas cannot
satisfy the selection. Missing corpora appear as `missing-corpus:<digest>` problems,
and unrelated reports remain visible as problems rather than disappearing. The
audit records sorted `requiredCorpusSha256` and `observedPortableCorpusSha256`
lists. Missing or unrelated evidence prevents an all-pass summary. An empty selection
preserves observation-only auditing and does not imply a fixed corpus was required.
`ArchivalPackager.create(..., requiredCorpusSha256 = setOf(expectedDigest))`
snapshots the selection, runs the audit under it, and requires a passing result
before publishing the archive. A rejected selection preserves an existing archive.
The selected policy is retained in the archived audit; creating an archive with no
selection still uses observation-only auditing. Extraction validates payload and
source/build lineage but does not independently apply a caller corpus selection or
execute an archived program. Consumers must reapply their selected policy when
qualifying the extracted project after its clean rebuild and comparison.

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

Native timeout arguments preserve the selected milliseconds (`1900` becomes
`1.900s`), alongside the JVM watchdog. Historical integer-second command recipes
remain readable, but arbitrary durations do not satisfy the recorded policy.
The live timing regression requires a 1.2-second authored program to finish within
a 1.9-second policy with its expected output and exit status; equal timeout exits
cannot satisfy that assertion. Distinguishing native watchdog termination from an
application's own exit status still requires a separate completion signal in the
local execution contract.

Until that completion channel exists, execution and record decoding conservatively
reject wrapper statuses outside 0–123. This includes watchdog status 124, wrapper
errors 125–127 and signal-style statuses. Genuine application exits in the same
range also remain unqualified. Rejected runs preserve any prior report; archived
records with these statuses remain present and appear as unresolved audit problems,
even when both observations match and every commitment is internally consistent.
Accepting a lower status does not independently establish application completion:
wrapper setup failures may also use lower statuses. This guard is partial progress
on #354, not the separate execution-owner completion signal required by that issue.

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

For an accepted module, the audit requires its manifest-bound checkpoint to use
compiler acceptance schema 5, contain no reconstruction issues, and record exactly
the module plan's function/global owners once each with accepted status. It also
checks successful compilation of the current source under the profile's command.
Unsupported schemas, missing or foreign owners, duplicate owners and contradictory
acceptance details become `moduleCompilationEvidenceProblems` and leave the module's
entities unresolved. These consistency checks do not authenticate an external
reconstructor invocation or establish execution coverage.

Reconstruction resume applies the same module acceptance constraints before reusing
an accepted checkpoint or supplying it as a rollback baseline. The checkpoint reader
also rejects entity statuses that contradict the top-level acceptance flag. Invalid
acceptance requires reconstruction again; a newly validated replacement can then be
reused normally. Historical checkpoints without compiler acceptance schema 5 do not
supply accepted rollback evidence.

The authored four-module resume fixture generates actual C calls along a
leaf/middle/root dependency chain, plus an unrelated module. After initial build
and audit, changing the leaf interface regenerates its consumers. An interruption
at the root preserves completed leaf/middle checkpoints; resume invokes only the
root and keeps the unrelated checkpoint unchanged. The final audit checks source
hashes independently of confidence records. Packaging, extraction, a clean rebuild
and a fresh consumer audit reproduce the same module revisions and successful
compiler evidence while leaving behavior and coverage explicitly unknown. This
tests a local scripted reconstructor, not authenticated external-agent restart or
behavior-driven repair convergence.

The web views present source-tree scores as reported structural heuristics and
exploration scores as exploration heuristics, explicitly uncalibrated. They use
decimal scores rather than confidence percentages; a missing or out-of-range
exploration score is unavailable. CLI exploration summaries use the same
uncalibrated terminology. Stored `confidence` fields remain compatible with the
existing report formats. These labels do not supply the empirical calibration,
validated assessment contract or evidence-gated equivalence required by #42.

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

The earlier behavior/audit/archive/reconstruction/profile checkpoint passed 42
focused tests. Bubblewrap was unavailable at that checkpoint; its two live runner
failures were not counted as successful containment verification.

The current `BehaviorValidationTest` includes a live bubblewrap file-input case.
An authored original and a generated, rebuilt project read binary and empty files,
report failed attempts to open the mounted files for writing, and observe an
undeclared file as absent in the next case. Assertions check expected exit codes
and exact bytes independently of original/rebuilt equality. The project audit
then verifies the current source/build/executable attribution of the retained
record. At the live-mount checkpoint, the focused behavior validation/evidence/file-input selection passed
22 tests with zero failures or skips on a host with bubblewrap 0.11.2. This verifies
these local mount behaviors, not production containment attestation.

The large authored archival fixture (121 functions, at least nine modules) also
declares its file case through `/inputs/sample.txt`. Its assertions require exit 0
and `from-file:25` output; comparing two file-open failures is insufficient. The
test retains the input bytes in the report, creates identical archives, removes
the original host input, extracts and rebuilds the archive, then restores the input
from the extracted record and repeats the corpus. Both runs check explicit expected
stdout, stderr and exits for stdin, argv, file and exit-code cases. The focused
large/small archive and live-file selection passes three tests with zero skips.
The archive replay also requires an identical schema-3 corpus digest after host
input relocation; execution observations retain their distinct mount locators.
Both initial execution and replay use the fixed authored corpus digest
`d916ad4bd5f3aeb8a039cfc9a5a8d6c4d63ad1afd44af43d078589bb671ffc74`
for pre-execution admission, rather than deriving the required identity from the
newly produced report.
After clean rebuild and replay, the consumer independently audits the extracted
project under that same fixed policy and requires the replay report to be recognized.
A negative check then changes the stored audit to claim unsupported corpus coverage:
the consumer audit recomputes coverage from behavior records, reports the missing
corpus, and refuses repackaging under the unsupported selection. Archived audit
claims do not supply the consumer's policy or replace current revision checks.

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
