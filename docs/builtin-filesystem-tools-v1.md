# Built-in filesystem tools v1

The built-in dispatcher now offers typed `read_text`, `write_text` and `search_text` calls.
Each call identifies a declared workspace root and normalized relative path. The dispatcher
translates this path to the existing ACP filesystem callback; it does not implement its own
filesystem access. JSON schemas reject unknown fields and malformed arguments before dispatch.

`read_text` returns bounded UTF-8 text. `write_text` replaces authorized candidate text through the
shared callback. `search_text` performs a literal query over one authorized bounded read, returns
at most 100 matching lines and explicitly reports omitted matches. Search has no regex execution
or directory walk. Result serialization and file content have explicit byte limits.

`BuiltinCapturedRepairHarness` implements the existing `CapturedRepairAgentHarness` seam. It is
usable by `CapturedRepairStagingAuthority`: initial files and writable paths are supplied by that
authority, and writes reach its `BoundedRepairOutput` sink through `AcpCapturedRepairFilesystem`.
The namespace-only anchor is never accessed on the host. Exact readonly oracle rules and file,
patch and staging limits remain under the existing authority. Ordinary host-backed execution of
this captured harness fails with a configuration result; it cannot silently fall back to a host
workspace. The production harness factory remains ACP-only pending C1 qualification.

Invocation evidence wraps the loop receipt with immutable shared filesystem audit records and
final candidate change hashes. Callback audit session identifiers are the stable built-in call
IDs. Captured sessions close before final candidate hashes are read. Refused and failed turns
retain candidate changes too; these changes do not become accepted revisions. Successful model
completion yields `VALIDATION_REQUIRED` until the surrounding workflow performs its independent
source, compile, behavior and lineage checks.

## Verification and remaining scope

```bash
./gradlew --offline test --tests 'decompengine.builtin.*' --tests 'decompengine.agent.*' \
  --tests 'decompengine.acp.AcpCapturedRepairFilesystemTest' --console=plain
```

Paired deterministic tests feed equivalent read/write operations to typed and direct ACP captured
callbacks, then compare exact candidate bytes, changed-file records and all decision-audit fields.
Additional tests cover readonly oracle denial, escaped paths, input/output size limits, bounded
search, and hashes retained after refusal or provider failure. A live local test passes the same
typed dispatcher an `AcpFilesystemBroker` and proves actual descriptor-contained reads, atomic
writes, policy denial and symlink rejection alongside direct ACP callbacks.

#74 remains open. General host-directory inspection, general patch operations, terminal permission
parity and full sandbox cancellation/cleanup qualification remain incomplete. Profile-bound process
operations are documented in [the process contract](builtin-process-tools-v1.md); they still require
positive hosted evidence and production profiles. Durable archive/restart integration is #75;
full reconstruction/repair acceptance, factory selection and comparative release evidence remain
C1/C2 work. The captured integration is a usable shared tool boundary, not a completed production
repair workflow or a release verdict.

## Captured directories and immutable evidence

`BuiltinCapturedContextTools` adds three read-only tools to the captured harness. `list_directory`
lists sorted direct children of the authority-supplied virtual workspace, restricted by the same
`AgentAccessPolicy` read rules; it never walks host directories or reveals write-only/undeclared
files. `list_evidence` pages immutable request-context IDs, media types, byte counts and hashes.
`read_evidence` returns bounded text pages with the complete input hash and an explicit next offset;
page boundaries preserve Unicode surrogate pairs. Unknown IDs and invalid offsets fail explicitly.

These tools serialize under the existing tool-result byte ceiling and retain bounded metadata-only
call/result-hash audits in the captured execution receipt. Source bytes, directory contents and
evidence are read-only inputs; the tools cannot certify oracle truth or accept a revision.
Six additional tests cover sorted/policy-restricted directories, evidence pagination and hashes,
Unicode-safe boundaries, invalid paths/offsets, output/audit exhaustion and actual loop routing.
The required core inventory is versioned as v2 with these six additional cases. This component is
retrieval support for #75; deterministic context selection, durable transcript/checkpoint recording
and validated restart still need implementation.
