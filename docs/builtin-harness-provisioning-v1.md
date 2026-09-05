# Built-in captured harness provisioning v1

`BuiltinHarnessProvisioning.load` is the internal application configuration seam for captured repair.
It creates a frozen selection that constructs the existing `OpenAiCompatibleModelProvider`, captured
filesystem/context tools, bounded loop and per-attempt journal factory. Selection binds factory
provenance once, before invocation; a caller-supplied provider with labeled journal metadata cannot
acquire that binding. The shared CLI/web resolver remains unchanged until the built-in workflows can
satisfy their acceptance and archive-lineage requirements.

The input is an absolute normalized path to a current-user-owned, single-link regular file with no
group/other permissions. The descriptor-bound reader is shared with ACP provisioning and preserves
its identity, size, timestamp, no-follow and mutation checks. Built-in files are capped at 64 KiB and
parsed as strict UTF-8 JSON with duplicate rejection and bounded depth/nodes/string/numeric lengths.
All fields below are required; unknown fields and coercions such as string-valued numbers fail.

```json
{
  "schemaVersion": 1,
  "provider": {
    "kind": "openai-compatible",
    "baseUrl": "https://provider.example.invalid/v1",
    "model": "configured-model",
    "apiKeyEnvironment": "BUILTIN_PROVIDER_API_KEY"
  },
  "journal": {
    "directory": "/private/operator/project-journals",
    "maximumBytes": 67108864,
    "maximumRecordBytes": 8388608,
    "maximumRecords": 10000
  },
  "loop": {
    "maxContextBytes": 2097152,
    "maxToolResultBytes": 262144,
    "maxIdenticalActions": 3,
    "maxTraceRecords": 4096,
    "maxInputTokens": 1000000,
    "maxOutputTokens": 128000,
    "maximumEvidenceBytes": 33554432,
    "contextHistoryReserveBytes": 524288,
    "provider": {
      "connectTimeoutMillis": 10000,
      "requestTimeoutMillis": 60000,
      "streamIdleTimeoutMillis": 30000,
      "overallTimeoutMillis": 180000,
      "maxRequestBytes": 2097152,
      "maxResponseBytes": 4194304,
      "maxEventBytes": 262144,
      "maxToolCalls": 32,
      "maxOutputTokens": 8192,
      "maxRetries": 2,
      "retryBaseDelayMillis": 200,
      "maxRetryDelayMillis": 10000
    }
  }
}
```

Production endpoints require HTTPS and exclude URI credentials, queries and fragments. Only the
named credential variable is resolved. Its value is frozen at load time, passed privately to the
provider and redaction boundary, and excluded from stable provenance. Legacy environment variables
do not supply fallback credentials or configuration. Credential values must meet the existing
provider's bounded printable-ASCII rules and cannot appear in exported model/provenance identity.
Configuration failures expose a fixed diagnostic with no underlying secret-bearing exception cause.

The canonical document SHA-256 binds the endpoint, model, credential reference name, state location
and every configured limit. Whitespace/key order and credential rotation do not change that digest.
Journal START identity, terminal receipt metadata, detached graph references and project archives
carry only the configuration digest, model/provider and implementation/contract identifiers plus a
fixture marker. Endpoint/state paths, environment names and credential values stay private. Changing
factory provenance changes the committed journal identity and fails verification against the original
independent reference. Existing journals without factory provenance retain their original encoding.

The internal `loadLoopbackFixture` path admits numeric-loopback HTTP and always sets `fixtureOnly`.
Production JSON cannot enable it. Factory-bound artifacts require the captured repair workflow and
its tool audit. They still report `releaseComplete = false`: this checkpoint provides provenance,
not release acceptance or authenticated oracle evidence.

Preflight performs local journal-directory checks without network requests or filesystem writes.
It reports captured repair, configured loop/provider limits and external validation requirements.
Reconstruction, terminal commands and checkpoint resume are unavailable through this selection;
provider authentication is unchecked, and release qualification is false. The private journal
directory must already exist with mode 0700 and be outside invocation workspaces; execution rechecks
its authority and uses exclusive per-task journal creation.

Nine provisioning tests cover canonical/credential-stable identity, strict schema and limits, private
file admission, HTTPS and explicit credential references, immutable environment resolution through
the real HTTP adapter, provenance forgery/rebinding, read-only preflight, and secret/implementation
substitution. An end-to-end fixture verifies factory provenance through graph persistence and archive
extraction after deleting private config and runtime journals. Local HTTP fixtures use fixed dummy
credentials and do not qualify real-provider execution. The required core corpus advances to v11.

Local verification before the next default-branch integration: **260 cases, 254 passed, six
live-terminal skips, zero failures/errors**. This includes the full built-in/shared contract corpus,
all 16 ACP factory cases (including descriptor-bound provisioning), all 92 revision-graph cases,
shared captured filesystem and ACP receipt artifacts, and the two focused repair integration cases.
Core v11 has 137 cases: 131 local passes plus six skips requiring the unavailable `/usr/bin/bwrap`.

#75/#77/#79 remain open. Shared operator selection, reconstruction integration, per-attempt checkpoint
provisioning, built-in accepted source lineage, full external compile/retained-regression acceptance
and comparative release qualification still need implementation and evidence.
