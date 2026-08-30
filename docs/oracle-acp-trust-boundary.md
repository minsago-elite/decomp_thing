# Oracle and ACP trust boundary

This project has two deliberately separate execution boundaries:

1. Kotlin/JVM code generates, validates, reconciles, scores, and publishes authenticated oracle evidence.
2. ACP v1 agents consume selected evidence and edit candidate reconstruction workspaces under bounded authority.

An ACP agent is never an oracle authority. Agent output is a candidate until deterministic host validation accepts it.

## Authoritative data flow

```text
rich reference binary + authenticated source/build records
                         |
                         v
              deterministic Kotlin oracle
          generate -> reconcile -> validate -> publish
                         |
                         | immutable, authenticated evidence
                         v
               ACP reconstruction/repair turn
                         |
                         | candidate workspace changes + ACP evidence
                         v
              deterministic Kotlin validation
                  build -> replay -> score
                         |
                         v
                 accepted revision or rollback
```

Oracle truth, exclusions, source locks, artifact manifests, shard indexes, scores, and release manifests are never
writable ACP inputs. A workflow may expose the minimum required subset as read-only context. The host independently
checks every digest and binding before using it and again before accepting a candidate.

## First-class ACP contract

ACP is the default production transport for every model-driven reconstruction and repair operation. An omitted harness
selection means ACP. Missing, malformed, unauthenticated, or unsupported ACP provisioning fails before a model-driven
operation starts. Unknown harness names never fall back to another transport.

The legacy OpenAI-compatible HTTP adapter is a deprecated compatibility mode. It requires an explicit
`legacy-openai` selection, must pass the same workflow acceptance contract, and cannot claim ACP provenance. Evidence-
only reconstruction is agent-free and is not a harness fallback.

One trusted factory owns harness selection and construction for CLI, web, reconstruction, repair, and patch workflows.
Provisioning uses structured ordered arguments, explicit environment provenance, authenticated executable/runtime
manifests, stable ACP v1 capability requirements, bounded lifecycle/resource settings, and the verified Linux
bubblewrap/cgroup boundary. Provider credentials belong to the ACP agent's own configuration and are not inherited by
the engine process boundary.

Accepted model-driven artifacts bind at least:

- ACP protocol and SDK versions, agent implementation identity, and negotiated capabilities;
- session and turn references, stop reason, bounded events, usage, and truncation state;
- exact authorized changes and their before/after hashes;
- filesystem, terminal, permission, and sandbox decisions and cleanup evidence; and
- deterministic build, behavior, structural-score, acceptance, or rollback results.

## Kotlin oracle contract

Production oracle commands do not import, launch, or require Python. JSON remains the versioned interchange format,
but canonical bytes, schema validation, sharding, hashing, atomic publication, and release decisions are implemented in
Kotlin/JVM. Large evidence is processed with bounded streaming and authenticated scratch storage rather than complete
in-memory materialization.

During migration, existing Python outputs may be retained as explicitly non-authoritative differential fixtures. They
cannot enter a new release as truth or validation evidence. A stage becomes authoritative only after frozen-fixture
parity, fail-closed mutation coverage, worker-count determinism, repeated byte-identical output, and a Kotlin-only
production run all pass.

## Release invariant

A release fails closed if either boundary is ambiguous: missing Kotlin oracle provenance, writable oracle inputs,
unverified shard/digest bindings, missing ACP provenance for agent-generated content, an implicit legacy transport,
unaccounted workspace changes, incomplete cleanup evidence, or validation/score mismatch. Agent completion by itself is
never acceptance evidence.

The live work and acceptance criteria are tracked in GitHub issues
[#72](https://github.com/minsago-elite/decomp_thing/issues/72) and
[#136](https://github.com/minsago-elite/decomp_thing/issues/136).
