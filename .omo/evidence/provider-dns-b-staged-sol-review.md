# Staged DNS B source checkpoint

Issue238 remains open. This is deliberately staged consume-only authority; Task6 composition and approved closed runtime profile remain held. No usable production context, native qualification or release authority is claimed. Local full native gate failed strict namespace observability; no qualification receipt was produced.

## provider-dns-b-combined/full-review-freeze.json

SHA256 `0c244a4a44931526c5a2e1b041c44949766869cad278a4f8cf8360a4baf3b4b1`

```json
{
  "sources": {
    "build.gradle.kts": "33f8a918c654ff7a90a9139359d25234cdbdcecf2bd1874f97b92dadbe5912ee",
    "src/main/kotlin/decompengine/acp/AcpProviderDnsRuntimeContext.kt": "02a9b9f1ff0d485cba262ad91434fe0dc6a6d3e52c089665b4b7568d2c1b3d91",
    "src/main/kotlin/decompengine/acp/AcpProviderDnsProcess.kt": "dd35519d9418e6ba7b69a881842b1624e7622fc95085bbac309240c4fed3864a",
    "src/main/kotlin/decompengine/acp/AcpProviderBroker.kt": "b5a564d98daec26d4a398afc882b390caf4228355d11babfab89edffedbfedc2",
    "src/main/kotlin/decompengine/acp/AcpHarnessFactory.kt": "17224f99f0a1518a69846942ec9e845431ee25294d5af35367b0da4c26076557",
    "src/main/kotlin/decompengine/acp/AcpProviderQualification.kt": "3b2c73d049ca9e687c35e2b70f4c48f5124138018ccc86a74ca5cb10f4c1c60a",
    "src/main/kotlin/decompengine/acp/LinuxBubblewrapBoundary.kt": "5e109d13583a0609a9a723b846847d6a0cd56299ec27be17d5ed4dd5f49861d0",
    "src/test/kotlin/decompengine/acp/AcpProviderNativeDnsContractTest.kt": "67a5834d69029c3770139bfbfc41948e62b4343373e10c6f5edb2125f9c50d5f",
    "src/test/provider-dns/native/provider_dns_loopback_fixture.c": "8400ba48e1df5140d4b03fb5be3f2a1d30cde06748b5d54c8701688e064f7f56",
    "src/test/kotlin/decompengine/acp/AcpProviderDnsProcessTest.kt": "2881520c76a98ffd23dfbc918417be34c43b0a1ee82b99350892b2b4c01547e3",
    "src/test/kotlin/decompengine/acp/AcpProviderDnsRuntimeContextTest.kt": "f10fa8749e99accf9621f1610eb0f459a7ee51d3325bb9ed6f0588086ac40fde",
    "scripts/verify-acp-provider-dns.py": "8df395a277a0934550602b97fb9cd28d339e1e3821a5a71843bd84b22883dc34",
    "src/test/provider-dns/checker/test_verify_acp_provider_dns.py": "a46dcf92dbdb0d6e20fceb736fefdcc43b3f1219a6fb7903d88007a92b739919",
    ".github/workflows/acp-contract.yml": "84089b2c796cf000e1c0018de3ed1040742743a28e6decd62e7695417014f722",
    "scripts/validate-acp-contract.sh": "193e956caf22645f04798657437a80795b925e9cda529e95234c66e15ba7acc0"
  },
  "handoffSha256": "e48f60e3e1d2c4093754e4463e7471b41ca9307ef6072a59f130de368b67f0f1",
  "componentReportSha256": "e64af6acf40b5a7d1b0cb5ceb56697775a8d4315595c8f2c36b1c6c04dd83d7e",
  "checkerTests": {
    "count": 14,
    "log": "build/provider-dns-b-combined/checker-tests.log",
    "sha256": "8bdfc5381c2481c252b2d602f90f24f6af6d60878c0a73b83e828037f95301bb"
  },
  "buildScriptChecks": {
    "gradle-help.log": {
      "exit": 0,
      "sha256": "ee6b53bd6f09797e1e80684e186639de4798f945ff86a65b32a317e51bbca4b8"
    },
    "gradle-native-helper.log": {
      "exit": 0,
      "sha256": "b38b4279ca1dca2ba4fd7906f4f813dcf6c64c4442ad1f2b3269a4bb03191e1f"
    }
  }
}

```
## provider-dns-b-combined/final-handoff.json

SHA256 `e48f60e3e1d2c4093754e4463e7471b41ca9307ef6072a59f130de368b67f0f1`

```json
{
  "status": "STAGED_SOURCE_COMPONENT_VERIFIED_NATIVE_FULL_GATE_UNQUALIFIED",
  "sources": {
    "build.gradle.kts": "33f8a918c654ff7a90a9139359d25234cdbdcecf2bd1874f97b92dadbe5912ee",
    "src/main/kotlin/decompengine/acp/AcpProviderDnsRuntimeContext.kt": "02a9b9f1ff0d485cba262ad91434fe0dc6a6d3e52c089665b4b7568d2c1b3d91",
    "src/main/kotlin/decompengine/acp/AcpProviderDnsProcess.kt": "dd35519d9418e6ba7b69a881842b1624e7622fc95085bbac309240c4fed3864a",
    "src/main/kotlin/decompengine/acp/AcpProviderBroker.kt": "b5a564d98daec26d4a398afc882b390caf4228355d11babfab89edffedbfedc2",
    "src/main/kotlin/decompengine/acp/AcpHarnessFactory.kt": "17224f99f0a1518a69846942ec9e845431ee25294d5af35367b0da4c26076557",
    "src/main/kotlin/decompengine/acp/AcpProviderQualification.kt": "3b2c73d049ca9e687c35e2b70f4c48f5124138018ccc86a74ca5cb10f4c1c60a",
    "src/main/kotlin/decompengine/acp/LinuxBubblewrapBoundary.kt": "5e109d13583a0609a9a723b846847d6a0cd56299ec27be17d5ed4dd5f49861d0",
    "src/test/kotlin/decompengine/acp/AcpProviderNativeDnsContractTest.kt": "67a5834d69029c3770139bfbfc41948e62b4343373e10c6f5edb2125f9c50d5f",
    "src/test/provider-dns/native/provider_dns_loopback_fixture.c": "8400ba48e1df5140d4b03fb5be3f2a1d30cde06748b5d54c8701688e064f7f56",
    "src/test/kotlin/decompengine/acp/AcpProviderDnsProcessTest.kt": "2881520c76a98ffd23dfbc918417be34c43b0a1ee82b99350892b2b4c01547e3",
    "src/test/kotlin/decompengine/acp/AcpProviderDnsRuntimeContextTest.kt": "f10fa8749e99accf9621f1610eb0f459a7ee51d3325bb9ed6f0588086ac40fde",
    "scripts/verify-acp-provider-dns.py": "8df395a277a0934550602b97fb9cd28d339e1e3821a5a71843bd84b22883dc34",
    "src/test/provider-dns/checker/test_verify_acp_provider_dns.py": "a46dcf92dbdb0d6e20fceb736fefdcc43b3f1219a6fb7903d88007a92b739919",
    ".github/workflows/acp-contract.yml": "84089b2c796cf000e1c0018de3ed1040742743a28e6decd62e7695417014f722",
    "scripts/validate-acp-contract.sh": "193e956caf22645f04798657437a80795b925e9cda529e95234c66e15ba7acc0"
  },
  "combinedCurrentAcpAgentCompileAndControls": {
    "report": "build/provider-dns-b-combined/verification.json",
    "sha256": "e64af6acf40b5a7d1b0cb5ceb56697775a8d4315595c8f2c36b1c6c04dd83d7e",
    "selectedTests": 29,
    "status": "PASS"
  },
  "priorExactNativePartialEvidence": {
    "report": "build/provider-dns-native-revised/verification.json",
    "sha256": "9f09668efbc3baa96db27c1b2993dca481dd8cffa05542964b6640dc7898e260",
    "status": "FULL_GATE_FAILED",
    "scope": "Both actual inner JVM and stalled production worker masks, query, reap/join/pipes observed; no complete namespace cleanup or case receipts. Earlier source hash closure is preserved in report."
  },
  "changesAfterNativePartialRun": [
    "One cleanup absolute end through DNS/active scopes/retained launches/private deletion; later explicit remediation changes cleanup authority only.",
    "Exact invocation deadline required at context consume.",
    "Ten privileged reflection authority/race/counter/deletion checkpoint controls.",
    "Original18 component tests preserve methods and predicates, add fixed launcher metadata on failed artifact construction.",
    "Trusted systemctl owner registered before native start; exact process, caller, reap, pipes and reaper join retained across expired pass/remediation.",
    "Private checker validates exact fresh native source-bound complete receipts;14 inert checker controls PASS."
  ],
  "stagingLimits": [
    "No real factory DNS permit issuer or Harness/Broker composition was added; staged real provider remains failclosed and unqualified.",
    "Current JDK strict production snapshot rejects206 symlinks; no policy relaxation.",
    "Full native local run fails strict namespace observability for7 existing sameUID host processes; no fallback, permissions changes or qualification receipt.",
    "Reflection tests are privileged component controls and do not prove production context issuance or supported runtime tree lifetime."
  ],
  "cleanupRationale": "Boundary.close serializes only cleanup passes. Each explicit pass binds its one absolute end to existing active scope cleanup, DNS cleanup, waits/retries and deletion. A later explicit remediation pass may obtain fresh cleanup authority; immutable invocationDeadlineNanos and revoked DNS state prevent revived execution. Prior cleanup failures remain sticky.",
  "rootOwnedGateDelta": "build/provider-dns-native-revised/required-gate-delta.md",
  "pending": [
    "Independent final staged source review",
    "Required hosted source-bound native gate success",
    "Task6 production composition/runtime qualification"
  ],
  "checkerTests": {
    "count": 14,
    "log": "build/provider-dns-b-combined/checker-tests.log",
    "sha256": "8bdfc5381c2481c252b2d602f90f24f6af6d60878c0a73b83e828037f95301bb"
  },
  "buildScriptChangesAfterComponentCompile": {
    "explanation": "Kotlin source closure unchanged since29PASS; Gradle script subsequently fixed Base64 shadow and resource CopySpec syntax, binds fresh runID/required flags and disables required-test/native-helper cache reuse. Real Gradle configuration and helper build checks passed.",
    "checks": {
      "gradle-help.log": {
        "exit": 0,
        "sha256": "ee6b53bd6f09797e1e80684e186639de4798f945ff86a65b32a317e51bbca4b8"
      },
      "gradle-native-helper.log": {
        "exit": 0,
        "sha256": "b38b4279ca1dca2ba4fd7906f4f813dcf6c64c4442ad1f2b3269a4bb03191e1f"
      }
    }
  }
}

```
## provider-dns-b-final-review/review.md

SHA256 `4c0bf0e2c86e4e5f289070f1e4170ab2134b1f5ab5ad208f36190e21a7e72072`

# Final staged checkpoint B source review

Verdict: CLEAR for the exact staged source freeze below. No unresolved source finding remains from this review. This is not native qualification or checkpoint-B release approval.

Scope: the explicitly approved fail-closed stage comprising one-use context/lease, DNS component/native fixture and mandatory gate wiring. Task6 production Harness/Broker composition remains held. No usable production context issuer, supported production runtime lifetime or actual provider admission is claimed. Earlier reviews are retained as prior-unscoped-review.md and prior-trusted-helper-review.md; the former incorrectly counted deliberately deferred composition as a staged defect. This review performed only source/evidence reads and wrote review artifacts; it did not run privileged tests, change source/Git/GitHub, or modify host networking.

## Resolved source findings

The exact context consumer removes before validation, checks consumer identity, request binding and exact immutable invocation deadline, and revokes mismatches/replay. Dispatch deadlines remain clamped to invocation end. The lease contains credential-free resources and concrete DNS owner identities without request, broker, harness or boundary callbacks. Preparation/binding races cannot release resources before the concrete owner's task, timer, late child publication, reap and pipes are verified; failure keeps sticky quarantine.

Boundary cleanup now uses one absolute end across DNS, active scopes, retained failed starts, trusted control helpers and private deletion. Cleanup passes alone are serialized; live invocation work is not. A later explicit remediation pass can renew cleanup authority without changing invocationDeadlineNanos or reviving revoked execution. Expiry retains ownership and the boundary control tree; prior failure remains sticky.

The trusted-control-helper blocker is fixed. A capped credential-free owner is globally registered before ProcessBuilder.start, retains exact Process state and caller completion, signals late publication, and preserves ownership across expiry. Its daemon reaper proves actual waitFor termination and all pipe closures; release additionally requires reaper termination. Endpoint groups use weak keys and owners do not capture bus/boundary/request/context or callbacks. Boundary cleanup binds the end before processing owners, and includes grouped trusted-owner emptiness in control-tree deletion admission. Capacity rejection occurs before native start. The deterministic actual-child control demonstrates an expired cleanup pass retains the global/group owner until caller completion and explicit successful remediation. Unverified reap/pipe states remain retained rather than becoming success.

The authenticated fixture C transition preserves exact outer P/E/I/A/Bnd0x1400, sets NNP before clearing ambient and P/E/I, verifies post-drop zero masks/Bnd0x1400/NNP1, and uses fixed absolute Java execve, fixed argv and empty environment. The read-only full-JDK relocation is fixture-only; production strict snapshots still reject symlinks. No general path/starter production authority is introduced.

## Gate assessment

The required wrapper creates a fresh UUID, sets both required flags and performs the existing single ACP/agent Gradle test invocation followed by the strict Python-B DNS checker. The workflow exposes the required-native flag and uploads native/DNS evidence directories. Required flags/run ID are test task inputs; required runs and the native helper deny cached/up-to-date reuse. Compiler/linker/source/ELF/reference/argv identities are generated for the fixed helper build. Current Gradle configuration and actual helper task both succeed.

The checker requires exactly one native XML suite, exactly two named cases with zero failures/errors/skips, fresh exact-schema receipts with all cleanup/query/capability/NNP facts, current source/runtime/helper/worker/reference hashes, matching compiler argv and commitments, no SPI/fixture worker entries, and absent private trees. Duplicate JSON keys, partial inner observations, stale run IDs, altered masks/hashes, extra/duplicate XML cases/suites and missing facts are rejected. It does not accept inner.properties as a qualification receipt. The main wrapper additionally preserves global required-suite and zero failure/error/skip checks. No partial-proof fallback was added.

## Exact freeze and evidence

All15 source hashes in build/provider-dns-b-combined/full-review-freeze.json match the files inspected. Full source/evidence hashes are in final-reviewed-hashes.json.

- full-review-freeze.json: 0c244a4a44931526c5a2e1b041c44949766869cad278a4f8cf8360a4baf3b4b1
- final-handoff.json: e48f60e3e1d2c4093754e4463e7471b41ca9307ef6072a59f130de368b67f0f1
- LinuxBubblewrapBoundary.kt: 5e109d13583a0609a9a723b846847d6a0cd56299ec27be17d5ed4dd5f49861d0
- combined verification: e64af6acf40b5a7d1b0cb5ceb56697775a8d4315595c8f2c36b1c6c04dd83d7e — current ACP/agent compilation and29 selected controls PASS, zero skips/failures
- checker14-case log: 8bdfc5381c2481c252b2d602f90f24f6af6d60878c0a73b83e828037f95301bb — PASS
- Gradle help log: ee6b53bd6f09797e1e80684e186639de4798f945ff86a65b32a317e51bbca4b8 — BUILD SUCCESSFUL
- actual Gradle native helper task log: b38b4279ca1dca2ba4fd7906f4f813dcf6c64c4442ad1f2b3269a4bb03191e1f — BUILD SUCCESSFUL, task executed

Gradle script/gate checker changes postdate component compilation; Kotlin closure is unchanged since29-control PASS, and the current script has separate real Gradle configuration/helper-build evidence. This review does not present those checks as a full Gradle test run.

## Qualification still pending

Prior native verification9f09668efbc3baa96db27c1b2993dca481dd8cffa05542964b6640dc7898e260 records two failed native tests: strict namespace observability rejects seven preexisting same-UID inaccessible processes. No cancel.json/deadline.json qualification receipts exist. Inner JVM/stalled worker masks, NNP, actual built-in queries, reap, owner join and pipes are partial observations only. Final lifecycle corrections postdate that native run.

Required hosted verification against this final source freeze, with both native tests successful and complete cleanup receipts, remains mandatory and unfulfilled. Reflection controls do not prove production context issuance or supported strict JDK snapshot lifetime. Task6 composition remains deferred; actual provider effectiveness and credentials are unqualified. Source CLEAR must not be represented as full native gate PASS, production admission or release approval. Binder checkpoint244e scope was not edited.

## provider-dns-b-final-review/final-reviewed-hashes.json

SHA256 `7b64a9f1c7db0e849616a138b48fefd9d23a87bbebd49e483effbfe20c820f8c`

```json
{
  "build.gradle.kts": "33f8a918c654ff7a90a9139359d25234cdbdcecf2bd1874f97b92dadbe5912ee",
  "src/main/kotlin/decompengine/acp/AcpProviderDnsRuntimeContext.kt": "02a9b9f1ff0d485cba262ad91434fe0dc6a6d3e52c089665b4b7568d2c1b3d91",
  "src/main/kotlin/decompengine/acp/AcpProviderDnsProcess.kt": "dd35519d9418e6ba7b69a881842b1624e7622fc95085bbac309240c4fed3864a",
  "src/main/kotlin/decompengine/acp/AcpProviderBroker.kt": "b5a564d98daec26d4a398afc882b390caf4228355d11babfab89edffedbfedc2",
  "src/main/kotlin/decompengine/acp/AcpHarnessFactory.kt": "17224f99f0a1518a69846942ec9e845431ee25294d5af35367b0da4c26076557",
  "src/main/kotlin/decompengine/acp/AcpProviderQualification.kt": "3b2c73d049ca9e687c35e2b70f4c48f5124138018ccc86a74ca5cb10f4c1c60a",
  "src/main/kotlin/decompengine/acp/LinuxBubblewrapBoundary.kt": "5e109d13583a0609a9a723b846847d6a0cd56299ec27be17d5ed4dd5f49861d0",
  "src/test/kotlin/decompengine/acp/AcpProviderNativeDnsContractTest.kt": "67a5834d69029c3770139bfbfc41948e62b4343373e10c6f5edb2125f9c50d5f",
  "src/test/provider-dns/native/provider_dns_loopback_fixture.c": "8400ba48e1df5140d4b03fb5be3f2a1d30cde06748b5d54c8701688e064f7f56",
  "src/test/kotlin/decompengine/acp/AcpProviderDnsProcessTest.kt": "2881520c76a98ffd23dfbc918417be34c43b0a1ee82b99350892b2b4c01547e3",
  "src/test/kotlin/decompengine/acp/AcpProviderDnsRuntimeContextTest.kt": "f10fa8749e99accf9621f1610eb0f459a7ee51d3325bb9ed6f0588086ac40fde",
  "scripts/verify-acp-provider-dns.py": "8df395a277a0934550602b97fb9cd28d339e1e3821a5a71843bd84b22883dc34",
  "src/test/provider-dns/checker/test_verify_acp_provider_dns.py": "a46dcf92dbdb0d6e20fceb736fefdcc43b3f1219a6fb7903d88007a92b739919",
  ".github/workflows/acp-contract.yml": "84089b2c796cf000e1c0018de3ed1040742743a28e6decd62e7695417014f722",
  "scripts/validate-acp-contract.sh": "193e956caf22645f04798657437a80795b925e9cda529e95234c66e15ba7acc0",
  "build/provider-dns-b-combined/full-review-freeze.json": "0c244a4a44931526c5a2e1b041c44949766869cad278a4f8cf8360a4baf3b4b1",
  "build/provider-dns-b-combined/final-handoff.json": "e48f60e3e1d2c4093754e4463e7471b41ca9307ef6072a59f130de368b67f0f1",
  "build/provider-dns-b-combined/verification.json": "e64af6acf40b5a7d1b0cb5ceb56697775a8d4315595c8f2c36b1c6c04dd83d7e",
  "build/provider-dns-b-combined/checker-tests.log": "8bdfc5381c2481c252b2d602f90f24f6af6d60878c0a73b83e828037f95301bb",
  "build/provider-dns-b-combined/gradle-help.log": "ee6b53bd6f09797e1e80684e186639de4798f945ff86a65b32a317e51bbca4b8",
  "build/provider-dns-b-combined/gradle-native-helper.log": "b38b4279ca1dca2ba4fd7906f4f813dcf6c64c4442ad1f2b3269a4bb03191e1f"
}

```
