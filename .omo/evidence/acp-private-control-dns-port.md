# Composed private control concurrency and staged DNS B

34 focused controls pass without skips against the exact composed source. Hosted native DNS qualification and Task6 remain unqualified. Standalone 70d evidence is retained separately; this report binds the composed closure.

## composed-handoff.md

SHA256 `f980c531e339c5f8370669cb4a3815628e3bbc4c88f07119db22ccf7379936b7`

# #1508 port to staged DNS B: composed source handoff

Worktree: `/home/june/decomp_thing/.claude/worktrees/wf_ce026d1b-c24-68`. Coordinator applied the approved plan and started the no-commit concurrency cherry-pick over staged B. Source worker resolved only content conflicts and one test signature adaptation, without staging, committing, continuing, aborting or modifying Git/GitHub state. #1508 and parent #238 remain OPEN in milestone 16; no issue closure is claimed.

## Resolution

The two content conflicts were in PinnedControlDirectory.deleteAndProve. Preserve staged B's no-argument delegation and cancellationCheck overload, initial callback and all callback checkpoints through descriptor drain, quarantine, unlink and name-absence proof. Remove only that control's obsolete method monitor because the registry now owns lifecycle transactions. Combine the existing pre-quarantine cancellationCheck with the new private transaction observer. Preserve 1508's exact proof-before-PROVED_DELETED transition, active membership removal, epoch advancement and descriptor closure order. Preserve sticky prior cleanup failure.

Restore AtomicLong import: concurrency no longer uses its old AtomicLong epoch, but staged B still requires AtomicLong for authenticated scope task peak observations. No whole-file replacement was used.

The independent PinnedPrivateTree retains all synchronized overloads and deleteAndProveBefore cancellation/deadline semantics. No cleanupEnd, cleanup pass, per-pass remediation, retained trusted helper, DNS resource/context, guardian or unsupported-runtime policy code was rewritten.

An auto-merged native probe used the old three-argument reflective cleanupLaunchResources signature. Staged B requires a fourth Function0 cancellation callback. The test now invokes that exact four-argument signature with its explicit empty checkpoint. Production APIs were preserved; no compatibility fallback or weaker cleanup assertion was added.

## Symbol preservation evidence

`preserved-staged-b-symbols.json` byte-compares the actual conflict stage-2 source with the composition. All three sections match exactly: DNS context/lease/resources, PinnedPrivateTree plus private cleanup helpers, and trusted-helper ownership through end of source. `preserved-1508-symbols.json` confirms the registry, root physical coverage and RuntimePrivateControlScope block matches reviewed standalone 1508 byte for byte (block SHA256 c95ea1db824fc7ae60e4e6d192fa8547b422597b3984ee72e4cd112ba63ef3f1). The independent reviewer reproduced these comparisons.

Exact composed files:

- LinuxBubblewrapBoundary.kt: `8b742d19941a01ed4d5d11f49a4bc15232ae1536ffb0b478af4aa7b8b83762aa`.
- LinuxBubblewrapBoundaryTest.kt: `d1d4261ef76e259e1edc0b620a10114f47174ede4199203d501eb5ed2daa1858`.
- AcpAgentHarnessTest.kt: `671546c7a762724a250a9df2489785358d0ed9cca60525fd7dc35723a9ee233d`.
- AcpProviderDnsProcessTest.kt: `2881520c76a98ffd23dfbc918417be34c43b0a1ee82b99350892b2b4c01547e3`.
- AcpProviderDnsRuntimeContextTest.kt: `f10fa8749e99accf9621f1610eb0f459a7ee51d3325bb9ed6f0588086ac40fde`.

`composed-freeze.json` SHA256 `bf62900939ab66b433926b954f8f4b09e6ced02d4d5948ec0d65aa7bc3118cfa` records all 17 current staged source/test/gate files, exact XML/log hashes, case names/counts and prior source distinctions. Standalone Boundary bf0075a4 and prior staged-B Boundary 5e109d13 remain separate historical snapshots; neither is presented as composed proof.

## Composed verification

The initial composed Gradle invocation executed main compilation and test compilation, then ran 34 focused cases. 33 passed; one native probe failed with NoSuchMethodException for the obsolete cleanupLaunchResources signature. That diagnostic and all initial XML are retained in `focused-gradle.log` and `initial-results/`. There was no production failure behind that reflective mismatch.

After the single test signature adaptation, final Gradle test compilation executed and the same production main source remained unchanged. Final command:

```sh
./gradlew --no-daemon test -x stageFrontend \
  --tests 'decompengine.acp.LinuxBubblewrapBoundaryTest.manifest scopes reconcile bounded disjoint churn and retain failed cleanup protection' \
  --tests 'decompengine.acp.LinuxBubblewrapBoundaryTest.unproved partial control creation poisons all later authority admission without descriptor leaks' \
  --tests 'decompengine.acp.LinuxBubblewrapBoundaryTest.private controls reject native bind aliases and late callback exposure without denying disjoint grants' \
  --tests 'decompengine.acp.LinuxBubblewrapBoundaryTest.live boundary hides host data isolates network and launches concurrently through static helpers' \
  --tests 'decompengine.acp.AcpAgentHarnessTest.overlapping receipts retain their own request prompt and provider evidence' \
  --tests 'decompengine.acp.AcpProviderDnsProcessTest' \
  --tests 'decompengine.acp.AcpProviderDnsRuntimeContextTest'
```

BUILD SUCCESSFUL in 1m 30s, 34 tests, zero failures/errors/skips. Full log: `final-focused-gradle.log`. This is focused JVM/native source verification with unrelated frontend staging excluded, not packaged frontend qualification. `git diff --check` passes and conflict markers are absent from the source; coordinator still owns Git conflict/index completion.

Retained final XML in `final-results/`:

- Boundary: 4/4, 39.861s, SHA256 `8b5a951b9a20f56162e8bb7897cf20ffb48b67ace5788accfb90fa6fe45e7c95`. Actual native bind probe 33.735s within unchanged 45s; real live concurrent static-helper launches also pass.
- Harness overlap: 1/1, 2.299s, SHA256 `a116a0c99ac7720fc978762b809be42da4bfa0d7b20a5c58b943a6192f127864`. Both real callbacks must enter before either can complete; successful receipts and authorized changes remain required.
- DNS process: 18/18, 5.861s, SHA256 `61d35fb382d5b80e112d3e8fdf67471774094054fc7d7d53035fe2cf376ddce5`.
- DNS runtime context: 11/11, 0.059s, SHA256 `b6a5dba9b246120da5ac9e537b2dd03f78696be157c3158d600d6635d753ffa8`.

Boundary controls preserve deterministic metadata transaction pauses and waiting peers, exact record identity/ABA, lifecycle refresh rollback, resource ceilings, failure/poison/low-RLIMIT controls, hostile live control/mount/alias observations, recursive same- and cross-filesystem bind admission, 64MiB integrity/copy and 4096-file scale. DNS/context controls retain actual child reap/pipe/deadline/late-publication ownership plus cleanup expiry/explicit remediation checks.

## Remaining gates

Independent composed source/result review is recorded separately in `independent-sol-review.md`. Source approval and 34 focused controls do not qualify full native DNS contract or the required hosted ACP contract. Prior local strict native DNS qualification remains unsupported/unqualified: no unsupported or failed test is counted as pass, and no fresh cancel/deadline native qualification receipt is claimed. Required final hosted ACP/native DNS gate, automatic review resolution and coordinator commit/push/merge remain separate.

Task6 production composition is not included. No provider/model/authentication call or timeout increase was made. The retained exact 9cfc failure diagnosis remains historical; fae's lower cause remains UNKNOWN.

## composed-freeze.json

SHA256 `bf62900939ab66b433926b954f8f4b09e6ced02d4d5948ec0d65aa7bc3118cfa`

```json
{
  "scope": "staged DNS B plus reviewed private-control concurrency correction; source/focused controls only",
  "sources": {
    "build.gradle.kts": "33f8a918c654ff7a90a9139359d25234cdbdcecf2bd1874f97b92dadbe5912ee",
    "src/main/kotlin/decompengine/acp/AcpProviderDnsRuntimeContext.kt": "02a9b9f1ff0d485cba262ad91434fe0dc6a6d3e52c089665b4b7568d2c1b3d91",
    "src/main/kotlin/decompengine/acp/AcpProviderDnsProcess.kt": "dd35519d9418e6ba7b69a881842b1624e7622fc95085bbac309240c4fed3864a",
    "src/main/kotlin/decompengine/acp/AcpProviderBroker.kt": "b5a564d98daec26d4a398afc882b390caf4228355d11babfab89edffedbfedc2",
    "src/main/kotlin/decompengine/acp/AcpHarnessFactory.kt": "17224f99f0a1518a69846942ec9e845431ee25294d5af35367b0da4c26076557",
    "src/main/kotlin/decompengine/acp/AcpProviderQualification.kt": "3b2c73d049ca9e687c35e2b70f4c48f5124138018ccc86a74ca5cb10f4c1c60a",
    "src/main/kotlin/decompengine/acp/LinuxBubblewrapBoundary.kt": "8b742d19941a01ed4d5d11f49a4bc15232ae1536ffb0b478af4aa7b8b83762aa",
    "src/test/kotlin/decompengine/acp/AcpProviderNativeDnsContractTest.kt": "67a5834d69029c3770139bfbfc41948e62b4343373e10c6f5edb2125f9c50d5f",
    "src/test/provider-dns/native/provider_dns_loopback_fixture.c": "8400ba48e1df5140d4b03fb5be3f2a1d30cde06748b5d54c8701688e064f7f56",
    "src/test/kotlin/decompengine/acp/AcpProviderDnsProcessTest.kt": "2881520c76a98ffd23dfbc918417be34c43b0a1ee82b99350892b2b4c01547e3",
    "src/test/kotlin/decompengine/acp/AcpProviderDnsRuntimeContextTest.kt": "f10fa8749e99accf9621f1610eb0f459a7ee51d3325bb9ed6f0588086ac40fde",
    "scripts/verify-acp-provider-dns.py": "8df395a277a0934550602b97fb9cd28d339e1e3821a5a71843bd84b22883dc34",
    "src/test/provider-dns/checker/test_verify_acp_provider_dns.py": "a46dcf92dbdb0d6e20fceb736fefdcc43b3f1219a6fb7903d88007a92b739919",
    ".github/workflows/acp-contract.yml": "84089b2c796cf000e1c0018de3ed1040742743a28e6decd62e7695417014f722",
    "scripts/validate-acp-contract.sh": "193e956caf22645f04798657437a80795b925e9cda529e95234c66e15ba7acc0",
    "src/test/kotlin/decompengine/acp/LinuxBubblewrapBoundaryTest.kt": "d1d4261ef76e259e1edc0b620a10114f47174ede4199203d501eb5ed2daa1858",
    "src/test/kotlin/decompengine/acp/AcpAgentHarnessTest.kt": "671546c7a762724a250a9df2489785358d0ed9cca60525fd7dc35723a9ee233d"
  },
  "priorStandaloneNotComposedProof": {
    "concurrencyBoundarySha256": "bf0075a4178db1f2ed02ecf770e581a69482ea01f7cd43b42a053cbee79e6868",
    "dnsBoundarySha256": "5e109d13583a0609a9a723b846847d6a0cd56299ec27be17d5ed4dd5f49861d0"
  },
  "results": {
    "build/acp-private-control-dns-port/final-results/TEST-decompengine.acp.AcpAgentHarnessTest.xml": {
      "sha256": "a116a0c99ac7720fc978762b809be42da4bfa0d7b20a5c58b943a6192f127864",
      "tests": 1,
      "failures": 0,
      "errors": 0,
      "skipped": 0,
      "seconds": 2.299,
      "cases": [
        {
          "name": "overlapping receipts retain their own request prompt and provider evidence()",
          "time": "2.296"
        }
      ]
    },
    "build/acp-private-control-dns-port/final-results/TEST-decompengine.acp.AcpProviderDnsProcessTest.xml": {
      "sha256": "61d35fb382d5b80e112d3e8fdf67471774094054fc7d7d53035fe2cf376ddce5",
      "tests": 18,
      "failures": 0,
      "errors": 0,
      "skipped": 0,
      "seconds": 5.861,
      "cases": [
        {
          "name": "late real process publication is killed reaped and permanently quarantined()",
          "time": "0.334"
        },
        {
          "name": "actual child receives empty environment no arguments and EOF stdin()",
          "time": "0.15"
        },
        {
          "name": "production jar rejects resolver services and fixture classpath()",
          "time": "0.008"
        },
        {
          "name": "authenticated artifact mutation is refused before any child()",
          "time": "0.006"
        },
        {
          "name": "isolated lookup selects one IPv4 address and actually reaps child()",
          "time": "0.122"
        },
        {
          "name": "invalid and oversized actual child output is refused and reaped()",
          "time": "0.543"
        },
        {
          "name": "actual stalled resolver deadline kills child without a waiting caller()",
          "time": "1.513"
        },
        {
          "name": "valid address bytes do not bypass required child exit()",
          "time": "0.094"
        },
        {
          "name": "cancelled lookup cannot be revived by a released address()",
          "time": "0.126"
        },
        {
          "name": "repeated stalled lookup cleanup leaves no child descriptor or task accumulation()",
          "time": "0.234"
        },
        {
          "name": "completed lookup cannot be admitted after request deadline()",
          "time": "1.595"
        },
        {
          "name": "signal of actual child never waits for its Java pipe flush monitor()",
          "time": "0.435"
        },
        {
          "name": "isolated lookup selects one IPv6 address and actually reaps child()",
          "time": "0.142"
        },
        {
          "name": "cancel before admission starts no child()",
          "time": "0.007"
        },
        {
          "name": "actual stalled resolver is killed and reaped on cancel()",
          "time": "0.12"
        },
        {
          "name": "failed lookup returns a fixed failure with no child leak()",
          "time": "0.126"
        },
        {
          "name": "exact future task is published before execution and remains the completion proof()",
          "time": "0.135"
        },
        {
          "name": "two real stalled owners exhaust capacity without queued child launches()",
          "time": "0.155"
        }
      ]
    },
    "build/acp-private-control-dns-port/final-results/TEST-decompengine.acp.AcpProviderDnsRuntimeContextTest.xml": {
      "sha256": "b6a5dba9b246120da5ac9e537b2dd03f78696be157c3158d600d6635d753ffa8",
      "tests": 11,
      "failures": 0,
      "errors": 0,
      "skipped": 0,
      "seconds": 0.059,
      "cases": [
        {
          "name": "close racing transfer revokes future admissions()",
          "time": "0.017"
        },
        {
          "name": "expired trusted helper cleanup retains exact owner until explicit remediation()",
          "time": "0.011"
        },
        {
          "name": "eight lifetime admissions exhaust the lease even after verified slots()",
          "time": "0.003"
        },
        {
          "name": "expired shared cleanup checkpoint retains remaining private entries()",
          "time": "0.003"
        },
        {
          "name": "deadline mismatch revokes and consumes registered context()",
          "time": "0.003"
        },
        {
          "name": "unregistered context cannot grant launch authority()",
          "time": "0.001"
        },
        {
          "name": "concurrent replay admits at most one transfer()",
          "time": "0.003"
        },
        {
          "name": "wrong binding revokes and consumes registered context()",
          "time": "0.002"
        },
        {
          "name": "revoked context cannot transfer or dispatch()",
          "time": "0.003"
        },
        {
          "name": "wrong consumer revokes and consumes registered context()",
          "time": "0.001"
        },
        {
          "name": "valid context transfers only once and clamps dispatch deadline()",
          "time": "0.002"
        }
      ]
    },
    "build/acp-private-control-dns-port/final-results/TEST-decompengine.acp.LinuxBubblewrapBoundaryTest.xml": {
      "sha256": "8b5a951b9a20f56162e8bb7897cf20ffb48b67ace5788accfb90fa6fe45e7c95",
      "tests": 4,
      "failures": 0,
      "errors": 0,
      "skipped": 0,
      "seconds": 39.861,
      "cases": [
        {
          "name": "manifest scopes reconcile bounded disjoint churn and retain failed cleanup protection()",
          "time": "2.236"
        },
        {
          "name": "unproved partial control creation poisons all later authority admission without descriptor leaks()",
          "time": "0.574"
        },
        {
          "name": "private controls reject native bind aliases and late callback exposure without denying disjoint grants()",
          "time": "33.735"
        },
        {
          "name": "live boundary hides host data isolates network and launches concurrently through static helpers()",
          "time": "3.27"
        }
      ]
    }
  },
  "total": {
    "tests": 34,
    "failures": 0,
    "errors": 0,
    "skipped": 0
  },
  "gradle": {
    "exit": 0,
    "log": "build/acp-private-control-dns-port/final-focused-gradle.log",
    "sha256": "599025a1079804df92d4777c1be231bedf4612ddc1cd99b7c0390d0ac50eef2b",
    "mainCompile": "executed in first composed run; unchanged source final run reused compiled output",
    "testCompile": "executed final run after adapting staged B cleanup callback reflection"
  },
  "preservedSymbols": {
    "preserved-staged-b-symbols.json": "b878e468245fb9531c7acca5f01914e6df3302b191d94c91d56bed58974ab15e",
    "preserved-1508-symbols.json": "176fd00df03b58bc8fdf1bfff113edb60cc1c177fef471e05c5944d25afc3949"
  },
  "limits": [
    "No required hosted ACP contract run performed by source worker",
    "Native DNS full qualification remains unqualified; no failed/unsupported run is counted as pass",
    "No provider/authentication/model call",
    "No Task6 production composition",
    "No Git index/cherry-pick state mutations by source worker"
  ]
}

```
## independent-sol-review.md

SHA256 `0c20cac7913d3cfd5c9f04ab70f41a4393cb1ad9a5f66d6f106b231aa7e173e8`

# Independent composed concurrency/DNS B port review

Verdict: CLEAR for the exact composed source and 34 focused controls recorded below.

Read wt68 AGENTS.md. Reviewed the working source conflict resolution against staged B (Git conflict stage 2) and independently reviewed standalone concurrency source. No source, Git, GitHub, CI, provider, model or authentication writes/operations were performed. This review artifact is the only reviewer-created file.

Exact composed boundary SHA256: `8b742d19941a01ed4d5d11f49a4bc15232ae1536ffb0b478af4aa7b8b83762aa`.

## Composition findings

No blocking source finding found. Independently extracted the registry/scope/root-coverage region and reproduced SHA256 `c95ea1db824fc7ae60e4e6d192fa8547b422597b3984ee72e4cd112ba63ef3f1`, identical to reviewed standalone source. Exact record identity, nonreused epoch token, LIVE/PROVED_DELETED reconciliation, independently owned root leases, nested mounted subtree coverage, sticky mount event detection, complete finish mount table equality, bounded refresh ownership and conservative poisoned admission therefore retain the previously reviewed implementation.

Inspected both resolved PinnedControlDirectory.deleteAndProve regions. The no-argument wrapper delegates to the B callback overload; both control method monitors are removed in favor of the existing shared registry monitor. The B cancellation callback still runs on entry, mount reads, contents drain, before quarantine, between proof syscalls and after unlink before name-absence proof. The new observation point follows the original pre-quarantine cancellation check. Only after link-count zero and both name-absence proofs does lifecycle become PROVED_DELETED and active membership disappear. Cancellation or failure before that point preserves LIVE ownership and records cleanup failure; it cannot publish a half-created record or grant an unproved deletion exemption. Remediation retains prior failure provenance. B callbacks do not introduce a new per-control monitor inversion. Sticky global poison still gates subsequent authority admission.

PinnedPrivateTree delete wrappers and deleteAndProveBefore remain synchronized, including B absolute cleanup deadline and callback checks. Independently compared its entire class text against staged B: identical. This preserves the corrected mutual exclusion with unlinkExactRoot. AtomicLong import remains available for B task counts.

Independently compared ProviderDnsControlLease through the start of PinnedControlDirectory against staged B: identical. Reviewed detached ticket/owner identity, revocation, binding-in-progress and verified completion predicates. Lease close only releases resources after no preparation/binding remains and every concrete DNS owner proves cleanup; a failure retains unverified ownership. Pinned resource cleanup retains B's cleanupGuard and absolute deadline, deleting exact trees before setting released. The concurrency port does not reset or widen any DNS admission lifetime.

Independently compared trusted helper owner code and cleanup checkpoint region against staged B: identical. Boundary close retains one absolute cleanupDeadline, binds it to trusted controls and active processes, revokes DNS contexts, waits concrete lease/process/late helper proof, and deletes launcher snapshots/control only after active/unresolved/DNS/helper ownership is clear. The port preserves the late publication/reap/pipe owner anchoring. Source diff against staged B does not alter these B blocks.

## Focused test status

Initial 34-control run had 33 passing tests and one native test failure caused by obsolete reflection of cleanupLaunchResources(List, SandboxEnvironmentFile, List). Staged B adds a Function0 checkpoint parameter. Source owner adapted that test invocation to the four-argument signature; production hash is unchanged. Initial result XML is retained under initial-results and is not treated as qualification.

Current test hashes: BoundaryTest `d1d4261ef76e259e1edc0b620a10114f47174ede4199203d501eb5ed2daa1858`; HarnessTest `671546c7a762724a250a9df2489785358d0ed9cca60525fd7dc35723a9ee233d`. DNS production hashes: AcpProviderDnsProcess.kt `dd35519d9418e6ba7b69a881842b1624e7622fc95085bbac309240c4fed3864a`; AcpProviderDnsRuntimeContext.kt `02a9b9f1ff0d485cba262ad91434fe0dc6a6d3e52c089665b4b7568d2c1b3d91`.

Hosted native DNS remains UNQUALIFIED. Task 6/full hosted contract, automatic reviews and parent production qualification remain separate gates. Standalone passing evidence is not substituted for composed tests. Retained exact 9cfc cause is not attributed to fae, whose lower cause remains UNKNOWN.


## Final composed verification: CLEAR

Read final-focused-gradle.log: BUILD SUCCESSFUL in 1m 30s. Independently read all four fresh result XML files and recomputed SHA256. All 34 tests passed with zero failures, errors or skips:

- LinuxBubblewrapBoundaryTest: 4 tests, 39.861s, XML `8b5a951b9a20f56162e8bb7897cf20ffb48b67ace5788accfb90fa6fe45e7c95`.
- AcpAgentHarnessTest: 1 test, 2.299s, XML `a116a0c99ac7720fc978762b809be42da4bfa0d7b20a5c58b943a6192f127864`.
- AcpProviderDnsProcessTest: 18 tests, 5.861s, XML `61d35fb382d5b80e112d3e8fdf67471774094054fc7d7d53035fe2cf376ddce5`.
- AcpProviderDnsRuntimeContextTest: 11 tests, 0.059s, XML `b6a5dba9b246120da5ac9e537b2dd03f78696be157c3158d600d6635d753ffa8`.

Retained XML source: build/acp-private-control-dns-port/final-results/TEST-decompengine.acp.<class>.xml. Independently recomputed all four retained-copy hashes; they match the reviewed fresh results above. Boundary output confirms actual same/cross-filesystem nested aliases in both admission orders, persistent cross-mount refresh, 4097-entry scale, 64MiB integrity and positive disjoint copy churn, partial-copy cancellation cleanup, retained hostile controls, mount restoration and bind rename. Native testcase took 33.735s under unchanged 45s budget; live concurrent boundary launch took 3.270s. Deterministic transaction/churn/capacity/ABA test passed 2.236s; isolated poison/low-FD test passed 0.574s. Actual overlapping callback test passed against the composed source with required two-held-callback and successful receipt/operation/cleanup assertions.

DNS XML includes real late publication kill/reap/quarantine, stalled resolver deadline/cancel, repeated cleanup with no task/child/descriptor accumulation, capped simultaneous owners, exact future task proof, empty child environment/EOF and malformed output denial. Context XML includes transfer replay/races, deadline clamping, eight lifetime admissions, expired shared private cleanup and trusted helper ownership retention. These preserve the focused B controls; they do not establish hosted native DNS production qualification.

Recomputed production/test file hashes after successful run match the source/test freeze above. No additional blocking composition finding remains. CLEAR is limited to this exact composed port and focused evidence; final hosted contract/Task 6, automatic reviews, native DNS qualification and broader #238 acceptance remain pending as separately tracked gates. No provider/authentication behavior was newly exercised by this review.

Composed freeze manifest `build/acp-private-control-dns-port/composed-freeze.json` SHA256 `bf62900939ab66b433926b954f8f4b09e6ced02d4d5948ec0d65aa7bc3118cfa` was read and independently checked against all 17 listed current file hashes; all match. This binds the review to the composed freeze and retained XML, while preserving the explicit distinction from prior standalone hashes.

