# CI/CD Usage

`decomp_engine` is intended to be usable from CI as both a project under test and as a validation tool for generated C reconstruction artifacts.

## Project CI

Run the shared JVM/Kotlin entry point:

```bash
scripts/ci.sh
```

By default, this runs `verifyReconstructionNeutrality` and `test` through
`./gradlew --no-daemon`, plus `v3BoundaryFinalStagingIsolated`,
`v3BoundaryPublicationIsolated` and `v3BoundaryCensusIsolated` with
`-PisolateV3BoundaryTests=true`. Those three RSS-sensitive methods run in fresh
workers instead of the shared worker. The test task also requires the entire
`GccCompilerEnginePlanningTest` class in a fresh, single-fork 512 MiB-heap worker;
this does not raise its production/fixture RSS cap.

`DECOMP_CI_TEST_SHARD=core` selects tests excluding the `ci-live` tag and retains
these isolated checks. `live` selects only that tag; the full default selects
both. These existing entry points retain their full selections.

Hosted CI splits ordinary core tests into `core-main` (the complement of
`decompengine.oracle.*`) and `core-oracle` (that namespace recursively), each
excluding `ci-live`. Gradle's [test-name filters](https://docs.gradle.org/current/javadoc/org/gradle/api/tasks/testing/TestFilter.html)
select a package recursively and its complement; new classes enter their group
automatically. Both selections fail if no tests match. The existing `kotlin-core`
job runs `core-main`; `kotlin-oracle` runs `core-oracle`.

Hosted live tests use `live-fulltree` for `decompengine.oracle.fulltree.*` and
`live-rest` for its complement, both retaining the `ci-live` tag. Their Gradle
property is accepted only with `ciTestShard=live`; unknown values fail. New live
classes enter exactly one group, and both selections fail if no tests match.
`kotlin-live` runs the complement and retains the existing Goose/Codex preflights;
`kotlin-live-fulltree` runs the full-tree group. The original `live` shell/Gradle
entry point still selects the complete tagged suite. The `kotlin` aggregate
requires all four jobs.

The completed [7b29 main run](https://github.com/minsago-elite/decomp_thing/actions/runs/39109611472)
reported 62 live executions in three XML suites: 36 full-tree cases totaling
716.947 case-seconds and 26 other cases totaling 775.577 case-seconds. The live
job took 2,034 seconds; its JVM/Kotlin step took 1,635 seconds. These historical
case timings motivate the two groups. Current-source runs must establish actual
elapsed improvement and total runner cost; no speedup is inferred from the split.

`core-oracle` owns the isolated GCC planning class, the three isolated V3 boundary
methods and the 115 synthetic class-data controls. The class-data gate still runs
before expensive Kotlin compilation in its owning task graph. The isolated
workers keep their existing heaps, RSS bounds and fresh execution. `core-main`
retains real Angr selection/qualification and the quota-backed repair snapshot
follow-up. All four jobs retain their existing hosted runtime, sandbox, quota,
scratch provisioning and unconditional cleanup. Each uploads its own
`kotlin-core`, `kotlin-oracle`, `kotlin-live` or `kotlin-live-fulltree` test-report artifact.
The quota follow-up receives `core-main` in its nested test invocation, keeping
the selected repair fixture while its host-side preparation remains unchanged.
This prevents that follow-up from starting the isolated GCC/class-data gates
again. Nonowning or unknown CI selectors refuse before preparation; legacy
combined and local invocations keep their original selection.

`scripts/test-ci-partitions.py` exercises the actual shell entry point with an
inert Gradle argument recorder, including full/legacy/live selections, each new
partition and refusal before invocation for unsupported values. Before accepting
the split, compare the complete current XML execution union against the qualified
original inventory, preserving explicit skips and isolated executions. In
particular, the quota snapshot method's full-suite skip and separately required
pass are distinct executions. Job/step durations and total runner time describe
different costs; the historical elapsed observations alone establish no speedup.
The aggregate also downloads only the four standard Kotlin test-report artifacts
into separate named directories. Its Python XML check requires nonempty reports,
correct oracle/complement and full-tree/complement ownership, no failed cases and
no test identity shared across physical shards. Unexpected artifacts are rejected.
Schema 2 retains logical `core`/`oracle`/`live` totals and adds physical `reportShards`
plus each input's shard identity. Within core, the quota fixture's skip/pass pair stays
distinct. `kotlin-partition-inventory` retains counts and input hashes; routing and
report-placement regression controls run in the core job. This placement check
complements the complete original-inventory comparison above.

Core also runs the authored source/XML controls in
`scripts/test-web-job-recovery-inventory.py` and consumes its already executed
JUnit reports with `scripts/verify-web-job-recovery.py --reports`. This guard
requires every literal zero-argument `@Test` scenario in the 19 selected benign
jobs/web classes, including nested source declarations that Jupiter would fail
to discover. Missing, duplicate, unexpected, failed, erroneous or skipped cases
refuse coverage; reported counts must match actual testcase outcomes. Other test
declaration forms require an explicit extension and are refused by this corpus's
declaration check. No additional Gradle/JVM test run is started by the guard.

`web-job-recovery-inventory.json` is retained with the core reports. It binds case
identities/results to XML hashes, declaration source hashes and a Git snapshot;
the CI checkout/compilation join remains separate evidence. Every selected test
also emits a bounded record from its existing JUnit JVM: Java runtime/vendor/VM,
OS/kernel version and architecture, plus provider, filesystem type, block-size
availability, read-only state and POSIX/Unix views for each created fixture root.
The fixture factory keeps temporary roots inside the repository. Records contain
test identities and root ordinals, without fixture paths, prefixes, environment
values, process identifiers or exception messages.

Missing, duplicated or mismatched records, unknown fields and inconsistent facts
refuse configuration coverage. The selected source contract also refuses known
direct temporary-root APIs or local bindings that bypass the recorded factory.
Cases without fixture roots and unsupported
block-size observations remain explicit. These are observed fixture facts;
they do not authenticate an immutable host, a mount identity or execution
authority. `fullMatrixQualified` remains false pending the complete supported
matrix and integration evidence. No power-loss, external-process, provider/model
or release qualification follows from these records.
The standalone runner's manifest is version 2; its Java/kernel/temporary-filesystem
fields describe the launcher, while testcase configuration comes from the JUnit
records. The report-consumption inventory is version 3.

The pinned Codex ACP qualifier admits its exact-size/SHA-256 archive before
`installDist`. Two official HTTPS endpoints have one bounded attempt each; only
verified regular archives enter the content-keyed Actions download cache. Corrupt
or linked cache entries refuse rather than repair or follow them, and atomic
publication never replaces an existing entry. `--fetch-archive` stops before the
build, extraction and qualification. The core job runs nine inert acquisition
controls with fake curl and forbidden runtime/extraction commands. This caches
archive bytes only; current qualification reports still require fresh execution.
The original native mount-event refusal and cleanup gates remain unwaived.

Hosted workflows additionally prepare fixtures and run credential-free
preflights, frontend/browser jobs and separate contract/oracle workflows through
the entry points below.

Gradle also builds the embedded frontend. CI provisions the exact Node 24.20.0 /
npm 11.19.0 distribution using `scripts/install-frontend-node.sh`; the installer
checks the reviewed official archive digest and repository version pins. Local
builds need the same toolchain on PATH. Node is a build dependency and is absent
from the application Docker runtime stage.

The production frontend build also runs the same strict lint gate before emitting
its bundle. When embedded assets and root Kotlin compilation are already selected
in one Gradle graph, `frontendBuild` runs before `compileKotlin` and
`compileTestKotlin`, so frontend validation errors refuse before that Kotlin work.
This ordering does not select frontend tasks for standalone Kotlin compilation.
All existing qualification tasks still run; only JVM compiler outputs are cached.

The independent **Frontend contracts and bundle** job runs on pull requests and
pushes to master or tags. It uses a clean locked npm install, strict type checking, lint, component
and state tests, the versioned web schema's positive/negative fixtures, a production
bundle with size/dependency checks, and the manifest completeness/digest tests.
It also rejects changes to checked frontend or contract inputs produced by those
commands. CI restores npm's package-download cache keyed to the lockfile, while
each job still installs clean `node_modules` and builds the current bundle. No
generated bundle or `node_modules` tree is restored.
Its existing deliberate contract-drift fixtures retain four
`expected-web-api-rejection` records in `api-drift-tests.txt`: changed generated
types, changed generated schema, changed source schema and an unsupported schema
keyword. Each records exit 1 without a signal, a bounded rejection diagnostic
with the fixture root redacted, and unchanged hashes for all four fixture inputs.
The authored bad inputs are expected refusals within the passing test; this
receipt supplies no clean/cache-hit or broader integration qualification.

### Compilation and download cache boundaries

`gradle.properties` enables Gradle task-output caching. The root build applies an
unconditional `doNotCacheIf` predicate across all projects to every task except
`JavaCompile` and `KotlinCompile`. Compiler outputs retain Gradle's ordinary source,
classpath, compiler and toolchain cache inputs. This enables no configuration
cache, remote cache service or additional credential authority.

`Test`, `Exec`, `JavaExec`, resource generation and packaging tasks cannot restore
task outputs from this cache. Existing task selections, freshness guards, native
limits and required failures remain in force. Qualification reports must describe
the current compiled source and join its actual standard XML inventory; compiler
reuse does not qualify a runtime test or release.

Gradle jobs restore the shared master cache on pull requests; only master writes
new entries. npm caching retains package downloads, with a clean locked install
and current frontend build in each job. Neither cache supplies prior test XML or
a generated release bundle.

A completed ordinary log's compiler `FROM-CACHE` disposition demonstrates reused
compiler output for that source. `UP-TO-DATE` alone does not establish cross-build
reuse. Cache configuration, a cache hit or elapsed time alone establishes no fixed
speedup or whole-CI cost improvement; preserve the required execution and report
evidence independently.

Run the frontend checks locally with the pinned tools:

```bash
npm --prefix frontend ci --ignore-scripts --no-audit --no-fund
python3 -m pip install --requirement requirements/oracle-generation.txt
python3 contracts/web/v1/verify.py
npm --prefix frontend run typecheck
npm --prefix frontend run lint
npm --prefix frontend test
npm --prefix frontend run build
frontend_version="$(node -p "require('./frontend/package.json').version")"
node scripts/web-asset-manifest.mjs build/frontend/dist "$frontend_version" --write build/frontend/asset-manifest.json
node scripts/web-asset-manifest.mjs build/frontend/dist "$frontend_version" --verify build/frontend/asset-manifest.json
node --test scripts/web-asset-manifest.test.mjs
```

The standalone manifest check uses the frontend package version; Gradle binds the
packaged inventory to the JVM application version. CI retains synthetic test
results, tool/lock/schema identities and bundle/manifest metadata as
`frontend-verification` for 14 days, including after failures. It does not upload
environment dumps, credentials, private source maps or generated job content.

The **Packaged web contracts and browser** job also runs on pull requests and
pushes to master or tags. It builds the archives from the current checkout, runs
`BrowserSessionExpiryTest` with pinned Chrome/Node, verifies relocated read-only
ZIP/TAR HTTP serving and Ghidra native
permissions, and retains the existing ACP/LLVM/BOOT distribution checks. Pinned
Chrome then checks the public shell, lazy Runtime route, explicit chunk recovery,
session exchange/reload/logout, exact binary metadata, focused live updates,
10,000-job paging and the explicit Vite proxy against the same ZIP.
The application process has no Node/npm on PATH and starts from an unrelated
directory. Session/proxy journeys preserve empty job storage; metadata, live and
scale journeys use authored inert job fixtures and start no workflow execution.
The JVM web-contract step uses those same pinned Chrome/Node paths to require the
existing real-browser session-expiry, private-read refusal and fresh operator-link
exchange test. Its injected monotonic clock advances the session age without a
wall-clock wait; ordinary hosts without Chrome retain the opt-in test behavior.

All ordinary web/job JVM contracts remain in the automatic core namespace
selection and its required aggregate; the packaged lane no longer repeats those
hundreds of executions. It retains all methods in `BrowserSessionExpiryTest`,
including HTTP-clock and process-cleanup controls, because the actual browser
method is explicitly skipped on ordinary hosts without Chrome. A report gate
requires that exact browser method once, valid suite/class/method identities,
matching aggregate counts and no failed, errored or skipped case in its suite. The complete report directory is
inventoried under 128-entry/eight-level limits and must contain exactly that one
regular XML input, including nested/case-variant XML. Gradle's regular binary
result files remain allowed; symlink files/directories and nonregular entries
refuse. Missing, linked, malformed, oversized, foreign, duplicate and empty reports refuse; the retained receipt binds the exact
XML bytes/hash. Core runs the report gate's positive and negative controls.
The focused `packaged-browser-expiry-test-reports` artifact retains the exact
expiry XML and gate receipt for independent byte/hash checks without restoring
browser journey payloads. The existing full packaged evidence upload is retained.
Packaging, archive/helper/closure verification and every packaged browser journey
keep their existing commands and current-source inputs. This scheduling change
does not qualify an additional target/resource matrix or establish a measured
speedup; compare actual job and runner costs after current Actions finish.

`scripts/web-test-browser.json` pins Chrome for Testing 149.0.7827.55 for Linux
x86-64 by exact URL, length, archive SHA-256 and expanded inventory. Its
[official version metadata](https://googlechromelabs.github.io/chrome-for-testing/149.0.7827.55.json)
identifies the download; the checked SHA-256 is our content lock on those bytes,
not an upstream signature. `scripts/install-web-test-browser.py` verifies the
archive before extracting into a fresh test-tool directory and preserves an
existing destination. Ubuntu CI installs the archive's `deb.deps`, following the
[upstream dependency instructions](https://github.com/GoogleChromeLabs/chrome-for-testing#how-to-install-the-system-level-dependencies-required-for-archived-linux64-binaries).
The browser is separate from all application distributions. CI explicitly uses
`--no-sandbox` on its disposable runner; each report records that setting and the
actual executable digest/CDP version. It does not qualify browser sandbox behavior.

The packaged lane retains JSON reports, screenshots, tool pins and JVM test
reports as `packaged-web-verification` for 14 days even after failure. Session
secrets and bootstrap fragments are redacted; extraction/browser working data is
removed after confirmed process shutdown. No browser cache or frontend output
cache supplies the release; the existing Gradle dependency cache remains enabled.

These are checkpoints under [#225](https://github.com/minsago-elite/decomp_thing/issues/225)
and [#227](https://github.com/minsago-elite/decomp_thing/issues/227). Expanded
upload/workflow/evidence/download journeys, accessibility/scale qualification,
Git/provider gates and hosted clean/cache/failure evidence remain open. A schema
fixture pass does not establish an implemented endpoint. Branch-protection
requirements are administered separately; a workflow job alone does not prove
that GitHub requires its result for merge.
The existing Kotlin, ACP, Clang, archival and oracle jobs retain their checks;
the manual LLVM source rebuild remains the optional expensive lane described below.

### Lane ownership and explicit qualification

The workflow/script paths below own scheduling and gate behavior. Normal runs
mean pull requests and master/tag pushes; the oracle-model normal jobs explicitly
exclude manual dispatch. Expensive scheduled checks remain part of normal CI.
Optional means an explicit selection condition; selected jobs must still pass
their checks. GitHub branch-protection requirements remain separate as noted above.

| Lane | Scheduling and responsibility | Source |
| --- | --- | --- |
| Frontend contracts and bundle | Normal; locked install, schema/generated-input drift, type/lint/component/state, isolated Git fixtures and bundle checks. Frontend behavior remains owned by #223 and integration by #227. | [ci.yml](../.github/workflows/ci.yml), `frontend/package.json` |
| Packaged web contracts and browser | Normal; browser-expiry JVM suite with positive report gate, current archives, helper/closure/BOOT distribution checks and packaged session/metadata/live/scale/proxy journeys. #224 owns JVM contracts, #225 packaged journeys and #227 integration. | [ci.yml](../.github/workflows/ci.yml), [web-packaging.md](web-packaging.md) |
| Kotlin core / oracle / live / live-fulltree / aggregate | Normal; complementary ordinary core/oracle namespaces and tagged full-tree/complement live groups run with required hosted fixtures. Oracle owns the isolated RSS/class-data checks; core owns real Angr and quota snapshot follow-up. Primary live retains the pinned credential-free Goose initialize and Codex authentication-boundary preflights. The `kotlin` aggregate requires every shard to succeed. | [ci.yml](../.github/workflows/ci.yml), [ci.sh](../scripts/ci.sh), `build.gradle.kts` |
| Bundled Ghidra / archival Ghidra / Clang | Normal, including the heavier direct-API/native, Docker archival and strict Clang/sanitizer checks. | [ci.yml](../.github/workflows/ci.yml), `scripts/validate-archival-docker.sh`, `scripts/validate-clang.sh` |
| ACP contract / Built-in core contract | Normal and dispatchable; required host and strict fixture inventories, with missing/failed/skipped required verification refused. | [acp-contract.yml](../.github/workflows/acp-contract.yml), [builtin-contract.yml](../.github/workflows/builtin-contract.yml) |
| GCC / LLVM oracle-model normal jobs | Normal; their existing source, provenance, artifact/reference and generation checks retain their separate oracle authority. The LLVM workflow also emits a dedicated `required-contract` check that succeeds only after the normal provenance lane succeeds; manual dispatch does not rerun these normal jobs. | [gcc-oracle-model.yml](../.github/workflows/gcc-oracle-model.yml), [llvm-oracle-model.yml](../.github/workflows/llvm-oracle-model.yml) |
| Retained GCC driver DWARF interfaces | Explicit dispatch, or a triggered PR run already carrying `qualify:driver-dwarf-interfaces`. Applying the label alone is not a configured workflow trigger. | `driver-dwarf-interfaces` in [gcc-oracle-model.yml](../.github/workflows/gcc-oracle-model.yml) |
| LLVM native runtime measurement | Explicit dispatch with `qualification=native-runtime-measurement`; measurement does not approve a production runtime. | `native-runtime-measurement` in [llvm-oracle-model.yml](../.github/workflows/llvm-oracle-model.yml) |
| LLVM oracle clean rebuild | Manual dispatch only; run when the locked source/toolchain/flags/artifact pair needs fresh rebuild evidence. | [llvm-oracle-rebuild.yml](../.github/workflows/llvm-oracle-rebuild.yml) |

Core performs installed analysis-I/O verification and quota snapshot preparation
in one invocation of `bash scripts/test-repair-validation-snapshot.sh --ci-verify-installed-analysis-io`.
The fixed mode includes `verifyAnalysisIoHelperInstalled` with the existing
preparation targets, retains `build/analysis-native-installed-verification.txt`,
and fails before fixture work if that Gradle pipeline fails. The combined
invocation preserves this check. Live does not request this core-only mode.

Capability acceptance remains with its existing owners. #215 owns
Git synchronization/provider qualification; #223–#226 retain their component,
JVM, packaged, accessibility/scale/adverse-condition requirements. #227 and this
documentation slice #653 do not close those dependencies or supply a release claim.

The test task first builds and verifies the same static ACP gate helper shipped by `installDist`; security-boundary
tests do not compile private helper copies. Distribution jobs should additionally run
`./gradlew --no-daemon verifyAcpGateHelperDistribution`.

The independent `ACP contract` workflow runs every ACP and shared-agent regression suite
with `DECOMP_REQUIRE_LIVE_ACP_CONTRACT=1`. Missing host capabilities fail this lane.
It installs the same checksum-verified frontend Node/npm distribution before invoking
Gradle and adds its `bin` directory to subsequent steps through `GITHUB_PATH`.
The runner's default Node is not a valid substitute for the embedded bundle's build pins.
It provisions an empty, user-owned mode-0700 dedicated tmpfs with 64 MiB and 4,096
inodes for `DECOMP_TEST_ACP_QUOTA_TMPFS`, and unmounts it in an unconditional cleanup
step. The main Kotlin job provisions the same fixture. An existing mount is never
adopted, and cleanup does not use a lazy unmount.

On an already provisioned supported host, run `bash scripts/validate-acp-contract.sh`.
The gate rejects missing required suites, failures and skipped tests, and retains
JUnit XML plus `build/acp-contract-qualification/summary.json`. This qualifies the
scripted contract boundary; independent authenticated agents and full release
acceptance have their separate issue #67/#72 requirements. Ordinary local tests may
skip unavailable host integrations when the required-host flag is unset.

The independent **Built-in core contract** invokes
`python3 scripts/validate-builtin-contract.py`. It forces test execution with the
required live host and checks its fixed required suite/case inventory with zero
failures, errors or skips. It retains
`build/builtin-contract-qualification/summary.json`; its real-provider and workflow
release qualification fields remain false.

Run the independent generated-C compatibility lane with LLVM/Clang:

```bash
DECOMP_TEST_CLANG=/absolute/path/to/clang scripts/validate-clang.sh
```

That gate compiles the single-file, archival, and vulnerability fixtures with
strict Clang warnings, proves the intentional uninitialized-use diagnostic,
requires AddressSanitizer and UndefinedBehaviorSanitizer findings, and builds a
generated multi-module project through an explicit `CC=clang` selection.

The two existing sanitizer calls retain their original options and diagnostic
checks. Before executing GNU `timeout`, `run-clang-sanitizer.py` sets a hard
regular-file write limit of 1 MiB plus one overflow sentinel byte, disables core
files, and refuses a smaller inherited limit. Both stdout and stderr must remain
at or below 1 MiB; exactly that size is accepted, while the sentinel byte forces
rejection even if an expected diagnostic was already printed. Timeout requests
TERM after ten seconds and KILL one second later. Timeout, setup, invocation and
file-limit signal statuses fail before diagnostic matching; status 137 supplies
no process-absence fact. The temporary validation tree is beneath repository
`build/`. Early Actions controls exercise the real script and limit launcher
with authored fake compiler output and a fake Gradle command; they run no compiler,
JVM or native vulnerability fixture. The existing Clang lane remains the actual
compatibility integration gate.

The repository workflow also runs the pinned Ghidra image against symbol-bearing and stripped large fixtures:

```bash
scripts/validate-archival-docker.sh
```

That heavier gate compiles both binaries, runs complete evidence-only source-tree reconstruction, requires non-empty global/string recovery, compares repeated rich and stripped models and archives byte-for-byte, verifies every archive payload hash, and rebuilds the freshly extracted project. The explicit evidence-only policy retains every raw model entity and its planned ownership while compiling diagnostic inventory sources. It preserves unsupported display text as evidence, keeps implementation acceptance false, and does not claim that the diagnostic executable reproduces the input program's ABI or behavior. The ordinary generated-C declaration and implementation gates remain strict.

Archival exit cleanup retains bounded build/owner diagnostics before removal. It
admits the original disposable root device/inode and reads selected regular,
single-link files through retained non-following directory descriptors. Names are
JSON-escaped data. Collection allows 4,096 entry advances (including EOF), 24
relative path components including output, 128 KiB of cumulative entry paths, and 256 KiB of
JSONL output. Each file supplies at most 32 KiB, 240 lines and 1 KiB per rendered
line; `truncated` records intentional excerpt omissions. Missing, unreadable,
changed or over-budget evidence produces an explicit incomplete result and
retains the tree. `archival-build-diagnostics` uploads the bounded JSONL on both
successful and failed runs.

GNU [`timeout`](https://www.gnu.org/software/coreutils/manual/html_node/timeout-invocation.html)
requests TERM after 10 seconds for the single permission-repair attempt and for
collection, two seconds for root checks and diagnostic display, and 20 seconds
for removal; KILL is requested one second later. Collection also checks an
eight-second internal deadline and applies a non-increasing
[`RLIMIT_FSIZE`](https://docs.python.org/3.12/library/resource.html) ceiling in its
own process. A timeout or status 137 remains incomplete cleanup and establishes
no process-absence fact. Repair cannot pull an image and runs only after
the build completed. A failed repair is not relaunched by the EXIT trap. Cleanup
preserves the original nonzero validation exit; incomplete cleanup also fails an
otherwise successful validation. Authored controls exercise the actual collector
and shell trap with fake Docker, including bounded hung-command cases, in the
frontend gate before the heavy job fanout. These controls do not qualify an ACP
agent, host-mount cause or production process-cleanup authority.

### Real Angr proposal qualification

The core partition selects `realAngrQualification` when the workflow, Docker
production pin, Gradle build, Angr requirement/runner/selector, or exploration
source/tests change. Pull requests compare against their event base SHA; pushes
compare the complete update against the event's previous SHA, fetching that
specific commit if needed. An absent/zero/unavailable base conservatively selects
qualification. Authored local-Git fixtures in Actions cover multi-commit pushes,
shallow history, production-pin changes, unrelated updates and missing bases.
Unrelated changes reuse the deterministic adapter suite without installing Angr;
selected runs cache package downloads without reusing prior qualification results.
The shared `angr-compatibility.txt` constrains bitstring to 4.4.0 in both Docker and
qualification: the unconstrained 5.0 release removed `ConstBitStream` used by this
Angr version. Docker also checks that the installed Angr imports successfully.

The selected lane requires matching Docker/default and requirements Angr pins
(currently `9.2.213`) before installing into a workspace virtual environment and
runs the existing branching argv/stdin fixture once. Its dedicated Gradle task
requires an absolute executable `ANGR_PYTHON`, disables cached test credit, and gives
the test JVM a small explicit environment without parent credentials. The ordinary
optional test reports SKIP when the interpreter is absent. Missing configuration,
no matching test, a skipped test, or a failed discovery cannot qualify the lane.

`real-angr-qualification` retains the checkout/tree, source digests, pip install
report and resolved package versions, interpreter/module identities, compiler
version, exact Gradle command, compiled fixture and C source, candidate bytes,
search diagnostics and JUnit result. The adapter's 60-second search bound and
dedicated task's three-minute timeout sit inside an eight-minute Actions step.
These results concern proposal discovery on the authored fixture; they establish
neither equivalence nor production execution attestation.

### Reporting skipped or unrun verification

Record the source commit/ref, exact command and selected lane, required-host flags
and prerequisites, actual test/failure/error/skip counts, reasons and retained
artifacts. Distinguish reused task output from fresh execution. An optional lane
not selected, or a phase blocked by setup/preflight failure before tests, is unrun;
missing reports do not establish passing tests or verified cleanup. Ordinary local
integration skips do not satisfy a required no-skip contract. Retain the original
failure and any later repeat separately, and state which checks were not repeated.

Project planning is maintained in [GitHub milestones](https://github.com/minsago-elite/decomp_thing/milestones) and [issues](https://github.com/minsago-elite/decomp_thing/issues). `ROADMAP.md` is deprecated and is not generated or checked by CI.

## Source-aligned compiler oracles

The independent `GCC oracle model` and `LLVM oracle model` workflows verify
authenticated upstream releases, immutable toolchain/build records,
DWARF-rich and stripped ELF equivalence, deterministic function-recovery
ground truth, and checked behavior evidence. The LLVM lane fetches the binary
pair as ordinary release assets from the separate
`minsago-elite/decomp_thing-oracle-artifacts` repository. The checked release
lock authenticates the repository, non-moving tag, URLs, byte lengths, and
SHA-256 digests before either binary is installed in runner-temporary storage;
no binary is stored in this repository. The lane also rebuilds the Clang
toolchain recipe and checks its immutable base, Dockerfile, build-record
binding, platform, and every recorded live tool's exact executable bytes and
version output. The Docker image ID is retained as origin provenance rather
than used as a false layer-reproducibility claim.
On push/PR events, `llvm-oracle-model.yml` publishes the uniquely named
`LLVM oracle required-contract` check (job ID `llvm-required-contract`). It fails
if the normal provenance lane does not pass, so branch protection can require
this LLVM status independently of the ACP workflow's `required-contract` check.

The expensive source rebuild is intentionally manual. Run the `LLVM oracle
clean rebuild` workflow when the source lock, toolchain, flags, or artifact
pair changes; ordinary pushes and pull requests verify the already-reviewed
bytes. Exact LLVM commands and benchmark boundaries are documented in
`oracle/llvm/22.1.6/README.md`.

## Required CI Tools

Install these system tools before running the test suite:

- JDK 21
- Node 24.20.0 and npm 11.19.0 for frontend build tasks
- `gcc` and `make`
- static libc development objects for `/usr/bin/cc -static` (included by Ubuntu's `build-essential` dependency set)
- LLVM/Clang 18 for `scripts/validate-clang.sh`
- `bubblewrap`
- `binutils` for `strings`

Optional local integrations:

- Set `ANGR_PYTHON` to an angr-enabled Python executable to run the real symbolic argv/stdin integration test. The Docker image pins angr for production exploration; ordinary JVM tests use a deterministic process-adapter fixture.
- `ACP_CONFIG_FILE` selects the strict ACP v1 provisioning used by agent-backed workflows. Explicit non-provider agent
  secrets remain in the named environment sources declared by that private configuration and are forwarded to the
  agent, not serialized into the configuration. Provider credentials belong only to the separately qualified operator
  broker, whose transport is unavailable in the current network-free deployment; see the
  [provider credential boundary](acp-v1-client.md#provider-credentials-and-current-availability).
- `BASE_URL`, `API_KEY`, and `MODEL` are deprecated compatibility inputs and are accepted only with exact
  `ACP_HARNESS=legacy-openai` or `--harness legacy-openai`. The pinned MVP fixture retains that explicit legacy path.
- Ghidra is bundled through its Java API worker. Gradle stages the hash-locked
  release even for focused test tasks; fake-worker tests avoid analysis execution.
  The separate bundled-Ghidra lane enables the real installed API/provenance,
  decompiler and source-tree tests without `GHIDRA_HOME`.

## GitHub Actions Consumer Example

Projects that want to run decompilation validation in CI can use the same dependency set:

```yaml
name: Decomp Validation

on:
  pull_request:

jobs:
  validate:
    runs-on: ubuntu-24.04
    steps:
      - uses: actions/checkout@v4
        with:
          submodules: recursive
      - uses: actions/setup-java@v4
        with:
          distribution: temurin
          java-version: "21"
      - run: |
          bash scripts/install-frontend-node.sh "$RUNNER_TEMP/frontend-node"
          echo "$RUNNER_TEMP/frontend-node/bin" >> "$GITHUB_PATH"
      - run: |
          sudo apt-get update
          sudo apt-get install -y --no-install-recommends \
            bubblewrap \
            binutils \
            build-essential
      - run: ./gradlew --no-daemon test
```

## CI Artifacts

### Pinned Goose archive acquisition

The live lane rechecks the exact Goose 1.46.0 archive size and SHA-256 on every
cache read. Its digest-keyed Actions cache retains only archive bytes, with no
restore prefix or runtime evidence. Missing bytes use the canonical official
release URL and then its immutable release-asset API endpoint, with one attempt
per endpoint, HTTPS-only redirects, a 15-second connection bound, 120 seconds per
transfer and the exact archive byte ceiling. Invalid successful responses and
invalid/linked cache entries refuse; complete verified bytes publish atomically
without replacing an existing entry. Acquisition precedes the application build.
Transport-only controls use inert bytes and a fake curl. The unchanged archive
layout, provisioning, runtime manifest, credential-free initialize and required
outcome gate still apply; no agent invocation is retried and no failure is waived.
The `--fetch-archive` mode only verifies/acquires bytes and performs no extraction
or runtime execution. This cache is an optimization, not measured speedup evidence.

Useful artifacts to retain:

- `frontend-verification` from the dedicated frontend job (component results and build/contract metadata)
- `packaged-web-verification` (sanitized browser reports/screenshots, exact tool pins and JVM web contracts)
- `build/reports/tests/test`
- `build/test-results/test`
- generated behavior reports under project `reports/`
- generated exploration reports such as `exploration.json`
- repair history reports such as `repair_history.json`
- archival `source-tree.zip`, `ARCHIVE_MANIFEST.sha256`, and `reports/archival_audit.json`

## Determinism Notes

The default CI path does not require external services. Tests exercise deterministic fakes for angr and the OpenAI-compatible API. Ghidra is additionally exercised in the pinned Docker gate so exporter API compatibility and stripped-binary determinism are verified against the production integration.


### Reviewed Node archive download cache

Eight existing install steps in normal CI, ACP, built-in and LLVM model jobs opt
in with `DECOMP_FRONTEND_NODE_DOWNLOAD_CACHE=1`. Other callers, including Docker,
keep the original download behavior and require no writable repository cache.
Actions shares an exact-key cache for `build/frontend-node-downloads`, containing
only the pinned official Node archive. The key includes OS/architecture, installer,
reviewed checksums, Node pin and package metadata; there is no broad restore prefix.
A hit is copied into a fresh owned stage and passes the original strict SHA-256,
extracted Node/npm versions and repository package/toolchain checks before use.
Linked cache directories, linked/nonregular archive entries and bad checksums refuse.

A miss uses the original fixed HTTPS download and bounds, then publishes the fully
verified archive through an owned same-directory temporary file without overwriting
a concurrent winner. Interrupted copies are not published as hits; owned staging
and cache temporary files are cleaned on exit. Every installation remains fresh;
all original qualification/test commands still run. The cache contains no
node_modules, compiled output, installation, report or runtime/provider evidence.
A corrupt immutable Actions cache must be removed; archive authentication remains
mandatory.

This is prepared source. Its own normal Actions must establish hit/miss behavior
and any download or whole-CI savings; no measured speedup is claimed.
