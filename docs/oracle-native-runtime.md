# Authenticated native runtime on noexec scratch

Full-tree oracle scratch remains `rw,nodev,nosuid,noexec`. JNA normally extracts
`libjnidispatch.so` into its temporary directory, then maps executable segments.
On `noexec` scratch this fails before the worker can open its first Linux directory
descriptor and publish BOOT. SQLite JDBC's extracted native library has the same
mount incompatibility. Changing the scratch mount to executable is not a fix.

`stageOracleNativeLibraries` selects the exact resolved JNA 5.19.1 and SQLite JDBC
3.53.2.1 JARs and authenticates their complete SHA-256 digests before extracting the
single selected Linux x86-64 resource from each. Resource size and SHA-256 are also
fixed in `src/main/resources/oracle-native-libraries-v1.properties`; its SHA-256 is
`9aaf1a677614cb354269ed55f5f86e5ec4a91d87c917954c54e972da4a6bb2e2`.
No target binary is run by staging. Application distributions carry the two files
under `libexec/oracle-native`; the build staging directory is `build/native/oracle`.

The trusted provisioner installs the two libraries at
`<authenticated-java-runtime>/lib/decomp-oracle-native`, as root-owned mode-0644
regular files in a root-owned mode-0755 directory, **before** calculating the JDK
runtime manifest. CI does this in `scripts/ci-prepare-oracle-runtime.sh` while
constructing its separate root-owned JDK. Production authentication requires exactly
the two filenames, exact descriptor-checked sizes/digests, and exactly one matching
dependency JAR identity in the authenticated classpath. The complete JDK manifest
continues to enforce recursive root ownership and absence of group/world writes.
No user-owned build directory substitutes for that runtime trust root.

Supervisor, observer and generic Kotlin BOOT keeper use the sandbox-side JDK native
directory, already covered by the existing read-only runtime mount. Their JVMs set
`jna.nosys=true`, `jna.nounpack=true`, and `jna.boot.library.path` to that directory,
plus explicit `org.sqlite.lib.path` and `org.sqlite.lib.name=libsqlitejdbc.so`.
The supervisor passes the same native directory to its worker. Java/JNA temporary
paths remain the existing bounded run `tmp` directory; native/runtime paths must
not overlap writable run scratch. This adds no mount, writable executable output,
START permission, publication authority, or larger resource budget.

## Identity transition

Native-library integration introduced isolation configuration schema 3 / provider
`kotlin-full-tree-function-observation-isolation-configuration-v3`; its internal
supervisor protocol is 2. The generic Kotlin BOOT runtime closure is schema 2 /
provider `kotlin-systemd-cgroup-boot-runtime-v2`. Both canonical configurations bind
`nativeLibraryProfileSha256`. Worker and BOOT-keeper wire protocols are unchanged.
The canonical fixture isolation digest changes from
`107fe58551ea95533bada45432758c1882ba3876c5681a1c43282c10433138d3` to
`0feb4469bc91b6668777ddc336dd39c4d2db76db932ee4e74a729de34deff740`.
Tests retain the old fixture digest and independently reconstruct its old shape.

Existing artifact schemas remain unchanged. Operation bindings, receipts, journal
chains and deployment runtime references derived from the changed configuration
have new hashes. Old bytes are not rewritten, blessed or silently upgraded: they
cannot match the new runtime configuration. Resume must use its original verified
runtime or remain unadmitted; new work needs fresh configuration-bound identities.

## Verification scope

`OracleNativeLibrariesTest` checks dependency identity, missing/extra/corrupted and
linked native files, scratch overlap and JVM flags. A fresh-process paired test
first reproduces the old JNA `UnsatisfiedLinkError` on a writable `noexec` mount,
then loads both pinned JNI libraries and executes a SQLite query successfully with
all writable state on that same mount and no native extraction residue. CI requires
this regression to run; other hosts without a writable `noexec` mount skip it.
The frozen configuration and journal tests cover the derived identity transition.

The local focused selection completed 82 tests: 72 passed, zero failed, and ten
live systemd/ext4 cases skipped because this host lacks their provisioned boundary.
It includes all four native-library tests, 24 operation-journal tests, seven BOOT
diagnostic tests, seven GCC containment-contract tests and ten selected GCC
deployment/bootstrap tests. `./gradlew --offline installDist` and provisioner shell
syntax checks also pass; both installed library hashes match the pinned resources.

These tests do not prove production full-tree BOOT, retained compiler execution,
all-shard scoring, or release eligibility. Those still require their respective
provisioned hosted lifecycle and evidence gates.

### Hosted follow-up and failure preservation

The completed `bd45cfc` CI run `33943106312` ran 1,380 tests: 1,323 passed,
32 skipped and 25 failed. The first full-tree cold-attachment case retained
`worker.boot`, `worker.failure`, `supervisor.failure` and a quarantined deletion
entry; later cases failed because the ext4 slot remained occupied. This differs
from the earlier no-protocol pre-BOOT failure, but does not prove a successful
attachment. The fixture's final cleanup assertion replaced the original failure,
so neither that failure nor the protocol contents could be recovered from its
report. Do not attribute the remaining cause to JNA or claim hosted success.

The fixture now retains the original exception with cleanup failures suppressed,
and its existing bounded, pinned-root protocol sampler spans the full prepared
action, including cold recovery rather than launch alone. Cleanup-only failures
still fail. No residual filename is newly allowed, no unknown entry is deleted,
and unit/cgroup absence and ext4 cleanup requirements are unchanged. Local checks
run 39 tests: 29 pass, ten provisioned systemd/ext4 cases skip, and none fail.
All nine diagnostic tests execute, including primary/cleanup exception identity,
retained protocol evidence, and standalone cleanup failure regressions.

### Parent-owned failure cleanup

Completed [CI run 33944269759](https://github.com/minsago-elite/decomp_thing/actions/runs/33944269759)
at `fc1b821` ran 1,388 tests: 1,331 passed, 32 skipped and 25 failed. The preserved
first failure is `cannot open materialized class-path entry 0 through its pinned
descriptor`. Its bounded trace observes BOOT at 28,982 ms, a worker
`parent.start timed out` failure at 59,059 ms, and supervisor failure at 60,062 ms.
Cleanup then finds `.decomp-acp-entry-delete-...` instead of the original runtime
layout. The worker's failure handler attempted whole-run deletion, renaming the
parent-owned runtime before failing against its nested read-only mounts. Later
tests encounter the occupied ext4 slot. The journal collector's exit 137 is not
a worker exit or evidence of OOM.

The failed worker now publishes its bounded failure protocol, closes its own run
descriptor and exits without deleting the run tree. Runtime, scratch and protocol
evidence remain owned by the parent. Existing parent cleanup still requires its
retained authority, exact unit/cgroup absence and bounded deletion; an abandoned
lease remains fail-closed residue, not permission to delete an unknown tree.
No filename allowance, mount permission, START authority, timeout or resource
limit changes.

A fresh-JVM regression first reproduced the old runtime deletion as
`NoSuchFileException`. Two independent cases now pass: rejected START and an
invalid scope after valid START. Both require unchanged runtime bytes, inode and
read-only mode, preserved scratch, exact root membership and retained BOOT/failure
protocols. The focused ownership/native/diagnostic/isolation/disk/journal selection
runs 79 tests: 63 pass, 16 provisioned systemd/ext4 cases skip, none fail or error.
This proves failure ownership, not hosted lifecycle success. At this checkpoint,
the separate 30-second BOOT-to-START window and complete production
recovery/terminal release remained unresolved under #136/#138.

The subsequent full-tree-only run at `50288a4` executes 434 tests in 62 suites:
395 pass, 39 environment-dependent cases skip, and none fail or error. This run
does not include the separate schema-catalog suite or prove hosted containment.

### START admission within the existing systemd lifetime

The former 30-second timeout served two different purposes: waiting for the first
BOOT record, and holding the booted worker while the parent authenticated its
runtime, persisted UNIT_ATTACHED and performed query-only cold recovery. The latter
can legitimately outlast 30 seconds, as the retained hosted trace demonstrates.
Removing runtime verification or increasing the aggregate lifetime is not needed.

The first-BOOT wait remains 30 seconds. For both production preparation and the
non-authoritative fixture, the parent now supplies the authenticated scope-derived
systemd lifetime as an explicit upper bound on the worker's START wait. Command
construction rejects a different START bound. The existing lifetime formula is
unchanged: per-shard derivation wall seconds plus 360 seconds of existing protocol,
freeze and cleanup allowance. For the 1,200-second fixture scope, RuntimeMaxSec
remains 1,560 seconds. Whole seconds must be canonical, positive and representable
in nanoseconds; malformed or overflowing arguments fail before BOOT.

This is a shared lifetime, not a new admission allowance added to execution time.
The systemd clock begins before the child reaches BOOT and remains the earlier
hard deadline. START never resets that clock, and late admission may leave too
little time for derivation or acknowledgement. Parent derivation/CPU/memory/disk
limits and terminal absence requirements are unchanged. Without the exact parent
START record the worker still cannot load scope or produce candidate observations;
its finite local wait expires without deleting parent-owned evidence.

The current isolation configuration is schema 4 / provider
`kotlin-full-tree-function-observation-isolation-configuration-v4`. It binds
`workerRequestVersion=2` and
`workerStartWaitPolicy=scope-derived-systemd-lifetime-upper-bound-v1`; the supervisor
request protocol is 3. The worker request gains the canonical START-wait seconds
as its tenth argument. BOOT/START/READY/ACK/failure wire records remain protocol 1,
and the generic Kotlin BOOT keeper is unchanged. Legacy nine-argument requests are
rejected, not upgraded with an implicit new timeout.

The canonical isolation fixture digest changes from schema-3
`0feb4469bc91b6668777ddc336dd39c4d2db76db932ee4e74a729de34deff740` to
`4684f36bebedaba80eaedf7c7f578b66f9219d4dd1042d0f1debcab6c64d7a90`.
Tests reconstruct the previous schema-3 and schema-2 configurations independently.
Journal schemas do not change: their configuration/request/binding commitments
and subsequent receipt/transition hashes do. Historical schema-3-runtime journal
bytes retain all six previous frozen digests, round-trip unchanged and cannot
validate a history against the current runtime binding. They do not authorize
resume under the new configuration.

Fresh JVM cases cover valid START delayed until 31 seconds after observed BOOT,
one-second missing-START expiry, rejected START, malformed scope after START and
legacy request rejection. These checks are not proof of the provisioned hosted
BOOT/UNIT_ATTACHED/cold-recovery lifecycle or completed production START/release.
The focused admission/native/diagnostic/isolation/disk/journal/schema selection
executes 94 tests: 78 pass, 16 provisioned systemd/ext4 cases skip, and none fail
or error. All seven admission/ownership tests, 25 journal tests and nine schema
tests execute without skips.
