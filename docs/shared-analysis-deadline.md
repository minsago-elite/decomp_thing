# Shared analysis deadline

The JVM wrapper now passes its original elapsed allowance into the bundled
program-model analyzer. Previously the wrapper checked an injected analyzer only
after it returned, while the bundled worker used a later start time and bundle
verification/model parsing had no caller checkpoints. This layer supplies the
missing integration; it reuses the existing
[bounded metadata reader](bounded-elf-metadata.md) and
[bounded report publisher](bounded-report-publication.md).

## Deadline propagation and evidence

`GhidraJvmAnalyzer` creates an `AnalysisDeadline` before output preparation. Its
bundled `GhidraHeadlessProgramModelAnalyzer` receives that parent through an
internal method and creates a child with its own configured worker timeout.
Remaining time is the smaller of the parent and child allowances, computed from
elapsed subtraction. Neither clock is restarted for command preparation, worker
execution, diagnostic collection, or canonical model validation. Metadata and
summary publication continue to use the wrapper's original deadline.

`withExportBudgets` retains stricter configured worker limits and the
checkpoint-aware bundled command factory. It does not mutate profile identity or
the requested budget descriptor. An arbitrary injected `ProgramModelAnalyzer`
SAM keeps its existing calling contract: the wrapper checks before dispatch and
after return, but cannot interrupt its implementation internally.

The bundled path checks time and cancellation before preparation, after command
construction, immediately before worker launch, and after launch inside cleanup
protection. Worker waiting and normal diagnostic draining use the earliest
remaining deadline. Expired work cannot return a successful exported model.

`reports/ghidra_resource_usage.json` retains its configured resource fields:

| Field | Meaning |
| --- | --- |
| `wallClockMillisLimit` | Configured local worker allowance; not the time remaining at launch. |
| `parentWallClockMillisLimit` | Configured wrapper allowance, or JSON `null` for direct worker calls without a parent. |
| `remainingWallClockNanosAtLaunch` | Remaining allowance sampled at the prelaunch gate after preparation, including the parent constraint. |
| `maximumResidentBytesLimit` | Existing configured worker resident-memory ceiling. |
| `maximumResidentBytesObserved` | Existing worker/process-descendant sampling result; not parent JVM RSS. |

These values describe the configured invocation and the launch observation; they
do not rewrite immutable profile budgets. Resource and diagnostic files may be
retained on a failed invocation and do not establish successful analysis.

## Checkpoint coverage and compatibility

Bundle verification now delivers checkpoints around checksum-manifest reads,
each bounded checksum-manifest stream read, each checksum record and
path-component check, each 64 KiB file read, directory inventory advancement,
library sorting, property reads, and command preparation.
The callback may abort preparation; it cannot supply verification results.
Checksum, inventory, version and existing path checks remain in the verifier.
The application continues to use bundled Ghidra Java APIs without an external
`GHIDRA_HOME` or `analyzeHeadless` installation.

Exported model input is still admitted against `maximumProgramModelBytes`, whose
default ceiling remains 512 MiB. The reader allocates the admitted byte array,
fills it in reads of at most 64 KiB with checkpoints, rejects short or extra
bytes, and retains the before/after file identity, size and modification-time
comparison. It does not become a streaming model representation.

Canonical model handling adds checks around decoding, parsing, uniqueness
validation, ordering, encoding and byte comparison, and during entity/set
traversal and string escaping. Long-string escaping checks every 1,024 UTF-16
characters. Existing schema-v1/v2 canonical field order, formatting, status
semantics and exact-byte comparison are retained by the implementation.

Existing public constructors, methods, data classes and default-argument entry
points remain compatible. The former Function1 command-factory
constructor remains as a delegating overload; the bundled implementation uses a
private Function2 factory carrying the checkpoint. Existing `readCanonical`,
`read` and `toJson` methods delegate to internal checkpoint-aware overloads.
Compiled comparison against `9b6bcfcf` retained 91 of 92 raw public JVM
declaration/descriptor pairs, including the Function1 constructor/default bridge,
public constructors, interface bridges and model entry points. The sole replaced
pair is the compiler-generated local checkpoint accessor, whose captured state
changed from a start time/wrapper to `AnalysisDeadline`. Eight pairs were added,
including its replacement and the checkpoint overloads. This audit did not
exclude default-argument constructors or interface bridges merely because the
compiler marks them synthetic.

## Cooperative limits

Checkpoints do not preempt blocked native I/O, process creation, charset
conversion, library JSON parsing, sorting, constructor validation, or the
allocation/copying inside joins and indentation. Those operations have checks
on either side; some surrounding loops also check internally. They can still
overrun an allowance before the next check rejects the result.

Canonical parsing retains the complete admitted input byte array, decoded text,
JSON/model structures and canonical rendering buffers. This layer does not
establish whole-parent heap or RSS bounds, nor new model cardinality limits.

Cleanup has a separate scope. Existing termination snapshots descendants, uses
its configured graceful wait and subsequent per-handle forced-exit waits, and
closes/cancels process resources. After a worker timeout, diagnostic draining
has a separate five-second allowance so available output can be retained.
These paths are not governed by the expired analysis deadline and do not form a
strict aggregate cleanup-time guarantee. No stronger descendant-discovery or
cleanup qualification is claimed here.

## Reproducing the authored input-size probe

`MetadataScaleProbe` is a standalone test utility with no `@Test` annotation.
It accepts only `1MiB`, `64MiB`, or `1GiB`, creates a private temporary directory,
writes the existing authored ELF64 header followed by sparse zero padding, and
verifies the header/padding while computing the expected SHA-256 with fixed
64 KiB buffers. It injects an explicitly labelled no-op exporter returning an
empty model with that digest. It does not launch Ghidra, a compiler, an ACP agent,
or the authored input.

The utility checks model/report/input identity, zero section-header/symbol/name
visits, at most 128 KiB of charged metadata reads, the fixed 8 MiB metadata
reservation, and recorded profile/report limits. It prints one JSON result only
after cleanup. `elapsedMillis` covers the analyzer call; preparation and expected
hashing have separate fields. The input has already been fully read for that
expected hash, so this is explicitly a sparse, pre-read input experiment.

From the repository root, use the application's JDK and the following temporary
Gradle init script to extract the test runtime classpath. This compiles test
classes and stages the existing native library dependencies without modifying
`build.gradle.kts` or running tests:

```sh
probe_dir="$(mktemp -d "${TMPDIR:-/tmp}/metadata-scale.XXXXXX")"
cat > "$probe_dir/runtime-classpath.init.gradle" <<'GRADLE'
gradle.projectsEvaluated {
    def probeProject = gradle.rootProject
    probeProject.tasks.register('writeMetadataProbeRuntimeClasspath') {
        dependsOn 'testClasses', 'stageOracleNativeLibraries'
        doLast {
            def destination = System.getProperty('metadataScale.classpathOutput')
            if (destination == null) {
                throw new GradleException('metadataScale.classpathOutput is required')
            }
            def sourceSets = probeProject.extensions.getByName('sourceSets')
            probeProject.file(destination).write(
                sourceSets.getByName('test').runtimeClasspath.asPath, 'UTF-8')
        }
    }
}
GRADLE
./gradlew --no-daemon -I "$probe_dir/runtime-classpath.init.gradle" \
  -DmetadataScale.classpathOutput="$probe_dir/runtime-classpath.txt" \
  writeMetadataProbeRuntimeClasspath
probe_classpath="$(cat "$probe_dir/runtime-classpath.txt")"
cat > "$probe_dir/run-probe.py" <<'PYTHON'
import json
from pathlib import Path
import resource
import subprocess
import sys
import time

size, classpath, native_directory, output_prefix = sys.argv[1:]
started = time.monotonic()
with open(output_prefix + ".json", "wb") as stdout, open(output_prefix + ".stderr.log", "wb") as stderr:
    completed = subprocess.run(
        [
            "java", "-Xmx64m",
            "-Ddecompengine.oracle.nativeLibraryDirectory=" + native_directory,
            "-cp", classpath,
            "decompengine.analysis.MetadataScaleProbe", size,
        ],
        stdout=stdout,
        stderr=stderr,
        check=False,
    )
usage = resource.getrusage(resource.RUSAGE_CHILDREN)
measurement = {
    "maximumResidentKiB": usage.ru_maxrss,
    "processElapsedSeconds": time.monotonic() - started,
    "exitCode": completed.returncode,
    "method": "Linux RUSAGE_CHILDREN; one Java child in a fresh Python process",
}
Path(output_prefix + ".time.json").write_text(json.dumps(measurement) + "\n", encoding="utf-8")
raise SystemExit(completed.returncode)
PYTHON
for size in 1MiB 64MiB 1GiB; do
  python3 "$probe_dir/run-probe.py" "$size" "$probe_classpath" \
    "$PWD/build/native/oracle" "$probe_dir/$size" || exit "$?"
done
printf 'Evidence retained in %s\n' "$probe_dir"
```

Each loop iteration starts a fresh Python process whose only child is one JVM
with a 64 MiB maximum heap. After waiting for that child, Python reads
`resource.getrusage(resource.RUSAGE_CHILDREN).ru_maxrss`; on Linux this is the
child's maximum resident set in KiB. A fresh parent prevents another case's
child usage from contaminating the measurement. The Python interpreter's own RSS
is not included. The measurement does include the test JVM's runtime/native
overhead; it is not the RSS of a production parent carrying a recovered program
model. The utility JSON records the actual JVM maximum heap and labels the
absent export and complexity qualification. No `/usr/bin/time` installation is
required.

## Retained authored evidence

The [measurement record](evidence/metadata-scale-2026-09-08.json) retains input
identities, source hashes, effective limits, usage counters, runtime identity and
one local observation per size on Linux x86-64 with Temurin 21.0.12+8. All three
processes exited successfully and reported an actual 67,108,864-byte maximum heap.

| Authored logical input size | Analyzer elapsed | Whole probe process elapsed | Process maximum RSS |
| --- | ---: | ---: | ---: |
| 1 MiB | 429 ms | 1.006 s | 93,620 KiB |
| 64 MiB | 216 ms | 0.724 s | 101,872 KiB |
| 1 GiB | 1,452 ms | 2.441 s | 104,988 KiB |

Each case charged 65,600 metadata-read bytes and the fixed 8 MiB modeled metadata
reservation, with no section/symbol/name visits. Authentication still hashes the
whole admitted input before and after inspection. The smaller case taking longer
than the middle case illustrates why these individual startup/JIT/cache-sensitive
observations are not timing guarantees or a throughput benchmark. The 64 MiB heap
ceiling is also not a 64 MiB RSS ceiling.

The 24 focused JVM tests passed: three bundle checkpoint fixtures, four canonical
model compatibility/cancellation fixtures, six shared deadline fixtures, three
existing export lifecycle fixtures, two export budget binding fixtures, two JVM
wrapper binding fixtures and four metadata wrapper fixtures. They cover rejection
before preparation/launch, earlier parent and configured deadlines with owned
worker termination, wrapper forwarding, and successful canonical model input
larger than one 64 KiB chunk. They use ordinary authored data and local
sleep/printf/touch commands; they do not run real Ghidra, compiler/ACP qualification
or the broader security/full-tree/web suites. The repository neutrality gate
still reports the same 80 known findings and remains failing.

The remaining matrix must cover actual section/symbol/name complexity, recovered
model size and structure, and real bundled export/integration at supported
production sizes. These authored cases alone cannot complete
[#825](https://github.com/minsago-elite/decomp_thing/issues/825) or the complete
phase/resource and production requirements in
[#84](https://github.com/minsago-elite/decomp_thing/issues/84).
