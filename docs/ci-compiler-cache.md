# Actions compiler cache

The ordinary Gradle jobs use the pinned open-source `minsago-elite/gradle-cache-action`
for Gradle dependency caching and a separately pinned `gradle/actions/wrapper-validation`
step for wrapper authentication. A separate workspace directory, `build/ci-compiler-cache`,
holds Gradle task outputs. `DECOMP_CI_COMPILER_CACHE=1` selects that directory only
in these Actions jobs; other invocations keep their existing local cache path.

Only JavaCompile and KotlinCompile outputs are eligible under the unchanged
`build.gradle.kts` task policy. Test, Exec, JavaExec, reports, archives and native
outputs remain excluded. No task or qualification step is skipped on a cache hit.
Gradle checks its own complete task-input fingerprint before using any output.

## Restore and publication

The compiler key includes a format version, runner OS and architecture, the
SHA-256 of the selected JDK's `release` file, Gradle build/configuration inputs,
and the checked-out Actions revision. A prefix restore can obtain outputs from a
previous source revision in the same toolchain/configuration bucket. The unique
revision key lets a later default-branch build publish newer compiler outputs
without trying to overwrite an immutable entry.

Every ordinary consumer uses the restore-only action. Only the successful CI
core partition on a push to `master` publishes the resulting compiler directory,
after its original qualification, report retention and cleanup steps. PRs never
publish compiler entries. One publisher avoids competing partial entries and
per-partition duplication. It refuses publication above one GiB; retained entries
also remain subject to GitHub's repository cache quota and eviction. Dependency
caches are not copied into this directory or duplicated for each source revision.

Dependency cache writes are restricted to the repository default branch, with
existing read-only callers remaining read-only. All consumers use
`cache-family: decomp-gradle-dependencies-v1`, allowing a read-only workflow or PR
job to fall back to a default-branch manifest from another workflow. Default-branch
CI jobs such as `web-packaged` and the Kotlin partitions can publish these manifests.
The first cross-workflow restore requires a manifest and its content units to be
available in the repository cache. Matrix jobs pass `${{ toJSON(matrix) }}`; the
composite defaults to `{}` for non-matrix jobs. Generated and metadata cache keys
include the publishing job's scope. On family fallback, the action restores the
units referenced by the publishing job's manifest.

Manually selected LLVM observation jobs retain their explicit private Gradle homes
and read-only policy. Offline Ghidra verification still prepares inputs online
before copying dependency caches into its separate private replay home. No new
cache ownership is introduced for deliberately cold jobs or private replay homes.
The dependency action excludes `build/ci-compiler-cache`; its shared family never
changes the single default-branch compiler publisher or the one-GiB limit.

## Archival image Gradle resolution

The `archival-ghidra` job builds its image with BuildKit, whose `/root/.gradle`
cache mount starts empty on a hosted runner, so the image's single `installDist`
invocation resolves every plugin and dependency from its repository. The job does
not restore the runner dependency cache into the image build. GitHub can serve a
pull request a cache entry saved from that pull request's own merge ref, and the
copied resolution metadata has no integrity check independent of the cache. A
restored entry could therefore change which dependencies or plugins resolve. Reusing
it safely would need repository-wide Gradle dependency verification metadata, which
the build does not have.

`scripts/archival-gradle-install.sh` is the only place that sets the resolver retry
properties for that invocation. On a transient repository failure, including HTTP
429, Gradle sends up to 8 requests per resource. It sleeps the initial backoff, then
double that, and so on. Each build draws the initial backoff uniformly from 3000 to
5000 ms, so concurrent builds do not retry in lockstep. The sleeps total 127 times
the initial backoff, so one throttled resource waits 381 to 635 seconds (6.4 to 10.6
minutes) before the build fails. The earlier window was 30 seconds: 5 requests from
a fixed 2000 ms. The 45-minute timeout bounds the whole invocation, and the image
build capture keeps its 2700-second deadline inside the job's 60-minute timeout.
`scripts/test-archival-gradle-resolution.py` checks the window, the jitter and the
original resolver failure cases.

## Evidence

Ordinary job logs retain the exact source checkout, cache key/restored key, cache
size at publication, compiler task dispositions and original qualification task
results. Cold, reuse and changed-input observations must come from meaningful
ordinary source work. Cache hits alone do not qualify tests, native behavior or a
release, and no fixed CI or CPU improvement is claimed.

Provider contracts:

- [Gradle dependency cache contract](https://github.com/minsago-elite/gradle-cache-action/blob/6dea8fd64949676aa3da5d1e107d8efaaca7e05a/README.md)
- [Pinned wrapper validation](https://github.com/gradle/actions/blob/8da46b539cd8fe6ab27ca75128919a18d757604c/wrapper-validation/action.yml)
- [Pinned restore-only action](https://github.com/actions/cache/blob/55cc8345863c7cc4c66a329aec7e433d2d1c52a9/restore/action.yml)
- [Pinned save-only action](https://github.com/actions/cache/blob/55cc8345863c7cc4c66a329aec7e433d2d1c52a9/save/action.yml)
- [Gradle build cache input validation](https://docs.gradle.org/current/userguide/build_cache.html)

## Prerequisite acquisition boundary

The Kotlin partitions keep their existing sandbox package list and host checks.
Their APT update and installation use two download retries and 30-second HTTP
and HTTPS connection/data timeouts. The enclosing prerequisite step has a
ten-minute ceiling. Update errors fail the step even when APT could retain old
indexes; qualification cannot proceed with a failed prerequisite.

This bounds the prerequisite stall observed in an ordinary live partition. Its
last acquisition output came from APT update, the setup step did not finish for
six hours, and the JVM tests never started. The exact blocked subprocess after
that last output is not established by the log. This change
does not diagnose native cleanup failures or demonstrate compiler cache reuse.
The test selections, commands, native fixtures, runtime limits and aggregate
requirement remain unchanged. Completed normal Actions must qualify the new
source; the configured bounds alone are not runtime evidence.

- [APT download retry configuration](https://manpages.debian.org/bookworm/apt/apt.conf.5.en.html)
- [HTTP connection and data timeout](https://manpages.debian.org/bookworm/apt/apt-transport-http.1.en.html)
- [HTTPS transport options](https://manpages.debian.org/bookworm/apt/apt-transport-https.1.en.html)
- [APT update error handling](https://manpages.debian.org/bookworm/apt/apt-get.8.en.html)
- [Actions step timeout](https://docs.github.com/en/actions/reference/workflows-and-actions/workflow-syntax#jobsjob_idstepstimeout-minutes)
