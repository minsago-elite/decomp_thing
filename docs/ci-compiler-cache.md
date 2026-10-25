# Actions compiler cache

The ordinary Gradle jobs use the open-source basic provider for dependencies and
wrapper validation. A separate workspace directory, `build/ci-compiler-cache`,
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

The existing basic provider's read-only policy is preserved. Manually selected
LLVM observation/qualification jobs are unchanged and do not use this wrapper.

## Evidence

Ordinary job logs retain the exact source checkout, cache key/restored key, cache
size at publication, compiler task dispositions and original qualification task
results. Cold, reuse and changed-input observations must come from meaningful
ordinary source work. Cache hits alone do not qualify tests, native behavior or a
release, and no fixed CI or CPU improvement is claimed.

Provider contracts:

- [Pinned basic Gradle provider](https://github.com/gradle/actions/blob/3f5f9adaf7d9fecd50b5935e54106014257a94e6/docs/setup-gradle.md#basic-caching)
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
