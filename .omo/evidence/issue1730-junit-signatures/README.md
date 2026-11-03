# Issue 1730 verification

Tested source checkpoint: `de238fd3bf897eef9bac857b85a5dc2a54bc67d1`, based on
master `87bd707094730fb2a238c56e7000977974a0670e`. The subsequent evidence commit
does not change implementation. PR 1728 was left unchanged.

## Executed evidence

- All **17** source-declared `StructuralBoundaryReplayV1Test` methods executed:
  zero failures, errors or skips. Exact source-to-XML method-name equality was
  independently checked by the parent reviewer as well as the implementer.
- All **16** authored javac controls passed, both directly and as the actual
  `verifyJunitSignatureGuard` dependency. The parent separately reran these controls.
- The required compiled guard accepted **1,696 classes / 4,387 annotated methods**
  from this master-based checkout, with no non-void ordinary methods. This is a
  signature census, not a claim that all 4,387 methods executed as tests.
- A real Gradle configuration audit confirmed all **six** existing root `Test`
  tasks directly depend on `verifyCompiledJunitSignatures`. Original class roots,
  selectors, heaps and fork settings are retained in `task-routes.json`.
- All **37** existing CI partition/routing controls passed. All six edited
  workflow files parsed successfully; changes there only add the evidence path.

The previously omitted methods appear by their exact names in the retained XML
and now have descriptor `()V` in the compiled report:

1. `selected verification rejects altered results metadata and canonical bytes`
2. `selected observation preserves name-independent stable ties and exclusion accounting`
3. `selected full export parser admits large source without widening historical replay`

`discovery-summary.json` binds the observed baseline and corrected class bytes,
full report hashes, the three corrected descriptors, and the retained XML. The
baseline used the already-compiled producer worktree (1,721 classes / 4,421
annotations) and reproduced exactly the three original non-void methods. That
source population differs from this master-based checkout; neither population is
silently treated as the historical issue 1545 execution union.

## Invocation and limits

The final focused Gradle run completed successfully in **2m14s** with Java 21,
repository-local Gradle 9.6.1/cache, `--offline --no-daemon`, and:

```text
junitSignatureTaskGraphAudit test
--tests decompengine.oracle.structural.StructuralBoundaryReplayV1Test
-x stageFrontend
-x gccCompilerEnginePlanningIsolated
-x snapshotCapsuleAuditDataTest
```

`junitSignatureTaskGraphAudit` is a local diagnostic init-script task. The actual
required production-build hooks are `verifyJunitSignatureGuard` and
`verifyCompiledJunitSignatures`, both visible in `focused.log` before `test`.
An initial local audit harness stalled when resolving task dependencies inside
its task action and was stopped before tests; the final harness inspects direct
dependency providers. The implementation was unchanged by that harness fix.

JVM homes, Java/JNA temporary directories, Python control workspaces and Gradle
cache were inside the repository. JVM performance-data output was disabled.
No unrelated process was stopped and no existing application/test resource limit
was widened. The focused run does not claim the excluded suites or a full CI run.

Independent source review found no remaining scoped defect. Normal current-head
Actions and automatic review gates remain required before merging. This check
does not replace contained production qualification or solve every possible
JUnit discovery condition.
