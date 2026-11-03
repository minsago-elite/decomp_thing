# Compiled JUnit return-signature verification

[Issue 1730](https://github.com/minsago-elite/decomp_thing/issues/1730) fixes a
specific silent discovery omission: a Kotlin expression-body test may infer the
exception returned by its final `assertFailsWith`, rather than `Unit`. JUnit's
ordinary test annotation requires a method that does not return a value. Dynamic
test factories have a different return contract.
[JUnit Test API](https://docs.junit.org/6.1.3/api/org.junit.jupiter.api/org/junit/jupiter/api/Test.html)

The `StructuralBoundaryReplayV1Test` fixture helper now explicitly accepts and
returns `Unit`. Its original assertions are unchanged. This enables the previously
omitted altered-result/canonical-byte, stable-tie/exclusion, and large-source
parser denial controls to execute.

## Required guard

Every existing root-project Gradle `Test` task depends on
`verifyCompiledJunitSignatures`. The guard depends on compiled test classes and
`verifyJunitSignatureGuard`, which runs authored fixtures compiled by the selected
Java 21 compiler. Both checks execute each invocation; no prior qualification
receipt supplies success.

The full/local test route, explicit `--tests` selections, core/oracle/live
partitions, fresh GCC planning worker, three isolated V3 tasks and real-Angr task
retain their existing selectors, tags, dependencies and worker resource settings.
The guard inspects the complete root test source-set outputs even for a filtered
run. It runs once per Gradle task graph and does not add a second test execution
or alter partition ownership.

`scripts/check-junit-signatures.py` reads class-file bytes directly. It never
loads or initializes test or application classes. It checks declaration metadata
for these ordinary annotations:

- `org.junit.Test`
- `org.junit.jupiter.api.Test`
- `org.junit.jupiter.api.RepeatedTest`
- `org.junit.jupiter.api.TestTemplate`
- `org.junit.jupiter.params.ParameterizedTest`

Each ordinary method must have a JVM descriptor whose return type is `V`.
`org.junit.jupiter.api.TestFactory` alone is exempt from that requirement, so its
valid stream, collection, iterable, iterator and array results remain available.
A method with both factory and ordinary markers still has an ordinary obligation.
Composed annotation definitions present in the scanned class roots are followed
transitively; cycles terminate without recursive expansion. Annotation definitions
available only in external dependency jars are outside this scan's composed-
annotation scope. This is not an assertion that every possible JUnit discovery
condition is solved: visibility, lifecycle configuration, parameter resolution,
external composed annotations and factory result validity remain JUnit concerns.

## Bounded metadata and evidence

The reader supports non-preview class versions 45.0–45.3 and 46.0–65.0, matching
the Java 21 build target. It validates class framing, supported constant-pool tags
and references, modified UTF-8, method/field descriptors and declaration annotation
structure. Unsupported versions/tags, malformed inspected metadata, truncated
structures, missing/empty class roots, linked inputs and duplicate class identities
fail with a diagnostic. Other/custom attribute bodies, including executable code,
are retained as opaque framed bytes: this return-signature check is not a JVM
bytecode verifier.
[JVMS class-file format](https://docs.oracle.com/javase/specs/jvms/se21/html/jvms-4.html)

Bounds are 16 roots, 20,000 class files, 100,000 filesystem entries, directory
depth 64, 8 MiB per
class, 256 MiB total class bytes, 250,000 methods, 4,096 characters per inspected
metadata identity, annotation depth 32, 100,000 annotation nodes per class and
16 MiB report bytes. Each Gradle guard task has its own two-minute timeout.
Existing test/application memory and timeout policies are unchanged. No input
classes execute while determining their signatures.

`build/reports/junit-signatures/compiled-signatures.json` records input class
paths, exact byte counts and SHA-256 digests; recognized method names/descriptors;
direct/effective annotations; and explicit non-void violations or parse errors.
`controls.json` records the authored javac controls and their outcomes. Existing
JVM report artifacts retain this directory, including on failed runs. A guard
failure prevents the dependent test task from claiming an executed suite.

The historical partition evidence in
[issue 1545](https://github.com/minsago-elite/decomp_thing/issues/1545) remains an
account of the retained historical execution union. This guard neither rewrites
that evidence nor treats it as proof that newly declared methods execute. Current
JUnit XML must still show each expected denial control by exact name, and normal
Actions, review and production qualification requirements remain in force.
