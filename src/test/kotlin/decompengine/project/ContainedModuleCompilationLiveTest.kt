package decompengine.project

import decompengine.acp.LinuxFilesystemSyscalls
import decompengine.acp.LinuxProcessDescriptor
import decompengine.acp.LinuxBoundedSessionCommand
import decompengine.acp.LinuxBoundedSessionProcess
import decompengine.oracle.core.OracleJson
import decompengine.oracle.fulltree.OracleNativeLibraries
import decompengine.oracle.fulltree.parseFullTreeFunctionObservationProcessStartTimeTicks
import java.io.ByteArrayOutputStream
import java.io.InputStream
import java.nio.file.Files
import java.nio.file.LinkOption
import java.nio.file.Path
import java.time.Duration
import java.util.concurrent.TimeUnit
import java.util.concurrent.atomic.AtomicBoolean
import java.util.concurrent.atomic.AtomicReference
import kotlin.test.Test
import kotlin.test.assertContentEquals
import kotlin.test.assertEquals
import kotlin.test.assertFailsWith
import kotlin.test.assertFalse
import kotlin.test.assertNotEquals
import kotlin.test.assertNotNull
import kotlin.test.assertTrue
import kotlinx.serialization.json.Json
import kotlinx.serialization.json.JsonArray
import kotlinx.serialization.json.JsonObject
import kotlinx.serialization.json.JsonPrimitive
import kotlinx.serialization.json.boolean
import kotlinx.serialization.json.int
import kotlinx.serialization.json.jsonObject
import kotlinx.serialization.json.jsonPrimitive
import org.junit.jupiter.api.Assumptions.assumeTrue
import org.junit.jupiter.api.Tag
import org.junit.jupiter.api.parallel.Execution
import org.junit.jupiter.api.parallel.ExecutionMode
import org.junit.jupiter.api.parallel.ResourceLock

/** Real configured compiler qualification with an authored reconstructor; this is not ACP qualification. */
@Tag("ci-live")
@Execution(ExecutionMode.SAME_THREAD)
@ResourceLock("contained-module-compilation-runtime")
class ContainedModuleCompilationLiveTest {
    @Test
    fun `real compilation issues live authority only for the exact current source and header snapshot`(): Unit = moduleCases("exact-snapshot", "real compilation issues live authority only for the exact current source and header snapshot") { fixture ->
        val sourcePath = fixture.path("module-implementation")
        val headerPath = fixture.path("module-interface")
        fixture.write(fixture.path("shared-interface"), "/* authored live fixture */\n")
        fixture.write(headerPath, "enum { OBSERVED_CONSTANT = 7 };\nint parse_input(void);\n")
        fixture.write(fixture.path("module-private-interface"), "/* private live fixture */\n")
        fixture.write(sourcePath, ContainedModuleCompilationHostedSupport.source(fixture.profile, "parse",
            longCompilerBody().replace("return (int)value;", "return (int)(value + headers_sum + OBSERVED_CONSTANT);")))

        val observer = ContainedModuleCompilationHostedObservation.start(fixture.project, fixture.runtime)
        var observationFailure: Throwable? = null
        val first = try {
            fixture.compile(sourcePath, "first").also { evidence ->
                val observed = observer.finish(evidence)
                observed.rawFiles.forEach { (name, bytes) -> fixture.cell.retain("inheritance/$name", bytes) }
                fixture.cell.retain("inheritance/joined.json", OracleJson.canonicalBytes(observed.joined))
            }
        } catch (failure: Throwable) {
            observationFailure = failure
            observer.retainedFiles().forEach { (name, bytes) ->
                try { fixture.cell.retain("inheritance-failure/$name", bytes) }
                catch (retention: Throwable) { failure.addSuppressed(retention) }
            }
            throw failure
        } finally {
            try { observer.close() }
            catch (cleanup: Throwable) {
                val original = observationFailure
                if (original == null) throw cleanup else if (original !== cleanup) original.addSuppressed(cleanup)
            }
        }
        assertLiveAcceptance(first, fixture.profile)
        val firstProof = ContainedModuleCompilationProof.verify(first)
        assertEquals("compiled-object", firstProof.result.outcome)
        assertNotNull(firstProof.result.objectSha256)
        assertTrue(assertNotNull(firstProof.result.objectBytes) > 0)
        assertEquals(sha256(Files.readAllBytes(fixture.project.resolve(sourcePath))), first.sourceSha256)
        val replay = ModuleCompilationEvidence.decode(Json.parseToJsonElement(first.toJson()).jsonObject,
            7, fixture.profile, sourcePath, first.sourceSha256, accepted = true)
        assertTrue(replay.passed)
        assertFalse(replay.authorizesAcceptance(first.sourceSha256, fixture.profile.sha256, POLICY),
            "recorded proof must not recreate the live coordinator permit")

        // Kotlin exposes a public synthetic constructor for companion access. Calling that
        // ordinary public API with genuine proof bytes must not recreate coordinator issuance.
        val constructor = assertNotNull(VerifiedContainedModuleCompilation::class.java.constructors.singleOrNull {
            it.parameterTypes.map { parameter -> parameter.name } == listOf("java.lang.String",
                ContainedModuleCompilationSnapshot::class.java.name, "kotlin.jvm.internal.DefaultConstructorMarker")
        }, "the public synthetic constructor is the bypass this regression exercises")
        assertTrue(constructor.isSynthetic)
        val proof = assertNotNull(first.containedProof)
        val forgedToken = constructor.newInstance(sha256(OracleJson.canonicalBytes(proof)),
            ContainedModuleCompilationSnapshot.capture(fixture.project, sourcePath, fixture.profile), null)
            as VerifiedContainedModuleCompilation
        val cloned = ModuleCompilationEvidence(first.sourceSha256, first.command, first.outcome, first.returnCode,
            first.diagnosticsSha256, first.diagnosticsBytes, proof, forgedToken)
        assertTrue(cloned.passed, "the clone retains the genuinely successful compiler facts")
        assertFalse(cloned.authorizesAcceptance(first.sourceSha256, fixture.profile.sha256, POLICY),
            "a public constructor call must not manufacture the coordinator's live admission")
        assertLiveAcceptance(first, fixture.profile)

        fixture.write(headerPath, "enum { OBSERVED_CONSTANT = 8 };\nint parse_input(void);\n")
        assertFalse(first.authorizesAcceptance(first.sourceSha256, fixture.profile.sha256, POLICY),
            "the old permit must reject a changed header even when source bytes are identical")
        val changedHeader = fixture.compile(sourcePath, "changed-header")
        assertLiveAcceptance(changedHeader, fixture.profile)
        val secondProof = ContainedModuleCompilationProof.verify(changedHeader)
        assertEquals(first.sourceSha256, changedHeader.sourceSha256)
        assertNotEquals(firstProof.request.snapshotSha256, secondProof.request.snapshotSha256)
        assertNotEquals(firstProof.result.objectSha256, secondProof.result.objectSha256)

        fixture.write(sourcePath, ContainedModuleCompilationHostedSupport.source(fixture.profile, "parse",
            "return (int)(OBSERVED_CONSTANT + headers_sum + 1u);"))
        assertFalse(changedHeader.authorizesAcceptance(changedHeader.sourceSha256, fixture.profile.sha256, POLICY),
            "the old permit must reject source mutation even when the caller supplies the old hash")
        val changedSource = fixture.compile(sourcePath, "changed-source")
        assertLiveAcceptance(changedSource, fixture.profile)
        val thirdProof = ContainedModuleCompilationProof.verify(changedSource)
        assertNotEquals(changedHeader.sourceSha256, changedSource.sourceSha256)
        assertNotEquals(secondProof.request.snapshotSha256, thirdProof.request.snapshotSha256)
        fixture.requireClean()
    }

    @Test
    fun `real compiler rejection preserves the earlier accepted SourceTree revision and checkpoint`(): Unit = moduleCases("source-tree-rejection", "real compiler rejection preserves the earlier accepted SourceTree revision and checkpoint") { fixture ->
        val original = model()
        val manifest = fixture.generate(original, authoredReconstructor(fixture.profile), "baseline")
        val accepted = fixture.acceptedRevision(manifest)
        fixture.retainRevision("accepted-baseline", accepted)
        val candidateModel = original.copy(functions = original.functions.map { it.copy(strings = setOf("new recovered evidence")) })
        val rejection = assertFailsWith<ModuleReconstructionRevisionRejectedException> {
            fixture.generate(candidateModel, authoredReconstructor(fixture.profile, "return missing_live_fixture_value;"), "rejected-candidate")
        }
        assertTrue(rejection.issues.any { it.code == "module-compilation-failed" })
        accepted.forEach { (path, bytes) -> assertContentEquals(bytes, Files.readAllBytes(fixture.project.resolve(path)), path) }
        val attempt = Json.parseToJsonElement(Files.readString(fixture.project.resolve("reports/modules/parse.attempt.json"))).jsonObject
        assertEquals("rejected", attempt.getValue("status").jsonPrimitive.content)
        val candidate = attempt.getValue("candidate").jsonObject
        assertFalse(candidate.getValue("accepted").jsonPrimitive.boolean)
        val compilation = candidate.getValue("compilation").jsonObject
        val rejectedEvidence = ModuleCompilationEvidence.decode(compilation, candidate.getValue("schemaVersion").jsonPrimitive.int,
            fixture.profile, fixture.path("module-implementation"), candidate.getValue("sourceSha256").jsonPrimitive.content, accepted = false)
        assertFalse(rejectedEvidence.passed)
        assertFalse(rejectedEvidence.authorizesAcceptance(rejectedEvidence.sourceSha256, fixture.profile.sha256, POLICY))
        val proof = ContainedModuleCompilationProof.verify(rejectedEvidence)
        assertEquals("compiler-failed", proof.result.outcome)
        assertTrue(assertNotNull(proof.result.exitCode) != 0)
        assertTrue(proof.result.stderrBytes > 0, "the actual compiler must retain the rejected candidate's diagnostic commitment")
        fixture.verifyCapturedInputs("rejected-candidate", rejectedEvidence)
        fixture.retainAttempt("rejected-attempt.json")
        fixture.retainRevision("rejected-restored", accepted)
        fixture.report("rejected-evidence.json", Json.parseToJsonElement(rejectedEvidence.toJson()).jsonObject)
        fixture.requireClean(rejectedEvidence)
    }

    @Test
    fun `interrupting an observed real compiler restores prior acceptance and removes its processes scope and scratch`(): Unit = moduleCases("source-tree-cancellation", "interrupting an observed real compiler restores prior acceptance and removes its processes scope and scratch") { fixture ->
        val original = model()
        val manifest = fixture.generate(original, authoredReconstructor(fixture.profile), "baseline")
        val accepted = fixture.acceptedRevision(manifest)
        fixture.retainRevision("accepted-baseline", accepted)
        val candidateModel = original.copy(functions = original.functions.map { it.copy(strings = setOf("cancelled recovered revision")) })
        val failure = AtomicReference<Throwable?>()
        val interrupted = AtomicBoolean()
        val thread = Thread({
            try {
                fixture.generate(candidateModel, authoredReconstructor(fixture.profile, longCompilerBody()), "cancelled-candidate")
            } catch (caught: Throwable) {
                failure.set(caught)
            } finally {
                interrupted.set(Thread.currentThread().isInterrupted)
            }
        }, "contained-module-live-cancellation")
        val handles = linkedMapOf<Long, LinuxProcessDescriptor>()
        var observed: ObservedCompiler? = null
        var interruptionRetained = false
        var cancellationPrimary: Throwable? = null
        try {
            thread.start()
            observed = awaitRealCompiler(fixture, thread, failure, handles)
            fixture.verifyCapturedRequest("cancelled-candidate", observed.request)
            fixture.cell.retain("cancelled-request.json", observed.request.canonicalBytes)
            assertTrue(observed.compilerPids.any { pid -> LinuxFilesystemSyscalls.processExists(handles.getValue(pid)) },
                "cancellation must begin while a real configured compiler is alive")
            assertNotEquals(sha256(accepted.getValue(fixture.path("module-implementation"))),
                sha256(Files.readAllBytes(fixture.project.resolve(fixture.path("module-implementation")))))
            thread.interrupt()
            thread.join(90_000)
            assertFalse(thread.isAlive, "contained compilation cancellation failed to finish its owned cleanup")
            assertTrue(failure.get() is ModuleReconstructionInterruptedException, failure.get()?.stackTraceToString())
            assertTrue(interrupted.get(), "SourceTree must preserve cancellation after rollback")
            accepted.forEach { (path, bytes) -> assertContentEquals(bytes, Files.readAllBytes(fixture.project.resolve(path)), path) }
            handles.forEach { (pid, handle) -> assertFalse(LinuxFilesystemSyscalls.processExists(handle), "owned process $pid remains alive") }
            fixture.requireScopeAbsent(observed.request.nonce)
            fixture.requireClean()
            val attempt = Json.parseToJsonElement(Files.readString(fixture.project.resolve("reports/modules/parse.attempt.json"))).jsonObject
            assertEquals("interrupted", attempt.getValue("status").jsonPrimitive.content)
            assertFalse(Thread.currentThread().isInterrupted, "only the generation worker was interrupted")
            fixture.cell.retain("cancellation-exception.txt", assertNotNull(failure.get()).stackTraceToString().toByteArray())
            interruptionRetained = true
            fixture.retainRevision("interrupted-restored", accepted)
            fixture.retainAttempt("interrupted-attempt.json")
            val resumed = fixture.generate(original,
                ModuleReconstructor { error("the preserved accepted revision must resume without reconstruction dispatch") }, "retry")
            val revalidated = fixture.acceptedRevision(resumed)
            fixture.retainRevision("retry-accepted", revalidated)
            val sourcePath = fixture.path("module-implementation")
            assertContentEquals(accepted.getValue(sourcePath), revalidated.getValue(sourcePath))
            fun compilationNonce(revision: Map<String, ByteArray>): String {
                val checkpoint = Json.parseToJsonElement(revision.getValue(fixture.path("module-evidence")).decodeToString()).jsonObject
                return ContainedModuleCompilationProof.verify(checkpoint.getValue("compilation").jsonObject
                    .getValue("containedProof").jsonObject).request.nonce
            }
            val retryNonce = compilationNonce(revalidated)
            assertNotEquals(compilationNonce(accepted), retryNonce, "resuming acceptance requires a fresh real contained compilation")
            assertFalse(Files.exists(fixture.project.resolve("reports/modules/parse.attempt.json")),
                "successful retry must clear the interrupted attempt")
            fixture.report("cancellation-observations.json", JsonObject(mapOf(
                "qualification" to JsonPrimitive("real-contained-compiler-authored-reconstructor-not-acp"),
                "nonce" to JsonPrimitive(observed.request.nonce),
                "observedCompilerPids" to JsonPrimitive(observed.compilerPids.sorted().joinToString(",")),
                "allObservedProcessesAbsent" to JsonPrimitive(true),
                "scopeAndCgroupAbsent" to JsonPrimitive(true), "scratchEmpty" to JsonPrimitive(true),
                "priorAcceptedBytesPreserved" to JsonPrimitive(true),
                "retryWithoutReconstructionDispatch" to JsonPrimitive(true), "retryCompilationNonce" to JsonPrimitive(retryNonce),
            )))
        } catch (problem: Throwable) {
            cancellationPrimary = problem
            throw problem
        } finally {
            var teardownFailure: Throwable? = null
            fun cleanup(action: () -> Unit) {
                try { action() } catch (problem: Throwable) {
                    val original = cancellationPrimary
                    val previous = teardownFailure
                    if (original != null) { if (original !== problem) original.addSuppressed(problem) }
                    else if (previous == null) teardownFailure = problem else if (previous !== problem) previous.addSuppressed(problem)
                }
            }
            cleanup {
                if (thread.isAlive) { thread.interrupt(); thread.join(90_000) }
                assertFalse(thread.isAlive, "cancelled generation remains alive after final cleanup")
            }
            handles.values.forEach { handle -> cleanup { handle.close() } }
            cleanup { failure.get()?.let {
                val bytes = it.stackTraceToString().toByteArray()
                Files.write(fixture.root.resolve("cancellation-exception.txt"), bytes)
                if (!interruptionRetained) fixture.cell.retain("cancellation-exception.txt", bytes)
            } }
            cleanup { observed?.let { Files.write(fixture.root.resolve("cancelled-request.json"), it.request.canonicalBytes) } }
            if (cancellationPrimary == null) teardownFailure?.let { throw it }
        }
    }

    @Test
    fun `configured module output refusal preserves acceptance and permits a clean retry`(): Unit = moduleCases(
        "output-refusal", "configured module output refusal preserves acceptance and permits a clean retry",
        transform = { base -> ReconstructionProfile(base.schemaVersion, base.id, base.layout,
            base.budgets.copy(buildMaximumOutputBytes = 1024), base.adapterConfiguration) }) { fixture ->
        val original = model()
        val baseline = fixture.generate(original, authoredReconstructor(fixture.profile), "baseline")
        val accepted = fixture.acceptedRevision(baseline)
        fixture.retainRevision("accepted-baseline", accepted)
        val candidate = original.copy(functions = original.functions.map { it.copy(strings = setOf("output refusal fixture")) })
        // Ordinary unconditional C syntax reaches the compiler; unsupported preprocessing would not.
        val body = buildString {
            append("unsigned diagnosed = headers_sum;\n")
            repeat(32) { append("diagnosed += missing_output_symbol_$it;\n") }
            append("return (int)diagnosed;\n")
        }
        assertFailsWith<ModuleReconstructionRevisionRejectedException> {
            fixture.generate(candidate, authoredReconstructor(fixture.profile, body), "output-rejected")
        }
        val attempt = Json.parseToJsonElement(fixture.retainAttempt("output-refusal-attempt.json").decodeToString()).jsonObject
        assertEquals("rejected", attempt.getValue("status").jsonPrimitive.content)
        val recorded = attempt.getValue("candidate").jsonObject
        val evidence = ModuleCompilationEvidence.decode(recorded.getValue("compilation").jsonObject,
            recorded.getValue("schemaVersion").jsonPrimitive.int, fixture.profile, fixture.path("module-implementation"),
            recorded.getValue("sourceSha256").jsonPrimitive.content, accepted = false)
        val proof = ContainedModuleCompilationProof.verify(evidence)
        fixture.verifyCapturedInputs("output-rejected", evidence)
        assertEquals("output-limit-exceeded", proof.result.outcome)
        assertEquals(null, proof.result.objectSha256)
        assertFalse(evidence.authorizesAcceptance(evidence.sourceSha256, fixture.profile.sha256, POLICY))
        fixture.report("output-refusal-evidence.json", Json.parseToJsonElement(evidence.toJson()).jsonObject)
        fixture.retainRevision("output-restored", accepted)
        fixture.requireClean(evidence)
        val retry = fixture.generate(candidate, authoredReconstructor(fixture.profile), "retry")
        val fresh = fixture.acceptedRevision(retry)
        fixture.retainRevision("retry-accepted", fresh)
        assertNotEquals(revisionNonce(fixture, accepted), revisionNonce(fixture, fresh))
        assertFalse(Files.exists(fixture.project.resolve("reports/modules/parse.attempt.json")))
    }

    @Test
    fun `unsupported inherited descriptor hard limit refuses before module START and preserves acceptance`(): Unit = moduleCases(
        "inherited-hard-refusal", "unsupported inherited descriptor hard limit refuses before module START and preserves acceptance") { fixture ->
        val original = model()
        val baseline = fixture.generate(original, authoredReconstructor(fixture.profile), "baseline")
        val accepted = fixture.acceptedRevision(baseline)
        fixture.retainRevision("accepted-baseline", accepted)
        val baselineInputs = fixture.currentInputs()
        val baselineManifest = JsonObject(mapOf("entries" to JsonArray(accepted.toSortedMap().map { (path, bytes) ->
            JsonObject(mapOf("path" to JsonPrimitive(path), "bytes" to JsonPrimitive(bytes.size), "sha256" to JsonPrimitive(sha256(bytes))))
        })))
        val baselinePath = fixture.root.resolve("child-baseline.json")
        Files.write(baselinePath, OracleJson.canonicalBytes(baselineManifest), java.nio.file.StandardOpenOption.CREATE_NEW)
        fixture.cell.retain("child/baseline-manifest.json", Files.readAllBytes(baselinePath))
        val manifestPath = Path.of(assertNotNull(System.getProperty(ContainedModuleCompilationHostedSupport.CHILD_CLASSPATH_PROPERTY)))
        val manifestBytes = ContainedModuleCompilationHostedSupport.readRegular(manifestPath, 1024 * 1024)
        val manifestSha = sha256(manifestBytes)
        val classpath = ContainedModuleCompilationHostedSupport.validateChildClasspathManifest(manifestPath, manifestSha)
        fixture.cell.retain("child/classpath-manifest.json", manifestBytes)
        val native = Path.of(assertNotNull(System.getProperty("decompengine.oracle.nativeLibraryDirectory")))
        OracleNativeLibraries.requireCurrent(native, classpath.map { ContainedModuleCompilationHostedSupport.fileDigest(it, 128L * 1024 * 1024).second })
        val temporary = Files.createDirectory(fixture.root.resolve("child-tmp"))
        val home = Files.createDirectory(fixture.root.resolve("child-home"))
        val reports = fixture.root.resolve("child-reports")
        val arguments = listOf(fixture.runtime.isolation.resourceLimiterExecutable.toString(), "--nofile=7677:7677", "--",
            fixture.runtime.isolation.javaExecutable.toString(), "-Xms16m", "-Xmx512m", "-XX:+UseSerialGC",
            "-XX:-UsePerfData", "-XX:+DisableAttachMechanism", "-Djava.io.tmpdir=$temporary", "-Djna.tmpdir=$temporary",
            "-Duser.home=$home", "-Ddecompengine.oracle.nativeLibraryDirectory=$native") + OracleNativeLibraries.jvmArguments(native) +
            listOf("-classpath", classpath.joinToString(java.io.File.pathSeparator),
                ContainedModuleCompilationLowHardChild::class.java.name, fixture.project.toString(), fixture.profile.id,
                reports.toString(), baselinePath.toString(), manifestPath.toString(), manifestSha)
        val environment = mapOf("LANG" to "C.UTF-8", "LC_ALL" to "C.UTF-8", "TZ" to "UTC", "HOME" to home.toString(),
            "TMPDIR" to temporary.toString(), "GENERATED_C_MODULE_COMPILE_REQUIRE" to "true",
            ContainedModuleCompilationRuntimeConfiguration.DIRECTORY_ENVIRONMENT to assertNotNull(
                System.getenv(ContainedModuleCompilationRuntimeConfiguration.DIRECTORY_ENVIRONMENT)))
        fixture.requireModuleScopesAbsent()
        fixture.cell.stage("low-hard-child")
        var childFailure: Throwable? = null
        var childIdentity: Pair<Long, Long>? = null
        try {
            childIdentity = fixture.runLowHardChild(arguments, environment)
        } catch (failure: Throwable) {
            childFailure = failure
            throw failure
        } finally {
            try { fixture.retainDirectory("child/reports", reports) }
            catch (retention: Throwable) {
                val original = childFailure
                if (original == null) throw retention else if (original !== retention) original.addSuppressed(retention)
            }
        }
        val result = Json.parseToJsonElement(ContainedModuleCompilationHostedSupport.readRegular(
            reports.resolve("child-result.json"), 1024 * 1024).decodeToString()).jsonObject
        assertEquals(JsonPrimitive("hosted-low-hard-source-tree-refusal-v1"), result["provider"])
        assertEquals(JsonPrimitive(fixture.profile.id), result["profileId"])
        assertEquals(JsonPrimitive(assertNotNull(childIdentity).first), result["hostPid"])
        assertEquals(JsonPrimitive(assertNotNull(childIdentity).second), result["startTimeTicks"])
        assertEquals(JsonPrimitive(fixture.profile.sha256), result["profileSha256"])
        assertEquals(JsonPrimitive(fixture.runtime.configurationSha256), result["runtimeConfigurationSha256"])
        assertEquals(JsonPrimitive(manifestSha), result["classpathManifestSha256"])
        assertEquals(JsonPrimitive(sha256(Files.readAllBytes(baselinePath))), result["baselineManifestSha256"])
        for (field in listOf("expectedAdmissionRefusal", "launcherCleanupAbsenceProved", "baselineBytesPreserved",
            "scratchEmpty", "privateRequestDirectoriesAbsent")) assertEquals(JsonPrimitive(true), result[field], field)
        for (field in listOf("reconstructionDispatched", "newAcceptedProof")) assertEquals(JsonPrimitive(false), result[field], field)
        assertEquals(JsonPrimitive(7677), result["softLimit"])
        assertEquals(JsonPrimitive(7677), result["hardLimit"])
        assertEquals(baselineInputs.map { it.json() }, fixture.currentInputs().map { it.json() })
        fixture.retainRevision("low-hard-restored", accepted)
        fixture.retainAttempt("low-hard-attempt.json")
        fixture.requireClean()
        fixture.requireModuleScopesAbsent()
        val retry = fixture.generate(original,
            ModuleReconstructor { error("preserved low-hard revision must retry without reconstruction dispatch") }, "retry")
        val fresh = fixture.acceptedRevision(retry)
        assertContentEquals(accepted.getValue(fixture.path("module-implementation")), fresh.getValue(fixture.path("module-implementation")))
        assertNotEquals(revisionNonce(fixture, accepted), revisionNonce(fixture, fresh))
        fixture.retainRevision("retry-accepted", fresh)
        assertFalse(Files.exists(fixture.project.resolve("reports/modules/parse.attempt.json")))
    }

    private fun revisionNonce(fixture: Fixture, revision: Map<String, ByteArray>): String {
        val checkpoint = Json.parseToJsonElement(revision.getValue(fixture.path("module-evidence")).decodeToString()).jsonObject
        return ContainedModuleCompilationProof.verify(checkpoint.getValue("compilation").jsonObject
            .getValue("containedProof").jsonObject).request.nonce
    }

    private fun moduleCases(case: String, method: String,
        transform: (ReconstructionProfile) -> ReconstructionProfile = { it }, block: (Fixture) -> Unit) {
        val directory = System.getenv(ContainedModuleCompilationRuntimeConfiguration.DIRECTORY_ENVIRONMENT)
        val required = System.getenv("GENERATED_C_MODULE_COMPILE_REQUIRE") == "true"
        if (required) assertTrue(!directory.isNullOrBlank(), "required Make/Ninja qualification needs the provisioned configuration directory")
        assumeTrue(!directory.isNullOrBlank(), "set GENERATED_C_MODULE_COMPILE_CONFIG_DIRECTORY for both registered profiles")
        val completed = linkedSetOf<String>()
        for ((short, id) in listOf("make" to "generated-c-make-v1", "ninja" to "generated-c-ninja-v1")) {
            ContainedModuleHostedCase.run("module-$short-$case", javaClass.name, method, id) { cell ->
                cell.stage("configured")
                assertTrue(System.getProperty("os.name").lowercase().contains("linux"))
                val runtime = ContainedModuleCompilationRuntimeConfiguration.loadFromEnvironment(id)
                val profile = transform(ReconstructionProfiles.named(id))
                requireContainedModuleCompilerProfile(profile)
                val reports = Path.of("build", "reports", "contained-module-compilation-live", id).toAbsolutePath().normalize()
                Files.createDirectories(reports)
                val root = Files.createTempDirectory(reports, "$case-")
                val fixture = Fixture(root, Files.createDirectory(root.resolve("project")), runtime, profile, cell)
                fixture.report("qualification.json", JsonObject(mapOf(
                    "qualification" to JsonPrimitive("real-contained-compiler-authored-reconstructor-not-acp"),
                    "profileId" to JsonPrimitive(profile.id), "profileSha256" to JsonPrimitive(profile.sha256),
                    "runtimeConfigurationSha256" to JsonPrimitive(runtime.configurationSha256),
                    "required" to JsonPrimitive(required), "expectedInputCount" to JsonPrimitive(514))))
                fixture.requireClean()
                fixture.extraHeaders = ContainedModuleCompilationHostedSupport.stageExtraHeaders(fixture.project, profile)
                block(fixture)
                fixture.requireClean()
                cell.stage("completed")
                completed += id
            }
        }
        assertEquals(setOf("generated-c-make-v1", "generated-c-ninja-v1"), completed)
    }

    private class Fixture(val root: Path, val project: Path,
        val runtime: ContainedModuleCompilationRuntimeConfiguration, val profile: ReconstructionProfile,
        val cell: ContainedModuleHostedCase.Case) {
        var extraHeaders: List<String> = emptyList()
        private val captured = linkedMapOf<String, List<ContainedModuleCompilerInput>>()
        private var scopeQuery = 0
        fun path(role: String): String = profile.layout.declaration(role).let { declaration ->
            declaration.materialize(if ("{module}" in declaration.pathTemplate) mapOf("module" to "parse") else emptyMap())
        }
        fun write(relative: String, content: String) {
            val target = project.resolve(relative)
            Files.createDirectories(target.parent)
            Files.writeString(target, content)
        }
        fun report(name: String, value: JsonObject) {
            val bytes = OracleJson.canonicalBytes(value)
            Files.write(root.resolve(name), bytes, java.nio.file.StandardOpenOption.CREATE_NEW)
            cell.retain(name, bytes)
        }
        fun currentInputs(): List<ContainedModuleCompilerInput> {
            val paths = (extraHeaders + listOf(path("shared-interface"), path("module-interface"),
                path("module-private-interface"), path("module-implementation"))).sorted()
            require(paths.size == 514 && paths.distinct().size == 514)
            return paths.map { relative ->
                val bytes = ContainedModuleCompilationHostedSupport.readRegular(project.resolve(relative),
                    ContainedModuleCompilerRequest.MAXIMUM_INPUT_FILE_BYTES.toInt())
                require(bytes.isNotEmpty())
                ContainedModuleCompilerInput(relative, sha256(bytes), bytes.size.toLong())
            }.also { rows -> require(rows.sumOf { it.bytes } <= ContainedModuleCompilerRequest.MAXIMUM_TOTAL_INPUT_BYTES) }
        }
        private fun captureInputs(label: String) {
            require(label !in captured)
            val inputs = currentInputs()
            inputs.forEach { input ->
                val bytes = ContainedModuleCompilationHostedSupport.readRegular(project.resolve(input.path),
                    ContainedModuleCompilerRequest.MAXIMUM_INPUT_FILE_BYTES.toInt())
                require(bytes.size.toLong() == input.bytes && sha256(bytes) == input.sha256)
                cell.retain("$label/inputs/${input.path}", bytes)
            }
            captured[label] = inputs
            cell.retain("$label/input-manifest.json", OracleJson.canonicalBytes(kotlinx.serialization.json.JsonArray(inputs.map { it.json() })))
        }
        fun verifyCapturedInputs(label: String, evidence: ModuleCompilationEvidence) {
            val proof = ContainedModuleCompilationProof.verify(evidence)
            verifyCapturedRequest(label, proof.request)
            assertEquals(JsonPrimitive(2), assertNotNull(evidence.containedProof)["schemaVersion"])
        }
        fun verifyCapturedRequest(label: String, request: ContainedModuleCompilerRequest) {
            assertEquals(514, request.inputs.size)
            assertEquals(requireNotNull(captured[label]).map { it.json() }, request.inputs.map { it.json() })
            assertEquals(profile.sha256, request.profileSha256)
        }
        fun compile(source: String, label: String): ModuleCompilationEvidence {
            cell.stage(label)
            captureInputs(label)
            return ContainedModuleCompilationPolicy.validate(project, source, profile).also {
                verifyCapturedInputs(label, it)
                cell.retain("$label/evidence.json", it.toJson().toByteArray())
                requireClean(it)
            }
        }
        fun generate(model: RecoveredProgramModel, reconstructor: ModuleReconstructor, label: String): SourceTreeManifest {
            cell.stage(label)
            return SourceTreeGenerator.generate(model, project, profile = profile, reconstructor = reconstructor,
                progress = object : decompengine.agent.AgentWorkflowProgress by decompengine.agent.AgentWorkflowProgress.NONE {
                    override fun phase(phase: decompengine.agent.AgentWorkflowPhase, taskId: String?, acceptedRevisionSha256: String?) {
                        if (phase == decompengine.agent.AgentWorkflowPhase.BUILD_VALIDATING) captureInputs(label)
                    }
                }).also { manifest ->
                    val source = manifest.files.single { it.path == path("module-implementation") }
                    val checkpoint = Json.parseToJsonElement(Files.readString(project.resolve(path("module-evidence")))).jsonObject
                    val evidence = ModuleCompilationEvidence.decode(checkpoint.getValue("compilation").jsonObject, 7, profile,
                        source.path, checkpoint.getValue("sourceSha256").jsonPrimitive.content, accepted = true)
                    verifyCapturedInputs(label, evidence)
                    cell.retain("$label/evidence.json", evidence.toJson().toByteArray())
                }
        }
        fun retainRevision(label: String, expected: Map<String, ByteArray>): Map<String, ByteArray> = expected.mapValues { (relative, original) ->
            val actual = ContainedModuleCompilationHostedSupport.readRegular(project.resolve(relative), 4 * 1024 * 1024)
            assertContentEquals(original, actual, relative)
            cell.retain("$label/$relative", actual)
            actual
        }
        fun retainAttempt(name: String): ByteArray = ContainedModuleCompilationHostedSupport.readRegular(
            project.resolve("reports/modules/parse.attempt.json"), 4 * 1024 * 1024).also { cell.retain(name, it) }
        fun retainDirectory(prefix: String, directory: Path) {
            if (!Files.exists(directory, LinkOption.NOFOLLOW_LINKS)) {
                cell.retain("$prefix/absent.json", OracleJson.canonicalBytes(JsonObject(mapOf("directoryPresent" to JsonPrimitive(false)))))
                return
            }
            require(directory.toRealPath() == directory && Files.isDirectory(directory, LinkOption.NOFOLLOW_LINKS))
            Files.walk(directory, 8).use { entries ->
                val iterator = entries.iterator()
                var count = 0
                while (iterator.hasNext()) {
                    val path = iterator.next()
                    require(++count <= 128 && !Files.isSymbolicLink(path))
                    if (Files.isDirectory(path, LinkOption.NOFOLLOW_LINKS)) continue
                    val bytes = ContainedModuleCompilationHostedSupport.readRegular(path, 4 * 1024 * 1024)
                    cell.retain("$prefix/${directory.relativize(path)}", bytes)
                }
            }
        }
        /** Ordinary test coordinator only: production's root-only 30-second native helper is unchanged. */
        fun runLowHardChild(arguments: List<String>, environment: Map<String, String>): Pair<Long, Long> {
            val output = ByteArrayOutputStream()
            val error = ByteArrayOutputStream()
            val captureFailure = AtomicReference<Throwable?>()
            val stdoutComplete = AtomicBoolean()
            val stderrComplete = AtomicBoolean()
            var outThread: Thread? = null
            var errThread: Thread? = null
            var primary: Throwable? = null
            var startTime: Long? = null
            val commandDeadline = System.nanoTime() + TimeUnit.SECONDS.toNanos(120)
            val builder = ProcessBuilder(arguments).directory(Path.of("").toAbsolutePath().toRealPath().toFile())
            builder.environment().clear()
            builder.environment().putAll(environment)
            val process = builder.start()
            try {
                process.outputStream.close()
                fun capture(name: String, stream: InputStream, bytes: ByteArrayOutputStream, complete: AtomicBoolean): Thread = Thread({
                    try {
                        stream.use { input ->
                            val buffer = ByteArray(4096)
                            while (true) {
                                val count = input.read(buffer, 0, minOf(buffer.size, 64 * 1024 + 1 - bytes.size()))
                                if (count < 0) { complete.set(true); break }
                                synchronized(bytes) { bytes.write(buffer, 0, count) }
                                check(bytes.size() <= 64 * 1024) { "low-hard child $name exceeds its bounded pipe capture" }
                            }
                        }
                    } catch (failure: Throwable) {
                        captureFailure.compareAndSet(null, failure)
                        if (process.isAlive) process.destroyForcibly()
                    }
                }, "module-low-hard-$name").apply { isDaemon = true; start() }
                outThread = capture("stdout", process.inputStream, output, stdoutComplete)
                errThread = capture("stderr", process.errorStream, error, stderrComplete)
                val stat = Files.newInputStream(Path.of("/proc", process.pid().toString(), "stat")).use { it.readNBytes(64 * 1024 + 1) }
                require(stat.size <= 64 * 1024)
                startTime = parseFullTreeFunctionObservationProcessStartTimeTicks(process.pid(), stat.decodeToString())
                cell.retain("child/parent-observed-stat.txt", stat)
                fun remaining(): Long = (commandDeadline - System.nanoTime()).also {
                    if (it <= 0L) throw java.util.concurrent.TimeoutException("low-hard child exceeded its aggregate test command window")
                }
                if (!process.waitFor(remaining(), TimeUnit.NANOSECONDS)) {
                    throw java.util.concurrent.TimeoutException("low-hard child did not terminate inside its aggregate test command window")
                }
                for (thread in listOfNotNull(outThread, errThread)) {
                    TimeUnit.NANOSECONDS.timedJoin(thread, remaining())
                    check(!thread.isAlive) { "low-hard child pipe capture did not terminate inside the command window" }
                }
                captureFailure.get()?.let { throw it }
                check(stdoutComplete.get() && stderrComplete.get()) { "low-hard child pipe capture is incomplete" }
                assertEquals(0, process.exitValue(), synchronized(error) { error.toString(Charsets.UTF_8) })
                return process.pid() to checkNotNull(startTime)
            } catch (failure: Throwable) {
                primary = failure
                throw failure
            } finally {
                val cleanupDeadline = System.nanoTime() + TimeUnit.SECONDS.toNanos(5)
                var cleanupFailure: Throwable? = null
                val cleanupProblems = mutableListOf<String>()
                fun cleanup(action: () -> Unit) {
                    try { action() } catch (failure: Throwable) {
                        cleanupProblems += failure.javaClass.name
                        val original = primary
                        val previous = cleanupFailure
                        if (original != null) original.addSuppressed(failure)
                        else if (previous == null) cleanupFailure = failure else previous.addSuppressed(failure)
                    }
                }
                cleanup {
                    if (process.isAlive) process.destroyForcibly()
                    val remaining = cleanupDeadline - System.nanoTime()
                    check(!process.isAlive || remaining > 0L && process.waitFor(remaining, TimeUnit.NANOSECONDS)) {
                        "low-hard child remains alive after bounded cleanup"
                    }
                }
                cleanup { process.inputStream.close() }
                cleanup { process.errorStream.close() }
                cleanup { process.outputStream.close() }
                for (thread in listOfNotNull(outThread, errThread)) cleanup {
                    val remaining = cleanupDeadline - System.nanoTime()
                    if (thread.isAlive && remaining > 0L) TimeUnit.NANOSECONDS.timedJoin(thread, remaining)
                    check(!thread.isAlive) { "low-hard child capture thread remains alive after bounded cleanup" }
                }
                cleanup { cell.retain("child/stdout.bin", synchronized(output) { output.toByteArray() }) }
                cleanup { cell.retain("child/stderr.bin", synchronized(error) { error.toByteArray() }) }
                cleanup { cell.retain("child/process-outcome.json", OracleJson.canonicalBytes(JsonObject(mapOf(
                    "schemaVersion" to JsonPrimitive(1), "provider" to JsonPrimitive("hosted-low-hard-test-process-v1"),
                    "hostPid" to JsonPrimitive(process.pid()), "parentObservedStartTimeTicks" to JsonPrimitive(startTime),
                    "commandSha256" to JsonPrimitive(sha256(OracleJson.canonicalBytes(JsonArray(arguments.map(::JsonPrimitive))))),
                    "processAbsent" to JsonPrimitive(!process.isAlive), "stdoutComplete" to JsonPrimitive(stdoutComplete.get()),
                    "stderrComplete" to JsonPrimitive(stderrComplete.get()), "maximumPipeBytes" to JsonPrimitive(64 * 1024),
                    "captureThreadsAbsent" to JsonPrimitive(listOfNotNull(outThread, errThread).none { it.isAlive }),
                    "cleanupFailures" to JsonArray(cleanupProblems.map(::JsonPrimitive)),
                    "exitCode" to JsonPrimitive(if (process.isAlive) null else process.exitValue()),
                    "captureFailure" to (captureFailure.get()?.let { JsonPrimitive(it.javaClass.name) } ?: kotlinx.serialization.json.JsonNull),
                )))) }
                if (primary == null) cleanupFailure?.let { throw it }
            }
        }
        fun acceptedRevision(manifest: SourceTreeManifest): Map<String, ByteArray> {
            val source = manifest.files.single { it.path == path("module-implementation") }
            assertEquals(true, source.acceptedImplementation)
            assertTrue(manifest.unresolvedImplementationIds.isEmpty())
            val checkpoint = Json.parseToJsonElement(Files.readString(project.resolve(path("module-evidence")))).jsonObject
            assertEquals(7, checkpoint.getValue("schemaVersion").jsonPrimitive.int)
            assertTrue(checkpoint.getValue("accepted").jsonPrimitive.boolean)
            val recorded = ModuleCompilationEvidence.decode(checkpoint.getValue("compilation").jsonObject,
                7, profile, source.path, checkpoint.getValue("sourceSha256").jsonPrimitive.content, accepted = true)
            assertTrue(recorded.passed)
            assertFalse(recorded.authorizesAcceptance(recorded.sourceSha256, profile.sha256, POLICY))
            assertEquals("compiled-object", ContainedModuleCompilationProof.verify(recorded).result.outcome)
            requireClean(recorded)
            return listOf(source.path, path("module-evidence"), "source_tree_manifest.json")
                .associateWith { Files.readAllBytes(project.resolve(it)) }
        }
        fun requireClean(evidence: ModuleCompilationEvidence? = null) {
            assertTrue(Files.list(runtime.scratchMount).use { it.findAny().isEmpty }, "dedicated finite scratch must be empty after cleanup")
            assertTrue(Files.list(project).use { entries -> entries.noneMatch { it.fileName.toString().startsWith(".module-compilation-") } },
                "private coordinator request directories must be removed")
            evidence?.let {
                val proof = assertNotNull(it.containedProof)
                assertTrue(proof.getValue("cleanup").jsonObject.values.all { value -> value == JsonPrimitive(true) })
                requireScopeAbsent(ContainedModuleCompilationProof.verify(it).request.nonce)
            }
        }
        fun requireScopeAbsent(nonce: String) {
            val unit = "decomp-module-compile-${nonce.take(32)}.scope"
            val group = Path.of("/sys/fs/cgroup").resolve("${runtime.managerControlGroup.trimEnd('/')}/app.slice/$unit".removePrefix("/"))
            assertFalse(Files.exists(group, LinkOption.NOFOLLOW_LINKS), "owned cgroup remains: $group")
            requireUnitsAbsent(unit, "exact-operation")
        }
        fun requireModuleScopesAbsent() {
            val app = Path.of("/sys/fs/cgroup").resolve("${runtime.managerControlGroup.trimEnd('/')}/app.slice".removePrefix("/"))
            if (Files.exists(app, LinkOption.NOFOLLOW_LINKS)) Files.newDirectoryStream(app).use { entries ->
                var count = 0
                for (entry in entries) {
                    require(++count <= 4096) { "module scope absence inventory exceeds its test bound" }
                    assertFalse(entry.fileName.toString().startsWith("decomp-module-compile-"), "module scope remains: $entry")
                }
            }
            requireUnitsAbsent("decomp-module-compile-*.scope", "module-prefix-not-operation-nonce")
        }
        private fun requireUnitsAbsent(unit: String, scope: String) {
            val configuration = runtime.isolation
            val result = LinuxBoundedSessionProcess.execute(LinuxBoundedSessionCommand(
                listOf(configuration.scopeInspectorExecutable.toString(), "--user", "--no-pager", "list-units", "--all", "--no-legend", "--plain", unit),
                mapOf("XDG_RUNTIME_DIR" to configuration.systemdUserRuntimeDirectory.toString(),
                    "DBUS_SESSION_BUS_ADDRESS" to "unix:path=${configuration.systemdUserRuntimeDirectory.resolve("bus")}"),
                timeout = Duration.ofSeconds(5), maximumStdoutBytes = 4096, maximumStderrBytes = 4096))
            val label = "scope-checks/query-${scopeQuery++}"
            cell.retain("$label.stdout", result.stdout)
            cell.retain("$label.stderr", result.stderr)
            cell.retain("$label.json", OracleJson.canonicalBytes(JsonObject(mapOf("scope" to JsonPrimitive(scope),
                "unitPattern" to JsonPrimitive(unit), "exitCode" to JsonPrimitive(result.exitCode),
                "signal" to JsonPrimitive(result.signal), "stdoutSha256" to JsonPrimitive(sha256(result.stdout)),
                "stderrSha256" to JsonPrimitive(sha256(result.stderr))))))
            assertEquals(null, result.signal)
            assertEquals(0, result.exitCode, result.stderr.decodeToString())
            assertTrue(result.stdout.decodeToString().isBlank(), "owned systemd scope remains registered")
        }
    }

    private data class ObservedCompiler(val request: ContainedModuleCompilerRequest, val compilerPids: Set<Long>)

    private fun awaitRealCompiler(fixture: Fixture, thread: Thread, failure: AtomicReference<Throwable?>,
        handles: MutableMap<Long, LinuxProcessDescriptor>): ObservedCompiler {
        val deadline = System.nanoTime() + TimeUnit.SECONDS.toNanos(90)
        var request: ContainedModuleCompilerRequest? = null
        while (thread.isAlive && System.nanoTime() < deadline) {
            if (request == null) request = Files.list(fixture.project).use { paths ->
                paths.filter { it.fileName.toString().startsWith(".module-compilation-") }.map { it.resolve("request.json") }
                    .filter { Files.isRegularFile(it, LinkOption.NOFOLLOW_LINKS) }.findFirst().orElse(null)
            }?.let { path -> runCatching {
                ContainedModuleCompilerRequest.parse(boundedRead(path, ContainedModuleCompilerRequest.MAXIMUM_REQUEST_BYTES).toByteArray())
            }.getOrNull() }
            val current = request
            if (current != null) {
                val unit = "decomp-module-compile-${current.nonce.take(32)}.scope"
                val cgroup = Path.of("/sys/fs/cgroup").resolve("${fixture.runtime.managerControlGroup.trimEnd('/')}/app.slice/$unit".removePrefix("/"))
                val pids = runCatching { boundedRead(cgroup.resolve("cgroup.procs"), 64 * 1024).lineSequence()
                    .filter(String::isNotBlank).map { it.toLong() }.toList() }.getOrDefault(emptyList())
                val compilerPids = linkedSetOf<Long>()
                for (pid in pids) {
                    val handle = handles[pid] ?: runCatching { LinuxFilesystemSyscalls.openProcessHandle(pid) }.getOrNull()
                        ?.also { handles[pid] = it } ?: continue
                    val comm = runCatching { boundedRead(Path.of("/proc", pid.toString(), "comm"), 4096).trim() }.getOrNull()
                    // comm is a read-only observation, never acceptance authority. The immutable
                    // configured compiler and its actual invocation are authenticated by the policy.
                    if (comm in setOf("cc1", "cc1plus", "clang", fixture.runtime.compilerExecutable.fileName.toString().take(15)) &&
                        LinuxFilesystemSyscalls.processExists(handle)) compilerPids += pid
                }
                if (compilerPids.isNotEmpty()) return ObservedCompiler(current, compilerPids)
            }
            Thread.sleep(2)
        }
        error("real configured compiler was not observed before cancellation; ${failure.get()?.stackTraceToString()}")
    }

    private fun authoredReconstructor(profile: ReconstructionProfile,
        body: String = ContainedModuleCompilationHostedSupport.DEFAULT_BODY,
        extraPrelude: String = ""): ModuleReconstructor = ContainedModuleCompilationHostedSupport.reconstructor(profile, body, extraPrelude)

    private fun model() = ContainedModuleCompilationHostedSupport.model()

    private fun longCompilerBody(): String = buildString {
        append("volatile unsigned value = 9u;\n")
        repeat(40_000) { append("value = value * 1664525u + 1013904223u;\n") }
        append("return (int)value;\n")
    }.also { require(it.toByteArray().size < ContainedModuleCompilerRequest.MAXIMUM_INPUT_FILE_BYTES) }

    private fun assertLiveAcceptance(evidence: ModuleCompilationEvidence, profile: ReconstructionProfile) {
        assertTrue(evidence.passed)
        assertTrue(evidence.authorizesAcceptance(evidence.sourceSha256, profile.sha256, POLICY))
    }

    companion object {
        private const val POLICY = ContainedModuleCompilationPolicy.POLICY_ID
        private const val FUNCTION_ID = "fn_0000000000401000"
        private fun boundedRead(path: Path, maximum: Int): String = Files.newInputStream(path).use { stream ->
            val bytes = stream.readNBytes(maximum + 1)
            require(bytes.size <= maximum) { "live qualification observation exceeds its bound: $path" }
            bytes.toString(Charsets.UTF_8)
        }
    }
}
