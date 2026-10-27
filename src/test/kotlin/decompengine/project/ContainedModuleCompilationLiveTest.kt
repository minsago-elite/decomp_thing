package decompengine.project

import decompengine.acp.LinuxFilesystemSyscalls
import decompengine.acp.LinuxProcessDescriptor
import decompengine.oracle.core.OracleJson
import java.nio.file.Files
import java.nio.file.LinkOption
import java.nio.file.Path
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
    fun `real compilation issues live authority only for the exact current source and header snapshot`() {
        val fixture = fixture("exact-snapshot")
        // The configured lane must exercise the deployment boundary host-only fixtures miss:
        // this host-root inode is mounted through --unshare-user, where root is unmapped.
        val compilerIdentity = Files.readAttributes(fixture.runtime.compilerExecutable, "unix:uid,gid,mode,nlink", LinkOption.NOFOLLOW_LINKS)
        assertEquals(0, compilerIdentity.getValue("uid"), "configured qualification requires the root-owned runtime compiler")
        assertEquals(1, compilerIdentity.getValue("nlink"))
        assertEquals(0, (compilerIdentity.getValue("mode") as Int) and 0x12)
        assertEquals(fixture.runtime.compilerSha256, sha256(Files.readAllBytes(fixture.runtime.compilerExecutable)))
        fixture.report("root-owned-compiler-regression.json", JsonObject(mapOf(
            "compilerSha256" to JsonPrimitive(fixture.runtime.compilerSha256),
            "hostUid" to JsonPrimitive(compilerIdentity.getValue("uid") as Int),
            "hostGid" to JsonPrimitive(compilerIdentity.getValue("gid") as Int),
            "boundary" to JsonPrimitive("configured-unshare-user-with-digest-authenticated-owned-compiler-copy"),
        )))
        val sourcePath = fixture.path("module-implementation")
        val headerPath = fixture.path("module-interface")
        fixture.write(fixture.path("shared-interface"), "/* authored live fixture */\n")
        fixture.write(headerPath, "enum { OBSERVED_CONSTANT = 7 };\nint parse_input(void);\n")
        fixture.write(fixture.path("module-private-interface"), "/* private live fixture */\n")
        fixture.write(sourcePath, "#include \"modules/parse.h\"\n#include \"parse_internal.h\"\nint parse_input(void) { return OBSERVED_CONSTANT; }\n")

        val first = fixture.compile(sourcePath, "first")
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

        fixture.write(sourcePath, "#include \"modules/parse.h\"\n#include \"parse_internal.h\"\nint parse_input(void) { return OBSERVED_CONSTANT + 1; }\n")
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
    fun `real compiler rejection preserves the earlier accepted SourceTree revision and checkpoint`() {
        val fixture = fixture("source-tree-rejection")
        val original = model()
        val manifest = SourceTreeGenerator.generate(original, fixture.project, profile = fixture.profile,
            reconstructor = authoredReconstructor())
        val accepted = fixture.acceptedRevision(manifest)
        val candidateModel = original.copy(functions = original.functions.map { it.copy(strings = setOf("new recovered evidence")) })
        val rejection = assertFailsWith<ModuleReconstructionRevisionRejectedException> {
            SourceTreeGenerator.generate(candidateModel, fixture.project, profile = fixture.profile,
                reconstructor = authoredReconstructor(body = "return missing_live_fixture_value;"))
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
        fixture.requireClean(rejectedEvidence)
    }

    @Test
    fun `interrupting an observed real compiler restores prior acceptance and removes its processes scope and scratch`() {
        val fixture = fixture("source-tree-cancellation")
        val original = model()
        val manifest = SourceTreeGenerator.generate(original, fixture.project, profile = fixture.profile,
            reconstructor = authoredReconstructor())
        val accepted = fixture.acceptedRevision(manifest)
        val candidateModel = original.copy(functions = original.functions.map { it.copy(strings = setOf("cancelled recovered revision")) })
        val failure = AtomicReference<Throwable?>()
        val interrupted = AtomicBoolean()
        val thread = Thread({
            try {
                SourceTreeGenerator.generate(candidateModel, fixture.project, profile = fixture.profile,
                    reconstructor = authoredReconstructor(body = longCompilerBody()))
            } catch (caught: Throwable) {
                failure.set(caught)
            } finally {
                interrupted.set(Thread.currentThread().isInterrupted)
            }
        }, "contained-module-live-cancellation")
        val handles = linkedMapOf<Long, LinuxProcessDescriptor>()
        var observed: ObservedCompiler? = null
        try {
            thread.start()
            observed = awaitRealCompiler(fixture, thread, failure, handles)
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
            val resumed = SourceTreeGenerator.generate(original, fixture.project, profile = fixture.profile,
                reconstructor = ModuleReconstructor { error("the preserved accepted revision must resume without reconstruction dispatch") })
            val revalidated = fixture.acceptedRevision(resumed)
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
        } finally {
            if (thread.isAlive) {
                thread.interrupt()
                thread.join(90_000)
            }
            handles.values.forEach { it.close() }
            failure.get()?.let { Files.writeString(fixture.root.resolve("cancellation-exception.txt"), it.stackTraceToString()) }
            observed?.let { Files.write(fixture.root.resolve("cancelled-request.json"), it.request.canonicalBytes) }
        }
    }

    private fun fixture(case: String): Fixture {
        val configured = System.getenv(ContainedModuleCompilationRuntimeConfiguration.ENVIRONMENT)
        val directory = System.getenv("GENERATED_C_MODULE_COMPILE_CONFIG_DIRECTORY")
        val required = System.getenv("GENERATED_C_MODULE_COMPILE_REQUIRE") == "true"
        val present = !configured.isNullOrBlank() || !directory.isNullOrBlank()
        if (required) assertTrue(present, "required contained compiler qualification has no runtime configuration")
        assumeTrue(present, "set GENERATED_C_MODULE_COMPILE_CONFIG_FILE or DIRECTORY to run real contained compiler qualification")
        // Once configured, invalid runtime data or a missing boundary is a failure, never an assumption abort.
        assertTrue(System.getProperty("os.name").lowercase().contains("linux"))
        val runtime = ContainedModuleCompilationRuntimeConfiguration.loadFromEnvironment()
        val profile = ReconstructionProfiles.named(runtime.profileId)
        val reports = Path.of("build", "reports", "contained-module-compilation-live", profile.id).toAbsolutePath().normalize()
        Files.createDirectories(reports)
        val root = Files.createTempDirectory(reports, "$case-")
        val fixture = Fixture(root, Files.createDirectory(root.resolve("project")), runtime, profile)
        fixture.report("qualification.json", JsonObject(mapOf(
            "qualification" to JsonPrimitive("real-contained-compiler-authored-reconstructor-not-acp"),
            "profileId" to JsonPrimitive(profile.id), "profileSha256" to JsonPrimitive(profile.sha256),
            "runtimeConfigurationSha256" to JsonPrimitive(runtime.configurationSha256),
            "required" to JsonPrimitive(required),
        )))
        fixture.requireClean()
        return fixture
    }

    private class Fixture(val root: Path, val project: Path,
        val runtime: ContainedModuleCompilationRuntimeConfiguration, val profile: ReconstructionProfile) {
        fun path(role: String): String = profile.layout.declaration(role).let { declaration ->
            declaration.materialize(if ("{module}" in declaration.pathTemplate) mapOf("module" to "parse") else emptyMap())
        }
        fun write(relative: String, content: String) {
            val target = project.resolve(relative)
            Files.createDirectories(target.parent)
            Files.writeString(target, content)
        }
        fun report(name: String, value: JsonObject) { Files.write(root.resolve(name), OracleJson.canonicalBytes(value)) }
        fun compile(source: String, label: String): ModuleCompilationEvidence =
            ContainedModuleCompilationPolicy.validate(project, source, profile).also {
                Files.writeString(root.resolve("$label-evidence.json"), it.toJson())
                requireClean(it)
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
            val output = root.resolve("$unit.systemctl.stdout")
            val error = root.resolve("$unit.systemctl.stderr")
            val configuration = runtime.isolation
            val process = ProcessBuilder(configuration.scopeInspectorExecutable.toString(), "--user", "--no-pager",
                "list-units", "--all", "--no-legend", "--plain", unit).also { builder ->
                builder.environment().clear()
                builder.environment()["XDG_RUNTIME_DIR"] = configuration.systemdUserRuntimeDirectory.toString()
                builder.environment()["DBUS_SESSION_BUS_ADDRESS"] = "unix:path=${configuration.systemdUserRuntimeDirectory.resolve("bus")}"
                builder.redirectOutput(output.toFile()).redirectError(error.toFile())
            }.start()
            try {
                assertTrue(process.waitFor(5, TimeUnit.SECONDS), "owned scope absence query timed out")
                assertEquals(0, process.exitValue(), boundedRead(error, 4096))
                assertTrue(boundedRead(output, 4096).isBlank(), "owned systemd scope remains registered")
            } finally {
                if (process.isAlive) { process.destroyForcibly(); process.waitFor(5, TimeUnit.SECONDS) }
            }
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

    private fun authoredReconstructor(body: String = "volatile unsigned value = 7u; return (int)value;"): ModuleReconstructor =
        ModuleReconstructor { request ->
            assertEquals(listOf(FUNCTION_ID), request.module.functionIds)
            val source = "#include \"modules/${request.module.id}.h\"\n/* $FUNCTION_ID */\nint parse_input(void) { $body }\n"
            ReconstructedModule(source, "authored-contained-compiler-live-fixture", sha256(source.toByteArray()))
        }

    private fun model() = RecoveredProgramModel(inputSha256 = sha256("authored live module fixture".toByteArray()),
        functions = listOf(RecoveredFunction(FUNCTION_ID, "parse_input", 0x401000UL, "int parse_input(void)",
            decompiledC = "int parse_input(void) { volatile unsigned value = 7u; return (int)value; }")))

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
