package decompengine.oracle.reference

import decompengine.acp.LinuxFilesystemSyscalls
import decompengine.oracle.behavior.LlvmBehaviorNativeOciImageV2
import decompengine.oracle.core.DescriptorBoundAtomicStateFile
import decompengine.oracle.core.OracleArtifacts
import decompengine.oracle.core.OracleJson
import decompengine.oracle.fulltree.OracleNativeLibraries
import java.nio.file.Files
import java.nio.file.LinkOption.NOFOLLOW_LINKS
import java.nio.file.Path
import java.nio.file.attribute.PosixFilePermissions
import java.util.concurrent.Executors
import java.util.concurrent.TimeUnit
import kotlin.test.Test
import kotlin.test.assertEquals
import kotlin.test.assertFalse
import kotlin.test.assertNotNull
import kotlin.test.assertTrue
import kotlinx.serialization.json.JsonArray
import kotlinx.serialization.json.JsonObject
import kotlinx.serialization.json.JsonPrimitive
import kotlinx.serialization.json.jsonArray
import kotlinx.serialization.json.jsonObject
import kotlinx.serialization.json.jsonPrimitive
import org.junit.jupiter.api.Assumptions.assumeTrue

/** Optional semantic regression only: unprivileged bwrap is not an admitted production owner. */
class ReferenceCorpusWorkerPinnedImageTest {
    @Test
    fun `real worker reproduces every frozen metadata case in the pinned native image`() {
        val configured = System.getenv("DECOMP_REFERENCE_NATIVE_REAL_STAGE").orEmpty()
        assumeTrue(configured.isNotEmpty(), "set DECOMP_REFERENCE_NATIVE_REAL_STAGE and DECOMP_REFERENCE_NATIVE_REAL_OCI for pinned-image computation")
        val repository = Path.of(System.getProperty("user.dir")).toRealPath()
        val stage = Path.of(configured).toRealPath()
        val oci = Path.of(checkNotNull(System.getenv("DECOMP_REFERENCE_NATIVE_REAL_OCI"))).toRealPath()
        val build = repository.resolve("build")
        require(build.toRealPath() == build) { "test build directory contains path indirection" }
        val parent = build.resolve("reference-worker-pinned-image")
        if (Files.notExists(parent, NOFOLLOW_LINKS)) Files.createDirectory(parent, PRIVATE_DIRECTORY)
        require(parent.toRealPath() == parent) { "test evidence parent contains path indirection" }
        val configuredOutput = System.getenv("DECOMP_REFERENCE_WORKER_REAL_OUTPUT")
        val root = if (configuredOutput == null) Files.createTempDirectory(parent, "capture-", PRIVATE_DIRECTORY) else {
            val selected = Path.of(configuredOutput).toAbsolutePath().normalize()
            require(selected.startsWith(repository) && selected != repository) { "test output must remain in the repository" }
            require(selected.parent.toRealPath() == selected.parent) { "test output parent contains path indirection" }
            Files.createDirectory(selected, PRIVATE_DIRECTORY)
        }
        require(root.toRealPath() == root)
        val profileRoot = repository.resolve("oracle/gcc/16.2.0")
        AuthenticatedReferenceCorpusProfile.open(profileRoot, "gcc-metadata-v1").use { profile ->
            LlvmBehaviorNativeOciImageV2.openLayout(oci).use { image ->
                val plan = ReferenceNativeRuntime.plan(image, profile.nativeRuntimeSelection, profile.originalArtifacts)
                ReferenceNativeRuntime.verify(stage, plan, trustedOwnership = false)
                val nativeLibraries = repository.resolve("build/native/oracle").toRealPath()
                val classPath = minimalWorkerClassPath()
                OracleNativeLibraries.requireCurrent(nativeLibraries, classPath.filter { Files.isRegularFile(it, NOFOLLOW_LINKS) }
                    .map { OracleArtifacts.sha256(Files.readAllBytes(it)) })
                val profilePath = root.resolve("profile.json")
                Files.write(profilePath, profile.canonicalBytes)
                val observations = mutableListOf<JsonObject>()
                val batchReceipts = mutableListOf<JsonObject>()
                for (batch in profile.definition.batches.values) {
                    val control = Files.createDirectory(root.resolve("control-${batch.id}"), PRIVATE_DIRECTORY)
                    listOf("state", "reports", "tmp").forEach { Files.createDirectory(control.resolve(it), PRIVATE_DIRECTORY) }
                    val request = ReferenceCorpusWorkerRequest(profilePath, profile.canonicalBytes.size, profile.profileSha256,
                        batch.id, control, OracleArtifacts.sha256("non-authoritative-pinned-image-computation".toByteArray()))
                    val requestPath = root.resolve("request-${batch.id}.json")
                    Files.write(requestPath, request.canonicalBytes)
                    val mounts = plan.mounts.filter { it.role.isEmpty() || it.role in batch.artifactRoles }
                        .map { stage.resolve(it.relative) to Path.of(it.guest) }
                    val log = root.resolve("worker-${batch.id}.log")
                    val command = command(request, requestPath, mounts, classPath, nativeLibraries)
                    Files.write(root.resolve("command-${batch.id}.json"), OracleJson.canonicalBytes(JsonArray(command.map(::JsonPrimitive))))
                    val process = ProcessBuilder(command).directory(repository.toFile()).redirectErrorStream(true)
                        .also { it.environment().clear() }.start()
                    val reader = Executors.newSingleThreadExecutor { task -> Thread(task, "pinned-image-test-log").apply { isDaemon = true } }
                    val captured = reader.submit<ByteArray> {
                        process.inputStream.use { it.readNBytes(64 * 1024 + 1) }.also { bytes ->
                            Files.write(log, bytes.copyOf(minOf(bytes.size, 64 * 1024)))
                        }
                    }
                    try {
                        val deadline = System.nanoTime() + TimeUnit.SECONDS.toNanos(180)
                        while (!process.waitFor(25, TimeUnit.MILLISECONDS)) {
                            if (captured.isDone) assertTrue(captured.get().size <= 64 * 1024, "worker launch log exceeds fixture bound")
                            assertTrue(System.nanoTime() < deadline, "pinned-image worker exceeded test fixture timeout")
                        }
                        val logBytes = captured.get(5, TimeUnit.SECONDS)
                        assertTrue(logBytes.size <= 64 * 1024, "worker launch log exceeds fixture bound")
                        assertEquals(0, process.exitValue(), logBytes.decodeToString().take(16 * 1024))
                    } finally {
                        try {
                            if (process.isAlive) {
                                process.descendants().use { descendants -> descendants.limit(256).toList().asReversed().forEach { it.destroyForcibly() } }
                                process.toHandle().destroyForcibly()
                                assertTrue(process.waitFor(5, TimeUnit.SECONDS), "bwrap fixture did not terminate")
                            }
                        } finally {
                            reader.shutdownNow()
                        }
                    }
                    val report = LinuxFilesystemSyscalls.openRoot(control.resolve("reports")).use { reports ->
                        assertEquals(listOf(ReferenceCorpusWorker.OBSERVATIONS_FILE), LinuxFilesystemSyscalls.directoryEntryNames(reports, 2))
                        assertNotNull(DescriptorBoundAtomicStateFile.readManifestOrNull(reports, ReferenceCorpusWorker.OBSERVATIONS_FILE,
                            ReferenceCorpusWorker.MAXIMUM_OBSERVATION_BYTES)).bytes
                    }
                    val checked = ReferenceCorpusWorkerObservations.verify(profile.definition, request, report)
                    assertFalse(checked.executionAuthenticated)
                    assertFalse(checked.referenceAuthority)
                    observations += checked.cases
                    batchReceipts += JsonObject(mapOf("batchId" to JsonPrimitive(batch.id), "cases" to JsonPrimitive(checked.cases.size),
                        "reportSha256" to JsonPrimitive(OracleArtifacts.sha256(report)), "capturedOutputBytes" to JsonPrimitive(checked.capturedOutputBytes)))
                }
                val byId = observations.associateBy { it.getValue("id").jsonPrimitive.content }
                assertEquals(profile.definition.cases.map { it.id }.toSet(), byId.keys)
                assertEquals(19, observations.size)
                val ordered = profile.definition.cases.map { byId.getValue(it.id) }
                // Expected bytes exist only in this outer regression. No reference-output file
                // or expected observation is mounted into either native worker namespace.
                val frozenBytes = Files.readAllBytes(profileRoot.resolve("metadata-diagnostic-reference.json"))
                val frozen = OracleJson.parse(frozenBytes).jsonObject.getValue("cases").jsonArray
                    .associateBy { it.jsonObject.getValue("id").jsonPrimitive.content }
                assertEquals(byId.keys, frozen.keys)
                ordered.forEach { case ->
                    val id = case.getValue("id").jsonPrimitive.content
                    val expected = frozen.getValue(id).jsonObject.getValue("observed").jsonObject
                    val converted = JsonObject(expected + mapOf(
                        "stdout" to JsonObject(expected.getValue("stdout").jsonObject - "text"),
                        "stderr" to JsonObject(expected.getValue("stderr").jsonObject - "text"),
                        "artifacts" to JsonArray(expected.getValue("artifacts").jsonArray.map { JsonObject(it.jsonObject - "text") }),
                    ))
                    assertEquals(converted, case.getValue("observed"), "pinned-image worker observation differs for $id")
                }
                val canonical = OracleJson.canonicalBytes(JsonArray(ordered))
                Files.write(root.resolve("canonical-observations.json"), canonical)
                ReferenceNativeRuntime.verify(stage, plan, trustedOwnership = false)
                image.requireCurrent()
                profile.requireCurrent("after pinned-image computation regression")
                val receipt = JsonObject(mapOf(
                    "provider" to JsonPrimitive("reference-worker-pinned-image-computation-test-v1"),
                    "profileSha256" to JsonPrimitive(profile.profileSha256), "runtimeProjectionSha256" to JsonPrimitive(OracleArtifacts.sha256(plan.canonicalBytes)),
                    "frozenReferenceSha256" to JsonPrimitive(OracleArtifacts.sha256(frozenBytes)),
                    "canonicalObservationsSha256" to JsonPrimitive(OracleArtifacts.sha256(canonical)),
                    "caseCount" to JsonPrimitive(ordered.size), "batches" to JsonArray(batchReceipts),
                    "frozenObservationsMatch" to JsonPrimitive(true), "executionAuthenticated" to JsonPrimitive(false),
                    "referenceAuthority" to JsonPrimitive(false), "containmentAuthority" to JsonPrimitive(false), "releaseEligible" to JsonPrimitive(false),
                ))
                Files.write(root.resolve("computation-receipt.json"), OracleJson.canonicalBytes(receipt))
                println("REFERENCE_WORKER_COMPUTATION_EVIDENCE=${root.resolve("computation-receipt.json")}")
            }
        }
    }

    private fun command(
        request: ReferenceCorpusWorkerRequest,
        requestPath: Path,
        nativeMounts: List<Pair<Path, Path>>,
        classPath: List<Path>,
        nativeLibraries: Path,
    ): List<String> {
        val javaRoot = Path.of(System.getProperty("java.home")).toRealPath()
        val javaGuest = Path.of("/decomp-worker-java")
        val runtimeGuest = Path.of("/decomp-worker-runtime")
        val nativeGuest = runtimeGuest.resolve("native")
        val readOnly = nativeMounts + listOf(javaRoot to javaGuest, nativeLibraries to nativeGuest,
            request.profilePath to request.profilePath, requestPath to requestPath) +
            classPath.mapIndexed { index, path -> path to runtimeGuest.resolve("classpath-$index") }
        val writable = request.controlRoot to request.controlRoot
        val parents = (readOnly.map { it.second } + writable.second).flatMap { destination ->
            generateSequence(destination.parent) { it.parent }.filter { it != Path.of("/") }.toList()
        }.distinct().sortedWith(compareBy<Path> { it.nameCount }.thenBy { it.toString() })
        return buildList {
            addAll(listOf("/usr/bin/bwrap", "--die-with-parent", "--unshare-all", "--unshare-user", "--new-session", "--disable-userns", "--tmpfs", "/"))
            parents.forEach { addAll(listOf("--dir", it.toString())) }
            addAll(listOf("--proc", "/proc", "--dev", "/dev"))
            readOnly.forEach { (source, guest) -> addAll(listOf("--ro-bind", source.toString(), guest.toString())) }
            addAll(listOf("--bind", writable.first.toString(), writable.second.toString(), "--remount-ro", "/", "--chdir", request.controlRoot.toString(), "--"))
            add(javaGuest.resolve("bin/java").toString())
            addAll(listOf("-Xms32m", "-Xmx256m", "-XX:+UseSerialGC", "-XX:ActiveProcessorCount=1", "-XX:-UsePerfData", "-XX:+DisableAttachMechanism",
                "-Djava.io.tmpdir=${request.controlRoot.resolve("tmp")}"))
            addAll(OracleNativeLibraries.jvmArguments(nativeGuest))
            addAll(listOf("-classpath", classPath.indices.joinToString(":") { runtimeGuest.resolve("classpath-$it").toString() },
                ReferenceCorpusWorker::class.java.name, requestPath.toString(), OracleArtifacts.sha256(request.canonicalBytes)))
        }
    }

    private fun minimalWorkerClassPath(): List<Path> {
        val types = listOf(ReferenceCorpusWorker::class.java, Unit::class.java, kotlinx.serialization.json.Json::class.java,
            kotlinx.serialization.KSerializer::class.java, com.sun.jna.Native::class.java, org.sqlite.JDBC::class.java,
            org.tukaani.xz.SingleXZInputStream::class.java)
        val sources = types.map { Path.of(checkNotNull(it.protectionDomain.codeSource).location.toURI()).toRealPath() }.toMutableList()
        val resource = checkNotNull(OracleNativeLibraries::class.java.getResource("/oracle-native-libraries-v1.properties"))
        sources.add(when (resource.protocol) {
            "file" -> Path.of(resource.toURI()).parent.toRealPath()
            "jar" -> Path.of((resource.openConnection() as java.net.JarURLConnection).jarFileURL.toURI()).toRealPath()
            else -> error("worker native policy has unsupported resource origin")
        })
        return sources.distinct()
    }

    companion object {
        private val PRIVATE_DIRECTORY = PosixFilePermissions.asFileAttribute(PosixFilePermissions.fromString("rwx------"))
    }
}
