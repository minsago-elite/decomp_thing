package decompengine.oracle.behavior

import java.io.ByteArrayOutputStream
import java.io.InputStream
import java.lang.reflect.Modifier
import java.nio.charset.CodingErrorAction
import java.nio.charset.StandardCharsets
import java.nio.file.Files
import java.nio.file.LinkOption
import java.nio.file.Path
import java.nio.file.StandardOpenOption
import java.nio.file.attribute.PosixFilePermissions
import java.security.MessageDigest
import java.time.Duration
import java.util.Comparator
import java.util.UUID
import java.util.concurrent.Callable
import java.util.concurrent.Executors
import java.util.concurrent.TimeUnit
import java.util.concurrent.atomic.AtomicInteger
import java.util.jar.JarEntry
import java.util.jar.JarFile
import java.util.jar.JarOutputStream
import kotlin.test.Test
import kotlin.test.assertEquals
import kotlin.test.assertFailsWith
import kotlin.test.assertFalse
import kotlin.test.assertNotEquals
import kotlin.test.assertTrue
import org.junit.jupiter.api.Assumptions.assumeTrue
import org.opentest4j.TestAbortedException
import kotlinx.serialization.json.Json
import kotlinx.serialization.json.JsonArray
import kotlinx.serialization.json.JsonNull
import kotlinx.serialization.json.JsonPrimitive

class LlvmBehaviorHostedWorkerImageLiveIntegrationTest {
    @Test
    fun `required live worker-image capability fails instead of silently skipping`() {
        val failure = assertFailsWith<AssertionError> {
            LlvmBehaviorHostedWorkerImageLiveHost.requireCapability(
                available = false,
                message = { "fixture Docker endpoint is unavailable" },
                required = true,
            )
        }

        assertTrue(failure.message.orEmpty().contains("$REQUIRED_ENVIRONMENT=1"))
        assertFailsWith<TestAbortedException> {
            LlvmBehaviorHostedWorkerImageLiveHost.requireCapability(
                available = false,
                message = { "fixture Docker endpoint is unavailable" },
                required = false,
            )
        }
    }

    @Test
    fun `required workflow invokes the actual worker-image retained-tool regression`() {
        val workflow = Files.readString(WORKFLOW)
        val imageIdExport = "LLVM_TOOLCHAIN_IMAGE_ID=\$observed"
        val requiredFlag = "$REQUIRED_ENVIRONMENT: \"1\""
        val selectedTest =
            "--tests decompengine.oracle.behavior.LlvmBehaviorHostedWorkerImageLiveIntegrationTest"

        assertTrue(workflow.contains(imageIdExport))
        assertTrue(workflow.contains(requiredFlag))
        assertTrue(workflow.contains("$DOCKER_EXECUTABLE_ENVIRONMENT: /usr/bin/docker"))
        assertTrue(workflow.contains("$DOCKER_HOST_ENVIRONMENT: unix:///var/run/docker.sock"))
        assertTrue(workflow.contains("$TOOLCHAIN_IMAGE_ENVIRONMENT: \${{ env.LLVM_TOOLCHAIN_IMAGE_ID }}"))
        assertTrue(workflow.contains("$JDK_ROOT_ENVIRONMENT: /var/lib/decomp-llvm-hosted-worker-jdk"))
        assertTrue(workflow.contains("sudo cp --archive --no-preserve=ownership,links"))
        assertFalse(workflow.contains("cp --archive --dereference"))
        assertTrue(workflow.contains("test \"\$cacerts_target\" = /etc/ssl/certs/adoptium/cacerts"))
        assertTrue(workflow.contains("test \"\$(sudo realpath -e -- \"\$cacerts_target\")\" = \"\$cacerts_target\""))
        assertTrue(workflow.contains("sudo mv -T -- \"\$staged_cacerts_temporary\" \"\$staged_cacerts\""))
        assertTrue(workflow.contains("sudo chown -hR root:root \"\$hosted_jdk\""))
        assertTrue(workflow.contains("sudo test -s \"\$staged_cacerts\""))
        assertTrue(workflow.contains("sudo chmod 0755 \"\$hosted_jdk\""))
        assertTrue(workflow.contains(selectedTest))
        assertTrue(workflow.indexOf(imageIdExport) < workflow.indexOf(requiredFlag))
        assertTrue(workflow.indexOf("--no-preserve=ownership,links") < workflow.indexOf(selectedTest))
        assertTrue(workflow.indexOf("sudo chown -hR") < workflow.indexOf("staged_cacerts="))
        assertTrue(workflow.lastIndexOf("sudo chmod 0755") < workflow.indexOf(selectedTest))
        assertFalse(workflow.contains("continue-on-error:"))
    }

    @Test
    fun `live probe remains a zero-argument test-classpath-only overlay`() {
        assertTrue(Files.isRegularFile(TEST_PROBE_SOURCE, LinkOption.NOFOLLOW_LINKS))
        assertFalse(Files.exists(PRODUCTION_PROBE_SOURCE, LinkOption.NOFOLLOW_LINKS))
        assertTrue(Files.isRegularFile(TEST_HOSTILE_CHECK_SOURCE, LinkOption.NOFOLLOW_LINKS))
        assertFalse(Files.exists(PRODUCTION_HOSTILE_CHECK_SOURCE, LinkOption.NOFOLLOW_LINKS))
        val probeCodeSource = LlvmBehaviorHostedWorkerImageLiveProbeMain::class.java.protectionDomain
            .codeSource.location.toURI().let(Path::of).toAbsolutePath().normalize().toRealPath()
        val productionCodeSource = LlvmBehaviorHostedCleanBuildV2InnerWorkerMain::class.java.protectionDomain
            .codeSource.location.toURI().let(Path::of).toAbsolutePath().normalize().toRealPath()
        assertNotEquals(productionCodeSource, probeCodeSource)
        assertTrue(Files.isDirectory(probeCodeSource, LinkOption.NOFOLLOW_LINKS))
        val methods = LlvmBehaviorHostedWorkerImageLiveProbeMain::class.java.declaredMethods
            .filterNot { it.isSynthetic }
        assertEquals(1, methods.size)
        assertEquals("main", methods.single().name)
        assertTrue(Modifier.isPublic(methods.single().modifiers))
        assertTrue(Modifier.isStatic(methods.single().modifiers))
        assertEquals(listOf(Array<String>::class.java), methods.single().parameterTypes.toList())

        val root = Files.createTempDirectory("llvm-hosted-worker-live-probe-contract-")
        try {
            Files.setPosixFilePermissions(root, OWNER_DIRECTORY_PERMISSIONS)
            createProbeJar(root.resolve("probe.jar"))
        } finally {
            deleteTree(root)
        }
    }

    @Test
    fun `temporary base tag plan is unique bounded and never removes the exact base ID`() {
        val exactBaseId = "sha256:${"1".repeat(64)}"
        val plans = List(128) { LiveWorkerImageTemporaryBaseTagPlan.create(exactBaseId) }

        assertEquals(plans.size, plans.map { it.reference }.toSet().size)
        plans.forEach { plan ->
            assertEquals(exactBaseId, plan.exactImageId)
            assertTrue(plan.reference.matches(TEMPORARY_BASE_TAG))
            assertTrue(plan.reference.length <= MAXIMUM_TEMPORARY_BASE_TAG_CHARACTERS)
            assertEquals(listOf("image", "tag", exactBaseId, plan.reference), plan.createArguments)
            assertEquals("--build-arg=TOOLCHAIN_IMAGE=${plan.reference}", plan.buildArgument)
            assertEquals(listOf("image", "rm", plan.reference), plan.removeArguments)
            assertFalse(plan.removeArguments.contains(exactBaseId))
        }
    }

    @Test
    fun `Docker image absence requires an exact missing-image response for the requested reference`() {
        val imageId = "sha256:${"1".repeat(64)}"
        val references = listOf(imageId, LiveWorkerImageTemporaryBaseTagPlan.create(imageId).reference)
        for (reference in references) {
            val missing = "Error response from daemon: No such image: $reference\n".toByteArray()
            for (stdout in listOf(byteArrayOf(), byteArrayOf('\n'.code.toByte()))) {
                assertEquals(null, parseLiveWorkerImageId(reference, LiveDockerCommandResult(1, stdout, missing)))
            }
            assertEquals(
                imageId,
                parseLiveWorkerImageId(
                    reference,
                    LiveDockerCommandResult(0, "$imageId\tlinux\tamd64\t\n".toByteArray(), byteArrayOf()),
                    expectedImageId = imageId,
                ),
            )
            val invalidAbsence = listOf(
                LiveDockerCommandResult(2, byteArrayOf(), missing),
                LiveDockerCommandResult(1, "[]\n".toByteArray(), missing),
                LiveDockerCommandResult(1, "$imageId\n".toByteArray(), missing),
                LiveDockerCommandResult(1, byteArrayOf(), missing + "additional failure\n".toByteArray()),
                LiveDockerCommandResult(1, byteArrayOf(), "Error response from daemon: No such image: another-image\n".toByteArray()),
                LiveDockerCommandResult(1, byteArrayOf(), byteArrayOf()),
            )
            for (result in invalidAbsence) {
                assertFailsWith<IllegalStateException> { parseLiveWorkerImageId(reference, result) }
            }
        }
    }

    @Test
    fun `Docker daemon permission and platform errors never establish image absence`() {
        val imageId = "sha256:${"2".repeat(64)}"
        val errors = listOf(
            "Cannot connect to the Docker daemon at unix:///var/run/docker.sock. Is the docker daemon running?",
            "permission denied while trying to connect to the Docker daemon socket at unix:///var/run/docker.sock",
            "unknown flag: --platform",
            "image inspect platform is only supported with API version 1.49 and newer",
            "Error response from daemon: internal server error",
            "Error response from daemon: No such container: $imageId",
        )
        for (diagnostic in errors) {
            val failure = assertFailsWith<IllegalStateException> {
                parseLiveWorkerImageId(
                    imageId,
                    LiveDockerCommandResult(1, byteArrayOf(), "$diagnostic\n".toByteArray()),
                )
            }
            assertTrue(failure.message.orEmpty().contains(diagnostic))
            assertTrue(failure.message.orEmpty().contains("exit=1"))
            assertTrue(failure.message.orEmpty().contains(imageId))
        }
    }

    @Test
    fun `Docker image inspect rejects malformed success and bounds escaped failure diagnostics`() {
        val imageId = "sha256:${"3".repeat(64)}"
        val validProjection = "$imageId\tlinux\tamd64\t\n"
        val invalidResults = listOf(
            LiveDockerCommandResult(0, byteArrayOf(), byteArrayOf()),
            LiveDockerCommandResult(0, imageId.toByteArray(), byteArrayOf()),
            LiveDockerCommandResult(0, "$imageId\n$imageId\n".toByteArray(), byteArrayOf()),
            LiveDockerCommandResult(0, validProjection.dropLast(1).toByteArray(), byteArrayOf()),
            LiveDockerCommandResult(0, "$validProjection$validProjection".toByteArray(), byteArrayOf()),
            LiveDockerCommandResult(0, byteArrayOf(0xff.toByte()), byteArrayOf()),
            LiveDockerCommandResult(0, validProjection.toByteArray(), "warning\n".toByteArray()),
        )
        for (result in invalidResults) {
            assertFailsWith<IllegalStateException> { parseLiveWorkerImageId(imageId, result) }
        }
        val oversized = ByteArray(MAXIMUM_IMAGE_INSPECT_DIAGNOSTIC_BYTES + 1) { 0x1b } +
            "omitted diagnostic tail".toByteArray()
        val failure = assertFailsWith<IllegalStateException> {
            parseLiveWorkerImageId(imageId, LiveDockerCommandResult(1, oversized, oversized))
        }
        val message = failure.message.orEmpty()
        assertTrue(message.contains("\\x1b"))
        assertTrue(message.contains("[truncated; ${oversized.size} bytes total]"))
        assertFalse(message.contains("omitted diagnostic tail"))
        assertFalse(message.any { it.code < 0x20 || it.code == 0x7f })
        assertTrue(message.length <= MAXIMUM_IMAGE_INSPECT_DIAGNOSTIC_BYTES * 8 + 512)
    }

    @Test
    fun `Docker image lookup binds the exact expected ID and platform in one response`() {
        val imageId = "sha256:${"4".repeat(64)}"
        val wrongId = "sha256:${"5".repeat(64)}"
        val tag = LiveWorkerImageTemporaryBaseTagPlan.create(imageId).reference
        val invalidPlatforms = listOf(
            "$imageId\twindows\tamd64\t\n",
            "$imageId\tlinux\tarm64\t\n",
            "$imageId\tlinux\tamd64\tv3\n",
            "$imageId\tlinux\tamd64\t<no value>\n",
            "$imageId\tlinux\tamd64\tnull\n",
            "$imageId\tlinux\tamd64\n",
            "$imageId\tlinux\tamd64\t\textra\n",
        )
        for (reference in listOf(imageId, tag)) {
            for (output in invalidPlatforms + "$wrongId\tlinux\tamd64\t\n") {
                assertFailsWith<IllegalStateException> {
                    parseLiveWorkerImageId(
                        reference,
                        LiveDockerCommandResult(0, output.toByteArray(), byteArrayOf()),
                        expectedImageId = imageId,
                    )
                }
            }
        }
        assertFailsWith<IllegalStateException> {
            parseLiveWorkerImageId(
                imageId,
                LiveDockerCommandResult(0, "$wrongId\tlinux\tamd64\t\n".toByteArray(), byteArrayOf()),
            )
        }
        for (expectedImageId in listOf(null, wrongId)) {
            assertFailsWith<IllegalStateException> {
                parseLiveWorkerImageId(
                    imageId,
                    LiveDockerCommandResult(0, "$wrongId\tlinux\tamd64\t\n".toByteArray(), byteArrayOf()),
                    expectedImageId,
                )
            }
        }
    }

    @Test
    fun `Docker image lookup uses Docker 28 compatible inspection without platform selection`() {
        val imageId = "sha256:${"6".repeat(64)}"
        assertEquals(
            listOf(
                "image",
                "inspect",
                "--format={{.ID}}\t{{.Os}}\t{{.Architecture}}\t{{if .Variant}}{{.Variant}}{{end}}",
                imageId,
            ),
            liveWorkerImageIdentityInspectArguments(imageId),
        )
        assertFalse(liveWorkerImageIdentityInspectArguments(imageId).any { it.startsWith("--platform") })
    }

    @Test
    fun `live production-staged worker image executes retained clang and direct lld`() {
        val required = System.getenv(REQUIRED_ENVIRONMENT) == "1"
        LlvmBehaviorHostedWorkerImageLiveHost.requireCapability(
            available = required,
            message = {
                "$REQUIRED_ENVIRONMENT=1 and the four DECOMP_LLVM_HOSTED_WORKER_* settings " +
                    "are required for the live Docker regression"
            },
            required = false,
        )
        val configuration = LiveWorkerImageConfiguration.load()
        val root = Files.createTempDirectory("llvm-hosted-worker-image-live-")
            .toAbsolutePath()
            .normalize()
        Files.setPosixFilePermissions(root, OWNER_DIRECTORY_PERMISSIONS)
        val dockerConfig = Files.createDirectory(root.resolve("docker-config"))
        val context = Files.createDirectory(root.resolve("production-context"))
        Files.setPosixFilePermissions(dockerConfig, OWNER_DIRECTORY_PERMISSIONS)
        Files.setPosixFilePermissions(context, OWNER_DIRECTORY_PERMISSIONS)
        val docker = LiveWorkerImageDockerClient(
            configuration.dockerExecutable,
            configuration.dockerHost,
            dockerConfig,
        )

        var imageId: String? = null
        var containerName: String? = null
        var failure: Throwable? = null
        fun cleanup(action: () -> Unit) {
            try {
                action()
            } catch (cleanupFailure: Throwable) {
                val current = failure
                if (current == null) failure = cleanupFailure
                else if (cleanupFailure !== current) current.addSuppressed(cleanupFailure)
            }
        }

        try {
            LlvmBehaviorHostedWorkerImageV1BuildContext.stage(
                WORKER_DOCKERFILE,
                configuration.jdkRoot,
                context,
            ).use { owner ->
                val productionClassPath = requireProductionWorkerArguments(context)
                requireProbeAbsentFromProductionContext(context)
                val tar = root.resolve("production-worker-context.tar")
                Files.newOutputStream(
                    tar,
                    StandardOpenOption.CREATE_NEW,
                    StandardOpenOption.WRITE,
                ).use(owner::writeDeterministicTarTo)
                Files.setPosixFilePermissions(tar, OWNER_READ_ONLY_PERMISSIONS)
                assertEquals(owner.deterministicTarBytes, Files.size(tar))
                assertEquals(owner.deterministicTarSha256, sha256(tar))
                owner.requireCurrent()

                val iidFile = root.resolve("worker-image.id")
                imageId = docker.buildProductionContext(
                    tar = tar,
                    iidFile = iidFile,
                    toolchainImageId = configuration.toolchainImageId,
                )
                docker.removeTemporaryBaseTagAndRequireBasePreserved()
                assertEquals(owner.deterministicTarBytes, Files.size(tar))
                assertEquals(owner.deterministicTarSha256, sha256(tar))
                val retainedImageId = checkNotNull(imageId)
                val inspect = docker.execute(
                    listOf("image", "inspect", retainedImageId),
                    INSPECT_TIMEOUT,
                    MAXIMUM_INSPECT_BYTES,
                )
                val projection = LlvmBehaviorHostedWorkerImageV1Inspect.project(
                    inspect.stdout,
                    retainedImageId,
                )
                assertEquals(retainedImageId, projection.imageId)
                assertEquals("linux/amd64", projection.platform)
                owner.requireCurrent()

                // The image is complete and strictly inspected before either test-only overlay is
                // created. Neither the probe JAR nor these fixture trees can enter its build context.
                val probeJar = createProbeJar(root.resolve("retained-tool-live-probe.jar"))
                val inputs = Files.createDirectory(root.resolve("inputs"))
                val stageOutput = Files.createDirectory(root.resolve("stage-output"))
                Files.setPosixFilePermissions(inputs, OWNER_DIRECTORY_PERMISSIONS)
                Files.setPosixFilePermissions(stageOutput, OWNER_DIRECTORY_PERMISSIONS)
                createCandidate(inputs.resolve("retained-tool-source-one"))
                createCandidate(inputs.resolve("retained-tool-source-two"))

                containerName = "decomp-llvm-worker-live-${UUID.randomUUID()}"
                val live = docker.execute(
                    liveProbeArguments(
                        imageId = retainedImageId,
                        containerName = checkNotNull(containerName),
                        uid = configuration.uid,
                        gid = configuration.gid,
                        inputs = inputs,
                        stageOutput = stageOutput,
                        probeJar = probeJar,
                        productionClassPath = productionClassPath,
                    ),
                    LIVE_PROBE_TIMEOUT,
                    MAXIMUM_PROBE_OUTPUT_BYTES,
                )
                assertTrue(live.stderr.isEmpty(), live.stderr.decodeUtf8())
                assertTrue(RESULT_LINE.matches(live.stdout.decodeUtf8()))
                assertFalse(Files.exists(stageOutput.resolve("candidate-build-script-ran"), LinkOption.NOFOLLOW_LINKS))
                owner.requireCurrent()
            }
        } catch (caught: Throwable) {
            failure = caught
        } finally {
            containerName?.let { name -> cleanup { docker.requireContainerAbsent(name) } }
            (imageId ?: docker.retainedBuiltImageId)?.let { id ->
                cleanup { docker.removeImageAndRequireAbsent(id) }
            }
            cleanup { docker.removeTemporaryBaseTagAndRequireBasePreserved() }
            cleanup { deleteTree(root) }
        }
        failure?.let { throw it }
    }

    private fun requireProductionWorkerArguments(context: Path): String {
        val text = Files.readString(context.resolve("app/worker.args"), StandardCharsets.US_ASCII)
        val lines = text.split('\n')
        check(lines.size == 6 && lines.last().isEmpty()) {
            "production worker arguments do not have the exact five-line shape"
        }
        check(lines[0] == "-Djna.nosys=true")
        check(lines[1] == "-Djna.tmpdir=/decomp-jna")
        check(lines[2] == "-cp")
        check(lines[3].matches(PRODUCTION_CLASS_PATH))
        check(lines[4] == "decompengine.oracle.behavior.LlvmBehaviorHostedCleanBuildV2InnerWorkerMain")
        return lines[3]
    }

    private fun requireProbeAbsentFromProductionContext(context: Path) {
        val applicationRoot = context.resolve("app/lib")
        val jars = Files.newDirectoryStream(applicationRoot, "*.jar").use { stream ->
            stream.toList().sortedBy(Path::toString)
        }
        check(jars.isNotEmpty()) { "production worker context has no application JARs" }
        jars.forEach { jar ->
            JarFile(jar.toFile(), false).use { opened ->
                check(TEST_OVERLAY_CLASS_ENTRIES.all { entry -> opened.getJarEntry(entry) == null }) {
                    "test-only retained-tool probe leaked into production application closure"
                }
            }
        }
    }

    private fun createProbeJar(output: Path): Path {
        val codeSource = LlvmBehaviorHostedWorkerImageLiveProbeMain::class.java.protectionDomain
            .codeSource.location.toURI().let(Path::of).toAbsolutePath().normalize().toRealPath()
        check(Files.isDirectory(codeSource, LinkOption.NOFOLLOW_LINKS)) {
            "live probe is not loaded from the Gradle test-classes directory"
        }
        val packageRoot = codeSource.resolve(PROBE_CLASS_ENTRY).parent
        val classes = TEST_OVERLAY_CLASS_ENTRIES.flatMap { entry ->
            val className = Path.of(entry).fileName.toString()
            val classPrefix = className.removeSuffix(".class")
            Files.newDirectoryStream(packageRoot, "$classPrefix*.class").use { stream ->
                stream.toList().also { selected ->
                    check(selected.any { it.fileName.toString() == className }) {
                        "test-only retained-tool overlay class bytes are unavailable: $entry"
                    }
                }
            }
        }
            .sortedBy { it.fileName.toString() }
        JarOutputStream(
            Files.newOutputStream(output, StandardOpenOption.CREATE_NEW, StandardOpenOption.WRITE),
        ).use { jar ->
            classes.forEach { source ->
                val entryName = "decompengine/oracle/behavior/${source.fileName}"
                jar.putNextEntry(JarEntry(entryName).apply { time = 0L })
                Files.newInputStream(source).use { input -> input.copyTo(jar) }
                jar.closeEntry()
            }
        }
        Files.setPosixFilePermissions(output, OWNER_READ_ONLY_PERMISSIONS)
        JarFile(output.toFile(), false).use { jar ->
            val entries = jar.entries().asSequence().map(JarEntry::getName).toList()
            check(entries.isNotEmpty() && entries.all { entry ->
                TEST_OVERLAY_CLASS_ENTRIES.any { allowed ->
                    entry == allowed ||
                        entry.startsWith(allowed.removeSuffix(".class") + "$") && entry.endsWith(".class")
                }
            }) { "test-only retained-tool probe JAR contains an unrelated class" }
            check(TEST_OVERLAY_CLASS_ENTRIES.all(entries::contains)) {
                "test-only retained-tool overlay omitted a required regression class"
            }
        }
        return output
    }

    private fun createCandidate(root: Path) {
        Files.createDirectory(root)
        Files.createDirectory(root.resolve("src"))
        Files.createDirectory(root.resolve("include"))
        Files.createDirectory(root.resolve("reports"))
        Files.writeString(
            root.resolve("Makefile"),
            "all:\n\t/usr/bin/touch /stage-output/candidate-build-script-ran\n",
        )
        Files.writeString(root.resolve("include/value.h"), "int value(void);\n")
        Files.writeString(
            root.resolve("src/value.c"),
            "#include \"value.h\"\nint value(void) { return 17; }\n",
        )
        Files.writeString(
            root.resolve("src/main.c"),
            "#include <stdio.h>\n#include \"value.h\"\n" +
                "int main(void) { if (value() != 17) return 1; return puts(\"hosted-ok\") < 0; }\n",
        )
        Files.writeString(
            root.resolve("reports/build_contract.json"),
            "{\"command\":[\"/bin/sh\",\"-c\",\"touch /stage-output/candidate-build-script-ran\"]}\n",
        )
        Files.walk(root).use { paths ->
            paths.sorted(Comparator.reverseOrder()).forEach { path ->
                Files.setPosixFilePermissions(
                    path,
                    if (Files.isDirectory(path, LinkOption.NOFOLLOW_LINKS)) {
                        OWNER_DIRECTORY_PERMISSIONS
                    } else {
                        OWNER_READ_ONLY_PERMISSIONS
                    },
                )
            }
        }
    }

    private fun liveProbeArguments(
        imageId: String,
        containerName: String,
        uid: Int,
        gid: Int,
        inputs: Path,
        stageOutput: Path,
        probeJar: Path,
        productionClassPath: String,
    ): List<String> = listOf(
        "container",
        "run",
        "--rm",
        "--pull=never",
        "--platform=linux/amd64",
        "--name=$containerName",
        "--hostname=llvm-hosted-build",
        "--user=$uid:$gid",
        "--workdir=/",
        "--env=LC_ALL=C",
        "--env=PATH=/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin",
        "--env=SOURCE_DATE_EPOCH=1779182222",
        "--env=TZ=UTC",
        "--network=none",
        "--ipc=private",
        "--cgroupns=private",
        "--read-only",
        "--cap-drop=ALL",
        "--security-opt=no-new-privileges",
        "--security-opt=seccomp=builtin",
        "--runtime=runc",
        "--init=false",
        "--restart=no",
        "--log-driver=none",
        "--oom-score-adj=0",
        "--memory=4294967296",
        "--memory-swap=4294967296",
        "--pids-limit=512",
        "--cpu-period=100000",
        "--cpu-quota=200000",
        "--shm-size=67108864",
        "--ulimit=core=0:0",
        "--ulimit=fsize=2147483648:2147483648",
        "--ulimit=nofile=1024:1024",
        "--mount=type=bind,source=$inputs,target=/inputs,readonly,bind-propagation=rprivate",
        "--mount=type=bind,source=$stageOutput,target=/stage-output,bind-propagation=rprivate",
        "--tmpfs=/work:rw,nosuid,nodev,exec,size=17179869184,nr_inodes=1000000,mode=0700,uid=$uid,gid=$gid",
        "--tmpfs=/tmp:rw,nosuid,nodev,noexec,size=268435456,nr_inodes=4096,mode=1777",
        "--tmpfs=/decomp-jna:rw,nosuid,nodev,exec,size=16777216,nr_inodes=128,mode=0700,uid=$uid,gid=$gid",
        "--mount=type=bind,source=$probeJar,target=/decomp-live-retained-tool-probe.jar," +
            "readonly,bind-propagation=rprivate",
        "--entrypoint=/decomp-jdk/bin/java",
        imageId,
        "-Djna.nosys=true",
        "-Djna.tmpdir=/decomp-jna",
        "-cp",
        "/decomp-live-retained-tool-probe.jar:$productionClassPath",
        "decompengine.oracle.behavior.LlvmBehaviorHostedWorkerImageLiveProbeMain",
    )

    private fun sha256(path: Path): String {
        val digest = MessageDigest.getInstance("SHA-256")
        Files.newInputStream(path).use { input ->
            val buffer = ByteArray(64 * 1024)
            while (true) {
                val count = input.read(buffer)
                if (count < 0) break
                if (count > 0) digest.update(buffer, 0, count)
            }
        }
        return digest.digest().joinToString("") { byte ->
            (byte.toInt() and 0xff).toString(16).padStart(2, '0')
        }
    }

    private fun deleteTree(root: Path) {
        if (!Files.exists(root, LinkOption.NOFOLLOW_LINKS)) return
        Files.walk(root).use { paths ->
            paths.sorted(Comparator.reverseOrder()).forEach(Files::deleteIfExists)
        }
    }

    private companion object {
        val WORKER_DOCKERFILE: Path =
            Path.of("oracle/llvm/22.1.6/hosted-clean-build-v2-worker.Dockerfile")
        val WORKFLOW: Path = Path.of(".github/workflows/llvm-oracle-model.yml")
        val TEST_PROBE_SOURCE: Path = Path.of(
            "src/test/kotlin/decompengine/oracle/behavior/LlvmBehaviorHostedWorkerImageLiveProbeMain.kt",
        )
        val PRODUCTION_PROBE_SOURCE: Path = Path.of(
            "src/main/kotlin/decompengine/oracle/behavior/LlvmBehaviorHostedWorkerImageLiveProbeMain.kt",
        )
        val TEST_HOSTILE_CHECK_SOURCE: Path = Path.of(
            "src/test/kotlin/decompengine/oracle/behavior/LlvmBehaviorHostedRetainedToolChecks.kt",
        )
        val PRODUCTION_HOSTILE_CHECK_SOURCE: Path = Path.of(
            "src/main/kotlin/decompengine/oracle/behavior/LlvmBehaviorHostedRetainedToolChecks.kt",
        )
        val OWNER_DIRECTORY_PERMISSIONS = PosixFilePermissions.fromString("rwx------")
        val OWNER_READ_ONLY_PERMISSIONS = PosixFilePermissions.fromString("r--------")
        const val PROBE_CLASS_ENTRY =
            "decompengine/oracle/behavior/LlvmBehaviorHostedWorkerImageLiveProbeMain.class"
        val TEST_OVERLAY_CLASS_ENTRIES = listOf(
            PROBE_CLASS_ENTRY,
            "decompengine/oracle/behavior/LlvmBehaviorHostedRetainedToolChecks.class",
        )
        val PRODUCTION_CLASS_PATH =
            Regex("/decomp-app/lib/[A-Za-z0-9._-]+\\.jar(?::/decomp-app/lib/[A-Za-z0-9._-]+\\.jar)*")
        val RESULT_LINE =
            Regex(
                "DECOMP_LLVM_HOSTED_WORKER_RETAINED_TOOL_TEST_V2 [0-9a-f]{64} [1-9][0-9]* " +
                    "swaps=5 outside-header=blocked\\n",
            )
        val INSPECT_TIMEOUT: Duration = Duration.ofSeconds(30)
        val LIVE_PROBE_TIMEOUT: Duration = Duration.ofMinutes(3)
        const val MAXIMUM_INSPECT_BYTES = 4 * 1024 * 1024
        const val MAXIMUM_PROBE_OUTPUT_BYTES = 1024 * 1024
    }
}

private object LlvmBehaviorHostedWorkerImageLiveHost {
    fun requireCapability(
        available: Boolean,
        message: () -> String,
        required: Boolean = System.getenv(REQUIRED_ENVIRONMENT) == "1",
    ) {
        if (available) return
        val detail = message()
        if (required) throw AssertionError("$REQUIRED_ENVIRONMENT=1 but $detail")
        assumeTrue(false, detail)
    }
}

private data class LiveWorkerImageConfiguration(
    val dockerExecutable: Path,
    val dockerHost: String,
    val toolchainImageId: String,
    val jdkRoot: Path,
    val uid: Int,
    val gid: Int,
) {
    companion object {
        fun load(): LiveWorkerImageConfiguration {
            val dockerExecutable = requireCanonicalPath(
                requireEnvironment(DOCKER_EXECUTABLE_ENVIRONMENT),
                DOCKER_EXECUTABLE_ENVIRONMENT,
                directory = false,
            )
            check(Files.isExecutable(dockerExecutable)) {
                "$DOCKER_EXECUTABLE_ENVIRONMENT is not executable"
            }
            val dockerHost = requireEnvironment(DOCKER_HOST_ENVIRONMENT)
            check(dockerHost.startsWith("unix://")) { "$DOCKER_HOST_ENVIRONMENT must select a Unix socket" }
            val socketPath = Path.of(dockerHost.removePrefix("unix://"))
            check(socketPath.isAbsolute && socketPath.normalize() == socketPath) {
                "$DOCKER_HOST_ENVIRONMENT must contain an absolute normalized Unix-socket path"
            }
            check(Files.exists(socketPath, LinkOption.NOFOLLOW_LINKS)) {
                "$DOCKER_HOST_ENVIRONMENT socket is unavailable"
            }
            val toolchainImageId = requireEnvironment(TOOLCHAIN_IMAGE_ENVIRONMENT)
            check(toolchainImageId.matches(IMAGE_ID)) {
                "$TOOLCHAIN_IMAGE_ENVIRONMENT must be one exact sha256 image ID"
            }
            val jdkRoot = requireCanonicalPath(
                requireEnvironment(JDK_ROOT_ENVIRONMENT),
                JDK_ROOT_ENVIRONMENT,
                directory = true,
            )
            val uid = (Files.getAttribute(Path.of("/proc/self"), "unix:uid") as Number).toInt()
            val gid = (Files.getAttribute(Path.of("/proc/self"), "unix:gid") as Number).toInt()
            check(uid > 0 && gid > 0) { "live worker-image regression requires a non-root UID and GID" }
            return LiveWorkerImageConfiguration(
                dockerExecutable,
                dockerHost,
                toolchainImageId,
                jdkRoot,
                uid,
                gid,
            )
        }

        private fun requireCanonicalPath(raw: String, label: String, directory: Boolean): Path {
            val path = Path.of(raw)
            check(path.isAbsolute && path.normalize() == path) { "$label must be an absolute normalized path" }
            val real = path.toRealPath()
            check(real == path && !Files.isSymbolicLink(path)) { "$label must be a canonical non-symlink path" }
            check(
                if (directory) Files.isDirectory(path, LinkOption.NOFOLLOW_LINKS)
                else Files.isRegularFile(path, LinkOption.NOFOLLOW_LINKS),
            ) { "$label has the wrong file type" }
            return path
        }
    }
}

private class LiveWorkerImageTemporaryBaseTagPlan private constructor(
    val exactImageId: String,
    val reference: String,
) {
    val createArguments: List<String> = listOf("image", "tag", exactImageId, reference)
    val buildArgument: String = "--build-arg=TOOLCHAIN_IMAGE=$reference"
    val removeArguments: List<String> = listOf("image", "rm", reference)

    companion object {
        fun create(exactImageId: String): LiveWorkerImageTemporaryBaseTagPlan {
            require(exactImageId.matches(IMAGE_ID))
            val reference = "$TEMPORARY_BASE_TAG_REPOSITORY:${UUID.randomUUID()}"
            require(reference.length <= MAXIMUM_TEMPORARY_BASE_TAG_CHARACTERS)
            require(reference.matches(TEMPORARY_BASE_TAG))
            return LiveWorkerImageTemporaryBaseTagPlan(exactImageId, reference)
        }
    }
}

private class LiveWorkerImageDockerClient(
    private val executable: Path,
    private val host: String,
    private val configurationRoot: Path,
) {
    var retainedBuiltImageId: String? = null
        private set
    private var temporaryBaseTagPlan: LiveWorkerImageTemporaryBaseTagPlan? = null
    private var protectedBaseImageId: String? = null
    private var protectedBaseTags: Set<String>? = null

    fun buildProductionContext(tar: Path, iidFile: Path, toolchainImageId: String): String {
        check(temporaryBaseTagPlan == null) { "a temporary worker-image base tag is already armed" }
        check(protectedBaseImageId == null || protectedBaseImageId == toolchainImageId) {
            "worker-image Docker client cannot change its protected base image"
        }
        requireImageReferenceResolves(toolchainImageId, toolchainImageId, "exact toolchain image ID")
        val initialBaseTags = inspectRepositoryTags(toolchainImageId)
        check(initialBaseTags.isNotEmpty()) {
            "exact toolchain image lacks a pre-existing tag that can preserve it"
        }
        val baseTag = LiveWorkerImageTemporaryBaseTagPlan.create(toolchainImageId)
        requireTagAbsent(baseTag.reference, "temporary base tag preflight")
        check(baseTag.reference !in initialBaseTags)
        protectedBaseImageId = toolchainImageId
        protectedBaseTags = initialBaseTags
        // Arm before the mutation: a client timeout after the daemon tags the image must still
        // drive tag-only cleanup through the retained, collision-checked reference.
        temporaryBaseTagPlan = baseTag
        execute(
            baseTag.createArguments,
            CLEANUP_TIMEOUT,
            MAXIMUM_CLEANUP_OUTPUT_BYTES,
        )
        requireImageReferenceResolves(
            baseTag.reference,
            toolchainImageId,
            "temporary base tag before derived build",
        )
        try {
            execute(
                listOf(
                    "build",
                    "--network=none",
                    "--pull=false",
                    "--no-cache",
                    "--platform=linux/amd64",
                    "--file=Dockerfile",
                    baseTag.buildArgument,
                    "--iidfile=$iidFile",
                    "--quiet",
                    "-",
                ),
                BUILD_TIMEOUT,
                MAXIMUM_BUILD_OUTPUT_BYTES,
                standardInput = tar,
            )
        } catch (failure: Throwable) {
            retainDerivedIidFileIfValid(iidFile, toolchainImageId)
            throw failure
        }
        try {
            requireImageReferenceResolves(
                baseTag.reference,
                toolchainImageId,
                "temporary base tag after derived build",
            )
        } catch (failure: Throwable) {
            retainDerivedIidFileIfValid(iidFile, toolchainImageId)
            throw failure
        }
        val imageId = retainDerivedIidFileIfValid(iidFile, toolchainImageId)
            ?: throw IllegalStateException("Docker build did not write its derived image ID")
        return imageId
    }

    private fun retainDerivedIidFileIfValid(iidFile: Path, baseImageId: String): String? {
        if (!Files.isRegularFile(iidFile, LinkOption.NOFOLLOW_LINKS)) return null
        val size = Files.size(iidFile)
        if (size !in IMAGE_ID_TEXT_MINIMUM_BYTES..IMAGE_ID_TEXT_MAXIMUM_BYTES) return null
        val candidate = try {
            Files.newInputStream(iidFile).use { input ->
                val bytes = input.readNBytes(IMAGE_ID_TEXT_MAXIMUM_BYTES + 1)
                if (bytes.size.toLong() != size || bytes.size > IMAGE_ID_TEXT_MAXIMUM_BYTES) return null
                bytes.decodeUtf8().trimEnd('\n')
            }
        } catch (_: Throwable) {
            return null
        }
        if (!candidate.matches(IMAGE_ID) || candidate == baseImageId) return null
        retainedBuiltImageId = candidate
        return candidate
    }

    fun removeTemporaryBaseTagAndRequireBasePreserved() {
        val plan = temporaryBaseTagPlan ?: return
        val originalTags = checkNotNull(protectedBaseTags)
        repeat(TEMPORARY_TAG_ABSENCE_CHECKS) { attempt ->
            val observed = inspectImageIdOrNull(plan.reference)
            if (observed != null) {
                check(observed == plan.exactImageId) {
                    "temporary base tag changed identity; refusing to remove an unowned tag"
                }
                val preRemovalTags = inspectRepositoryTags(plan.exactImageId)
                check(preRemovalTags.containsAll(originalTags) && plan.reference in preRemovalTags) {
                    "prebuilt toolchain tags changed before temporary-tag cleanup"
                }
                val removal = execute(
                    plan.removeArguments,
                    CLEANUP_TIMEOUT,
                    MAXIMUM_CLEANUP_OUTPUT_BYTES,
                    requireSuccess = false,
                )
                check(removal.exitCode == 0) {
                    "cannot remove temporary worker-image base tag: ${removal.stderr.decodeUtf8()}"
                }
            }
            requireTagAbsent(plan.reference, "temporary base tag cleanup")
            requireImageReferenceResolves(
                plan.exactImageId,
                plan.exactImageId,
                "exact toolchain image ID after temporary-tag cleanup",
            )
            val terminalTags = inspectRepositoryTags(plan.exactImageId)
            check(terminalTags.containsAll(originalTags) && plan.reference !in terminalTags) {
                "temporary base-tag cleanup changed the prebuilt toolchain image tags"
            }
            if (attempt + 1 < TEMPORARY_TAG_ABSENCE_CHECKS) {
                Thread.sleep(TEMPORARY_TAG_ABSENCE_RECHECK_MILLIS)
            }
        }
        temporaryBaseTagPlan = null
    }

    private fun requireImageReferenceResolves(reference: String, expectedImageId: String, label: String) {
        val observed = inspectImageIdOrNull(reference, expectedImageId)
            ?: throw IllegalStateException("$label is unavailable")
        check(observed == expectedImageId) { "$label resolved to a different image ID" }
    }

    private fun inspectImageIdOrNull(
        reference: String,
        expectedImageId: String? = reference.takeIf { it.matches(IMAGE_ID) },
    ): String? {
        val result = execute(
            liveWorkerImageIdentityInspectArguments(reference),
            CLEANUP_TIMEOUT,
            MAXIMUM_CLEANUP_OUTPUT_BYTES,
            requireSuccess = false,
        )
        return parseLiveWorkerImageId(reference, result, expectedImageId)
    }

    private fun requireTagAbsent(reference: String, label: String) {
        check(inspectImageIdOrNull(reference) == null) { "$label found a colliding image tag" }
        val inventory = execute(
            listOf(
                "image",
                "ls",
                "--all",
                "--no-trunc",
                "--filter=reference=$reference",
                "--format={{.Repository}}:{{.Tag}}",
            ),
            CLEANUP_TIMEOUT,
            MAXIMUM_CLEANUP_OUTPUT_BYTES,
        )
        check(inventory.stdout.isEmpty() && inventory.stderr.isEmpty()) {
            "$label did not prove the temporary tag absent"
        }
    }

    private fun inspectRepositoryTags(reference: String): Set<String> {
        val result = execute(
            listOf(
                "image",
                "inspect",
                "--format={{json .RepoTags}}",
                reference,
            ),
            CLEANUP_TIMEOUT,
            MAXIMUM_CLEANUP_OUTPUT_BYTES,
        )
        check(result.stderr.isEmpty()) { "Docker repository-tag inspect emitted diagnostics" }
        val text = result.stdout.decodeUtf8()
        check(text.endsWith('\n') && '\n' !in text.dropLast(1)) {
            "Docker repository-tag inspect output is malformed"
        }
        val element = Json.parseToJsonElement(text.dropLast(1))
        if (element === JsonNull) return emptySet()
        val array = element as? JsonArray
            ?: throw IllegalStateException("Docker repository-tag inspect did not return an array")
        check(array.size <= MAXIMUM_REPOSITORY_TAGS) { "Docker image has excessive repository tags" }
        val tags = array.map { value ->
            val primitive = value as? JsonPrimitive
                ?: throw IllegalStateException("Docker repository-tag inspect contains a non-string")
            check(primitive.isString && primitive.content.length in 1..MAXIMUM_REPOSITORY_TAG_CHARACTERS &&
                primitive.content.matches(REPOSITORY_TAG)
            ) { "Docker repository-tag inspect contains an invalid tag" }
            primitive.content
        }
        check(tags.size == tags.toSet().size) { "Docker repository-tag inspect contains duplicates" }
        return tags.toSet()
    }

    fun requireContainerAbsent(name: String) {
        var absent = false
        repeat(CONTAINER_ABSENCE_CHECKS) { attempt ->
            execute(
                listOf("container", "rm", "--force", "--volumes", name),
                CLEANUP_TIMEOUT,
                MAXIMUM_CLEANUP_OUTPUT_BYTES,
                requireSuccess = false,
            )
            val inspect = execute(
                listOf("container", "inspect", name),
                CLEANUP_TIMEOUT,
                MAXIMUM_CLEANUP_OUTPUT_BYTES,
                requireSuccess = false,
            )
            absent = inspect.exitCode != 0
            if (attempt + 1 < CONTAINER_ABSENCE_CHECKS) {
                Thread.sleep(CONTAINER_ABSENCE_RECHECK_MILLIS)
            }
        }
        check(absent) { "live regression container survived exact-name cleanup: $name" }
    }

    fun removeImageAndRequireAbsent(imageId: String) {
        check(imageId != protectedBaseImageId) {
            "refusing to remove the protected prebuilt toolchain image as a derived image"
        }
        val removal = execute(
            listOf("image", "rm", "--force", imageId),
            CLEANUP_TIMEOUT,
            MAXIMUM_CLEANUP_OUTPUT_BYTES,
            requireSuccess = false,
        )
        check(removal.exitCode == 0) {
            "cannot remove live regression worker image $imageId: ${removal.stderr.decodeUtf8()}"
        }
        check(inspectImageIdOrNull(imageId) == null) {
            "live regression worker image survived exact-ID cleanup: $imageId"
        }
        protectedBaseImageId?.let { baseImageId ->
            requireImageReferenceResolves(
                baseImageId,
                baseImageId,
                "exact toolchain image ID after derived-image cleanup",
            )
        }
    }

    fun execute(
        arguments: List<String>,
        timeout: Duration,
        maximumOutputBytes: Int,
        standardInput: Path? = null,
        requireSuccess: Boolean = true,
    ): LiveDockerCommandResult {
        require(arguments.isNotEmpty() && arguments.none { it.isEmpty() || '\u0000' in it })
        require(!timeout.isZero && !timeout.isNegative)
        require(maximumOutputBytes > 0)
        val command = listOf(
            executable.toString(),
            "--config=${configurationRoot}",
            "--host=$host",
        ) + arguments
        val builder = ProcessBuilder(command).also { processBuilder ->
            processBuilder.environment().clear()
            processBuilder.environment()["DOCKER_BUILDKIT"] = "1"
            if (standardInput != null) processBuilder.redirectInput(standardInput.toFile())
        }
        val process = builder.start()
        if (standardInput == null) process.outputStream.close()
        val sequence = AtomicInteger()
        val executor = Executors.newFixedThreadPool(2) { task ->
            Thread(task, "llvm-worker-image-live-docker-${sequence.incrementAndGet()}").apply {
                isDaemon = true
            }
        }
        val stdout = executor.submit(Callable {
            process.inputStream.readBounded(maximumOutputBytes) { process.destroyForcibly() }
        })
        val stderr = executor.submit(Callable {
            process.errorStream.readBounded(maximumOutputBytes) { process.destroyForcibly() }
        })
        try {
            if (!process.waitFor(timeout.toMillis(), TimeUnit.MILLISECONDS)) {
                process.destroyForcibly()
                process.waitFor(5, TimeUnit.SECONDS)
                throw AssertionError("Docker test command timed out: ${arguments.take(2).joinToString(" ")}")
            }
            val outputBytes = try {
                stdout.get(5, TimeUnit.SECONDS)
            } catch (caught: Throwable) {
                throw AssertionError("Docker test stdout capture failed", caught)
            }
            val diagnosticBytes = try {
                stderr.get(5, TimeUnit.SECONDS)
            } catch (caught: Throwable) {
                throw AssertionError("Docker test stderr capture failed", caught)
            }
            val result = LiveDockerCommandResult(process.exitValue(), outputBytes, diagnosticBytes)
            if (requireSuccess && result.exitCode != 0) {
                throw AssertionError(
                    "Docker test command exited ${result.exitCode}: ${result.stderr.decodeUtf8()}",
                )
            }
            return result
        } finally {
            if (process.isAlive) {
                process.destroyForcibly()
                process.waitFor(5, TimeUnit.SECONDS)
            }
            process.inputStream.close()
            process.errorStream.close()
            stdout.cancel(true)
            stderr.cancel(true)
            executor.shutdownNow()
            executor.awaitTermination(5, TimeUnit.SECONDS)
        }
    }

    private companion object {
        val BUILD_TIMEOUT: Duration = Duration.ofMinutes(10)
        val CLEANUP_TIMEOUT: Duration = Duration.ofSeconds(30)
        const val CONTAINER_ABSENCE_CHECKS = 3
        const val CONTAINER_ABSENCE_RECHECK_MILLIS = 250L
        const val TEMPORARY_TAG_ABSENCE_CHECKS = 3
        const val TEMPORARY_TAG_ABSENCE_RECHECK_MILLIS = 250L
        const val MAXIMUM_BUILD_OUTPUT_BYTES = 2 * 1024 * 1024
        const val MAXIMUM_CLEANUP_OUTPUT_BYTES = 1024 * 1024
    }
}

private data class LiveDockerCommandResult(
    val exitCode: Int,
    val stdout: ByteArray,
    val stderr: ByteArray,
)

private fun liveWorkerImageIdentityInspectArguments(reference: String): List<String> {
    require(reference.matches(IMAGE_ID) || reference.matches(TEMPORARY_BASE_TAG))
    return listOf(
        "image",
        "inspect",
        "--format={{.ID}}\t{{.Os}}\t{{.Architecture}}\t{{if .Variant}}{{.Variant}}{{end}}",
        reference,
    )
}

private fun parseLiveWorkerImageId(
    reference: String,
    result: LiveDockerCommandResult,
    expectedImageId: String? = reference.takeIf { it.matches(IMAGE_ID) },
): String? {
    require(reference.matches(IMAGE_ID) || reference.matches(TEMPORARY_BASE_TAG))
    require(expectedImageId == null || expectedImageId.matches(IMAGE_ID))
    fun reject(reason: String): Nothing = throw IllegalStateException(
        "Docker image inspect for $reference $reason; exit=${result.exitCode}; " +
            "stdout=${result.stdout.imageInspectDiagnostic()}; stderr=${result.stderr.imageInspectDiagnostic()}",
    )
    if (result.exitCode != 0) {
        val missingImage = "Error response from daemon: No such image: $reference\n".toByteArray(StandardCharsets.UTF_8)
        val emptyTemplateOutput = result.stdout.isEmpty() ||
            result.stdout.contentEquals(byteArrayOf('\n'.code.toByte()))
        if (result.exitCode == 1 && emptyTemplateOutput && result.stderr.contentEquals(missingImage)) return null
        reject("did not establish presence or absence")
    }
    if (result.stderr.isNotEmpty()) reject("emitted diagnostics on success")
    val text = try {
        result.stdout.decodeUtf8()
    } catch (_: Exception) {
        reject("returned invalid UTF-8")
    }
    val projection = IMAGE_IDENTITY_LINE.matchEntire(text)
        ?: reject("returned a malformed image identity or unsupported platform")
    val observedImageId = projection.groupValues[1]
    if (reference.matches(IMAGE_ID) && observedImageId != reference) {
        reject("did not repeat the requested exact image ID")
    }
    if (expectedImageId != null && observedImageId != expectedImageId) {
        reject("resolved to an unexpected image ID")
    }
    return observedImageId
}

private fun ByteArray.imageInspectDiagnostic(): String = buildString {
    append('"')
    for (index in 0 until minOf(size, MAXIMUM_IMAGE_INSPECT_DIAGNOSTIC_BYTES)) {
        val value = this@imageInspectDiagnostic[index].toInt() and 0xff
        when (value) {
            '\\'.code -> append("\\\\")
            '"'.code -> append("\\\"")
            '\n'.code -> append("\\n")
            '\r'.code -> append("\\r")
            '\t'.code -> append("\\t")
            in 0x20..0x7e -> append(value.toChar())
            else -> append("\\x").append(value.toString(16).padStart(2, '0'))
        }
    }
    append('"')
    if (size > MAXIMUM_IMAGE_INSPECT_DIAGNOSTIC_BYTES) append("[truncated; $size bytes total]")
}

private fun InputStream.readBounded(maximumBytes: Int, overflow: () -> Unit): ByteArray {
    val output = ByteArrayOutputStream(minOf(maximumBytes, 64 * 1024))
    val buffer = ByteArray(8192)
    while (true) {
        val count = read(buffer)
        if (count < 0) return output.toByteArray()
        if (count == 0) continue
        if (output.size() > maximumBytes - count) {
            overflow()
            throw IllegalStateException("Docker test output exceeded $maximumBytes bytes")
        }
        output.write(buffer, 0, count)
    }
}

private fun ByteArray.decodeUtf8(): String =
    StandardCharsets.UTF_8.newDecoder()
        .onMalformedInput(CodingErrorAction.REPORT)
        .onUnmappableCharacter(CodingErrorAction.REPORT)
        .decode(java.nio.ByteBuffer.wrap(this))
        .toString()

private fun requireEnvironment(name: String): String =
    System.getenv(name)?.takeIf(String::isNotBlank)
        ?: throw AssertionError("$REQUIRED_ENVIRONMENT=1 but $name is unset")

private const val REQUIRED_ENVIRONMENT = "DECOMP_REQUIRE_LLVM_HOSTED_WORKER_IMAGE"
private const val DOCKER_EXECUTABLE_ENVIRONMENT = "DECOMP_LLVM_HOSTED_WORKER_DOCKER"
private const val DOCKER_HOST_ENVIRONMENT = "DECOMP_LLVM_HOSTED_WORKER_DOCKER_HOST"
private const val TOOLCHAIN_IMAGE_ENVIRONMENT = "DECOMP_LLVM_HOSTED_WORKER_TOOLCHAIN_IMAGE"
private const val JDK_ROOT_ENVIRONMENT = "DECOMP_LLVM_HOSTED_WORKER_JDK_ROOT"
private const val TEMPORARY_BASE_TAG_REPOSITORY = "decomp-llvm-hosted-worker-live-base"
private const val MAXIMUM_TEMPORARY_BASE_TAG_CHARACTERS = 128
private const val MAXIMUM_REPOSITORY_TAGS = 128
private const val MAXIMUM_REPOSITORY_TAG_CHARACTERS = 512
private const val IMAGE_ID_TEXT_MINIMUM_BYTES = 71L
private const val IMAGE_ID_TEXT_MAXIMUM_BYTES = 72
private const val MAXIMUM_IMAGE_INSPECT_DIAGNOSTIC_BYTES = 4096
private val IMAGE_ID = Regex("sha256:[0-9a-f]{64}")
private val IMAGE_IDENTITY_LINE = Regex("(sha256:[0-9a-f]{64})\\tlinux\\tamd64\\t\\n")
private val TEMPORARY_BASE_TAG = Regex(
    "$TEMPORARY_BASE_TAG_REPOSITORY:[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-" +
        "[0-9a-f]{4}-[0-9a-f]{12}",
)
private val REPOSITORY_TAG = Regex(
    "[a-z0-9]+(?:[._-][a-z0-9]+)*(?:/[a-z0-9]+(?:[._-][a-z0-9]+)*)*:" +
        "[A-Za-z0-9_][A-Za-z0-9_.-]{0,127}",
)
