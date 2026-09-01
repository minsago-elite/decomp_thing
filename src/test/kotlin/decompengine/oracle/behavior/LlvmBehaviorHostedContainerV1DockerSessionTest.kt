package decompengine.oracle.behavior

import decompengine.oracle.core.OracleArtifacts
import java.net.StandardProtocolFamily
import java.net.UnixDomainSocketAddress
import java.nio.channels.ServerSocketChannel
import java.nio.file.Files
import java.nio.file.Path
import java.nio.file.attribute.PosixFilePermission
import java.nio.file.attribute.PosixFilePermissions
import kotlin.test.Test
import kotlin.test.assertContentEquals
import kotlin.test.assertEquals
import kotlin.test.assertFailsWith
import kotlin.test.assertFalse
import kotlin.test.assertNotEquals
import kotlin.test.assertTrue

class LlvmBehaviorHostedContainerV1DockerSessionTest {
    @Test
    fun `pinned client executes only the four read-only fixed slots with exact process tuples`() {
        DockerSessionFixture().use { fixture ->
            val bindings = fixture.capture()
            fixture.openJournal("happy").use { owner ->
                val plan = fixture.plan(owner)
                val retained = plan.retainCreatedContainer("$CONTAINER_ID\n".encodeToByteArray())
                LlvmBehaviorHostedContainerV1DockerSession.open(bindings).use { session ->
                    assertEquals("first-class-candidate-producer-operator", session.acpRole)
                    assertEquals("none", session.acpOracleAccess)
                    assertAllAuthorityFalse(session)

                    val image = session.inspectWorkerImage(plan)
                    val container = session.inspectCandidateContainer(retained)
                    val nameInventory = session.inventoryExactName(plan)
                    val labelInventory = session.inventoryExactOperationLabel(plan)

                    assertEquals(LlvmBehaviorHostedContainerV1OperationPhase.RECOVERED, owner.phase)
                    assertEquals(CONTAINER_ID, retained.expectation.containerId)
                    assertEquals(plan.imageId, image.imageId)
                    assertEquals(plan.operationId, image.operationId)
                    assertEquals(plan.journalBindingSha256, image.journalBindingSha256)
                    assertEquals(plan.journalRootPathSha256, image.journalRootPathSha256)
                    assertEquals(CONTAINER_ID, container.containerId)
                    assertEquals(plan.imageId, container.imageId)
                    assertEquals(plan.operationId, container.operationId)
                    assertEquals(plan.journalBindingSha256, container.journalBindingSha256)
                    assertEquals(plan.journalRootPathSha256, container.journalRootPathSha256)
                    assertContentEquals(IMAGE_INSPECT_BYTES, image.bytes)
                    assertContentEquals(CONTAINER_INSPECT_BYTES, container.bytes)
                    val callerImageBytes = image.bytes
                    val callerContainerBytes = container.bytes
                    callerImageBytes.fill(0)
                    callerContainerBytes.fill(0)
                    assertContentEquals(IMAGE_INSPECT_BYTES, image.bytes)
                    assertContentEquals(CONTAINER_INSPECT_BYTES, container.bytes)

                    assertEquals(listOf(CONTAINER_ID), nameInventory.projection.containerIds)
                    assertEquals(listOf(OTHER_CONTAINER_ID), labelInventory.projection.containerIds)
                    assertInventoryBinding(plan, nameInventory)
                    assertInventoryBinding(plan, labelInventory)
                    @Suppress("UNCHECKED_CAST")
                    val mutableIds = nameInventory.projection.containerIds as MutableList<String>
                    assertFailsWith<UnsupportedOperationException> { mutableIds.clear() }

                    assertEquals(
                        listOf(
                            expectedInvocation(bindings, plan.imageInspectArguments),
                            expectedInvocation(bindings, retained.candidateContainerInspectArguments),
                            expectedInvocation(bindings, plan.exactNameInventoryArguments),
                            expectedInvocation(bindings, plan.exactOperationLabelInventoryArguments),
                        ),
                        fixture.invocations(),
                    )
                }
            }
        }
    }

    @Test
    fun `read-only failures reject signals statuses stderr and post-command binding drift`() {
        DockerSessionFixture().use { fixture ->
            val bindings = fixture.capture()
            LlvmBehaviorHostedContainerV1DockerSession.open(bindings).use { session ->
                fixture.openJournal("read-only-failure").use { owner ->
                    val plan = fixture.plan(owner)
                    listOf("stderr", "nonzero", "signal").forEach { behavior ->
                        fixture.setBehavior(behavior)
                        val failure = assertFailsWith<LlvmBehaviorHostedContainerV1DockerSessionException> {
                            session.inspectWorkerImage(plan)
                        }
                        assertEquals(
                            LlvmBehaviorHostedContainerV1DockerSessionFailureKind.CONTROL_COMMAND_FAILED,
                            failure.kind,
                        )
                        assertFalse(
                            throwableTexts(failure).any { SECRET_DIAGNOSTIC in it },
                            "raw client stderr escaped through the exception tree",
                        )
                    }

                    fixture.setBehavior("contaminate-read")
                    val failure = assertFailsWith<LlvmBehaviorHostedContainerV1DockerSessionException> {
                        session.inspectWorkerImage(plan)
                    }
                    assertEquals(
                        LlvmBehaviorHostedContainerV1DockerSessionFailureKind.CONTROL_COMMAND_FAILED,
                        failure.kind,
                    )
                    assertTrue(Files.exists(fixture.dockerConfig.resolve("config.json")))
                    assertEquals(LlvmBehaviorHostedContainerV1OperationPhase.RECOVERED, owner.phase)
                }
            }
        }
    }

    @Test
    fun `inspect and separate bound inventories enforce output parsers and byte ceilings`() {
        DockerSessionFixture().use { fixture ->
            val bindings = fixture.capture()
            fixture.openJournal("bounded-output").use { owner ->
                val plan = fixture.plan(owner)
                LlvmBehaviorHostedContainerV1DockerSession.open(bindings).use { session ->
                    fixture.setBehavior("inspect-maximum")
                    assertEquals(1024 * 1024, session.inspectWorkerImage(plan).bytes.size)

                    fixture.setBehavior("inspect-overflow")
                    assertControlFailure { session.inspectWorkerImage(plan) }

                    fixture.setBehavior("inventory-maximum")
                    val maximumIds = (0 until 16).map { it.toString(16).padStart(64, '0') }
                    assertEquals(maximumIds, session.inventoryExactName(plan).projection.containerIds)

                    fixture.setBehavior("malformed-inventory")
                    assertControlFailure { session.inventoryExactName(plan) }

                    fixture.setBehavior("inventory-overflow")
                    assertControlFailure { session.inventoryExactOperationLabel(plan) }

                    fixture.setBehavior("empty-inventory")
                    val emptyName = session.inventoryExactName(plan)
                    val emptyLabel = session.inventoryExactOperationLabel(plan)
                    assertEquals(emptyList(), emptyName.projection.containerIds)
                    assertEquals(emptyList(), emptyLabel.projection.containerIds)
                    assertInventoryBinding(plan, emptyName)
                    assertInventoryBinding(plan, emptyLabel)
                    assertNotEquals(emptyName.javaClass.name, emptyLabel.javaClass.name)
                }
            }
        }
    }

    @Test
    fun `session construction and methods expose no generic executor or lifecycle escape hatch`() {
        val factory = LlvmBehaviorHostedContainerV1DockerSession.Companion::class.java.declaredMethods
            .single { it.name == "open" }
        assertEquals(listOf(PinnedDockerRuntimeBindings::class.java), factory.parameterTypes.toList())

        val methods = LlvmBehaviorHostedContainerV1DockerSession::class.java.declaredMethods
        val prohibitedNames = setOf("create", "start", "wait", "exec", "execute", "run", "remove", "rm")
        assertTrue(methods.none { it.name.lowercase() in prohibitedNames })
        assertTrue(
            methods.flatMap { it.parameterTypes.toList() }.none { type ->
                type == Process::class.java || type == ProcessBuilder::class.java ||
                    type == ByteArray::class.java || type == Path::class.java || type == Map::class.java ||
                    type.name.startsWith("kotlin.jvm.functions.")
            },
        )
        assertTrue(
            methods.none { method ->
                method.name.contains("durable", ignoreCase = true) ||
                    method.name.contains("absence", ignoreCase = true)
            },
        )
    }
}

private class DockerSessionFixture : AutoCloseable {
    val root: Path = Files.createTempDirectory("hosted-docker-session-").toAbsolutePath().normalize()
    val dockerConfig: Path = root.resolve("docker-config")
    private val controlClient = root.resolve("fake-docker-client")
    private val source = root.resolve("fake-docker-client.c")
    private val invocationLog = root.resolve("invocations.log")
    private val behaviorFile = root.resolve("behavior")
    private val socketParent = root.resolve("runtime")
    private val runtimeSocket = socketParent.resolve("docker.sock")
    private val socketServer: ServerSocketChannel
    private var journalIndex = 0

    init {
        Files.setPosixFilePermissions(root, OWNER_DIRECTORY_MODE)
        Files.writeString(behaviorFile, "normal\n")
        Files.writeString(source, fakeDockerClientSource(invocationLog, behaviorFile))
        compileFakeClient(source, controlClient)
        Files.setPosixFilePermissions(controlClient, OWNER_EXECUTABLE_MODE)
        Files.createDirectory(dockerConfig)
        Files.setPosixFilePermissions(dockerConfig, OWNER_DIRECTORY_MODE)
        Files.createDirectory(socketParent)
        Files.setPosixFilePermissions(socketParent, OWNER_DIRECTORY_MODE)
        socketServer = ServerSocketChannel.open(StandardProtocolFamily.UNIX).also { channel ->
            channel.bind(UnixDomainSocketAddress.of(runtimeSocket))
            Files.setPosixFilePermissions(runtimeSocket, OWNER_SOCKET_MODE)
        }
    }

    fun capture(): PinnedDockerRuntimeBindings {
        val bytes = Files.readAllBytes(controlClient)
        return PinnedDockerRuntimeBindings.capture(
            controlClientPath = controlClient,
            expectedControlClientBytes = bytes.size.toLong(),
            expectedControlClientSha256 = OracleArtifacts.sha256(bytes),
            maximumControlClientBytes = 1024 * 1024,
            dockerConfigPath = dockerConfig,
            runtimeSocketPath = runtimeSocket,
        )
    }

    fun openJournal(label: String): LlvmBehaviorHostedContainerV1OperationJournalOwner {
        val container = Files.createDirectory(root.resolve("journal-${journalIndex++}-$label"))
        Files.setPosixFilePermissions(container, OWNER_DIRECTORY_MODE)
        val journal = Files.createDirectory(container.resolve("journal"))
        Files.setPosixFilePermissions(journal, OWNER_DIRECTORY_MODE)
        return LlvmBehaviorHostedContainerV1OperationJournal.open(journal)
    }

    fun plan(
        owner: LlvmBehaviorHostedContainerV1OperationJournalOwner,
    ): LlvmBehaviorHostedContainerV1DockerControlPlan =
        LlvmBehaviorHostedContainerV1DockerControlPlan.render(
            LlvmBehaviorHostedContainerV1PreCreateExpectation.fromJournal(
                journalOwner = owner,
                imageId = IMAGE_ID,
                uid = 1001,
                gid = 1002,
                inputsSource = INPUTS_SOURCE,
                stageOutputSource = STAGE_OUTPUT_SOURCE,
            ),
        )

    fun setBehavior(behavior: String) {
        Files.writeString(behaviorFile, "$behavior\n")
    }

    fun invocations(): List<FakeDockerInvocation> {
        if (!Files.exists(invocationLog)) return emptyList()
        val invocations = mutableListOf<FakeDockerInvocation>()
        var cwd: String? = null
        var arguments = mutableListOf<String>()
        var environment = mutableListOf<String>()
        Files.readAllLines(invocationLog).forEach { line ->
            when {
                line == "BEGIN" -> {
                    check(cwd == null && arguments.isEmpty() && environment.isEmpty())
                    cwd = ""
                }
                line == "END" -> {
                    invocations += FakeDockerInvocation(requireNotNull(cwd), arguments, environment)
                    cwd = null
                    arguments = mutableListOf()
                    environment = mutableListOf()
                }
                line.startsWith("CWD:") -> cwd = line.removePrefix("CWD:")
                line.startsWith("ARG:") -> arguments += line.removePrefix("ARG:")
                line.startsWith("ENV:") -> environment += line.removePrefix("ENV:")
                else -> error("malformed fake Docker invocation log")
            }
        }
        check(cwd == null && arguments.isEmpty() && environment.isEmpty())
        return invocations
    }

    override fun close() {
        socketServer.close()
        Files.deleteIfExists(runtimeSocket)
        root.toFile().deleteRecursively()
    }
}

private data class FakeDockerInvocation(
    val workingDirectory: String,
    val arguments: List<String>,
    val environment: List<String>,
)

private fun expectedInvocation(
    bindings: PinnedDockerRuntimeBindings,
    suffix: List<String>,
) = FakeDockerInvocation(
    workingDirectory = "/",
    arguments = listOf(bindings.executableDescriptorPath.toString()) + suffix,
    environment = bindings.environment.entries
        .sortedBy { it.key }
        .map { (name, value) -> "$name=$value" },
)

private fun assertInventoryBinding(
    plan: LlvmBehaviorHostedContainerV1DockerControlPlan,
    token: LlvmBehaviorHostedContainerV1ExactNameInventoryToken,
) {
    assertEquals(plan.operationId, token.operationId)
    assertEquals(plan.journalBindingSha256, token.journalBindingSha256)
    assertEquals(plan.journalRootPathSha256, token.journalRootPathSha256)
}

private fun assertInventoryBinding(
    plan: LlvmBehaviorHostedContainerV1DockerControlPlan,
    token: LlvmBehaviorHostedContainerV1ExactOperationLabelInventoryToken,
) {
    assertEquals(plan.operationId, token.operationId)
    assertEquals(plan.journalBindingSha256, token.journalBindingSha256)
    assertEquals(plan.journalRootPathSha256, token.journalRootPathSha256)
}

private fun assertControlFailure(action: () -> Unit) {
    val failure = assertFailsWith<LlvmBehaviorHostedContainerV1DockerSessionException> { action() }
    assertEquals(
        LlvmBehaviorHostedContainerV1DockerSessionFailureKind.CONTROL_COMMAND_FAILED,
        failure.kind,
    )
}

private fun assertAllAuthorityFalse(session: LlvmBehaviorHostedContainerV1DockerSession) {
    assertFalse(session.oracleAuthority)
    assertFalse(session.referenceAuthority)
    assertFalse(session.validationAuthority)
    assertFalse(session.startAuthority)
    assertFalse(session.containmentAuthority)
    assertFalse(session.scoringAuthority)
    assertFalse(session.certificationAuthority)
    assertFalse(session.publicationAuthority)
    assertFalse(session.releaseAuthority)
}

private fun throwableTexts(root: Throwable): List<String> {
    val seen = java.util.Collections.newSetFromMap(java.util.IdentityHashMap<Throwable, Boolean>())
    val pending = ArrayDeque<Throwable>()
    val texts = mutableListOf<String>()
    pending += root
    while (pending.isNotEmpty()) {
        val next = pending.removeFirst()
        if (!seen.add(next)) continue
        next.message?.let(texts::add)
        next.cause?.let(pending::add)
        next.suppressed.forEach(pending::add)
    }
    return texts
}

private fun compileFakeClient(source: Path, output: Path) {
    val process = ProcessBuilder(
        "/usr/bin/cc",
        "-std=c11",
        "-O2",
        "-Wall",
        "-Wextra",
        "-Werror",
        source.toString(),
        "-o",
        output.toString(),
    ).redirectErrorStream(true).start()
    val diagnostics = process.inputStream.readNBytes(64 * 1024).decodeToString()
    check(process.waitFor() == 0) { "cannot compile fake Docker client: $diagnostics" }
}

private fun fakeDockerClientSource(log: Path, behavior: Path): String =
    """
    #define _GNU_SOURCE
    #include <errno.h>
    #include <fcntl.h>
    #include <limits.h>
    #include <signal.h>
    #include <stdio.h>
    #include <stdlib.h>
    #include <string.h>
    #include <unistd.h>

    extern char **environ;

    static const char *LOG_PATH = "${cString(log.toString())}";
    static const char *BEHAVIOR_PATH = "${cString(behavior.toString())}";
    static const char *CONTAINER_ID = "$CONTAINER_ID";
    static const char *OTHER_CONTAINER_ID = "$OTHER_CONTAINER_ID";

    static void record_invocation(int argc, char **argv) {
        FILE *stream = fopen(LOG_PATH, "a");
        char cwd[PATH_MAX];
        if (stream == NULL || getcwd(cwd, sizeof(cwd)) == NULL) _exit(91);
        fputs("BEGIN\n", stream);
        fprintf(stream, "CWD:%s\n", cwd);
        for (int index = 0; index < argc; ++index) fprintf(stream, "ARG:%s\n", argv[index]);
        for (char **entry = environ; *entry != NULL; ++entry) fprintf(stream, "ENV:%s\n", *entry);
        fputs("END\n", stream);
        if (fclose(stream) != 0) _exit(92);
    }

    static void read_behavior(char *destination, size_t capacity) {
        FILE *stream = fopen(BEHAVIOR_PATH, "r");
        if (stream == NULL || fgets(destination, (int) capacity, stream) == NULL) _exit(93);
        fclose(stream);
        destination[strcspn(destination, "\r\n")] = '\0';
    }

    static int is_slot(int argc, char **argv, const char *first, const char *second) {
        return argc >= 3 && strcmp(argv[1], first) == 0 && strcmp(argv[2], second) == 0;
    }

    static int inventory_has_filter(int argc, char **argv, const char *prefix) {
        for (int index = 3; index < argc; ++index) {
            if (strncmp(argv[index], prefix, strlen(prefix)) == 0) return 1;
        }
        return 0;
    }

    static void repeat_stdout(size_t count) {
        for (size_t index = 0; index < count; ++index) fputc('x', stdout);
    }

    static void contaminate_config(void) {
        const char *config = getenv("DOCKER_CONFIG");
        char path[PATH_MAX];
        if (config == NULL || snprintf(path, sizeof(path), "%s/config.json", config) >= (int) sizeof(path)) _exit(94);
        int descriptor = open(path, O_WRONLY | O_CREAT | O_EXCL, 0600);
        if (descriptor < 0 || close(descriptor) != 0) _exit(95);
    }

    int main(int argc, char **argv) {
        char behavior[64];
        record_invocation(argc, argv);
        read_behavior(behavior, sizeof(behavior));
        if (strcmp(behavior, "stderr") == 0) {
            fputs("$SECRET_DIAGNOSTIC\n", stderr);
        }
        if (strcmp(behavior, "nonzero") == 0) return 23;
        if (strcmp(behavior, "signal") == 0) {
            raise(SIGTERM);
            return 96;
        }

        if (is_slot(argc, argv, "image", "inspect")) {
            if (strcmp(behavior, "contaminate-read") == 0) contaminate_config();
            if (strcmp(behavior, "inspect-maximum") == 0) repeat_stdout(1024U * 1024U);
            else if (strcmp(behavior, "inspect-overflow") == 0) repeat_stdout(1024U * 1024U + 1U);
            else fputs("${IMAGE_INSPECT_BYTES.decodeToString().replace("\n", "\\n")}", stdout);
            return 0;
        }
        if (is_slot(argc, argv, "container", "inspect")) {
            fputs("${CONTAINER_INSPECT_BYTES.decodeToString().replace("\n", "\\n")}", stdout);
            return 0;
        }
        if (is_slot(argc, argv, "container", "ls")) {
            if (strcmp(behavior, "inventory-overflow") == 0) repeat_stdout(16U * 65U + 1U);
            else if (strcmp(behavior, "malformed-inventory") == 0) fputs("bad\n", stdout);
            else if (strcmp(behavior, "inventory-maximum") == 0) {
                for (unsigned int index = 0; index < 16U; ++index) fprintf(stdout, "%064x\n", index);
            } else if (strcmp(behavior, "empty-inventory") != 0) {
                fprintf(
                    stdout,
                    "%s\n",
                    inventory_has_filter(argc, argv, "--filter=name=") ? CONTAINER_ID : OTHER_CONTAINER_ID
                );
            }
            return 0;
        }
        fputs("unexpected fake Docker control slot\n", stderr);
        return 97;
    }
    """.trimIndent() + "\n"

private fun cString(value: String): String = value
    .replace("\\", "\\\\")
    .replace("\"", "\\\"")

private const val IMAGE_ID = "sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"
private const val CONTAINER_ID = "bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb"
private const val OTHER_CONTAINER_ID = "cccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccc"
private const val SECRET_DIAGNOSTIC = "raw-secret-diagnostic-that-must-not-escape"
private val IMAGE_INSPECT_BYTES = "raw-image-inspect-json\n".encodeToByteArray()
private val CONTAINER_INSPECT_BYTES = "raw-container-inspect-json\n".encodeToByteArray()
private val INPUTS_SOURCE = Path.of("/var/lib/decomp/operations/inputs")
private val STAGE_OUTPUT_SOURCE = Path.of("/var/lib/decomp/operations/stage-output")
private val OWNER_DIRECTORY_MODE = PosixFilePermissions.fromString("rwx------")
private val OWNER_EXECUTABLE_MODE = PosixFilePermissions.fromString("r-x------")
private val OWNER_SOCKET_MODE = setOf(
    PosixFilePermission.OWNER_READ,
    PosixFilePermission.OWNER_WRITE,
)
