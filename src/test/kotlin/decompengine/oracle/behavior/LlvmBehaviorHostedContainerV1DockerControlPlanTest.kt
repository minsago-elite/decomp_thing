package decompengine.oracle.behavior

import java.lang.reflect.Modifier
import java.nio.file.Files
import java.nio.file.LinkOption
import java.nio.file.Path
import java.nio.file.attribute.PosixFilePermissions
import kotlin.test.Test
import kotlin.test.assertEquals
import kotlin.test.assertFailsWith
import kotlin.test.assertFalse
import kotlin.test.assertTrue

class LlvmBehaviorHostedContainerV1DockerControlPlanTest {
    @Test
    fun `pre-create renderer emits the single exact create suffix and recovery queries`() {
        val expectation = preCreateExpectation()
        val plan = LlvmBehaviorHostedContainerV1DockerControlPlan.render(expectation)

        assertEquals(expectation.imageId, plan.imageId)
        assertEquals(expectation.containerName, plan.containerName)
        assertEquals(expectation.operationId, plan.operationId)
        assertEquals(expectation.journalBindingSha256, plan.journalBindingSha256)
        assertEquals(expectation.journalRootPathSha256, plan.journalRootPathSha256)

        assertEquals(
            listOf(
                "container",
                "create",
                "--pull=never",
                "--platform=linux/amd64",
                "--name=${expectation.containerName}",
                "--hostname=llvm-hosted-build",
                "--label=$OPERATION_LABEL=${expectation.operationId}",
                "--user=1001:1002",
                "--workdir=/",
                "--attach=stdout",
                "--attach=stderr",
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
                "--mount=type=bind,source=$INPUTS_SOURCE,target=/inputs,readonly,bind-propagation=rprivate",
                "--mount=type=bind,source=$STAGE_SOURCE,target=/stage-output,bind-propagation=rprivate",
                "--tmpfs=/work:rw,nosuid,nodev,exec,size=17179869184," +
                    "nr_inodes=1000000,mode=0700,uid=1001,gid=1002",
                "--tmpfs=/tmp:rw,nosuid,nodev,noexec,size=268435456,nr_inodes=4096,mode=1777",
                "--tmpfs=/decomp-jna:rw,nosuid,nodev,exec,size=16777216," +
                    "nr_inodes=128,mode=0700,uid=1001,gid=1002",
                IMAGE_ID,
            ),
            plan.createArguments,
        )
        assertEquals(
            listOf("image", "inspect", "--platform=linux/amd64", IMAGE_ID),
            plan.imageInspectArguments,
        )
        assertEquals(
            listOf("container", "inspect", expectation.containerName),
            plan.inspectByDurableNameArguments,
        )
        assertEquals(
            listOf(
                "container",
                "ls",
                "--all",
                "--no-trunc",
                "--filter=name=^/${expectation.containerName}\$",
                "--format={{.ID}}",
            ),
            plan.exactNameInventoryArguments,
        )
        assertEquals(
            listOf(
                "container",
                "ls",
                "--all",
                "--no-trunc",
                "--filter=label=$OPERATION_LABEL=${expectation.operationId}",
                "--format={{.ID}}",
            ),
            plan.exactOperationLabelInventoryArguments,
        )
    }

    @Test
    fun `created ID is parsed after create and initially unlocks only exact ID inspection`() {
        val source = preCreateExpectation()
        val preCreate = LlvmBehaviorHostedContainerV1DockerControlPlan.render(source)
        val stdout = "$CONTAINER_ID\n".encodeToByteArray()

        val retained = preCreate.retainCreatedContainer(stdout)
        stdout.fill('0'.code.toByte())

        assertEquals(CONTAINER_ID, retained.expectation.containerId)
        assertEquals(IMAGE_ID, retained.expectation.imageId)
        assertEquals(source.containerName, retained.expectation.containerName)
        assertEquals(source.operationId, retained.operationId)
        assertEquals(source.journalBindingSha256, retained.journalBindingSha256)
        assertEquals(source.journalRootPathSha256, retained.journalRootPathSha256)
        assertEquals(listOf("container", "inspect", CONTAINER_ID), retained.candidateContainerInspectArguments)
        assertTrue(
            retained.javaClass.declaredMethods.none {
                it.name in setOf("getStartArguments", "getWaitArguments", "getRemoveByIdArguments")
            },
        )
        assertEquals(
            listOf("container", "inspect", OTHER_CONTAINER_ID),
            LlvmBehaviorHostedContainerV1DockerControlPlan.inspectById(OTHER_CONTAINER_ID),
        )
        assertFailsWith<LlvmBehaviorHostedContainerV1DockerControlPlanException> {
            LlvmBehaviorHostedContainerV1DockerControlPlan.inspectById("caller-name")
        }
    }

    @Test
    fun `pre-create API contains no container ID and create stdout syntax is exact and bounded`() {
        assertTrue(
            LlvmBehaviorHostedContainerV1PreCreateExpectation::class.java.declaredFields.none {
                "containerid" in it.name.lowercase()
            },
        )
        assertTrue(
            LlvmBehaviorHostedContainerV1PreCreateExpectation::class.java.declaredConstructors
                .filterNot { it.isSynthetic }
                .all {
                Modifier.isPrivate(it.modifiers)
            },
        )
        val fromJournal = LlvmBehaviorHostedContainerV1PreCreateExpectation.Companion::class.java
            .declaredMethods.single { it.name == "fromJournal" }
        assertEquals(
            listOf(
                LlvmBehaviorHostedContainerV1OperationJournalOwner::class.java,
                String::class.java,
                Int::class.javaPrimitiveType,
                Int::class.javaPrimitiveType,
                Path::class.java,
                Path::class.java,
            ),
            fromJournal.parameterTypes.toList(),
        )
        assertEquals(1, fromJournal.parameterTypes.count { it == String::class.java })
        val plan = LlvmBehaviorHostedContainerV1DockerControlPlan.render(preCreateExpectation())
        assertTrue(plan.javaClass.declaredFields.none { "containerid" in it.name.lowercase() })
        assertFalse(plan.createArguments.contains(CONTAINER_ID))
        assertEquals(
            listOf(ByteArray::class.java),
            plan.javaClass.getDeclaredMethod("retainCreatedContainer", ByteArray::class.java).parameterTypes.toList(),
        )
        assertTrue(
            LlvmBehaviorHostedContainerV1RetainedDockerControlPlan::class.java.declaredConstructors
                .filterNot { it.isSynthetic }
                .all {
                Modifier.isPrivate(it.modifiers)
            },
        )

        listOf(
            byteArrayOf(),
            CONTAINER_ID.encodeToByteArray(),
            "$CONTAINER_ID\r\n".encodeToByteArray(),
            "${CONTAINER_ID.uppercase()}\n".encodeToByteArray(),
            "${CONTAINER_ID.dropLast(1)}\n".encodeToByteArray(),
            " $CONTAINER_ID\n".encodeToByteArray(),
            "$CONTAINER_ID\nextra\n".encodeToByteArray(),
            "${"g".repeat(64)}\n".encodeToByteArray(),
        ).forEach { bytes ->
            assertFailsWith<LlvmBehaviorHostedContainerV1DockerOutputException>(bytes.decodeToString()) {
                plan.retainCreatedContainer(bytes)
            }
        }
    }

    @Test
    fun `code-only plan exposes no START wait or removal suffix`() {
        val plan = LlvmBehaviorHostedContainerV1DockerControlPlan.render(preCreateExpectation())
        val retained = plan.retainCreatedContainer("$CONTAINER_ID\n".encodeToByteArray())
        val forbidden = setOf("start", "wait", "remove", "rm")

        listOf(plan.javaClass, retained.javaClass).forEach { type ->
            assertTrue(
                type.declaredMethods.none { method ->
                    forbidden.any { token -> token in method.name.lowercase() }
                },
            )
            assertTrue(
                type.declaredFields.none { field ->
                    forbidden.any { token -> token in field.name.lowercase() }
                },
            )
        }
        (plan.argumentLists() + retained.argumentLists()).flatten().forEach { argument ->
            assertTrue(argument.lowercase() !in forbidden, argument)
        }
    }

    @Test
    fun `create has no command tail alternate launcher host namespace or implicit expansion verb`() {
        val plan = LlvmBehaviorHostedContainerV1DockerControlPlan.render(preCreateExpectation())
        val create = plan.createArguments

        assertTrue(create.size <= 63)
        assertEquals(IMAGE_ID, create.last())
        assertEquals(1, create.count { it == IMAGE_ID })
        assertEquals(2, create.count { it.startsWith("--mount=") })
        assertEquals(3, create.count { it.startsWith("--tmpfs=") })
        assertEquals(3, create.count { it.startsWith("--ulimit=") })
        listOf("--entrypoint", "--pid", "--uts", "--userns", "--cpus", "--rm", "--privileged").forEach { flag ->
            assertFalse(create.any { it == flag || it.startsWith("$flag=") }, flag)
        }

        val retained = plan.retainCreatedContainer("$CONTAINER_ID\n".encodeToByteArray())
        val forbiddenTokens = setOf("exec", "run", "shell", "sh", "bash", "zsh", "-c")
        (plan.argumentLists() + retained.argumentLists()).forEach { arguments ->
            assertTrue(arguments.none { it.lowercase() in forbiddenTokens }, arguments.toString())
        }
    }

    @Test
    fun `argument lists are immutable detached and expose no runner or authority state`() {
        val source = preCreateExpectation()
        val plan = LlvmBehaviorHostedContainerV1DockerControlPlan.render(source)
        val retained = plan.retainCreatedContainer("$CONTAINER_ID\n".encodeToByteArray())
        val arguments = plan.argumentLists() + retained.argumentLists() +
            listOf(LlvmBehaviorHostedContainerV1DockerControlPlan.inspectById(OTHER_CONTAINER_ID))
        val snapshots = arguments.map(List<String>::toList)

        arguments.forEach { argv ->
            @Suppress("UNCHECKED_CAST")
            val mutableView = argv as MutableList<String>
            assertFailsWith<UnsupportedOperationException> { mutableView.add("exec") }
            assertFailsWith<UnsupportedOperationException> { mutableView[0] = "run" }
        }
        assertEquals(snapshots, arguments)

        listOf(
            plan.javaClass,
            retained.javaClass,
            LlvmBehaviorHostedContainerV1PreCreateExpectation::class.java,
        ).forEach { type ->
            val instanceFields = type.declaredFields.filterNot { Modifier.isStatic(it.modifiers) }
            assertTrue(
                instanceFields.none {
                    it.type == Process::class.java || it.type == ProcessBuilder::class.java ||
                        it.type == Boolean::class.java || it.type == Boolean::class.javaObjectType
                },
            )
            assertTrue(
                type.declaredMethods.none { method ->
                    method.name.lowercase() in setOf("run", "exec", "execute")
                },
            )
        }
    }

    @Test
    fun `portable mount grammar is bounded and reflectively corrupted inputs fail closed`() {
        val oversized = Path.of("/" + "a".repeat(4095))
        assertFailsWith<LlvmBehaviorHostedContainerV1DockerControlPlanException> {
            preCreateExpectation(inputs = oversized)
        }

        listOf(
            "/var/lib/decomp/inputs,readonly=false",
            "/var/lib/decomp/inputs\"quoted",
            "/var/lib/decomp/inputs with-space",
            "/var/lib/decomp/inputs\nnext-record",
            "/var/lib/decomp/inputs;command",
            "/var/lib/decomp/inputs\$variable",
            "/var/lib/decomp/inputs\\backslash",
        ).forEach { hostile ->
            assertFailsWith<LlvmBehaviorHostedContainerV1DockerControlPlanException>(hostile) {
                preCreateExpectation(inputs = Path.of(hostile))
            }
        }

        val corrupted = preCreateExpectation()
        val renderedBeforeCorruption = LlvmBehaviorHostedContainerV1DockerControlPlan.render(corrupted)
        corrupted.javaClass.getDeclaredField("inputsSource").apply {
            isAccessible = true
            set(corrupted, Path.of("/var/lib/decomp/inputs,type=tmpfs"))
        }
        assertFailsWith<LlvmBehaviorHostedContainerV1DockerControlPlanException> {
            LlvmBehaviorHostedContainerV1DockerControlPlan.render(corrupted)
        }
        assertTrue(renderedBeforeCorruption.createArguments.any { "source=$INPUTS_SOURCE,target=/inputs" in it })
    }

    @Test
    fun `frozen journal identity rejects valid-looking reflective substitution`() {
        listOf(
            "journalBindingSha256" to "f".repeat(64),
            "journalRootPathSha256" to "e".repeat(64),
        ).forEach { (field, replacement) ->
            val expectation = preCreateExpectation()
            expectation.javaClass.getDeclaredField(field).apply {
                isAccessible = true
                set(expectation, replacement)
            }
            assertFailsWith<LlvmBehaviorHostedContainerV1DockerControlPlanException>(field) {
                LlvmBehaviorHostedContainerV1DockerControlPlan.render(expectation)
            }
        }
    }

    @Test
    fun `safe mount punctuation remains literal inside one argv element`() {
        val inputs = Path.of("/var/lib/decomp/source=literal%2Cvalue+v1@host:0")
        val stage = Path.of("/var/lib/decomp/stage=literal%22value+v1@host:0")
        val plan = LlvmBehaviorHostedContainerV1DockerControlPlan.render(
            preCreateExpectation(inputs = inputs, stage = stage),
        )

        assertEquals(
            "--mount=type=bind,source=$inputs,target=/inputs,readonly,bind-propagation=rprivate",
            plan.createArguments.single { it.contains("target=/inputs") },
        )
        assertEquals(
            "--mount=type=bind,source=$stage,target=/stage-output,bind-propagation=rprivate",
            plan.createArguments.single { it.contains("target=/stage-output") },
        )
    }
}

private fun preCreateExpectation(
    inputs: Path = INPUTS_SOURCE,
    stage: Path = STAGE_SOURCE,
): LlvmBehaviorHostedContainerV1PreCreateExpectation {
    val temporary = Files.createTempDirectory("hosted-control-plan-journal-")
    Files.setPosixFilePermissions(temporary, OWNER_DIRECTORY_MODE)
    val container = Files.createDirectory(temporary.resolve("container"))
    Files.setPosixFilePermissions(container, OWNER_DIRECTORY_MODE)
    val journalRoot = Files.createDirectory(container.resolve("journal"))
    Files.setPosixFilePermissions(journalRoot, OWNER_DIRECTORY_MODE)
    return try {
        LlvmBehaviorHostedContainerV1OperationJournal.open(journalRoot).use { owner ->
            LlvmBehaviorHostedContainerV1PreCreateExpectation.fromJournal(
                journalOwner = owner,
                imageId = IMAGE_ID,
                uid = 1001,
                gid = 1002,
                inputsSource = inputs,
                stageOutputSource = stage,
            )
        }
    } finally {
        if (Files.exists(temporary, LinkOption.NOFOLLOW_LINKS)) {
            Files.walk(temporary).use { paths ->
                paths.sorted(Comparator.reverseOrder()).forEach { path ->
                    if (Files.isDirectory(path, LinkOption.NOFOLLOW_LINKS)) {
                        Files.setPosixFilePermissions(path, OWNER_DIRECTORY_MODE)
                    }
                    Files.deleteIfExists(path)
                }
            }
        }
    }
}

private fun LlvmBehaviorHostedContainerV1DockerControlPlan.argumentLists(): List<List<String>> = listOf(
    createArguments,
    imageInspectArguments,
    inspectByDurableNameArguments,
    exactNameInventoryArguments,
    exactOperationLabelInventoryArguments,
)

private fun LlvmBehaviorHostedContainerV1RetainedDockerControlPlan.argumentLists(): List<List<String>> = listOf(
    candidateContainerInspectArguments,
)

private const val IMAGE_ID = "sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"
private const val CONTAINER_ID = "bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb"
private const val OTHER_CONTAINER_ID = "cccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccc"
private const val OPERATION_LABEL = "dev.decompengine.llvm-behavior-hosted-operation"
private val INPUTS_SOURCE = Path.of("/var/lib/decomp/operations/inputs")
private val STAGE_SOURCE = Path.of("/var/lib/decomp/operations/stage-output")
private val OWNER_DIRECTORY_MODE = PosixFilePermissions.fromString("rwx------")
