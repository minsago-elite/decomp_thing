package decompengine.acp

import com.agentclientprotocol.protocol.AcpExpectedError
import decompengine.agent.AgentAccessPolicy
import decompengine.agent.AgentCancellation
import decompengine.agent.AgentCancellationSource
import decompengine.agent.AgentExecutionRequest
import decompengine.agent.AgentOperation
import decompengine.agent.AgentPathRule
import decompengine.agent.AgentWorkspacePath
import decompengine.agent.AgentWorkspaceRoot
import java.io.IOException
import java.nio.ByteBuffer
import java.nio.file.Files
import java.nio.file.Path
import java.nio.file.attribute.PosixFilePermissions
import java.nio.file.attribute.UserDefinedFileAttributeView
import java.util.concurrent.atomic.AtomicBoolean
import kotlin.io.path.createDirectories
import kotlin.io.path.createSymbolicLinkPointingTo
import kotlin.io.path.createTempDirectory
import kotlin.io.path.exists
import kotlin.io.path.listDirectoryEntries
import kotlin.io.path.readText
import kotlin.io.path.writeBytes
import kotlin.io.path.writeText
import kotlin.test.Test
import kotlin.test.assertEquals
import kotlin.test.assertFailsWith
import kotlin.test.assertFalse
import kotlin.test.assertNotNull
import kotlin.test.assertNull
import kotlin.test.assertTrue
import kotlinx.coroutines.runBlocking

class AcpFilesystemBrokerTest {
    @Test
    fun `capabilities follow the immutable workflow policy and valid operations are audited without content`() {
        val workspace = createTempDirectory("acp-fs-valid-").toAbsolutePath().normalize()
        val source = workspace.resolve("src/module.c")
        source.parent.createDirectories()
        source.writeText("first\nsecond\nthird\n")
        val request = request(
            workspace,
            listOf(
                rule("src/module.c", AgentOperation.READ_FILE, AgentOperation.WRITE_FILE),
                rule("src/new.c", AgentOperation.CREATE_FILE),
            ),
        )
        val audit = AcpFilesystemAuditRecorder()

        AcpFilesystemBroker.open(request, AcpFilesystemLimits(), audit).use { broker ->
            assertEquals(true, broker.capability?.readTextFile)
            assertEquals(true, broker.capability?.writeTextFile)

            val selected = runBlocking {
                broker.readTextFile("session-1", source.toString(), 2u, 1u)
            }
            assertEquals("second\n", selected.content)

            val secret = "replacement-value-that-must-not-enter-the-audit"
            runBlocking { broker.writeTextFile("session-1", source.toString(), secret) }
            runBlocking { broker.writeTextFile("session-1", workspace.resolve("src/new.c").toString(), "created\n") }

            assertEquals(secret, source.readText())
            assertEquals("created\n", workspace.resolve("src/new.c").readText())
            assertTrue(source.parent.listDirectoryEntries().none { it.fileName.toString().startsWith(".decomp-acp-") })
        }

        val records = audit.snapshot()
        assertEquals(listOf(0L, 1L, 2L), records.map { it.sequence })
        assertEquals(List(3) { "session-1" }, records.map { it.sessionId })
        assertEquals(
            listOf("fs/read_text_file", "fs/write_text_file", "fs/write_text_file"),
            records.map { it.method },
        )
        assertEquals(
            listOf("src/module.c", "src/module.c", "src/new.c"),
            records.map { assertNotNull(it.policyPath).relativePath },
        )
        assertTrue(records.all { it.outcome == AcpFilesystemAuditOutcome.ALLOWED })
        assertTrue(records.all { it.requestedPathSha256.matches(Regex("[0-9a-f]{64}")) })
        assertFalse(records.toString().contains("replacement-value-that-must-not-enter-the-audit"))
        assertFalse(records.toString().contains(workspace.toString()))
        assertFailsWith<UnsupportedOperationException> {
            @Suppress("UNCHECKED_CAST")
            (records as MutableList<AcpFilesystemAuditRecord>).clear()
        }
    }

    @Test
    fun `disabled and read-only workflows advertise only their enabled methods`() {
        val workspace = createTempDirectory("acp-fs-capability-").toAbsolutePath().normalize()
        val source = workspace.resolve("source.c")
        source.writeText("source\n")

        val disabledAudit = AcpFilesystemAuditRecorder()
        val deleteOnly = request(workspace, listOf(rule("source.c", AgentOperation.DELETE_FILE)))
        AcpFilesystemBroker.open(deleteOnly, AcpFilesystemLimits(), disabledAudit).use { broker ->
            assertNull(broker.capability)
            assertFailsWith<AcpExpectedError> {
                runBlocking { broker.readTextFile("disabled-session", source.toString(), null, null) }
            }
        }
        assertEquals(AcpFilesystemAuditReason.CAPABILITY_DISABLED, disabledAudit.snapshot().single().reason)

        val readAudit = AcpFilesystemAuditRecorder()
        val readRequest = request(workspace, listOf(rule("source.c", AgentOperation.READ_FILE)))
        AcpFilesystemBroker.open(readRequest, AcpFilesystemLimits(), readAudit).use { broker ->
            assertEquals(true, broker.capability?.readTextFile)
            assertEquals(false, broker.capability?.writeTextFile)
            assertFailsWith<AcpExpectedError> {
                runBlocking { broker.writeTextFile("read-session", source.toString(), "forbidden") }
            }
        }
        assertEquals(AcpFilesystemAuditReason.CAPABILITY_DISABLED, readAudit.snapshot().single().reason)
        assertEquals("source\n", source.readText())

        assertFalse(
            hasEffectiveFilesystemWriteCapability(
                listOf(rule("source.c", AgentOperation.WRITE_FILE)),
                setOf(AgentOperation.CREATE_FILE),
            ),
            "a CREATE global grant must not activate an unrelated WRITE path rule",
        )
        assertFalse(
            hasEffectiveFilesystemWriteCapability(
                listOf(rule("source.c", AgentOperation.CREATE_FILE)),
                setOf(AgentOperation.WRITE_FILE),
            ),
            "a WRITE global grant must not activate an unrelated CREATE path rule",
        )
        assertTrue(
            hasEffectiveFilesystemWriteCapability(
                listOf(rule("source.c", AgentOperation.WRITE_FILE)),
                setOf(AgentOperation.WRITE_FILE),
            ),
        )
    }

    @Test
    fun `create and replace permissions are not interchangeable`() {
        val workspace = createTempDirectory("acp-fs-operation-policy-").toAbsolutePath().normalize()
        val createOnly = workspace.resolve("create-only.c")
        createOnly.writeText("existing\n")
        val replaceOnly = workspace.resolve("replace-only.c")
        val request = request(
            workspace,
            listOf(
                rule("create-only.c", AgentOperation.CREATE_FILE),
                rule("replace-only.c", AgentOperation.WRITE_FILE),
            ),
        )
        val audit = AcpFilesystemAuditRecorder()

        AcpFilesystemBroker.open(request, AcpFilesystemLimits(), audit).use { broker ->
            assertDenied { broker.writeTextFile("policy", createOnly.toString(), "must-not-replace\n") }
            assertDenied { broker.writeTextFile("policy", replaceOnly.toString(), "must-not-create\n") }
        }

        assertEquals("existing\n", createOnly.readText())
        assertFalse(replaceOnly.exists())
        assertEquals(
            List(2) { AcpFilesystemAuditReason.POLICY_DENIED },
            audit.snapshot().map { it.reason },
        )
    }

    @Test
    fun `multiple declared roots retain root-qualified policy and equal roots are ambiguous`() {
        val project = createTempDirectory("acp-fs-primary-root-").toAbsolutePath().normalize()
        val support = createTempDirectory("acp-fs-support-root-").toAbsolutePath().normalize()
        val context = support.resolve("context.txt")
        context.writeText("support context\n")
        val request = AgentExecutionRequest(
            objective = "read a secondary root",
            workspaceRoots = listOf(
                AgentWorkspaceRoot("project", project),
                AgentWorkspaceRoot("support", support),
            ),
            accessPolicy = AgentAccessPolicy(
                listOf(
                    AgentPathRule(
                        AgentWorkspacePath("support", "context.txt"),
                        setOf(AgentOperation.READ_FILE),
                    ),
                ),
            ),
        )
        val audit = AcpFilesystemAuditRecorder()
        AcpFilesystemBroker.open(request, AcpFilesystemLimits(), audit).use { broker ->
            val response = runBlocking {
                broker.readTextFile("multi-root", context.toString(), null, null)
            }
            assertEquals("support context\n", response.content)
        }
        assertEquals("support", assertNotNull(audit.snapshot().single().policyPath).rootId)

        val ambiguousRequest = AgentExecutionRequest(
            objective = "reject ambiguous roots",
            workspaceRoots = listOf(
                AgentWorkspaceRoot("first", project),
                AgentWorkspaceRoot("second", project),
            ),
            accessPolicy = AgentAccessPolicy(
                listOf(
                    AgentPathRule(
                        AgentWorkspacePath("first", "source.c"),
                        setOf(AgentOperation.READ_FILE),
                    ),
                ),
            ),
        )
        val ambiguousAudit = AcpFilesystemAuditRecorder()
        AcpFilesystemBroker.open(ambiguousRequest, AcpFilesystemLimits(), ambiguousAudit).use { broker ->
            assertDenied { broker.readTextFile("ambiguous", project.resolve("source.c").toString(), null, null) }
        }
        assertEquals(AcpFilesystemAuditReason.AMBIGUOUS_ROOT, ambiguousAudit.snapshot().single().reason)
    }

    @Test
    fun `absolute normalized containment and workflow path rules reject bypasses`() {
        val parent = createTempDirectory("acp-fs-containment-").toAbsolutePath().normalize()
        val workspace = parent.resolve("workspace").createDirectories()
        val outside = parent.resolve("outside").createDirectories()
        val allowed = workspace.resolve("module").createDirectories()
        val allowedSource = allowed.resolve("source.c")
        allowedSource.writeText("allowed\n")
        val evidence = workspace.resolve("evidence.json")
        evidence.writeText("evidence\n")
        val outsideSecret = outside.resolve("secret.txt")
        outsideSecret.writeText("outside-secret\n")
        allowed.resolve("escape").createSymbolicLinkPointingTo(outside)
        val finalLink = allowed.resolve("linked.c")
        finalLink.createSymbolicLinkPointingTo(outsideSecret)
        val request = request(
            workspace,
            listOf(
                AgentPathRule(
                    AgentWorkspacePath("project", "module"),
                    setOf(AgentOperation.READ_FILE, AgentOperation.WRITE_FILE, AgentOperation.CREATE_FILE),
                    recursive = true,
                ),
            ),
        )
        val audit = AcpFilesystemAuditRecorder()

        AcpFilesystemBroker.open(request, AcpFilesystemLimits(), audit).use { broker ->
            val valid = runBlocking {
                broker.readTextFile("session", allowedSource.toString(), null, null)
            }
            assertEquals("allowed\n", valid.content)
            assertDenied {
                broker.readTextFile("session", "module/source.c", null, null)
            }
            assertDenied {
                broker.readTextFile("session", workspace.resolve("module/../evidence.json").toString(), null, null)
            }
            assertDenied {
                broker.readTextFile("session", outsideSecret.toString(), null, null)
            }
            assertDenied {
                broker.readTextFile("session", evidence.toString(), null, null)
            }
            assertDenied {
                broker.readTextFile("session", allowed.resolve("escape/secret.txt").toString(), null, null)
            }
            assertDenied {
                broker.writeTextFile("session", finalLink.toString(), "overwrite-attempt")
            }
        }

        assertEquals("outside-secret\n", outsideSecret.readText())
        assertTrue(finalLink.toFile().isFile)
        assertEquals(
            listOf(
                AcpFilesystemAuditReason.COMPLETED,
                AcpFilesystemAuditReason.INVALID_PATH,
                AcpFilesystemAuditReason.INVALID_PATH,
                AcpFilesystemAuditReason.OUTSIDE_WORKSPACE,
                AcpFilesystemAuditReason.POLICY_DENIED,
                AcpFilesystemAuditReason.SYMLINK_REJECTED,
                AcpFilesystemAuditReason.SYMLINK_REJECTED,
            ),
            audit.snapshot().map { it.reason },
        )
        assertEquals(AcpFilesystemAuditOutcome.ALLOWED, audit.snapshot().first().outcome)
        assertTrue(audit.snapshot().drop(1).all { it.outcome == AcpFilesystemAuditOutcome.DENIED })
    }

    @Test
    fun `an authorized directory component replaced after secure open is rejected deterministically`() {
        val parent = createTempDirectory("acp-fs-component-race-").toAbsolutePath().normalize()
        val workspace = parent.resolve("workspace").createDirectories()
        val outside = parent.resolve("outside").createDirectories()
        val scope = workspace.resolve("scope").createDirectories()
        scope.resolve("target.c").writeText("authorized-content\n")
        outside.resolve("target.c").writeText("outside-secret\n")
        val moved = workspace.resolve("scope-held")
        val fired = AtomicBoolean()
        val hook = AcpFilesystemRaceHook { stage, _ ->
            if (stage == AcpFilesystemRaceStage.AFTER_PARENT_OPENED && fired.compareAndSet(false, true)) {
                Files.move(scope, moved)
                scope.createSymbolicLinkPointingTo(outside)
            }
        }
        val request = request(workspace, listOf(rule("scope/target.c", AgentOperation.READ_FILE)))
        val audit = AcpFilesystemAuditRecorder()

        AcpFilesystemBroker.open(request, AcpFilesystemLimits(), audit, hook).use { broker ->
            assertDenied {
                broker.readTextFile("race-session", scope.resolve("target.c").toString(), null, null)
            }
        }

        assertTrue(fired.get())
        assertEquals("outside-secret\n", outside.resolve("target.c").readText())
        assertEquals("authorized-content\n", moved.resolve("target.c").readText())
        assertEquals(AcpFilesystemAuditReason.PATH_REPLACED, audit.snapshot().single().reason)
    }

    @Test
    fun `a final target swapped for an escape link at the exchange is restored and rejected`() {
        val parent = createTempDirectory("acp-fs-final-race-").toAbsolutePath().normalize()
        val workspace = parent.resolve("workspace").createDirectories()
        val outside = parent.resolve("outside.txt")
        outside.writeText("outside-stays\n")
        val target = workspace.resolve("target.c")
        target.writeText("old\n")
        val fired = AtomicBoolean()
        val hook = AcpFilesystemRaceHook { stage, _ ->
            if (stage == AcpFilesystemRaceStage.BEFORE_REPLACE_EXCHANGE && fired.compareAndSet(false, true)) {
                Files.delete(target)
                target.createSymbolicLinkPointingTo(outside)
            }
        }
        val request = request(workspace, listOf(rule("target.c", AgentOperation.WRITE_FILE)))
        val audit = AcpFilesystemAuditRecorder()

        AcpFilesystemBroker.open(request, AcpFilesystemLimits(), audit, hook).use { broker ->
            assertDenied { broker.writeTextFile("race-session", target.toString(), "new\n") }
        }

        assertTrue(fired.get())
        assertEquals("outside-stays\n", outside.readText())
        assertTrue(target.toFile().isFile)
        assertTrue(workspace.listDirectoryEntries().none { it.fileName.toString().startsWith(".decomp-acp-") })
        assertEquals(AcpFilesystemAuditReason.SYMLINK_REJECTED, audit.snapshot().single().reason)
    }

    @Test
    fun `the final read descriptor remains bound across a swap and restore at open`() {
        val workspace = createTempDirectory("acp-fs-read-open-race-").toAbsolutePath().normalize()
        val target = workspace.resolve("target.c")
        val held = workspace.resolve("target-held.c")
        val replacement = workspace.resolve("replacement.c")
        target.writeText("authorized-content\n")
        replacement.writeText("replacement-content\n")
        val beforeFired = AtomicBoolean()
        val afterFired = AtomicBoolean()
        val hook = AcpFilesystemRaceHook { stage, _ ->
            when (stage) {
                AcpFilesystemRaceStage.BEFORE_FINAL_OPEN -> {
                    if (beforeFired.compareAndSet(false, true)) {
                        Files.move(target, held)
                        Files.move(replacement, target)
                    }
                }

                AcpFilesystemRaceStage.AFTER_FINAL_OPEN -> {
                    if (afterFired.compareAndSet(false, true)) {
                        Files.move(target, replacement)
                        Files.move(held, target)
                    }
                }

                else -> Unit
            }
        }
        val audit = AcpFilesystemAuditRecorder()
        val request = request(workspace, listOf(rule("target.c", AgentOperation.READ_FILE)))

        AcpFilesystemBroker.open(request, AcpFilesystemLimits(), audit, hook).use { broker ->
            val response = runBlocking {
                broker.readTextFile("read-open-race", target.toString(), null, null)
            }
            assertEquals("authorized-content\n", response.content)
        }

        assertTrue(beforeFired.get())
        assertTrue(afterFired.get())
        assertEquals("authorized-content\n", target.readText())
        assertEquals("replacement-content\n", replacement.readText())
        assertEquals(AcpFilesystemAuditReason.COMPLETED, audit.snapshot().single().reason)
    }

    @Test
    fun `a fifo substituted at final read open is rejected without opening the fifo`() {
        val workspace = createTempDirectory("acp-fs-read-fifo-race-").toAbsolutePath().normalize()
        val target = workspace.resolve("target.c")
        val held = workspace.resolve("target-held.c")
        val fifo = workspace.resolve("replacement.fifo")
        target.writeText("authorized-content\n")
        val mkfifo = ProcessBuilder("mkfifo", fifo.toString()).start()
        assertEquals(0, mkfifo.waitFor())
        val fired = AtomicBoolean()
        val hook = AcpFilesystemRaceHook { stage, _ ->
            if (stage == AcpFilesystemRaceStage.BEFORE_FINAL_OPEN && fired.compareAndSet(false, true)) {
                Files.move(target, held)
                Files.move(fifo, target)
            }
        }
        val audit = AcpFilesystemAuditRecorder()
        val request = request(workspace, listOf(rule("target.c", AgentOperation.READ_FILE)))

        val started = System.nanoTime()
        AcpFilesystemBroker.open(request, AcpFilesystemLimits(), audit, hook).use { broker ->
            assertDenied { broker.readTextFile("fifo-race", target.toString(), null, null) }
        }
        val elapsedMillis = (System.nanoTime() - started) / 1_000_000

        assertTrue(fired.get())
        assertTrue(elapsedMillis < 2_000, "descriptor-bound read unexpectedly blocked for ${elapsedMillis}ms")
        assertEquals("authorized-content\n", held.readText())
        assertEquals(AcpFilesystemAuditReason.PATH_REPLACED, audit.snapshot().single().reason)
    }

    @Test
    fun `create no-replace preserves a target created at the native rename gap`() {
        val workspace = createTempDirectory("acp-fs-create-race-").toAbsolutePath().normalize()
        val target = workspace.resolve("target.c")
        val fired = AtomicBoolean()
        val hook = AcpFilesystemRaceHook { stage, _ ->
            if (stage == AcpFilesystemRaceStage.BEFORE_CREATE_RENAME && fired.compareAndSet(false, true)) {
                target.writeText("concurrent-create\n")
            }
        }
        val audit = AcpFilesystemAuditRecorder()
        val request = request(workspace, listOf(rule("target.c", AgentOperation.CREATE_FILE)))

        AcpFilesystemBroker.open(request, AcpFilesystemLimits(), audit, hook).use { broker ->
            assertDenied { broker.writeTextFile("create-race", target.toString(), "broker-content\n") }
        }

        assertTrue(fired.get())
        assertEquals("concurrent-create\n", target.readText())
        assertTrue(workspace.listDirectoryEntries().none { it.fileName.toString().startsWith(".decomp-acp-") })
        assertEquals(AcpFilesystemAuditReason.PATH_REPLACED, audit.snapshot().single().reason)
    }

    @Test
    fun `replacement exchange rolls back a target replaced at the native syscall gap`() {
        val workspace = createTempDirectory("acp-fs-replace-race-").toAbsolutePath().normalize()
        val target = workspace.resolve("target.c")
        val held = workspace.resolve("original-held.c")
        target.writeText("authorized-old\n")
        val fired = AtomicBoolean()
        val hook = AcpFilesystemRaceHook { stage, _ ->
            if (stage == AcpFilesystemRaceStage.BEFORE_REPLACE_EXCHANGE && fired.compareAndSet(false, true)) {
                Files.move(target, held)
                target.writeText("concurrent-replacement\n")
            }
        }
        val audit = AcpFilesystemAuditRecorder()
        val request = request(workspace, listOf(rule("target.c", AgentOperation.WRITE_FILE)))

        AcpFilesystemBroker.open(request, AcpFilesystemLimits(), audit, hook).use { broker ->
            assertDenied { broker.writeTextFile("replace-race", target.toString(), "broker-content\n") }
        }

        assertTrue(fired.get())
        assertEquals("concurrent-replacement\n", target.readText())
        assertEquals("authorized-old\n", held.readText())
        assertTrue(workspace.listDirectoryEntries().none { it.fileName.toString().startsWith(".decomp-acp-") })
        assertEquals(AcpFilesystemAuditReason.PATH_REPLACED, audit.snapshot().single().reason)
    }

    @Test
    fun `creates are mode 0600 and replacements preserve the existing POSIX mode`() {
        val workspace = createTempDirectory("acp-fs-mode-").toAbsolutePath().normalize()
        val created = workspace.resolve("created.c")
        val replaced = workspace.resolve("replaced.c")
        replaced.writeText("old\n")
        val preservedMode = PosixFilePermissions.fromString("rwxr-xr--")
        Files.setPosixFilePermissions(replaced, preservedMode)
        val sawCreateTemporary = AtomicBoolean()
        val hook = AcpFilesystemRaceHook { stage, requested ->
            if (stage == AcpFilesystemRaceStage.BEFORE_CREATE_RENAME && requested == created) {
                val temporary = workspace.listDirectoryEntries(".decomp-acp-*.tmp").single()
                assertEquals(
                    PosixFilePermissions.fromString("rw-------"),
                    Files.getPosixFilePermissions(temporary),
                )
                sawCreateTemporary.set(true)
            }
        }
        val audit = AcpFilesystemAuditRecorder()
        val request = request(
            workspace,
            listOf(
                rule("created.c", AgentOperation.CREATE_FILE),
                rule("replaced.c", AgentOperation.WRITE_FILE),
            ),
        )

        AcpFilesystemBroker.open(request, AcpFilesystemLimits(), audit, hook).use { broker ->
            runBlocking { broker.writeTextFile("mode", created.toString(), "created\n") }
            runBlocking { broker.writeTextFile("mode", replaced.toString(), "replaced\n") }
        }

        assertTrue(sawCreateTemporary.get())
        assertEquals(PosixFilePermissions.fromString("rw-------"), Files.getPosixFilePermissions(created))
        assertEquals(preservedMode, Files.getPosixFilePermissions(replaced))
        assertEquals("replaced\n", replaced.readText())
    }

    @Test
    fun `replacement rejects extended metadata instead of silently stripping it`() {
        val workspace = createTempDirectory("acp-fs-xattr-").toAbsolutePath().normalize()
        val target = workspace.resolve("target.c")
        target.writeText("old\n")
        val attributes = Files.getFileAttributeView(target, UserDefinedFileAttributeView::class.java)
        assertNotNull(attributes)
        attributes.write("decomp-test", ByteBuffer.wrap("metadata".toByteArray()))
        val audit = AcpFilesystemAuditRecorder()
        val request = request(workspace, listOf(rule("target.c", AgentOperation.WRITE_FILE)))

        AcpFilesystemBroker.open(request, AcpFilesystemLimits(), audit).use { broker ->
            assertDenied { broker.writeTextFile("metadata", target.toString(), "new\n") }
        }

        assertEquals("old\n", target.readText())
        assertTrue("decomp-test" in attributes.list())
        assertTrue(workspace.listDirectoryEntries().none { it.fileName.toString().startsWith(".decomp-acp-") })
        assertEquals(AcpFilesystemAuditReason.UNSUPPORTED_METADATA, audit.snapshot().single().reason)
    }

    @Test
    fun `temporary setup failures remove the owned name before returning an error`() {
        val stages = listOf(
            AcpFilesystemRaceStage.AFTER_TEMPORARY_OPEN,
            AcpFilesystemRaceStage.AFTER_TEMPORARY_CHMOD,
            AcpFilesystemRaceStage.AFTER_TEMPORARY_LINK,
        )
        val warmup = createTempDirectory("acp-fs-temp-setup-warmup-").toAbsolutePath().normalize()
        LinuxFilesystemSyscalls.requireSupported(warmup)
        val descriptorsBefore = openDescriptorCount()

        stages.forEachIndexed { index, injectedStage ->
            listOf(AgentOperation.CREATE_FILE, AgentOperation.WRITE_FILE).forEach { operation ->
                val workspace = createTempDirectory("acp-fs-temp-setup-failure-$index-")
                    .toAbsolutePath().normalize()
                val target = workspace.resolve("target.c")
                if (operation == AgentOperation.WRITE_FILE) target.writeText("original\n")
                val hook = AcpFilesystemRaceHook { stage, _ ->
                    if (stage == injectedStage) throw IOException("injected $injectedStage failure")
                }
                val audit = AcpFilesystemAuditRecorder()
                val request = request(workspace, listOf(rule("target.c", operation)))

                AcpFilesystemBroker.open(request, AcpFilesystemLimits(), audit, hook).use { broker ->
                    assertDenied { broker.writeTextFile("temp-setup-$index", target.toString(), "new\n") }
                }

                if (operation == AgentOperation.WRITE_FILE) {
                    assertEquals("original\n", target.readText(), "$injectedStage changed the replacement target")
                } else {
                    assertFalse(target.exists(), "$injectedStage created the target")
                }
                assertTrue(
                    workspace.listDirectoryEntries().none { it.fileName.toString().startsWith(".decomp-acp-") },
                    "$injectedStage left a partially initialized temporary",
                )
                assertEquals(AcpFilesystemAuditReason.IO_FAILURE, audit.snapshot().single().reason)
            }
        }

        assertTrue(openDescriptorCount() <= descriptorsBefore, "temporary setup failures leaked file descriptors")
    }

    @Test
    fun `every injected post-create failure restores absence and closes descriptors`() {
        val stages = listOf(
            AcpFilesystemRaceStage.AFTER_CREATE_RENAME,
            AcpFilesystemRaceStage.AFTER_INSTALLED_OPEN,
            AcpFilesystemRaceStage.AFTER_METADATA_VALIDATION,
        )
        val warmup = createTempDirectory("acp-fs-create-failure-warmup-").toAbsolutePath().normalize()
        LinuxFilesystemSyscalls.requireSupported(warmup)
        val descriptorsBefore = openDescriptorCount()

        stages.forEachIndexed { index, injectedStage ->
            val workspace = createTempDirectory("acp-fs-create-failure-$index-").toAbsolutePath().normalize()
            val target = workspace.resolve("target.c")
            val audit = AcpFilesystemAuditRecorder()
            val hook = AcpFilesystemRaceHook { stage, _ ->
                if (stage == injectedStage) throw IOException("injected $injectedStage failure")
            }
            val request = request(workspace, listOf(rule("target.c", AgentOperation.CREATE_FILE)))

            AcpFilesystemBroker.open(request, AcpFilesystemLimits(), audit, hook).use { broker ->
                assertDenied { broker.writeTextFile("create-failure-$index", target.toString(), "new\n") }
            }

            assertFalse(target.exists(), "$injectedStage left the create target installed")
            assertTrue(
                workspace.listDirectoryEntries().none { it.fileName.toString().startsWith(".decomp-acp-") },
                "$injectedStage left a transaction entry behind",
            )
            assertEquals(AcpFilesystemAuditReason.IO_FAILURE, audit.snapshot().single().reason)
        }

        assertTrue(openDescriptorCount() <= descriptorsBefore, "post-create failures leaked file descriptors")
    }

    @Test
    fun `every injected post-exchange failure restores the original and removes the temporary`() {
        val stages = listOf(
            AcpFilesystemRaceStage.AFTER_REPLACE_EXCHANGE,
            AcpFilesystemRaceStage.AFTER_DISPLACED_OPEN,
            AcpFilesystemRaceStage.AFTER_INSTALLED_OPEN,
            AcpFilesystemRaceStage.AFTER_METADATA_VALIDATION,
            AcpFilesystemRaceStage.BEFORE_OLD_UNLINK,
        )
        val descriptorsBefore = openDescriptorCount()

        stages.forEachIndexed { index, injectedStage ->
            val workspace = createTempDirectory("acp-fs-exchange-failure-$index-").toAbsolutePath().normalize()
            val target = workspace.resolve("target.c")
            target.writeText("original\n")
            val originalKey = Files.readAttributes(target, "unix:dev,ino")
            val audit = AcpFilesystemAuditRecorder()
            val hook = AcpFilesystemRaceHook { stage, _ ->
                if (stage == injectedStage) throw IOException("injected $injectedStage failure")
            }
            val request = request(workspace, listOf(rule("target.c", AgentOperation.WRITE_FILE)))

            AcpFilesystemBroker.open(request, AcpFilesystemLimits(), audit, hook).use { broker ->
                assertDenied { broker.writeTextFile("exchange-failure-$index", target.toString(), "new\n") }
            }

            assertEquals("original\n", target.readText(), "$injectedStage changed target content")
            assertEquals(originalKey, Files.readAttributes(target, "unix:dev,ino"))
            assertTrue(
                workspace.listDirectoryEntries().none { it.fileName.toString().startsWith(".decomp-acp-") },
                "$injectedStage left a transaction entry behind",
            )
            assertEquals(AcpFilesystemAuditReason.IO_FAILURE, audit.snapshot().single().reason)
        }

        assertTrue(openDescriptorCount() <= descriptorsBefore, "post-exchange failures leaked file descriptors")
    }

    @Test
    fun `cleanup quarantines and revalidates an owned name before unlinking`() {
        val workspace = createTempDirectory("acp-fs-cleanup-substitute-").toAbsolutePath().normalize()
        val target = workspace.resolve("target.c")
        val heldPreparedFile = workspace.resolve("held-prepared-file")
        val failedCommit = AtomicBoolean()
        val substituted = AtomicBoolean()
        val hook = AcpFilesystemRaceHook { stage, _ ->
            when (stage) {
                AcpFilesystemRaceStage.BEFORE_CREATE_RENAME -> {
                    if (failedCommit.compareAndSet(false, true)) {
                        throw IOException("force pre-commit cleanup")
                    }
                }

                AcpFilesystemRaceStage.BEFORE_OWNED_UNLINK -> {
                    if (substituted.compareAndSet(false, true)) {
                        val quarantine = workspace.listDirectoryEntries(".decomp-acp-quarantine-*.tmp").single()
                        Files.move(quarantine, heldPreparedFile)
                        quarantine.writeText("must-not-delete\n")
                    }
                }

                else -> Unit
            }
        }
        val audit = AcpFilesystemAuditRecorder()
        val request = request(workspace, listOf(rule("target.c", AgentOperation.CREATE_FILE)))

        AcpFilesystemBroker.open(request, AcpFilesystemLimits(), audit, hook).use { broker ->
            assertDenied { broker.writeTextFile("cleanup-substitute", target.toString(), "prepared\n") }
        }

        assertTrue(failedCommit.get())
        assertTrue(substituted.get())
        assertFalse(target.exists())
        assertEquals("prepared\n", heldPreparedFile.readText())
        val preservedSubstitute = workspace.listDirectoryEntries(".decomp-acp-*.tmp").single()
        assertEquals("must-not-delete\n", preservedSubstitute.readText())
        assertEquals(AcpFilesystemAuditReason.IO_FAILURE, audit.snapshot().single().reason)
    }

    @Test
    fun `cancellation at each rename commit point leaves the workspace unchanged`() {
        val createWorkspace = createTempDirectory("acp-fs-create-cancel-").toAbsolutePath().normalize()
        val createTarget = createWorkspace.resolve("target.c")
        val createCancellation = AgentCancellationSource()
        val createAudit = AcpFilesystemAuditRecorder()
        val createHook = AcpFilesystemRaceHook { stage, _ ->
            if (stage == AcpFilesystemRaceStage.BEFORE_CREATE_RENAME) createCancellation.cancel()
        }
        val createRequest = request(
            createWorkspace,
            listOf(rule("target.c", AgentOperation.CREATE_FILE)),
            createCancellation.cancellation,
        )
        AcpFilesystemBroker.open(createRequest, AcpFilesystemLimits(), createAudit, createHook).use { broker ->
            assertDenied { broker.writeTextFile("create-cancel", createTarget.toString(), "new\n") }
        }
        assertFalse(createTarget.exists())
        assertTrue(createWorkspace.listDirectoryEntries().none { it.fileName.toString().startsWith(".decomp-acp-") })
        assertEquals(AcpFilesystemAuditReason.CANCELLED, createAudit.snapshot().single().reason)

        val replaceWorkspace = createTempDirectory("acp-fs-replace-cancel-").toAbsolutePath().normalize()
        val replaceTarget = replaceWorkspace.resolve("target.c")
        replaceTarget.writeText("original\n")
        val replaceCancellation = AgentCancellationSource()
        val replaceAudit = AcpFilesystemAuditRecorder()
        val replaceHook = AcpFilesystemRaceHook { stage, _ ->
            if (stage == AcpFilesystemRaceStage.BEFORE_REPLACE_EXCHANGE) replaceCancellation.cancel()
        }
        val replaceRequest = request(
            replaceWorkspace,
            listOf(rule("target.c", AgentOperation.WRITE_FILE)),
            replaceCancellation.cancellation,
        )
        AcpFilesystemBroker.open(replaceRequest, AcpFilesystemLimits(), replaceAudit, replaceHook).use { broker ->
            assertDenied { broker.writeTextFile("replace-cancel", replaceTarget.toString(), "new\n") }
        }
        assertEquals("original\n", replaceTarget.readText())
        assertTrue(replaceWorkspace.listDirectoryEntries().none { it.fileName.toString().startsWith(".decomp-acp-") })
        assertEquals(AcpFilesystemAuditReason.CANCELLED, replaceAudit.snapshot().single().reason)
    }

    @Test
    fun `reads reject hard links even when the authorized name is contained`() {
        val parent = createTempDirectory("acp-fs-hardlink-read-").toAbsolutePath().normalize()
        val workspace = parent.resolve("workspace").createDirectories()
        val outside = parent.resolve("outside-secret.txt")
        outside.writeText("outside-secret\n")
        val linked = workspace.resolve("linked.txt")
        Files.createLink(linked, outside)
        val audit = AcpFilesystemAuditRecorder()
        val request = request(workspace, listOf(rule("linked.txt", AgentOperation.READ_FILE)))

        AcpFilesystemBroker.open(request, AcpFilesystemLimits(), audit).use { broker ->
            assertDenied { broker.readTextFile("hardlink", linked.toString(), null, null) }
        }

        assertEquals("outside-secret\n", outside.readText())
        assertEquals(AcpFilesystemAuditReason.UNSUPPORTED_METADATA, audit.snapshot().single().reason)
    }

    @Test
    fun `bind mounts beneath a root are rejected for reads and writes`() {
        val java = Path.of(System.getProperty("java.home"), "bin", "java").toString()
        val process = ProcessBuilder(
            "unshare",
            "--user",
            "--map-root-user",
            "--mount",
            "--fork",
            "--",
            java,
            "-cp",
            System.getProperty("java.class.path"),
            "decompengine.acp.AcpFilesystemMountProbe",
        ).redirectErrorStream(true).start()
        val output = process.inputStream.bufferedReader().readText()
        val exitCode = process.waitFor()
        assertEquals(0, exitCode, output)
    }

    @Test
    fun `reserved descriptors recover from native EMFILE immediately after each commit rename`() {
        val java = Path.of(System.getProperty("java.home"), "bin", "java").toString()
        val process = ProcessBuilder(
            "prlimit",
            "--nofile=64:64",
            "--",
            java,
            "-cp",
            System.getProperty("java.class.path"),
            "decompengine.acp.AcpFilesystemDescriptorPressureProbe",
        ).redirectErrorStream(true).start()
        val output = process.inputStream.bufferedReader().readText()
        val exitCode = process.waitFor()
        assertEquals(0, exitCode, output)
    }

    @Test
    fun `platform support detection cannot rename a prepared working-directory entry`() {
        val workingDirectory = createTempDirectory("acp-fs-support-probe-").toAbsolutePath().normalize()
        val java = Path.of(System.getProperty("java.home"), "bin", "java").toString()
        val process = ProcessBuilder(
            java,
            "-cp",
            System.getProperty("java.class.path"),
            "decompengine.acp.AcpFilesystemSupportProbe",
        ).directory(workingDirectory.toFile()).redirectErrorStream(true).start()
        val output = process.inputStream.bufferedReader().readText()
        val exitCode = process.waitFor()
        assertEquals(0, exitCode, output)
    }

    @Test
    fun `text and byte bounds fail safely and workspace root links are refused`() {
        val workspace = createTempDirectory("acp-fs-bounds-").toAbsolutePath().normalize()
        val invalid = workspace.resolve("invalid.txt")
        invalid.writeBytes(byteArrayOf(0xc3.toByte(), 0x28))
        val request = request(
            workspace,
            listOf(rule("invalid.txt", AgentOperation.READ_FILE, AgentOperation.WRITE_FILE)),
        )
        val audit = AcpFilesystemAuditRecorder()
        AcpFilesystemBroker.open(request, AcpFilesystemLimits(maximumReadBytes = 1, maximumWriteBytes = 1), audit)
            .use { broker ->
                assertDenied { broker.readTextFile("bounds", invalid.toString(), null, null) }
                assertDenied { broker.writeTextFile("bounds", invalid.toString(), "too large") }
                assertDenied { broker.writeTextFile("bounds", invalid.toString(), "\uD800") }
            }
        assertEquals(
            listOf(
                AcpFilesystemAuditReason.RESOURCE_LIMIT,
                AcpFilesystemAuditReason.RESOURCE_LIMIT,
                AcpFilesystemAuditReason.INVALID_TEXT,
            ),
            audit.snapshot().map { it.reason },
        )

        val invalidTextAudit = AcpFilesystemAuditRecorder()
        AcpFilesystemBroker.open(
            request,
            AcpFilesystemLimits(maximumReadBytes = 16, maximumWriteBytes = 16),
            invalidTextAudit,
        ).use { broker ->
            assertDenied { broker.readTextFile("invalid-text", invalid.toString(), null, null) }
        }
        assertEquals(AcpFilesystemAuditReason.INVALID_TEXT, invalidTextAudit.snapshot().single().reason)

        val realRoot = createTempDirectory("acp-fs-real-root-").toAbsolutePath().normalize()
        realRoot.resolve("source.c").writeText("source\n")
        val rootLink = realRoot.parent.resolve("${realRoot.fileName}-link")
        rootLink.createSymbolicLinkPointingTo(realRoot)
        val linkedRequest = request(rootLink, listOf(rule("source.c", AgentOperation.READ_FILE)))
        val failure = assertFailsWith<decompengine.agent.AgentExecutionException> {
            AcpFilesystemBroker.open(linkedRequest, AcpFilesystemLimits(), AcpFilesystemAuditRecorder())
        }
        assertEquals(decompengine.agent.AgentFailureKind.CONFIGURATION, failure.failure.kind)
    }

    private fun request(
        workspace: Path,
        rules: List<AgentPathRule>,
        cancellation: AgentCancellation = AgentCancellation.NONE,
    ): AgentExecutionRequest = AgentExecutionRequest(
        objective = "exercise the filesystem broker",
        workspaceRoots = listOf(AgentWorkspaceRoot("project", workspace)),
        accessPolicy = AgentAccessPolicy(rules),
        cancellation = cancellation,
    )

    private fun rule(path: String, vararg operations: AgentOperation): AgentPathRule =
        AgentPathRule(AgentWorkspacePath("project", path), operations.toSet())

    private fun assertDenied(block: suspend () -> Unit) {
        assertFailsWith<AcpExpectedError> { runBlocking { block() } }
    }

    private fun openDescriptorCount(): Long = Files.list(Path.of("/proc/self/fd")).use { it.count() }
}
