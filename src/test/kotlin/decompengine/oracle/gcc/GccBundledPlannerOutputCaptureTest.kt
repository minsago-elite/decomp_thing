package decompengine.oracle.gcc

import decompengine.acp.LinuxFilesystemSyscalls
import decompengine.oracle.core.OracleArtifacts
import decompengine.oracle.core.OracleJson
import decompengine.oracle.fulltree.ContainedCommandOperationDeadline
import decompengine.project.GeneratedCMakeReconstructionProfile
import decompengine.project.RecoveredFunction
import decompengine.project.RecoveredProgramModel
import java.nio.file.Files
import java.nio.file.Path
import java.nio.file.attribute.PosixFilePermissions
import java.util.concurrent.CountDownLatch
import java.util.concurrent.TimeUnit
import kotlin.test.Test
import kotlin.test.assertContentEquals
import kotlin.test.assertEquals
import kotlin.test.assertFails
import kotlin.test.assertFalse
import kotlin.test.assertFailsWith
import kotlin.test.assertSame
import kotlin.test.assertTrue
import kotlinx.serialization.json.jsonObject
import kotlinx.serialization.json.jsonPrimitive

class GccBundledPlannerOutputCaptureTest {
    @Test
    fun `capture returns descriptor checked bytes with linked assessment and bounded logs`() = fixture { root, request, model ->
        LinuxFilesystemSyscalls.openAbsolutePathOrNull(root)!!.use { run ->
            LinuxFilesystemSyscalls.openDirectoryAt(run.fd, CONTROL).use { control ->
                val result = GccBundledPlannerOutputCapture.capture(run, CONTROL, control.identity, request, model, 4, 0)
                val expected = Files.readAllBytes(request.outputDirectory.resolve("module_plan.json"))
                assertContentEquals(expected, result.planBytes)
                result.planBytes.fill(0)
                assertContentEquals(expected, result.planBytes)
                val document = OracleJson.parseCanonical(result.canonicalBytes).jsonObject
                assertEquals("false", document.getValue("complete").jsonPrimitive.content)
                assertEquals("false", document.getValue("releaseEligible").jsonPrimitive.content)
                assertEquals(OracleArtifacts.sha256(expected), document.getValue("planSha256").jsonPrimitive.content)
                assertEquals("4", document.getValue("stdoutBytes").jsonPrimitive.content)
                assertFails { GccBundledPlannerOutputCapture.capture(run, CONTROL, control.identity, request, model, 3, 0) }
                assertFails { GccBundledPlannerOutputCapture.capture(run, "../$CONTROL", control.identity, request, model, 4, 0) }
            }
        }
    }

    @Test
    fun `capture rejects missing extra linked and writable output without changing source bytes`() {
        for (change in listOf("missing", "extra", "symlink", "hardlink", "writable", "metadata", "directory")) fixture { root, request, model ->
            val output = request.outputDirectory
            val plan = output.resolve("module_plan.json")
            val original = Files.readAllBytes(plan)
            when (change) {
                "missing" -> Files.delete(output.resolve("planner-output.json"))
                "extra" -> Files.writeString(output.resolve(".module_plan.json.pending"), "partial")
                "symlink" -> { Files.move(plan, root.resolve("original")); Files.createSymbolicLink(plan, root.resolve("original")) }
                "hardlink" -> Files.createLink(root.resolve("linked"), plan)
                "writable" -> Files.setPosixFilePermissions(plan, PosixFilePermissions.fromString("rw-rw-r--"))
                "metadata" -> Files.writeString(output.resolve("planner-output.json"), "{}")
                "directory" -> Files.setPosixFilePermissions(output, PosixFilePermissions.fromString("rwxr-xr-x"))
            }
            LinuxFilesystemSyscalls.openAbsolutePathOrNull(root)!!.use { run ->
                LinuxFilesystemSyscalls.openDirectoryAt(run.fd, CONTROL).use { control ->
                    assertFails(change) { GccBundledPlannerOutputCapture.capture(run, CONTROL, control.identity, request, model, 4, 0) }
                }
            }
            assertContentEquals(original, Files.readAllBytes(plan))
        }
    }

    @Test
    fun `capture denies replaced control identity and renamed run path`() = fixture { root, request, model ->
        LinuxFilesystemSyscalls.openAbsolutePathOrNull(root)!!.use { run ->
            LinuxFilesystemSyscalls.openDirectoryAt(run.fd, CONTROL).use { control ->
                Files.move(root.resolve(CONTROL), root.resolve("old-control"))
                Files.createDirectory(root.resolve(CONTROL), PosixFilePermissions.asFileAttribute(PosixFilePermissions.fromString("rwx------")))
                assertFails { GccBundledPlannerOutputCapture.capture(run, CONTROL, control.identity, request, model, 4, 0) }
                Files.delete(root.resolve(CONTROL))
                Files.move(root.resolve("old-control"), root.resolve(CONTROL))
                val moved = root.resolveSibling(root.fileName.toString() + "-moved")
                Files.move(root, moved)
                try {
                    assertFails { GccBundledPlannerOutputCapture.capture(run, CONTROL, control.identity, request, model, 4, 0) }
                } finally { Files.move(moved, root) }
            }
        }
    }

    @Test
    fun `shared descriptor reader rejects same bytes inode replacement after capture`() = fixture { root, request, _ ->
        LinuxFilesystemSyscalls.openAbsolutePathOrNull(request.outputDirectory)!!.use { reports ->
            val files = GccBoundExportFiles(1024 * 1024)
            val bytes = files.read(reports, "module_plan.json", 1024 * 1024)
            val path = request.outputDirectory.resolve("module_plan.json")
            Files.move(path, root.resolve("previous-plan"))
            Files.write(path, bytes)
            assertFails { files.verify() }
        }
    }

    @Test
    fun `planner capture checkpoints preserve exact descriptor and assessment commitments`() = fixture { root, request, model ->
        LinuxFilesystemSyscalls.openAbsolutePathOrNull(root)!!.use { run ->
            LinuxFilesystemSyscalls.openDirectoryAt(run.fd, CONTROL).use { control ->
                val baseline = GccBundledPlannerOutputCapture.capture(run, CONTROL, control.identity, request, model, 4, 0)
                val stages = mutableSetOf<String>()
                val checked = GccBundledPlannerOutputCapture.capture(run, CONTROL, control.identity, request, model, 4, 0) { stages += it }
                assertContentEquals(baseline.planBytes, checked.planBytes)
                assertContentEquals(baseline.canonicalBytes, checked.canonicalBytes)
                assertTrue("reading planner output file" in stages)
                assertTrue("before opening program model JSON parser" in stages)
                assertTrue("before planner plan validation" in stages)
                assertTrue("after module plan ownership" in stages)
                assertTrue("before returning captured planner output" in stages)
            }
        }
    }

    @Test
    fun `planner capture refuses expired handoffs without changing any producer evidence`() = fixture { root, request, model ->
        val names = listOf("module_plan.json", "planner-output.json", "contained-command.stdout", "contained-command.stderr")
        val before = names.associateWith { Files.readAllBytes(request.outputDirectory.resolve(it)) }
        LinuxFilesystemSyscalls.openAbsolutePathOrNull(root)!!.use { run ->
            LinuxFilesystemSyscalls.openDirectoryAt(run.fd, CONTROL).use { control ->
                for (target in listOf("before planner output capture", "reading planner output file", "before planner assessment",
                    "before opening program model JSON parser", "before planner plan validation", "after module plan ownership",
                    "before returning captured planner output")) {
                    var now = 0L
                    val deadline = ContainedCommandOperationDeadline(2_000) { now }
                    var reached = false
                    val failure = assertFailsWith<IllegalStateException> {
                        GccBundledPlannerOutputCapture.capture(run, CONTROL, control.identity, request, model, 4, 0) { stage ->
                            if (stage == target) { reached = true; now = 2_000_000_000L }
                            deadline.requireCurrent()
                        }
                    }
                    assertTrue(reached, target)
                    assertTrue(failure.message.orEmpty().contains("deadline expired or clock regressed"), target)
                    for (name in names) assertContentEquals(before.getValue(name), Files.readAllBytes(request.outputDirectory.resolve(name)))
                }
            }
        }
    }

    @Test
    fun `descriptor capture checks the admitted deadline between bounded read requests`() = fixture { root, _, _ ->
        val bytes = ByteArray(2 * 64 * 1024 + 1) { (it % 251).toByte() }
        val path = Files.write(root.resolve("large.capture"), bytes)
        LinuxFilesystemSyscalls.openAbsolutePathOrNull(root)!!.use { directory ->
            var calls = 0
            val complete = GccBoundExportFiles(bytes.size.toLong()) { calls++ }.read(directory, "large.capture", bytes.size)
            assertContentEquals(bytes, complete)
            assertTrue(calls >= 5, "the input must require at least three bounded reads plus admission/verification")
            var now = 0L
            val deadline = ContainedCommandOperationDeadline(2_000) { now }
            var checked = 0
            val failure = assertFailsWith<IllegalStateException> {
                GccBoundExportFiles(bytes.size.toLong()) {
                    if (++checked == 3) now = 2_000_000_000L
                    deadline.requireCurrent()
                }.read(directory, "large.capture", bytes.size)
            }
            assertEquals(3, checked)
            assertTrue(failure.message.orEmpty().contains("deadline expired or clock regressed"))
            assertContentEquals(bytes, Files.readAllBytes(path))
        }
    }

    @Test
    fun `planner capture over its host memory budget is refused before the refused allocation`() = fixture { root, request, model ->
        val names = listOf("module_plan.json", "planner-output.json", "contained-command.stdout", "contained-command.stderr")
        val before = names.associateWith { Files.readAllBytes(request.outputDirectory.resolve(it)) }
        val reserved = GccBundledHostMemoryBudget.WORKING_RESERVATION_BYTES
        val charge = 1 + GccBundledPlannerOutputCapture.ASSESSMENT_ALLOCATION_PER_INPUT_BYTE
        val planBytes = before.getValue("module_plan.json").size.toLong()
        val metadataBytes = before.getValue("planner-output.json").size.toLong()
        val exact = reserved + charge * (model.size + planBytes + metadataBytes) + 2 * 64 * 1024
        LinuxFilesystemSyscalls.openAbsolutePathOrNull(root)!!.use { run ->
            LinuxFilesystemSyscalls.openDirectoryAt(run.fd, CONTROL).use { control ->
                fun capture(maximum: Long, allocated: () -> Long) = GccBundledPlannerOutputCapture.capture(run, CONTROL,
                    control.identity, request, model, 4, 0, GccBundledHostMemoryBudget(maximum, allocated)) {}
                fun refusal(maximum: Long) = assertFailsWith<GccBundledHostMemoryBudgetException> { capture(maximum) { 0L } }.message.orEmpty()
                val baseline = GccBundledPlannerOutputCapture.capture(run, CONTROL, control.identity, request, model, 4, 0)
                assertContentEquals(baseline.canonicalBytes, capture(exact, ::currentThreadAllocatedBytes).canonicalBytes)
                assertTrue(refusal(reserved + charge * model.size - 1).contains("captured model copy and assessment"))
                // The plan buffer and its assessment allowance are charged from the pinned size before allocation.
                val plan = refusal(reserved + charge * (model.size + planBytes) - 1)
                assertTrue(plan.contains("planner output file read and assessment needs ${charge * planBytes} bytes"), plan)
                assertTrue(refusal(exact - 1).contains("planner log digest buffer"))
                val measured = assertFailsWith<GccBundledHostMemoryBudgetException> {
                    var checks = 0
                    capture(Long.MAX_VALUE / 2) { if (++checks >= 4) Long.MAX_VALUE / 8 else 0L }
                }
                assertTrue(measured.message.orEmpty().contains("beyond its"), measured.toString())
            }
        }
        for (name in names) assertContentEquals(before.getValue(name), Files.readAllBytes(request.outputDirectory.resolve(name)))
    }

    @Test
    fun `owned planner capture copies the model only after admitting its authenticated size`() = fixture { root, request, model ->
        val charge = 1 + GccBundledPlannerOutputCapture.ASSESSMENT_ALLOCATION_PER_INPUT_BYTE
        LinuxFilesystemSyscalls.openAbsolutePathOrNull(root)!!.use { run ->
            LinuxFilesystemSyscalls.openDirectoryAt(run.fd, CONTROL).use { control ->
                val tracker = GccBundledHostWorkTracker()
                var copied = false
                val failure = assertFailsWith<GccBundledHostMemoryBudgetException> {
                    GccBundledPlannerOutputCapture.captureOwned(tracker, LinuxFilesystemSyscalls.duplicate(run), CONTROL,
                        control.identity, request, { copied = true; model.copyOf() }, 4, 0,
                        GccBundledHostMemoryBudget.WORKING_RESERVATION_BYTES + charge * model.size - 1, ContainedCommandOperationDeadline(2_000))
                }
                assertTrue(failure.message.orEmpty().contains("captured model copy and assessment"), failure.toString())
                assertFalse(copied, "the model copy must follow its admission")
                tracker.requireRetired(5_000)
            }
        }
    }

    @Test
    fun `planner logs are digested through a bounded buffer instead of retained`() = fixture { root, request, model ->
        val stdout = ByteArray(24 * 1024 * 1024) { (it % 251).toByte() }
        Files.write(request.outputDirectory.resolve("contained-command.stdout"), stdout)
        LinuxFilesystemSyscalls.openAbsolutePathOrNull(root)!!.use { run ->
            LinuxFilesystemSyscalls.openDirectoryAt(run.fd, CONTROL).use { control ->
                val result = GccBundledPlannerOutputCapture.capture(run, CONTROL, control.identity, request, model, stdout.size, 0,
                    GccBundledHostMemoryBudget(32L * 1024 * 1024)) {}
                val document = OracleJson.parseCanonical(result.canonicalBytes).jsonObject
                assertEquals(stdout.size.toString(), document.getValue("stdoutBytes").jsonPrimitive.content)
                assertEquals(OracleArtifacts.sha256(stdout), document.getValue("stdoutSha256").jsonPrimitive.content)
                assertEquals(OracleArtifacts.sha256(byteArrayOf()), document.getValue("stderrSha256").jsonPrimitive.content)
            }
        }
    }

    @Test
    fun `owned planner capture matches direct capture and bounds a blocked read while keeping ownership`() = fixture { root, request, model ->
        LinuxFilesystemSyscalls.openAbsolutePathOrNull(root)!!.use { run ->
            LinuxFilesystemSyscalls.openDirectoryAt(run.fd, CONTROL).use { control ->
                val direct = GccBundledPlannerOutputCapture.capture(run, CONTROL, control.identity, request, model, 4, 0)
                val tracker = GccBundledHostWorkTracker()
                val owned = GccBundledPlannerOutputCapture.captureOwned(tracker, LinuxFilesystemSyscalls.duplicate(run), CONTROL,
                    control.identity, request, { model }, 4, 0, 1024L * 1024 * 1024, ContainedCommandOperationDeadline(2_000))
                assertContentEquals(direct.planBytes, owned.planBytes)
                assertContentEquals(direct.canonicalBytes, owned.canonicalBytes)
                tracker.requireRetired(5_000)

                val blocked = CountDownLatch(1)
                val release = CountDownLatch(1)
                val stages = java.util.Collections.synchronizedList(mutableListOf<String>())
                val started = System.nanoTime()
                assertFailsWith<GccBundledHostWorkTimeoutException> {
                    GccBundledPlannerOutputCapture.captureOwned(tracker, LinuxFilesystemSyscalls.duplicate(run), CONTROL,
                        control.identity, request, { model }, 4, 0, 1024L * 1024 * 1024, ContainedCommandOperationDeadline(2_000) { 0L }) { stage ->
                        stages += stage
                        if (stage == "reading planner output file" && blocked.count != 0L) {
                            blocked.countDown()
                            while (true) try { if (release.await(10, TimeUnit.SECONDS)) break } catch (_: InterruptedException) { }
                        }
                    }
                }
                val elapsedMillis = TimeUnit.NANOSECONDS.toMillis(System.nanoTime() - started)
                assertTrue(blocked.count == 0L && elapsedMillis in 2_000..12_000, "elapsed $elapsedMillis ms")
                assertEquals(listOf("planner output capture"), tracker.inFlightStages)
                assertFailsWith<IllegalStateException> { tracker.requireRetired(50) }
                release.countDown()
                tracker.requireRetired(10_000)
                assertTrue("before planner assessment" !in stages, "an abandoned capture stops at its next checkpoint")
            }
        }
    }

    private fun fixture(action: (Path, GccBundledPlannerRequest, ByteArray) -> Unit) {
        val scratch = Path.of("build/test-tmp").toAbsolutePath().normalize()
        Files.createDirectories(scratch)
        val root = Files.createTempDirectory(scratch, "gcc-planner-capture-").toRealPath()
        try {
            val privateMode = PosixFilePermissions.asFileAttribute(PosixFilePermissions.fromString("rwx------"))
            val control = Files.createDirectory(root.resolve(CONTROL), privateMode)
            val output = Files.createDirectory(control.resolve("reports"), privateMode)
            val model = RecoveredProgramModel(inputSha256 = SHA, functions = listOf(
                RecoveredFunction("fn1", "entry", 1u, "void entry(void)"))).toJson().toByteArray()
            val modelPath = Files.write(root.resolve("model.json"), model)
            val request = GccBundledPlannerRequest(modelPath, output, model.size, OracleArtifacts.sha256(model), SHA,
                1, SHA, SHA, GeneratedCMakeReconstructionProfile.descriptor.layout, 24, 100, 1000, 10000, 1024 * 1024)
            val requestPath = Files.write(root.resolve("request.json"), request.canonicalBytes)
            GccBundledPlannerWorker.main(arrayOf(requestPath.toString(), OracleArtifacts.sha256(request.canonicalBytes)))
            // Authored log files test capture only, not the contained launcher's process-absence proof.
            Files.writeString(output.resolve("contained-command.stdout"), "done")
            Files.write(output.resolve("contained-command.stderr"), byteArrayOf())
            action(root, request, model)
        } finally { Files.walk(root).use { paths -> paths.sorted(Comparator.reverseOrder()).forEach(Files::delete) } }
    }

    private companion object {
        const val SHA = "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"
        const val CONTROL = "control-$SHA"
    }
}
