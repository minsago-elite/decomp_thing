package decompengine.oracle.gcc

import decompengine.acp.LinuxFilesystemSyscalls
import decompengine.oracle.core.OracleArtifacts
import decompengine.oracle.core.OracleJson
import decompengine.project.GeneratedCMakeReconstructionProfile
import decompengine.project.RecoveredFunction
import decompengine.project.RecoveredProgramModel
import java.nio.file.Files
import java.nio.file.Path
import java.nio.file.attribute.PosixFilePermissions
import kotlin.test.Test
import kotlin.test.assertContentEquals
import kotlin.test.assertEquals
import kotlin.test.assertFails
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

    private fun fixture(action: (Path, GccBundledPlannerRequest, ByteArray) -> Unit) {
        val root = Files.createTempDirectory("gcc-planner-capture-").toRealPath()
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
