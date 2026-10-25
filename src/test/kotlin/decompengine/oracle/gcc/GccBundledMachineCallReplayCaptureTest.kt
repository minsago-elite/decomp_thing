package decompengine.oracle.gcc

import decompengine.acp.LinuxFilesystemSyscalls
import decompengine.analysis.BundledGhidra
import decompengine.oracle.core.OracleArtifacts
import decompengine.oracle.core.OracleJson
import decompengine.oracle.machinecalls.IndependentMachineCallRequestV1
import decompengine.oracle.machinecalls.MachineCallFileV1
import decompengine.oracle.machinecalls.MachineCallRuntimeV1
import decompengine.oracle.machinecalls.withMachineCallComponentFixtureV1
import decompengine.oracle.structural.VerifiedStructuralInputsV1
import java.nio.file.Files
import java.nio.file.Path
import java.nio.file.StandardCopyOption
import java.nio.file.attribute.PosixFilePermissions
import kotlin.test.*
import kotlinx.serialization.json.*

class GccBundledMachineCallReplayCaptureTest {
    @Test fun `owned output capture preserves component bytes without promoting its authority`() = fixture { f ->
        val captured = f.capture()
        assertContentEquals(f.bytes, captured.reportBytes)
        val first = captured.reportBytes
        first.fill(0)
        assertContentEquals(f.bytes, captured.reportBytes)
        val report = OracleJson.parseCanonical(captured.reportBytes).jsonObject
        assertEquals(JsonPrimitive(false), report["negativeCompleteness"])
        assertEquals(JsonPrimitive(false), report["complete"])
        val assessment = OracleJson.parseCanonical(captured.assessmentBytes).jsonObject
        assertEquals(JsonPrimitive(false), assessment["scored"])
        assertEquals(JsonPrimitive(OracleArtifacts.sha256(f.bytes)), assessment["reportSha256"])
    }

    @Test fun `changed request and substituted producer report cannot reuse a captured commitment`() {
        fixture { f ->
            assertFails { f.capture(f.request.copy(richFile = f.request.richFile.copy(sha256 = "f".repeat(64)))) }
        }
        fixture { f ->
            val parsed = OracleJson.parseCanonical(f.bytes).jsonObject
            f.writeReport(OracleJson.canonicalBytes(JsonObject(parsed + ("inputSha256" to JsonPrimitive("f".repeat(64))))))
            assertFails { f.capture() }
        }
        fixture { f ->
            assertFails { f.capture(f.request.copy(limits = f.request.limits.copy(maximumOutputBytes = 128))) }
        }
    }

    @Test fun `output capture refuses extra files aliases symlinks and nonprivate directories`() {
        val mutations = listOf<(Fixture) -> Unit>(
            { Files.writeString(it.reports.resolve("extra.json"), "{}") },
            { Files.createLink(it.root.resolve("alias"), it.request.outputPath) },
            { val original = it.root.resolve("original"); Files.move(it.request.outputPath, original)
                Files.createSymbolicLink(it.request.outputPath, original) },
            { Files.setPosixFilePermissions(it.reports, PosixFilePermissions.fromString("rwxr-xr-x")) },
            { Files.setPosixFilePermissions(it.request.outputPath, PosixFilePermissions.fromString("rw-rw----")) },
        )
        for (mutate in mutations) fixture { f -> mutate(f); assertFails { f.capture() } }
    }

    @Test fun `cancellation interrupts capture before returning owned evidence`() = fixture { f ->
        var checks = 0
        assertFailsWith<InterruptedException> {
            f.capture(checkpoint = { if (++checks >= 2) throw InterruptedException("cancel authored capture") })
        }
    }

    @Test fun `public producer operation constructors require existing guarded operations and capability`() {
        val constructors = GccBundledMachineCallReplayOperation::class.java.constructors
        assertTrue(constructors.isNotEmpty())
        for (constructor in constructors) {
            val parameters = constructor.parameterTypes
            assertTrue(GccBundledNativeClaimFreezeOperation::class.java in parameters)
            assertTrue(VerifiedStructuralInputsV1::class.java in parameters)
            assertTrue(IndependentMachineCallRequestV1::class.java in parameters)
            assertFails { constructor.newInstance(*arrayOfNulls<Any>(parameters.size)) }
        }
    }

    @Test fun `retained producer capture rejects identical-byte substitution before external composition`() = fixture { f ->
        val capture = f.capture()
        val replacement = Files.write(f.root.resolve("replacement"), f.bytes)
        Files.setPosixFilePermissions(replacement, PosixFilePermissions.fromString("rw-------"))
        Files.move(replacement, f.request.outputPath, StandardCopyOption.REPLACE_EXISTING)
        LinuxFilesystemSyscalls.openRoot(f.root).use { run ->
            assertFails { GccBundledMachineCallReplayOutputCapture.requireUnchanged(run, capture) }
        }
    }

    @Test fun `last producer capture callback cannot replace a previously checked report`() = fixture { f ->
        var total = 0
        f.capture(checkpoint = { total++ })
        var seen = 0
        assertFails {
            f.capture(checkpoint = {
                if (++seen == total) {
                    val replacement = Files.write(f.root.resolve("replacement"), f.bytes)
                    Files.setPosixFilePermissions(replacement, PosixFilePermissions.fromString("rw-------"))
                    Files.move(replacement, f.request.outputPath, StandardCopyOption.REPLACE_EXISTING)
                }
            })
        }
        assertEquals(total, seen)
    }

    private class Fixture(val root: Path, val reports: Path, val controlName: String,
        val request: IndependentMachineCallRequestV1, val bytes: ByteArray) {
        fun writeReport(value: ByteArray) {
            Files.write(request.outputPath, value)
            Files.setPosixFilePermissions(request.outputPath, PosixFilePermissions.fromString("rw-------"))
        }
        fun capture(selected: IndependentMachineCallRequestV1 = request, checkpoint: () -> Unit = {}): GccBundledMachineCallReplayCapture =
            LinuxFilesystemSyscalls.openRoot(root).use { run ->
                LinuxFilesystemSyscalls.openDirectoryAt(run.fd, controlName).use { control ->
                    GccBundledMachineCallReplayOutputCapture.capture(run, controlName, control.identity, selected, checkpoint)
                }
            }
    }

    private fun fixture(action: (Fixture) -> Unit) = withMachineCallComponentFixtureV1 { component ->
        val base = Files.createDirectories(Path.of("build/task-tmp/machine-call-capture-tests").toAbsolutePath())
        val root = Files.createTempDirectory(base, "capture-").toRealPath()
        fun directory(path: Path): Path = Files.createDirectories(path).also {
            Files.setPosixFilePermissions(it, PosixFilePermissions.fromString("rwx------"))
        }
        directory(root)
        val controlName = "control-" + "a".repeat(64)
        val reports = directory(directory(root.resolve(controlName)).resolve("reports"))
        try {
            val request = IndependentMachineCallRequestV1(
                MachineCallFileV1(root.resolve("rich"), component.getValue("inputBytes").jsonPrimitive.long,
                    component.getValue("inputSha256").jsonPrimitive.content),
                MachineCallFileV1(root.resolve("oracle"), 1, component.getValue("canonicalOracleSha256").jsonPrimitive.content),
                component.getValue("artifactManifestSha256").jsonPrimitive.content,
                MachineCallRuntimeV1(root.resolve("bundle"), root.resolve("archive"), BundledGhidra.ARCHIVE_SHA256,
                    569445154L, "b".repeat(64), "c".repeat(64), "x86:LE:64:default", "4.8"),
                reports.resolve(GccBundledMachineCallReplayOutputCapture.REPORT_NAME))
            val bytes = OracleJson.canonicalBytes(JsonObject(component + mapOf(
                "requestSha256" to JsonPrimitive(OracleArtifacts.sha256(request.canonicalBytes)),
                "runtime" to request.runtime.json(),
                "decoderAuthentication" to JsonPrimitive("authenticated-bundled-worker-v1"),
                "containmentStatus" to JsonPrimitive("external-owner-required"),
            )))
            val fixture = Fixture(root, reports, controlName, request, bytes)
            fixture.writeReport(bytes)
            for (name in listOf("contained-command.stdout", "contained-command.stderr")) {
                val file = Files.write(reports.resolve(name), byteArrayOf())
                Files.setPosixFilePermissions(file, PosixFilePermissions.fromString("rw-------"))
            }
            action(fixture)
        } finally {
            Files.walk(root).use { paths -> paths.sorted(Comparator.reverseOrder()).forEach(Files::deleteIfExists) }
        }
    }
}
