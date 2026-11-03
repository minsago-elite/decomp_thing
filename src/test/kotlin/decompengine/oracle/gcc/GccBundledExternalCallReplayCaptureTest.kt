package decompengine.oracle.gcc

import decompengine.acp.LinuxFilesystemSyscalls
import decompengine.oracle.core.OracleArtifacts
import decompengine.oracle.core.OracleJson
import decompengine.oracle.externalcalls.*
import decompengine.oracle.machinecalls.MachineCallFileV1
import decompengine.oracle.machinecalls.MachineCallRuntimeV1
import decompengine.analysis.BundledGhidra
import java.nio.file.Files
import java.nio.file.Path
import java.nio.file.StandardCopyOption
import java.nio.file.attribute.PosixFilePermissions
import kotlin.test.*
import kotlinx.serialization.json.*

/** Authored component outputs test capture mechanics; they never issue the private operation permit. */
class GccBundledExternalCallReplayCaptureTest {
    @Test fun `exact output capture retains immutable bytes and no scoring authority`() = fixture { f ->
        val captured = f.capture()
        assertContentEquals(f.bytes, captured.reportBytes)
        captured.reportBytes.fill(0)
        assertContentEquals(f.bytes, captured.reportBytes)
        val assessment = OracleJson.parseCanonical(captured.assessmentBytes).jsonObject
        assertEquals(JsonPrimitive(OracleArtifacts.sha256(f.bytes)), assessment["reportSha256"])
        for (key in listOf("complete", "scored", "negativeCompleteness", "releaseEligible")) assertEquals(JsonPrimitive(false), assessment[key])
        f.current(captured)
    }
    @Test fun `captured outputs reject identical byte replacement after capture`() = fixture { f ->
        val captured = f.capture()
        f.replace()
        assertFails { f.current(captured) }
    }
    @Test fun `first middle and final callback mutations are rejected before capture returns`() {
        var count = 0
        fixture { f -> f.capture { count++ } }
        assertTrue(count >= 6)
        for (target in setOf(1, count / 2, count)) fixture { f ->
            var seen = 0
            assertFails { f.capture { if (++seen == target) f.replace() } }
            assertTrue(seen >= target)
        }
    }
    @Test fun `missing extra aliased nonprivate and changed request outputs reject`() {
        for (mutate in listOf<(Fixture) -> Unit>(
            { Files.delete(it.request.outputPath) },
            { Files.writeString(it.reports.resolve("extra"), "unexpected") },
            { Files.createLink(it.root.resolve("alias"), it.request.outputPath) },
            { Files.setPosixFilePermissions(it.reports, PosixFilePermissions.fromString("rwxr-xr-x")) },
            { Files.setPosixFilePermissions(it.request.outputPath, PosixFilePermissions.fromString("rw-rw----")) },
            { Files.write(it.request.outputPath, "{}".toByteArray()) },
        )) fixture { f -> mutate(f); assertFails { f.capture() } }
        fixture { f -> assertFails { f.capture(f.request.copy(sourceReport = f.request.sourceReport.copy(sha256 = "0".repeat(64)))) } }
        fixture { f -> assertFails { f.capture(f.request.copy(limits = f.request.limits.copy(maximumOutputBytes = 128))) } }
    }
    @Test fun `cancellation returns no captured output`() = fixture { f ->
        var calls = 0
        assertFailsWith<InterruptedException> { f.capture { if (++calls == 3) throw InterruptedException("cancel") } }
        assertEquals(3, calls)
    }
    @Test fun `last callback mutation of an already read log is rejected`() = fixture { f ->
        var count = 0
        f.capture { count++ }
        var calls = 0
        assertFails { f.capture { if (++calls == count) Files.writeString(f.reports.resolve("contained-command.stdout"), "changed") } }
    }
    @Test fun `recovered capture requires complete raw re-freeze and held-pair semantic validation`() {
        withRecoveredExternalFixtureV1 { files, original ->
            val bindings = original.bindings.copy(ghidraArchiveSha256 = BundledGhidra.ARCHIVE_SHA256)
            val native = original.copy(bindings = bindings, document = JsonObject(original.document +
                ("bindings" to nativeExternalBindingsJsonV1(bindings))))
            val observations = native.observationBytes()
            val manifest = native.manifestBytes(observations)
            val frozen = FrozenNativeExternalClaimsV1.freeze(manifest, observations, bindings)
            files.withPair { pair ->
                val root = Files.createDirectory(files.root.resolve("captured"))
                fun privateDirectory(path: Path): Path = Files.createDirectories(path).also {
                    Files.setPosixFilePermissions(it, PosixFilePermissions.fromString("rwx------")) }
                privateDirectory(root)
                val control = "control-" + "d".repeat(64)
                val reports = privateDirectory(privateDirectory(root.resolve(control)).resolve("reports"))
                fun input(path: Path, bytes: ByteArray): MachineCallFileV1 {
                    Files.write(path, bytes)
                    Files.setPosixFilePermissions(path, PosixFilePermissions.fromString("rw-------"))
                    return MachineCallFileV1(path, bytes.size.toLong(), OracleArtifacts.sha256(bytes))
                }
                val request = RecoveredExternalNamespaceRequestV1(input(files.root.resolve("native-manifest"), manifest),
                    input(files.root.resolve("native-stream"), observations),
                    MachineCallFileV1(files.manifest, Files.size(files.manifest), files.manifestSha),
                    MachineCallFileV1(files.rich, Files.size(files.rich), files.richSha),
                    MachineCallFileV1(files.stripped, Files.size(files.stripped), files.strippedSha), bindings,
                    MachineCallRuntimeV1(files.root.resolve("bundle"), files.root.resolve("archive"), BundledGhidra.ARCHIVE_SHA256,
                        569445154, "a".repeat(64), "b".repeat(64), "x86:LE:64:default", "4.8"),
                    reports.resolve(GccBundledExternalCallReplayOutputCapture.RECOVERED_NAME))
                val component = RecoveredExternalNamespaceV1.compose(frozen, pair, ExternalCallFixtureV1.decoder, ExternalCallFixtureV1.memory)
                val worker = JsonObject(component + mapOf("requestSha256" to JsonPrimitive(OracleArtifacts.sha256(request.canonicalBytes)),
                    "runtime" to request.runtime.json(), "decoderAuthentication" to JsonPrimitive("authenticated-bundled-worker-v1"),
                    "containmentStatus" to JsonPrimitive("external-owner-required")))
                val bytes = OracleJson.canonicalBytes(worker)
                input(request.outputPath, bytes)
                for (name in listOf("contained-command.stdout", "contained-command.stderr")) {
                    Files.write(reports.resolve(name), byteArrayOf())
                    Files.setPosixFilePermissions(reports.resolve(name), PosixFilePermissions.fromString("rw-------"))
                }
                fun capture(selected: FrozenNativeExternalClaimsSnapshotV1 = frozen) = LinuxFilesystemSyscalls.openRoot(root).use { run ->
                    LinuxFilesystemSyscalls.openDirectoryAt(run.fd, control).use { directory ->
                        GccBundledExternalCallReplayOutputCapture.captureRecovered(run, control, directory.identity, request, selected, pair) {}
                    }
                }
                assertContentEquals(bytes, capture().reportBytes)
                val rows = worker.getValue("sites").jsonArray
                val changed = JsonObject(worker + ("sites" to JsonArray(rows.mapIndexed { index, row ->
                    if (index != 0) row else JsonObject(row.jsonObject + ("sourceRecordOrdinal" to JsonPrimitive(999))) })))
                // Request/hash envelope remains unchanged: full semantic validation must still reject.
                input(request.outputPath, OracleJson.canonicalBytes(changed))
                assertFails { capture() }
                input(request.outputPath, bytes)
                val substitute = FrozenNativeExternalClaimsSnapshotV1(frozen.bindings, frozen.addressSpaces, frozen.sites,
                    frozen.rawManifestBytes, frozen.rawObservationBytes, "{}".toByteArray(), frozen.rawRecordCount)
                assertFails { capture(substitute) }
            }
        }
    }
    private class Fixture(val root: Path, val reports: Path, val control: String,
        val request: IndependentExternalCallRequestV1, val bytes: ByteArray) {
        fun capture(request: IndependentExternalCallRequestV1 = this.request, checkpoint: () -> Unit = {}): GccBundledExternalCallReplayCapture =
            LinuxFilesystemSyscalls.openRoot(root).use { run ->
                LinuxFilesystemSyscalls.openDirectoryAt(run.fd, control).use { selected ->
                    GccBundledExternalCallReplayOutputCapture.captureIndependent(run, control, selected.identity, request, checkpoint)
                }
            }
        fun current(capture: GccBundledExternalCallReplayCapture) = LinuxFilesystemSyscalls.openRoot(root).use {
            GccBundledExternalCallReplayOutputCapture.requireUnchanged(it, capture)
        }
        fun replace() {
            val replacement = root.resolve("replacement")
            Files.write(replacement, bytes)
            Files.setPosixFilePermissions(replacement, PosixFilePermissions.fromString("rw-------"))
            Files.move(replacement, request.outputPath, StandardCopyOption.REPLACE_EXISTING)
        }
    }
    private fun fixture(action: (Fixture) -> Unit): Unit = withExternalCallFixtureV1 { component ->
        val root = Files.createDirectory(component.root.resolve("capture"))
        fun private(path: Path): Path = Files.createDirectories(path).also {
            Files.setPosixFilePermissions(it, PosixFilePermissions.fromString("rwx------")) }
        private(root)
        val control = "control-" + "a".repeat(64)
        val reports = private(private(root.resolve(control)).resolve("reports"))
        val request = IndependentExternalCallRequestV1(component.request.richFile,
            MachineCallFileV1(component.sourceReport, Files.size(component.sourceReport), component.reportSha),
            MachineCallFileV1(component.sourceRequest, Files.size(component.sourceRequest), component.requestSha),
            component.runtime, reports.resolve(GccBundledExternalCallReplayOutputCapture.INDEPENDENT_NAME))
        val bytes = OracleJson.canonicalBytes(JsonObject(component.produce() + mapOf(
            "requestSha256" to JsonPrimitive(OracleArtifacts.sha256(request.canonicalBytes)), "runtime" to request.runtime.json(),
            "decoderAuthentication" to JsonPrimitive("authenticated-bundled-worker-v1"),
            "containmentStatus" to JsonPrimitive("external-owner-required"))))
        Files.write(request.outputPath, bytes)
        for (name in listOf("contained-command.stdout", "contained-command.stderr")) Files.write(reports.resolve(name), byteArrayOf())
        for (name in listOf(GccBundledExternalCallReplayOutputCapture.INDEPENDENT_NAME, "contained-command.stdout", "contained-command.stderr"))
            Files.setPosixFilePermissions(reports.resolve(name), PosixFilePermissions.fromString("rw-------"))
        action(Fixture(root, reports, control, request, bytes))
    }
}
