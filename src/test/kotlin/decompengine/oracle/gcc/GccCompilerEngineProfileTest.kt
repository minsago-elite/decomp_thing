package decompengine.oracle.gcc

import decompengine.oracle.core.OracleArtifacts
import java.nio.file.Files
import java.nio.file.Path
import java.nio.file.StandardCopyOption
import java.nio.file.attribute.PosixFilePermissions
import java.util.zip.ZipEntry
import java.util.zip.ZipOutputStream
import kotlin.io.path.createSymbolicLinkPointingTo
import kotlin.io.path.createDirectories
import kotlin.io.path.createTempDirectory
import kotlin.io.path.readBytes
import kotlin.io.path.writeBytes
import kotlin.test.Test
import kotlin.test.assertEquals
import kotlin.test.assertContentEquals
import kotlin.test.assertFails
import decompengine.oracle.core.OracleJson
import kotlinx.serialization.json.jsonObject
import kotlinx.serialization.json.jsonArray
import kotlinx.serialization.json.jsonPrimitive
import kotlin.test.assertFailsWith
import kotlin.test.assertTrue

class GccCompilerEngineProfileTest {
    @Test
    fun `retained planner profile binds all parsed files and derived policy`() {
        val root = copyControlPlane(checkedProfile().parent)
        val retained = GccRetainedCompilerEngineProfile.open(root.resolve("compiler-engines-exporter17.json"))
        retained.use {
            val bytes = retained.policyBytes()
            val policy = OracleJson.parseCanonical(bytes).jsonObject
            val inputs = policy.getValue("inputs").jsonArray.map { it.jsonObject }
            assertEquals(CONTROL_FILES.sorted(), inputs.map { Path.of(it.getValue("path").jsonPrimitive.content).fileName.toString() }.sorted())
            inputs.forEach { input ->
                val path = Path.of(input.getValue("path").jsonPrimitive.content)
                assertEquals(OracleArtifacts.sha256(path.readBytes()), input.getValue("sha256").jsonPrimitive.content)
                assertEquals(Files.size(path).toString(), input.getValue("bytes").jsonPrimitive.content)
            }
            assertEquals(retained.suite.reconstructionProfile().sha256, policy.getValue("reconstructionProfileSha256").jsonPrimitive.content)
            assertEquals(OracleJson.parse(retained.suite.reconstructionProfile().canonicalJson().toByteArray()), policy.getValue("reconstructionProfile"))
            retained.policyBytes().fill(0)
            assertContentEquals(bytes, retained.policyBytes())
            retained.requireCurrent()
        }
        assertFails { retained.policyBytes() }
        retained.close()
    }

    @Test
    fun `retained profile rejects replacement of every dependency even with identical bytes`() {
        for (name in CONTROL_FILES) {
            val root = copyControlPlane(checkedProfile().parent)
            GccRetainedCompilerEngineProfile.open(root.resolve("compiler-engines-exporter17.json")).use { retained ->
                val path = root.resolve(name)
                val original = path.readBytes()
                Files.move(path, path.resolveSibling("saved-$name"))
                path.writeBytes(original)
                assertFails { retained.requireCurrent() }
                assertFails { retained.policyBytes() }
            }
        }
    }

    @Test
    fun `failed retained profile parse closes inputs and rejects symlink dependencies`() {
        val root = copyControlPlane(checkedProfile().parent)
        val source = root.resolve("source-lock.json")
        val original = source.readBytes()
        source.writeBytes(original + byteArrayOf(32))
        assertFails { GccRetainedCompilerEngineProfile.open(root.resolve("compiler-engines-exporter17.json")) }
        source.writeBytes(original)
        GccRetainedCompilerEngineProfile.open(root.resolve("compiler-engines-exporter17.json")).use { it.requireCurrent() }
        Files.move(source, root.resolve("saved-source-lock.json"))
        source.createSymbolicLinkPointingTo(root.resolve("saved-source-lock.json"))
        assertFails { GccRetainedCompilerEngineProfile.open(root.resolve("compiler-engines-exporter17.json")) }
    }

    @Test
    fun `checked compiler-engine control plane is authenticated entirely in Kotlin`() {
        val suite = GccCompilerEngineProfiles.load(checkedProfile())

        assertEquals("gcc-compiler-engines-16.2.0", suite.id)
        assertEquals("16.2.0", suite.version)
        assertEquals("x86_64-linux-gnu", suite.target)
        assertEquals("78d4ac73dd391005b895a6148cd9831e28e1208b", suite.sourceRevision)
        assertEquals(1_800_000L, suite.budgets.exportWallClockMillis)
        assertEquals(14_400_000L, suite.budgets.fullRecoveryCc1ExportWallClockMillis)
        assertEquals(16L * 1024 * 1024 * 1024, suite.budgets.exportMaximumResidentBytes)
        assertEquals("12.1.3", suite.analysis.ghidraVersion)
        assertEquals(569_445_154L, suite.analysis.ghidraArchive.bytes)
        assertEquals("93a5d11a9ad510622acaaf908c556a7b9b764d338e78a7567f3689bf5081fd54", suite.analysis.ghidraArchive.sha256)
        assertEquals("0ee91d684d310357363cbf8516b2dc65b5f56c4b38c62d4c9e09304eb3ecafaf", suite.analysis.exporterSha256)
        assertEquals(17, suite.analysis.exporterVersion)
        assertEquals("planning", suite.analysis.exporterMode)
        val diagnostics = checkNotNull(suite.cc1RuntimeDiagnostics)
        assertEquals("gcc-cc1-runtime-diagnostics-v1", diagnostics.provider)
        assertEquals(7, diagnostics.runtimeInvocationVersion)
        assertEquals("analyze-diagnostics-v1", diagnostics.workerOperation)
        assertEquals("jvm-mxbean-stdout-v1", diagnostics.diagnosticPolicy)
        assertEquals(2L * 1024 * 1024 * 1024, diagnostics.maximumJavaHeapBytes)
        assertEquals(16L * 1024 * 1024 * 1024, diagnostics.maximumResidentBytes)
        assertEquals(14_400L, diagnostics.wallClockSeconds)
        assertEquals(listOf(4, 4, 4), listOf(diagnostics.processorCount, diagnostics.analysisThreadCount, diagnostics.decompilerWorkerCount))
        assertEquals(null, suite.fullRecoveryCc1Throughput)
        assertEquals(listOf("cc1", "lto1"), suite.engines.map(GccCompilerEngine::id))

        val cc1 = suite.engine("cc1")
        assertEquals("e51bf6e3f3300d31ce9713e2160c6fe5895d1e4914fb25562c3542b161427905", cc1.strippedArtifact.sha256)
        assertEquals(41_935_768L, cc1.strippedArtifact.bytes)
        assertEquals("dbef520c025d268f5126229ace8ad5b08a15722573d45b5e1ab934611905abb4", cc1.oracleManifestSha256)

        val lto1 = suite.engine("lto1")
        assertEquals("35d73b94b8e33cd482095016de28ebaa4e71835720e39b7c5aa82206b562361f", lto1.strippedArtifact.sha256)
        assertEquals(40_497_008L, lto1.strippedArtifact.bytes)
        assertEquals("5f7e686168d6a6e35ef3719d077b0bfb246085c2d3738835be13eeed5e0d0a41", lto1.oracleManifestSha256)

        val reconstruction = suite.reconstructionProfile()
        assertEquals(suite.budgets.exportWallClockMillis, reconstruction.budgets.exportWallClockMillis)
        assertEquals(suite.budgets.plannerMaximumEntities, reconstruction.budgets.plannerMaximumEntities)
        assertEquals(suite.profileSha256, reconstruction.adapterConfiguration.getValue("benchmark-profile-sha256").single())
    }

    @Test
    fun `the explicit parallel profile differs from the serial default only by its throughput policy`() {
        val root = checkedProfile().parent
        val serial = OracleJson.parse(checkedProfile().readBytes()).jsonObject
        val parallelPath = root.resolve("compiler-engines-exporter17-parallel.json")
        decompengine.oracle.core.OracleSchemas.validate("gcc/compiler-engines-exporter17", OracleJson.parse(parallelPath.readBytes()))
        val parallel = GccCompilerEngineProfiles.load(parallelPath)
        val policy = checkNotNull(parallel.fullRecoveryCc1Throughput)
        assertEquals(1, policy.schemaVersion)
        assertEquals(6, policy.runtimeInvocationVersion)
        assertEquals(listOf(4, 4, 4), listOf(policy.processorCount, policy.analysisThreadCount, policy.decompilerWorkerCount))
        assertEquals(17, parallel.analysis.exporterVersion)
        assertEquals(GccCompilerEngineProfiles.load(checkedProfile()).analysis.exporterSha256, parallel.analysis.exporterSha256)
        val analysisOfParallel = OracleJson.parse(parallelPath.readBytes()).jsonObject.getValue("analysis").jsonObject
        val analysisOfSerial = serial.getValue("analysis").jsonObject
        assertEquals(analysisOfSerial.keys + "fullRecoveryCc1Throughput", analysisOfParallel.keys)
        assertEquals(serial.filterKeys { it != "analysis" }, OracleJson.parse(parallelPath.readBytes()).jsonObject.filterKeys { it != "analysis" })
    }

    @Test
    fun `historical exporter eleven twelve and thirteen profiles remain inspectable but cannot authorize current work`() {
        val root = checkedProfile().parent
        val historical = root.resolve("compiler-engines.json").readBytes()
        decompengine.oracle.core.OracleSchemas.validate("gcc/compiler-engines", OracleJson.parse(historical))
        decompengine.oracle.core.OracleSchemas.validate("gcc/compiler-engines-exporter17", OracleJson.parse(checkedProfile().readBytes()))
        assertEquals("d32c73335a8639c335c8e04d822a51256aee79dc889de1c9bfe999d584610732", OracleArtifacts.sha256(historical))
        assertEquals("11", OracleJson.parse(historical).jsonObject.getValue("analysis").jsonObject
            .getValue("exporter").jsonObject.getValue("version").jsonPrimitive.content)
        assertEquals("e3f74c9329c2124be0d123525d10ac59928097570f028afdf40ce5f8363539e4",
            OracleArtifacts.sha256(root.resolve("structural-full-export-profile.json").readBytes()))
        assertFailsWith<GccCompilerEngineProfileException> { GccCompilerEngineProfiles.load(root.resolve("compiler-engines.json")) }
        val twelve = root.resolve("compiler-engines-exporter12.json")
        decompengine.oracle.core.OracleSchemas.validate("gcc/compiler-engines-exporter12", OracleJson.parse(twelve.readBytes()))
        assertEquals("f8a487df5b35168a1a1212a95c9f40e84a299969005e1a9ffd7383a1db26ed19", OracleArtifacts.sha256(twelve.readBytes()))
        assertEquals("011f49895f66c4af2692eeaac6bb514a96761ed864f2b0051b533bda3fead06f",
            OracleArtifacts.sha256(root.resolve("structural-full-export-profile-exporter12.json").readBytes()))
        assertFailsWith<GccCompilerEngineProfileException> { GccCompilerEngineProfiles.load(twelve) }
        val thirteen = root.resolve("compiler-engines-exporter13.json")
        decompengine.oracle.core.OracleSchemas.validate("gcc/compiler-engines-exporter13", OracleJson.parse(thirteen.readBytes()))
        assertEquals("0d2c6f571b1ee7a977b2baf496823186da3fa95c97ede358e2c4ef75403927ca", OracleArtifacts.sha256(thirteen.readBytes()))
        assertEquals("1075cd580b0a5bc872149633c1aa95a30b08b9da2f2e9feb689352571032b615",
            OracleArtifacts.sha256(root.resolve("structural-full-export-profile-exporter13.json").readBytes()))
        assertFailsWith<GccCompilerEngineProfileException> { GccCompilerEngineProfiles.load(thirteen) }
    }

    @Test
    fun `current compiler profile rejects the previous exporter version`() {
        val root = copyControlPlane(checkedProfile().parent)
        val profile = root.resolve("compiler-engines-exporter17.json")
        val current = profile.readBytes().decodeToString()
        assertTrue("\"version\": 17" in current)
        profile.writeBytes(current.replaceFirst("\"version\": 17", "\"version\": 16").toByteArray())

        assertFailsWith<GccCompilerEngineProfileException> {
            GccCompilerEngineProfiles.load(profile)
        }
    }

    @Test
    fun `dependency and manifest substitutions fail their profile bindings`() {
        val sourceRoot = checkedProfile().parent

        val sourceMutation = copyControlPlane(sourceRoot)
        sourceMutation.resolve("source-lock.json").also { path -> path.writeBytes(path.readBytes() + '\n'.code.toByte()) }
        assertFailsWith<GccCompilerEngineProfileException> {
            GccCompilerEngineProfiles.load(sourceMutation.resolve("compiler-engines-exporter17.json"))
        }

        val manifestMutation = copyControlPlane(sourceRoot)
        val manifest = manifestMutation.resolve("cc1-oracle-manifest.json")
        val bytes = manifest.readBytes()
        val marker = "ba9b2f314bfb3d92".toByteArray()
        val offset = bytes.indexOfSubsequence(marker)
        assertTrue(offset >= 0)
        bytes[offset] = if (bytes[offset] == 'b'.code.toByte()) 'c'.code.toByte() else 'b'.code.toByte()
        manifest.writeBytes(bytes)
        assertFailsWith<GccCompilerEngineProfileException> {
            GccCompilerEngineProfiles.load(manifestMutation.resolve("compiler-engines-exporter17.json"))
        }
    }

    @Test
    fun `large artifact authentication binds bytes identity and trusted permissions`() {
        val directory = createTempDirectory("gcc-engine-artifact-").toAbsolutePath().normalize()
        val artifact = directory.resolve("engine")
        val content = ByteArray(2 * 1024 * 1024 + 17) { index -> (index * 31).toByte() }
        artifact.writeBytes(content)
        val binding = GccCompilerEngineArtifactBinding(
            relativePath = "artifacts/engine",
            bytes = content.size.toLong(),
            sha256 = OracleArtifacts.sha256(content),
        )

        val authenticated = authenticateLargeArtifact(artifact, binding, "test engine")
        assertEquals(artifact, authenticated.path)
        assertEquals(binding.sha256, authenticated.sha256)

        artifact.writeBytes(content.copyOf().also { it[0] = (it[0].toInt() xor 1).toByte() })
        assertFailsWith<GccCompilerEngineProfileException> {
            authenticateLargeArtifact(artifact, binding, "test engine")
        }

        artifact.writeBytes(content)
        Files.setPosixFilePermissions(artifact, PosixFilePermissions.fromString("rw-rw----"))
        assertFailsWith<GccCompilerEngineProfileException> {
            authenticateLargeArtifact(artifact, binding, "test engine")
        }

        Files.setPosixFilePermissions(artifact, PosixFilePermissions.fromString("rw-------"))
        val link = directory.resolve("engine-link")
        link.createSymbolicLinkPointingTo(artifact)
        assertFailsWith<GccCompilerEngineProfileException> {
            authenticateLargeArtifact(link, binding, "test engine")
        }
    }

    @Test
    fun `Ghidra home must expose the profiled application identity and executable launcher`() {
        val suite = GccCompilerEngineProfiles.load(checkedProfile())
        val home = createTempDirectory("gcc-engine-ghidra-").toAbsolutePath().normalize()
        val launcher = home.resolve("support/analyzeHeadless")
        launcher.parent.createDirectories()
        launcher.writeBytes("#!/bin/sh\n".toByteArray())
        launcher.toFile().setExecutable(true)
        val properties = home.resolve("Ghidra/application.properties")
        properties.parent.createDirectories()
        properties.writeBytes(
            "application.name=Ghidra\napplication.release.name=PUBLIC\napplication.version=12.1.3\n".toByteArray(),
        )

        assertEquals(home, suite.analysis.requireGhidraHome(home))

        properties.writeBytes(
            "application.name=Ghidra\napplication.release.name=PUBLIC\napplication.version=12.1.2\n".toByteArray(),
        )
        assertFailsWith<GccCompilerEngineProfileException> { suite.analysis.requireGhidraHome(home) }
    }

    @Test
    fun `Ghidra installation must exactly match its authenticated release archive`() {
        val root = createTempDirectory("gcc-engine-ghidra-archive-").toAbsolutePath().normalize()
        val archive = root.resolve("ghidra.zip")
        val home = root.resolve("ghidra_12.1.3_PUBLIC")
        val files = linkedMapOf(
            "support/analyzeHeadless" to "#!/bin/sh\n".toByteArray(),
            "Ghidra/application.properties" to
                "application.name=Ghidra\napplication.release.name=PUBLIC\napplication.version=12.1.3\n".toByteArray(),
        )
        ZipOutputStream(Files.newOutputStream(archive)).use { output ->
            listOf("ghidra_12.1.3_PUBLIC/", "ghidra_12.1.3_PUBLIC/support/", "ghidra_12.1.3_PUBLIC/Ghidra/")
                .forEach { name ->
                    output.putNextEntry(ZipEntry(name))
                    output.closeEntry()
                }
            files.forEach { (relative, bytes) ->
                output.putNextEntry(ZipEntry("ghidra_12.1.3_PUBLIC/$relative"))
                output.write(bytes)
                output.closeEntry()
            }
        }
        files.forEach { (relative, bytes) ->
            val path = home.resolve(relative)
            path.parent.createDirectories()
            path.writeBytes(bytes)
        }
        home.resolve("support/analyzeHeadless").toFile().setExecutable(true)
        val archiveBytes = archive.readBytes()
        val analysis = GccCompilerEngineProfiles.load(checkedProfile()).analysis.copy(
            ghidraArchive = GccCompilerEngineArtifactBinding(
                relativePath = archive.fileName.toString(),
                bytes = archiveBytes.size.toLong(),
                sha256 = OracleArtifacts.sha256(archiveBytes),
            ),
        )

        val authenticated = analysis.authenticateGhidraInstallation(archive, home)

        assertEquals(home, authenticated.home)
        assertEquals(2, authenticated.fileCount)
        home.resolve("unexpected.txt").writeBytes("extra".toByteArray())
        assertFailsWith<GccCompilerEngineProfileException> {
            analysis.authenticateGhidraInstallation(archive, home)
        }
        Files.delete(home.resolve("unexpected.txt"))
        home.resolve("support/analyzeHeadless").writeBytes("#!/bin/false\n".toByteArray())
        assertFailsWith<GccCompilerEngineProfileException> {
            analysis.authenticateGhidraInstallation(archive, home)
        }
    }

    private fun copyControlPlane(source: Path): Path {
        val target = createTempDirectory("gcc-engine-controls-").toAbsolutePath().normalize()
        CONTROL_FILES.forEach { name ->
            Files.copy(source.resolve(name), target.resolve(name), StandardCopyOption.COPY_ATTRIBUTES)
            Files.setPosixFilePermissions(target.resolve(name), PosixFilePermissions.fromString("rw-------"))
        }
        return target
    }

    private fun checkedProfile(): Path = Path.of(System.getProperty("user.dir"))
        .resolve("oracle/gcc/16.2.0/compiler-engines-exporter17.json")
        .toAbsolutePath()
        .normalize()

    private fun ByteArray.indexOfSubsequence(needle: ByteArray): Int {
        if (needle.isEmpty()) return 0
        for (offset in 0..size - needle.size) {
            if (needle.indices.all { index -> this[offset + index] == needle[index] }) return offset
        }
        return -1
    }

    private companion object {
        val CONTROL_FILES = listOf(
            "compiler-engines-exporter17.json",
            "source-lock.json",
            "build-record.json",
            "toolchain-reproduction.json",
            "build-toolchain.Dockerfile",
            "cc1-build-record.json",
            "lto1-build-record.json",
            "cc1-oracle-manifest.json",
            "lto1-oracle-manifest.json",
        )
    }
}
