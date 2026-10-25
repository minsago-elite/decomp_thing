package decompengine.oracle.gcc

import decompengine.oracle.core.OracleArtifacts
import decompengine.oracle.core.OracleJson
import decompengine.oracle.fulltree.FullTreeControlException
import java.nio.file.Files
import java.nio.file.Path
import java.nio.file.StandardCopyOption.REPLACE_EXISTING
import java.nio.file.attribute.PosixFilePermissions
import kotlin.test.Test
import kotlin.test.assertContentEquals
import kotlin.test.assertEquals
import kotlin.test.assertFailsWith
import kotlin.test.assertFalse
import kotlin.test.assertTrue
import kotlinx.serialization.json.JsonArray
import kotlinx.serialization.json.JsonObject
import kotlinx.serialization.json.JsonPrimitive
import kotlinx.serialization.json.boolean
import kotlinx.serialization.json.jsonArray
import kotlinx.serialization.json.jsonObject
import kotlinx.serialization.json.jsonPrimitive
import kotlinx.serialization.json.long
import org.junit.jupiter.api.Assumptions.assumeTrue
import org.junit.jupiter.api.Tag

/** Explicit live qualification of the locked source bytes, without build or ownership authority. */
@Tag("ci-live")
class GccSignedSourceQualificationTest {
    @Test
    fun `actual signed release is deterministic source only and retains every descriptor binding`() {
        val archiveValue = System.getenv("DECOMP_GCC_SIGNED_SOURCE_ARCHIVE")?.takeIf { it.isNotBlank() }
        val signatureValue = System.getenv("DECOMP_GCC_SIGNED_SOURCE_SIGNATURE")?.takeIf { it.isNotBlank() }
        val required = System.getenv("DECOMP_REQUIRE_GCC_SIGNED_SOURCE") == "1"
        if (required) {
            assertTrue(archiveValue != null && signatureValue != null,
                "dedicated qualification requires DECOMP_GCC_SIGNED_SOURCE_ARCHIVE and DECOMP_GCC_SIGNED_SOURCE_SIGNATURE")
        }
        assumeTrue(archiveValue != null && signatureValue != null,
            "set both GCC signed source input paths to run actual release qualification")
        val archive = Path.of(requireNotNull(archiveValue))
        val signature = Path.of(requireNotNull(signatureValue))
        assertTrue(archive.isAbsolute && archive.normalize() == archive)
        assertTrue(signature.isAbsolute && signature.normalize() == signature)
        assertEquals(107_200_820L, Files.size(archive))
        assertEquals(310L, Files.size(signature))
        assertContentEquals(GccSignedSourceFixture.signatureBytes(), Files.readAllBytes(signature))
        val inputIdentities = listOf(archive, signature).map { inputIdentity(it) }
        val output = Files.createDirectories(Path.of("build/gcc-signed-source-qualification").toAbsolutePath().normalize())
        listOf("evidence-first.json", "evidence-second.json", "qualification.json").forEach { Files.deleteIfExists(output.resolve(it)) }
        val started = System.nanoTime()
        val verifications = mutableListOf<JsonObject>()
        val phaseRefusals = mutableListOf<String>()
        var first: ByteArray? = null
        var second: ByteArray? = null
        var afterHandoff = false
        var copyIsolation = false
        var closeSemantics = false
        var succeeded = false
        try {
            observed("first-complete-verification", verifications) {
                GccSignedSourceFixture.create().use { fixture ->
                    val phases = mutableListOf<GccSignedSourcePhase>()
                    val held = GccSignedSource.open(fixture.lock, archive, signature, phaseObserver = { phases += it })
                    try {
                        assertEquals(GccSignedSourcePhase.entries.toList(), phases)
                        held.requireCurrent()
                        val evidence = held.canonicalEvidence()
                        assertActualEvidence(evidence)
                        first = evidence.copyOf()
                        evidence.fill(0)
                        assertContentEquals(requireNotNull(first), held.canonicalEvidence())
                        copyIsolation = true
                        Files.write(output.resolve("evidence-first.json"), requireNotNull(first))
                    } finally {
                        held.close()
                    }
                    held.close()
                    assertFailsWith<IllegalStateException> { held.requireCurrent() }
                    assertFailsWith<IllegalStateException> { held.canonicalEvidence() }
                    closeSemantics = true
                }
            }
            observed("second-complete-verification-and-handoff-substitution", verifications) {
                GccSignedSourceFixture.create().use { fixture ->
                    // Only owned copies are renamed. Both inodes contain the actual locked archive.
                    Files.copy(archive, fixture.archive, REPLACE_EXISTING)
                    val replacement = fixture.root.resolve("replacement.tar.xz")
                    Files.copy(archive, replacement)
                    listOf(fixture.archive, replacement).forEach {
                        Files.setPosixFilePermissions(it, PosixFilePermissions.fromString("rw-------"))
                    }
                    assertEquals(-1L, Files.mismatch(archive, replacement))
                    val originalInode = Files.getAttribute(fixture.archive, "unix:ino")
                    val replacementInode = Files.getAttribute(replacement, "unix:ino")
                    assertTrue(originalInode != replacementInode)
                    GccSignedSource.open(fixture.lock, fixture.archive, signature).use { held ->
                        second = held.canonicalEvidence()
                        assertActualEvidence(requireNotNull(second))
                        assertContentEquals(requireNotNull(first), requireNotNull(second))
                        Files.write(output.resolve("evidence-second.json"), requireNotNull(second))
                        Files.move(fixture.archive, fixture.root.resolve("displaced.tar.xz"))
                        Files.move(replacement, fixture.archive)
                        assertEquals(replacementInode, Files.getAttribute(fixture.archive, "unix:ino"))
                        assertFailsWith<FullTreeControlException> { held.requireCurrent() }
                        assertFailsWith<FullTreeControlException> { held.canonicalEvidence() }
                        afterHandoff = true
                    }
                }
            }
            for (stopAt in GccSignedSourcePhase.entries) {
                observed("substitution-at-${stopAt.name}", verifications) {
                    GccSignedSourceFixture.create().use { fixture ->
                        val phases = mutableListOf<GccSignedSourcePhase>()
                        var replaced = false
                        val failure = assertFailsWith<GccSignedSourceException> {
                            GccSignedSource.open(fixture.lock, archive, signature) { phase ->
                                phases += phase
                                if (phase == stopAt) {
                                    fixture.replaceKeyInode()
                                    replaced = true
                                }
                            }.close()
                        }
                        assertTrue(replaced, "the actual source must reach $stopAt before substitution refusal")
                        assertEquals(GccSignedSourcePhase.entries.take(stopAt.ordinal + 1), phases)
                        assertTrue(generateSequence<Throwable>(failure) { it.cause }.any { it is FullTreeControlException },
                            failure.stackTraceToString())
                        phaseRefusals += stopAt.name
                    }
                }
            }
            assertEquals(inputIdentities, listOf(archive, signature).map { inputIdentity(it) })
            assertEquals(GccSignedSourcePhase.entries.map { it.name }, phaseRefusals)
            assertTrue(afterHandoff && copyIsolation && closeSemantics)
            succeeded = true
        } finally {
            val report = JsonObject(mapOf(
                "schemaVersion" to JsonPrimitive(1),
                "provider" to JsonPrimitive("gcc-signed-source-live-qualification-v1"),
                "status" to JsonPrimitive(if (succeeded) "passed" else "failed"),
                "scope" to JsonPrimitive("exact-signed-source-release-only"),
                "evidenceFirstSha256" to JsonPrimitive(first?.let(OracleArtifacts::sha256)),
                "evidenceSecondSha256" to JsonPrimitive(second?.let(OracleArtifacts::sha256)),
                "deterministic" to JsonPrimitive(first != null && second != null && first!!.contentEquals(second!!)),
                "phaseSubstitutionRefusals" to JsonArray(phaseRefusals.map(::JsonPrimitive)),
                "afterHandoffSubstitutionRefused" to JsonPrimitive(afterHandoff),
                "afterHandoffSubstitutionTarget" to JsonPrimitive("archive"),
                "copyIsolationVerified" to JsonPrimitive(copyIsolation),
                "closeSemanticsVerified" to JsonPrimitive(closeSemantics),
                "verifications" to JsonArray(verifications),
                "observations" to observation(System.nanoTime() - started),
                "tool" to JsonObject(mapOf(
                    "javaVersion" to JsonPrimitive(System.getProperty("java.version")),
                    "javaVendor" to JsonPrimitive(System.getProperty("java.vendor")),
                    "javaVmVersion" to JsonPrimitive(System.getProperty("java.vm.version")),
                    "javaExecutableSha256" to JsonPrimitive(OracleArtifacts.sha256(Files.readAllBytes(
                        Path.of(System.getProperty("java.home"), "bin/java")))),
                    "javaReleaseSha256" to JsonPrimitive(OracleArtifacts.sha256(Files.readAllBytes(
                        Path.of(System.getProperty("java.home"), "release")))),
                )),
                "authority" to JsonObject(AUTHORITY.associateWith { JsonPrimitive(false) }),
            ))
            Files.write(output.resolve("qualification.json"), OracleJson.canonicalBytes(report))
        }
    }

    private fun assertActualEvidence(bytes: ByteArray) {
        val evidence = OracleJson.parseCanonical(bytes).jsonObject
        assertEquals(1L, evidence.number("schemaVersion"))
        assertEquals("gcc-signed-source-verification-v1", evidence.text("provider"))
        assertEquals("exact-signed-source-release-only", evidence.text("scope"))
        assertTrue(evidence.getValue("sourceAuthenticated").jsonPrimitive.boolean)
        assertEquals("78d4ac73dd391005b895a6148cd9831e28e1208b", evidence.text("sourceRevision"))
        assertEquals("gcc-16.2.0", evidence.text("archiveRoot"))
        assertEquals("e2930ecc9748b40e56d6fe09dbe88f21f735953d4e6da50403f2cc0aa5b650cc", evidence.text("sourceLockSha256"))
        assertCommitment(evidence, "archive", 107_200_820L, "e6738e29597f733270731aa90600f37ffdc045079dfc27ec7e8192cc81085c3e")
        assertCommitment(evidence, "detachedSignature", 310L, "43d73202dcede15d31001c6ba0d28723014ef57e4dc815631772daadbe23bcd2")
        assertCommitment(evidence, "releaseKey", 3630L, "2408f24e68b0f5530bfb02fdc2906524f6e143ed2f1d5af6e5a38d505f8f602b")
        assertCommitment(evidence, "tagPayload", 163L, "bfc082efedb5324641d89cbdc3fbce067a2524e4faf69ae6e17fe5eb40b9281a")
        assertCommitment(evidence, "tagSignature", 512L, "be83e6c296074195bab948872c6249fd2f007c328908530a515b5cde81990eb7")
        assertEquals("1831ac03fd08e3400c16b29f21762e6b326a618d", evidence.text("tagObject"))
        assertEquals("13975A70E63C361C73AE69EF6EEB81F8981C74C7", evidence.text("primaryFingerprint"))
        assertEquals("7F74F97C103468EE5D750B583AB00996FC26A641", evidence.text("signingFingerprint"))
        assertEquals(1786091352L, evidence.number("archiveSignatureEpoch"))
        assertEquals(1786088838L, evidence.number("tagSignatureEpoch"))
        assertEquals("gcc-source-posix-local-pax-v1", evidence.text("archiveProfile"))
        val scan = evidence.getValue("scan").jsonObject
        val actualCounts = mapOf("expandedBytes" to 1_201_551_360L, "logicalMembers" to 165_079L,
            "regularFiles" to 158_985L, "directories" to 6094L, "paxHeaders" to 165_079L,
            "rawHeaders" to 330_158L, "paxPayloadBytes" to 14_905_270L, "maximumPaxPayloadBytes" to 232L,
            "paxPathOverrides" to 863L, "paxLongPathOverrides" to 860L, "paxUtf8PathOverrides" to 3L)
        actualCounts.forEach { (field, count) -> assertEquals(count, scan.number(field), field) }
        val paxKeys = scan.getValue("paxKeys").jsonObject
        val expectedPaxKeys = mapOf("mtime" to 165_079L, "atime" to 165_079L, "ctime" to 165_079L, "path" to 863L)
        assertEquals(expectedPaxKeys.keys, paxKeys.keys)
        expectedPaxKeys.forEach { (field, count) -> assertEquals(count, paxKeys.number(field), field) }
        val limits = evidence.getValue("limits").jsonObject
        assertTrue(scan.number("indexBytesCharged") in 1..limits.number("maximumIndexBytes"))
        assertTrue(scan.number("workUnitsCharged") in 1..limits.number("maximumWorkUnits"))
        val expectedLimits = mapOf("maximumCompressedBytes" to 536_870_912L, "maximumExpandedBytes" to 4_294_967_296L,
            "maximumDecoderMemoryKiB" to 262_144L, "maximumLogicalMembers" to 200_000L,
            "maximumPaxHeaders" to 200_000L, "maximumRawHeaders" to 400_000L,
            "maximumPaxRecordBytes" to 1_048_576L, "maximumTotalPaxBytes" to 33_554_432L,
            "maximumEntryBytes" to 536_870_912L, "maximumPathBytes" to 4096L,
            "maximumComponentBytes" to 255L, "maximumIndexBytes" to 67_108_864L,
            "maximumSelectedBytes" to 1_048_576L, "maximumWorkUnits" to 100_000_000L,
            "maximumWallMillis" to 300_000L)
        assertEquals(expectedLimits.keys, limits.keys)
        expectedLimits.forEach { (field, count) -> assertEquals(count, limits.number(field), field) }
        val contents = evidence.getValue("lockedContents").jsonArray.map { it.jsonObject }
        assertEquals(CONTENTS.keys.sorted().map { "gcc-16.2.0/$it" }, contents.map { it.text("path") })
        contents.forEach { content ->
            val expected = CONTENTS.getValue(content.text("path").removePrefix("gcc-16.2.0/"))
            assertEquals(expected.first, content.number("bytes"))
            assertEquals(expected.second, content.text("sha256"))
        }
        val authority = evidence.getValue("authority").jsonObject
        assertEquals(AUTHORITY, authority.keys)
        authority.values.forEach { assertFalse(it.jsonPrimitive.boolean) }
        assertFalse(bytes.decodeToString().contains("build/task-tmp"))
    }

    private fun assertCommitment(parent: JsonObject, field: String, size: Long, sha256: String) {
        val value = parent.getValue(field).jsonObject
        assertEquals(setOf("bytes", "sha256"), value.keys)
        assertEquals(size, value.number("bytes"))
        assertEquals(sha256, value.text("sha256"))
    }

    private fun <T> observed(name: String, records: MutableList<JsonObject>, operation: () -> T): T {
        val started = System.nanoTime()
        try {
            return operation()
        } finally {
            records += JsonObject(observation(System.nanoTime() - started) + ("name" to JsonPrimitive(name)))
        }
    }

    private fun observation(wallNanos: Long): JsonObject {
        val status = Files.readString(Path.of("/proc/self/status"))
        val vmHwmKiB = requireNotNull(Regex("(?m)^VmHWM:\\s+(\\d+) kB$").find(status)).groupValues[1].toLong()
        val maximumHeap = Runtime.getRuntime().maxMemory()
        check(wallNanos > 0 && vmHwmKiB > 0 && maximumHeap > 0)
        return JsonObject(mapOf("wallNanos" to JsonPrimitive(wallNanos),
            "jvmMaximumHeapBytes" to JsonPrimitive(maximumHeap), "processVmHwmKiB" to JsonPrimitive(vmHwmKiB),
            "scope" to JsonPrimitive("Observed monotonic elapsed time and JVM process memory; VmHWM is cumulative for the test process, not an archive accounting bound or OS containment guarantee.")))
    }

    private fun inputIdentity(path: Path): List<Any> = listOf(Files.size(path),
        Files.getAttribute(path, "unix:dev"), Files.getAttribute(path, "unix:ino"),
        Files.getAttribute(path, "unix:nlink"), Files.getAttribute(path, "unix:ctime"), Files.getLastModifiedTime(path))

    private fun JsonObject.text(key: String): String = getValue(key).jsonPrimitive.content
    private fun JsonObject.number(key: String): Long = getValue(key).jsonPrimitive.long

    companion object {
        private val AUTHORITY = setOf("runtimeAuthenticated", "captureAuthenticated", "ownershipComplete",
            "nominalIdentityComplete", "modelBound", "sealed", "scored", "complete", "productionVerified", "releaseEligible")
        private val CONTENTS = mapOf(
            "LAST_UPDATED" to (89L to "d81180ed681d7fdbbc6ec89fad1d54520858dffa85557b29d6c972f024aab779"),
            "gcc/BASE-VER" to (7L to "e9f8839c742db21d285464b01dfb2e572f802c366729873cdc4a296c8c3a01ea"),
            "gcc/DEV-PHASE" to (0L to "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"),
            "COPYING" to (18002L to "231f7edcc7352d7734a96eef0b8030f77982678c516876fcb81e25b32d68564c"),
            "COPYING3" to (35147L to "8ceb4b9ee5adedde47b31e975c1d90c73ad27b6b165a1dcd80c7c545eb65b903"),
            "COPYING3.LIB" to (7639L to "a853c2ffec17057872340eee242ae4d96cbf2b520ae27d903e1b2fef1a5f9d1c"),
            "COPYING.RUNTIME" to (3324L to "9d6b43ce4d8de0c878bf16b54d8e7a10d9bd42b75178153e3af6a815bdc90f74"),
        )
    }
}
