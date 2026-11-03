package decompengine.oracle.gcc

import decompengine.oracle.core.OracleArtifacts
import java.lang.reflect.InvocationTargetException
import java.lang.reflect.Modifier
import java.nio.file.Files
import java.nio.file.Path
import java.nio.file.attribute.PosixFilePermissions
import java.util.Base64
import kotlin.test.Test
import kotlin.test.assertContentEquals
import kotlin.test.assertEquals
import kotlin.test.assertFailsWith
import kotlin.test.assertFalse
import kotlin.test.assertSame
import kotlin.test.assertTrue

class GccSignedSourceTest {
    @Test
    fun `compiled API has no public result constructor or unchecked issuer accessors`() {
        val result = GccSignedSource::class.java
        assertTrue(result.constructors.isEmpty(), "public synthetic constructors must not mint a held source")
        assertTrue(result.declaredConstructors.all { Modifier.isPrivate(it.modifiers) && !it.isSynthetic })
        val surfaces = mapOf(
            result to setOf("canonicalEvidence", "requireCurrent", "close"),
            GccSignedSource.Companion::class.java to setOf("open", "open\$default"),
            Class.forName("decompengine.oracle.gcc.GccSignedSourceIssuer") to setOf("open", "requireIssued", "revoke"),
        )
        surfaces.forEach { (type, expected) ->
            assertEquals(expected, type.declaredMethods.filter { Modifier.isPublic(it.modifiers) }.map { it.name }.toSet(), type.name)
            assertTrue(type.declaredFields.filter { Modifier.isPublic(it.modifiers) }.all {
                Modifier.isFinal(it.modifiers) && (it.type == String::class.java || it.type.isPrimitive ||
                    it.name == "Companion" || it.name == "INSTANCE")
            }, "no registry or constructor handle may escape ${type.name}")
        }
    }

    @Test
    fun `empty guard constructor clones refuse fabricated evidence before caller checkpoint`() {
        listOf(byteArrayOf(), "{\"sourceAuthenticated\":true}".toByteArray()).forEach { report ->
            GccSignedSourceConstructionControls.assertCloneRefused(report)
        }
    }

    @Test
    fun `exact vendored metadata verifies before any source archive is selected`() {
        GccSignedSourceFixture.create().use { fixture ->
            val stopped = IllegalStateException("stop after actual key and tag verification")
            val phases = mutableListOf<GccSignedSourcePhase>()
            val failure = assertFailsWith<GccSignedSourceException> {
                GccSignedSource.open(fixture.lock, fixture.root.resolve("absent-archive"),
                    fixture.root.resolve("absent-signature")) { phase ->
                    phases += phase
                    throw stopped
                }.close()
            }
            assertSame(stopped, failure.cause)
            assertEquals(listOf(GccSignedSourcePhase.METADATA_VERIFIED), phases)
        }
    }

    @Test
    fun `lock digest refuses altered revision signer paths unknown fields and trailing bytes`() {
        val original = Files.readString(GccSignedSourceFixture.PROFILE.resolve("source-lock.json"))
        val changed = listOf(
            original.replace(GccSignedSource.REVISION, "0".repeat(40)),
            original.replace("7F74F97C103468EE5D750B583AB00996FC26A641", "0".repeat(40)),
            original.replace("keys/richard-guenther-gcc-release.asc", "../keys/release.asc"),
            original.replace("\"schemaVersion\": 1,", "\"schemaVersion\": 1, \"unknown\": true,"),
            "$original\n",
        )
        changed.forEach { bytes ->
            GccSignedSourceFixture.create().use { fixture ->
                Files.writeString(fixture.lock, bytes)
                assertRefused(fixture, emptyList())
            }
        }
    }

    @Test
    fun `key payload and armored tag signature mutations refuse before metadata admission`() {
        for (relative in GccSignedSourceFixture.METADATA.drop(1)) {
            GccSignedSourceFixture.create().use { fixture ->
                val path = fixture.root.resolve(relative)
                val changed = Files.readAllBytes(path).also { it[it.lastIndex / 2] = (it[it.lastIndex / 2].toInt() xor 1).toByte() }
                Files.write(path, changed)
                assertRefused(fixture, emptyList())
            }
        }
    }

    @Test
    fun `lock requires an absolute canonical single link regular input`() {
        GccSignedSourceFixture.create().use { fixture ->
            val paths = listOf(Path.of("oracle/gcc/16.2.0/source-lock.json"),
                fixture.root.resolve("unused/../source-lock.json"),
                fixture.root.resolve("x".repeat(4097)))
            paths.forEach { path ->
                assertFailsWith<GccSignedSourceException> {
                    GccSignedSource.open(path, fixture.archive, fixture.signature).close()
                }
            }
        }
        for (kind in listOf("missing", "directory", "symlink", "hardlink")) {
            GccSignedSourceFixture.create().use { fixture ->
                fixture.replaceInputKind(fixture.lock, kind)
                assertRefused(fixture, emptyList())
            }
        }
    }

    @Test
    fun `resolved metadata inputs reject missing directories symlinks hardlinks and unsafe permissions`() {
        for (relative in GccSignedSourceFixture.METADATA.drop(1)) {
            for (kind in listOf("missing", "directory", "symlink", "hardlink", "writable")) {
                GccSignedSourceFixture.create().use { fixture ->
                    fixture.replaceInputKind(fixture.root.resolve(relative), kind)
                    assertRefused(fixture, emptyList())
                }
            }
        }
    }

    @Test
    fun `detached archive signature requires its exact bytes and safe descriptor`() {
        val original = GccSignedSourceFixture.signatureBytes()
        assertEquals(310, original.size)
        assertEquals(GccSignedSource.SIGNATURE_SHA256, OracleArtifacts.sha256(original))
        for (changed in listOf(original.copyOf().also { it[100] = (it[100].toInt() xor 1).toByte() },
            original.copyOf(original.size - 1), original + 0)) {
            GccSignedSourceFixture.create().use { fixture ->
                Files.write(fixture.signature, changed)
                assertRefused(fixture, listOf(GccSignedSourcePhase.METADATA_VERIFIED))
            }
        }
        for (kind in listOf("missing", "directory", "symlink", "hardlink")) {
            GccSignedSourceFixture.create().use { fixture ->
                fixture.replaceInputKind(fixture.signature, kind)
                assertRefused(fixture, listOf(GccSignedSourcePhase.METADATA_VERIFIED))
            }
        }
    }

    @Test
    fun `archive selection rejects short empty missing aliased and nonregular inputs`() {
        for (kind in listOf("short", "empty", "missing", "directory", "symlink", "hardlink")) {
            GccSignedSourceFixture.create().use { fixture ->
                when (kind) {
                    "short" -> Unit
                    "empty" -> Files.write(fixture.archive, byteArrayOf())
                    else -> fixture.replaceInputKind(fixture.archive, kind)
                }
                assertRefused(fixture, listOf(GccSignedSourcePhase.METADATA_VERIFIED))
            }
        }
    }

    @Test
    fun `wall bounds and lowered compressed limit refuse without an actual archive`() {
        GccSignedSourceFixture.create().use { fixture ->
            for (wall in listOf(-1L, 0L, 300_001L, Long.MAX_VALUE)) {
                var observed = false
                assertFailsWith<IllegalArgumentException> {
                    GccSignedSource.open(fixture.lock, fixture.archive, fixture.signature,
                        maximumWallMillis = wall, phaseObserver = { observed = true }).close()
                }
                assertFalse(observed)
            }
            val phases = mutableListOf<GccSignedSourcePhase>()
            val failure = assertFailsWith<GccSignedSourceException> {
                GccSignedSource.open(fixture.lock, fixture.archive, fixture.signature,
                    archiveLimits = GccSourceArchiveLimits(maximumCompressedBytes = 2),
                    phaseObserver = { phases += it }).close()
            }
            assertEquals(listOf(GccSignedSourcePhase.METADATA_VERIFIED), phases)
            assertTrue(generateSequence<Throwable>(failure) { it.cause }.any {
                it.message.orEmpty().contains("1..2 bytes")
            }, failure.stackTraceToString())
        }
    }

    @Test
    fun `metadata checkpoint refuses byte identical key inode replacement and releases descriptors`() {
        GccSignedSourceFixture.create().use { fixture ->
            val before = Files.readAllBytes(fixture.key)
            val phases = mutableListOf<GccSignedSourcePhase>()
            assertFailsWith<GccSignedSourceException> {
                GccSignedSource.open(fixture.lock, fixture.archive, fixture.signature) { phase ->
                    phases += phase
                    fixture.replaceKeyInode()
                }.close()
            }
            assertEquals(listOf(GccSignedSourcePhase.METADATA_VERIFIED), phases)
            assertContentEquals(before, Files.readAllBytes(fixture.key))
            val stop = IllegalStateException("reopened metadata")
            val reopened = assertFailsWith<GccSignedSourceException> {
                GccSignedSource.open(fixture.lock, fixture.archive, fixture.signature) { throw stop }.close()
            }
            assertSame(stop, reopened.cause)
        }
    }

    @Test
    fun `observer failure and cancellation propagate without manufacturing a held source`() {
        GccSignedSourceFixture.create().use { fixture ->
            val stopped = IllegalStateException("authored observer stop")
            val failure = assertFailsWith<GccSignedSourceException> {
                GccSignedSource.open(fixture.lock, fixture.archive, fixture.signature) { throw stopped }.close()
            }
            assertSame(stopped, failure.cause)
            val phases = mutableListOf<GccSignedSourcePhase>()
            try {
                val cancelled = assertFailsWith<GccSignedSourceException> {
                    GccSignedSource.open(fixture.lock, fixture.archive, fixture.signature) { phase ->
                        phases += phase
                        Thread.currentThread().interrupt()
                    }.close()
                }
                assertTrue(generateSequence<Throwable>(cancelled) { it.cause }.any {
                    it.message.orEmpty().contains("cancellation")
                })
            } finally {
                Thread.interrupted()
            }
            assertEquals(listOf(GccSignedSourcePhase.METADATA_VERIFIED), phases)
        }
    }

    private fun assertRefused(fixture: GccSignedSourceFixture, expected: List<GccSignedSourcePhase>) {
        val phases = mutableListOf<GccSignedSourcePhase>()
        assertFailsWith<GccSignedSourceException> {
            GccSignedSource.open(fixture.lock, fixture.archive, fixture.signature) { phases += it }.close()
        }
        assertEquals(expected, phases)
    }
}

/** Reflection deliberately bypasses constructor privacy to test the independent issuance boundary. */
internal object GccSignedSourceConstructionControls {
    fun assertCloneRefused(report: ByteArray) {
        var checkpointCalled = false
        val constructor = GccSignedSource::class.java.getDeclaredConstructor(
            List::class.java, ByteArray::class.java, kotlin.jvm.functions.Function0::class.java,
        ).apply { check(trySetAccessible()) }
        val clone = constructor.newInstance(emptyList<Any>(), report.copyOf(), { checkpointCalled = true })
        clone.use {
            assertUnissued { clone.requireCurrent() }
            assertUnissued { clone.canonicalEvidence() }
            assertFalse(checkpointCalled, "unissued access must refuse before invoking caller-controlled code")
        }
        clone.close()
        assertUnissued { clone.requireCurrent() }
        assertUnissued { clone.canonicalEvidence() }
    }

    fun assertIssuance(source: GccSignedSource, issued: Boolean) {
        val owner = Class.forName("decompengine.oracle.gcc.GccSignedSourceIssuer")
        val query = owner.getDeclaredMethod("requireIssued", GccSignedSource::class.java).apply { check(trySetAccessible()) }
        val instance = owner.getDeclaredField("INSTANCE").apply { check(trySetAccessible()) }.get(null)
        if (issued) query.invoke(instance, source) else {
            val failure = assertFailsWith<InvocationTargetException> { query.invoke(instance, source) }
            assertTrue(failure.cause is IllegalStateException)
            assertTrue(failure.cause?.message.orEmpty().contains("not issued"))
        }
    }

    private fun assertUnissued(action: () -> Unit) {
        val failure = assertFailsWith<IllegalStateException>(block = action)
        assertTrue(failure.message.orEmpty().contains("not issued"), failure.stackTraceToString())
    }
}

/** Shared test-only metadata copies; no fixture changes the downloaded source archive. */
internal class GccSignedSourceFixture private constructor(val root: Path) : AutoCloseable {
    val lock: Path = root.resolve("source-lock.json")
    val key: Path = root.resolve("keys/richard-guenther-gcc-release.asc")
    val archive: Path = root.resolve("placeholder.tar.xz")
    val signature: Path = root.resolve("gcc-16.2.0.tar.xz.sig")

    fun replaceKeyInode() {
        val bytes = Files.readAllBytes(key)
        val replacement = key.resolveSibling("replacement-key.asc")
        writeOwnerFile(replacement, bytes)
        val originalIdentity = Files.getAttribute(key, "unix:ino")
        val replacementIdentity = Files.getAttribute(replacement, "unix:ino")
        check(originalIdentity != replacementIdentity)
        Files.move(key, key.resolveSibling("displaced-key.asc"))
        Files.move(replacement, key)
        check(Files.getAttribute(key, "unix:ino") == replacementIdentity)
    }

    fun replaceInputKind(path: Path, kind: String) {
        when (kind) {
            "missing" -> Files.delete(path)
            "directory" -> { Files.delete(path); Files.createDirectory(path) }
            "symlink" -> {
                val target = path.resolveSibling("${path.fileName}.target")
                Files.move(path, target)
                Files.createSymbolicLink(path, target.fileName)
            }
            "hardlink" -> Files.createLink(path.resolveSibling("${path.fileName}.alias"), path)
            "writable" -> Files.setPosixFilePermissions(path, PosixFilePermissions.fromString("rw-rw----"))
            else -> error("unknown authored input kind")
        }
    }

    override fun close() {
        Files.walk(root).use { paths -> paths.sorted(Comparator.reverseOrder()).forEach { Files.deleteIfExists(it) } }
    }

    companion object {
        val PROFILE: Path = Path.of("oracle/gcc/16.2.0").toAbsolutePath().normalize()
        val METADATA = listOf("source-lock.json", "keys/richard-guenther-gcc-release.asc",
            "tag/releases-gcc-16.2.0.payload", "tag/releases-gcc-16.2.0.sig")

        fun create(): GccSignedSourceFixture {
            val temporary = Files.createDirectories(Path.of("build/task-tmp").toAbsolutePath().normalize())
            val root = Files.createTempDirectory(temporary, "gcc-signed-source-",
                PosixFilePermissions.asFileAttribute(PosixFilePermissions.fromString("rwx------")))
            val fixture = GccSignedSourceFixture(root)
            try {
                METADATA.forEach { relative ->
                    val output = root.resolve(relative)
                    Files.createDirectories(output.parent)
                    writeOwnerFile(output, Files.readAllBytes(PROFILE.resolve(relative)))
                }
                writeOwnerFile(fixture.archive, byteArrayOf(1, 2, 3))
                writeOwnerFile(fixture.signature, signatureBytes())
                return fixture
            } catch (failure: Throwable) {
                fixture.close()
                throw failure
            }
        }

        fun signatureBytes(): ByteArray = Base64.getDecoder().decode(ARCHIVE_SIGNATURE_BASE64)

        private fun writeOwnerFile(path: Path, bytes: ByteArray) {
            Files.write(path, bytes)
            Files.setPosixFilePermissions(path, PosixFilePermissions.fromString("rw-------"))
        }

        // Exact 310-byte locked signature lets boundary tests reach archive selection without its payload.
        private const val ARCHIVE_SIGNATURE_BASE64 = "iQEzBAABCAAdFiEEf3T5fBA0aO5ddQtYOrAJlvwmpkEFAmp1l1gACgkQOrAJlvwmpkGChAgAtu0sRF51OkBjwLfopAjg91FhJATt8gXHnrDEGfYS/kasWEhSv4OETAxEAqS7t/fgDuSoSZxTo8BTEDi1NAaeYaIVyF00KQca+yBoby9q1dlIUDKXLDcLQmYyX112Zd2ds+RD7g5S5WgMmVpZeEY+Ar91xY22+L35oc8eiNWNEntgI/hRT3fEMLLR9j9uZ3RdP8IL4ajsP03YbdueMpv/nnJ5IAWpAFw+xx++iGyFapZ50u+p1cZS7YeCOg2lNbSDf0R9VUGTFWZvVWaFVNwrMv7F3e9rdY6DGBlpBgxGjHe2tUa0ZKgrFn1ogcR19Gh0dqivvrgX3R+iQX5vuNRlqg=="
    }
}
