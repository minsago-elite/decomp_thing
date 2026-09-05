package decompengine.oracle.behavior

import decompengine.oracle.core.OracleArtifacts
import decompengine.oracle.core.OracleJson
import java.io.ByteArrayInputStream
import java.io.ByteArrayOutputStream
import java.io.IOException
import java.lang.reflect.Modifier
import java.nio.file.Files
import java.nio.file.Path
import java.nio.file.attribute.BasicFileAttributes
import java.nio.file.attribute.PosixFilePermissions
import java.util.Comparator
import java.util.jar.Attributes
import java.util.jar.JarEntry
import java.util.jar.JarOutputStream
import java.util.jar.Manifest
import kotlin.test.Test
import kotlin.test.assertContentEquals
import kotlin.test.assertEquals
import kotlin.test.assertFailsWith
import kotlin.test.assertFalse
import kotlin.test.assertTrue
import kotlinx.serialization.json.JsonArray
import kotlinx.serialization.json.JsonObject
import kotlinx.serialization.json.JsonPrimitive
import org.apache.commons.compress.archivers.tar.TarArchiveInputStream

class LlvmBehaviorHostedWorkerImageV1BuildContextTest {
    @Test
    fun `production owner can only be constructed from the three raw paths`() {
        val factory = LlvmBehaviorHostedWorkerImageV1BuildContext::class.java
        val stage = factory.declaredMethods.single { method -> method.name == "stage" && !method.isSynthetic }
        assertEquals(List(3) { Path::class.java }, stage.parameterTypes.toList())
        assertEquals(LlvmBehaviorHostedWorkerImageV1BuildContextOwner::class.java, stage.returnType)

        val owner = LlvmBehaviorHostedWorkerImageV1BuildContextOwner::class.java
        assertTrue(owner.isSealed)
        val implementation = owner.permittedSubclasses.single()
        assertTrue(Modifier.isPrivate(implementation.modifiers))
        assertEquals(List(3) { Path::class.java }, implementation.declaredConstructors.single().parameterTypes.toList())
        assertEquals(
            setOf(
                "close",
                "getApplicationClosureSha256",
                "getContextManifestSha256",
                "getContextRootPathSha256",
                "getDeterministicTarBytes",
                "getDeterministicTarSha256",
                "getJdkClosureSha256",
                "getWorkerDockerfileSha256",
                "requireCurrent",
                "writeDeterministicTarTo",
            ),
            owner.declaredMethods.filterNot { it.isSynthetic }.map { it.name }.toSet(),
        )
        LlvmBehaviorHostedWorkerImageV1BuildContextTestSupport::class.java.declaredMethods
            .filterNot { it.isSynthetic }
            .forEach { method ->
                assertFalse(owner.isAssignableFrom(method.returnType), method.toString())
            }
    }

    @Test
    fun `Docker stdin prefix contains a complete regular Dockerfile header before any PAX records`() = withFixture {
        writeJar(applicationRoot.resolve("worker.jar"), listOf(WORKER_MAIN to byteArrayOf(1, 2, 3)))
        writeReference(listOf("worker.jar"))
        val output = ByteArrayOutputStream()
        LlvmBehaviorHostedWorkerImageV1BuildContextTestSupport.stage(
            dockerfile, jdkRoot, contextRoot, reference, applicationRoot, uid, output,
        )
        val archive = output.toByteArray()
        for (prefixBytes in listOf(1024, 512)) {
            TarArchiveInputStream(ByteArrayInputStream(archive.copyOf(prefixBytes))).use { input ->
                val first = checkNotNull(input.nextEntry) { "Docker stdin probe did not find a logical tar entry" }
                assertEquals("Dockerfile", first.name)
                assertTrue(first.isFile && first.isCheckSumOK)
                assertEquals(Files.size(dockerfile), first.size)
                assertEquals(292, first.mode)
                assertEquals(0L, first.longUserId)
                assertEquals(0L, first.longGroupId)
            }
        }
        assertEquals('0'.code.toByte(), archive[156])
        assertContentEquals(
            Files.readAllBytes(dockerfile),
            archive.copyOfRange(512, 512 + Files.size(dockerfile).toInt()),
        )
        val nextHeader = 512 + ((Files.size(dockerfile).toInt() + 511) / 512) * 512
        val paxPrefix = archive.copyOfRange(nextHeader, nextHeader + 1024)
        assertEquals('x'.code.toByte(), paxPrefix[156])
        val recognized = try {
            TarArchiveInputStream(ByteArrayInputStream(paxPrefix)).use { it.nextEntry != null }
        } catch (_: IOException) {
            false
        }
        assertFalse(recognized, "a PAX-only prefix must not be mistaken for a complete logical file header")
    }

    @Test
    fun `ordered launcher arguments are staged exactly and deterministic tar is replay bound`() = withFixture {
        writeJar(applicationRoot.resolve("worker.jar"), listOf(WORKER_MAIN to byteArrayOf(1, 2, 3)))
        writeJar(applicationRoot.resolve("a-dependency.jar"), listOf("dependency/Value.class" to byteArrayOf(4)))
        writeReference(listOf("worker.jar", "a-dependency.jar"))
        val lib = Files.createDirectory(jdkRoot.resolve("lib"))
        val readonly = Files.createDirectory(lib.resolve("readonly"))
        val deep = Files.createDirectory(readonly.resolve("deep"))
        val longName = "경".repeat(40) + ".txt"
        Files.writeString(deep.resolve(longName), "long UTF-8 path\n")
        mode(deep.resolve(longName), "rw-r--r--")
        Files.createSymbolicLink(lib.resolve("current"), Path.of("readonly"))
        mode(deep, "r-xr-xr-x")
        mode(readonly, "r-xr-xr-x")
        mode(lib, "r-xr-xr-x")

        val tar = ByteArrayOutputStream()
        val projection = LlvmBehaviorHostedWorkerImageV1BuildContextTestSupport.stage(
            dockerfile,
            jdkRoot,
            contextRoot,
            reference,
            applicationRoot,
            uid,
            tar,
        )
        val expectedArguments = (
            "-Djna.nosys=true\n" +
                "-Djna.tmpdir=/decomp-jna\n" +
                "-cp\n" +
                "/decomp-app/lib/worker.jar:/decomp-app/lib/a-dependency.jar\n" +
                "decompengine.oracle.behavior.LlvmBehaviorHostedCleanBuildV2InnerWorkerMain\n"
            ).encodeToByteArray()
        assertEquals(OracleArtifacts.sha256(expectedArguments), projection.workerArgumentsSha256)
        assertEquals(tar.size().toLong(), projection.deterministicTarBytes)
        assertEquals(OracleArtifacts.sha256(tar.toByteArray()), projection.deterministicTarSha256)

        val archive = parsePaxTar(tar.toByteArray())
        assertEquals(
            listOf(
                "Dockerfile",
                "app/",
                "app/lib/",
                "app/lib/a-dependency.jar",
                "app/lib/worker.jar",
                "app/worker.args",
                "jdk/",
                "jdk/bin/",
                "jdk/bin/java",
                "jdk/lib/",
                "jdk/lib/current",
                "jdk/lib/readonly/",
                "jdk/lib/readonly/deep/",
                "jdk/lib/readonly/deep/$longName",
                "jdk/release",
            ),
            archive.map(TarFixtureEntry::path),
        )
        assertContentEquals(Files.readAllBytes(dockerfile), archive.single { it.path == "Dockerfile" }.content)
        assertContentEquals(expectedArguments, archive.single { it.path == "app/worker.args" }.content)
        archive.forEach { entry ->
            assertEquals(0L, entry.uid)
            assertEquals(0L, entry.gid)
            assertEquals(1_779_182_222L, entry.mtime)
        }
        assertEquals(292, archive.single { it.path == "app/worker.args" }.mode)
        assertEquals(365, archive.single { it.path == "jdk/bin/java" }.mode)

        val commonsArchive = parsePaxTarWithCommons(tar.toByteArray())
        assertEquals(archive.map(TarFixtureEntry::path), commonsArchive.map(CommonsTarFixtureEntry::path))
        assertTrue(longName.toByteArray(Charsets.UTF_8).size > 100)
        val customByPath = archive.associateBy(TarFixtureEntry::path)
        commonsArchive.forEach { entry ->
            assertTrue(entry.checksumOk, entry.path)
            assertEquals(0L, entry.uid, entry.path)
            assertEquals(0L, entry.gid, entry.path)
            assertEquals(1_779_182_222L, entry.mtime, entry.path)
            val expectedType = when {
                entry.path.endsWith('/') -> "directory"
                entry.path == "jdk/lib/current" -> "symlink"
                else -> "file"
            }
            val expectedMode = when (expectedType) {
                "directory" -> 365 // 0555
                "symlink" -> 511 // 0777
                else -> if (entry.path == "jdk/bin/java") 365 else 292 // 0555 or 0444
            }
            assertEquals(expectedType, entry.type, entry.path)
            assertEquals(expectedMode, entry.mode, entry.path)
            assertContentEquals(customByPath.getValue(entry.path).content, entry.content, entry.path)
        }
        val link = commonsArchive.single { it.path == "jdk/lib/current" }
        assertEquals("readonly", link.linkName)
        assertContentEquals(
            "long UTF-8 path\n".encodeToByteArray(),
            commonsArchive.single { it.path.endsWith(longName) }.content,
        )
        assertTrue(tar.toByteArray().takeLast(1024).all { it == 0.toByte() })
        mode(deep, "rwxr-xr-x")
        mode(readonly, "rwxr-xr-x")
        mode(lib, "rwxr-xr-x")
        assertTrue(Files.list(contextRoot).use { stream -> stream.findAny().isEmpty })
    }

    @Test
    fun `real Gradle worker sidecar authenticates with the production parser`() {
        val projection = LlvmBehaviorHostedWorkerImageV1BuildContextTestSupport.projectConfiguredApplication()
        assertTrue(projection.entryCount > 1)
        assertTrue(projection.closureSha256.matches(Regex("[0-9a-f]{64}")))
        assertTrue(projection.workerArgumentsSha256.matches(Regex("[0-9a-f]{64}")))
    }

    @Test
    fun `nonempty private context rejection never removes caller residue`() = withFixture {
        writeJar(applicationRoot.resolve("worker.jar"), listOf(WORKER_MAIN to byteArrayOf(1)))
        writeReference(listOf("worker.jar"))
        val sentinel = contextRoot.resolve("sentinel")
        Files.writeString(sentinel, "retain me")
        mode(sentinel, "rw-------")
        val before = Files.readAttributes(sentinel, BasicFileAttributes::class.java)

        assertFailsWith<LlvmBehaviorHostedWorkerImageV1BuildContextException> {
            LlvmBehaviorHostedWorkerImageV1BuildContextTestSupport.stage(
                dockerfile,
                jdkRoot,
                contextRoot,
                reference,
                applicationRoot,
                uid,
            )
        }
        val after = Files.readAttributes(sentinel, BasicFileAttributes::class.java)
        assertEquals(before.fileKey(), after.fileKey())
        assertEquals("retain me", Files.readString(sentinel))
    }

    @Test
    fun `application closure rejects versioned main manifest indirection and ZIP64 locator`() = withFixture {
        val worker = applicationRoot.resolve("worker.jar")

        writeJar(
            worker,
            listOf(
                WORKER_MAIN to byteArrayOf(1),
                "META-INF/versions/21/$WORKER_MAIN" to byteArrayOf(2),
            ),
        )
        writeReference(listOf("worker.jar"))
        assertApplicationRejected("versioned worker main")

        val manifest = Manifest().apply {
            mainAttributes[Attributes.Name.MANIFEST_VERSION] = "1.0"
            mainAttributes[Attributes.Name.CLASS_PATH] = "ambient.jar"
        }
        writeJar(worker, listOf(WORKER_MAIN to byteArrayOf(1)), manifest)
        writeReference(listOf("worker.jar"))
        assertApplicationRejected("Class-Path")

        writeJar(
            worker,
            listOf(
                "meta-inf/manifest.mf" to
                    "Manifest-Version: 1.0\r\nClass-Path: ambient.jar\r\n\r\n".encodeToByteArray(),
                WORKER_MAIN to byteArrayOf(1),
            ),
        )
        writeReference(listOf("worker.jar"))
        assertApplicationRejected("Class-Path")

        writeJar(
            worker,
            listOf(
                "META-INF/MANIFEST.MF" to "Manifest-Version: 1.0\r\n\r\n".encodeToByteArray(),
                "meta-inf/manifest.mf" to "Manifest-Version: 1.0\r\n\r\n".encodeToByteArray(),
                WORKER_MAIN to byteArrayOf(1),
            ),
        )
        writeReference(listOf("worker.jar"))
        assertApplicationRejected("duplicate manifests")

        writeJar(
            worker,
            listOf(
                "META-INF/MANIFEST.MF" to ByteArray(2 * 1024 * 1024 + 1) { 'A'.code.toByte() },
                WORKER_MAIN to byteArrayOf(1),
            ),
        )
        writeReference(listOf("worker.jar"))
        assertApplicationRejected("manifest exceeds")

        writeJar(worker, listOf(WORKER_MAIN to byteArrayOf(1)))
        val bytes = Files.readAllBytes(worker)
        val end = findZipEnd(bytes)
        val locator = ByteArray(20)
        locator[0] = 0x50
        locator[1] = 0x4b
        locator[2] = 0x06
        locator[3] = 0x07
        Files.write(worker, bytes.copyOfRange(0, end) + locator + bytes.copyOfRange(end, bytes.size))
        writeReference(listOf("worker.jar"))
        assertApplicationRejected("ZIP64 end locator")

        writeJar(
            worker,
            listOf(
                WORKER_MAIN to byteArrayOf(1),
                "extra/Second.class" to byteArrayOf(2),
            ),
        )
        val underreported = Files.readAllBytes(worker)
        val underreportedEnd = findZipEnd(underreported)
        underreported[underreportedEnd + 8] = 1
        underreported[underreportedEnd + 9] = 0
        underreported[underreportedEnd + 10] = 1
        underreported[underreportedEnd + 11] = 0
        Files.write(worker, underreported)
        writeReference(listOf("worker.jar"))
        assertApplicationRejected("count differs")

        writeJar(worker, listOf(WORKER_MAIN to byteArrayOf(1)))
        val maximumCommentJar = Files.readAllBytes(worker)
        val maximumCommentEnd = findZipEnd(maximumCommentJar)
        val classicEnd = maximumCommentJar.copyOfRange(maximumCommentEnd, maximumCommentEnd + 22)
        classicEnd[20] = 0xff.toByte()
        classicEnd[21] = 0xff.toByte()
        Files.write(
            worker,
            maximumCommentJar.copyOfRange(0, maximumCommentEnd) + locator + classicEnd + ByteArray(65_535),
        )
        writeReference(listOf("worker.jar"))
        assertApplicationRejected("ZIP64 end locator")
    }

    @Test
    fun `sidecar order and logical JAR NAME_MAX are exact`() = withFixture {
        writeJar(applicationRoot.resolve("worker.jar"), listOf(WORKER_MAIN to byteArrayOf(1)))
        writeJar(applicationRoot.resolve("b.jar"), listOf("b/C.class" to byteArrayOf(2)))
        writeJar(applicationRoot.resolve("a.jar"), listOf("a/C.class" to byteArrayOf(3)))
        writeReference(listOf("worker.jar", "b.jar", "a.jar"))
        assertApplicationRejected("order is not canonical")

        val maximumName = "a".repeat(251) + ".jar"
        writeJar(applicationRoot.resolve(maximumName), listOf(WORKER_MAIN to byteArrayOf(1)))
        writeReference(listOf(maximumName))
        val accepted = LlvmBehaviorHostedWorkerImageV1BuildContextTestSupport.projectApplication(
            reference,
            applicationRoot,
        )
        assertEquals(1, accepted.entryCount)

        writeReferenceNamesWithoutFiles(listOf("a".repeat(252) + ".jar"))
        assertApplicationRejected("name is invalid")
    }

    @Test
    fun `JDK projection accepts only the exact runtime and safe in-root links`() = withFixture {
        val link = jdkRoot.resolve("bin/java-link")
        Files.createSymbolicLink(link, Path.of("java"))
        assertTrue(LlvmBehaviorHostedWorkerImageV1BuildContextTestSupport.projectJdk(jdkRoot, uid).entryCount >= 5)

        Files.delete(link)
        Files.createSymbolicLink(link, Path.of("../../outside"))
        assertFailsWith<LlvmBehaviorHostedWorkerImageV1BuildContextException> {
            LlvmBehaviorHostedWorkerImageV1BuildContextTestSupport.projectJdk(jdkRoot, uid)
        }
    }

    @Test
    fun `JDK projection rejects writable hard-linked and wrong-platform files`() = withFixture {
        mode(jdkRoot.resolve("release"), "rw-rw-r--")
        assertFailsWith<LlvmBehaviorHostedWorkerImageV1BuildContextException> {
            LlvmBehaviorHostedWorkerImageV1BuildContextTestSupport.projectJdk(jdkRoot, uid)
        }

        mode(jdkRoot.resolve("release"), "rw-r--r--")
        val hardLink = jdkRoot.resolve("bin/java-hardlink")
        Files.createLink(hardLink, jdkRoot.resolve("bin/java"))
        assertFailsWith<LlvmBehaviorHostedWorkerImageV1BuildContextException> {
            LlvmBehaviorHostedWorkerImageV1BuildContextTestSupport.projectJdk(jdkRoot, uid)
        }

        Files.delete(hardLink)
        Files.writeString(
            jdkRoot.resolve("release"),
            "JAVA_VERSION=\"21.0.1\"\nOS_NAME=\"Linux\"\nOS_ARCH=\"aarch64\"\nIMAGE_TYPE=\"JDK\"\n",
        )
        assertFailsWith<LlvmBehaviorHostedWorkerImageV1BuildContextException> {
            LlvmBehaviorHostedWorkerImageV1BuildContextTestSupport.projectJdk(jdkRoot, uid)
        }
    }

    @Test
    fun `JDK projection rejects owner-inaccessible directories and files`() = withFixture {
        mode(jdkRoot.resolve("release"), "---r--r--")
        assertFailsWith<LlvmBehaviorHostedWorkerImageV1BuildContextException> {
            LlvmBehaviorHostedWorkerImageV1BuildContextTestSupport.projectJdk(jdkRoot, uid)
        }

        mode(jdkRoot.resolve("release"), "rw-r--r--")
        val directory = Files.createDirectory(jdkRoot.resolve("owner-inaccessible"))
        mode(directory, "---r-xr-x")
        assertFailsWith<LlvmBehaviorHostedWorkerImageV1BuildContextException> {
            LlvmBehaviorHostedWorkerImageV1BuildContextTestSupport.projectJdk(jdkRoot, uid)
        }
        mode(directory, "rwx------")
    }

    private fun Fixture.assertApplicationRejected(messageFragment: String) {
        val failure = assertFailsWith<LlvmBehaviorHostedWorkerImageV1BuildContextException> {
            LlvmBehaviorHostedWorkerImageV1BuildContextTestSupport.projectApplication(reference, applicationRoot)
        }
        assertTrue(failure.message.orEmpty().contains(messageFragment), failure.message)
    }

    private fun withFixture(action: Fixture.() -> Unit) {
        val root = Files.createTempDirectory("llvm-worker-context-test-")
        try {
            val fixture = Fixture(root)
            fixture.action()
        } finally {
            Files.walk(root).use { paths ->
                paths.sorted(Comparator.reverseOrder()).forEach(Files::deleteIfExists)
            }
        }
    }

    private class Fixture(
        val root: Path,
    ) {
        val uid = (Files.getAttribute(root, "unix:uid") as Number).toInt()
        val applicationRoot: Path = Files.createDirectory(root.resolve("application"))
        val jdkRoot: Path = Files.createDirectory(root.resolve("jdk-source"))
        private val contextParent: Path = Files.createDirectory(root.resolve("context-parent"))
        val contextRoot: Path = Files.createDirectory(contextParent.resolve("context"))
        val reference: Path = applicationRoot.resolve(REFERENCE_NAME)
        val dockerfile: Path = root.resolve("worker.Dockerfile")

        init {
            mode(root, "rwx------")
            mode(applicationRoot, "rwxr-xr-x")
            mode(jdkRoot, "rwxr-xr-x")
            mode(contextParent, "rwx------")
            mode(contextRoot, "rwx------")
            Files.copy(Path.of("oracle/llvm/22.1.6/hosted-clean-build-v2-worker.Dockerfile"), dockerfile)
            mode(dockerfile, "rw-r--r--")
            val bin = Files.createDirectory(jdkRoot.resolve("bin"))
            mode(bin, "rwxr-xr-x")
            Files.writeString(jdkRoot.resolve("release"), VALID_RELEASE)
            mode(jdkRoot.resolve("release"), "rw-r--r--")
            Files.writeString(bin.resolve("java"), "java fixture\n")
            mode(bin.resolve("java"), "rwxr-xr-x")
        }

        fun writeReference(names: List<String>) {
            val entries = names.map { name ->
                val path = applicationRoot.resolve(name)
                ReferenceEntry(name, Files.size(path), OracleArtifacts.sha256(Files.readAllBytes(path)))
            }
            writeReferenceEntries(entries)
        }

        fun writeReferenceNamesWithoutFiles(names: List<String>) {
            writeReferenceEntries(names.map { name -> ReferenceEntry(name, 1L, "0".repeat(64)) })
        }

        private fun writeReferenceEntries(entries: List<ReferenceEntry>) {
            val encodedEntries = JsonArray(entries.map { entry ->
                JsonObject(
                    mapOf(
                        "bytes" to JsonPrimitive(entry.bytes),
                        "logicalName" to JsonPrimitive(entry.name),
                        "sha256" to JsonPrimitive(entry.sha256),
                    ),
                )
            })
            val unsigned = JsonObject(
                mapOf(
                    "entries" to encodedEntries,
                    "provider" to JsonPrimitive(PROVIDER),
                    "schemaVersion" to JsonPrimitive(1),
                ),
            )
            val closure = OracleArtifacts.sha256(OracleJson.canonicalBytes(unsigned))
            val signed = JsonObject(unsigned + ("closureSha256" to JsonPrimitive(closure)))
            Files.write(reference, OracleJson.canonicalBytes(signed))
            mode(reference, "rw-r--r--")
        }
    }

    private data class ReferenceEntry(val name: String, val bytes: Long, val sha256: String)

    private data class TarFixtureEntry(
        val path: String,
        val mode: Int,
        val uid: Long,
        val gid: Long,
        val mtime: Long,
        val content: ByteArray,
    )

    private data class CommonsTarFixtureEntry(
        val path: String,
        val type: String,
        val mode: Int,
        val uid: Long,
        val gid: Long,
        val mtime: Long,
        val linkName: String,
        val checksumOk: Boolean,
        val content: ByteArray,
    )

    private fun parsePaxTarWithCommons(bytes: ByteArray): List<CommonsTarFixtureEntry> {
        val result = mutableListOf<CommonsTarFixtureEntry>()
        TarArchiveInputStream(ByteArrayInputStream(bytes)).use { input ->
            while (true) {
                val entry = input.nextEntry ?: break
                val type = when {
                    entry.isDirectory -> "directory"
                    entry.isSymbolicLink -> "symlink"
                    entry.isFile -> "file"
                    else -> "other"
                }
                val content = input.readNBytes(entry.size.toInt())
                assertEquals(entry.size, content.size.toLong(), entry.name)
                result += CommonsTarFixtureEntry(
                    path = entry.name,
                    type = type,
                    mode = entry.mode,
                    uid = entry.longUserId,
                    gid = entry.longGroupId,
                    mtime = entry.modTime.time / 1000L,
                    linkName = entry.linkName,
                    checksumOk = entry.isCheckSumOK,
                    content = content,
                )
            }
        }
        return result
    }

    private fun parsePaxTar(bytes: ByteArray): List<TarFixtureEntry> {
        val result = mutableListOf<TarFixtureEntry>()
        var offset = 0
        var pendingPath: String? = null
        while (offset + 512 <= bytes.size) {
            val header = bytes.copyOfRange(offset, offset + 512)
            offset += 512
            if (header.all { it == 0.toByte() }) break
            val size = tarOctal(header, 124, 12)
            val type = header[156].toInt().toChar()
            val content = bytes.copyOfRange(offset, Math.addExact(offset, size.toInt()))
            offset = Math.addExact(offset, size.toInt())
            offset += (512 - size.toInt() % 512) % 512
            if (type == 'x') {
                var recordOffset = 0
                while (recordOffset < content.size) {
                    var space = recordOffset
                    while (space < content.size && content[space] != ' '.code.toByte()) space += 1
                    check(space < content.size)
                    val length = content.copyOfRange(recordOffset, space).decodeToString().toInt()
                    val record = content.copyOfRange(space + 1, recordOffset + length).decodeToString()
                    if (record.startsWith("path=")) pendingPath = record.removePrefix("path=").removeSuffix("\n")
                    recordOffset += length
                }
                continue
            }
            val path = pendingPath ?: header.copyOfRange(0, 100).takeWhile { it != 0.toByte() }
                .toByteArray().decodeToString()
            pendingPath = null
            result += TarFixtureEntry(
                path,
                tarOctal(header, 100, 8).toInt(),
                tarOctal(header, 108, 8),
                tarOctal(header, 116, 8),
                tarOctal(header, 136, 12),
                content,
            )
        }
        assertEquals(bytes.size, offset + 512)
        return result
    }

    private fun tarOctal(bytes: ByteArray, offset: Int, length: Int): Long =
        bytes.copyOfRange(offset, offset + length).takeWhile { it != 0.toByte() && it != ' '.code.toByte() }
            .toByteArray().decodeToString().ifEmpty { "0" }.toLong(8)

    private fun writeJar(path: Path, entries: List<Pair<String, ByteArray>>, manifest: Manifest? = null) {
        val output = Files.newOutputStream(path)
        (if (manifest == null) JarOutputStream(output) else JarOutputStream(output, manifest)).use { jar ->
            entries.forEach { (name, content) ->
                jar.putNextEntry(JarEntry(name))
                jar.write(content)
                jar.closeEntry()
            }
        }
        mode(path, "rw-r--r--")
    }

    private fun findZipEnd(bytes: ByteArray): Int {
        for (offset in bytes.size - 22 downTo 0) {
            if (bytes[offset] == 0x50.toByte() && bytes[offset + 1] == 0x4b.toByte() &&
                bytes[offset + 2] == 0x05.toByte() && bytes[offset + 3] == 0x06.toByte()
            ) return offset
        }
        error("ZIP end not found")
    }

    private companion object {
        const val WORKER_MAIN =
            "decompengine/oracle/behavior/LlvmBehaviorHostedCleanBuildV2InnerWorkerMain.class"
        const val REFERENCE_NAME = "llvm-behavior-hosted-worker-classpath-reference-v1.json"
        const val PROVIDER = "llvm-behavior-hosted-worker-deployment-classpath-reference-v1"
        const val VALID_RELEASE =
            "JAVA_VERSION=\"21.0.1\"\nOS_NAME=\"Linux\"\nOS_ARCH=\"amd64\"\nIMAGE_TYPE=\"JDK\"\n"
    }
}

private fun mode(path: Path, value: String) {
    Files.setPosixFilePermissions(path, PosixFilePermissions.fromString(value))
}
