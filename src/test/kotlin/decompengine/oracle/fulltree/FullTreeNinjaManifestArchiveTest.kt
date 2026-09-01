package decompengine.oracle.fulltree

import decompengine.acp.AcpRuntimeClosureLimits
import java.io.ByteArrayOutputStream
import java.io.IOException
import java.lang.reflect.Modifier
import java.nio.charset.StandardCharsets
import java.nio.file.Files
import java.nio.file.Path
import java.nio.file.LinkOption
import java.nio.file.attribute.PosixFilePermissions
import java.security.MessageDigest
import kotlin.test.Test
import kotlin.test.assertEquals
import kotlin.test.assertFailsWith
import kotlin.test.assertFalse
import kotlin.test.assertNotEquals
import kotlin.test.assertTrue
import org.tukaani.xz.LZMA2Options
import org.tukaani.xz.XZ
import org.tukaani.xz.XZOutputStream

class FullTreeNinjaManifestArchiveTest {
    @Test
    fun `strict archive derives deterministic immutable closure and rule manifests`() =
        inControlTemporaryDirectory { directory ->
            val files = validNinjaManifestFiles()
            val rootBytes = files.getValue("build.ninja")
            val archivePath = writeNinjaManifestArchiveForTest(
                directory.resolve("manifest.tar.xz"),
                files,
                NINJA_TEST_EPOCH,
            )

            val first = FullTreeNinjaManifestArchive.inspect(
                archivePath,
                rootBytes.size.toLong(),
                ninjaManifestTestSha256(rootBytes),
                NINJA_TEST_EPOCH,
            )
            val second = FullTreeNinjaManifestArchive.inspect(
                archivePath,
                rootBytes.size.toLong(),
                ninjaManifestTestSha256(rootBytes),
                NINJA_TEST_EPOCH,
            )

            assertEquals(Files.size(archivePath), first.archiveBytes)
            assertEquals(ninjaManifestTestSha256(Files.readAllBytes(archivePath)), first.archiveSha256)
            assertEquals(FullTreeNinjaManifestArchive.configurationSha256, first.configurationSha256)
            assertEquals("ninja-manifest", first.archiveRoot)
            assertEquals("build.ninja", first.rootManifest)
            assertEquals(files.values.sumOf { it.size.toLong() }, first.totalBytes)
            assertEquals(files.keys, first.files.map { it.path }.toSet())
            assertEquals(3, first.edges.size)
            assertEquals(
                setOf(
                    Triple("build.ninja", FullTreeNinjaManifestEdgeKind.INCLUDE, "CMakeFiles/rules.ninja"),
                    Triple("build.ninja", FullTreeNinjaManifestEdgeKind.SUBNINJA, "sub/targets.ninja"),
                    Triple("CMakeFiles/rules.ninja", FullTreeNinjaManifestEdgeKind.INCLUDE, "shared/common.ninja"),
                ),
                first.edges.map { Triple(it.sourcePath, it.kind, it.targetPath) }.toSet(),
            )
            assertEquals(listOf("CUSTOM", "CXX", "LINK"), first.rules.map { it.name })
            assertEquals(first.reportSha256, second.reportSha256)
            assertEquals(first.fileManifestSha256, second.fileManifestSha256)
            assertEquals(first.includeGraphSha256, second.includeGraphSha256)
            assertEquals(first.ruleManifestSha256, second.ruleManifestSha256)
            assertNotEquals(first.fileManifestSha256, first.includeGraphSha256)
            assertNotEquals(first.includeGraphSha256, first.ruleManifestSha256)
            assertFalse(first.processAuthority)
            assertFalse(first.runAuthority)

            val materialization = loadFullTreeNinjaManifestMaterialization(
                archivePath,
                rootBytes.size.toLong(),
                ninjaManifestTestSha256(rootBytes),
                NINJA_TEST_EPOCH,
            )
            assertEquals(first.reportSha256, materialization.snapshot.reportSha256)
            assertEquals(files.keys, materialization.paths.toSet())
            val defensive = materialization.bytes("build.ninja")
            defensive[0] = (defensive[0].toInt() xor 1).toByte()
            assertEquals(
                ninjaManifestTestSha256(rootBytes),
                ninjaManifestTestSha256(materialization.bytes("build.ninja")),
            )
            val sharedScratch = directory.resolve("shared-materialization-scratch")
            Files.createDirectory(sharedScratch)
            Files.setPosixFilePermissions(sharedScratch, PosixFilePermissions.fromString("rwxr-xr-x"))
            assertFailsWith<IOException> {
                PrivateNinjaManifestTree.create(
                    sharedScratch,
                    materialization,
                    AcpRuntimeClosureLimits(64, 1024L * 1024L, 16),
                )
            }
            assertTrue(Files.list(sharedScratch).use { children -> children.findAny().isEmpty })
            val scratch = directory.resolve("materialization-scratch")
            Files.createDirectory(scratch)
            Files.setPosixFilePermissions(scratch, PosixFilePermissions.fromString("rwx------"))
            val tree = PrivateNinjaManifestTree.create(
                scratch,
                materialization,
                AcpRuntimeClosureLimits(
                    maximumEntries = 64,
                    maximumUserOwnedFileBytes = 1024L * 1024L,
                    maximumDepth = 16,
                ),
            )
            val treePath = tree.path
            materialization.paths.forEach { relative ->
                assertTrue(Files.readAllBytes(treePath.resolve(relative)).contentEquals(files.getValue(relative)))
                assertEquals(
                    PosixFilePermissions.fromString("r--------"),
                    Files.getPosixFilePermissions(treePath.resolve(relative), LinkOption.NOFOLLOW_LINKS),
                )
            }
            tree.verifyUnchanged()
            tree.close()
            assertFalse(Files.exists(treePath, LinkOption.NOFOLLOW_LINKS))
            assertTrue(Files.list(scratch).use { children -> children.findAny().isEmpty })

            assertFailsWith<UnsupportedOperationException> {
                @Suppress("UNCHECKED_CAST")
                (first.files as MutableList<FullTreeNinjaManifestFile>).clear()
            }
            assertFailsWith<UnsupportedOperationException> {
                @Suppress("UNCHECKED_CAST")
                (first.edges as MutableList<FullTreeNinjaManifestEdge>).clear()
            }
            assertFailsWith<UnsupportedOperationException> {
                @Suppress("UNCHECKED_CAST")
                (first.rules as MutableList<FullTreeNinjaManifestRule>).clear()
            }
        }

    @Test
    fun `public surface admits raw archive identity only and invokes no process`() {
        val methods = FullTreeNinjaManifestArchive::class.java.declaredMethods
            .filter { Modifier.isPublic(it.modifiers) && !it.isSynthetic }
        assertEquals(setOf("getConfigurationSha256", "inspect"), methods.map { it.name }.toSet())
        val inspect = methods.single { it.name == "inspect" }
        assertEquals(
            listOf(
                Path::class.java,
                Long::class.javaPrimitiveType,
                String::class.java,
                Long::class.javaPrimitiveType,
                FullTreeNinjaManifestArchiveLimits::class.java,
            ),
            inspect.parameterTypes.toList(),
        )
        val production = Path.of(
            "src/main/kotlin/decompengine/oracle/fulltree/FullTreeNinjaManifestArchive.kt",
        ).toFile().readText()
        listOf(
            "ProcessBuilder",
            "Runtime.getRuntime",
            "java.lang.Process",
            "java.util.function",
            "kotlin.io.path.createTempDirectory",
        ).forEach { forbidden -> assertFalse(production.contains(forbidden), forbidden) }
    }

    @Test
    fun `missing dynamic duplicate cyclic and extra closure material fails closed`() =
        inControlTemporaryDirectory { directory ->
            val variants = listOf(
                mapOf("build.ninja" to "include missing.ninja\n".ninjaBytes()),
                mapOf("build.ninja" to "include \$manifest\n".ninjaBytes()),
                mapOf(
                    "build.ninja" to "include child.ninja\ninclude child.ninja\n".ninjaBytes(),
                    "child.ninja" to "# child\n".ninjaBytes(),
                ),
                mapOf(
                    "build.ninja" to "include\tchild.ninja\n".ninjaBytes(),
                    "child.ninja" to "# child\n".ninjaBytes(),
                ),
                mapOf(
                    "build.ninja" to "include child.ninja|ignored\n".ninjaBytes(),
                    "child.ninja|ignored" to "# child\n".ninjaBytes(),
                ),
                mapOf(
                    "build.ninja" to "include first.ninja second.ninja\n".ninjaBytes(),
                    "first.ninja" to "# first\n".ninjaBytes(),
                    "second.ninja" to "# second\n".ninjaBytes(),
                ),
                mapOf(
                    "build.ninja" to "include child.ninja\n".ninjaBytes(),
                    "child.ninja" to "include build.ninja\n".ninjaBytes(),
                ),
                mapOf(
                    "build.ninja" to "include child.ninja\n".ninjaBytes(),
                    "child.ninja" to "# complete comment\$\ninclude build.ninja\n".ninjaBytes(),
                ),
                mapOf(
                    "build.ninja" to
                        "include child.ninja\ninclude shared.ninja\n".ninjaBytes(),
                    "child.ninja" to
                        "include shared.ninja\n  # complete comment\$\ninclude shared.ninja\n".ninjaBytes(),
                    "shared.ninja" to "# shared\n".ninjaBytes(),
                ),
                mapOf(
                    "build.ninja" to "rule SAME\n  command = first\ninclude child.ninja\n".ninjaBytes(),
                    "child.ninja" to "rule SAME\n  command = second\n".ninjaBytes(),
                ),
                mapOf(
                    "build.ninja" to "# no includes\n".ninjaBytes(),
                    "extra.ninja" to "# unreachable\n".ninjaBytes(),
                ),
            )
            variants.forEachIndexed { index, files ->
                val path = writeNinjaManifestArchiveForTest(
                    directory.resolve("invalid-$index.tar.xz"),
                    files,
                    NINJA_TEST_EPOCH,
                )
                val root = files.getValue("build.ninja")
                assertFailsWith<FullTreeNinjaManifestArchiveException>("variant $index") {
                    FullTreeNinjaManifestArchive.inspect(
                        path,
                        root.size.toLong(),
                        ninjaManifestTestSha256(root),
                        NINJA_TEST_EPOCH,
                    )
                }
            }
        }

    @Test
    fun `text root epoch and caller lowered bounds fail closed`() =
        inControlTemporaryDirectory { directory ->
            val textVariants = listOf(
                "rule CXX\r\n".toByteArray(StandardCharsets.UTF_8),
                "rule CXX".toByteArray(StandardCharsets.UTF_8),
                byteArrayOf(0xc3.toByte(), 0x28, '\n'.code.toByte()),
                "include child\$\n  .ninja\n".ninjaBytes(),
                "rule INVALID+RULE\n  command = rejected\n".ninjaBytes(),
            )
            textVariants.forEachIndexed { index, root ->
                val path = writeNinjaManifestArchiveForTest(
                    directory.resolve("text-$index.tar.xz"),
                    mapOf("build.ninja" to root),
                    NINJA_TEST_EPOCH,
                )
                assertFailsWith<FullTreeNinjaManifestArchiveException>("text variant $index") {
                    FullTreeNinjaManifestArchive.inspect(
                        path,
                        root.size.toLong(),
                        ninjaManifestTestSha256(root),
                        NINJA_TEST_EPOCH,
                    )
                }
            }

            val files = validNinjaManifestFiles()
            val root = files.getValue("build.ninja")
            val path = writeNinjaManifestArchiveForTest(
                directory.resolve("bounded.tar.xz"),
                files,
                NINJA_TEST_EPOCH,
            )
            assertFailsWith<FullTreeNinjaManifestArchiveException> {
                FullTreeNinjaManifestArchive.inspect(
                    path,
                    root.size.toLong(),
                    "0".repeat(64),
                    NINJA_TEST_EPOCH,
                )
            }
            assertFailsWith<FullTreeNinjaManifestArchiveException> {
                FullTreeNinjaManifestArchive.inspect(
                    path,
                    root.size.toLong(),
                    ninjaManifestTestSha256(root),
                    NINJA_TEST_EPOCH + 1,
                )
            }
            assertFailsWith<FullTreeNinjaManifestArchiveException> {
                FullTreeNinjaManifestArchive.inspect(
                    path,
                    root.size.toLong(),
                    ninjaManifestTestSha256(root),
                    NINJA_TEST_EPOCH,
                    FullTreeNinjaManifestArchiveLimits(maximumManifestFiles = 1),
                )
            }
            assertFailsWith<FullTreeNinjaManifestArchiveException> {
                FullTreeNinjaManifestArchive.inspect(
                    path,
                    root.size.toLong(),
                    ninjaManifestTestSha256(root),
                    NINJA_TEST_EPOCH,
                    FullTreeNinjaManifestArchiveLimits(maximumIncludeEdges = 1),
                )
            }
        }
}

/** Strict deterministic archive writer shared only by full-tree Ninja control tests. */
internal fun writeNinjaManifestArchiveForTest(
    output: Path,
    files: Map<String, ByteArray>,
    sourceDateEpoch: Long,
): Path {
    require(files.isNotEmpty())
    val directories = linkedSetOf("")
    files.keys.forEach { path ->
        require(path.isNotEmpty() && !path.startsWith('/') && !path.endsWith('/'))
        val components = path.split('/')
        for (end in 1 until components.size) directories += components.take(end).joinToString("/")
    }
    val tar = ByteArrayOutputStream()
    writeNinjaManifestTestTarEntry(
        tar,
        NinjaManifestTestTarEntry("ninja-manifest/", '5', byteArrayOf()),
        sourceDateEpoch,
    )
    directories.filter(String::isNotEmpty)
        .sortedWith(compareBy<String> { it.count { character -> character == '/' } }.thenBy { it })
        .forEach { directory ->
            writeNinjaManifestTestTarEntry(
                tar,
                NinjaManifestTestTarEntry("ninja-manifest/$directory/", '5', byteArrayOf()),
                sourceDateEpoch,
            )
        }
    files.toSortedMap().forEach { (path, bytes) ->
        writeNinjaManifestTestTarEntry(
            tar,
            NinjaManifestTestTarEntry("ninja-manifest/$path", '0', bytes),
            sourceDateEpoch,
        )
    }
    val recordRemainder = tar.size() / NINJA_TEST_TAR_BLOCK_BYTES % NINJA_TEST_TAR_RECORD_BLOCKS
    val terminatorBlocks = (NINJA_TEST_TAR_RECORD_BLOCKS - recordRemainder).let { remainder ->
        if (remainder < 2) remainder + NINJA_TEST_TAR_RECORD_BLOCKS else remainder
    }
    repeat(terminatorBlocks) { tar.write(ByteArray(NINJA_TEST_TAR_BLOCK_BYTES)) }

    val compressed = ByteArrayOutputStream()
    XZOutputStream(compressed, LZMA2Options(1), XZ.CHECK_CRC64).use { stream ->
        stream.write(tar.toByteArray())
    }
    Files.write(output, compressed.toByteArray())
    Files.setPosixFilePermissions(output, PosixFilePermissions.fromString("rw-r--r--"))
    return output
}

private fun writeNinjaManifestTestTarEntry(
    output: ByteArrayOutputStream,
    entry: NinjaManifestTestTarEntry,
    sourceDateEpoch: Long,
) {
    output.write(ninjaManifestTestTarHeader(entry, sourceDateEpoch))
    output.write(entry.bytes)
    val padding = (NINJA_TEST_TAR_BLOCK_BYTES - entry.bytes.size % NINJA_TEST_TAR_BLOCK_BYTES) %
        NINJA_TEST_TAR_BLOCK_BYTES
    repeat(padding) { output.write(0) }
}

private fun ninjaManifestTestTarHeader(entry: NinjaManifestTestTarEntry, mtime: Long): ByteArray {
    val header = ByteArray(NINJA_TEST_TAR_BLOCK_BYTES)
    val (name, prefix) = splitNinjaManifestTestUstarPath(entry.path)
    ninjaManifestTestTarText(header, 0, 100, name, terminate = false)
    ninjaManifestTestTarOctal(header, 100, 8, if (entry.kind == '5') 0x1fd else 0x1b4)
    ninjaManifestTestTarOctal(header, 108, 8, 0)
    ninjaManifestTestTarOctal(header, 116, 8, 0)
    ninjaManifestTestTarOctal(header, 124, 12, entry.bytes.size.toLong())
    ninjaManifestTestTarOctal(header, 136, 12, mtime)
    repeat(8) { header[148 + it] = ' '.code.toByte() }
    header[156] = entry.kind.code.toByte()
    ninjaManifestTestTarText(header, 257, 6, "ustar")
    ninjaManifestTestTarText(header, 263, 2, "00", terminate = false)
    ninjaManifestTestTarText(header, 265, 32, "root")
    ninjaManifestTestTarText(header, 297, 32, "root")
    ninjaManifestTestTarOctal(header, 329, 8, 0)
    ninjaManifestTestTarOctal(header, 337, 8, 0)
    ninjaManifestTestTarText(header, 345, 155, prefix, terminate = false)
    val checksum = header.sumOf { byte -> byte.toInt() and 0xff }.toLong()
    ninjaManifestTestTarOctal(header, 148, 8, checksum)
    return header
}

private fun ninjaManifestTestTarText(
    header: ByteArray,
    offset: Int,
    length: Int,
    value: String,
    terminate: Boolean = true,
) {
    val bytes = value.toByteArray(StandardCharsets.US_ASCII)
    require(bytes.size <= length - if (terminate) 1 else 0)
    bytes.copyInto(header, offset)
}

private fun ninjaManifestTestTarOctal(
    header: ByteArray,
    offset: Int,
    length: Int,
    value: Number,
) {
    val encoded = value.toLong().toString(8).padStart(length - 1, '0')
    require(encoded.length == length - 1)
    encoded.toByteArray(StandardCharsets.US_ASCII).copyInto(header, offset)
    header[offset + length - 1] = 0
}

private fun splitNinjaManifestTestUstarPath(path: String): Pair<String, String> {
    if (path.toByteArray(StandardCharsets.US_ASCII).size <= 100) return path to ""
    val separator = path.indices.reversed().firstOrNull { index ->
        index != path.lastIndex && path[index] == '/' &&
            path.substring(0, index).toByteArray(StandardCharsets.US_ASCII).size <= 155 &&
            path.substring(index + 1).toByteArray(StandardCharsets.US_ASCII).size <= 100
    } ?: error("test path does not fit canonical USTAR")
    return path.substring(separator + 1) to path.substring(0, separator)
}

private fun validNinjaManifestFiles(): Map<String, ByteArray> = linkedMapOf(
    "build.ninja" to (
        "ninja_required_version = 1.11\n" +
            "include.name = ordinary-variable\n" +
            "include CMakeFiles/rules.ninja\n" +
            "subninja sub/targets.ninja\n" +
            "build all: phony\n"
        ).ninjaBytes(),
    "CMakeFiles/rules.ninja" to (
        "rule CXX\n" +
            "  command = clang++ -c input.cc -o output.o\n" +
            "include shared/common.ninja\n"
        ).ninjaBytes(),
    "shared/common.ninja" to (
        "rule CUSTOM\n" +
            "  command = tool\n"
        ).ninjaBytes(),
    "sub/targets.ninja" to (
        "rule LINK\n" +
            "  command = clang++ input.o -o output\n"
        ).ninjaBytes(),
)

private fun String.ninjaBytes(): ByteArray = toByteArray(StandardCharsets.UTF_8)

private fun ninjaManifestTestSha256(bytes: ByteArray): String = MessageDigest.getInstance("SHA-256")
    .digest(bytes)
    .joinToString("") { byte -> (byte.toInt() and 0xff).toString(16).padStart(2, '0') }

private data class NinjaManifestTestTarEntry(
    val path: String,
    val kind: Char,
    val bytes: ByteArray,
)

private const val NINJA_TEST_TAR_BLOCK_BYTES = 512
private const val NINJA_TEST_TAR_RECORD_BLOCKS = 20
private const val NINJA_TEST_EPOCH = 946_684_800L
