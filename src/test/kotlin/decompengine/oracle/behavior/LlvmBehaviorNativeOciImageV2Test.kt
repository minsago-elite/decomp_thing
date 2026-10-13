package decompengine.oracle.behavior

import decompengine.oracle.core.OracleArtifacts
import decompengine.oracle.core.OracleJson
import io.airlift.compress.zstd.ZstdInputStream
import java.io.ByteArrayInputStream
import java.io.ByteArrayOutputStream
import java.nio.file.Files
import java.nio.file.Path
import java.nio.file.StandardCopyOption
import java.nio.file.attribute.PosixFilePermission
import java.util.Base64
import java.util.zip.GZIPOutputStream
import kotlin.test.Test
import kotlin.test.assertContentEquals
import kotlin.test.assertEquals
import kotlin.test.assertFailsWith
import kotlin.test.assertFalse
import kotlin.test.assertNotEquals
import kotlin.test.assertTrue
import kotlinx.serialization.json.JsonArray
import kotlinx.serialization.json.JsonObject
import kotlinx.serialization.json.JsonPrimitive
import org.apache.commons.compress.archivers.tar.TarArchiveEntry
import org.apache.commons.compress.archivers.tar.TarArchiveOutputStream
import org.apache.commons.compress.archivers.tar.TarConstants

class LlvmBehaviorNativeOciImageV2Test {
    @Test
    fun `actual GNU pax tar retains long paths hardlinks and container-root symlinks`() {
        Fixture().use { fixture ->
            val tree = fixture.directory("tree")
            val bin = Files.createDirectories(tree.resolve("usr/bin"))
            val bytes = "actual tar file\n".encodeToByteArray()
            Files.write(bin.resolve("compiler"), bytes)
            Files.createLink(bin.resolve("compiler-alias"), bin.resolve("compiler"))
            Files.createSymbolicLink(bin.resolve("absolute"), Path.of("/usr/bin/compiler"))
            Files.createSymbolicLink(bin.resolve("relative"), Path.of("compiler"))
            val long = "long-" + "q".repeat(180)
            Files.write(bin.resolve(long), "long path\n".encodeToByteArray())
            val tar = fixture.gnuTar(tree, listOf("--format=pax"))
            val layout = fixture.layout(listOf(tar), gzip = true)
            LlvmBehaviorNativeOciImageV2.openLayout(layout).use { image ->
                assertContentEquals(bytes, image.readFile("/usr/bin/absolute", 100))
                assertContentEquals(bytes, image.readFile("/usr/bin/relative", 100))
                assertContentEquals("long path\n".encodeToByteArray(), image.readFile("/usr/bin/$long", 100))
                assertEquals(image.resolve("/usr/bin/compiler").inode, image.resolve("/usr/bin/compiler-alias").inode)
                assertEquals(OracleArtifacts.sha256(tar), image.layers.single().diffId)
                assertNotEquals(image.layers.single().blobSha256, image.layers.single().diffId)
                assertTrue(image.namespaceSha256.matches(Regex("[0-9a-f]{64}")))
                @Suppress("UNCHECKED_CAST")
                assertFailsWith<UnsupportedOperationException> { (image.namespace as MutableMap<String, LlvmBehaviorNativeOciImageV2.Entry>).clear() }
            }
        }
    }

    @Test
    fun `whiteouts and opaque markers precede same-layer creates regardless tar order`() {
        Fixture().use { fixture ->
            val lower = tar(
                Item("a/", type = TarConstants.LF_DIR), Item("a/old", "old"),
                Item("a/sub/", type = TarConstants.LF_DIR), Item("a/sub/old", "nested"),
                Item("gone", "old"), Item("preserved", "lower"),
            )
            val upper = tar(
                Item("a/new", "new"), Item("gone", "replacement"),
                Item("a/.wh..wh..opq"), Item(".wh.gone"),
            )
            LlvmBehaviorNativeOciImageV2.openLayout(fixture.layout(listOf(lower, upper))).use { image ->
                assertFalse(image.namespace.containsKey("/a/old"))
                assertFalse(image.namespace.containsKey("/a/sub/old"))
                assertFalse(image.namespace.keys.any { it.contains(".wh.") })
                assertContentEquals("new".encodeToByteArray(), image.readFile("/a/new", 30))
                assertContentEquals("replacement".encodeToByteArray(), image.readFile("/gone", 30))
                assertContentEquals("lower".encodeToByteArray(), image.readFile("/preserved", 30))
            }
        }
    }

    @Test
    fun `forward hardlinks and cross-layer aliases retain inode bytes after target replacement`() {
        Fixture().use { fixture ->
            val first = tar(Item("original", "old"), Item("cross-alias", type = TarConstants.LF_LINK, link = "original"))
            val second = tar(
                Item("forward", type = TarConstants.LF_LINK, link = "new"),
                Item("original", "replacement"), Item("new", "fresh"),
            )
            LlvmBehaviorNativeOciImageV2.openLayout(fixture.layout(listOf(first, second))).use { image ->
                assertContentEquals("old".encodeToByteArray(), image.readFile("/cross-alias", 30))
                assertContentEquals("replacement".encodeToByteArray(), image.readFile("/original", 30))
                assertContentEquals("fresh".encodeToByteArray(), image.readFile("/forward", 30))
                assertEquals(image.resolve("/forward").inode, image.resolve("/new").inode)
                assertNotEquals(image.resolve("/original").inode, image.resolve("/cross-alias").inode)
            }
            assertFailsWith<LlvmBehaviorNativeOciImageV2Exception> {
                LlvmBehaviorNativeOciImageV2.openLayout(fixture.layout(listOf(first, tar(Item("original", type = TarConstants.LF_LINK, link = "original")))))
            }
        }
    }

    @Test
    fun `hardlink headers update every inode alias while preserving shared content`() {
        Fixture().use { fixture ->
            val layer = tar(
                Item("original", "content", mode = 0x180, mtime = 1000),
                Item("first-alias", type = TarConstants.LF_LINK, link = "original", mode = 0x1a0, uid = 123, gid = 456, mtime = 2000, pax = mapOf("SCHILY.xattr.user.note" to "first")),
                Item("second-alias", type = TarConstants.LF_LINK, link = "/original", mode = 0x1b0, uid = 789, gid = 987, mtime = 3000, pax = mapOf("SCHILY.xattr.user.second" to "second")),
            )
            LlvmBehaviorNativeOciImageV2.openLayout(fixture.layout(listOf(layer))).use { image ->
                val aliases = listOf("/original", "/first-alias", "/second-alias").map(image::resolve)
                assertEquals(1, aliases.map { it.inode }.distinct().size)
                aliases.forEach { entry ->
                    assertEquals(0x1b0L, entry.mode); assertEquals(789L, entry.uid); assertEquals(987L, entry.gid)
                    assertEquals("3", entry.modificationTime)
                    assertEquals(Base64.getEncoder().encodeToString("first".encodeToByteArray()), entry.xattrs["user.note"])
                    assertEquals(Base64.getEncoder().encodeToString("second".encodeToByteArray()), entry.xattrs["user.second"])
                    assertContentEquals("content".encodeToByteArray(), image.readFile(entry.path, 100))
                }
            }
            val currentUid = Files.getAttribute(fixture.root, "unix:uid") as Int
            val currentGid = Files.getAttribute(fixture.root, "unix:gid") as Int
            val nativeLayer = tar(Item("original", "content", mode = 0x180, uid = currentUid, gid = currentGid, mtime = 1000),
                Item("alias", type = TarConstants.LF_LINK, link = "original", mode = 0x1a0, uid = currentUid, gid = currentGid, mtime = 2000))
            val extracted = fixture.extractTar(nativeLayer)
            assertTrue(Files.isSameFile(extracted.resolve("original"), extracted.resolve("alias")))
            // GNU tar ignores differing hardlink-header metadata. The pinned Docker extractor
            // explicitly applies it; verify that the actual filesystem updates every inode alias.
            assertEquals(0x180, (Files.getAttribute(extracted.resolve("original"), "unix:mode") as Int) and 0xfff)
            assertEquals(1000L, Files.getLastModifiedTime(extracted.resolve("original")).toMillis())
            Files.setPosixFilePermissions(extracted.resolve("alias"), setOf(PosixFilePermission.OWNER_READ, PosixFilePermission.OWNER_WRITE, PosixFilePermission.GROUP_READ))
            Files.setLastModifiedTime(extracted.resolve("alias"), java.nio.file.attribute.FileTime.fromMillis(2000))
            assertEquals(0x1a0, (Files.getAttribute(extracted.resolve("original"), "unix:mode") as Int) and 0xfff)
            assertEquals(2000L, Files.getLastModifiedTime(extracted.resolve("original")).toMillis())
        }
    }

    @Test
    fun `implied directories are present with explicit unknown timestamps and later headers override`() {
        Fixture().use { fixture ->
            val first = tar(Item("bin/nested/tool", "implied parents"))
            val second = tar(Item("bin/", type = TarConstants.LF_DIR, mode = 0x1c0, mtime = 3000))
            LlvmBehaviorNativeOciImageV2.openLayout(fixture.layout(listOf(first, second))).use { image ->
                assertEquals("directory", image.resolve("/bin").kind)
                assertEquals(0x1c0L, image.resolve("/bin").mode)
                assertEquals("tar-header", image.resolve("/bin").metadataOrigin)
                val implied = image.resolve("/bin/nested")
                assertEquals(0x1edL, implied.mode); assertEquals(0L, implied.uid); assertEquals(0L, implied.gid)
                assertEquals("implied-directory", implied.metadataOrigin)
                assertFalse(implied.modificationTimeKnown)
                assertFalse(image.resolve("/").modeKnown)
                assertContentEquals("implied parents".encodeToByteArray(), image.readFile("/bin/nested/tool", 100))
            }
            val tree = fixture.directory("implied-gnu-tree")
            Files.createDirectories(tree.resolve("bin")); Files.writeString(tree.resolve("bin/tool"), "GNU implied")
            val bytes = fixture.gnuTar(tree, listOf("--format=pax"), listOf("bin/tool"))
            LlvmBehaviorNativeOciImageV2.openLayout(fixture.layout(listOf(bytes))).use { image ->
                assertEquals("implied-directory", image.resolve("/bin").metadataOrigin)
                assertContentEquals("GNU implied".encodeToByteArray(), image.readFile("/bin/tool", 100))
            }
        }
    }

    @Test
    fun `range batches stream large selected files with order overlap and bounds preserved`() {
        Fixture().use { fixture ->
            val bytes = "0123456789abcdefghijklmnopqrstuvwxyz"
            val layer = tar(Item("file", bytes))
            listOf(false, true).forEach { gzip ->
                LlvmBehaviorNativeOciImageV2.openLayout(fixture.layout(listOf(layer), gzip = gzip)).use { image ->
                    val result = image.readFileRanges("/file", listOf(LlvmBehaviorNativeOciImageV2.FileRange(10, 8), LlvmBehaviorNativeOciImageV2.FileRange(0, 12), LlvmBehaviorNativeOciImageV2.FileRange(10, 2), LlvmBehaviorNativeOciImageV2.FileRange(bytes.length.toLong(), 0)))
                    assertContentEquals("abcdefgh".encodeToByteArray(), result[0]); assertContentEquals("0123456789ab".encodeToByteArray(), result[1]); assertContentEquals("ab".encodeToByteArray(), result[2]); assertEquals(0, result[3].size)
                    assertContentEquals("xyz".encodeToByteArray(), image.readFileRange("/file", 33, 3))
                    assertFailsWith<LlvmBehaviorNativeOciImageV2Exception> { image.readFileRange("/file", Long.MAX_VALUE, 1) }
                    assertFailsWith<LlvmBehaviorNativeOciImageV2Exception> { image.readFileRange("/file", 0, 4 * 1024 * 1024 + 1) }
                    assertFailsWith<LlvmBehaviorNativeOciImageV2Exception> { image.readFileRange("/file", -1, 0) }
                    assertFailsWith<TestCancellation> { image.readFileRange("/file", 0, 3) { throw TestCancellation() } }
                }
            }
        }
    }

    @Test
    fun `range API reads authored 65MiB file without the full-file allocation admission`() {
        Fixture().use { fixture ->
            val tree = fixture.directory("large-range-tree")
            val source = tree.resolve("large")
            Files.newOutputStream(source).use { output ->
                val block = ByteArray(64 * 1024)
                repeat(65 * 16) { output.write(block) }
            }
            val layer = fixture.gnuTar(tree, listOf("--format=gnu"))
            LlvmBehaviorNativeOciImageV2.openLayout(fixture.layout(listOf(layer), gzip = true)).use { image ->
                assertEquals(65L * 1024 * 1024, image.resolve("/large").size)
                assertFailsWith<LlvmBehaviorNativeOciImageV2Exception> { image.readFile("/large", 64 * 1024 * 1024) }
                val result = image.readFileRanges("/large", listOf(LlvmBehaviorNativeOciImageV2.FileRange(0, 16), LlvmBehaviorNativeOciImageV2.FileRange(65L * 1024 * 1024 - 16, 16)))
                assertContentEquals(ByteArray(16), result[0]); assertContentEquals(ByteArray(16), result[1])
                image.requireCurrent()
            }
        }
    }

    @Test
    fun `symlink parents resolve inside container root and non-directories are rejected`() {
        Fixture().use { fixture ->
            val lower = tar(Item("real/", type = TarConstants.LF_DIR), Item("alias", type = TarConstants.LF_SYMLINK, link = "/real"))
            val upper = tar(Item("alias/file", "through virtual symlink"))
            LlvmBehaviorNativeOciImageV2.openLayout(fixture.layout(listOf(lower, upper))).use { image ->
                assertTrue(image.namespace.containsKey("/real/file"))
                assertContentEquals("through virtual symlink".encodeToByteArray(), image.readFile("/alias/file", 100))
            }
            assertFailsWith<LlvmBehaviorNativeOciImageV2Exception> {
                LlvmBehaviorNativeOciImageV2.openLayout(fixture.layout(listOf(tar(Item("file", "x"), Item("file/child", "y")))))
            }
        }
    }

    @Test
    fun `actual GNU base256 metadata and devices are modelled without extraction`() {
        Fixture().use { fixture ->
            val tree = fixture.directory("base256-tree")
            Files.write(tree.resolve("file"), "content".encodeToByteArray())
            val bytes = fixture.gnuTar(tree, listOf("--format=gnu", "--owner=2147483648", "--group=2147483649"))
            LlvmBehaviorNativeOciImageV2.openLayout(fixture.layout(listOf(bytes))).use { image ->
                assertEquals(2147483648L, image.resolve("/file").uid)
                assertEquals(2147483649L, image.resolve("/file").gid)
            }
            val nodes = tar(Item("device", type = TarConstants.LF_CHR, major = 1, minor = 3), Item("pipe", type = TarConstants.LF_FIFO))
            LlvmBehaviorNativeOciImageV2.openLayout(fixture.layout(listOf(nodes))).use { image ->
                assertEquals("character", image.resolve("/device").kind)
                assertEquals(1L, image.resolve("/device").deviceMajor)
                assertEquals(3L, image.resolve("/device").deviceMinor)
                assertEquals("fifo", image.resolve("/pipe").kind)
                assertFailsWith<LlvmBehaviorNativeOciImageV2Exception> { image.readFile("/device", 10) }
            }
            assertFalse(Files.exists(fixture.root.resolve("device")))
        }
    }

    @Test
    fun `binary PAX xattrs are retained without UTF8 loss`() {
        Fixture().use { fixture ->
            val binary = byteArrayOf(0, 0xff.toByte(), 0x80.toByte(), 65)
            val encoded = Base64.getEncoder().encodeToString(binary)
            val layer = tar(Item("binary", "x", pax = mapOf("LIBARCHIVE.xattr.user.test" to encoded, "mtime" to "-1.25")))
            LlvmBehaviorNativeOciImageV2.openLayout(fixture.layout(listOf(layer))).use { image ->
                assertEquals(encoded, image.resolve("/binary").xattrs["user.test"])
                assertEquals("-1.25", image.resolve("/binary").modificationTime)
            }
        }
    }

    @Test
    fun `Docker classic export authenticates OCI graph and exact config and layer order`() {
        Fixture().use { fixture ->
            val layers = listOf(tar(Item("one", "first")), tar(Item("two", "second")))
            val layout = fixture.layout(layers, gzip = true)
            LlvmBehaviorNativeOciImageV2.openLayout(layout).use { image ->
                val export = fixture.dockerExport(layout, layers)
                val measured = LlvmBehaviorNativeOciImageV2.readDockerExport(ByteArrayInputStream(export), image)
                assertEquals(image.configSha256, measured.configSha256)
                assertEquals(layers.map(OracleArtifacts::sha256), measured.layerDiffIds)
                assertEquals(image.namespaceSha256, measured.namespaceSha256)
                assertEquals(export.size.toLong(), measured.exportBytes)
                assertEquals(OracleArtifacts.sha256(export), measured.exportSha256)
                val reversed = fixture.dockerExport(layout, layers, reverseCompatibilityLayers = true)
                assertFailsWith<LlvmBehaviorNativeOciImageV2Exception> { LlvmBehaviorNativeOciImageV2.readDockerExport(ByteArrayInputStream(reversed), image) }
                val descriptorDrift = fixture.dockerExport(layout, layers, corruptDescriptorSize = true)
                assertFailsWith<LlvmBehaviorNativeOciImageV2Exception> { LlvmBehaviorNativeOciImageV2.readDockerExport(ByteArrayInputStream(descriptorDrift), image) }
            }
        }
    }

    @Test
    fun `compatibility manifest alone never proves Docker exported OCI graph`() {
        Fixture().use { fixture ->
            val layer = tar(Item("file", "x"))
            val layout = fixture.layout(listOf(layer))
            LlvmBehaviorNativeOciImageV2.openLayout(layout).use { image ->
                val classicOnly = tar(Item("manifest.json", "[]"))
                assertFailsWith<LlvmBehaviorNativeOciImageV2Exception> { LlvmBehaviorNativeOciImageV2.readDockerExport(ByteArrayInputStream(classicOnly), image) }
            }
        }
    }

    @Test
    fun `tar corruption duplicate paths traversal cycles and trailing payload fail closed`() {
        Fixture().use { fixture ->
            val controls = listOf(
                tar(Item("../escape", "x")),
                tar(Item("same", "a"), Item("./same", "b")),
                tar(Item("cycle-a", type = TarConstants.LF_LINK, link = "cycle-b"), Item("cycle-b", type = TarConstants.LF_LINK, link = "cycle-a")),
                tar(Item(".wh.", "")),
                tar(Item(".wh.file", "not empty")),
                tar(Item("cycle", type = TarConstants.LF_SYMLINK, link = "/cycle"), Item("cycle/child", "x")),
                tar(Item("file", "x")).copyOf(700),
                tar(Item("file", "x")).also { it[0] = 'Q'.code.toByte() },
                tar(Item("file", "x")) + byteArrayOf(1),
            )
            controls.forEachIndexed { index, bytes ->
                assertFailsWith<LlvmBehaviorNativeOciImageV2Exception>("control $index") {
                    LlvmBehaviorNativeOciImageV2.openLayout(fixture.layout(listOf(bytes)))
                }
            }
            assertFalse(Files.exists(fixture.root.resolve("escape")))
        }
    }

    @Test
    fun `descriptor size digest diffID JSON duplicates and unsupported compression are rejected`() {
        Fixture().use { fixture ->
            val layer = tar(Item("file", "x"))
            val layout = fixture.layout(listOf(layer), overrideDiffId = "0".repeat(64))
            assertFailsWith<LlvmBehaviorNativeOciImageV2Exception> { LlvmBehaviorNativeOciImageV2.openLayout(layout) }
            val duplicate = fixture.layout(listOf(layer))
            Files.writeString(duplicate.resolve("index.json"), "{\"schemaVersion\":2,\"schemaVersion\":2,\"manifests\":[]}")
            assertFailsWith<IllegalArgumentException> { LlvmBehaviorNativeOciImageV2.openLayout(duplicate) }
            val unknown = fixture.layout(listOf(layer), overrideMedia = "application/vnd.oci.image.layer.v1.tar+unknown")
            assertFailsWith<LlvmBehaviorNativeOciImageV2Exception> { LlvmBehaviorNativeOciImageV2.openLayout(unknown) }
        }
    }

    @Test
    fun `independent native zstd frames single concatenated corrupt and truncated are measured`() {
        Fixture().use { fixture ->
            val layer = tar(Item("file", "native zstd payload"))
            val single = fixture.zstd(layer)
            val midpoint = layer.size / 2
            val concatenated = fixture.zstd(layer.copyOfRange(0, midpoint)) + fixture.zstd(layer.copyOfRange(midpoint, layer.size))
            listOf(single, concatenated).forEach { encoded ->
                LlvmBehaviorNativeOciImageV2.BoundedZstdFrames(ByteArrayInputStream(encoded)).use { framed ->
                    assertContentEquals(encoded, framed.readAllBytes())
                    assertEquals(-1, framed.read()); assertEquals(-1, framed.read())
                }
                LlvmBehaviorNativeOciImageV2.openLayout(fixture.layout(listOf(layer), storedLayers = listOf(encoded), overrideMedia = "application/vnd.oci.image.layer.v1.tar+zstd")).use { image ->
                    assertEquals(OracleArtifacts.sha256(layer), image.layers.single().diffId)
                    assertContentEquals("native zstd payload".encodeToByteArray(), image.readFile("/file", 100))
                }
            }
            val controls = listOf(single.copyOf(single.size - 1), single.copyOf().also { it[it.lastIndex] = (it.last().toInt() xor 1).toByte() }, single + byteArrayOf(1, 2, 3, 4))
            controls.forEach { encoded ->
                assertFailsWith<Exception> {
                    LlvmBehaviorNativeOciImageV2.openLayout(fixture.layout(listOf(layer), storedLayers = listOf(encoded), overrideMedia = "application/vnd.oci.image.layer.v1.tar+zstd"))
                }
            }
        }
    }

    @Test
    fun `zstd oversized windows and streaming decompression budget refuse before large allocation`() {
        Fixture().use { fixture ->
            val layer = tar(Item("file", "bounded decoder"))
            val encoded = fixture.zstd(layer, listOf("--no-content-size"))
            assertEquals(0, encoded[4].toInt() and 0x20, "native frame must have a separate window descriptor")
            val oversized = encoded.copyOf().also { it[5] = 0x70 } // 16 MiB Zstandard window descriptor.
            val failure = assertFailsWith<LlvmBehaviorNativeOciImageV2Exception> {
                LlvmBehaviorNativeOciImageV2.openLayout(fixture.layout(listOf(layer), storedLayers = listOf(oversized), overrideMedia = "application/vnd.oci.image.layer.v1.tar+zstd"))
            }
            assertTrue(failure.message!!.contains("window exceeds"))
            // Standards-valid raw/RLE blocks bypass the decoder's compressed-block window check.
            // The independent native implementation accepts them; our encoded scanner refuses the
            // declared window before passing the header to the Java decoder.
            val rawFrame = zstdRawFrame(layer, rle = false)
            val zeroTar = ByteArray(1024)
            val rleFrame = zstdRawFrame(zeroTar, rle = true)
            listOf(layer to rawFrame, zeroTar to rleFrame).forEach { (decoded, frame) ->
                fixture.nativeZstdValidate(frame)
                val refusal = assertFailsWith<LlvmBehaviorNativeOciImageV2Exception> {
                    LlvmBehaviorNativeOciImageV2.openLayout(fixture.layout(listOf(decoded), storedLayers = listOf(frame), overrideMedia = "application/vnd.oci.image.layer.v1.tar+zstd"))
                }
                assertTrue(refusal.message!!.contains("window exceeds"))
            }
            // Exercise the exact production counting/deadline owner with a smaller test budget.
            var checkpoints = 0
            LlvmBehaviorNativeOciImageV2.CountingInput(ZstdInputStream(ByteArrayInputStream(encoded)), LlvmBehaviorNativeOciImageV2.ByteBudget(512) { checkpoints++ }).use { stream ->
                assertFailsWith<LlvmBehaviorNativeOciImageV2Exception> { stream.readAllBytes() }
            }
            assertTrue(checkpoints <= 1)
        }
    }

    @Test
    fun `oversized metadata extension is refused from its header without payload allocation`() {
        val header = ByteArray(512)
        TarArchiveEntry("pax", TarConstants.LF_PAX_EXTENDED_HEADER_LC).also {
            it.size = 4L * 1024 * 1024 + 1
            it.writeEntryHeader(header)
        }
        val reader = LlvmBehaviorNativeOciImageV2.RawTarReader(ByteArrayInputStream(header), LlvmBehaviorNativeOciImageV2.MetadataBudget()) {}
        assertFailsWith<LlvmBehaviorNativeOciImageV2Exception> { reader.next() }
    }

    @Test
    fun `retained layout directory replacement and same-byte blob replacement are rejected`() {
        Fixture().use { fixture ->
            val layer = tar(Item("file", "x"))
            val layout = fixture.layout(listOf(layer))
            LlvmBehaviorNativeOciImageV2.openLayout(layout).use { image ->
                val moved = fixture.root.resolve("displaced-layout")
                Files.move(layout, moved)
                Files.createDirectory(layout)
                assertFailsWith<IllegalArgumentException> { image.requireCurrent() }
            }
            val second = fixture.layout(listOf(layer))
            LlvmBehaviorNativeOciImageV2.openLayout(second).use { image ->
                val blob = second.resolve("blobs/sha256/${OracleArtifacts.sha256(layer)}")
                val replacement = fixture.root.resolve("replacement-blob")
                Files.write(replacement, layer); fixture.privateFile(replacement)
                Files.move(replacement, blob, StandardCopyOption.REPLACE_EXISTING)
                assertFailsWith<IllegalArgumentException> { image.readFile("/file", 100) }
            }
        }
    }

    @Test
    fun `named layout file replacement and added members invalidate retained inputs`() {
        Fixture().use { fixture ->
            val layout = fixture.layout(listOf(tar(Item("file", "x"))))
            LlvmBehaviorNativeOciImageV2.openLayout(layout).use { image ->
                val index = layout.resolve("index.json")
                val original = Files.readAllBytes(index)
                val replacement = fixture.root.resolve("replacement-index")
                Files.write(replacement, original)
                fixture.privateFile(replacement)
                Files.move(replacement, index, StandardCopyOption.REPLACE_EXISTING)
                assertFailsWith<IllegalArgumentException> { image.requireCurrent() }
            }
            val second = fixture.layout(listOf(tar(Item("file", "x"))))
            LlvmBehaviorNativeOciImageV2.openLayout(second).use { image ->
                Files.write(second.resolve("unexpected"), byteArrayOf(1))
                assertFailsWith<IllegalArgumentException> { image.requireCurrent() }
            }
        }
    }

    @Test
    fun `checkpoint cancellation stops acquisition and selected reading without a publication`() {
        Fixture().use { fixture ->
            val layout = fixture.layout(listOf(tar(Item("file", "x"))))
            var calls = 0
            assertFailsWith<TestCancellation> {
                LlvmBehaviorNativeOciImageV2.openLayout(layout) { if (++calls == 4) throw TestCancellation() }
            }
            LlvmBehaviorNativeOciImageV2.openLayout(layout).use { image ->
                assertFailsWith<TestCancellation> { image.readFile("/file", 100) { throw TestCancellation() } }
                image.requireCurrent()
            }
            assertFalse(Files.exists(layout.resolve("manifest.json")))
        }
    }

    private class TestCancellation : RuntimeException()

    private fun zstdRawFrame(bytes: ByteArray, rle: Boolean): ByteArray {
        val word = (bytes.size shl 3) or (if (rle) 2 else 0) or 1
        val prefix = byteArrayOf(0x28, 0xb5.toByte(), 0x2f, 0xfd.toByte(), 0, 0x70,
            word.toByte(), (word ushr 8).toByte(), (word ushr 16).toByte())
        return prefix + if (rle) byteArrayOf(0) else bytes
    }

    private data class Item(
        val name: String,
        val data: String = "",
        val type: Byte = TarConstants.LF_NORMAL,
        val link: String = "",
        val major: Int = 0,
        val minor: Int = 0,
        val pax: Map<String, String> = emptyMap(),
        val mode: Int = 0x1a4,
        val uid: Int = 0,
        val gid: Int = 0,
        val mtime: Long = 0,
    )

    private fun tar(vararg items: Item): ByteArray = tarBytes(items.map { it to it.data.encodeToByteArray() })

    private fun tarBytes(items: List<Pair<Item, ByteArray>>): ByteArray {
        val output = ByteArrayOutputStream()
        TarArchiveOutputStream(output).use { stream ->
            stream.setLongFileMode(TarArchiveOutputStream.LONGFILE_POSIX)
            stream.setBigNumberMode(TarArchiveOutputStream.BIGNUMBER_POSIX)
            items.forEach { (item, bytes) ->
                val entry = TarArchiveEntry(item.name, item.type)
                entry.mode = item.mode
                entry.userId = item.uid
                entry.groupId = item.gid
                entry.setModTime(item.mtime)
                entry.linkName = item.link
                entry.devMajor = item.major
                entry.devMinor = item.minor
                entry.size = if (item.type == TarConstants.LF_NORMAL) bytes.size.toLong() else 0L
                item.pax.forEach(entry::addPaxHeader)
                stream.putArchiveEntry(entry)
                if (entry.size > 0) stream.write(bytes)
                stream.closeArchiveEntry()
            }
        }
        return output.toByteArray()
    }

    private inner class Fixture : AutoCloseable {
        val root: Path = Files.createTempDirectory(Files.createDirectories(Path.of("build/native-oci-tests").toAbsolutePath()), "image-")
        private var sequence = 0

        init { Files.setPosixFilePermissions(root, PRIVATE_DIRECTORY) }

        fun directory(name: String): Path = Files.createDirectory(root.resolve(name)).also { Files.setPosixFilePermissions(it, PRIVATE_DIRECTORY) }
        fun privateFile(path: Path) = Files.setPosixFilePermissions(path, PRIVATE_FILE)

        fun gnuTar(tree: Path, options: List<String>, names: List<String> = listOf(".")): ByteArray {
            val output = root.resolve("gnu-${sequence++}.tar")
            val argv = listOf("tar") + options + listOf("--sort=name", "--mtime=@0", "--numeric-owner", "-C", tree.toString(), "-cf", output.toString()) + names
            val process = ProcessBuilder(argv).redirectErrorStream(true).also {
                it.environment()["HOME"] = root.toString()
                it.environment()["TMPDIR"] = root.toString()
                it.environment()["LANG"] = "C"
                it.environment()["LC_ALL"] = "C"
            }.start()
            val log = process.inputStream.readAllBytes()
            assertEquals(0, process.waitFor(), log.decodeToString())
            return Files.readAllBytes(output)
        }

        fun extractTar(bytes: ByteArray): Path {
            val input = root.resolve("native-extract-${sequence++}.tar")
            Files.write(input, bytes)
            val destination = directory("native-extracted-${sequence++}")
            val process = ProcessBuilder("tar", "--extract", "--preserve-permissions", "--same-owner", "--file", input.toString(), "--directory", destination.toString()).redirectErrorStream(true).start()
            val log = process.inputStream.readAllBytes()
            assertEquals(0, process.waitFor(), log.decodeToString())
            return destination
        }

        fun layout(layers: List<ByteArray>, gzip: Boolean = false, overrideDiffId: String? = null, overrideMedia: String? = null, storedLayers: List<ByteArray>? = null): Path {
            val layout = directory("layout-${sequence++}")
            Files.createDirectories(layout.resolve("blobs/sha256"))
            Files.setPosixFilePermissions(layout.resolve("blobs"), PRIVATE_DIRECTORY)
            Files.setPosixFilePermissions(layout.resolve("blobs/sha256"), PRIVATE_DIRECTORY)
            val diffIds = layers.map { overrideDiffId ?: OracleArtifacts.sha256(it) }
            val config = json(JsonObject(linkedMapOf(
                "architecture" to JsonPrimitive("amd64"), "os" to JsonPrimitive("linux"),
                "rootfs" to JsonObject(mapOf("type" to JsonPrimitive("layers"), "diff_ids" to JsonArray(diffIds.map { JsonPrimitive("sha256:$it") }))),
            )))
            writeBlob(layout, config)
            val layerDescriptors = layers.mapIndexed { index, bytes ->
                val stored = storedLayers?.get(index) ?: if (gzip) ByteArrayOutputStream().also { output -> GZIPOutputStream(output).use { it.write(bytes) } }.toByteArray() else bytes
                writeBlob(layout, stored)
                desc(stored, overrideMedia ?: if (gzip) "application/vnd.oci.image.layer.v1.tar+gzip" else "application/vnd.oci.image.layer.v1.tar")
            }
            val manifest = json(JsonObject(mapOf(
                "schemaVersion" to JsonPrimitive(2), "mediaType" to JsonPrimitive("application/vnd.oci.image.manifest.v1+json"),
                "config" to desc(config, "application/vnd.oci.image.config.v1+json"), "layers" to JsonArray(layerDescriptors),
            )))
            writeBlob(layout, manifest)
            write(layout.resolve("oci-layout"), "{\"imageLayoutVersion\":\"1.0.0\"}".encodeToByteArray())
            write(layout.resolve("index.json"), json(JsonObject(mapOf("schemaVersion" to JsonPrimitive(2), "manifests" to JsonArray(listOf(desc(manifest, "application/vnd.oci.image.manifest.v1+json")))))))
            return layout
        }

        fun zstd(bytes: ByteArray, options: List<String> = emptyList()): ByteArray {
            val input = root.resolve("zstd-${sequence++}.input")
            val output = root.resolve("zstd-${sequence++}.frame")
            Files.write(input, bytes)
            val process = ProcessBuilder(listOf("/usr/bin/zstd", "-q", "-f", "--check") + options + listOf(input.toString(), "-o", output.toString())).redirectErrorStream(true).also {
                it.environment()["HOME"] = root.toString(); it.environment()["TMPDIR"] = root.toString()
            }.start()
            val log = process.inputStream.readAllBytes()
            assertEquals(0, process.waitFor(), log.decodeToString())
            return Files.readAllBytes(output)
        }

        fun nativeZstdValidate(frame: ByteArray) {
            val path = root.resolve("validate-${sequence++}.zstd")
            Files.write(path, frame)
            val process = ProcessBuilder("/usr/bin/zstd", "-q", "-t", "--long=24", path.toString()).redirectErrorStream(true).start()
            val log = process.inputStream.readAllBytes()
            assertEquals(0, process.waitFor(), log.decodeToString())
        }

        fun dockerExport(layout: Path, layers: List<ByteArray>, reverseCompatibilityLayers: Boolean = false, corruptDescriptorSize: Boolean = false): ByteArray {
            val config = Files.list(layout.resolve("blobs/sha256")).use { paths ->
                paths.map { Files.readAllBytes(it) }.filter { bytes -> bytes.decodeToString().contains("\"rootfs\"") }.findFirst().orElseThrow()
            }
            val layerDescriptors = layers.map { bytes ->
                if (corruptDescriptorSize) JsonObject(desc(bytes, "application/vnd.oci.image.layer.v1.tar") + ("size" to JsonPrimitive(bytes.size + 1)))
                else desc(bytes, "application/vnd.oci.image.layer.v1.tar")
            }
            val manifest = json(JsonObject(mapOf(
                "schemaVersion" to JsonPrimitive(2), "mediaType" to JsonPrimitive("application/vnd.oci.image.manifest.v1+json"),
                "config" to desc(config, "application/vnd.oci.image.config.v1+json"), "layers" to JsonArray(layerDescriptors),
            )))
            val configName = "blobs/sha256/${OracleArtifacts.sha256(config)}"
            val layerNames = layers.map { "blobs/sha256/${OracleArtifacts.sha256(it)}" }
            val compatibility = json(JsonArray(listOf(JsonObject(mapOf(
                "Config" to JsonPrimitive(configName), "RepoTags" to JsonArray(emptyList()),
                "Layers" to JsonArray((if (reverseCompatibilityLayers) layerNames.reversed() else layerNames).map(::JsonPrimitive)),
            )))))
            val index = json(JsonObject(mapOf("schemaVersion" to JsonPrimitive(2), "manifests" to JsonArray(listOf(desc(manifest, "application/vnd.oci.image.manifest.v1+json"))))))
            // Metadata intentionally follows layers: the parser may not depend on outer tar ordering.
            val members = layers.zip(layerNames).map { (bytes, name) -> Item(name) to bytes } + listOf(
                Item(configName) to config, Item("blobs/sha256/${OracleArtifacts.sha256(manifest)}") to manifest,
                Item("manifest.json") to compatibility, Item("index.json") to index,
                Item("oci-layout") to "{\"imageLayoutVersion\":\"1.0.0\"}".encodeToByteArray(),
            )
            return tarBytes(members)
        }

        private fun desc(bytes: ByteArray, media: String): JsonObject = JsonObject(mapOf(
            "digest" to JsonPrimitive("sha256:${OracleArtifacts.sha256(bytes)}"), "size" to JsonPrimitive(bytes.size), "mediaType" to JsonPrimitive(media),
        ))
        private fun json(value: kotlinx.serialization.json.JsonElement): ByteArray = OracleJson.canonicalBytes(value)
        private fun writeBlob(layout: Path, bytes: ByteArray) = write(layout.resolve("blobs/sha256/${OracleArtifacts.sha256(bytes)}"), bytes)
        private fun write(path: Path, bytes: ByteArray) { Files.write(path, bytes); privateFile(path) }

        override fun close() {
            Files.walk(root).use { paths -> paths.sorted(Comparator.reverseOrder()).forEach(Files::delete) }
        }
    }

    companion object {
        private val PRIVATE_DIRECTORY = setOf(PosixFilePermission.OWNER_READ, PosixFilePermission.OWNER_WRITE, PosixFilePermission.OWNER_EXECUTE)
        private val PRIVATE_FILE = setOf(PosixFilePermission.OWNER_READ, PosixFilePermission.OWNER_WRITE)
    }
}
