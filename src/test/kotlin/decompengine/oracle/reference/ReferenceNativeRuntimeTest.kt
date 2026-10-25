package decompengine.oracle.reference

import decompengine.oracle.behavior.LlvmBehaviorNativeOciImageV2
import decompengine.oracle.core.OracleArtifacts
import decompengine.oracle.core.OracleJson
import decompengine.oracle.fulltree.calculateFullTreeObservationRuntimeManifestSha256
import java.io.ByteArrayOutputStream
import java.nio.file.Files
import java.nio.file.LinkOption.NOFOLLOW_LINKS
import java.nio.file.Path
import java.nio.file.StandardCopyOption
import java.nio.file.attribute.PosixFilePermissions
import java.util.zip.GZIPOutputStream
import kotlin.test.Test
import kotlin.test.assertContentEquals
import kotlin.test.assertEquals
import kotlin.test.assertFails
import kotlin.test.assertFalse
import kotlin.test.assertTrue
import kotlinx.serialization.json.JsonArray
import kotlinx.serialization.json.JsonObject
import kotlinx.serialization.json.JsonPrimitive
import org.apache.commons.compress.archivers.tar.TarArchiveEntry
import org.apache.commons.compress.archivers.tar.TarArchiveOutputStream
import org.apache.commons.compress.archivers.tar.TarConstants
import org.junit.jupiter.api.Assumptions.assumeTrue

class ReferenceNativeRuntimeTest {
    @Test
    fun `materializer preserves measured bytes paths links and separate artifact directory`(): Unit = Fixture().use { fixture ->
        val stage = fixture.stage()
        val image = stage.root.resolve("image")
        assertContentEquals("tool\n".encodeToByteArray(), Files.readAllBytes(image.resolve("usr/bin/tool")))
        assertEquals(0L, Files.size(image.resolve("etc/empty")))
        assertTrue(Files.isSameFile(image.resolve("usr/bin/tool"), image.resolve("usr/bin/tool-alias")))
        assertFalse(Files.isSameFile(image.resolve("usr/bin/tool"), image.resolve("usr/bin/same-bytes")))
        assertEquals(Path.of("usr/lib"), Files.readSymbolicLink(image.resolve("lib")))
        assertEquals(Path.of("/usr/bin/tool"), Files.readSymbolicLink(image.resolve("usr/bin/absolute")))
        assertEquals(Path.of("/run/absent"), Files.readSymbolicLink(image.resolve("etc/runtime-link")))
        assertContentEquals("original\n".encodeToByteArray(), Files.readAllBytes(stage.root.resolve("artifacts/compiler/compiler")))
        assertEquals(0x1ed, stage.provisioningEntries.single { it.relativePath == "image/usr/bin/tool" }.mode)
        assertEquals(42L, stage.provisioningEntries.single { it.relativePath == "image/etc/group-file" }.gid)
        fixture.verify(stage.root)
        if ((Files.getAttribute(stage.root, "unix:uid", NOFOLLOW_LINKS) as Number).toInt() != 0) {
            assertFails { calculateFullTreeObservationRuntimeManifestSha256(stage.root) }
        }
        val copy = stage.canonicalBytes
        copy.fill(0)
        assertEquals(stage.identitySha256, OracleArtifacts.sha256(stage.canonicalBytes))
    }

    @Test
    fun `wrong config compressed transport unsupported nodes and traversal fail before staging writes`(): Unit = Fixture().use { fixture ->
        val absent = fixture.root.resolve("not-created")
        assertFails { ReferenceNativeRuntime.materializeTransport(fixture.layout, absent, "0".repeat(64), fixture.artifacts) }
        assertFalse(Files.exists(absent))
        val compressed = fixture.layout(gzip = true)
        val config = LlvmBehaviorNativeOciImageV2.openLayout(compressed).use { it.configSha256 }
        assertFails { ReferenceNativeRuntime.materializeTransport(compressed, absent, config, fixture.artifacts) }
        assertFalse(Files.exists(absent))
        val evil = fixture.artifact("/oracle/../escape/compiler")
        assertFails { ReferenceNativeRuntime.materializeTransport(fixture.layout, absent, fixture.config, listOf(evil)) }
        assertFalse(Files.exists(absent))
        val special = fixture.layout(additional = listOf(Item("usr/device", TarConstants.LF_CHR)))
        val specialConfig = LlvmBehaviorNativeOciImageV2.openLayout(special).use { it.configSha256 }
        assertFails { ReferenceNativeRuntime.materializeTransport(special, absent, specialConfig, fixture.artifacts) }
        assertFalse(Files.exists(absent))
    }

    @Test
    fun `existing staging and symlink ancestors are rejected without writing through aliases`(): Unit = Fixture().use { fixture ->
        val target = Files.createDirectory(fixture.root.resolve("existing"))
        assertFails { ReferenceNativeRuntime.materializeTransport(fixture.layout, target, fixture.config, fixture.artifacts) }
        Files.createSymbolicLink(fixture.root.resolve("alias"), target)
        assertFails { ReferenceNativeRuntime.materializeTransport(fixture.layout, fixture.root.resolve("alias/child"), fixture.config, fixture.artifacts) }
        assertFalse(Files.exists(target.resolve("child")))
    }

    @Test
    fun `transport verification rejects extra nodes bytes changed symlinks and invented hardlinks`(): Unit = Fixture().use { fixture ->
        val stage = fixture.stage()
        val extra = stage.root.resolve("unexpected")
        Files.writeString(extra, "extra")
        assertFails { fixture.verify(stage.root) }
        Files.delete(extra)
        val tool = stage.root.resolve("image/usr/bin/tool")
        val originalTime = Files.getLastModifiedTime(tool)
        Files.writeString(tool, "evil\n")
        Files.setLastModifiedTime(tool, originalTime)
        assertTrue(assertFails { fixture.verify(stage.root) }.message.orEmpty().contains("bytes differ from authenticated input"))
        Files.writeString(tool, "tool\n")
        Files.setLastModifiedTime(tool, originalTime)
        val link = stage.root.resolve("image/lib")
        val linkTime = Files.getLastModifiedTime(link, NOFOLLOW_LINKS)
        val imageTime = Files.getLastModifiedTime(link.parent)
        Files.delete(link)
        Files.createSymbolicLink(link, Path.of("/tmp"))
        Files.setLastModifiedTime(link.parent, imageTime)
        Files.getFileAttributeView(link, java.nio.file.attribute.BasicFileAttributeView::class.java, NOFOLLOW_LINKS).setTimes(linkTime, null, null)
        assertFails { fixture.verify(stage.root) }
        Files.delete(link)
        Files.createSymbolicLink(link, Path.of("usr/lib"))
        Files.setLastModifiedTime(link.parent, imageTime)
        Files.getFileAttributeView(link, java.nio.file.attribute.BasicFileAttributeView::class.java, NOFOLLOW_LINKS).setTimes(linkTime, null, null)
        val same = stage.root.resolve("image/usr/bin/same-bytes")
        val binTime = Files.getLastModifiedTime(same.parent)
        Files.delete(same)
        Files.createLink(same, tool)
        Files.setLastModifiedTime(same.parent, binTime)
        assertFails { fixture.verify(stage.root) }
    }

    @Test
    fun `transport verification rejects broken hardlink identity even with original bytes and mode`(): Unit = Fixture().use { fixture ->
        val stage = fixture.stage()
        val file = stage.root.resolve("image/usr/bin/tool-alias")
        val sibling = file.resolveSibling("tool")
        val binTime = Files.getLastModifiedTime(file.parent)
        Files.delete(file)
        Files.copy(sibling, file, StandardCopyOption.COPY_ATTRIBUTES)
        Files.setLastModifiedTime(file.parent, binTime)
        assertTrue(assertFails { fixture.verify(stage.root) }.message.orEmpty().contains("hardlink alias"))
    }

    @Test
    fun `transport rejects external hardlink aliases and unmeasured extended metadata`(): Unit = Fixture().use { fixture ->
        val stage = fixture.stage()
        val original = stage.root.resolve("artifacts/compiler/compiler")
        val alias = fixture.root.resolve("external-alias")
        Files.createLink(alias, original)
        assertTrue(assertFails { fixture.verify(stage.root) }.message.orEmpty().contains("hardlink alias"))
        Files.delete(alias)
        val attributes = Files.getFileAttributeView(original, java.nio.file.attribute.UserDefinedFileAttributeView::class.java)
        Files.setPosixFilePermissions(original, PosixFilePermissions.fromString("rwxr-xr-x"))
        attributes.write("unmeasured", java.nio.ByteBuffer.wrap(byteArrayOf(1)))
        Files.setPosixFilePermissions(original, PosixFilePermissions.fromString("r-xr-xr-x"))
        assertTrue(assertFails { fixture.verify(stage.root) }.message.orEmpty().contains("extended metadata"))
        Files.setPosixFilePermissions(original, PosixFilePermissions.fromString("rwxr-xr-x"))
        attributes.delete("unmeasured")
        Files.setPosixFilePermissions(original, PosixFilePermissions.fromString("r-xr-xr-x"))
        fixture.verify(stage.root)
    }

    @Test
    fun `empty image file must remain empty and a regular inode`(): Unit = Fixture().use { fixture ->
        val stage = fixture.stage()
        val empty = stage.root.resolve("image/etc/empty")
        val time = Files.getLastModifiedTime(empty)
        Files.writeString(empty, "x")
        Files.setLastModifiedTime(empty, time)
        assertTrue(assertFails { fixture.verify(stage.root) }.message.orEmpty().contains("native runtime file identity changed"))
        Files.write(empty, byteArrayOf())
        Files.setLastModifiedTime(empty, time)
        fixture.verify(stage.root)
        val parentTime = Files.getLastModifiedTime(empty.parent)
        Files.delete(empty)
        Files.createSymbolicLink(empty, Path.of("/dev/null"))
        Files.setLastModifiedTime(empty.parent, parentTime)
        assertTrue(assertFails { fixture.verify(stage.root) }.message.orEmpty().contains("node type changed"))
    }

    @Test
    fun `unrelated ancestor sibling writes do not change measured runtime bytes`(): Unit = Fixture().use { fixture ->
        val stage = fixture.stage()
        LlvmBehaviorNativeOciImageV2.openLayout(fixture.layout).use { image ->
            val plan = ReferenceNativeRuntime.plan(image, fixture.config, fixture.artifacts)
            val sibling = fixture.root.resolve("unrelated-control-output")
            val running = java.util.concurrent.atomic.AtomicBoolean(true)
            val writer = Thread.ofPlatform().start {
                while (running.get()) Files.writeString(sibling, "unrelated output")
            }
            try { repeat(8) { ReferenceNativeRuntime.verify(stage.root, plan, trustedOwnership = false) } }
            finally { running.set(false); writer.join(10_000); assertFalse(writer.isAlive) }
            image.requireCurrent()
        }
    }

    @Test
    fun `mutated OCI blob cannot authorize matching staged output`(): Unit = Fixture().use { fixture ->
        val stage = fixture.stage()
        val blob = fixture.layout.resolve("blobs/sha256/${fixture.layerSha}")
        val bytes = Files.readAllBytes(blob)
        bytes[512] = (bytes[512].toInt() xor 1).toByte()
        Files.write(blob, bytes)
        assertFails { fixture.verify(stage.root) }
    }

    @Test
    fun `real registered pinned image stages without any container execution`() {
        val configured = System.getenv("DECOMP_REFERENCE_NATIVE_REAL_OCI").orEmpty()
        assumeTrue(configured.isNotEmpty(), "set DECOMP_REFERENCE_NATIVE_REAL_OCI for real pinned image staging")
        val layout = Path.of(configured).toAbsolutePath()
        val output = Path.of(System.getenv("DECOMP_REFERENCE_NATIVE_REAL_OUTPUT") ?: "build/native-reference-real-stage").toAbsolutePath()
        AuthenticatedReferenceCorpusProfile.open(Path.of("oracle/gcc/16.2.0").toAbsolutePath().normalize(), "gcc-metadata-v1").use { profile ->
            val stage = ReferenceNativeRuntime.materialize(layout, output, profile)
            assertTrue(stage.provisioningEntries.size > 10_000)
            assertTrue(stage.provisioningEntries.any { it.gid == 42L })
            assertFails { ReferenceNativeRuntime.admit(layout, output, profile) }
            Files.writeString(output.resolveSibling("native-reference-real-stage-evidence.json"), stage.canonicalBytes.decodeToString() + "\n")
        }
    }

    private data class Item(val path: String, val type: Byte = TarConstants.LF_NORMAL, val text: String = "", val target: String = "", val mode: Int = 0x1ed, val gid: Int = 0)

    private inner class Fixture : AutoCloseable {
        val root: Path = Files.createTempDirectory(Files.createDirectories(Path.of("build/native-reference-tests").toAbsolutePath()), "runtime-")
        private var sequence = 0
        val layout: Path = layout()
        val config: String = LlvmBehaviorNativeOciImageV2.openLayout(layout).use { it.configSha256 }
        val layerSha: String = LlvmBehaviorNativeOciImageV2.openLayout(layout).use { it.layers.single().blobSha256 }
        val artifacts = listOf(artifact())
        fun artifact(guest: String = "/oracle/install/bin/compiler"): ReferenceCorpusArtifact {
            val bytes = "original\n".encodeToByteArray()
            return ReferenceCorpusArtifact("compiler", root.resolve("original"), guest, bytes.size.toLong(), OracleArtifacts.sha256(bytes), bytes.size.toLong(), OracleArtifacts.sha256(bytes), "raw", bytes)
        }
        fun stage(): ReferenceNativeRuntimeStage = ReferenceNativeRuntime.materializeTransport(layout, root.resolve("stage-${sequence++}"), config, artifacts)
        fun verify(stage: Path) = ReferenceNativeRuntime.verifyTransport(layout, stage, config, artifacts)
        fun layout(gzip: Boolean = false, additional: List<Item> = emptyList()): Path {
            val directory = Files.createDirectory(root.resolve("layout-${sequence++}"))
            val blobRoot = Files.createDirectories(directory.resolve("blobs/sha256"))
            val items = listOf("usr", "usr/bin", "usr/sbin", "usr/lib", "usr/lib64", "etc").map { Item("$it/", TarConstants.LF_DIR) } + listOf(
                Item("bin", TarConstants.LF_SYMLINK, target = "usr/bin"), Item("sbin", TarConstants.LF_SYMLINK, target = "usr/sbin"),
                Item("lib", TarConstants.LF_SYMLINK, target = "usr/lib"), Item("lib64", TarConstants.LF_SYMLINK, target = "usr/lib64"),
                Item("usr/bin/tool", text = "tool\n"), Item("usr/bin/tool-alias", TarConstants.LF_LINK, target = "usr/bin/tool"),
                Item("usr/bin/same-bytes", text = "tool\n"), Item("usr/bin/absolute", TarConstants.LF_SYMLINK, target = "/usr/bin/tool"),
                Item("etc/empty", text = "", mode = 0x1a0),
                Item("etc/runtime-link", TarConstants.LF_SYMLINK, target = "/run/absent"), Item("etc/group-file", text = "group\n", mode = 0x1a0, gid = 42),
            ) + additional
            val tar = ByteArrayOutputStream().also { bytes -> TarArchiveOutputStream(bytes).use { stream ->
                items.forEach { item ->
                    val entry = TarArchiveEntry(item.path, item.type)
                    entry.mode = item.mode
                    entry.userId = 0
                    entry.groupId = item.gid
                    entry.setModTime(1000L)
                    entry.linkName = item.target
                    val content = item.text.encodeToByteArray()
                    entry.size = if (item.type == TarConstants.LF_NORMAL) content.size.toLong() else 0
                    stream.putArchiveEntry(entry)
                    if (entry.size > 0) stream.write(content)
                    stream.closeArchiveEntry()
                }
            } }.toByteArray()
            val stored = if (gzip) ByteArrayOutputStream().also { output -> GZIPOutputStream(output).use { it.write(tar) } }.toByteArray() else tar
            fun blob(bytes: ByteArray): String { val sha = OracleArtifacts.sha256(bytes); Files.write(blobRoot.resolve(sha), bytes); return sha }
            fun desc(bytes: ByteArray, media: String): JsonObject = JsonObject(mapOf("digest" to JsonPrimitive("sha256:${blob(bytes)}"), "size" to JsonPrimitive(bytes.size), "mediaType" to JsonPrimitive(media)))
            val config = OracleJson.canonicalBytes(JsonObject(mapOf("architecture" to JsonPrimitive("amd64"), "os" to JsonPrimitive("linux"), "rootfs" to JsonObject(mapOf("type" to JsonPrimitive("layers"), "diff_ids" to JsonArray(listOf(JsonPrimitive("sha256:${OracleArtifacts.sha256(tar)}"))))))))
            val manifest = OracleJson.canonicalBytes(JsonObject(mapOf("schemaVersion" to JsonPrimitive(2), "mediaType" to JsonPrimitive("application/vnd.oci.image.manifest.v1+json"), "config" to desc(config, "application/vnd.oci.image.config.v1+json"), "layers" to JsonArray(listOf(desc(stored, "application/vnd.oci.image.layer.v1.tar" + if (gzip) "+gzip" else ""))))))
            Files.write(directory.resolve("index.json"), OracleJson.canonicalBytes(JsonObject(mapOf("schemaVersion" to JsonPrimitive(2), "manifests" to JsonArray(listOf(desc(manifest, "application/vnd.oci.image.manifest.v1+json")))))))
            Files.writeString(directory.resolve("oci-layout"), "{\"imageLayoutVersion\":\"1.0.0\"}")
            Files.walk(directory).use { paths -> paths.forEach { Files.setPosixFilePermissions(it, PosixFilePermissions.fromString(if (Files.isDirectory(it)) "rwx------" else "rw-------")) } }
            return directory
        }
        override fun close() { Files.walk(root).use { paths -> paths.sorted(Comparator.reverseOrder()).forEach { if (!Files.isSymbolicLink(it) && Files.isDirectory(it)) Files.setPosixFilePermissions(it, PosixFilePermissions.fromString("rwx------")); Files.delete(it) } } }
    }
}
