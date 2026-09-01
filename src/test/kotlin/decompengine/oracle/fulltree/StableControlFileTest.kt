package decompengine.oracle.fulltree

import com.sun.jna.Library
import com.sun.jna.Memory
import com.sun.jna.Native
import com.sun.jna.NativeLong
import com.sun.jna.Platform
import decompengine.acp.LinuxDescriptor
import decompengine.acp.LinuxFilesystemSyscalls
import decompengine.oracle.core.OracleArtifacts
import java.lang.reflect.InvocationTargetException
import java.lang.reflect.Modifier
import java.nio.channels.FileChannel
import java.nio.file.Files
import java.nio.file.LinkOption
import java.nio.file.Path
import java.nio.file.StandardOpenOption
import java.nio.file.attribute.PosixFilePermissions
import java.util.concurrent.TimeUnit
import kotlin.test.Test
import kotlin.test.assertContentEquals
import kotlin.test.assertEquals
import kotlin.test.assertFailsWith
import kotlin.test.assertFalse
import kotlin.test.assertTrue
import org.junit.jupiter.api.Assumptions.assumeTrue

class StableControlFileTest {
    @Test
    fun `stable input hashing checkpoints every MiB`() = inControlTemporaryDirectory { root ->
        val bytes = ByteArray(2 * 1024 * 1024 + 17) { index -> index.toByte() }
        val input = root.resolve("large-control.bin")
        Files.write(input, bytes)
        Files.setPosixFilePermissions(input, PosixFilePermissions.fromString("rw-------"))
        val checkpoints = mutableListOf<String>()

        val digest = StableControlFile.open(input, bytes.size.toLong(), "large control fixture").use { file ->
            file.sha256({ checkpoints += it }, "large control fixture")
        }

        assertEquals(OracleArtifacts.sha256(bytes), digest)
        assertEquals(
            listOf(
                "while hashing large control fixture",
                "while hashing large control fixture",
                "while hashing large control fixture",
                "after hashing large control fixture",
            ),
            checkpoints,
        )
    }

    @Test
    fun `same-size named inode substitution after descriptor pinning fails closed`() =
        inControlTemporaryDirectory { root ->
            val original = ByteArray(4096) { index -> index.toByte() }
            val replacement = ByteArray(original.size) { index -> (index xor 0x5a).toByte() }
            val input = root.resolve("selected-control.bin")
            val hostile = root.resolve("hostile-control.bin")
            val displaced = root.resolve("selected-control.displaced")
            writeOwnerFile(input, original)
            writeOwnerFile(hostile, replacement)

            val failure = assertFailsWith<FullTreeControlException> {
                openWithPrivateSelectionMutation(input, original.size.toLong()) { point ->
                    if (point == "AFTER_FILE_PINNED") {
                        Files.move(input, displaced)
                        Files.move(hostile, input)
                    }
                }.close()
            }

            assertTrue(failure.message.orEmpty().contains("mutated"), failure.message)
            assertContentEquals(original, Files.readAllBytes(displaced))
            assertContentEquals(replacement, Files.readAllBytes(input))
        }

    @Test
    fun `terminal authentication rejects a replaced selected name`() =
        inControlTemporaryDirectory { root ->
            val original = ByteArray(8192) { index -> index.toByte() }
            val changed = ByteArray(original.size) { index -> (index xor 0x33).toByte() }
            val input = root.resolve("same-inode-control.bin")
            val hostile = root.resolve("hostile-control.bin")
            val displaced = root.resolve("same-inode-control.displaced")
            writeOwnerFile(input, original)
            writeOwnerFile(hostile, changed)

            StableControlFile.open(input, original.size.toLong(), "same-inode control fixture").use { file ->
                Files.move(input, displaced)
                Files.move(hostile, input)
                val failure = assertFailsWith<FullTreeControlException> {
                    file.verifyUnchanged("same-inode control fixture")
                }
                assertTrue(failure.message.orEmpty().contains("mutated"), failure.message)
            }
        }

    @Test
    fun `transient ancestor exchange fails before descriptor bytes escape`() =
        inControlTemporaryDirectory { root ->
            val original = ByteArray(4096) { index -> index.toByte() }
            val replacement = ByteArray(original.size) { index -> (index xor 0x47).toByte() }
            val selectedTree = root.resolve("selected-tree")
            val replacementTree = root.resolve("replacement-tree")
            val input = selectedTree.resolve("parent/control.bin")
            val replacementInput = replacementTree.resolve("parent/control.bin")
            Files.createDirectories(input.parent)
            Files.createDirectories(replacementInput.parent)
            writeOwnerFile(input, original)
            writeOwnerFile(replacementInput, replacement)

            StableControlFile.open(input, original.size.toLong(), "ancestor exchange fixture").use { file ->
                LinuxFilesystemSyscalls.openRoot(root).use { openedRoot ->
                    openedRoot.whileOpen { rootFd ->
                        LinuxFilesystemSyscalls.exchange(rootFd, "selected-tree", "replacement-tree")
                        LinuxFilesystemSyscalls.exchange(rootFd, "selected-tree", "replacement-tree")
                    }
                }
                assertContentEquals(original, Files.readAllBytes(input))
                assertContentEquals(replacement, Files.readAllBytes(replacementInput))
                val destination = ByteArray(original.size) { 0x5a.toByte() }
                val expectedDestination = destination.copyOf()

                val failure = assertFailsWith<FullTreeControlException> {
                    file.readAt(0L, destination, 0, destination.size)
                }

                assertTrue(failure.message.orEmpty().contains("mutated"), failure.message)
                assertContentEquals(expectedDestination, destination)
            }
        }

    @Test
    fun `preexisting writable mapping prevents stable authentication`() =
        inControlTemporaryDirectory { root ->
            val original = ByteArray(8192) { index -> index.toByte() }
            val hostile = ByteArray(original.size) { index -> (index xor 0x6d).toByte() }
            val input = root.resolve("transient-same-inode-control.bin")
            writeOwnerFile(input, original)

            FileChannel.open(input, StandardOpenOption.READ, StandardOpenOption.WRITE).use { writer ->
                val mapping = writer.map(FileChannel.MapMode.READ_WRITE, 0L, original.size.toLong())
                mapping.put(hostile)
                mapping.force()
                mapping.position(0)
                mapping.put(original)
                mapping.force()

                val failure = assertFailsWith<FullTreeControlException> {
                    StableControlFile.open(
                        input,
                        original.size.toLong(),
                        "pre-mapped same-inode fixture",
                    ).close()
                }
                assertTrue(failure.message.orEmpty().contains("read lease"), failure.message)
            }
            assertContentEquals(original, Files.readAllBytes(input))
        }

    @Test
    fun `conflicting nonblocking writer poisons the guard before bytes escape`() =
        inControlTemporaryDirectory { root ->
            val original = ByteArray(8192) { index -> index.toByte() }
            val input = root.resolve("leased-control.bin")
            writeOwnerFile(input, original)

            StableControlFile.open(input, original.size.toLong(), "leased control fixture").use { file ->
                val opened = HostileWriterLibC.open(input.toString(), O_WRONLY or O_NONBLOCK)
                val error = if (opened < 0) Native.getLastError() else 0
                if (opened >= 0) HostileWriterLibC.close(opened)
                assertEquals(-1, opened)
                assertEquals(EWOULDBLOCK, error)
                val failure = assertFailsWith<FullTreeControlException> {
                    file.readExactly(0L, original.size, "leased control fixture")
                }
                assertTrue(failure.message.orEmpty().contains("lease"), failure.message)
            }
            assertContentEquals(original, Files.readAllBytes(input))
        }

    @Test
    fun `host-root-owned file without effective write authority remains admissible`() {
        val effectiveUid = HostileWriterLibC.geteuid()
        val candidate = listOf(Path.of("/etc/passwd"), Path.of("/etc/hosts")).firstOrNull { path ->
            Files.isRegularFile(path, LinkOption.NOFOLLOW_LINKS) &&
                Files.size(path) > 0L &&
                (Files.getAttribute(path, "unix:uid", LinkOption.NOFOLLOW_LINKS) as Number).toInt() == 0
        } ?: return

        StableControlFile.open(
            candidate,
            Files.size(candidate),
            "host-root control fixture",
        ).use { file ->
            assertEquals(OracleArtifacts.sha256(Files.readAllBytes(candidate)), file.sha256())
            file.verifyUnchanged("host-root control fixture")
        }
        assertTrue(effectiveUid == 0 || !Files.isWritable(candidate))
    }

    @Test
    fun `foreign non-root owner without kernel lease authority fails closed`() =
        inControlTemporaryDirectory { root ->
            val unshare = Path.of("/usr/bin/unshare")
            assumeTrue(Files.isExecutable(unshare), "unshare is unavailable")
            Files.setPosixFilePermissions(root, PosixFilePermissions.fromString("rwxrwxrwx"))
            val input = root.resolve("foreign-owner-control.bin")
            val process = ProcessBuilder(
                unshare.toString(),
                "--map-subids",
                "--map-current-user",
                "--setuid",
                "100000",
                "--setgid",
                "100000",
                "--fork",
                "/bin/sh",
                "-c",
                "printf foreign-owner > \"\$1\" && chmod 0444 \"\$1\"",
                "sh",
                input.toString(),
            ).redirectErrorStream(true).start()
            val finished = process.waitFor(10L, TimeUnit.SECONDS)
            if (!finished) process.destroyForcibly()
            assumeTrue(finished, "foreign-owner fixture creation timed out")
            val processOutput = process.inputStream.readAllBytes().decodeToString()
            assumeTrue(
                process.exitValue() == 0,
                "foreign-owner fixture creation is unavailable: $processOutput",
            )
            Files.setPosixFilePermissions(root, PosixFilePermissions.fromString("rwx--x--x"))
            val owner = (Files.getAttribute(
                input,
                "unix:uid",
                LinkOption.NOFOLLOW_LINKS,
            ) as Number).toInt()
            assertTrue(owner != 0 && owner != HostileWriterLibC.geteuid())

            val failure = assertFailsWith<FullTreeControlException> {
                StableControlFile.open(
                    input,
                    Files.size(input),
                    "foreign non-root control fixture",
                ).close()
            }
            assertTrue(failure.message.orEmpty().contains("foreign non-root owner"), failure.message)
        }

    @Test
    fun `non-UTF-8 raw filename cannot alias its replacement-character spelling`() =
        inControlTemporaryDirectory { root ->
            val rawName = "raw-name-".toByteArray(Charsets.UTF_8) + byteArrayOf(0xff.toByte())
            val rawPathBytes = root.toString().toByteArray(Charsets.UTF_8) +
                byteArrayOf('/'.code.toByte()) + rawName + byteArrayOf(0)
            Memory(rawPathBytes.size.toLong()).use { nativePath ->
                nativePath.write(0L, rawPathBytes, 0, rawPathBytes.size)
                val descriptor = HostileWriterLibC.open(
                    nativePath,
                    O_WRONLY or O_CREAT or O_EXCL,
                    OWNER_READ_WRITE,
                )
                val openError = if (descriptor < 0) Native.getLastError() else 0
                assertTrue(descriptor >= 0, "cannot create raw-name fixture (errno=$openError)")
                try {
                    val truncateResult = HostileWriterLibC.ftruncate(descriptor, NativeLong(1L))
                    val truncateError = if (truncateResult != 0) Native.getLastError() else 0
                    assertEquals(0, truncateResult, "cannot size raw-name fixture (errno=$truncateError)")
                } finally {
                    HostileWriterLibC.close(descriptor)
                }
            }

            val replacementSpelling = root.resolve("raw-name-\uFFFD")
            writeOwnerFile(replacementSpelling, byteArrayOf(2, 2))
            val rawPath = Files.list(root).use { entries ->
                entries.filter { candidate -> Files.size(candidate) == 1L }.findFirst().orElseThrow()
            }
            assertEquals(replacementSpelling.toString(), rawPath.toString())

            val failure = assertFailsWith<FullTreeControlException> {
                StableControlFile.open(rawPath, 16L, "non-UTF-8 raw-name fixture").close()
            }
            assertTrue(failure.message.orEmpty().contains("exact Linux name bytes"), failure.message)
        }

    @Test
    fun `unrelated sibling mutations do not invalidate the selected name`() =
        inControlTemporaryDirectory { root ->
            val original = ByteArray(1024) { index -> index.toByte() }
            val input = root.resolve("selected-control.bin")
            val sibling = root.resolve("unrelated.tmp")
            val movedSibling = root.resolve("unrelated.done")
            val siblingDirectory = root.resolve("unrelated-directory")
            writeOwnerFile(input, original)

            StableControlFile.open(input, original.size.toLong(), "selected control fixture").use { file ->
                writeOwnerFile(sibling, byteArrayOf(1, 2, 3))
                Files.move(sibling, movedSibling)
                Files.delete(movedSibling)
                Files.createDirectory(siblingDirectory)
                Files.delete(siblingDirectory)
                assertContentEquals(
                    original,
                    file.readExactly(0L, original.size, "selected control fixture"),
                )
                file.verifyUnchanged("selected control fixture")
            }
        }

    @Test
    fun `one shared mutation monitor retains the full 512 guard caller bound`() =
        inControlTemporaryDirectory { root ->
            val inputs = (0 until 512).map { index ->
                root.resolve("guard-${index.toString().padStart(3, '0')}.bin").also { input ->
                    writeOwnerFile(input, byteArrayOf((index and 0xff).toByte()))
                }
            }
            val guards = ArrayDeque<StableControlFile>()
            try {
                inputs.forEachIndexed { index, input ->
                    guards.addLast(StableControlFile.open(input, 1L, "retained guard $index"))
                }
                assertEquals(512, guards.size)
                guards.forEachIndexed { index, guard ->
                    assertContentEquals(
                        byteArrayOf((index and 0xff).toByte()),
                        guard.readExactly(0L, 1, "retained guard $index"),
                    )
                }
            } finally {
                while (guards.isNotEmpty()) guards.removeLast().close()
            }
        }

    @Test
    fun `public surface exposes no descriptor or selection mutation seam`() {
        assertTrue(StableControlFile::class.java.declaredConstructors.all { constructor ->
            Modifier.isPrivate(constructor.modifiers) && !constructor.isSynthetic
        })
        val publicMethods = StableControlFile::class.java.declaredMethods.filter { method ->
            Modifier.isPublic(method.modifiers) || Modifier.isProtected(method.modifiers)
        }
        assertTrue(
            publicMethods.none { method ->
                method.returnType == LinuxDescriptor::class.java ||
                    method.parameterTypes.any { it == LinuxDescriptor::class.java }
            },
        )
        assertTrue(publicMethods.none { method -> method.returnType == Path::class.java })
        assertTrue(
            publicMethods.none { method ->
                listOf("runner", "mutate", "faultinjector", "descriptor").any { marker ->
                    marker in method.name.lowercase()
                }
            },
        )
        val open = StableControlFile.Companion::class.java.declaredMethods.single {
            it.name == "open"
        }
        assertTrue(Modifier.isPublic(open.modifiers))
        assertEquals(
            listOf(Path::class.java, Long::class.javaPrimitiveType, String::class.java),
            open.parameterTypes.toList(),
        )
        val privateOpen = StableControlFile.Companion::class.java.declaredMethods.single {
            it.name == "openDescriptorBound"
        }
        assertTrue(Modifier.isPrivate(privateOpen.modifiers))
        assertFalse(privateOpen.isSynthetic)
        val facade = Class.forName("decompengine.oracle.fulltree.FullTreeControlSupportKt")
        assertTrue(
            facade.declaredMethods.none { method ->
                Modifier.isPublic(method.modifiers) && method.name.startsWith("access$") &&
                    (method.returnType == LinuxDescriptor::class.java ||
                        method.parameterTypes.any { it == LinuxDescriptor::class.java })
            },
            "no public synthetic accessor may expose retained StableControlFile descriptors",
        )
        assertTrue(
            LinuxFilesystemSyscalls::class.java.declaredMethods.none { method ->
                method.name == "readAt" && method.parameterTypes.any { it == LinuxDescriptor::class.java }
            },
            "StableControlFile must not add a JVM-public raw-descriptor positional-read operation",
        )
        val publiclyReachableTypes = generateSequence(listOf<Class<*>>(StableControlFile::class.java)) { level ->
            level.flatMap { type -> type.declaredClasses.asList() }
                .takeIf { types -> types.isNotEmpty() }
        }.flatten().filter { type -> Modifier.isPublic(type.modifiers) }.toList()
        assertTrue(publiclyReachableTypes.flatMap { type -> type.declaredMethods.asList() }.none { method ->
            (Modifier.isPublic(method.modifiers) || Modifier.isProtected(method.modifiers)) &&
                (method.returnType == LinuxDescriptor::class.java ||
                    method.parameterTypes.any { parameter -> parameter == LinuxDescriptor::class.java })
        })
        assertTrue(publiclyReachableTypes.flatMap { type -> type.declaredConstructors.asList() }.none { constructor ->
            (Modifier.isPublic(constructor.modifiers) || Modifier.isProtected(constructor.modifiers)) &&
                constructor.parameterTypes.any { parameter -> parameter == LinuxDescriptor::class.java }
        })
        assertTrue(publiclyReachableTypes.flatMap { type -> type.declaredFields.asList() }.none { field ->
            Modifier.isPublic(field.modifiers) && (!Modifier.isFinal(field.modifiers) || field.type.isArray)
        })
        assertTrue(publiclyReachableTypes.filterNot { type -> type.isSynthetic }.none { type ->
            listOf("mutation", "fault", "runner", "descriptor").any { marker ->
                marker in type.simpleName.lowercase()
            }
        })
    }

    private fun writeOwnerFile(path: Path, bytes: ByteArray) {
        Files.write(path, bytes)
        Files.setPosixFilePermissions(path, PosixFilePermissions.fromString("rw-------"))
    }

    private interface HostileWriterLibC : Library {
        fun open(path: String, flags: Int): Int
        fun open(path: Memory, flags: Int, mode: Int): Int
        fun ftruncate(descriptor: Int, length: NativeLong): Int
        fun close(descriptor: Int): Int
        fun geteuid(): Int

        companion object : HostileWriterLibC by Native.load(
            Platform.C_LIBRARY_NAME,
            HostileWriterLibC::class.java,
        )
    }

    private companion object {
        const val O_WRONLY = 0x1
        const val O_CREAT = 0x40
        const val O_EXCL = 0x80
        const val O_NONBLOCK = 0x800
        const val OWNER_READ_WRITE = 0x180
        const val EWOULDBLOCK = 11
    }

    private fun openWithPrivateSelectionMutation(
        path: Path,
        maximumBytes: Long,
        mutation: (String) -> Unit,
    ): StableControlFile {
        val method = StableControlFile.Companion::class.java.declaredMethods.single {
            it.name == "openDescriptorBound"
        }
        assertTrue(method.trySetAccessible())
        val reflectedMutation: (Any) -> Unit = { point -> mutation((point as Enum<*>).name) }
        return try {
            method.invoke(
                StableControlFile.Companion,
                path,
                maximumBytes,
                "descriptor selection fixture",
                reflectedMutation,
            ) as StableControlFile
        } catch (failure: InvocationTargetException) {
            throw failure.targetException
        }
    }
}
