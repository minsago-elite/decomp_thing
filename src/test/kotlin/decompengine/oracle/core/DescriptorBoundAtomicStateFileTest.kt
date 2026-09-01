package decompengine.oracle.core

import decompengine.acp.LinuxFilesystemSyscalls
import java.io.IOException
import java.nio.file.Files
import java.nio.file.LinkOption
import java.nio.file.Path
import java.nio.file.attribute.PosixFilePermissions
import kotlin.io.path.createTempDirectory
import kotlin.test.Test
import kotlin.test.assertContentEquals
import kotlin.test.assertEquals
import kotlin.test.assertFailsWith
import kotlin.test.assertFalse
import kotlin.test.assertTrue

class DescriptorBoundAtomicStateFileTest {
    @Test
    fun `immutable publication is durable idempotent and never replaces different bytes`() =
        withStateDirectory { path ->
            LinuxFilesystemSyscalls.openRoot(path).use { root ->
                val expected = "canonical operation state\n".toByteArray()
                val published = DescriptorBoundAtomicStateFile.publishNoReplace(
                    root,
                    STATE_FILE,
                    expected,
                    MAXIMUM_BYTES,
                )

                assertContentEquals(expected, published.bytes)
                assertEquals(
                    PosixFilePermissions.fromString("r--------"),
                    Files.getPosixFilePermissions(path.resolve(STATE_FILE), LinkOption.NOFOLLOW_LINKS),
                )
                assertContentEquals(
                    expected,
                    DescriptorBoundAtomicStateFile.publishNoReplace(
                        root,
                        STATE_FILE,
                        expected,
                        MAXIMUM_BYTES,
                    ).bytes,
                )
                assertFailsWith<IOException> {
                    DescriptorBoundAtomicStateFile.publishNoReplace(
                        root,
                        STATE_FILE,
                        "different\n".toByteArray(),
                        MAXIMUM_BYTES,
                    )
                }
                assertContentEquals(expected, Files.readAllBytes(path.resolve(STATE_FILE)))
                assertEquals(listOf(STATE_FILE), Files.list(path).use { entries ->
                    entries.map { it.fileName.toString() }.sorted().toList()
                })
            }
        }

    @Test
    fun `executable publication is durable idempotent and never replaces different bytes`() =
        withStateDirectory { path ->
            LinuxFilesystemSyscalls.openRoot(path).use { root ->
                val expected = byteArrayOf(0x7f, 'E'.code.toByte(), 'L'.code.toByte(), 'F'.code.toByte())
                val published = DescriptorBoundAtomicStateFile.publishExecutableNoReplace(
                    root,
                    EXECUTABLE_FILE,
                    expected,
                    MAXIMUM_BYTES,
                )

                assertContentEquals(expected, published.bytes)
                assertEquals(
                    PosixFilePermissions.fromString("r-x------"),
                    Files.getPosixFilePermissions(path.resolve(EXECUTABLE_FILE), LinkOption.NOFOLLOW_LINKS),
                )
                assertContentEquals(
                    expected,
                    DescriptorBoundAtomicStateFile.publishExecutableNoReplace(
                        root,
                        EXECUTABLE_FILE,
                        expected,
                        MAXIMUM_BYTES,
                    ).bytes,
                )
                DescriptorBoundAtomicStateFile.inspectExecutableOrNull(
                    root,
                    EXECUTABLE_FILE,
                    MAXIMUM_BYTES,
                ).use { inspection ->
                    assertContentEquals(expected, requireNotNull(inspection).bytes)
                }
                assertFailsWith<IOException> {
                    DescriptorBoundAtomicStateFile.inspectOrNull(root, EXECUTABLE_FILE, MAXIMUM_BYTES)
                }
                assertFailsWith<IOException> {
                    DescriptorBoundAtomicStateFile.publishExecutableNoReplace(
                        root,
                        EXECUTABLE_FILE,
                        byteArrayOf(0x7f, 'B'.code.toByte(), 'A'.code.toByte(), 'D'.code.toByte()),
                        MAXIMUM_BYTES,
                    )
                }
                assertContentEquals(expected, Files.readAllBytes(path.resolve(EXECUTABLE_FILE)))
            }
        }

    @Test
    fun `every executable crash point converges through an exact retry`() {
        DescriptorBoundStateFaultPoint.entries.forEachIndexed { index, point ->
            withStateDirectory { path ->
                LinuxFilesystemSyscalls.openRoot(path).use { root ->
                    val name = "candidate-$index"
                    val expected = byteArrayOf(0x7f, index.toByte(), point.ordinal.toByte())
                    assertFailsWith<SimulatedProcessDeath> {
                        DescriptorBoundAtomicStateFile.publishExecutableNoReplace(
                            root,
                            name,
                            expected,
                            MAXIMUM_BYTES,
                            DescriptorBoundStateFaultInjector { observed ->
                                if (observed == point) throw SimulatedProcessDeath()
                            },
                        )
                    }

                    val recovered = DescriptorBoundAtomicStateFile.publishExecutableNoReplace(
                        root,
                        name,
                        expected,
                        MAXIMUM_BYTES,
                    )
                    assertContentEquals(expected, recovered.bytes)
                    assertEquals(
                        PosixFilePermissions.fromString("r-x------"),
                        Files.getPosixFilePermissions(path.resolve(name), LinkOption.NOFOLLOW_LINKS),
                    )
                    assertFalse(
                        Files.exists(
                            path.resolve(DescriptorBoundAtomicStateFile.temporaryName(name)),
                            LinkOption.NOFOLLOW_LINKS,
                        ),
                    )
                }
            }
        }
    }

    @Test
    fun `every durable no-replace crash point converges through an exact retry`() {
        DescriptorBoundStateFaultPoint.entries.forEachIndexed { index, point ->
            withStateDirectory { path ->
                LinuxFilesystemSyscalls.openRoot(path).use { root ->
                    val name = "state-$index.json"
                    val expected = "state-$point\n".toByteArray()
                    assertFailsWith<SimulatedProcessDeath> {
                        DescriptorBoundAtomicStateFile.publishNoReplace(
                            root,
                            name,
                            expected,
                            MAXIMUM_BYTES,
                            DescriptorBoundStateFaultInjector { observed ->
                                if (observed == point) throw SimulatedProcessDeath()
                            },
                        )
                    }

                    val temporary = path.resolve(DescriptorBoundAtomicStateFile.temporaryName(name))
                    when (point) {
                        DescriptorBoundStateFaultPoint.AFTER_UNNAMED_FILE_SYNC -> {
                            assertFalse(Files.exists(path.resolve(name), LinkOption.NOFOLLOW_LINKS))
                            assertFalse(Files.exists(temporary, LinkOption.NOFOLLOW_LINKS))
                        }

                        DescriptorBoundStateFaultPoint.AFTER_TEMPORARY_DIRECTORY_SYNC -> {
                            assertFalse(Files.exists(path.resolve(name), LinkOption.NOFOLLOW_LINKS))
                            assertTrue(Files.isRegularFile(temporary, LinkOption.NOFOLLOW_LINKS))
                        }

                        DescriptorBoundStateFaultPoint.AFTER_PUBLICATION_RENAME,
                        DescriptorBoundStateFaultPoint.AFTER_PUBLICATION_DIRECTORY_SYNC,
                        -> {
                            assertTrue(Files.isRegularFile(path.resolve(name), LinkOption.NOFOLLOW_LINKS))
                            assertFalse(Files.exists(temporary, LinkOption.NOFOLLOW_LINKS))
                        }
                    }

                    val recovered = DescriptorBoundAtomicStateFile.publishNoReplace(
                        root,
                        name,
                        expected,
                        MAXIMUM_BYTES,
                    )
                    assertContentEquals(expected, recovered.bytes)
                    assertContentEquals(expected, Files.readAllBytes(path.resolve(name)))
                    assertFalse(Files.exists(temporary, LinkOption.NOFOLLOW_LINKS))
                }
            }
        }
    }

    @Test
    fun `unknown deterministic temporary residue is retained and rejected`() =
        withStateDirectory { path ->
            val temporaryName = DescriptorBoundAtomicStateFile.temporaryName(STATE_FILE)
            val temporary = path.resolve(temporaryName)
            Files.write(temporary, "foreign\n".toByteArray())
            Files.setPosixFilePermissions(temporary, PosixFilePermissions.fromString("r--------"))

            LinuxFilesystemSyscalls.openRoot(path).use { root ->
                assertFailsWith<IOException> {
                    DescriptorBoundAtomicStateFile.publishNoReplace(
                        root,
                        STATE_FILE,
                        "expected\n".toByteArray(),
                        MAXIMUM_BYTES,
                    )
                }
            }

            assertContentEquals("foreign\n".toByteArray(), Files.readAllBytes(temporary))
            assertFalse(Files.exists(path.resolve(STATE_FILE), LinkOption.NOFOLLOW_LINKS))
        }

    @Test
    fun `publication and snapshots defensively copy mutable byte arrays`() = withStateDirectory { path ->
        LinuxFilesystemSyscalls.openRoot(path).use { root ->
            val source = "immutable\n".toByteArray()
            val snapshot = DescriptorBoundAtomicStateFile.publishNoReplace(
                root,
                STATE_FILE,
                source,
                MAXIMUM_BYTES,
            )
            source.fill('x'.code.toByte())
            val exposed = snapshot.bytes
            exposed.fill('y'.code.toByte())

            assertContentEquals(
                "immutable\n".toByteArray(),
                DescriptorBoundAtomicStateFile.readOrNull(root, STATE_FILE, MAXIMUM_BYTES)?.bytes,
            )
        }
    }

    @Test
    fun `simultaneous target and temporary residue is retained and rejected`() = withStateDirectory { path ->
        LinuxFilesystemSyscalls.openRoot(path).use { root ->
            val expected = "immutable\n".toByteArray()
            DescriptorBoundAtomicStateFile.publishNoReplace(root, STATE_FILE, expected, MAXIMUM_BYTES)
            val temporary = path.resolve(DescriptorBoundAtomicStateFile.temporaryName(STATE_FILE))
            Files.write(temporary, expected)
            Files.setPosixFilePermissions(temporary, PosixFilePermissions.fromString("r--------"))

            assertFailsWith<IOException> {
                DescriptorBoundAtomicStateFile.publishNoReplace(root, STATE_FILE, expected, MAXIMUM_BYTES)
            }
            assertContentEquals(expected, Files.readAllBytes(path.resolve(STATE_FILE)))
            assertContentEquals(expected, Files.readAllBytes(temporary))
        }
    }

    private inline fun withStateDirectory(action: (Path) -> Unit) {
        val directory = createTempDirectory("descriptor-state-").toAbsolutePath().normalize()
        Files.setPosixFilePermissions(directory, PosixFilePermissions.fromString("rwx------"))
        try {
            action(directory)
        } finally {
            Files.list(directory).use { entries -> entries.toList() }
                .forEach(Files::deleteIfExists)
            Files.deleteIfExists(directory)
        }
    }

    private class SimulatedProcessDeath : Error()

    private companion object {
        const val STATE_FILE = "operation.json"
        const val EXECUTABLE_FILE = "candidate-reconstructed"
        const val MAXIMUM_BYTES = 64 * 1024
    }
}
