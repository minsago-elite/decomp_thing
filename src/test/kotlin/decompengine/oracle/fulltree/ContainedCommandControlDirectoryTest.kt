package decompengine.oracle.fulltree

import decompengine.acp.LinuxFilesystemSyscalls
import java.nio.file.Files
import java.nio.file.Path
import java.nio.file.attribute.PosixFilePermissions
import kotlin.test.Test
import kotlin.test.assertEquals
import kotlin.test.assertFails
import kotlin.test.assertFalse
import kotlin.test.assertNotEquals
import kotlin.test.assertTrue

class ContainedCommandControlDirectoryTest {
    @Test
    fun `fresh execution directories retain separate protocol files and preserve shared project data`() = fixture { path ->
        Files.createDirectory(path.resolve("state"))
        Files.writeString(path.resolve("state/database"), "retained-project")
        LinuxFilesystemSyscalls.openRoot(path).use { parent ->
            val firstName = "control-${"a".repeat(64)}"
            val secondName = "control-${"b".repeat(64)}"
            createContainedCommandControlDirectory(parent, firstName).use { first ->
                Files.writeString(path.resolve(firstName).resolve("token"), "old-protocol")
                createContainedCommandControlDirectory(parent, secondName).use { second ->
                    assertNotEquals(first.identity.key, second.identity.key)
                    assertEquals(setOf("state", "reports", "tmp"), LinuxFilesystemSyscalls.directoryEntryNames(second, 4).toSet())
                    requireContainedControlDirectory(parent, firstName, first)
                    requireContainedControlDirectory(parent, secondName, second)
                    for (name in listOf(firstName, secondName)) {
                        assertEquals(PosixFilePermissions.fromString("rwx------"), Files.getPosixFilePermissions(path.resolve(name)))
                    }
                }
            }
            assertEquals("old-protocol", Files.readString(path.resolve(firstName).resolve("token")))
            assertEquals("retained-project", Files.readString(path.resolve("state/database")))
            assertFails { createContainedCommandControlDirectory(parent, firstName) }
        }
    }

    @Test
    fun `unsafe names existing directories and links are rejected without replacement`() = fixture { path ->
        LinuxFilesystemSyscalls.openRoot(path).use { parent ->
            for (name in listOf("../outside", "control-", "control-${"A".repeat(64)}", "control-${"a".repeat(63)}", "arbitrary")) {
                assertFails { createContainedCommandControlDirectory(parent, name) }
            }
            assertTrue(LinuxFilesystemSyscalls.directoryEntryNames(parent, 1).isEmpty())
            val name = "control-${"c".repeat(64)}"
            val target = Files.createDirectory(path.resolve("target"))
            Files.createSymbolicLink(path.resolve(name), target)
            assertFails { createContainedCommandControlDirectory(parent, name) }
            assertTrue(Files.isSymbolicLink(path.resolve(name)))
            assertTrue(Files.isDirectory(target))
        }
    }

    @Test
    fun `same-name replacement and changed permissions revoke directory validation`() = fixture { path ->
        LinuxFilesystemSyscalls.openRoot(path).use { parent ->
            val name = "control-${"d".repeat(64)}"
            createContainedCommandControlDirectory(parent, name).use { child ->
                Files.move(path.resolve(name), path.resolve("retained-old"))
                Files.createDirectory(path.resolve(name))
                assertFails { requireContainedControlDirectory(parent, name, child) }
                assertFalse(Files.notExists(path.resolve("retained-old")))
            }
            val nextName = "control-${"e".repeat(64)}"
            createContainedCommandControlDirectory(parent, nextName).use { child ->
                Files.setPosixFilePermissions(path.resolve(nextName), PosixFilePermissions.fromString("rwxr-xr-x"))
                assertFails { requireContainedControlDirectory(parent, nextName, child) }
            }
        }
    }

    @Test
    fun `changed parent permissions fail before any control directory is created`() = fixture { path ->
        LinuxFilesystemSyscalls.openRoot(path).use { parent ->
            Files.setPosixFilePermissions(path, PosixFilePermissions.fromString("rwxr-xr-x"))
            assertFails { createContainedCommandControlDirectory(parent, "control-${"f".repeat(64)}") }
            assertTrue(LinuxFilesystemSyscalls.directoryEntryNames(parent, 1).isEmpty())
        }
    }

    @Test
    fun `prior controls pin identities and snapshot read-only mount membership`() = fixture { path ->
        LinuxFilesystemSyscalls.openRoot(path).use { parent ->
            val oldName = "control-${"a".repeat(64)}"
            val activeName = "control-${"b".repeat(64)}"
            createContainedCommandControlDirectory(parent, oldName).use { old ->
                val previous = mutableMapOf(oldName to LinuxFilesystemSyscalls.identity(old.fd))
                val controls = ContainedCommandPriorControls(activeName, previous)
                previous.clear()
                createContainedCommandControlDirectory(parent, activeName).use {
                    controls.verify(parent)
                    val oldPath = path.resolve(oldName).toString()
                    assertEquals(listOf("--ro-bind", oldPath, oldPath), controls.mountArguments(path))
                    assertEquals(1, controls.toJson().size)
                    Files.move(path.resolve(oldName), path.resolve("retained-old"))
                    Files.createDirectory(path.resolve(oldName))
                    assertFails { controls.verify(parent) }
                }
            }
        }
    }

    @Test
    fun `prior controls reject active overlap unsafe names and changed permissions`() = fixture { path ->
        LinuxFilesystemSyscalls.openRoot(path).use { parent ->
            val oldName = "control-${"c".repeat(64)}"
            val activeName = "control-${"d".repeat(64)}"
            createContainedCommandControlDirectory(parent, oldName).use { old ->
                assertFails { ContainedCommandPriorControls(null, mapOf(oldName to LinuxFilesystemSyscalls.identity(old.fd))) }
                assertFails { ContainedCommandPriorControls(oldName, mapOf(oldName to LinuxFilesystemSyscalls.identity(old.fd))) }
                assertFails { ContainedCommandPriorControls(activeName, mapOf("../outside" to LinuxFilesystemSyscalls.identity(old.fd))) }
                val controls = ContainedCommandPriorControls(activeName, mapOf(oldName to LinuxFilesystemSyscalls.identity(old.fd)))
                controls.verify(parent)
                Files.setPosixFilePermissions(path.resolve(oldName), PosixFilePermissions.fromString("rwxr-xr-x"))
                assertFails { controls.verify(parent) }
            }
        }
    }

    private fun fixture(action: (Path) -> Unit) {
        val path = Files.createTempDirectory("contained-control-fixture-")
        Files.setPosixFilePermissions(path, PosixFilePermissions.fromString("rwx------"))
        try { action(path) } finally {
            Files.walk(path).use { stream -> stream.sorted(Comparator.reverseOrder()).forEach(Files::delete) }
        }
    }
}
