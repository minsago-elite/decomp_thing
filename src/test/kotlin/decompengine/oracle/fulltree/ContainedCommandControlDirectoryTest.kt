package decompengine.oracle.fulltree

import decompengine.acp.LinuxFilesystemSyscalls
import java.nio.file.Files
import java.nio.file.Path
import java.nio.file.attribute.PosixFilePermissions
import java.util.concurrent.TimeUnit
import org.junit.jupiter.api.Assumptions.assumeTrue
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
                val controls = ContainedCommandRetainedDirectories(activeName, previous)
                previous.clear()
                createContainedCommandControlDirectory(parent, activeName).use {
                    controls.verify(parent)
                    val oldPath = path.resolve(oldName).toString()
                    assertEquals(listOf("--ro-bind", oldPath, oldPath), controls.mountArguments(path))
                    assertEquals(1, controls.controlsToJson().size)
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
                assertFails { ContainedCommandRetainedDirectories(null, mapOf(oldName to LinuxFilesystemSyscalls.identity(old.fd))) }
                assertFails { ContainedCommandRetainedDirectories(oldName, mapOf(oldName to LinuxFilesystemSyscalls.identity(old.fd))) }
                assertFails { ContainedCommandRetainedDirectories(activeName, mapOf("../outside" to LinuxFilesystemSyscalls.identity(old.fd))) }
                val controls = ContainedCommandRetainedDirectories(activeName, mapOf(oldName to LinuxFilesystemSyscalls.identity(old.fd)))
                controls.verify(parent)
                Files.setPosixFilePermissions(path.resolve(oldName), PosixFilePermissions.fromString("rwxr-xr-x"))
                assertFails { controls.verify(parent) }
            }
        }
    }

    @Test
    fun `retained state binds only the original state subtree beside prior controls`() = fixture { path ->
        Files.createDirectory(path.resolve("state"), PosixFilePermissions.asFileAttribute(PosixFilePermissions.fromString("rwx------")))
        Files.writeString(path.resolve("state/database"), "retained-project")
        LinuxFilesystemSyscalls.openRoot(path).use { parent ->
            LinuxFilesystemSyscalls.openDirectoryAt(parent.fd, "state").use { state ->
                val oldName = "control-${"e".repeat(64)}"
                val activeName = "control-${"f".repeat(64)}"
                createContainedCommandControlDirectory(parent, oldName).use { old ->
                    val retained = ContainedCommandRetainedDirectories(activeName,
                        mapOf(oldName to LinuxFilesystemSyscalls.identity(old.fd)), state.identity)
                    retained.verify(parent)
                    val oldPath = path.resolve(oldName).toString()
                    val statePath = path.resolve("state").toString()
                    assertEquals(listOf("--ro-bind", oldPath, oldPath, "--ro-bind", statePath, statePath), retained.mountArguments(path))
                    assertEquals(1, retained.controlsToJson().size)
                    assertEquals(containedControlIdentityJson("state", state.identity), retained.stateToJson())
                    assertFails { ContainedCommandRetainedDirectories(null, emptyMap(), state.identity) }
                    assertFails { ContainedCommandRetainedDirectories(activeName, mapOf("state" to state.identity)) }
                    val stateOnly = ContainedCommandRetainedDirectories(activeName, emptyMap(), state.identity)
                    assertTrue(stateOnly.controlsAreEmpty)
                    assertEquals(listOf("--ro-bind", statePath, statePath), stateOnly.mountArguments(path))
                    Files.move(path.resolve("state"), path.resolve("retained-old-state"))
                    Files.createDirectory(path.resolve("state"), PosixFilePermissions.asFileAttribute(PosixFilePermissions.fromString("rwx------")))
                    assertFails { retained.verify(parent) }
                    assertEquals("retained-project", Files.readString(path.resolve("retained-old-state/database")))
                }
            }
        }
    }

    @Test
    fun `retained state protection rejects changed directory permissions`() = fixture { path ->
        Files.createDirectory(path.resolve("state"), PosixFilePermissions.asFileAttribute(PosixFilePermissions.fromString("rwx------")))
        LinuxFilesystemSyscalls.openRoot(path).use { parent ->
            LinuxFilesystemSyscalls.openDirectoryAt(parent.fd, "state").use { state ->
                val retained = ContainedCommandRetainedDirectories("control-${"a".repeat(64)}", emptyMap(), state.identity)
                retained.verify(parent)
                Files.setPosixFilePermissions(path.resolve("state"), PosixFilePermissions.fromString("rwxr-xr-x"))
                assertFails { retained.verify(parent) }
            }
        }
    }

    @Test
    fun `local mount fixture prevents retained writes while allowing new project and report writes`() = fixture { path ->
        // Namespace mount behavior only: this fixture supplies no authenticated runtime, cgroup or disk lease.
        val bwrap = Path.of("/usr/bin/bwrap")
        assumeTrue(Files.isExecutable(bwrap), "local bubblewrap fixture requires bwrap")
        val prefix = listOf(bwrap.toString(), "--unshare-user", "--unshare-pid", "--ro-bind", "/", "/",
            "--proc", "/proc", "--die-with-parent", "--cap-drop", "ALL")
        assumeTrue(runLocalMountCommand(prefix + "/bin/true") == 0, "local user/mount namespaces are unavailable")
        val privateMode = PosixFilePermissions.asFileAttribute(PosixFilePermissions.fromString("rwx------"))
        Files.createDirectory(path.resolve("state"), privateMode)
        Files.createDirectory(path.resolve("reports"), privateMode)
        Files.writeString(path.resolve("state/database"), "retained-project")
        LinuxFilesystemSyscalls.openRoot(path).use { parent ->
            LinuxFilesystemSyscalls.openDirectoryAt(parent.fd, "state").use { state ->
                val oldName = "control-${"b".repeat(64)}"
                val activeName = "control-${"c".repeat(64)}"
                createContainedCommandControlDirectory(parent, oldName).use { old ->
                    Files.writeString(path.resolve(oldName).resolve("token"), "retained-token")
                    createContainedCommandControlDirectory(parent, activeName).use {
                        val retained = ContainedCommandRetainedDirectories(activeName,
                            mapOf(oldName to LinuxFilesystemSyscalls.identity(old.fd)), state.identity)
                        retained.verify(parent)
                        val command = prefix + listOf("--bind", path.toString(), path.toString()) + retained.mountArguments(path) +
                            listOf("/bin/sh", "-c", """set -eu
if (printf changed > "${'$'}1/state/database") 2>/dev/null; then exit 10; fi
if (printf changed > "${'$'}1/${'$'}2/token") 2>/dev/null; then exit 11; fi
printf active > "${'$'}1/${'$'}3/state/new"
printf exported > "${'$'}1/reports/new"
""", "mount-fixture", path.toString(), oldName, activeName)
                        assertEquals(0, runLocalMountCommand(command), "retained mount fixture failed")
                        retained.verify(parent)
                        assertEquals("retained-project", Files.readString(path.resolve("state/database")))
                        assertEquals("retained-token", Files.readString(path.resolve(oldName).resolve("token")))
                        assertEquals("active", Files.readString(path.resolve(activeName).resolve("state/new")))
                        assertEquals("exported", Files.readString(path.resolve("reports/new")))
                    }
                }
            }
        }
    }

    private fun runLocalMountCommand(command: List<String>): Int {
        val process = ProcessBuilder(command).redirectOutput(ProcessBuilder.Redirect.DISCARD)
            .redirectError(ProcessBuilder.Redirect.DISCARD).start()
        try {
            assertTrue(process.waitFor(10, TimeUnit.SECONDS), "local mount fixture timed out")
            return process.exitValue()
        } finally {
            if (process.isAlive) {
                process.destroyForcibly()
                assertTrue(process.waitFor(5, TimeUnit.SECONDS), "local mount fixture was not reaped")
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
