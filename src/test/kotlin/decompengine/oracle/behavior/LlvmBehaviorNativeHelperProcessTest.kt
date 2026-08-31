package decompengine.oracle.behavior

import java.nio.file.Files
import java.nio.file.LinkOption
import java.nio.file.Path
import java.nio.file.StandardCopyOption
import java.nio.file.attribute.PosixFilePermissions
import java.util.concurrent.TimeUnit
import kotlin.io.path.createTempDirectory
import kotlin.test.Test
import kotlin.test.assertContentEquals
import kotlin.test.assertEquals
import kotlin.test.assertFalse
import kotlin.test.assertTrue
import org.junit.jupiter.api.Assumptions.assumeTrue

class LlvmBehaviorNativeHelperProcessTest {
    @Test
    fun `closed CLI rejects missing wrong extra relative and overflow arguments`() {
        listOf(
            emptyList(),
            listOf("wrong-v2", "stage"),
            listOf(PROTOCOL, "unknown"),
            listOf(PROTOCOL, "stage", "extra"),
            preExecArguments(nonce = "A".repeat(32)),
            preExecArguments(command = "relative-command"),
            preExecArguments(memory = "01073741824"),
        ).forEach { arguments ->
            val result = runHelper(arguments, emptyMap())
            assertEquals(125, result.exitCode, "invocation unexpectedly accepted: $arguments")
            assertTrue(result.stdout.isEmpty())
            assertEquals("$PROTOCOL: rejected\n", result.stderr.toString(Charsets.UTF_8))
        }
    }

    @Test
    fun `stage and collection require exact cleared environment allowlists`() {
        val stage = runHelper(
            listOf(PROTOCOL, "stage"),
            mapOf(
                "TARGET_UID" to "0",
                "TARGET_GID" to "0",
                "WORKSPACE_BYTES" to "4096",
                "WORKSPACE_ENTRIES" to "16",
                "EXTRA" to "forbidden",
            ),
        )
        assertEquals(125, stage.exitCode)

        val collection = runHelper(
            listOf(PROTOCOL, "collect"),
            mapOf("WORKSPACE_BYTES" to "4096", "WORKSPACE_ENTRIES" to "16", "PATH" to "/bin"),
        )
        assertEquals(125, collection.exitCode)
    }

    @Test
    fun `descriptor-safe staging and collection preserve bytes and closed modes`() = withNamespaceRoot { root ->
        requireNamespaceSupport(root)
        val nested = Files.createDirectory(root.resolve("case-inputs/nested"))
        val data = byteArrayOf(0, 1, 2, 3, 0x7f, 0xff.toByte())
        Files.write(nested.resolve("data.bin"), data)
        Files.writeString(root.resolve("case-inputs/tool"), "native-tool\n")
        Files.setPosixFilePermissions(root.resolve("case-inputs/tool"), PosixFilePermissions.fromString("rwxr-xr-x"))

        val result = runNamespace(root, NamespaceAction.STAGE_AND_COLLECT)
        assertEquals(0, result.exitCode, result.stderr.toString(Charsets.UTF_8))
        assertTrue(result.stdout.isEmpty())
        assertTrue(result.stderr.isEmpty())
        assertContentEquals(data, Files.readAllBytes(root.resolve("case-results/nested/data.bin")))
        assertEquals("native-tool\n", Files.readString(root.resolve("case-results/tool")))
        assertEquals(0x100, unixMode(root.resolve("case-results/nested/data.bin")))
        assertEquals(0x140, unixMode(root.resolve("case-results/tool")))
        assertEquals(0x1c0, unixMode(root.resolve("case-results/nested")))
    }

    @Test
    fun `staging and collection reject links bounds and mount-boundary crossings`() {
        listOf(
            NamespaceAction.SYMLINK_INPUT,
            NamespaceAction.HARDLINK_INPUT,
            NamespaceAction.BYTE_BOUND,
            NamespaceAction.SUBDIRECTORY_MOUNT,
            NamespaceAction.NESTED_BIND_MOUNT,
        ).forEach { action ->
            withNamespaceRoot { root ->
                requireNamespaceSupport(root)
                when (action) {
                    NamespaceAction.SYMLINK_INPUT -> {
                        Files.writeString(root.resolve("case-inputs/target"), "target")
                        Files.createSymbolicLink(root.resolve("case-inputs/link"), Path.of("target"))
                    }
                    NamespaceAction.HARDLINK_INPUT -> {
                        val first = root.resolve("case-inputs/first")
                        Files.writeString(first, "shared")
                        Files.createLink(root.resolve("case-inputs/second"), first)
                    }
                    NamespaceAction.BYTE_BOUND -> Files.write(root.resolve("case-inputs/large"), ByteArray(8192))
                    NamespaceAction.SUBDIRECTORY_MOUNT -> Files.writeString(root.resolve("case-inputs/input"), "input")
                    NamespaceAction.NESTED_BIND_MOUNT -> Unit
                    else -> error("unexpected action")
                }
                val result = runNamespace(root, action)
                assertEquals(125, result.exitCode, "$action was not rejected")
                assertTrue(result.stdout.isEmpty())
                assertTrue(result.stderr.toString(Charsets.UTF_8).contains("rejected"))
            }
        }
    }

    @Test
    fun `collector rejects candidate-created symlink instead of escaping workspace`() = withNamespaceRoot { root ->
        requireNamespaceSupport(root)
        Files.writeString(root.resolve("case-inputs/input"), "input")
        val outside = root.resolve("outside-secret")
        Files.writeString(outside, "must-not-copy")

        val result = runNamespace(root, NamespaceAction.COLLECT_SYMLINK)
        assertEquals(125, result.exitCode)
        assertFalse(Files.exists(root.resolve("case-results/leak"), LinkOption.NOFOLLOW_LINKS))
        assertEquals("must-not-copy", Files.readString(outside))
    }

    @Test
    fun `collector rejects a non-tmpfs workspace and a permissive results root`() {
        listOf(
            NamespaceAction.COLLECT_NON_TMPFS,
            NamespaceAction.COLLECT_PERMISSIVE_RESULTS,
        ).forEach { action ->
            withNamespaceRoot { root ->
                requireNamespaceSupport(root)
                val result = runNamespace(root, action)
                assertEquals(125, result.exitCode, "$action was not rejected")
                assertTrue(result.stdout.isEmpty())
                assertTrue(result.stderr.toString(Charsets.UTF_8).contains("rejected"))
            }
        }
    }

    private fun preExecArguments(
        nonce: String = "0".repeat(32),
        command: String = "/bin/true",
        memory: String = "1073741824",
    ): List<String> = listOf(
        PROTOCOL,
        "pre-exec",
        "target",
        nonce,
        memory,
        "128",
        "100000",
        "100000",
        "16777216",
        "128",
        "128",
        "10",
        "500",
        "--",
        command,
    )

    private fun runHelper(arguments: List<String>, environment: Map<String, String>): ProcessResult = runProcess(
        listOf(productionHelper().toString(), *arguments.toTypedArray()),
        environment,
    )

    private fun runNamespace(root: Path, action: NamespaceAction): ProcessResult {
        val bytes = if (action == NamespaceAction.BYTE_BOUND) 4096 else 32 * 1024 * 1024
        val entries = if (action == NamespaceAction.BYTE_BOUND) 16 else 1024
        val script = when (action) {
            NamespaceAction.STAGE_AND_COLLECT -> STAGE_AND_COLLECT_SCRIPT
            NamespaceAction.COLLECT_SYMLINK -> COLLECT_SYMLINK_SCRIPT
            NamespaceAction.SUBDIRECTORY_MOUNT -> SUBDIRECTORY_MOUNT_SCRIPT
            NamespaceAction.NESTED_BIND_MOUNT -> NESTED_BIND_MOUNT_SCRIPT
            NamespaceAction.COLLECT_NON_TMPFS -> COLLECT
            NamespaceAction.COLLECT_PERMISSIVE_RESULTS -> COLLECT_PERMISSIVE_RESULTS_SCRIPT
            else -> STAGE_ONLY_SCRIPT
        }
        return runProcess(
            listOf(
                UNSHARE.toString(),
                "-Urmfp",
                "--mount-proc=${root.resolve("proc")}",
                SHELL.toString(),
                "-eu",
                "-c",
                script,
                "sh",
                root.toString(),
                bytes.toString(),
                entries.toString(),
            ),
            emptyMap(),
            timeoutSeconds = 15,
        )
    }

    private fun runProcess(
        command: List<String>,
        environment: Map<String, String>,
        timeoutSeconds: Long = 5,
    ): ProcessResult {
        val process = ProcessBuilder(command).also { builder ->
            builder.environment().clear()
            builder.environment().putAll(environment)
        }.start()
        process.outputStream.close()
        val stdout = process.inputStream.readNBytes(MAXIMUM_CAPTURE_BYTES + 1)
        val stderr = process.errorStream.readNBytes(MAXIMUM_CAPTURE_BYTES + 1)
        val exited = process.waitFor(timeoutSeconds, TimeUnit.SECONDS)
        if (!exited) {
            process.destroyForcibly()
            process.waitFor(2, TimeUnit.SECONDS)
        }
        assertTrue(exited, "native helper test process timed out")
        assertTrue(stdout.size <= MAXIMUM_CAPTURE_BYTES && stderr.size <= MAXIMUM_CAPTURE_BYTES)
        return ProcessResult(process.exitValue(), stdout, stderr)
    }

    private fun withNamespaceRoot(block: (Path) -> Unit) {
        val root = createTempDirectory("llvm-behavior-helper-root-")
        try {
            listOf("case-inputs", "case-results", "workspace", "workspace-source", "proc").forEach {
                Files.createDirectory(root.resolve(it))
            }
            Files.setPosixFilePermissions(
                root.resolve("case-results"),
                PosixFilePermissions.fromString("rwx------"),
            )
            Files.setPosixFilePermissions(
                root.resolve("workspace"),
                PosixFilePermissions.fromString("rwx------"),
            )
            Files.copy(productionHelper(), root.resolve("helper"), StandardCopyOption.COPY_ATTRIBUTES)
            Files.setPosixFilePermissions(root.resolve("helper"), PosixFilePermissions.fromString("rwxr-xr-x"))
            block(root)
        } finally {
            root.toFile().deleteRecursively()
        }
    }

    private fun requireNamespaceSupport(root: Path) {
        assumeTrue(Files.isExecutable(UNSHARE) && Files.isExecutable(MOUNT) && Files.isExecutable(CHROOT))
        val result = runProcess(
            listOf(UNSHARE.toString(), "-Ur", "/usr/bin/true"),
            emptyMap(),
        )
        assumeTrue(result.exitCode == 0, "unprivileged user namespaces are unavailable")
        assertTrue(Files.isDirectory(root.resolve("proc")))
    }

    private fun productionHelper(): Path {
        val configured = requireNotNull(System.getProperty("decompengine.oracle.behavior.nativeHelperExecutable")) {
            "production LLVM behavior helper was not supplied by Gradle"
        }
        val path = Path.of(configured).toAbsolutePath().normalize()
        require(path == Path.of(configured) && Files.isRegularFile(path, LinkOption.NOFOLLOW_LINKS))
        return path
    }

    private fun unixMode(path: Path): Int = (Files.getAttribute(path, "unix:mode") as Number).toInt() and 0x1ff

    private data class ProcessResult(val exitCode: Int, val stdout: ByteArray, val stderr: ByteArray)

    private enum class NamespaceAction {
        STAGE_AND_COLLECT,
        SYMLINK_INPUT,
        HARDLINK_INPUT,
        BYTE_BOUND,
        SUBDIRECTORY_MOUNT,
        NESTED_BIND_MOUNT,
        COLLECT_SYMLINK,
        COLLECT_NON_TMPFS,
        COLLECT_PERMISSIVE_RESULTS,
    }

    private companion object {
        const val PROTOCOL = "decomp-llvm-behavior-helper-v2"
        const val MAXIMUM_CAPTURE_BYTES = 64 * 1024
        val UNSHARE: Path = Path.of("/usr/bin/unshare")
        val MOUNT: Path = Path.of("/usr/bin/mount")
        val CHROOT: Path = Path.of("/usr/bin/chroot")
        val SHELL: Path = Path.of("/usr/bin/sh")
        const val MOUNT_WORKSPACE =
            "/usr/bin/mount -t tmpfs -o rw,nosuid,nodev,size=\$2,nr_inodes=\$3,mode=0700,uid=0,gid=0 " +
                "tmpfs \"\$1/workspace-source\"\n" +
                "/usr/bin/mount --bind \"\$1/workspace-source\" \"\$1/workspace\""
        const val STAGE =
            "/usr/bin/env -i TARGET_UID=0 TARGET_GID=0 WORKSPACE_BYTES=\$2 WORKSPACE_ENTRIES=\$3 " +
                "/usr/bin/chroot \"\$1\" /helper $PROTOCOL stage"
        const val COLLECT =
            "/usr/bin/env -i TARGET_UID=0 TARGET_GID=0 WORKSPACE_BYTES=\$2 WORKSPACE_ENTRIES=\$3 " +
                "/usr/bin/chroot \"\$1\" /helper $PROTOCOL collect"
        const val REMOUNT_WORKSPACE_READ_ONLY =
            "/usr/bin/mount -o remount,bind,ro,nosuid,nodev \"\$1/workspace\""
        const val STAGE_ONLY_SCRIPT = "$MOUNT_WORKSPACE\n$STAGE"
        const val STAGE_AND_COLLECT_SCRIPT =
            "$MOUNT_WORKSPACE\n$STAGE\n$REMOUNT_WORKSPACE_READ_ONLY\n$COLLECT"
        const val COLLECT_SYMLINK_SCRIPT =
            "$MOUNT_WORKSPACE\n$STAGE\n/usr/bin/ln -s /outside-secret \"\$1/workspace/leak\"\n" +
                "$REMOUNT_WORKSPACE_READ_ONLY\n$COLLECT"
        const val COLLECT_PERMISSIVE_RESULTS_SCRIPT =
            "$MOUNT_WORKSPACE\n$REMOUNT_WORKSPACE_READ_ONLY\n" +
                "/usr/bin/chmod 0755 \"\$1/case-results\"\n$COLLECT"
        const val SUBDIRECTORY_MOUNT_SCRIPT =
            "/usr/bin/mount -t tmpfs -o rw,nosuid,nodev,size=\$2,nr_inodes=\$3,mode=0700,uid=0,gid=0 " +
                "tmpfs \"\$1/workspace-source\"\n" +
                "/usr/bin/mkdir -m 0700 \"\$1/workspace-source/subdirectory\"\n" +
                "/usr/bin/mount --bind \"\$1/workspace-source/subdirectory\" \"\$1/workspace\"\n" +
                STAGE
        const val NESTED_BIND_MOUNT_SCRIPT =
            "$MOUNT_WORKSPACE\n" +
                "/usr/bin/mkdir -m 0700 \"\$1/workspace-source/nested\" " +
                "\"\$1/workspace-source/nested-source\"\n" +
                "/usr/bin/touch \"\$1/workspace-source/nested-source/injected\"\n" +
                "/usr/bin/mount --bind \"\$1/workspace-source/nested-source\" \"\$1/workspace/nested\"\n" +
                "/usr/bin/mount -o remount,bind,ro,nosuid,nodev \"\$1/workspace/nested\"\n" +
                "$REMOUNT_WORKSPACE_READ_ONLY\n$COLLECT"
    }
}
