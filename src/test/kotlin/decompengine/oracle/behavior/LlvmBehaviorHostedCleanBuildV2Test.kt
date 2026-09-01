package decompengine.oracle.behavior

import decompengine.oracle.core.OracleArtifacts
import decompengine.oracle.fulltree.StableControlFile
import java.lang.reflect.InvocationTargetException
import java.lang.reflect.Modifier
import java.nio.file.Files
import java.nio.file.LinkOption
import java.nio.file.Path
import java.nio.file.StandardCopyOption
import java.nio.file.attribute.PosixFilePermissions
import java.time.Duration
import java.util.Comparator
import java.util.concurrent.TimeUnit
import java.util.concurrent.atomic.AtomicBoolean
import java.util.concurrent.atomic.AtomicReference
import kotlin.io.path.createTempDirectory
import kotlin.test.Test
import kotlin.test.assertContentEquals
import kotlin.test.assertEquals
import kotlin.test.assertFailsWith
import kotlin.test.assertFalse
import kotlin.test.assertTrue

class LlvmBehaviorHostedCleanBuildV2Test {
    @Test
    fun `two fixed direct clang builds ignore candidate build scripts and reproduce exact ELF bytes`() {
        val toolchain = localClangToolchainOrNull() ?: return
        val root = createTempDirectory("hosted-clean-build-test-").toAbsolutePath().normalize()
        val marker = root.resolve("candidate-build-script-ran")
        val first = root.resolve("source-one")
        val second = root.resolve("source-two")
        try {
            createCandidate(first, marker)
            createCandidate(second, marker)

            val assessment = LlvmBehaviorHostedCleanBuildV2TestSupport.assess(
                first,
                second,
            )

            assertFalse(Files.exists(marker, LinkOption.NOFOLLOW_LINKS))
            assertEquals(2, assessment.sourceCount)
            assertEquals(
                assessment.firstBuildEnvironmentSha256,
                assessment.secondBuildEnvironmentSha256,
            )
            assertEquals(
                assessment.firstCompileCommandSetSha256,
                assessment.secondCompileCommandSetSha256,
                "canonical argv commitments must not retain random private roots",
            )
            assertTrue(assessment.dependencyCount >= assessment.sourceCount)
            assertEquals(assessment.firstDependencySetSha256, assessment.secondDependencySetSha256)
            assertEquals(assessment.firstObjectSetSha256, assessment.secondObjectSetSha256)
            assertEquals(assessment.firstLinkCommandSha256, assessment.secondLinkCommandSha256)
            assertEquals(assessment.sourceCount + 12, assessment.linkPlanInputCount)
            assertEquals(
                assessment.firstLinkPlanSha256,
                assessment.secondLinkPlanSha256,
            )
            assertEquals(assessment.firstCombinedOutputBytes, assessment.secondCombinedOutputBytes)
            assertEquals(assessment.firstCombinedOutputSha256, assessment.secondCombinedOutputSha256)
            assertEquals(assessment.executable.size.toLong(), assessment.executableBytes)
            assertEquals(OracleArtifacts.sha256(assessment.executable), assessment.executableSha256)
            assertContentEquals(byteArrayOf(0x7f, 'E'.code.toByte(), 'L'.code.toByte(), 'F'.code.toByte()),
                assessment.executable.copyOfRange(0, 4))

            val liveExecutable = root.resolve("live-candidate")
            Files.write(liveExecutable, assessment.executable)
            Files.setPosixFilePermissions(liveExecutable, PosixFilePermissions.fromString("r-x------"))
            val live = ProcessBuilder(liveExecutable.toString()).start()
            assertTrue(live.waitFor(5, TimeUnit.SECONDS), "linked candidate did not terminate")
            assertEquals(0, live.exitValue())
            assertEquals("hosted-ok\n", live.inputStream.readBytes().toString(Charsets.UTF_8))
            assertTrue(live.errorStream.readBytes().isEmpty())

            val exposed = assessment.executable
            exposed.fill(0)
            assertTrue(assessment.executable[0] != 0.toByte())

            val retry = LlvmBehaviorHostedCleanBuildV2TestSupport.assess(
                first,
                second,
            )
            assertEquals(assessment.firstBuildEnvironmentSha256, retry.firstBuildEnvironmentSha256)
            assertEquals(assessment.firstCompileCommandSetSha256, retry.firstCompileCommandSetSha256)
            assertEquals(assessment.firstDependencySetSha256, retry.firstDependencySetSha256)
            assertEquals(assessment.firstObjectSetSha256, retry.firstObjectSetSha256)
            assertEquals(assessment.firstLinkCommandSha256, retry.firstLinkCommandSha256)
            assertEquals(assessment.firstLinkPlanSha256, retry.firstLinkPlanSha256)
            assertEquals(assessment.firstCombinedOutputBytes, retry.firstCombinedOutputBytes)
            assertEquals(assessment.firstCombinedOutputSha256, retry.firstCombinedOutputSha256)
            assertContentEquals(assessment.executable, retry.executable)
        } finally {
            deleteTree(root)
        }
    }

    @Test
    fun `test build seam rejects cross-paired source revisions before compilation`() {
        val toolchain = localClangToolchainOrNull() ?: return
        val root = createTempDirectory("hosted-clean-build-pairing-").toAbsolutePath().normalize()
        val marker = root.resolve("must-not-run")
        val first = root.resolve("source-one")
        val second = root.resolve("source-two")
        try {
            createCandidate(first, marker)
            createCandidate(second, marker)
            Files.writeString(second.resolve("src/value.c"), "#include \"value.h\"\nint value(void) { return 18; }\n")

            val failure = assertFailsWith<LlvmBehaviorHostedCleanBuildV2Exception> {
                LlvmBehaviorHostedCleanBuildV2TestSupport.assess(
                    first,
                    second,
                )
            }
            assertTrue(failure.message.orEmpty().contains("same source revision"), failure.message)
            assertFalse(Files.exists(marker, LinkOption.NOFOLLOW_LINKS))
        } finally {
            deleteTree(root)
        }
    }

    @Test
    fun `direct build rejects compiler dependencies outside authenticated source and system roots`() {
        val toolchain = localClangToolchainOrNull() ?: return
        val root = createTempDirectory("hosted-clean-build-dependency-").toAbsolutePath().normalize()
        val marker = root.resolve("must-not-run")
        val outside = root.resolve("outside-candidate.h")
        val first = root.resolve("source-one")
        val second = root.resolve("source-two")
        try {
            Files.writeString(outside, "#define OUTSIDE_VALUE 17\n")
            createCandidate(first, marker)
            createCandidate(second, marker)
            val source = "#include \"${outside}\"\nint main(void) { return OUTSIDE_VALUE == 17 ? 0 : 1; }\n"
            Files.writeString(first.resolve("src/main.c"), source)
            Files.writeString(second.resolve("src/main.c"), source)

            val failure = assertFailsWith<LlvmBehaviorHostedCleanBuildV2Exception> {
                LlvmBehaviorHostedCleanBuildV2TestSupport.assess(
                    first,
                    second,
                )
            }
            assertTrue(failure.message.orEmpty().contains("outside reviewed container"), failure.message)
            assertFalse(Files.exists(marker, LinkOption.NOFOLLOW_LINKS))
        } finally {
            deleteTree(root)
        }
    }

    @Test
    fun `direct build rejects inline assembler external-input channels before compilation`() {
        val toolchain = localClangToolchainOrNull() ?: return
        val root = createTempDirectory("hosted-clean-build-assembler-").toAbsolutePath().normalize()
        val marker = root.resolve("must-not-run")
        val first = root.resolve("source-one")
        val second = root.resolve("source-two")
        try {
            createCandidate(first, marker)
            createCandidate(second, marker)
            val source = "int main(void) { __asm__(\".incbin \\\"/etc/hostname\\\"\"); return 0; }\n"
            Files.writeString(first.resolve("src/main.c"), source)
            Files.writeString(second.resolve("src/main.c"), source)

            val failure = assertFailsWith<LlvmBehaviorHostedCleanBuildV2Exception> {
                LlvmBehaviorHostedCleanBuildV2TestSupport.assess(
                    first,
                    second,
                )
            }
            assertTrue(failure.message.orEmpty().contains("unsupported external-input token"), failure.message)
            assertFalse(Files.exists(marker, LinkOption.NOFOLLOW_LINKS))
        } finally {
            deleteTree(root)
        }
    }

    @Test
    fun `inner worker has no caller-selected path or claim surface`() {
        val methods = LlvmBehaviorHostedCleanBuildV2InnerWorker::class.java.declaredMethods
            .filter { it.name == "produce" && !it.isSynthetic }
        assertEquals(1, methods.size)
        assertTrue(methods.single().parameterTypes.isEmpty())
    }

    @Test
    fun `retained executable ignores a hostile post-adoption tool-name replacement`() {
        val toolchain = localClangToolchainOrNull() ?: return
        val root = createTempDirectory("hosted-retained-tool-swap-").toAbsolutePath().normalize()
        var retained: AutoCloseable? = null
        var workingDirectory: AutoCloseable? = null
        try {
            val selected = root.resolve("selected-clang")
            val replacement = root.resolve("hostile-replacement")
            Files.copy(toolchain.compiler, selected)
            Files.copy(Path.of("/usr/bin/false"), replacement)
            Files.setPosixFilePermissions(selected, PosixFilePermissions.fromString("r-x------"))
            Files.setPosixFilePermissions(replacement, PosixFilePermissions.fromString("r-x------"))
            val authenticatedSha256 = OracleArtifacts.sha256(Files.readAllBytes(selected))
            retained = reflectedSnapshot(selected, executable = true)

            Files.move(
                replacement,
                selected,
                StandardCopyOption.ATOMIC_MOVE,
                StandardCopyOption.REPLACE_EXISTING,
            )
            assertTrue(OracleArtifacts.sha256(Files.readAllBytes(selected)) != authenticatedSha256)

            workingDirectory = reflectedPinnedDirectory(root)
            val result = reflectedRun(
                retained,
                listOf("--no-default-config", "--version"),
                workingDirectory,
                Duration.ofSeconds(5),
                1024 * 1024,
                "hostile retained-tool exchange",
            )
            assertEquals(0, reflectedInt(result, "getExitCode"))
            assertTrue(
                reflectedBytes(result, "getStdout").toString(Charsets.UTF_8).contains("clang version 22.1.8"),
            )
            assertTrue(reflectedBytes(result, "getStderr").isEmpty())
        } finally {
            runCatching { workingDirectory?.close() }
            runCatching { retained?.close() }
            deleteTree(root)
        }
    }

    @Test
    fun `sealed stdin and VFS inputs ignore hostile source and header name replacement`() {
        val toolchain = localClangToolchainOrNull() ?: return
        val root = createTempDirectory("hosted-retained-input-swap-").toAbsolutePath().normalize()
        var retainedCompiler: AutoCloseable? = null
        var retainedSource: AutoCloseable? = null
        var retainedHeader: AutoCloseable? = null
        var retainedOverlay: AutoCloseable? = null
        var workingDirectory: AutoCloseable? = null
        try {
            val selectedSource = root.resolve("selected-main.c")
            val selectedHeader = root.resolve("selected-value.h")
            val hostileSource = root.resolve("hostile-main.c")
            val hostileHeader = root.resolve("hostile-value.h")
            Files.writeString(selectedSource, "#include \"value.h\"\nint retained_value(void) { return VALUE; }\n")
            Files.writeString(selectedHeader, "#define VALUE 17\n")
            Files.writeString(hostileSource, "#error hostile source substitution\n")
            Files.writeString(hostileHeader, "#error hostile header substitution\n")

            val compilerSnapshot = reflectedSnapshot(toolchain.compiler, executable = true)
            retainedCompiler = compilerSnapshot
            val sourceSnapshot = reflectedSnapshot(selectedSource, executable = false)
            retainedSource = sourceSnapshot
            val headerSnapshot = reflectedSnapshot(selectedHeader, executable = false)
            retainedHeader = headerSnapshot
            val sourceCapability = reflectedCapability(sourceSnapshot, "retained hostile-test source")
            val headerCapability = reflectedCapability(headerSnapshot, "retained hostile-test header")
            val overlayPath = root.resolve("overlay.json")
            Files.writeString(
                overlayPath,
                """{"version":0,"case-sensitive":true,"use-external-names":false,"redirecting-with":"fallthrough","roots":[{"type":"file","name":"/decomp-candidate/src/main.c","use-external-name":false,"external-contents":"$sourceCapability"},{"type":"file","name":"/decomp-candidate/include/value.h","use-external-name":false,"external-contents":"$headerCapability"}]}""",
            )
            val overlaySnapshot = reflectedSnapshot(overlayPath, executable = false)
            retainedOverlay = overlaySnapshot
            val pinnedDirectory = reflectedPinnedDirectory(root)
            workingDirectory = pinnedDirectory

            Files.move(
                hostileSource,
                selectedSource,
                StandardCopyOption.ATOMIC_MOVE,
                StandardCopyOption.REPLACE_EXISTING,
            )
            Files.move(
                hostileHeader,
                selectedHeader,
                StandardCopyOption.ATOMIC_MOVE,
                StandardCopyOption.REPLACE_EXISTING,
            )

            val result = reflectedRun(
                compilerSnapshot,
                listOf(
                    "--no-default-config",
                    "--target=x86_64-pc-linux-gnu",
                    "-fintegrated-cc1",
                    "-fintegrated-as",
                    "-nostdinc",
                    "-ivfsoverlay",
                    reflectedCapability(overlaySnapshot, "retained hostile-test overlay"),
                    "-iquote",
                    "/decomp-candidate/src",
                    "-I/decomp-candidate/include",
                    "-std=c11",
                    "-c",
                    "-x",
                    "c",
                    "-",
                    "-o",
                    "-",
                ),
                pinnedDirectory,
                Duration.ofSeconds(5),
                1024 * 1024,
                "hostile retained source and header compile",
                standardInput = sourceSnapshot,
            )
            assertEquals(0, reflectedInt(result, "getExitCode"))
            assertContentEquals(
                byteArrayOf(0x7f, 'E'.code.toByte(), 'L'.code.toByte(), 'F'.code.toByte()),
                reflectedBytes(result, "getStdout").copyOfRange(0, 4),
            )
            assertTrue(reflectedBytes(result, "getStderr").isEmpty())
        } finally {
            runCatching { workingDirectory?.close() }
            runCatching { retainedOverlay?.close() }
            runCatching { retainedHeader?.close() }
            runCatching { retainedSource?.close() }
            runCatching { retainedCompiler?.close() }
            deleteTree(root)
        }
    }

    @Test
    fun `retained LLD consumes a sealed object after its authenticated name is replaced`() {
        val toolchain = localClangToolchainOrNull() ?: return
        val root = createTempDirectory("hosted-retained-object-swap-").toAbsolutePath().normalize()
        val retained = ArrayList<AutoCloseable>()
        var workingDirectory: AutoCloseable? = null
        try {
            fun snapshot(path: Path, executable: Boolean): AutoCloseable =
                reflectedSnapshot(path, executable).also(retained::add)

            val pinnedDirectory = reflectedPinnedDirectory(root)
            workingDirectory = pinnedDirectory
            val compiler = snapshot(toolchain.compiler, executable = true)
            val query = reflectedRun(
                compiler,
                listOf("--no-default-config", "--target=x86_64-pc-linux-gnu", "--print-file-name=crti.o"),
                pinnedDirectory,
                Duration.ofSeconds(5),
                16 * 1024,
                "resolve hostile-test object fixture",
            )
            assertEquals(0, reflectedInt(query, "getExitCode"))
            val crti = Path.of(reflectedBytes(query, "getStdout").toString(Charsets.UTF_8).trim())
                .toRealPath()
            val selected = root.resolve("selected-object.o")
            val hostile = root.resolve("hostile-object.o")
            Files.copy(crti, selected)
            Files.writeString(hostile, "not an ELF object\n")
            val retainedObject = snapshot(selected, executable = false)
            val linker = snapshot(toolchain.linker, executable = true)

            Files.move(hostile, selected, StandardCopyOption.ATOMIC_MOVE, StandardCopyOption.REPLACE_EXISTING)
            val result = reflectedRun(
                linker,
                listOf(
                    "-flavor",
                    "gnu",
                    "-r",
                    "-o",
                    "-",
                    reflectedCapability(retainedObject, "retained hostile-test object"),
                ),
                pinnedDirectory,
                Duration.ofSeconds(5),
                1024 * 1024,
                "hostile retained-object LLD link",
                roleName = "LLD",
            )
            assertEquals(0, reflectedInt(result, "getExitCode"))
            assertContentEquals(
                byteArrayOf(0x7f, 'E'.code.toByte(), 'L'.code.toByte(), 'F'.code.toByte()),
                reflectedBytes(result, "getStdout").copyOfRange(0, 4),
            )
            assertTrue(reflectedBytes(result, "getStderr").isEmpty())
        } finally {
            runCatching { workingDirectory?.close() }
            retained.asReversed().forEach { runCatching(it::close) }
            deleteTree(root)
        }
    }

    @Test
    fun `private retained runner reaps timeout and overflow leaders without adopting unrelated JVM children`() {
        val root = createTempDirectory("hosted-retained-cleanup-").toAbsolutePath().normalize()
        var retainedShell: AutoCloseable? = null
        var workingDirectory: AutoCloseable? = null
        val unrelated = ProcessBuilder("/usr/bin/sleep", "30").start()
        try {
            val shell = root.resolve("retained-shell")
            Files.copy(Path.of("/bin/sh"), shell)
            Files.setPosixFilePermissions(shell, PosixFilePermissions.fromString("r-x------"))
            retainedShell = reflectedSnapshot(shell, executable = true)
            workingDirectory = reflectedPinnedDirectory(root)

            val timeoutPid = root.resolve("timeout.pid")
            val timeoutFailure = assertFailsWith<InvocationTargetException> {
                reflectedRun(
                    retainedShell,
                    listOf("-c", "/usr/bin/sleep 30 & child=\$!; echo \"\$\$ \$child\" > $timeoutPid; wait"),
                    workingDirectory,
                    Duration.ofMillis(200),
                    1024,
                    "hostile timeout command",
                )
            }.targetException
            assertTrue(timeoutFailure.message.orEmpty().contains("deadline"), timeoutFailure.message)
            readPids(timeoutPid).forEach(::assertProcessGone)
            assertTrue(unrelated.isAlive, "hosted cleanup must not scan and kill unrelated JVM descendants")

            val overflowPid = root.resolve("overflow.pid")
            val overflowFailure = assertFailsWith<InvocationTargetException> {
                reflectedRun(
                    retainedShell,
                    listOf("-c", "echo \$\$ > $overflowPid; exec /usr/bin/yes x"),
                    workingDirectory,
                    Duration.ofSeconds(5),
                    1024,
                    "hostile overflow command",
                )
            }.targetException
            assertTrue(overflowFailure.message.orEmpty().contains("output bound"), overflowFailure.message)
            assertProcessGone(readPid(overflowPid))
            assertTrue(unrelated.isAlive)

            val crossStreamPid = root.resolve("cross-stream.pid")
            val crossStreamFailure = assertFailsWith<InvocationTargetException> {
                reflectedRun(
                    retainedShell,
                    listOf(
                        "-c",
                        "echo \$\$ > $crossStreamPid; printf '%0700d' 0; " +
                            "printf '%0700d' 0 >&2; exec /usr/bin/sleep 30",
                    ),
                    workingDirectory,
                    Duration.ofSeconds(5),
                    1024,
                    "hostile aggregate overflow command",
                )
            }.targetException
            assertTrue(crossStreamFailure.message.orEmpty().contains("output bound"), crossStreamFailure.message)
            assertProcessGone(readPid(crossStreamPid))
            assertTrue(unrelated.isAlive)

            val interruptPid = root.resolve("interrupt.pid")
            val interruptFailure = AtomicReference<Throwable?>()
            val interruptRestored = AtomicBoolean(false)
            val interruptThread = Thread {
                try {
                    reflectedRun(
                        retainedShell,
                        listOf(
                            "-c",
                            "/usr/bin/sleep 30 >/dev/null 2>&1 & child=\$!; " +
                                "echo \"\$\$ \$child\" > $interruptPid; " +
                                "exec 1>&- 2>&-; wait",
                        ),
                        workingDirectory,
                        Duration.ofSeconds(5),
                        1024,
                        "hostile interrupted command",
                    )
                } catch (failure: Throwable) {
                    interruptFailure.set(failure)
                } finally {
                    interruptRestored.set(Thread.currentThread().isInterrupted)
                }
            }.also { thread -> thread.isDaemon = true }
            interruptThread.start()
            val interruptedPids = readPids(interruptPid)
            interruptThread.interrupt()
            interruptThread.join(5_000)
            assertFalse(interruptThread.isAlive, "interrupted retained runner did not complete exact cleanup")
            val interruptedTarget = (interruptFailure.get() as? InvocationTargetException)?.targetException
            assertTrue(interruptedTarget?.message.orEmpty().contains("interrupted"), interruptedTarget?.message)
            assertTrue(interruptRestored.get(), "retained runner did not restore interruption after exact cleanup")
            interruptedPids.forEach(::assertProcessGone)
            assertTrue(unrelated.isAlive)
        } finally {
            unrelated.destroyForcibly()
            unrelated.waitFor()
            runCatching { workingDirectory?.close() }
            runCatching { retainedShell?.close() }
            deleteTree(root)
        }
    }

    @Test
    fun `private retained spawn fixes argv0 cwd environment and inherited descriptors`() {
        val root = createTempDirectory("hosted-retained-spawn-contract-").toAbsolutePath().normalize()
        var workingDirectory: AutoCloseable? = null
        try {
            val pinnedDirectory = reflectedPinnedDirectory(root)
            workingDirectory = pinnedDirectory

            fun invoke(path: Path, arguments: List<String>, label: String): Any {
                val retained = reflectedSnapshot(path, executable = true)
                return try {
                    reflectedRun(
                        retained,
                        arguments,
                        pinnedDirectory,
                        Duration.ofSeconds(5),
                        1024 * 1024,
                        label,
                    )
                } finally {
                    retained.close()
                }
            }

            val environment = invoke(Path.of("/usr/bin/env"), emptyList(), "exact environment probe")
            assertEquals(0, reflectedInt(environment, "getExitCode"))
            assertEquals(
                setOf("LC_ALL=C", "TZ=UTC"),
                reflectedBytes(environment, "getStdout").toString(Charsets.UTF_8)
                    .lineSequence().filter(String::isNotEmpty).toSet(),
            )

            val cwd = invoke(Path.of("/usr/bin/pwd"), emptyList(), "exact cwd probe")
            assertEquals(0, reflectedInt(cwd, "getExitCode"))
            assertEquals("$root\n", reflectedBytes(cwd, "getStdout").toString(Charsets.UTF_8))

            val shell = invoke(
                Path.of("/bin/sh").toRealPath(),
                listOf(
                    "-c",
                    "[ \"\$0\" = clang ] || exit 71; " +
                        "descriptor=3; while [ \"\$descriptor\" -lt 1024 ]; do " +
                        "[ ! -e /proc/self/fd/\$descriptor ] || exit 72; " +
                        "descriptor=\$((descriptor + 1)); done; printf closed",
                ),
                "exact argv0 and descriptor probe",
            )
            assertEquals(0, reflectedInt(shell, "getExitCode"))
            assertEquals("closed", reflectedBytes(shell, "getStdout").toString(Charsets.UTF_8))
            assertTrue(reflectedBytes(shell, "getStderr").isEmpty())
        } finally {
            runCatching { workingDirectory?.close() }
            deleteTree(root)
        }
    }

    @Test
    fun `hosted retained implementation has no public capability or generic runner surface`() {
        val repository = Path.of("").toAbsolutePath().normalize()
        val kotlinSource = Files.readString(
            repository.resolve("src/main/kotlin/decompengine/oracle/behavior/LlvmBehaviorHostedCleanBuildV2.kt"),
        )
        val nativeSource = Files.readString(
            repository.resolve("src/main/java/decompengine/oracle/behavior/HostedNativeExecution.java"),
        )
        val implementationSource = kotlinSource + nativeSource
        listOf("ProcessBuilder", "--ld-path", "-Wl,", "parseLldLink").forEach { forbidden ->
            assertFalse(implementationSource.contains(forbidden), forbidden)
        }
        listOf(
            "memfd_create",
            "posix_spawn_file_actions_addfchdir_np",
            "posix_spawn_file_actions_addclosefrom_np",
            "pidfd_open",
            "pidfd_send_signal",
        ).forEach { required -> assertTrue(nativeSource.contains(required), required) }
        listOf(
            "retained-descriptor-clang-per-source",
            "retained-descriptor-lld-direct",
        ).forEach { required -> assertTrue(kotlinSource.contains(required), required) }

        val assess = LlvmBehaviorHostedCleanBuildV2TestSupport::class.java.declaredMethods.single { method ->
            method.name == "assess" && !method.isSynthetic
        }
        assertEquals(listOf(Path::class.java, Path::class.java), assess.parameterTypes.toList())
        assertTrue(
            LlvmBehaviorHostedCleanBuildV2TestSupport::class.java.declaredMethods.none { method ->
                method.name.contains("LinkDependency") ||
                    method.parameterTypes.any { type -> type == Int::class.java || type == Process::class.java }
            },
        )
        val implementationClassLoader = LlvmBehaviorHostedCleanBuildV2Test::class.java.classLoader
        val nativeBoundary = Class.forName(
            "decompengine.oracle.behavior.HostedNativeExecution",
            false,
            implementationClassLoader,
        )
        assertFalse(Modifier.isPublic(nativeBoundary.modifiers), nativeBoundary.name)
        assertFalse(Modifier.isProtected(nativeBoundary.modifiers), nativeBoundary.name)
        assertTrue(
            nativeBoundary.declaredFields.none { field ->
                Modifier.isPublic(field.modifiers) || Modifier.isProtected(field.modifiers)
            },
            nativeBoundary.name,
        )
        assertTrue(
            nativeBoundary.declaredConstructors.none { constructor ->
                Modifier.isPublic(constructor.modifiers) || Modifier.isProtected(constructor.modifiers)
            },
            nativeBoundary.name,
        )
        assertTrue(
            nativeBoundary.declaredMethods.none { method ->
                Modifier.isPublic(method.modifiers) || Modifier.isProtected(method.modifiers)
            },
            nativeBoundary.name,
        )
        val nativeMethods = nativeBoundary.declaredMethods.filter { method -> Modifier.isNative(method.modifiers) }
        assertTrue(nativeMethods.isNotEmpty(), "hosted native boundary exposes no registered native methods")
        assertTrue(
            nativeMethods.all { method -> Modifier.isPrivate(method.modifiers) },
            nativeMethods.filterNot { method -> Modifier.isPrivate(method.modifiers) }
                .joinToString { method -> method.toString() },
        )
        nativeBoundary.declaredClasses.forEach { nested ->
            assertFalse(Modifier.isPublic(nested.modifiers), nested.name)
            assertFalse(Modifier.isProtected(nested.modifiers), nested.name)
            assertTrue(
                nested.declaredFields.none { field ->
                    Modifier.isPublic(field.modifiers) || Modifier.isProtected(field.modifiers)
                },
                nested.name,
            )
            assertTrue(
                nested.declaredConstructors.none { constructor ->
                    Modifier.isPublic(constructor.modifiers) || Modifier.isProtected(constructor.modifiers)
                },
                nested.name,
            )
            assertTrue(
                nested.declaredMethods.none { method ->
                    Modifier.isPublic(method.modifiers) || Modifier.isProtected(method.modifiers)
                },
                nested.name,
            )
        }

        val kotlinFacade = Class.forName(
            "decompengine.oracle.behavior.LlvmBehaviorHostedCleanBuildV2Kt",
            false,
            implementationClassLoader,
        )
        val forbiddenKotlinBridges = setOf(
            "access\$getHOSTED_LIBC",
            "access\$hostedDescriptorPath",
            "access\$hostedFcntlSeals",
            "access\$hostedNativeResult",
            "access\$hostedPidfdOpen",
            "access\$readRetainedBytes",
            "access\$readRetainedIdentity",
            "access\$requireHostedNativeVector",
            "access\$snapshotHostedFile",
        )
        val survivingKotlinBridges = kotlinFacade.declaredMethods
            .map { method -> method.name }
            .filter { name -> name in forbiddenKotlinBridges }
        assertTrue(
            survivingKotlinBridges.isEmpty(),
            "old Kotlin native bridges remain public: $survivingKotlinBridges",
        )

        listOf(
            "HostedRetainedFile",
            "HostedPinnedDirectory",
            "HostedBuildProcessRunner",
            "HostedNativeProcess",
            "HostedBoundedCapture",
            "HostedLibC",
        ).forEach { simpleName ->
            assertFailsWith<ClassNotFoundException>(simpleName) {
                Class.forName("decompengine.oracle.behavior.$simpleName", false, implementationClassLoader)
            }
        }
        val objectType = Class.forName(
            "decompengine.oracle.behavior.HostedBuildObject",
            false,
            implementationClassLoader,
        )
        assertTrue(objectType.declaredFields.none { field -> field.type == Path::class.java })
    }

    private fun createCandidate(root: Path, marker: Path) {
        Files.createDirectories(root.resolve("src"))
        Files.createDirectories(root.resolve("include"))
        Files.createDirectories(root.resolve("reports"))
        Files.writeString(
            root.resolve("Makefile"),
            "all:\n\t/usr/bin/touch ${marker.toAbsolutePath().normalize()}\n",
        )
        Files.writeString(root.resolve("include/value.h"), "int value(void);\n")
        Files.writeString(
            root.resolve("src/value.c"),
            "#include \"value.h\"\nint value(void) { return 17; }\n",
        )
        Files.writeString(
            root.resolve("src/main.c"),
            "#include <stdio.h>\n#include \"value.h\"\n" +
                "int main(void) { if (value() != 17) return 1; return puts(\"hosted-ok\") < 0; }\n",
        )
        Files.writeString(
            root.resolve("reports/build_contract.json"),
            "{\"command\":[\"/bin/sh\",\"-c\",\"touch ${marker.toAbsolutePath().normalize()}\"]}\n",
        )
    }

    private fun localClangToolchainOrNull(): LocalToolchain? {
        return listOf(
            LocalToolchain(Path.of("/usr/lib/llvm/22/bin/clang-22"), Path.of("/usr/lib/llvm/22/bin/lld")),
            LocalToolchain(Path.of("/usr/lib/llvm-22/bin/clang"), Path.of("/usr/lib/llvm-22/bin/lld")),
        ).firstOrNull { toolchain ->
            isRegularExecutable(toolchain.compiler) && isRegularExecutable(toolchain.linker)
        }
    }

    private fun isRegularExecutable(path: Path): Boolean =
        Files.isRegularFile(path, LinkOption.NOFOLLOW_LINKS) && !Files.isSymbolicLink(path) && Files.isExecutable(path)

    private fun reflectedSnapshot(path: Path, executable: Boolean): AutoCloseable =
        StableControlFile.open(path, 512L * 1024L * 1024L, "hostile reflected snapshot").use { guard ->
            val method = Class.forName(
                "decompengine.oracle.behavior.HostedNativeExecution",
            ).declaredMethods.single { candidate ->
                candidate.name == "snapshot" &&
                    candidate.parameterCount == 5 &&
                    candidate.parameterTypes.firstOrNull() == StableControlFile::class.java
            }.also { it.isAccessible = true }
            ReflectedHandle(
                method.invoke(
                    null,
                    guard,
                    guard.size,
                    guard.sha256(label = "hostile reflected snapshot"),
                    executable,
                    "hostile reflected snapshot",
                ),
            ) as AutoCloseable
        }

    private fun reflectedPinnedDirectory(path: Path): AutoCloseable {
        val method = Class.forName(
            "decompengine.oracle.behavior.HostedNativeExecution",
        ).declaredMethods.single { candidate ->
            candidate.name == "open" &&
                candidate.parameterCount == 2 &&
                candidate.parameterTypes.firstOrNull() == Path::class.java
        }.also { it.isAccessible = true }
        return ReflectedHandle(method.invoke(null, path, "hostile reflected working directory"))
    }

    private fun reflectedCapability(retained: AutoCloseable, label: String): String =
        reflectedValue(retained).javaClass.declaredMethods.single { method ->
            method.name == "capabilityPath" && method.parameterCount == 1
        }.also { it.isAccessible = true }.invoke(reflectedValue(retained), label) as String

    private fun reflectedRun(
        retained: AutoCloseable,
        arguments: List<String>,
        workingDirectory: AutoCloseable,
        timeout: Duration,
        maximumOutputBytes: Int,
        label: String,
        standardInput: AutoCloseable? = null,
        roleName: String = "CLANG",
    ): Any {
        val boundary = Class.forName("decompengine.oracle.behavior.HostedNativeExecution")
        val methodName = if (roleName == "LLD") "runLld" else "runClang"
        val parameterCount = if (roleName == "LLD") 8 else 9
        val run = boundary.declaredMethods.single { method ->
            method.name == methodName && method.parameterCount == parameterCount
        }
            .also { it.isAccessible = true }
        val shared = arrayOf(
            reflectedValue(retained),
            arguments,
            mapOf("LC_ALL" to "C", "TZ" to "UTC"),
            reflectedValue(workingDirectory),
            timeout,
            maximumOutputBytes,
            Duration.ofSeconds(2),
            label,
        )
        return if (roleName == "LLD") {
            run.invoke(null, *shared)
        } else {
            run.invoke(null, shared[0], standardInput?.let(::reflectedValue), *shared.copyOfRange(1, shared.size))
        }
    }

    private fun reflectedValue(handle: AutoCloseable): Any = (handle as ReflectedHandle).value

    private class ReflectedHandle(val value: Any) : AutoCloseable {
        override fun close() {
            value.javaClass.declaredMethods.single { method ->
                method.name == "close" && method.parameterCount == 0
            }.also { it.isAccessible = true }.invoke(value)
        }
    }

    private fun reflectedInt(value: Any, getter: String): Int =
        value.javaClass.getDeclaredMethod(getter).also { it.isAccessible = true }.invoke(value) as Int

    private fun reflectedBytes(value: Any, getter: String): ByteArray =
        value.javaClass.getDeclaredMethod(getter).also { it.isAccessible = true }.invoke(value) as ByteArray

    private fun readPid(path: Path): Long {
        val deadline = System.nanoTime() + Duration.ofSeconds(2).toNanos()
        while (!Files.exists(path, LinkOption.NOFOLLOW_LINKS) && System.nanoTime() < deadline) Thread.sleep(5)
        return Files.readString(path).trim().toLong()
    }

    private fun readPids(path: Path): List<Long> {
        val deadline = System.nanoTime() + Duration.ofSeconds(2).toNanos()
        while (!Files.exists(path, LinkOption.NOFOLLOW_LINKS) && System.nanoTime() < deadline) Thread.sleep(5)
        return Files.readString(path).trim().split(Regex(" +")).map(String::toLong)
    }

    private fun assertProcessGone(pid: Long) {
        val process = Path.of("/proc", pid.toString())
        val deadline = System.nanoTime() + Duration.ofSeconds(2).toNanos()
        while (Files.exists(process, LinkOption.NOFOLLOW_LINKS) && System.nanoTime() < deadline) Thread.sleep(5)
        assertFalse(Files.exists(process, LinkOption.NOFOLLOW_LINKS), "process $pid survived exact cleanup")
    }

    private fun deleteTree(root: Path) {
        if (!Files.exists(root, LinkOption.NOFOLLOW_LINKS)) return
        Files.walk(root).use { paths -> paths.sorted(Comparator.reverseOrder()).forEach(Files::deleteIfExists) }
    }

    private data class LocalToolchain(val compiler: Path, val linker: Path)
}
