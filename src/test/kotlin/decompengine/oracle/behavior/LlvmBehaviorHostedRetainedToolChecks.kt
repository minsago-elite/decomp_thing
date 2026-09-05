package decompengine.oracle.behavior

import decompengine.oracle.core.OracleArtifacts
import decompengine.oracle.fulltree.StableControlFile
import java.nio.file.Files
import java.nio.file.LinkOption
import java.nio.file.Path
import java.nio.file.StandardCopyOption
import java.nio.file.attribute.PosixFilePermissions
import java.time.Duration
import java.util.Comparator

internal object LlvmBehaviorHostedRetainedToolChecks {
    data class Toolchain(val compiler: Path, val linker: Path)

    fun availableToolchain(): Toolchain? = listOf(
        Toolchain(Path.of("/usr/lib/llvm/22/bin/clang-22"), Path.of("/usr/lib/llvm/22/bin/lld")),
        Toolchain(Path.of("/usr/lib/llvm-22/bin/clang"), Path.of("/usr/lib/llvm-22/bin/lld")),
    ).firstOrNull { toolchain ->
        listOf(toolchain.compiler, toolchain.linker).all { path ->
            Files.isRegularFile(path, LinkOption.NOFOLLOW_LINKS) &&
                !Files.isSymbolicLink(path) && Files.isExecutable(path)
        }
    }

    fun requireToolchain(available: Toolchain? = availableToolchain()): Toolchain =
        checkNotNull(available) { "required retained-tool hostile regressions need the fixed LLVM 22 toolchain" }

    fun outsideHeaderRejected() = withScratch("hosted-unbound-header-") { root ->
        val outside = root.resolve("outside-candidate.h")
        val marker = "DECOMP_UNBOUND_HEADER_WAS_CONSUMED"
        Files.writeString(outside, "#error $marker\n")
        val first = root.resolve("source-one")
        val second = root.resolve("source-two")
        listOf(first, second).forEach { candidate ->
            Files.createDirectories(candidate.resolve("src"))
            Files.createDirectories(candidate.resolve("include"))
            Files.createDirectories(candidate.resolve("reports"))
            Files.writeString(candidate.resolve("Makefile"), "all:\n\tfalse\n")
            Files.writeString(candidate.resolve("reports/build_contract.json"), "{}\n")
            Files.writeString(
                candidate.resolve("src/main.c"),
                "#include <stdio.h>\n#define OUTSIDE_HEADER \"$outside\"\n" +
                    "#include OUTSIDE_HEADER\nint main(void) { return 0; }\n",
            )
        }
        val failure = try {
            LlvmBehaviorHostedCleanBuildV2TestSupport.assess(first, second)
            error("hosted compiler accepted an unbound macro-computed header")
        } catch (caught: LlvmBehaviorHostedCleanBuildV2Exception) {
            caught
        }
        val diagnostic = failure.message.orEmpty()
        check(diagnostic.contains("file not found") && diagnostic.contains(outside.fileName.toString())) {
            "unbound header did not fail at lookup: $diagnostic"
        }
        check(!diagnostic.contains(marker)) { "hosted compiler consumed unbound header contents" }
    }

    fun executableReplacement(toolchain: Toolchain) = withScratch("hosted-retained-tool-swap-") { root ->
        listOf(toolchain.compiler to false, toolchain.linker to true).forEach { (tool, linker) ->
            val selected = root.resolve(if (linker) "selected-lld" else "selected-clang")
            val replacement = root.resolve(if (linker) "hostile-lld" else "hostile-clang")
            Files.copy(tool, selected)
            Files.copy(Path.of("/usr/bin/false"), replacement)
            Files.setPosixFilePermissions(selected, PosixFilePermissions.fromString("r-x------"))
            Files.setPosixFilePermissions(replacement, PosixFilePermissions.fromString("r-x------"))
            val retained = snapshot(selected, true)
            val directory = HostedNativeExecution.open(root, "hostile tool working directory")
            try {
                val arguments = if (linker) listOf("-flavor", "gnu", "--version")
                else listOf("--no-default-config", "--version")
                val before = run(retained, arguments, directory, linker = linker)
                requireSuccess(before)
                check(before.stdout.toString(Charsets.UTF_8).contains(if (linker) "LLD" else "clang version"))
                Files.move(replacement, selected, StandardCopyOption.ATOMIC_MOVE, StandardCopyOption.REPLACE_EXISTING)
                check(OracleArtifacts.sha256(Files.readAllBytes(selected)) != retained.sha256)
                val after = run(retained, arguments, directory, linker = linker)
                requireSuccess(after)
                check(before.stdout.contentEquals(after.stdout)) { "tool replacement changed retained version output" }
                check(before.stderr.contentEquals(after.stderr)) { "tool replacement changed retained diagnostics" }
            } finally {
                directory.close()
                retained.close()
            }
        }
    }

    fun sourceAndHeaderReplacement(toolchain: Toolchain) = withScratch("hosted-retained-input-swap-") { root ->
        val selectedSource = root.resolve("selected-main.c")
        val selectedHeader = root.resolve("selected-value.h")
        val hostileSource = root.resolve("hostile-main.c")
        val hostileHeader = root.resolve("hostile-value.h")
        Files.writeString(selectedSource, "#include \"value.h\"\nint retained_value(void) { return VALUE; }\n")
        Files.writeString(selectedHeader, "#define VALUE 17\n")
        Files.writeString(hostileSource, "#error hostile source substitution\n")
        Files.writeString(hostileHeader, "#error hostile header substitution\n")
        val retained = ArrayList<HostedNativeExecution.RetainedFile>()
        val directory = HostedNativeExecution.open(root, "hostile compiler-input working directory")
        try {
            val compiler = snapshot(toolchain.compiler, true).also(retained::add)
            val source = snapshot(selectedSource, false).also(retained::add)
            val header = snapshot(selectedHeader, false).also(retained::add)
            val sourceCapability = source.capabilityPath("hostile-test source")
            val headerCapability = header.capabilityPath("hostile-test header")
            val overlay = HostedNativeExecution.snapshot(
                """{"version":0,"case-sensitive":true,"use-external-names":false,"redirecting-with":"redirect-only","roots":[{"type":"file","name":"/decomp-candidate/src/main.c","use-external-name":false,"external-contents":"$sourceCapability"},{"type":"file","name":"/decomp-candidate/include/value.h","use-external-name":false,"external-contents":"$headerCapability"}]}""".toByteArray(Charsets.UTF_8),
                false,
                "hostile-test sealed overlay",
            ).also(retained::add)
            Files.move(hostileSource, selectedSource, StandardCopyOption.ATOMIC_MOVE, StandardCopyOption.REPLACE_EXISTING)
            Files.move(hostileHeader, selectedHeader, StandardCopyOption.ATOMIC_MOVE, StandardCopyOption.REPLACE_EXISTING)
            check(OracleArtifacts.sha256(Files.readAllBytes(selectedSource)) != source.sha256)
            check(OracleArtifacts.sha256(Files.readAllBytes(selectedHeader)) != header.sha256)
            val result = run(
                compiler,
                listOf(
                    "--no-default-config",
                    "--target=x86_64-pc-linux-gnu",
                    "-fintegrated-cc1",
                    "-fintegrated-as",
                    "-nostdinc",
                    "-ivfsoverlay",
                    overlay.capabilityPath("hostile-test overlay"),
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
                directory,
                standardInput = source,
            )
            requireElf(result)
        } finally {
            directory.close()
            retained.asReversed().forEach { it.close() }
        }
    }

    fun objectReplacement(toolchain: Toolchain) = withScratch("hosted-retained-object-swap-") { root ->
        val retained = ArrayList<HostedNativeExecution.RetainedFile>()
        val directory = HostedNativeExecution.open(root, "hostile object working directory")
        try {
            val compiler = snapshot(toolchain.compiler, true).also(retained::add)
            val query = run(
                compiler,
                listOf("--no-default-config", "--target=x86_64-pc-linux-gnu", "--print-file-name=crti.o"),
                directory,
            )
            requireSuccess(query)
            val crti = Path.of(query.stdout.toString(Charsets.UTF_8).trim()).toRealPath()
            val selected = root.resolve("selected-object.o")
            val hostile = root.resolve("hostile-object.o")
            Files.copy(crti, selected)
            Files.writeString(hostile, "not an ELF object\n")
            val retainedObject = snapshot(selected, false).also(retained::add)
            val linker = snapshot(toolchain.linker, true).also(retained::add)
            Files.move(hostile, selected, StandardCopyOption.ATOMIC_MOVE, StandardCopyOption.REPLACE_EXISTING)
            check(OracleArtifacts.sha256(Files.readAllBytes(selected)) != retainedObject.sha256)
            val result = run(
                linker,
                listOf(
                    "-flavor", "gnu", "-r", "-o", "-",
                    retainedObject.capabilityPath("hostile-test object"),
                ),
                directory,
                linker = true,
            )
            requireElf(result)
        } finally {
            directory.close()
            retained.asReversed().forEach { it.close() }
        }
    }

    private fun snapshot(path: Path, executable: Boolean): HostedNativeExecution.RetainedFile =
        StableControlFile.open(path, 512L * 1024L * 1024L, "hostile-test snapshot").use { guard ->
            HostedNativeExecution.snapshot(
                guard,
                guard.size,
                guard.sha256(label = "hostile-test snapshot"),
                executable,
                "hostile-test snapshot",
            )
        }

    private fun run(
        executable: HostedNativeExecution.RetainedFile,
        arguments: List<String>,
        directory: HostedNativeExecution.PinnedDirectory,
        standardInput: HostedNativeExecution.RetainedFile? = null,
        linker: Boolean = false,
    ): HostedNativeExecution.Result = if (linker) {
        check(standardInput == null)
        HostedNativeExecution.runLld(
            executable, arguments, ENVIRONMENT, directory, COMMAND_TIMEOUT, MAXIMUM_OUTPUT_BYTES,
            CLEANUP_TIMEOUT, "hostile-test retained LLD",
        )
    } else {
        HostedNativeExecution.runClang(
            executable, standardInput, arguments, ENVIRONMENT, directory, COMMAND_TIMEOUT,
            MAXIMUM_OUTPUT_BYTES, CLEANUP_TIMEOUT, "hostile-test retained Clang",
        )
    }

    private fun requireSuccess(result: HostedNativeExecution.Result) {
        check(result.exitCode == 0) { "retained-tool hostile check failed: ${result.stderr.toString(Charsets.UTF_8)}" }
        check(result.stderr.isEmpty()) { "retained-tool hostile check emitted diagnostics" }
    }

    private fun requireElf(result: HostedNativeExecution.Result) {
        requireSuccess(result)
        val bytes = result.stdout
        check(bytes.size >= 4 && bytes.copyOfRange(0, 4).contentEquals(ELF_MAGIC)) {
            "retained-tool hostile check did not produce ELF bytes"
        }
    }

    private fun withScratch(prefix: String, action: (Path) -> Unit) {
        val root = Files.createTempDirectory(prefix).toAbsolutePath().normalize()
        Files.setPosixFilePermissions(root, PosixFilePermissions.fromString("rwx------"))
        try {
            action(root)
        } finally {
            Files.walk(root).use { paths ->
                paths.sorted(Comparator.reverseOrder()).forEach(Files::deleteIfExists)
            }
        }
    }

    private val ENVIRONMENT = mapOf("LC_ALL" to "C", "TZ" to "UTC")
    private val COMMAND_TIMEOUT = Duration.ofSeconds(5)
    private val CLEANUP_TIMEOUT = Duration.ofSeconds(2)
    private const val MAXIMUM_OUTPUT_BYTES = 1024 * 1024
    private val ELF_MAGIC = byteArrayOf(0x7f, 'E'.code.toByte(), 'L'.code.toByte(), 'F'.code.toByte())
}
