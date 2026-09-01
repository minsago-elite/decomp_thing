package decompengine.oracle.behavior

import decompengine.oracle.core.OracleArtifacts
import java.nio.file.Files
import java.nio.file.LinkOption
import java.nio.file.Path
import java.nio.file.attribute.PosixFilePermissions
import java.util.Comparator
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
            assertTrue(assessment.linkPlanInputCount >= assessment.sourceCount)
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
            "#include \"value.h\"\nint main(void) { return value() == 17 ? 0 : 1; }\n",
        )
        Files.writeString(
            root.resolve("reports/build_contract.json"),
            "{\"command\":[\"/bin/sh\",\"-c\",\"touch ${marker.toAbsolutePath().normalize()}\"]}\n",
        )
    }

    private fun localClangToolchainOrNull(): LocalToolchain? {
        val roots = buildList {
            val llvm = Path.of("/usr/lib/llvm")
            if (Files.isDirectory(llvm, LinkOption.NOFOLLOW_LINKS)) {
                Files.list(llvm).use { versions -> addAll(versions.sorted(Comparator.reverseOrder()).toList()) }
            }
            add(Path.of("/usr/local/swift/usr"))
        }
        roots.forEach { root ->
            val bin = root.resolve("bin")
            if (!Files.isDirectory(bin, LinkOption.NOFOLLOW_LINKS)) return@forEach
            val linker = bin.resolve("lld")
            if (!isRegularExecutable(linker)) return@forEach
            val compiler = Files.list(bin).use { entries ->
                entries.filter { candidate ->
                    candidate.fileName.toString().matches(Regex("clang-[0-9]+")) && isRegularExecutable(candidate)
                }.sorted().findFirst().orElse(null)
            } ?: return@forEach
            return LocalToolchain(compiler.toAbsolutePath().normalize(), linker.toAbsolutePath().normalize())
        }
        return null
    }

    private fun isRegularExecutable(path: Path): Boolean =
        Files.isRegularFile(path, LinkOption.NOFOLLOW_LINKS) && !Files.isSymbolicLink(path) && Files.isExecutable(path)

    private fun deleteTree(root: Path) {
        if (!Files.exists(root, LinkOption.NOFOLLOW_LINKS)) return
        Files.walk(root).use { paths -> paths.sorted(Comparator.reverseOrder()).forEach(Files::deleteIfExists) }
    }

    private data class LocalToolchain(val compiler: Path, val linker: Path)
}
