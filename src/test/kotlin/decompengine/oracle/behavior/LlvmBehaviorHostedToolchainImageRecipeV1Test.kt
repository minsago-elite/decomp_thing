package decompengine.oracle.behavior

import decompengine.oracle.core.OracleArtifacts
import decompengine.oracle.provenance.LlvmToolchainReproductionVerification
import java.io.ByteArrayInputStream
import java.io.ByteArrayOutputStream
import java.io.OutputStream
import java.lang.reflect.InvocationTargetException
import java.lang.reflect.Modifier
import java.nio.file.Files
import java.nio.file.Path
import java.nio.file.StandardCopyOption
import java.nio.file.attribute.FileTime
import java.nio.file.attribute.PosixFilePermissions
import kotlin.io.path.createTempDirectory
import kotlin.test.Test
import kotlin.test.assertContentEquals
import kotlin.test.assertEquals
import kotlin.test.assertFailsWith
import kotlin.test.assertFalse
import kotlin.test.assertTrue
import org.apache.commons.compress.archivers.tar.TarArchiveInputStream

class LlvmBehaviorHostedToolchainImageRecipeV1Test {
    @Test
    fun `sealed owner retains only the exact reviewed recipe`() = withFixture { fixture ->
        val owner = fixture.open()
        try {
            assertEquals(REPRODUCTION_LOCK_SHA256, owner.reproductionLockSha256)
            assertEquals(BUILD_RECORD_SHA256, owner.buildRecordSha256)
            assertEquals(DOCKERFILE_SHA256, owner.dockerfileSha256)
            assertEquals(Files.size(CHECKED_DOCKERFILE), owner.dockerfileBytes)
            assertEquals(
                "ubuntu@sha256:33ceb71981b602c1a7443a53469e4dba065f7503eab3078a2d7a57a2ab987517",
                owner.baseImageReference,
            )
            assertEquals("linux/amd64", owner.platform)
            assertEquals("1779182222", owner.sourceDateEpoch)
            assertEquals(3_584L, owner.deterministicTarBytes)
            assertEquals(DETERMINISTIC_TAR_SHA256, owner.deterministicTarSha256)

            val emittedDockerfile = ByteArrayOutputStream()
            owner.writeDockerfileTo(emittedDockerfile)
            assertContentEquals(Files.readAllBytes(CHECKED_DOCKERFILE), emittedDockerfile.toByteArray())

            val emittedTar = ByteArrayOutputStream()
            owner.writeDeterministicTarTo(emittedTar)
            assertEquals(owner.deterministicTarBytes, emittedTar.size().toLong())
            assertEquals(owner.deterministicTarSha256, OracleArtifacts.sha256(emittedTar.toByteArray()))
            TarArchiveInputStream(ByteArrayInputStream(emittedTar.toByteArray())).use { tar ->
                val entry = checkNotNull(tar.nextEntry)
                assertEquals("Dockerfile", entry.name)
                assertEquals(292, entry.mode)
                assertEquals(0L, entry.longUserId)
                assertEquals(0L, entry.longGroupId)
                assertEquals(1_779_182_222L, entry.modTime.time / 1000L)
                assertTrue(entry.isCheckSumOK)
                assertContentEquals(Files.readAllBytes(CHECKED_DOCKERFILE), tar.readNBytes(entry.size.toInt()))
                assertEquals(null, tar.nextEntry)
            }
            owner.requireCurrent()
        } finally {
            owner.close()
        }

        assertFailsWith<IllegalStateException> { owner.requireCurrent() }
        val ownerSurface = LlvmBehaviorHostedToolchainImageRecipeV1Owner::class.java.declaredMethods
            .filterNot { it.isSynthetic }
        val forbiddenAuthorityMethods = setOf(
            "getImageId",
            "getImageAuthority",
            "getBuildAuthority",
            "getImageBuildAuthority",
            "mint",
        )
        assertTrue(ownerSurface.none { it.name in forbiddenAuthorityMethods })
        assertFalse(
            ownerSurface.any { method ->
                method.returnType == Boolean::class.java || method.returnType == Boolean::class.javaObjectType
            },
        )
    }

    @Test
    fun `production constructors accept only the three raw recipe paths`() {
        val factory = LlvmBehaviorHostedToolchainImageRecipeV1::class.java
        val open = factory.declaredMethods.single { method -> method.name == "open" && !method.isSynthetic }
        assertEquals(List(3) { Path::class.java }, open.parameterTypes.toList())
        assertEquals(LlvmBehaviorHostedToolchainImageRecipeV1Owner::class.java, open.returnType)
        assertTrue(factory.declaredConstructors.all { Modifier.isPrivate(it.modifiers) })
        val leaseConsume = factory.declaredMethods.single {
            it.name == "consumeImageBuildLeaseBinding"
        }
        assertTrue(Modifier.isPrivate(leaseConsume.modifiers))
        val retainedBinding = factory.declaredClasses.single {
            LlvmBehaviorHostedToolchainImageRecipeV1LeaseBinding::class.java.isAssignableFrom(it)
        }
        assertTrue(retainedBinding.declaredConstructors.all { Modifier.isPrivate(it.modifiers) })
        assertTrue(
            Modifier.isPrivate(retainedBinding.declaredMethods.single { it.name == "consume" }.modifiers),
        )

        val owner = LlvmBehaviorHostedToolchainImageRecipeV1Owner::class.java
        assertTrue(owner.isSealed)
        assertTrue(owner.declaredConstructors.isEmpty())
        val implementation = owner.permittedSubclasses.single()
        assertTrue(Modifier.isPrivate(implementation.modifiers))
        assertEquals(List(3) { Path::class.java }, implementation.declaredConstructors.single().parameterTypes.toList())
        assertEquals(
            setOf(
                "close",
                "getBaseImageReference",
                "getBuildRecordSha256",
                "getDeterministicTarBytes",
                "getDeterministicTarSha256",
                "getDockerfileBytes",
                "getDockerfileSha256",
                "getPlatform",
                "getReproductionLockSha256",
                "getSourceDateEpoch",
                "requireCurrent",
                "transferToImageBuildLease",
                "writeDeterministicTarTo",
                "writeDockerfileTo",
            ),
            owner.declaredMethods.filterNot { it.isSynthetic }.map { it.name }.toSet(),
        )

        val authorityMethods = owner.declaredMethods + factory.declaredMethods + implementation.declaredMethods
        assertTrue(
            authorityMethods.none { method ->
                method.returnType == LlvmToolchainReproductionVerification::class.java ||
                    method.parameterTypes.any { it == LlvmToolchainReproductionVerification::class.java }
            },
        )
        assertTrue(
            implementation.declaredConstructors.all { constructor ->
                constructor.parameterTypes.none { it == String::class.java }
            },
        )
    }

    @Test
    fun `recipe ownership transfers once and inert aliases cannot close the retained recipe`() =
        withFixture { fixture ->
            val owner = fixture.open()
            val binding = owner.transferToImageBuildLease()

            assertFailsWith<IllegalStateException> { owner.requireCurrent() }
            assertFailsWith<IllegalStateException> { owner.dockerfileSha256 }
            assertFailsWith<IllegalStateException> { owner.writeDockerfileTo(ByteArrayOutputStream()) }
            assertFailsWith<IllegalStateException> { owner.transferToImageBuildLease() }
            owner.close()
            owner.close()

            val retained = consumeRecipeBindingForPrivateLeaseTest(binding)
            binding.close()
            binding.close()
            retained.requireCurrent()
            val emitted = ByteArrayOutputStream()
            retained.writeDeterministicTarTo(emitted)
            assertEquals(DETERMINISTIC_TAR_SHA256, OracleArtifacts.sha256(emitted.toByteArray()))
            retained.close()
            retained.close()
            assertFailsWith<IllegalStateException> { retained.requireCurrent() }
            assertFailsWith<IllegalStateException> {
                consumeRecipeBindingForPrivateLeaseTest(binding)
            }

            assertTrue(LlvmBehaviorHostedToolchainImageRecipeV1LeaseBinding::class.java.isSealed)
            assertTrue(LlvmBehaviorHostedToolchainImageRecipeV1LeaseOwner::class.java.isSealed)
            assertEquals(
                setOf("close"),
                LlvmBehaviorHostedToolchainImageRecipeV1LeaseBinding::class.java.declaredMethods
                    .filterNot { it.isSynthetic }
                    .map { it.name }
                    .toSet(),
            )
        }

    @Test
    fun `mutated cross-named symlinked and writable recipe inputs fail closed`() {
        listOf(
            "reproduction lock" to { fixture: RecipeFixture -> mutate(fixture.reproductionLock) },
            "build record" to { fixture: RecipeFixture -> mutate(fixture.buildRecord) },
            "Dockerfile" to { fixture: RecipeFixture -> mutate(fixture.dockerfile) },
        ).forEach { (label, mutation) ->
            withFixture { fixture ->
                mutation(fixture)
                assertFailsWith<LlvmBehaviorHostedToolchainImageRecipeV1Exception>(label) { fixture.open() }
            }
        }

        withFixture { fixture ->
            val wrongName = fixture.root.resolve("caller-selected.Dockerfile")
            Files.move(fixture.dockerfile, wrongName)
            assertFailsWith<LlvmBehaviorHostedToolchainImageRecipeV1Exception> {
                LlvmBehaviorHostedToolchainImageRecipeV1.open(
                    fixture.reproductionLock,
                    fixture.buildRecord,
                    wrongName,
                )
            }
        }
        withFixture { fixture ->
            val hardLink = fixture.root.resolve("Dockerfile-hard-link")
            Files.createLink(hardLink, fixture.dockerfile)
            assertFailsWith<LlvmBehaviorHostedToolchainImageRecipeV1Exception> { fixture.open() }
        }
        withFixture { fixture ->
            val real = fixture.root.resolve("real-build-toolchain.Dockerfile")
            Files.move(fixture.dockerfile, real)
            Files.createSymbolicLink(fixture.dockerfile, real.fileName)
            assertFailsWith<LlvmBehaviorHostedToolchainImageRecipeV1Exception> { fixture.open() }
        }
        withFixture { fixture ->
            Files.setPosixFilePermissions(fixture.root, PosixFilePermissions.fromString("rwxrwx---"))
            assertFailsWith<LlvmBehaviorHostedToolchainImageRecipeV1Exception> { fixture.open() }
        }
    }

    @Test
    fun `relative and non-normalized recipe paths are rejected instead of canonicalized`() {
        assertFailsWith<LlvmBehaviorHostedToolchainImageRecipeV1Exception> {
            LlvmBehaviorHostedToolchainImageRecipeV1.open(
                Path.of("oracle/llvm/22.1.6/toolchain-reproduction.json"),
                Path.of("oracle/llvm/22.1.6/build-record.json"),
                Path.of("oracle/llvm/22.1.6/build-toolchain.Dockerfile"),
            )
        }
        withFixture { fixture ->
            val nonNormalizedLock = fixture.root.resolve("unused").resolve("..").resolve(
                fixture.reproductionLock.fileName,
            )
            assertTrue(nonNormalizedLock.normalize() != nonNormalizedLock)
            assertFailsWith<LlvmBehaviorHostedToolchainImageRecipeV1Exception> {
                LlvmBehaviorHostedToolchainImageRecipeV1.open(
                    nonNormalizedLock,
                    fixture.buildRecord,
                    fixture.dockerfile,
                )
            }
        }
    }

    @Test
    fun `retained drift poisons rechecks and Dockerfile emission`() {
        withFixture { fixture ->
            val owner = fixture.open()
            try {
                Files.createLink(fixture.root.resolve("retained-Dockerfile-hard-link"), fixture.dockerfile)
                val failure = assertFailsWith<LlvmBehaviorHostedToolchainImageRecipeV1Exception> {
                    owner.requireCurrent()
                }
                assertTrue(failure.message.orEmpty().contains("single-link"))
                assertFailsWith<LlvmBehaviorHostedToolchainImageRecipeV1Exception> { owner.requireCurrent() }
            } finally {
                owner.close()
            }
        }

        withFixture { fixture ->
            val owner = fixture.open()
            val original = Files.readAllBytes(fixture.dockerfile)
            try {
                mutate(fixture.dockerfile)
                assertFailsWith<LlvmBehaviorHostedToolchainImageRecipeV1Exception> { owner.requireCurrent() }
                Files.write(fixture.dockerfile, original)
                val poisoned = assertFailsWith<LlvmBehaviorHostedToolchainImageRecipeV1Exception> {
                    owner.requireCurrent()
                }
                assertTrue(poisoned.message.orEmpty().contains("poisoned"))
            } finally {
                owner.close()
            }
        }

        withFixture { fixture ->
            val owner = fixture.open()
            try {
                val mutatingOutput = object : OutputStream() {
                    private var changed = false

                    override fun write(value: Int) {
                        if (!changed) {
                            changed = true
                            mutate(fixture.buildRecord)
                        }
                    }

                    override fun write(bytes: ByteArray, offset: Int, length: Int) {
                        if (!changed) {
                            changed = true
                            mutate(fixture.buildRecord)
                        }
                    }
                }
                assertFailsWith<LlvmBehaviorHostedToolchainImageRecipeV1Exception> {
                    owner.writeDockerfileTo(mutatingOutput)
                }
                assertFailsWith<LlvmBehaviorHostedToolchainImageRecipeV1Exception> { owner.requireCurrent() }
            } finally {
                owner.close()
            }
        }
        withFixture { fixture ->
            val owner = fixture.open()
            val original = Files.readAllBytes(fixture.dockerfile)
            val originalModified = Files.getLastModifiedTime(fixture.dockerfile)
            try {
                var writeCount = 0
                val mutatingAndRestoringOutput = object : OutputStream() {
                    override fun write(value: Int) = error("single-byte write is not expected")

                    override fun write(bytes: ByteArray, offset: Int, length: Int) {
                        writeCount += 1
                        when (writeCount) {
                            1 -> {
                                val changed = original.copyOf()
                                changed[700] = (changed[700].toInt() xor 1).toByte()
                                Files.write(fixture.dockerfile, changed)
                                restoreModifiedTime(fixture.dockerfile, originalModified)
                            }
                            2 -> {
                                Files.write(fixture.dockerfile, original)
                                restoreModifiedTime(fixture.dockerfile, originalModified)
                            }
                        }
                    }
                }
                val failure = assertFailsWith<LlvmBehaviorHostedToolchainImageRecipeV1Exception> {
                    owner.writeDockerfileTo(mutatingAndRestoringOutput)
                }
                assertTrue(writeCount >= 2)
                assertTrue(failure.message.orEmpty().contains("emitted"))
                assertContentEquals(original, Files.readAllBytes(fixture.dockerfile))
            } finally {
                owner.close()
            }
        }
    }

    private fun withFixture(action: (RecipeFixture) -> Unit) {
        val root = createTempDirectory("llvm-hosted-toolchain-recipe-")
        Files.setPosixFilePermissions(root, PosixFilePermissions.fromString("rwx------"))
        try {
            action(RecipeFixture(root))
        } finally {
            root.toFile().deleteRecursively()
        }
    }
}

private fun consumeRecipeBindingForPrivateLeaseTest(
    binding: LlvmBehaviorHostedToolchainImageRecipeV1LeaseBinding,
): LlvmBehaviorHostedToolchainImageRecipeV1LeaseOwner {
    val method = LlvmBehaviorHostedToolchainImageRecipeV1::class.java.declaredMethods.single {
        it.name == "consumeImageBuildLeaseBinding"
    }
    assertTrue(Modifier.isPrivate(method.modifiers))
    assertTrue(method.trySetAccessible())
    return try {
        method.invoke(LlvmBehaviorHostedToolchainImageRecipeV1, binding)
            as LlvmBehaviorHostedToolchainImageRecipeV1LeaseOwner
    } catch (failure: InvocationTargetException) {
        throw failure.targetException
    }
}

private fun restoreModifiedTime(path: Path, modified: FileTime) {
    Files.setLastModifiedTime(path, modified)
}

private class RecipeFixture(val root: Path) {
    val reproductionLock: Path = copyChecked("toolchain-reproduction.json")
    val buildRecord: Path = copyChecked("build-record.json")
    val dockerfile: Path = copyChecked("build-toolchain.Dockerfile")

    fun open(): LlvmBehaviorHostedToolchainImageRecipeV1Owner =
        LlvmBehaviorHostedToolchainImageRecipeV1.open(reproductionLock, buildRecord, dockerfile)

    private fun copyChecked(name: String): Path = root.resolve(name).also { destination ->
        Files.copy(CHECKED_ROOT.resolve(name), destination, StandardCopyOption.COPY_ATTRIBUTES)
    }
}

private fun mutate(path: Path) {
    val bytes = Files.readAllBytes(path)
    bytes[bytes.lastIndex] = (bytes.last().toInt() xor 1).toByte()
    Files.write(path, bytes)
}

private val CHECKED_ROOT = Path.of("oracle/llvm/22.1.6")
private val CHECKED_DOCKERFILE = CHECKED_ROOT.resolve("build-toolchain.Dockerfile")
private const val REPRODUCTION_LOCK_SHA256 =
    "14a383bc5792b7ace786cbbd8964383469c1ffa5a4bb06a99e38c71518643f4f"
private const val BUILD_RECORD_SHA256 =
    "415afaf3554f954aed4442f0fa3c83ecc7e9f1fe0ddf68fb4c39e9231ece9005"
private const val DOCKERFILE_SHA256 =
    "97e2d13915806242c14489b5a8b1417bd0478f3a11dc05e76888ba2ab43b1291"
private const val DETERMINISTIC_TAR_SHA256 =
    "c47e1f8a2c70576c6aad1af2e68865c3d458da7288ea9ecc21dde4c3e364f20e"
