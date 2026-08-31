package decompengine.oracle.provenance

import java.io.InputStream
import java.net.http.HttpHeaders
import java.nio.ByteBuffer
import java.nio.channels.WritableByteChannel
import java.nio.file.Files
import java.nio.file.LinkOption
import java.nio.file.Path
import java.nio.file.StandardCopyOption
import java.nio.file.attribute.PosixFilePermissions
import java.util.Base64
import kotlin.io.path.createTempDirectory
import kotlin.test.Test
import kotlin.test.assertContentEquals
import kotlin.test.assertEquals
import kotlin.test.assertFailsWith
import kotlin.test.assertFalse
import kotlin.test.assertTrue
import org.junit.jupiter.api.Assumptions.assumeTrue

class LlvmSourceArchiveMaterializerTest {
    @Test
    fun `CLI requires exact explicit options and reports failures without materializing`() {
        val invalidArguments = listOf(
            emptyArray<String>(),
            arrayOf("--lock", "lock.json"),
            arrayOf("--output", "output"),
            arrayOf("--lock"),
            arrayOf("--lock", "", "--output", "output"),
            arrayOf("--lock", "one", "--lock", "two", "--output", "output"),
            arrayOf("--lock", "lock", "--output", "one", "--output", "two"),
            arrayOf("--lock", "lock", "--output", "output", "positional"),
            arrayOf("--unknown", "value", "--lock", "lock", "--output", "output"),
        )
        invalidArguments.forEach { arguments ->
            var invoked = false
            val stdout = mutableListOf<String>()
            val stderr = mutableListOf<String>()
            val status = LlvmSourceArchiveFetcherCli.run(
                arguments,
                materialize = { _, _ ->
                    invoked = true
                    error("invalid CLI arguments must not materialize")
                },
                stdout = stdout::add,
                stderr = stderr::add,
            )
            assertEquals(1, status, arguments.contentToString())
            assertFalse(invoked, arguments.contentToString())
            assertTrue(stdout.isEmpty(), arguments.contentToString())
            assertEquals(1, stderr.size, arguments.contentToString())
            assertTrue(stderr.single().startsWith("LLVM source archive fetch failed: "))
        }

        val stderr = mutableListOf<String>()
        val status = LlvmSourceArchiveFetcherCli.run(
            arrayOf("--lock", "lock", "--output", "output"),
            materialize = { _, _ -> throw InjectedSourceFailure() },
            stdout = { error("failed materialization must not write standard output") },
            stderr = stderr::add,
        )
        assertEquals(1, status)
        assertEquals(listOf("LLVM source archive fetch failed: injected source failure"), stderr)
    }

    @Test
    fun `CLI forwards explicit paths and emits stable authenticated output`() = withFixture { fixture ->
        val output = fixture.root.resolve("cli-output")
        val stdout = mutableListOf<String>()
        val stderr = mutableListOf<String>()
        var result: AuthenticatedLlvmSourceArchive? = null

        val status = LlvmSourceArchiveFetcherCli.run(
            arrayOf("--lock", fixture.lockPath.toString(), "--output", output.toString()),
            materialize = { lock, selectedOutput ->
                assertEquals(fixture.lockPath, lock)
                assertEquals(output, selectedOutput)
                fixture.materializer(SourcePairTransport(fixture.signatureBytes, fixture.archiveBytes))
                    .materialize(lock, selectedOutput)
                    .also { result = it }
            },
            stdout = stdout::add,
            stderr = stderr::add,
        )

        assertEquals(0, status)
        assertTrue(stderr.isEmpty())
        assertEquals(LlvmSourceArchiveFetcherCli.successMessages(requireNotNull(result)), stdout)
        assertTrue(Files.isRegularFile(requireNotNull(result).archive.path))
        assertTrue(Files.isRegularFile(requireNotNull(result).detachedSignature.path))
    }

    @Test
    fun `fresh and cached archives receive identical signature and archive phases`() = withFixture { fixture ->
        val output = privateDirectory(fixture.root.resolve("output"))
        var signatures = 0
        var scans = 0
        val firstTransport = SourcePairTransport(fixture.signatureBytes, fixture.archiveBytes)
        val first = fixture.materializer(
            firstTransport,
            signatureAuthority = fixture.signatureAuthority { signatures++ },
            archiveAuthority = fixture.archiveAuthority { scans++ },
        ).materialize(fixture.lockPath, output)

        val cachedTransport = SourcePairTransport()
        val second = fixture.materializer(
            cachedTransport,
            signatureAuthority = fixture.signatureAuthority { signatures++ },
            archiveAuthority = fixture.archiveAuthority { scans++ },
        ).materialize(fixture.lockPath, output)

        assertEquals(2, signatures)
        assertEquals(2, scans)
        assertEquals(2, firstTransport.requests)
        assertEquals(0, cachedTransport.requests)
        assertEquals(first.archive, second.archive)
        assertEquals(first.detachedSignature, second.detachedSignature)
        assertEquals(fixture.locked().archiveContents.size, second.archiveSummary.selected.size)
        assertEquals(
            PosixFilePermissions.fromString("r--------"),
            Files.getPosixFilePermissions(second.archive.path, LinkOption.NOFOLLOW_LINKS),
        )
        assertEquals(
            PosixFilePermissions.fromString("r--------"),
            Files.getPosixFilePermissions(second.detachedSignature.path, LinkOption.NOFOLLOW_LINKS),
        )
    }

    @Test
    fun `archive callback failure leaves no fresh archive publication`() = withFixture { fixture ->
        val output = privateDirectory(fixture.root.resolve("output"))
        val materializer = fixture.materializer(
            SourcePairTransport(fixture.signatureBytes, fixture.archiveBytes),
            signatureAuthority = LlvmArchiveSignatureAuthority { _, _, _, _, _ -> throw InjectedSourceFailure() },
        )

        assertFailsWith<InjectedSourceFailure> { materializer.materialize(fixture.lockPath, output) }
        val locked = fixture.locked()
        assertFalse(Files.exists(output.resolve(locked.archive.fileName), LinkOption.NOFOLLOW_LINKS))
        assertTrue(Files.isRegularFile(output.resolve(locked.detachedSignature.fileName)))
    }

    @Test
    fun `detached signature mutation after selection refuses the archive download and publication`() =
        withFixture { fixture ->
            val output = privateDirectory(fixture.root.resolve("output"))
            val locked = fixture.locked()
            val signature = output.resolve(locked.detachedSignature.fileName)
            val mutation = fixture.signatureBytes.copyOf().also {
                it[it.lastIndex] = (it.last().toInt() xor 1).toByte()
            }
            val transport = SourcePairTransport(fixture.signatureBytes, fixture.archiveBytes)
            val materializer = fixture.materializer(
                transport,
                faultInjector = LlvmSourceArchiveMaterializationFaultInjector { point ->
                    if (point == LlvmSourceArchiveMaterializationPoint.AFTER_SIGNATURE_SELECTED) {
                        Files.setPosixFilePermissions(signature, PosixFilePermissions.fromString("rw-------"))
                        Files.write(signature, mutation)
                        Files.setPosixFilePermissions(signature, PosixFilePermissions.fromString("r--------"))
                    }
                },
            )

            assertFailsWith<ReleaseArtifactProvenanceException> {
                materializer.materialize(fixture.lockPath, output)
            }
            assertEquals(1, transport.requests, "archive bytes must not be requested after signature mutation")
            assertFalse(Files.exists(output.resolve(locked.archive.fileName), LinkOption.NOFOLLOW_LINKS))
            assertContentEquals(mutation, Files.readAllBytes(signature))
        }

    @Test
    fun `local key substitution after OpenPGP phase is rejected before archive publication`() = withFixture { fixture ->
        val output = privateDirectory(fixture.root.resolve("output"))
        val key = fixture.root.resolve("keys/douglas-yung-llvm-release.asc")
        val displaced = fixture.root.resolve("keys/displaced.asc")
        val materializer = fixture.materializer(
            SourcePairTransport(fixture.signatureBytes, fixture.archiveBytes),
            faultInjector = LlvmSourceArchiveMaterializationFaultInjector { point ->
                if (point == LlvmSourceArchiveMaterializationPoint.AFTER_ARCHIVE_SIGNATURE_VERIFIED) {
                    Files.move(key, displaced, StandardCopyOption.ATOMIC_MOVE)
                    Files.copy(displaced, key)
                }
            },
        )

        assertFailsWith<ReleaseArtifactProvenanceException> {
            materializer.materialize(fixture.lockPath, output)
        }
        assertFalse(Files.exists(output.resolve(fixture.locked().archive.fileName), LinkOption.NOFOLLOW_LINKS))
        assertTrue(Files.exists(displaced))
    }

    @Test
    fun `cached archive same-inode mutation fails its phase checkpoint`() = withFixture { fixture ->
        val output = privateDirectory(fixture.root.resolve("output"))
        fixture.materializer(SourcePairTransport(fixture.signatureBytes, fixture.archiveBytes))
            .materialize(fixture.lockPath, output)
        val archive = output.resolve(fixture.locked().archive.fileName)
        val mutation = fixture.archiveBytes.copyOf().also { it[it.lastIndex] = (it.last().toInt() xor 1).toByte() }
        var scans = 0
        val cachedTransport = SourcePairTransport()
        val materializer = fixture.materializer(
            cachedTransport,
            archiveAuthority = fixture.archiveAuthority { scans++ },
            faultInjector = LlvmSourceArchiveMaterializationFaultInjector { point ->
                if (point == LlvmSourceArchiveMaterializationPoint.AFTER_ARCHIVE_SIGNATURE_VERIFIED) {
                    Files.setPosixFilePermissions(archive, PosixFilePermissions.fromString("rw-------"))
                    Files.write(archive, mutation)
                    Files.setPosixFilePermissions(archive, PosixFilePermissions.fromString("r--------"))
                }
            },
        )

        assertFailsWith<ReleaseArtifactProvenanceException> {
            materializer.materialize(fixture.lockPath, output)
        }
        assertEquals(0, cachedTransport.requests)
        assertEquals(0, scans, "the first phase checkpoint must fail before TAR scanning")
        assertContentEquals(mutation, Files.readAllBytes(archive))
    }

    @Test
    fun `cached archive ABA cannot substitute bytes seen through the pinned descriptor`() = withFixture { fixture ->
        val output = privateDirectory(fixture.root.resolve("output"))
        fixture.materializer(SourcePairTransport(fixture.signatureBytes, fixture.archiveBytes))
            .materialize(fixture.lockPath, output)
        val archive = output.resolve(fixture.locked().archive.fileName)
        val displaced = output.resolve("displaced.tar.xz")
        val substitute = ByteArray(fixture.archiveBytes.size) { 0x5a }
        var observed = ByteArray(0)
        val abaAuthority = LlvmArchiveSignatureAuthority { _, _, input, expectedBytes, expectedSha256 ->
            Files.move(archive, displaced, StandardCopyOption.ATOMIC_MOVE)
            Files.write(archive, substitute)
            Files.setPosixFilePermissions(archive, PosixFilePermissions.fromString("r--------"))
            observed = input.readAllBytes()
            Files.delete(archive)
            Files.move(displaced, archive, StandardCopyOption.ATOMIC_MOVE)
            LlvmArchiveSignatureVerification(
                expectedBytes,
                expectedSha256,
                fixture.locked().signingFingerprint,
                1_779_316_752L,
            )
        }
        val cachedTransport = SourcePairTransport()

        fixture.materializer(cachedTransport, signatureAuthority = abaAuthority)
            .materialize(fixture.lockPath, output)

        assertEquals(0, cachedTransport.requests)
        assertContentEquals(fixture.archiveBytes, observed)
        assertFalse(observed.contentEquals(substitute))
        assertContentEquals(fixture.archiveBytes, Files.readAllBytes(archive))
    }

    @Test
    fun `marker substitution rejects the fresh archive before link`() = withFixture { fixture ->
        val output = privateDirectory(fixture.root.resolve("output"))
        val badArchiveAuthority = LlvmSourceArchiveAuthority { artifact, locked ->
            fixture.archiveAuthority().scan(artifact, locked).let { summary ->
                summary.copy(selected = summary.selected - summary.selected.keys.first())
            }
        }

        assertFailsWith<ReleaseArtifactProvenanceException> {
            fixture.materializer(
                SourcePairTransport(fixture.signatureBytes, fixture.archiveBytes),
                archiveAuthority = badArchiveAuthority,
            ).materialize(fixture.lockPath, output)
        }
        assertFalse(Files.exists(output.resolve(fixture.locked().archive.fileName), LinkOption.NOFOLLOW_LINKS))
    }

    @Test
    fun `optional CLI verifies the frozen archive and signature from a fresh local cache without network`() {
        val configuredArchive = System.getenv("DECOMP_LLVM_SOURCE_ARCHIVE")
            ?.takeIf(String::isNotBlank)
            ?.let(Path::of)
        assumeTrue(configuredArchive != null && Files.isRegularFile(configuredArchive), "set DECOMP_LLVM_SOURCE_ARCHIVE")
        val archive = requireNotNull(configuredArchive)
        val configuredSignature = System.getenv("DECOMP_LLVM_SOURCE_SIGNATURE")
            ?.takeIf(String::isNotBlank)
            ?.let(Path::of)
        val signatureBytes = if (configuredSignature != null && Files.isRegularFile(configuredSignature)) {
            Files.readAllBytes(configuredSignature)
        } else {
            Base64.getDecoder().decode(FROZEN_ARCHIVE_SIGNATURE_BASE64)
        }
        val root = privateDirectory(createTempDirectory("llvm-source-real-materializer-"))
        try {
            val output = privateDirectory(root.resolve("output"))
            val locked = LlvmSourceLockVerifier().verify(CHECKED_LOCK)
            val archiveTarget = output.resolve(locked.archive.fileName)
            val signatureTarget = output.resolve(locked.detachedSignature.fileName)
            Files.copy(archive, archiveTarget)
            Files.write(signatureTarget, signatureBytes)
            listOf(archiveTarget, signatureTarget).forEach {
                Files.setPosixFilePermissions(it, PosixFilePermissions.fromString("r--------"))
            }

            val stdout = mutableListOf<String>()
            val stderr = mutableListOf<String>()
            val status = LlvmSourceArchiveFetcherCli.run(
                arrayOf("--lock", CHECKED_LOCK.toString(), "--output", output.toString()),
                stdout = stdout::add,
                stderr = stderr::add,
            )

            assertEquals(0, status)
            assertTrue(stderr.isEmpty())
            assertEquals(3, stdout.size)
            assertTrue(stdout[0].contains("167043464 bytes, sha256 ${locked.archive.sha256}"))
            assertTrue(stdout[1].contains("119 bytes, sha256 ${locked.detachedSignature.sha256}"))
            assertEquals(
                "verified LLVM source archive structure: 184819 members, commit-PAX and 3 locked markers",
                stdout[2],
            )
        } finally {
            deleteTree(root)
        }
    }

    private fun withFixture(action: (SyntheticLlvmSourceFixture) -> Unit) {
        val root = privateDirectory(createTempDirectory("llvm-source-materializer-"))
        try {
            action(SyntheticLlvmSourceFixture(root))
        } finally {
            deleteTree(root)
        }
    }
}

private class SyntheticLlvmSourceFixture(val root: Path) {
    val lockPath: Path = root.resolve("source-lock.json")
    val archiveBytes = "synthetic descriptor-bound LLVM source archive\n".toByteArray()
    val signatureBytes: ByteArray = Base64.getDecoder().decode(FROZEN_ARCHIVE_SIGNATURE_BASE64)
    private val markerBytes: List<ByteArray>

    init {
        privateDirectory(root.resolve("keys"))
        privateDirectory(root.resolve("tag"))
        Files.copy(CHECKED_LOCK, lockPath)
        Files.copy(CHECKED_PROFILE.resolve("keys/douglas-yung-llvm-release.asc"), root.resolve("keys/douglas-yung-llvm-release.asc"))
        Files.copy(CHECKED_PROFILE.resolve("tag/llvmorg-22.1.6.payload"), root.resolve("tag/llvmorg-22.1.6.payload"))
        Files.copy(CHECKED_PROFILE.resolve("tag/llvmorg-22.1.6.sig"), root.resolve("tag/llvmorg-22.1.6.sig"))
        val actual = LlvmSourceLockVerifier().verify(lockPath)
        markerBytes = listOf(
            actual.archiveContents[0].text!!.toByteArray(),
            "synthetic root license\n".toByteArray(),
            "synthetic clang license\n".toByteArray(),
        )
    }

    fun locked(): LlvmSourceLockVerification = adjust(LlvmSourceLockVerifier().verify(lockPath))

    fun materializer(
        transport: SourcePairTransport,
        signatureAuthority: LlvmArchiveSignatureAuthority = signatureAuthority(),
        archiveAuthority: LlvmSourceArchiveAuthority = archiveAuthority(),
        faultInjector: LlvmSourceArchiveMaterializationFaultInjector? = null,
    ): LlvmSourceArchiveMaterializer = LlvmSourceArchiveMaterializer(
        downloader = BoundedHttpsDownloader(transport),
        lockAuthority = LlvmSourceLockAuthority { adjust(LlvmSourceLockVerifier().verify(it)) },
        signatureAuthority = signatureAuthority,
        archiveAuthority = archiveAuthority,
        faultInjector = faultInjector,
    )

    fun signatureAuthority(onVerify: () -> Unit = {}): LlvmArchiveSignatureAuthority =
        LlvmArchiveSignatureAuthority { _, signature, input, expectedBytes, expectedSha256 ->
            onVerify()
            assertContentEquals(signatureBytes, signature)
            assertContentEquals(archiveBytes, input.readAllBytes())
            LlvmArchiveSignatureVerification(
                expectedBytes,
                expectedSha256,
                locked().signingFingerprint,
                1_779_316_752L,
            )
        }

    fun archiveAuthority(onScan: () -> Unit = {}): LlvmSourceArchiveAuthority =
        LlvmSourceArchiveAuthority { artifact, locked ->
            onScan()
            val observed = artifact.withReadableChannel { channel ->
                ByteArray(archiveBytes.size).also { bytes ->
                    val destination = ByteBuffer.wrap(bytes)
                    while (destination.hasRemaining()) channel.read(destination)
                }
            }
            assertContentEquals(archiveBytes, observed)
            val selected = linkedMapOf<String, SelectedTarEntry>()
            locked.archiveContents.indices.reversed().forEach { index ->
                val record = locked.archiveContents[index]
                val path = "${locked.archiveRoot}/${record.path}"
                selected[path] = SelectedTarEntry(path, markerBytes[index], markerBytes[index].sha256())
            }
            BoundedTarXzSummary(
                expandedBytes = archiveBytes.size.toLong(),
                memberCount = selected.size,
                regularFileCount = selected.size,
                directoryCount = 1,
                symbolicLinkCount = 0,
                selected = selected,
            )
        }

    private fun adjust(actual: LlvmSourceLockVerification): LlvmSourceLockVerification = actual.copy(
        archive = actual.archive.copy(bytes = archiveBytes.size.toLong(), sha256 = archiveBytes.sha256()),
        archiveContents = actual.archiveContents.mapIndexed { index, record ->
            record.copy(bytes = markerBytes[index].size.toLong(), sha256 = markerBytes[index].sha256())
        },
    )
}

private class SourcePairTransport(vararg bodies: ByteArray) : HttpsExchangeTransport {
    private val remaining = ArrayDeque(bodies.toList())
    var requests: Int = 0
        private set

    override fun exchange(
        request: HttpsExchangeRequest,
        shouldStreamBody: (Int, HttpHeaders) -> Boolean,
        sink: WritableByteChannel,
    ): HttpsExchangeResult {
        requests++
        val body = remaining.removeFirstOrNull()
            ?: throw ReleaseArtifactProvenanceException("unexpected source-pair network request")
        val headers = HttpHeaders.of(mapOf("Content-Length" to listOf(body.size.toString()))) { _, _ -> true }
        if (!shouldStreamBody(200, headers)) provenanceFail("source-pair response was not accepted")
        val source = ByteBuffer.wrap(body)
        while (source.hasRemaining()) {
            if (sink.write(source) <= 0) provenanceFail("source-pair test sink made no progress")
        }
        return HttpsExchangeResult(200, headers, HttpsBodyReceipt(body.size.toLong(), body.sha256()))
    }
}

private class InjectedSourceFailure : RuntimeException("injected source failure")

private val CHECKED_PROFILE = Path.of("oracle/llvm/22.1.6")
private val CHECKED_LOCK = CHECKED_PROFILE.resolve("source-lock.json")
private const val FROZEN_ARCHIVE_SIGNATURE_BASE64 =
    "iHUEABYKAB0WIQT/szaJgPPmu1c3FFoxbFbQZMrLpQUCag44EAAKCRAxbFbQZMrLpcKQAQCQzzlChOdV19dNNMFY7R6JEyXi1I1VNh7Hqu08+Dkz0AD/eHDRL6sp5cSh58IK/qZfv0klO7joFolz1rjCExhNoQw="
