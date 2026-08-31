package decompengine.oracle.provenance

import java.nio.ByteBuffer
import java.nio.file.Files
import java.nio.file.LinkOption
import java.nio.file.Path
import java.nio.file.StandardCopyOption
import java.nio.file.attribute.PosixFilePermissions
import kotlin.io.path.createTempDirectory
import kotlin.test.Test
import kotlin.test.assertContentEquals
import kotlin.test.assertEquals
import kotlin.test.assertFails
import kotlin.test.assertFailsWith
import kotlin.test.assertFalse
import kotlin.test.assertTrue

class DescriptorBoundDownloadPublisherTest {
    @Test
    fun `cache invokes input and descriptor verification without downloading`() {
        val root = privateDirectory(createTempDirectory("release-cache-verifier-"))
        try {
            val payload = "authenticated cache".toByteArray()
            val target = root.resolve("artifact.bin")
            Files.write(target, payload)
            Files.setPosixFilePermissions(target, PosixFilePermissions.fromString("r--------"))
            var inputs = 0
            var phases = 0

            DescriptorBoundDownloadPublisher.materialize(
                target,
                payload.size.toLong(),
                payload.sha256(),
                verifyInputs = { inputs++ },
                verificationPhases = listOf(
                    DescriptorBoundArtifactVerifier { artifact ->
                        phases++
                        val observed = artifact.withReadableChannel { channel ->
                            ByteArray(payload.size).also { bytes -> channel.read(ByteBuffer.wrap(bytes)) }
                        }
                        assertContentEquals(payload, observed)
                    },
                ),
                download = { error("verified cache must not invoke the downloader") },
            )

            assertEquals(2, inputs, "inputs are checked before selection and after the semantic phase")
            assertEquals(1, phases)
        } finally {
            deleteTree(root)
        }
    }

    @Test
    fun `callback failure leaves a fresh artifact unnamed`() {
        val root = privateDirectory(createTempDirectory("release-callback-failure-"))
        try {
            val payload = "never publish".toByteArray()
            val target = root.resolve("artifact.bin")

            assertFailsWith<InjectedFailure> {
                DescriptorBoundDownloadPublisher.materialize(
                    target,
                    payload.size.toLong(),
                    payload.sha256(),
                    verifyInputs = {},
                    verificationPhases = listOf(
                        DescriptorBoundArtifactVerifier { throw InjectedFailure() },
                    ),
                    download = { channel -> writeReceipt(channel, payload) },
                )
            }
            assertFalse(Files.exists(target, LinkOption.NOFOLLOW_LINKS))
        } finally {
            deleteTree(root)
        }
    }

    @Test
    fun `phase checkpoint rejects same-inode cache mutation`() {
        val root = privateDirectory(createTempDirectory("release-phase-mutation-"))
        try {
            val payload = "locked payload".toByteArray()
            val mutation = "evil payload!!".toByteArray()
            assertEquals(payload.size, mutation.size)
            val target = root.resolve("artifact.bin")
            Files.write(target, payload)
            Files.setPosixFilePermissions(target, PosixFilePermissions.fromString("r--------"))

            assertFailsWith<ReleaseArtifactProvenanceException> {
                DescriptorBoundDownloadPublisher.materialize(
                    target,
                    payload.size.toLong(),
                    payload.sha256(),
                    verifyInputs = {},
                    verificationPhases = listOf(
                        DescriptorBoundArtifactVerifier {
                            Files.setPosixFilePermissions(target, PosixFilePermissions.fromString("rw-------"))
                            Files.write(target, mutation)
                            Files.setPosixFilePermissions(target, PosixFilePermissions.fromString("r--------"))
                        },
                        DescriptorBoundArtifactVerifier { error("mutation must fail before the next phase") },
                    ),
                    download = { error("the selected cache must not download") },
                )
            }
            assertContentEquals(mutation, Files.readAllBytes(target))
        } finally {
            deleteTree(root)
        }
    }

    @Test
    fun `EEXIST winner reruns semantic verification and can be rejected`() {
        val root = privateDirectory(createTempDirectory("release-winner-verifier-"))
        try {
            val payload = "race winner".toByteArray()
            val target = root.resolve("artifact.bin")
            var phases = 0

            assertFailsWith<InjectedFailure> {
                DescriptorBoundDownloadPublisher.materialize(
                    target,
                    payload.size.toLong(),
                    payload.sha256(),
                    verifyInputs = {},
                    verificationPhases = listOf(
                        DescriptorBoundArtifactVerifier {
                            phases++
                            if (phases == 2) throw InjectedFailure()
                        },
                    ),
                    faultInjector = DownloadPublicationFaultInjector { point ->
                        if (point == DownloadPublicationPoint.BEFORE_LINK) {
                            Files.write(target, payload)
                            Files.setPosixFilePermissions(target, PosixFilePermissions.fromString("r--------"))
                        }
                    },
                    download = { channel -> writeReceipt(channel, payload) },
                )
            }
            assertEquals(2, phases)
            assertContentEquals(payload, Files.readAllBytes(target))
        } finally {
            deleteTree(root)
        }
    }

    @Test
    fun `terminal digest rejects same-inode content mutation`() {
        val root = privateDirectory(createTempDirectory("release-terminal-mutation-"))
        try {
            val payload = "terminal good".toByteArray()
            val mutation = "terminal evil".toByteArray()
            assertEquals(payload.size, mutation.size)
            val target = root.resolve("artifact.bin")

            assertFailsWith<ReleaseArtifactProvenanceException> {
                DescriptorBoundDownloadPublisher.materialize(
                    target,
                    payload.size.toLong(),
                    payload.sha256(),
                    verifyInputs = {},
                    verificationPhases = listOf(DescriptorBoundArtifactVerifier {}),
                    faultInjector = DownloadPublicationFaultInjector { point ->
                        if (point == DownloadPublicationPoint.BEFORE_TERMINAL_ACCEPTANCE) {
                            Files.setPosixFilePermissions(target, PosixFilePermissions.fromString("rw-------"))
                            Files.write(target, mutation)
                            Files.setPosixFilePermissions(target, PosixFilePermissions.fromString("r--------"))
                        }
                    },
                    download = { channel -> writeReceipt(channel, payload) },
                )
            }
            assertContentEquals(mutation, Files.readAllBytes(target))
        } finally {
            deleteTree(root)
        }
    }

    @Test
    fun `publishes a private read-only inode and reuses only exact existing bytes`() {
        val root = privateDirectory(createTempDirectory("release-publisher-"))
        try {
            val payload = "large artifact stand-in\n".toByteArray()
            val target = root.resolve("artifact.bin")
            var downloads = 0

            val first = publish(target, payload) { downloads++ }
            val second = DescriptorBoundDownloadPublisher.materialize(
                target,
                payload.size.toLong(),
                payload.sha256(),
                verifyInputs = {},
                download = { error("verified cache must not invoke the downloader") },
            )

            assertEquals(1, downloads)
            assertEquals(first, second)
            assertContentEquals(payload, Files.readAllBytes(target))
            assertEquals(
                PosixFilePermissions.fromString("r--------"),
                Files.getPosixFilePermissions(target, LinkOption.NOFOLLOW_LINKS),
            )
            assertEquals(listOf(target), Files.list(root).use { it.toList() })
        } finally {
            deleteTree(root)
        }
    }

    @Test
    fun `an exact racing winner is accepted and a different winner is retained and rejected`() {
        val root = privateDirectory(createTempDirectory("release-race-"))
        try {
            val payload = "winner".toByteArray()
            val exact = root.resolve("exact.bin")
            val exactResult = DescriptorBoundDownloadPublisher.materialize(
                exact,
                payload.size.toLong(),
                payload.sha256(),
                verifyInputs = {},
                faultInjector = DownloadPublicationFaultInjector { point ->
                    if (point == DownloadPublicationPoint.BEFORE_LINK) {
                        Files.write(exact, payload)
                        Files.setPosixFilePermissions(exact, PosixFilePermissions.fromString("r--------"))
                    }
                },
                download = { channel -> writeReceipt(channel, payload) },
            )
            assertEquals(exact, exactResult.path)
            assertContentEquals(payload, Files.readAllBytes(exact))

            val different = root.resolve("different.bin")
            val sentinel = "do-not-replace".toByteArray()
            assertFailsWith<ReleaseArtifactProvenanceException> {
                DescriptorBoundDownloadPublisher.materialize(
                    different,
                    payload.size.toLong(),
                    payload.sha256(),
                    verifyInputs = {},
                    faultInjector = DownloadPublicationFaultInjector { point ->
                        if (point == DownloadPublicationPoint.BEFORE_LINK) Files.write(different, sentinel)
                    },
                    download = { channel -> writeReceipt(channel, payload) },
                )
            }
            assertContentEquals(sentinel, Files.readAllBytes(different))
        } finally {
            deleteTree(root)
        }
    }

    @Test
    fun `owner-writable caches and exact race winners are rejected`() {
        val root = privateDirectory(createTempDirectory("release-writable-"))
        try {
            val payload = "exact but mutable".toByteArray()
            val cached = root.resolve("cached.bin")
            Files.write(cached, payload)
            Files.setPosixFilePermissions(cached, PosixFilePermissions.fromString("rw-------"))
            assertFailsWith<ReleaseArtifactProvenanceException> {
                DescriptorBoundDownloadPublisher.materialize(
                    cached,
                    payload.size.toLong(),
                    payload.sha256(),
                    verifyInputs = {},
                    download = { error("a mutable cache must fail before network") },
                )
            }

            val racing = root.resolve("racing.bin")
            assertFailsWith<ReleaseArtifactProvenanceException> {
                DescriptorBoundDownloadPublisher.materialize(
                    racing,
                    payload.size.toLong(),
                    payload.sha256(),
                    verifyInputs = {},
                    faultInjector = DownloadPublicationFaultInjector { point ->
                        if (point == DownloadPublicationPoint.BEFORE_LINK) {
                            Files.write(racing, payload)
                            Files.setPosixFilePermissions(racing, PosixFilePermissions.fromString("rw-------"))
                        }
                    },
                    download = { channel -> writeReceipt(channel, payload) },
                )
            }
            assertContentEquals(payload, Files.readAllBytes(cached))
            assertContentEquals(payload, Files.readAllBytes(racing))
        } finally {
            deleteTree(root)
        }
    }

    @Test
    fun `publication rejects parent permission drift after the download`() {
        val root = privateDirectory(createTempDirectory("release-parent-drift-"))
        try {
            val payload = "parent drift".toByteArray()
            val target = root.resolve("artifact.bin")
            assertFailsWith<ReleaseArtifactProvenanceException> {
                DescriptorBoundDownloadPublisher.materialize(
                    target,
                    payload.size.toLong(),
                    payload.sha256(),
                    verifyInputs = {},
                    faultInjector = DownloadPublicationFaultInjector { point ->
                        if (point == DownloadPublicationPoint.AFTER_STAGE_SYNC) {
                            Files.setPosixFilePermissions(root, PosixFilePermissions.fromString("rwxr-----"))
                        }
                    },
                    download = { channel -> writeReceipt(channel, payload) },
                )
            }
            assertFalse(Files.exists(target, LinkOption.NOFOLLOW_LINKS))
        } finally {
            Files.setPosixFilePermissions(root, PosixFilePermissions.fromString("rwx------"))
            deleteTree(root)
        }
    }

    @Test
    fun `cache and EEXIST winner synchronize file before directory acceptance`() {
        val root = privateDirectory(createTempDirectory("release-sync-order-"))
        try {
            val payload = "durable acceptance".toByteArray()
            val cached = root.resolve("cached.bin")
            Files.write(cached, payload)
            Files.setPosixFilePermissions(cached, PosixFilePermissions.fromString("r--------"))
            val cachePoints = mutableListOf<DownloadPublicationPoint>()

            DescriptorBoundDownloadPublisher.materialize(
                cached,
                payload.size.toLong(),
                payload.sha256(),
                verifyInputs = {},
                faultInjector = DownloadPublicationFaultInjector { cachePoints += it },
                download = { error("the exact cache must not download") },
            )
            assertAcceptedSyncOrder(cachePoints)

            val racing = root.resolve("racing.bin")
            val racePoints = mutableListOf<DownloadPublicationPoint>()
            DescriptorBoundDownloadPublisher.materialize(
                racing,
                payload.size.toLong(),
                payload.sha256(),
                verifyInputs = {},
                faultInjector = DownloadPublicationFaultInjector { point ->
                    racePoints += point
                    if (point == DownloadPublicationPoint.BEFORE_LINK) {
                        Files.write(racing, payload)
                        Files.setPosixFilePermissions(racing, PosixFilePermissions.fromString("r--------"))
                    }
                },
                download = { channel -> writeReceipt(channel, payload) },
            )
            assertAcceptedSyncOrder(racePoints)
        } finally {
            deleteTree(root)
        }
    }

    @Test
    fun `accepted directory mutations before and after fsync fail terminal validation`() {
        listOf(
            DownloadPublicationPoint.BEFORE_ACCEPTED_DIRECTORY_SYNC,
            DownloadPublicationPoint.AFTER_ACCEPTED_DIRECTORY_SYNC,
        ).forEach { mutationPoint ->
            val root = privateDirectory(createTempDirectory("release-parent-terminal-"))
            try {
                val payload = "parent terminal validation".toByteArray()
                val target = root.resolve("artifact.bin")
                Files.write(target, payload)
                Files.setPosixFilePermissions(target, PosixFilePermissions.fromString("r--------"))

                assertFailsWith<ReleaseArtifactProvenanceException> {
                    DescriptorBoundDownloadPublisher.materialize(
                        target,
                        payload.size.toLong(),
                        payload.sha256(),
                        verifyInputs = {},
                        faultInjector = DownloadPublicationFaultInjector { point ->
                            if (point == mutationPoint) {
                                Files.setPosixFilePermissions(root, PosixFilePermissions.fromString("rwxr-----"))
                            }
                        },
                        download = { error("the exact cache must not download") },
                    )
                }
                assertContentEquals(payload, Files.readAllBytes(target))
            } finally {
                Files.setPosixFilePermissions(root, PosixFilePermissions.fromString("rwx------"))
                deleteTree(root)
            }
        }
    }

    @Test
    fun `fresh publication rejects terminal named-file link-count drift`() {
        val root = privateDirectory(createTempDirectory("release-file-terminal-"))
        try {
            val payload = "terminal file identity".toByteArray()
            val target = root.resolve("artifact.bin")
            val alias = root.resolve("artifact-alias.bin")
            assertFailsWith<ReleaseArtifactProvenanceException> {
                DescriptorBoundDownloadPublisher.materialize(
                    target,
                    payload.size.toLong(),
                    payload.sha256(),
                    verifyInputs = {},
                    faultInjector = DownloadPublicationFaultInjector { point ->
                        if (point == DownloadPublicationPoint.BEFORE_TERMINAL_ACCEPTANCE) {
                            Files.createLink(alias, target)
                        }
                    },
                    download = { channel -> writeReceipt(channel, payload) },
                )
            }
            assertContentEquals(payload, Files.readAllBytes(target))
            assertTrue(Files.isSameFile(target, alias))
        } finally {
            deleteTree(root)
        }
    }

    @Test
    fun `directory creation rejects a symbolic-link ancestor without an outside side effect`() {
        val root = privateDirectory(createTempDirectory("release-directory-symlink-"))
        try {
            val outside = privateDirectory(root.resolve("outside"))
            val nested = privateDirectory(outside.resolve("nested"))
            val trusted = privateDirectory(root.resolve("trusted"))
            Files.createSymbolicLink(trusted.resolve("redirect"), outside)
            val attempted = trusted.resolve("redirect/nested/created")

            assertFailsWith<ReleaseArtifactProvenanceException> {
                openOrCreateAuthenticatedReleaseDirectory(attempted, "test release directory").use { }
            }
            assertFalse(Files.exists(nested.resolve("created"), LinkOption.NOFOLLOW_LINKS))
        } finally {
            deleteTree(root)
        }
    }

    @Test
    fun `directory creation detects a parent pathname swap before mkdirat`() {
        val root = privateDirectory(createTempDirectory("release-directory-swap-"))
        try {
            val parent = privateDirectory(root.resolve("parent"))
            val displaced = root.resolve("displaced")
            val attempted = parent.resolve("created")

            assertFailsWith<ReleaseArtifactProvenanceException> {
                openOrCreateAuthenticatedReleaseDirectory(
                    attempted,
                    "test release directory",
                    ReleaseDirectoryFaultInjector { point ->
                        if (point == ReleaseDirectoryPoint.BEFORE_CHILD_CREATE) {
                            Files.move(parent, displaced, StandardCopyOption.ATOMIC_MOVE)
                            privateDirectory(parent)
                        }
                    },
                ).use { }
            }
            assertFalse(Files.exists(parent.resolve("created"), LinkOption.NOFOLLOW_LINKS))
            assertFalse(Files.exists(displaced.resolve("created"), LinkOption.NOFOLLOW_LINKS))
        } finally {
            deleteTree(root)
        }
    }

    @Test
    fun `pre-link failures leave no name and post-link failures leave only verified retryable bytes`() {
        val root = privateDirectory(createTempDirectory("release-fault-"))
        try {
            val payload = "fault-boundary".toByteArray()
            val preLink = root.resolve("pre-link.bin")
            assertFails {
                DescriptorBoundDownloadPublisher.materialize(
                    preLink,
                    payload.size.toLong(),
                    payload.sha256(),
                    verifyInputs = { throw InjectedFailure() },
                    download = { channel -> writeReceipt(channel, payload) },
                )
            }
            assertFalse(Files.exists(preLink, LinkOption.NOFOLLOW_LINKS))

            val postLink = root.resolve("post-link.bin")
            assertFailsWith<InjectedFailure> {
                DescriptorBoundDownloadPublisher.materialize(
                    postLink,
                    payload.size.toLong(),
                    payload.sha256(),
                    verifyInputs = {},
                    faultInjector = DownloadPublicationFaultInjector { point ->
                        if (point == DownloadPublicationPoint.AFTER_LINK) throw InjectedFailure()
                    },
                    download = { channel -> writeReceipt(channel, payload) },
                )
            }
            assertContentEquals(payload, Files.readAllBytes(postLink))
            DescriptorBoundDownloadPublisher.materialize(
                postLink,
                payload.size.toLong(),
                payload.sha256(),
                verifyInputs = {},
                download = { error("retry must reuse the verified linked inode") },
            )
            assertEquals(setOf("post-link.bin"), Files.list(root).use { paths ->
                paths.map { it.fileName.toString() }.toList().toSet()
            })
        } finally {
            deleteTree(root)
        }
    }

    @Test
    fun `partial download and symbolic-link cache fail closed`() {
        val root = privateDirectory(createTempDirectory("release-invalid-"))
        try {
            val payload = "expected".toByteArray()
            val partial = root.resolve("partial.bin")
            assertFailsWith<InjectedFailure> {
                DescriptorBoundDownloadPublisher.materialize(
                    partial,
                    payload.size.toLong(),
                    payload.sha256(),
                    verifyInputs = {},
                    download = { channel ->
                        channel.write(ByteBuffer.wrap(payload.copyOf(2)))
                        throw InjectedFailure()
                    },
                )
            }
            assertFalse(Files.exists(partial, LinkOption.NOFOLLOW_LINKS))

            val host = root.resolve("host.bin")
            Files.write(host, payload)
            val symbolic = root.resolve("symbolic.bin")
            Files.createSymbolicLink(symbolic, host.fileName)
            assertFails {
                DescriptorBoundDownloadPublisher.materialize(
                    symbolic,
                    payload.size.toLong(),
                    payload.sha256(),
                    verifyInputs = {},
                    download = { error("symbolic cache must fail before network") },
                )
            }
            assertTrue(Files.isSymbolicLink(symbolic))
            assertContentEquals(payload, Files.readAllBytes(host))
        } finally {
            deleteTree(root)
        }
    }

    private fun publish(target: Path, payload: ByteArray, before: () -> Unit): AuthenticatedDownloadedArtifact =
        DescriptorBoundDownloadPublisher.materialize(
            target,
            payload.size.toLong(),
            payload.sha256(),
            verifyInputs = {},
            download = { channel ->
                before()
                writeReceipt(channel, payload)
            },
        )

    private fun assertAcceptedSyncOrder(points: List<DownloadPublicationPoint>) {
        val orderingPoints = setOf(
            DownloadPublicationPoint.BEFORE_ACCEPTED_FILE_SYNC,
            DownloadPublicationPoint.AFTER_ACCEPTED_FILE_SYNC,
            DownloadPublicationPoint.BEFORE_ACCEPTED_DIRECTORY_SYNC,
            DownloadPublicationPoint.AFTER_ACCEPTED_DIRECTORY_SYNC,
        )
        assertEquals(
            listOf(
                DownloadPublicationPoint.BEFORE_ACCEPTED_FILE_SYNC,
                DownloadPublicationPoint.AFTER_ACCEPTED_FILE_SYNC,
                DownloadPublicationPoint.BEFORE_ACCEPTED_DIRECTORY_SYNC,
                DownloadPublicationPoint.AFTER_ACCEPTED_DIRECTORY_SYNC,
            ),
            points.filter { it in orderingPoints },
        )
    }

    private class InjectedFailure : RuntimeException()
}

private fun writeReceipt(channel: java.nio.channels.WritableByteChannel, payload: ByteArray): HttpsDownloadReceipt {
    val buffer = ByteBuffer.wrap(payload)
    while (buffer.hasRemaining()) channel.write(buffer)
    return HttpsDownloadReceipt(
        payload.size.toLong(),
        payload.sha256(),
        java.net.URI.create("https://release-assets.githubusercontent.com/test"),
    )
}

internal fun privateDirectory(path: Path): Path = path.also {
    Files.createDirectories(it)
    Files.setPosixFilePermissions(it, PosixFilePermissions.fromString("rwx------"))
}

internal fun deleteTree(root: Path) {
    if (!Files.exists(root, LinkOption.NOFOLLOW_LINKS)) return
    Files.walk(root).use { paths ->
        paths.sorted(Comparator.reverseOrder()).forEach { path -> Files.deleteIfExists(path) }
    }
}
