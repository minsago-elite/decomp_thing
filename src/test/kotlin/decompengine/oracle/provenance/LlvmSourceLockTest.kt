package decompengine.oracle.provenance

import decompengine.oracle.core.OracleArtifacts
import decompengine.oracle.core.OracleJson
import java.io.ByteArrayInputStream
import java.io.ByteArrayOutputStream
import java.nio.file.Files
import java.nio.file.LinkOption
import java.nio.file.Path
import java.nio.file.StandardCopyOption
import java.nio.file.attribute.PosixFilePermission
import java.security.Security
import java.util.Base64
import kotlin.io.path.createTempDirectory
import kotlin.test.Test
import kotlin.test.assertEquals
import kotlin.test.assertFailsWith
import kotlin.test.assertFalse
import kotlin.test.assertNotEquals
import kotlin.test.assertTrue
import kotlinx.serialization.json.JsonArray
import kotlinx.serialization.json.JsonElement
import kotlinx.serialization.json.JsonObject
import kotlinx.serialization.json.JsonPrimitive
import org.bouncycastle.bcpg.ArmoredInputStream
import org.bouncycastle.bcpg.ArmoredOutputStream
import org.bouncycastle.openpgp.PGPPublicKey
import org.bouncycastle.openpgp.PGPPublicKeyRing
import org.bouncycastle.openpgp.PGPSignatureList
import org.bouncycastle.openpgp.bc.BcPGPObjectFactory
import org.junit.jupiter.api.Assumptions.assumeTrue

class LlvmSourceLockTest {
    @Test
    fun `checked source lock reconstructs and authenticates the real annotated tag deterministically`() {
        val providersBefore = Security.getProviders().map { it.name }
        val first = LlvmSourceLockVerifier().verify(CHECKED_LOCK)
        val second = LlvmSourceLockVerifier().verify(CHECKED_LOCK)

        assertEquals("179b1298b14ddb701c46eb1ed6a5bb0aa60ee01580bafcf5c555b1d13c994306", first.lockSha256)
        assertEquals("clang-driver-22.1.6", first.oracleId)
        assertEquals("22.1.6", first.version)
        assertEquals("llvmorg-22.1.6", first.tag)
        assertEquals("e1e54c548235b71134d53ec5e4d93873db5c70ef", first.tagObject)
        assertEquals("fc4aad7b5db3fff421df9a9637605b9ca5667881", first.commit)
        assertNotEquals(first.commit, first.tagObject)
        assertEquals(167_043_464L, first.archive.bytes)
        assertEquals("6e0b376a1f6d9873e7dfb09ae6e04b9c7024400f01733fa4c29be69d5c138bc2", first.archive.sha256)
        assertEquals(119L, first.detachedSignature.bytes)
        assertEquals("cb605632f17606799b8a3b76781e80ceeae5e2c7e7823823eff688557ce53a68", first.detachedSignature.sha256)
        assertEquals("e1975f318e84f5073a49b767a461d978e45f088b77758e36e6acf660c33b26ae", first.tagPayloadSha256)
        assertEquals("6b6c2f17edcf8929dea1303e7a65a6d05074b6439cfe33b74ed8eea603cf75dc", first.tagSignatureSha256)
        assertEquals("d3e02c6fbcc641935ebd8b5a0d623563f90fef1a51c161917d7d5ed921e36288", first.signingKeySha256)
        assertEquals("FFB3368980F3E6BB5737145A316C56D064CACBA5", first.signingFingerprint)
        assertEquals("316C56D064CACBA5", first.signingKey.primaryKeyId)
        assertEquals("1FE1C822C37D38862D36BBE9B977855DC9580AA9", first.signingKey.encryptionSubkeyFingerprint)
        assertEquals("B977855DC9580AA9", first.signingKey.encryptionSubkeyId)
        assertEquals(1_779_182_222L, first.tagSignature.creationEpochSeconds)
        assertEquals(
            listOf("cmake/Modules/LLVMVersion.cmake", "LICENSE.TXT", "clang/LICENSE.TXT"),
            first.archiveContents.map { it.path },
        )
        assertEquals(first.copy(signingKey = second.signingKey), second)
        assertEquals(providersBefore, Security.getProviders().map { it.name })
    }

    @Test
    fun `strict JSON schema and canonical encoding reject duplicate unknown and noncanonical fields`() {
        withFixture { fixture ->
            val original = Files.readString(fixture.lockPath)
            Files.writeString(
                fixture.lockPath,
                original.replaceFirst("\"oracle\": {", "\"oracle\": {},\n  \"oracle\": {"),
            )
            assertSourceFailure { fixture.verify() }
        }
        withFixture { fixture ->
            fixture.updateLock { JsonObject(it + ("unexpected" to JsonPrimitive(true))) }
            assertSourceFailure { fixture.verify() }
        }
        withFixture { fixture ->
            Files.write(fixture.lockPath, Files.readAllBytes(fixture.lockPath) + byteArrayOf('\n'.code.toByte()))
            assertSourceFailure { fixture.verify() }
        }
        withFixture { fixture ->
            fixture.updateLock { it.sourceTestWith("schemaVersion", JsonPrimitive(true)) }
            assertSourceFailure { fixture.verify() }
        }
    }

    @Test
    fun `version URL artifact revision signer and archive-content cross-bindings fail closed`() {
        val mutations: List<(JsonObject) -> JsonObject> = listOf(
            { it.sourceTestUpdate("oracle") { value -> value.sourceTestWith("id", JsonPrimitive("clang-driver-22.1.7")) } },
            { it.sourceTestUpdate("oracle") { value -> value.sourceTestWith("project", JsonPrimitive("LLVM") ) } },
            { it.sourceTestUpdate("source") { value -> value.sourceTestWith("archiveRoot", JsonPrimitive("llvm-project-22.1.7.src")) } },
            { it.sourceTestUpdate("source") { value -> value.sourceTestWith("releasePageUrl", JsonPrimitive("https://github.com/llvm/llvm-project/releases/tag/llvmorg-22.1.7")) } },
            { root -> root.sourceTestUpdate("source") { source -> source.sourceTestUpdate("archive") { it.sourceTestWith("fileName", JsonPrimitive("wrong.tar.xz")) } } },
            { root -> root.sourceTestUpdate("source") { source -> source.sourceTestUpdate("archive") { it.sourceTestWith("url", JsonPrimitive("https://example.invalid/archive")) } } },
            { root -> root.sourceTestUpdate("source") { source -> source.sourceTestUpdate("archive") { it.sourceTestWith("bytes", JsonPrimitive(536_870_913L)) } } },
            { root -> root.sourceTestUpdate("source") { source -> source.sourceTestUpdate("detachedSignature") { it.sourceTestWith("url", JsonPrimitive("https://example.invalid/signature")) } } },
            { it.sourceTestUpdate("revision") { value -> value.sourceTestWith("repositoryUrl", JsonPrimitive("https://example.invalid/repo.git")) } },
            { it.sourceTestUpdate("revision") { value -> value.sourceTestWith("tag", JsonPrimitive("llvmorg-22.1.7")) } },
            { root -> root.sourceTestUpdate("revision") { revision -> revision.sourceTestWith("tagObject", revision.getValue("commit")) } },
            { root -> root.sourceTestUpdate("revision") { revision -> revision.sourceTestUpdate("tagEvidence") { it.sourceTestWith("payloadFile", JsonPrimitive("tag/other.payload")) } } },
            { root -> root.sourceTestUpdate("revision") { revision -> revision.sourceTestUpdate("tagEvidence") { it.sourceTestWith("payloadBytes", JsonPrimitive(1)) } } },
            { root -> root.sourceTestUpdate("revision") { revision -> revision.sourceTestUpdate("tagEvidence") { it.sourceTestWith("signatureBytes", JsonPrimitive(65_537)) } } },
            { root -> root.sourceTestUpdate("revision") { revision -> revision.sourceTestUpdate("tagEvidence") { it.sourceTestWith("payloadSha256", JsonPrimitive("0".repeat(64))) } } },
            { root -> root.sourceTestUpdate("signing") { it.sourceTestWith("authorityUrl", JsonPrimitive("https://example.invalid/keys")) } },
            { root -> root.sourceTestUpdate("signing") { it.sourceTestWith("keyFile", JsonPrimitive("keys/other.asc")) } },
            { root -> root.sourceTestUpdate("signing") { it.sourceTestWith("keySha256", JsonPrimitive("0".repeat(64))) } },
            { root -> root.sourceTestUpdate("signing") { signing -> signing.sourceTestWith("signingFingerprint", JsonPrimitive("A".repeat(40))) } },
            { root -> root.sourceTestUpdate("redistribution") { redistribution -> redistribution.sourceTestWith("licenseFiles", JsonArray((redistribution["licenseFiles"] as JsonArray).reversed())) } },
            { root -> root.sourceTestUpdate("revision") { revision -> revision.sourceTestUpdate("archiveMarkers") { markers -> markers.sourceTestUpdate("version") { it.sourceTestWith("text", JsonPrimitive("set(LLVM_VERSION_MAJOR 22)\n")) } } } },
            { root -> root.sourceTestUpdate("revision") { revision -> revision.sourceTestUpdate("archiveMarkers") { markers -> markers.sourceTestUpdate("version") { it.sourceTestWith("sha256", JsonPrimitive("0".repeat(64))) } } } },
        )
        mutations.forEachIndexed { index, mutation ->
            withFixture { fixture ->
                fixture.updateLock(mutation)
                val failure = assertSourceFailure { fixture.verify() }
                assertTrue(failure.message.orEmpty().isNotEmpty(), "mutation $index must have a bounded diagnostic")
            }
        }
    }

    @Test
    fun `local key payload signature path digest permissions and symlink boundaries fail closed`() {
        for (relative in listOf(KEY_RELATIVE, PAYLOAD_RELATIVE, TAG_SIGNATURE_RELATIVE)) {
            withFixture { fixture ->
                Files.write(fixture.root.resolve(relative), byteArrayOf(0x41), java.nio.file.StandardOpenOption.APPEND)
                assertSourceFailure { fixture.verify() }
            }
        }
        withFixture { fixture ->
            val key = fixture.root.resolve(KEY_RELATIVE)
            Files.delete(key)
            Files.createSymbolicLink(key, CHECKED_PROFILE.resolve(KEY_RELATIVE))
            assertSourceFailure { fixture.verify() }
        }
        withFixture { fixture ->
            val payload = fixture.root.resolve(PAYLOAD_RELATIVE)
            val permissions = Files.getPosixFilePermissions(payload, LinkOption.NOFOLLOW_LINKS).toMutableSet()
            permissions += PosixFilePermission.GROUP_WRITE
            Files.setPosixFilePermissions(payload, permissions)
            assertSourceFailure { fixture.verify() }
        }
        withFixture { fixture ->
            val tagDirectory = fixture.root.resolve("tag")
            val permissions = Files.getPosixFilePermissions(tagDirectory, LinkOption.NOFOLLOW_LINKS).toMutableSet()
            permissions += PosixFilePermission.OTHERS_WRITE
            Files.setPosixFilePermissions(tagDirectory, permissions)
            assertSourceFailure { fixture.verify() }
        }
    }

    @Test
    fun `tag object reconstruction rejects payload line endings content and a merely formatted object id`() {
        withFixture { fixture ->
            val payload = fixture.root.resolve(PAYLOAD_RELATIVE)
            Files.write(payload, Files.readAllBytes(payload).replaceLfWithCrLf())
            fixture.rebindTagEvidence("payload", payload)
            assertSourceFailure { fixture.verify() }
        }
        withFixture { fixture ->
            val payload = fixture.root.resolve(PAYLOAD_RELATIVE)
            Files.writeString(payload, Files.readString(payload).replace("LLVM 22.1.6", "LLVM 22.1.7"))
            fixture.rebindTagEvidence("payload", payload)
            assertSourceFailure { fixture.verify() }
        }
        withFixture { fixture ->
            fixture.updateLock { root ->
                root.sourceTestUpdate("revision") { revision ->
                    revision.sourceTestWith("tagObject", JsonPrimitive("1".repeat(40)))
                }
            }
            assertSourceFailure { fixture.verify() }
        }
    }

    @Test
    fun `reviewed key profile rejects extra rings identities certifications bindings and packet mutations`() {
        val keyBytes = Files.readAllBytes(CHECKED_PROFILE.resolve(KEY_RELATIVE))
        val verified = checkedSigningKey()
        assertEquals("FFB3368980F3E6BB5737145A316C56D064CACBA5", verified.primaryFingerprint)

        val ring = parseKeyRing(keyBytes)
        val keys = ring.publicKeys.asSequence().toList()
        val primary = keys[0]
        val subkey = keys[1]
        val selfCertification = primary.getSignaturesForID(REVIEWED_USER_ID).next()
        val binding = subkey.signatures.next()
        val mutatedRings = listOf(
            PGPPublicKeyRing(listOf(PGPPublicKey.addCertification(primary, REVIEWED_USER_ID, selfCertification), subkey)),
            PGPPublicKeyRing(listOf(PGPPublicKey.addCertification(primary, "Other <other@example.invalid>", selfCertification), subkey)),
            PGPPublicKeyRing(listOf(PGPPublicKey.removeCertification(primary, REVIEWED_USER_ID, selfCertification), subkey)),
            PGPPublicKeyRing(listOf(primary, PGPPublicKey.addCertification(subkey, binding))),
            PGPPublicKeyRing(listOf(primary, PGPPublicKey.removeCertification(subkey, binding))),
        )
        mutatedRings.forEach { mutated ->
            assertSourceFailure {
                LlvmOpenPgpVerifier.verifyVendoredSigningKey(
                    armor(mutated.encoded),
                    verified.primaryFingerprint,
                    verified.primaryFingerprint,
                )
            }
        }
        val binary = decodeArmor(keyBytes)
        listOf(2, 3, 7, 55, binary.lastIndex).forEach { offset ->
            val mutated = binary.copyOf().also { it[offset] = (it[offset].toInt() xor 0x01).toByte() }
            assertSourceFailure {
                LlvmOpenPgpVerifier.verifyVendoredSigningKey(
                    armor(mutated),
                    verified.primaryFingerprint,
                    verified.primaryFingerprint,
                )
            }
        }
        val preferenceOffset = binary.indexOfSequence(byteArrayOf(9, 8, 7, 2))
        val preferenceMutation = binary.copyOf().also {
            it[preferenceOffset] = 8
        }
        assertSourceFailure {
            LlvmOpenPgpVerifier.verifyVendoredSigningKey(
                armor(preferenceMutation),
                verified.primaryFingerprint,
                verified.primaryFingerprint,
            )
        }
        assertSourceFailure {
            LlvmOpenPgpVerifier.verifyVendoredSigningKey(
                armor(binary + binary),
                verified.primaryFingerprint,
                verified.primaryFingerprint,
            )
        }
        val unexpectedTrustPacket = binary.copyOfRange(0, 53) +
            byteArrayOf(0xb0.toByte(), 1, 0) + binary.copyOfRange(53, binary.size)
        assertSourceFailure {
            LlvmOpenPgpVerifier.verifyVendoredSigningKey(
                armor(unexpectedTrustPacket),
                verified.primaryFingerprint,
                verified.primaryFingerprint,
            )
        }
        assertSourceFailure {
            LlvmOpenPgpVerifier.verifyVendoredSigningKey(
                keyBytes + keyBytes,
                verified.primaryFingerprint,
                verified.primaryFingerprint,
            )
        }
        val armorText = keyBytes.decodeToString()
        val firstDataLine = armorText.lineSequence().first { it.length == 64 && !it.startsWith('-') }
        val reflowed = armorText.replaceFirst(firstDataLine, "${firstDataLine.take(32)}\n${firstDataLine.drop(32)}")
            .toByteArray()
        assertSourceFailure {
            LlvmOpenPgpVerifier.verifyVendoredSigningKey(
                reflowed,
                verified.primaryFingerprint,
                verified.primaryFingerprint,
            )
        }
        assertSourceFailure {
            LlvmOpenPgpVerifier.verifyVendoredSigningKey(keyBytes, "A".repeat(40), "A".repeat(40))
        }
    }

    @Test
    fun `tag signature rejects multiplicity framing profile issuer and cryptographic mutations`() {
        val key = checkedSigningKey()
        val payload = Files.readAllBytes(CHECKED_PROFILE.resolve(PAYLOAD_RELATIVE))
        val armored = Files.readAllBytes(CHECKED_PROFILE.resolve(TAG_SIGNATURE_RELATIVE))
        val binary = decodeArmor(armored)
        assertEquals(1_779_182_222L, LlvmOpenPgpVerifier.verifyTagSignature(key, payload, armored).creationEpochSeconds)

        val profileOffsets = listOf(2, 3, 4, 5, 12, 32, 43)
        profileOffsets.forEach { offset ->
            val mutation = binary.copyOf().also { it[offset] = (it[offset].toInt() xor 0x01).toByte() }
            assertSourceFailure { LlvmOpenPgpVerifier.verifyTagSignature(key, payload, armor(mutation)) }
        }
        assertSourceFailure { LlvmOpenPgpVerifier.verifyTagSignature(key, payload + byteArrayOf(0), armored) }
        assertSourceFailure { LlvmOpenPgpVerifier.verifyTagSignature(key, payload, armor(binary + binary)) }
        assertSourceFailure { LlvmOpenPgpVerifier.verifyTagSignature(key, payload, armored + byteArrayOf('\n'.code.toByte())) }
        val badCrc = armored.copyOf().also { bytes ->
            val crc = bytes.indexOfSequence("=Sttm".toByteArray())
            bytes[crc + 1] = 'A'.code.toByte()
        }
        assertSourceFailure { LlvmOpenPgpVerifier.verifyTagSignature(key, payload, badCrc) }
    }

    @Test
    fun `real archive signature profile is singular exact and cryptographically rejects other bytes`() {
        val key = checkedSigningKey()
        val signature = Base64.getDecoder().decode(FROZEN_ARCHIVE_SIGNATURE_BASE64)
        assertEquals(119, signature.size)
        assertEquals("cb605632f17606799b8a3b76781e80ceeae5e2c7e7823823eff688557ce53a68", OracleArtifacts.sha256(signature))
        val profile = LlvmOpenPgpVerifier.inspectArchiveSignature(signature)
        assertEquals(1_779_316_752L, profile.creationEpochSeconds)
        assertEquals("FFB3368980F3E6BB5737145A316C56D064CACBA5", profile.signerFingerprint)
        assertEquals("316C56D064CACBA5", profile.signerKeyId)

        val wrong = "not the signed LLVM archive".toByteArray()
        assertSourceFailure {
            LlvmOpenPgpVerifier.verifyArchiveSignature(
                key,
                signature,
                ByteArrayInputStream(wrong),
                wrong.size.toLong(),
                OracleArtifacts.sha256(wrong),
            )
        }
        assertSourceFailure { LlvmOpenPgpVerifier.inspectArchiveSignature(signature + signature) }
        listOf(2, 3, 4, 5, 11, 31).forEach { offset ->
            val mutation = signature.copyOf().also { it[offset] = (it[offset].toInt() xor 0x01).toByte() }
            assertSourceFailure { LlvmOpenPgpVerifier.inspectArchiveSignature(mutation) }
        }
    }

    @Test
    fun `archive signature streaming enforces length digest progress and absolute safety bounds before trust`() {
        val key = checkedSigningKey()
        val signature = Base64.getDecoder().decode(FROZEN_ARCHIVE_SIGNATURE_BASE64)
        val content = "bounded unsigned input".toByteArray()

        assertSourceFailure {
            LlvmOpenPgpVerifier.verifyArchiveSignature(key, signature, ByteArrayInputStream(content), 0, OracleArtifacts.sha256(content))
        }
        assertSourceFailure {
            LlvmOpenPgpVerifier.verifyArchiveSignature(
                key,
                signature,
                ByteArrayInputStream(content),
                512L * 1024 * 1024 + 1,
                OracleArtifacts.sha256(content),
            )
        }
        assertSourceFailure {
            LlvmOpenPgpVerifier.verifyArchiveSignature(
                key,
                signature,
                ByteArrayInputStream(content),
                content.size.toLong() + 1,
                OracleArtifacts.sha256(content),
            )
        }
        assertSourceFailure {
            LlvmOpenPgpVerifier.verifyArchiveSignature(
                key,
                signature,
                ByteArrayInputStream(content),
                content.size.toLong() - 1,
                OracleArtifacts.sha256(content.copyOf(content.size - 1)),
            )
        }
        assertSourceFailure {
            LlvmOpenPgpVerifier.verifyArchiveSignature(
                key,
                signature,
                ByteArrayInputStream(content),
                content.size.toLong(),
                "0".repeat(64),
            )
        }
        val stalled = object : java.io.InputStream() {
            override fun read(): Int = -1
            override fun read(bytes: ByteArray, offset: Int, length: Int): Int = 0
        }
        assertSourceFailure {
            LlvmOpenPgpVerifier.verifyArchiveSignature(
                key,
                signature,
                stalled,
                content.size.toLong(),
                OracleArtifacts.sha256(content),
            )
        }
        assertSourceFailure {
            LlvmOpenPgpVerifier.verifyArchiveSignature(
                key,
                ByteArray(65_537),
                ByteArrayInputStream(content),
                content.size.toLong(),
                OracleArtifacts.sha256(content),
            )
        }
    }

    @Test
    fun `optional frozen real archive verifies twice with identical bounded evidence`() {
        val configured = System.getenv("DECOMP_LLVM_SOURCE_ARCHIVE")?.takeIf(String::isNotBlank)?.let(Path::of)
        assumeTrue(configured != null && Files.isRegularFile(configured), "set DECOMP_LLVM_SOURCE_ARCHIVE to the frozen archive")
        val archive = requireNotNull(configured)
        val lock = LlvmSourceLockVerifier().verify(CHECKED_LOCK)
        val signatureBytes = System.getenv("DECOMP_LLVM_SOURCE_SIGNATURE")
            ?.takeIf(String::isNotBlank)
            ?.let(Path::of)
            ?.also { assumeTrue(Files.isRegularFile(it), "configured detached signature is unavailable") }
            ?.let(Files::readAllBytes)
            ?: Base64.getDecoder().decode(FROZEN_ARCHIVE_SIGNATURE_BASE64)

        fun verifyOnce() = Files.newInputStream(archive).use { input ->
            LlvmOpenPgpVerifier.verifyArchiveSignature(
                lock.signingKey,
                signatureBytes,
                input,
                lock.archive.bytes,
                lock.archive.sha256,
            )
        }

        val first = verifyOnce()
        val second = verifyOnce()
        assertEquals(first, second)
        assertEquals(167_043_464L, first.bytes)
        assertEquals("6e0b376a1f6d9873e7dfb09ae6e04b9c7024400f01733fa4c29be69d5c138bc2", first.sha256)
        val corruptedSignature = signatureBytes.copyOf().also {
            it[it.lastIndex] = (it.last().toInt() xor 0x01).toByte()
        }
        assertSourceFailure {
            Files.newInputStream(archive).use { input ->
                LlvmOpenPgpVerifier.verifyArchiveSignature(
                    lock.signingKey,
                    corruptedSignature,
                    input,
                    lock.archive.bytes,
                    lock.archive.sha256,
                )
            }
        }
    }

    @Test
    fun `input drift after verification fails instead of returning mixed evidence`() {
        withFixture { fixture ->
            var changed = false
            val verifier = LlvmSourceLockVerifier(
                LlvmSourceLockFaultInjector { point ->
                    if (!changed && point == LlvmSourceLockVerificationPoint.AFTER_LOCAL_EVIDENCE_VERIFIED) {
                        changed = true
                        Files.write(
                            fixture.root.resolve(PAYLOAD_RELATIVE),
                            Files.readAllBytes(fixture.root.resolve(PAYLOAD_RELATIVE)) + byteArrayOf(0),
                        )
                    }
                },
            )
            val failure = assertSourceFailure { verifier.verify(fixture.lockPath) }
            assertTrue(changed)
            assertTrue(failure.message.orEmpty().contains("changed during verification"))
        }
    }

    @Test
    fun `checked metadata agrees with retained Python and Kotlin is deliberately stricter`() {
        assertEquals(0, runPythonMetadata(CHECKED_LOCK))

        withFixture { fixture ->
            fixture.updateLock { root ->
                root.sourceTestUpdate("revision") { revision ->
                    revision.sourceTestWith("tagObject", JsonPrimitive("1".repeat(40)))
                }
            }
            assertEquals(0, runPythonMetadata(fixture.lockPath), "legacy Python does not reconstruct the tag object")
            assertSourceFailure { fixture.verify() }
        }
        withFixture { fixture ->
            Files.write(fixture.lockPath, Files.readAllBytes(fixture.lockPath) + byteArrayOf('\n'.code.toByte()))
            assertEquals(0, runPythonMetadata(fixture.lockPath), "legacy Python accepts noncanonical JSON whitespace")
            assertSourceFailure { fixture.verify() }
        }
    }

    @Test
    fun `dependency surface pins lightweight OpenPGP libraries without registering a provider`() {
        val build = Files.readString(Path.of("build.gradle.kts"))
        assertTrue(build.contains("org.bouncycastle:bcpg-jdk18on:1.85"))
        assertTrue(build.contains("org.bouncycastle:bcutil-jdk18on:1.85"))
        assertTrue(build.contains("org.bouncycastle:bcprov-jdk18on"))
        assertTrue(build.contains("strictly(\"1.85.2\")"))
        val production = Files.readString(Path.of("src/main/kotlin/decompengine/oracle/provenance/LlvmOpenPgp.kt"))
        assertTrue(production.contains("BcPGPContentVerifierBuilderProvider"))
        assertFalse(production.contains("Security.addProvider"))
        assertFalse(production.contains("PGPUtil.setDefaultProvider"))
    }

    private fun checkedSigningKey(): VerifiedLlvmSigningKey {
        val keyBytes = Files.readAllBytes(CHECKED_PROFILE.resolve(KEY_RELATIVE))
        return LlvmOpenPgpVerifier.verifyVendoredSigningKey(
            keyBytes,
            "FFB3368980F3E6BB5737145A316C56D064CACBA5",
            "FFB3368980F3E6BB5737145A316C56D064CACBA5",
        )
    }

    private fun withFixture(action: (MutableLlvmSourceFixture) -> Unit) {
        val root = privateDirectory(createTempDirectory("llvm-source-lock-kotlin-"))
        try {
            action(MutableLlvmSourceFixture(root))
        } finally {
            deleteTree(root)
        }
    }
}

private class MutableLlvmSourceFixture(val root: Path) {
    val lockPath = root.resolve("source-lock.json")

    init {
        privateDirectory(root.resolve("keys"))
        privateDirectory(root.resolve("tag"))
        Files.copy(CHECKED_LOCK, lockPath, StandardCopyOption.REPLACE_EXISTING)
        Files.copy(CHECKED_PROFILE.resolve(KEY_RELATIVE), root.resolve(KEY_RELATIVE), StandardCopyOption.REPLACE_EXISTING)
        Files.copy(CHECKED_PROFILE.resolve(PAYLOAD_RELATIVE), root.resolve(PAYLOAD_RELATIVE), StandardCopyOption.REPLACE_EXISTING)
        Files.copy(
            CHECKED_PROFILE.resolve(TAG_SIGNATURE_RELATIVE),
            root.resolve(TAG_SIGNATURE_RELATIVE),
            StandardCopyOption.REPLACE_EXISTING,
        )
    }

    fun verify(): LlvmSourceLockVerification = LlvmSourceLockVerifier().verify(lockPath)

    fun updateLock(transform: (JsonObject) -> JsonObject) {
        val root = OracleJson.parseCanonical(Files.readAllBytes(lockPath)) as JsonObject
        Files.write(lockPath, OracleJson.canonicalBytes(transform(root)))
    }

    fun rebindTagEvidence(prefix: String, path: Path) {
        val bytes = Files.readAllBytes(path)
        updateLock { root ->
            root.sourceTestUpdate("revision") { revision ->
                revision.sourceTestUpdate("tagEvidence") { evidence ->
                    evidence.sourceTestWith("${prefix}Bytes", JsonPrimitive(bytes.size))
                        .sourceTestWith("${prefix}Sha256", JsonPrimitive(OracleArtifacts.sha256(bytes)))
                }
            }
        }
    }
}

private fun parseKeyRing(armored: ByteArray): PGPPublicKeyRing {
    val factory = BcPGPObjectFactory(ArmoredInputStream(ByteArrayInputStream(armored)))
    return factory.nextObject() as PGPPublicKeyRing
}

private fun decodeArmor(armored: ByteArray): ByteArray =
    ArmoredInputStream(ByteArrayInputStream(armored)).use { it.readAllBytes() }

private fun armor(binary: ByteArray): ByteArray {
    val output = ByteArrayOutputStream()
    ArmoredOutputStream.builder().clearHeaders().build(output).use { it.write(binary) }
    return output.toByteArray()
}

private fun ByteArray.replaceLfWithCrLf(): ByteArray = buildList<Byte>(size * 2) {
    this@replaceLfWithCrLf.forEach { byte ->
        if (byte == '\n'.code.toByte()) add('\r'.code.toByte())
        add(byte)
    }
}.toByteArray()

private fun ByteArray.indexOfSequence(needle: ByteArray): Int {
    for (start in 0..size - needle.size) {
        if (needle.indices.all { this[start + it] == needle[it] }) return start
    }
    error("test sequence is absent")
}

private fun runPythonMetadata(lock: Path): Int {
    val process = ProcessBuilder(
        "python3",
        "scripts/verify-llvm-oracle-source.py",
        "--metadata-only",
        "--lock",
        lock.toAbsolutePath().toString(),
    ).redirectErrorStream(true).start()
    process.inputStream.readAllBytes()
    assertTrue(process.waitFor(30, java.util.concurrent.TimeUnit.SECONDS), "legacy Python verifier timed out")
    return process.exitValue()
}

private fun assertSourceFailure(action: () -> Unit): LlvmSourceProvenanceException =
    assertFailsWith<LlvmSourceProvenanceException> { action() }

private fun JsonObject.sourceTestUpdate(name: String, transform: (JsonObject) -> JsonObject): JsonObject =
    sourceTestWith(name, transform(getValue(name) as JsonObject))

private fun JsonObject.sourceTestWith(name: String, value: JsonElement): JsonObject =
    JsonObject(toMutableMap().apply { this[name] = value })

private val CHECKED_PROFILE = Path.of("oracle/llvm/22.1.6")
private val CHECKED_LOCK = CHECKED_PROFILE.resolve("source-lock.json")
private const val KEY_RELATIVE = "keys/douglas-yung-llvm-release.asc"
private const val PAYLOAD_RELATIVE = "tag/llvmorg-22.1.6.payload"
private const val TAG_SIGNATURE_RELATIVE = "tag/llvmorg-22.1.6.sig"
private const val REVIEWED_USER_ID = "Douglas Yung <douglas.yung@sony.com>"
private const val FROZEN_ARCHIVE_SIGNATURE_BASE64 =
    "iHUEABYKAB0WIQT/szaJgPPmu1c3FFoxbFbQZMrLpQUCag44EAAKCRAxbFbQZMrLpcKQAQCQzzlChOdV19dNNMFY7R6JEyXi1I1VNh7Hqu08+Dkz0AD/eHDRL6sp5cSh58IK/qZfv0klO7joFolz1rjCExhNoQw="
