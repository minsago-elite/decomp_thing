package decompengine.oracle.provenance

import java.io.ByteArrayInputStream
import java.io.InputStream
import java.nio.ByteBuffer
import java.nio.charset.CodingErrorAction
import java.nio.charset.StandardCharsets
import java.security.MessageDigest
import org.bouncycastle.bcpg.ArmoredInputStream
import org.bouncycastle.bcpg.BCPGInputStream
import org.bouncycastle.bcpg.ECDHPublicBCPGKey
import org.bouncycastle.bcpg.EdDSAPublicBCPGKey
import org.bouncycastle.bcpg.HashAlgorithmTags
import org.bouncycastle.bcpg.PacketTags
import org.bouncycastle.bcpg.PublicKeyAlgorithmTags
import org.bouncycastle.bcpg.SignatureSubpacketTags
import org.bouncycastle.bcpg.sig.KeyFlags
import org.bouncycastle.openpgp.PGPObjectFactory
import org.bouncycastle.openpgp.PGPPublicKey
import org.bouncycastle.openpgp.PGPPublicKeyRing
import org.bouncycastle.openpgp.PGPSignature
import org.bouncycastle.openpgp.PGPSignatureList
import org.bouncycastle.openpgp.PGPSignatureSubpacketVector
import org.bouncycastle.openpgp.bc.BcPGPObjectFactory
import org.bouncycastle.openpgp.operator.bc.BcPGPContentVerifierBuilderProvider

internal class VerifiedLlvmSigningKey internal constructor(
    internal val primaryKey: PGPPublicKey,
    val primaryFingerprint: String,
    val primaryKeyId: String,
    val encryptionSubkeyFingerprint: String,
    val encryptionSubkeyId: String,
)

internal data class LlvmDetachedSignatureProfile(
    val creationEpochSeconds: Long,
    val signerFingerprint: String,
    val signerKeyId: String,
)

internal data class LlvmArchiveSignatureVerification(
    val bytes: Long,
    val sha256: String,
    val signerFingerprint: String,
    val signatureCreationEpochSeconds: Long,
)

/**
 * Offline verifier for the reviewed LLVM release key and its two exact detached-signature profiles.
 *
 * This intentionally uses Bouncy Castle's lightweight operators. It never registers a JVM provider,
 * opens a key store, performs key discovery, or accepts a generic OpenPGP message container.
 */
internal object LlvmOpenPgpVerifier {
    fun verifyVendoredSigningKey(
        armoredKey: ByteArray,
        expectedPrimaryFingerprint: String,
        expectedSigningFingerprint: String,
    ): VerifiedLlvmSigningKey = openPgpOperation("vendored LLVM signing key") {
        requireBoundedBytes(armoredKey, MAXIMUM_OPENPGP_EVIDENCE_BYTES, "vendored LLVM signing key")
        requireFingerprint(expectedPrimaryFingerprint, "locked primary fingerprint")
        requireFingerprint(expectedSigningFingerprint, "locked signing fingerprint")
        if (expectedPrimaryFingerprint != expectedSigningFingerprint) {
            openPgpFail("LLVM signing fingerprint must identify the reviewed primary key")
        }

        val objects = parseArmoredObjects(
            armoredKey,
            begin = "-----BEGIN PGP PUBLIC KEY BLOCK-----",
            end = "-----END PGP PUBLIC KEY BLOCK-----",
            expectedPacketTags = listOf(
                PacketTags.PUBLIC_KEY,
                PacketTags.USER_ID,
                PacketTags.SIGNATURE,
                PacketTags.PUBLIC_SUBKEY,
                PacketTags.SIGNATURE,
            ),
            label = "vendored LLVM signing key",
        )
        if (objects.size != 1 || objects.single() !is PGPPublicKeyRing) {
            openPgpFail("vendored LLVM signing key must contain exactly one public keyring")
        }
        val ring = objects.single() as PGPPublicKeyRing
        val keys = ring.publicKeys.asSequence().toList()
        if (keys.size != 2) {
            openPgpFail("vendored LLVM signing key must contain one primary key and one subkey")
        }
        val primary = keys[0]
        val subkey = keys[1]
        verifyPrimaryKey(primary, expectedPrimaryFingerprint)
        verifyEncryptionSubkey(primary, subkey)

        VerifiedLlvmSigningKey(
            primaryKey = primary,
            primaryFingerprint = fingerprint(primary),
            primaryKeyId = keyId(primary.keyID),
            encryptionSubkeyFingerprint = fingerprint(subkey),
            encryptionSubkeyId = keyId(subkey.keyID),
        )
    }

    fun verifyTagSignature(
        key: VerifiedLlvmSigningKey,
        payload: ByteArray,
        armoredSignature: ByteArray,
    ): LlvmDetachedSignatureProfile = openPgpOperation("LLVM annotated-tag signature") {
        requireBoundedBytes(payload, MAXIMUM_OPENPGP_EVIDENCE_BYTES, "LLVM annotated-tag payload")
        requireBoundedBytes(
            armoredSignature,
            MAXIMUM_OPENPGP_EVIDENCE_BYTES,
            "LLVM annotated-tag signature",
        )
        val objects = parseArmoredObjects(
            armoredSignature,
            begin = "-----BEGIN PGP SIGNATURE-----",
            end = "-----END PGP SIGNATURE-----",
            expectedPacketTags = listOf(PacketTags.SIGNATURE),
            label = "LLVM annotated-tag signature",
        )
        val signature = requireSingleSignature(objects, "LLVM annotated-tag signature")
        val profile = verifyDocumentSignatureProfile(
            signature = signature,
            expectedCreationEpochSeconds = TAG_SIGNATURE_EPOCH_SECONDS,
            requireSignerUserId = true,
            label = "LLVM annotated-tag signature",
        )
        signature.init(VERIFIER_PROVIDER, key.primaryKey)
        signature.update(payload)
        if (!signature.verify()) openPgpFail("LLVM annotated-tag signature is cryptographically invalid")
        profile
    }

    /** Checks packet/profile identity only; archive authority requires [verifyArchiveSignature]. */
    fun inspectArchiveSignature(binarySignature: ByteArray): LlvmDetachedSignatureProfile =
        openPgpOperation("LLVM source archive signature") {
            requireBoundedBytes(
                binarySignature,
                MAXIMUM_OPENPGP_EVIDENCE_BYTES,
                "LLVM source archive signature",
            )
            val signature = requireSingleSignature(
                parseBinaryObjects(
                    binarySignature,
                    listOf(PacketTags.SIGNATURE),
                    "LLVM source archive signature",
                ),
                "LLVM source archive signature",
            )
            verifyDocumentSignatureProfile(
                signature = signature,
                expectedCreationEpochSeconds = ARCHIVE_SIGNATURE_EPOCH_SECONDS,
                requireSignerUserId = false,
                label = "LLVM source archive signature",
            )
        }

    /** Streams and verifies the exact compressed archive bytes without materializing them in memory. */
    fun verifyArchiveSignature(
        key: VerifiedLlvmSigningKey,
        binarySignature: ByteArray,
        archive: InputStream,
        expectedBytes: Long,
        expectedSha256: String,
    ): LlvmArchiveSignatureVerification = openPgpOperation("LLVM source archive signature") {
        if (expectedBytes !in 1L..MAXIMUM_SOURCE_ARCHIVE_BYTES) {
            openPgpFail("LLVM source archive byte length is outside the supported bound")
        }
        if (!expectedSha256.matches(SHA256)) openPgpFail("LLVM source archive SHA-256 is invalid")
        requireBoundedBytes(
            binarySignature,
            MAXIMUM_OPENPGP_EVIDENCE_BYTES,
            "LLVM source archive signature",
        )
        val signature = requireSingleSignature(
            parseBinaryObjects(
                binarySignature,
                listOf(PacketTags.SIGNATURE),
                "LLVM source archive signature",
            ),
            "LLVM source archive signature",
        )
        val profile = verifyDocumentSignatureProfile(
            signature = signature,
            expectedCreationEpochSeconds = ARCHIVE_SIGNATURE_EPOCH_SECONDS,
            requireSignerUserId = false,
            label = "LLVM source archive signature",
        )
        signature.init(VERIFIER_PROVIDER, key.primaryKey)
        val digest = MessageDigest.getInstance("SHA-256")
        val buffer = ByteArray(STREAM_BUFFER_BYTES)
        var total = 0L
        while (total < expectedBytes) {
            val requested = minOf(buffer.size.toLong(), expectedBytes - total).toInt()
            val count = archive.read(buffer, 0, requested)
            if (count < 0) openPgpFail("LLVM source archive ended before its locked byte length")
            if (count == 0) openPgpFail("LLVM source archive stream made no progress")
            digest.update(buffer, 0, count)
            signature.update(buffer, 0, count)
            total = Math.addExact(total, count.toLong())
        }
        if (archive.read() >= 0) openPgpFail("LLVM source archive exceeds its locked byte length")
        val observedSha256 = digest.digest().toLowerHex()
        if (observedSha256 != expectedSha256) {
            openPgpFail("LLVM source archive SHA-256 differs from its lock")
        }
        if (!signature.verify()) openPgpFail("LLVM source archive signature is cryptographically invalid")
        LlvmArchiveSignatureVerification(
            bytes = total,
            sha256 = observedSha256,
            signerFingerprint = profile.signerFingerprint,
            signatureCreationEpochSeconds = profile.creationEpochSeconds,
        )
    }

    private fun verifyPrimaryKey(primary: PGPPublicKey, expectedFingerprint: String) {
        if (!primary.isMasterKey) openPgpFail("reviewed LLVM primary key is not a primary key")
        if (primary.version != OPENPGP_V4 || primary.algorithm != PublicKeyAlgorithmTags.EDDSA_LEGACY) {
            openPgpFail("reviewed LLVM primary key must be a v4 legacy Ed25519 key")
        }
        val packet = primary.publicKeyPacket.key
        if (packet !is EdDSAPublicBCPGKey || packet.curveOID.id != LEGACY_ED25519_OID) {
            openPgpFail("reviewed LLVM primary key curve is not legacy Ed25519")
        }
        if (
            fingerprint(primary) != REVIEWED_PRIMARY_FINGERPRINT ||
            fingerprint(primary) != expectedFingerprint ||
            keyId(primary.keyID) != REVIEWED_PRIMARY_KEY_ID
        ) {
            openPgpFail("reviewed LLVM primary key fingerprint or key ID differs")
        }
        if (epochSeconds(primary.creationTime.time) != KEY_CREATION_EPOCH_SECONDS || primary.validSeconds != 0L) {
            openPgpFail("reviewed LLVM primary key creation or expiry differs")
        }
        if (primary.hasRevocation()) {
            openPgpFail("reviewed LLVM primary key is revoked")
        }
        if (primary.trustData != null) openPgpFail("reviewed LLVM primary key contains trust packets")
        val userIds = primary.userIDs.asSequence().toList()
        if (userIds != listOf(REVIEWED_USER_ID)) {
            openPgpFail("reviewed LLVM primary key must contain its sole locked user ID")
        }
        if (primary.userAttributes.asSequence().any()) {
            openPgpFail("reviewed LLVM primary key must not contain user attributes")
        }
        val allSignatures = primary.signatures.asSequence().toList()
        val certifications = primary.getSignaturesForID(REVIEWED_USER_ID).asSequence().toList()
        if (allSignatures.size != 1 || certifications.size != 1 || allSignatures.single() !== certifications.single()) {
            openPgpFail("reviewed LLVM primary key must contain exactly one self-certification")
        }
        val selfCertification = certifications.single()
        verifyCertificationProfile(
            selfCertification,
            expectedType = PGPSignature.POSITIVE_CERTIFICATION,
            expectedFlags = KeyFlags.CERTIFY_OTHER or KeyFlags.SIGN_DATA,
            expectedHashedTags = SELF_CERTIFICATION_HASHED_TAGS,
            expectedHashedData = SELF_CERTIFICATION_HASHED_DATA,
            label = "reviewed LLVM primary self-certification",
        )
        selfCertification.init(VERIFIER_PROVIDER, primary)
        if (!selfCertification.verifyCertification(REVIEWED_USER_ID, primary)) {
            openPgpFail("reviewed LLVM primary self-certification is cryptographically invalid")
        }
    }

    private fun verifyEncryptionSubkey(primary: PGPPublicKey, subkey: PGPPublicKey) {
        if (subkey.isMasterKey) openPgpFail("reviewed LLVM encryption subkey is marked primary")
        if (subkey.version != OPENPGP_V4 || subkey.algorithm != PublicKeyAlgorithmTags.ECDH) {
            openPgpFail("reviewed LLVM encryption subkey must be a v4 cv25519 ECDH key")
        }
        val packet = subkey.publicKeyPacket.key
        if (packet !is ECDHPublicBCPGKey || packet.curveOID.id != LEGACY_CV25519_OID) {
            openPgpFail("reviewed LLVM encryption subkey curve is not cv25519")
        }
        if (
            fingerprint(subkey) != REVIEWED_ENCRYPTION_SUBKEY_FINGERPRINT ||
            keyId(subkey.keyID) != REVIEWED_ENCRYPTION_SUBKEY_ID
        ) {
            openPgpFail("reviewed LLVM encryption subkey fingerprint or key ID differs")
        }
        if (epochSeconds(subkey.creationTime.time) != KEY_CREATION_EPOCH_SECONDS || subkey.validSeconds != 0L) {
            openPgpFail("reviewed LLVM encryption subkey creation or expiry differs")
        }
        if (!subkey.isEncryptionKey || subkey.hasRevocation()) {
            openPgpFail("reviewed LLVM encryption subkey capabilities or revocation state differ")
        }
        if (subkey.trustData != null) openPgpFail("reviewed LLVM encryption subkey contains trust packets")
        if (subkey.userIDs.asSequence().any() || subkey.userAttributes.asSequence().any()) {
            openPgpFail("reviewed LLVM encryption subkey contains user identities")
        }
        val signatures = subkey.signatures.asSequence().toList()
        if (signatures.size != 1) {
            openPgpFail("reviewed LLVM encryption subkey must contain exactly one binding signature")
        }
        val binding = signatures.single()
        verifyCertificationProfile(
            binding,
            expectedType = PGPSignature.SUBKEY_BINDING,
            expectedFlags = KeyFlags.ENCRYPT_COMMS or KeyFlags.ENCRYPT_STORAGE,
            expectedHashedTags = SUBKEY_BINDING_HASHED_TAGS,
            expectedHashedData = SUBKEY_BINDING_HASHED_DATA,
            label = "reviewed LLVM subkey binding",
        )
        binding.init(VERIFIER_PROVIDER, primary)
        if (!binding.verifyCertification(primary, subkey)) {
            openPgpFail("reviewed LLVM subkey binding is cryptographically invalid")
        }
    }

    private fun verifyCertificationProfile(
        signature: PGPSignature,
        expectedType: Int,
        expectedFlags: Int,
        expectedHashedTags: List<Int>,
        expectedHashedData: Map<Int, String>,
        label: String,
    ) {
        requireCommonSignatureFields(signature, expectedType, KEY_CREATION_EPOCH_SECONDS, label)
        val hashed = signature.hashedSubPackets ?: openPgpFail("$label lacks hashed subpackets")
        val unhashed = signature.unhashedSubPackets ?: openPgpFail("$label lacks unhashed subpackets")
        requireExactSubpacketTags(hashed, expectedHashedTags, "$label hashed subpackets")
        val observedHashedData = hashed.toArray().associate { it.type to it.data.toLowerHex() }
        if (observedHashedData != expectedHashedData) {
            openPgpFail("$label hashed subpacket values differ from the reviewed profile")
        }
        requireExactSubpacketTags(unhashed, listOf(SignatureSubpacketTags.ISSUER_KEY_ID), "$label unhashed subpackets")
        requireIssuerFingerprint(hashed, label)
        if (hashed.getSubpackets(SignatureSubpacketTags.KEY_FLAGS).size != 1 || hashed.keyFlags != expectedFlags) {
            openPgpFail("$label key flags differ")
        }
        requireSoleUnhashedIssuer(unhashed, label)
        if (signature.keyID != REVIEWED_PRIMARY_KEY_ID_LONG) openPgpFail("$label signer key ID differs")
    }

    private fun verifyDocumentSignatureProfile(
        signature: PGPSignature,
        expectedCreationEpochSeconds: Long,
        requireSignerUserId: Boolean,
        label: String,
    ): LlvmDetachedSignatureProfile {
        requireCommonSignatureFields(
            signature,
            PGPSignature.BINARY_DOCUMENT,
            expectedCreationEpochSeconds,
            label,
        )
        val hashed = signature.hashedSubPackets ?: openPgpFail("$label lacks hashed subpackets")
        val unhashed = signature.unhashedSubPackets ?: openPgpFail("$label lacks unhashed subpackets")
        val expectedHashed = if (requireSignerUserId) {
            listOf(
                SignatureSubpacketTags.ISSUER_FINGERPRINT,
                SignatureSubpacketTags.CREATION_TIME,
                SignatureSubpacketTags.SIGNER_USER_ID,
            )
        } else {
            listOf(SignatureSubpacketTags.ISSUER_FINGERPRINT, SignatureSubpacketTags.CREATION_TIME)
        }
        requireExactSubpacketTags(hashed, expectedHashed, "$label hashed subpackets")
        requireExactSubpacketTags(unhashed, listOf(SignatureSubpacketTags.ISSUER_KEY_ID), "$label unhashed subpackets")
        requireIssuerFingerprint(hashed, label)
        requireSoleUnhashedIssuer(unhashed, label)
        if (signature.keyID != REVIEWED_PRIMARY_KEY_ID_LONG) openPgpFail("$label signer key ID differs")
        if (requireSignerUserId) {
            if (
                hashed.getSubpackets(SignatureSubpacketTags.SIGNER_USER_ID).size != 1 ||
                hashed.signerUserID != REVIEWED_TAG_SIGNER_USER_ID
            ) {
                openPgpFail("$label signer user ID differs")
            }
        } else if (hashed.hasSubpacket(SignatureSubpacketTags.SIGNER_USER_ID)) {
            openPgpFail("$label unexpectedly contains a signer user ID")
        }
        return LlvmDetachedSignatureProfile(
            creationEpochSeconds = expectedCreationEpochSeconds,
            signerFingerprint = REVIEWED_PRIMARY_FINGERPRINT,
            signerKeyId = REVIEWED_PRIMARY_KEY_ID,
        )
    }

    private fun requireCommonSignatureFields(
        signature: PGPSignature,
        expectedType: Int,
        expectedCreationEpochSeconds: Long,
        label: String,
    ) {
        if (
            signature.version != OPENPGP_V4 ||
            signature.signatureType != expectedType ||
            signature.keyAlgorithm != PublicKeyAlgorithmTags.EDDSA_LEGACY ||
            signature.hashAlgorithm != HashAlgorithmTags.SHA512
        ) {
            openPgpFail("$label version, type, public-key algorithm, or hash algorithm differs")
        }
        if (epochSeconds(signature.creationTime.time) != expectedCreationEpochSeconds) {
            openPgpFail("$label creation time differs")
        }
    }

    private fun requireIssuerFingerprint(hashed: PGPSignatureSubpacketVector, label: String) {
        if (hashed.getSubpackets(SignatureSubpacketTags.ISSUER_FINGERPRINT).size != 1) {
            openPgpFail("$label must contain exactly one hashed issuer fingerprint")
        }
        val issuer = hashed.issuerFingerprint ?: openPgpFail("$label lacks a hashed issuer fingerprint")
        if (issuer.keyVersion != OPENPGP_V4 || issuer.fingerprint.toHex() != REVIEWED_PRIMARY_FINGERPRINT) {
            openPgpFail("$label issuer fingerprint differs")
        }
        if (hashed.hasSubpacket(SignatureSubpacketTags.ISSUER_KEY_ID)) {
            openPgpFail("$label issuer key ID must not be hashed")
        }
    }

    private fun requireSoleUnhashedIssuer(unhashed: PGPSignatureSubpacketVector, label: String) {
        if (
            unhashed.getSubpackets(SignatureSubpacketTags.ISSUER_KEY_ID).size != 1 ||
            unhashed.issuerKeyID != REVIEWED_PRIMARY_KEY_ID_LONG
        ) {
            openPgpFail("$label must contain the sole locked unhashed issuer key ID")
        }
    }

    private fun requireExactSubpacketTags(
        vector: PGPSignatureSubpacketVector,
        expected: List<Int>,
        label: String,
    ) {
        val packets = vector.toArray().toList()
        if (packets.map { it.type } != expected || packets.any { it.isCritical || it.isLongLength }) {
            openPgpFail("$label differ from the reviewed closed profile")
        }
    }

    private fun requireSingleSignature(objects: List<Any>, label: String): PGPSignature {
        if (objects.size != 1 || objects.single() !is PGPSignatureList) {
            openPgpFail("$label must contain exactly one signature packet and no other objects")
        }
        val signatures = objects.single() as PGPSignatureList
        if (signatures.size() != 1) openPgpFail("$label must contain exactly one signature packet")
        return signatures[0]
    }

    private fun parseArmoredObjects(
        bytes: ByteArray,
        begin: String,
        end: String,
        expectedPacketTags: List<Int>,
        label: String,
    ): List<Any> {
        requireCanonicalArmor(bytes, begin, end, label)
        val raw = ByteArrayInputStream(bytes)
        val armored = ArmoredInputStream(raw)
        if (armored.armorHeaderLine != begin || armored.armorHeaders != null || armored.isClearText) {
            openPgpFail("$label armor header differs from the closed profile")
        }
        val decoded = armored.readAllBytes()
        if (raw.available() != 0) openPgpFail("$label has trailing armored data")
        requireExactPacketTags(decoded, expectedPacketTags, label)
        return parseObjects(BcPGPObjectFactory(decoded), label)
    }

    private fun parseBinaryObjects(bytes: ByteArray, expectedPacketTags: List<Int>, label: String): List<Any> {
        requireExactPacketTags(bytes, expectedPacketTags, label)
        return parseObjects(BcPGPObjectFactory(bytes), label)
    }

    private fun requireExactPacketTags(bytes: ByteArray, expected: List<Int>, label: String) {
        val input = BCPGInputStream(ByteArrayInputStream(bytes))
        val observed = ArrayList<Int>(expected.size + 1)
        while (true) {
            val tag = input.nextPacketTag()
            if (tag < 0) break
            if (observed.size == expected.size) openPgpFail("$label contains extra OpenPGP packets")
            observed += tag
            input.readPacket() ?: openPgpFail("$label contains an unreadable OpenPGP packet")
        }
        if (observed != expected) openPgpFail("$label packet sequence differs from the reviewed profile")
    }

    private fun parseObjects(factory: PGPObjectFactory, label: String): List<Any> {
        factory.setThrowForUnknownCriticalPackets(true)
        val objects = ArrayList<Any>(2)
        while (true) {
            val next = factory.nextObject() ?: break
            if (objects.size == MAXIMUM_OPENPGP_OBJECTS) openPgpFail("$label contains too many OpenPGP objects")
            objects += next
        }
        return objects
    }

    private fun requireCanonicalArmor(bytes: ByteArray, begin: String, end: String, label: String) {
        val text = decodeAscii(bytes, label)
        if ('\r' in text || !text.endsWith('\n')) openPgpFail("$label armor must use canonical LF line endings")
        val lines = text.split('\n')
        if (
            lines.size < 6 || lines.first() != begin || lines[1].isNotEmpty() ||
            lines[lines.lastIndex - 1] != end || lines.last().isNotEmpty()
        ) {
            openPgpFail("$label armor framing differs from the closed profile")
        }
        val encoded = lines.subList(2, lines.lastIndex - 1)
        val dataLines = encoded.dropLast(1)
        if (
            encoded.size < 2 || !encoded.last().matches(ARMOR_CRC) ||
            dataLines.any { it.isEmpty() || it.length > 64 || !it.matches(ARMOR_DATA) } ||
            dataLines.dropLast(1).any { it.length != 64 || '=' in it }
        ) {
            openPgpFail("$label armor body differs from the closed profile")
        }
    }

    private fun decodeAscii(bytes: ByteArray, label: String): String = try {
        StandardCharsets.US_ASCII.newDecoder()
            .onMalformedInput(CodingErrorAction.REPORT)
            .onUnmappableCharacter(CodingErrorAction.REPORT)
            .decode(ByteBuffer.wrap(bytes))
            .toString()
    } catch (failure: Exception) {
        throw LlvmSourceProvenanceException("$label armor is not ASCII", failure)
    }

    private fun requireBoundedBytes(bytes: ByteArray, maximumBytes: Int, label: String) {
        if (bytes.isEmpty() || bytes.size > maximumBytes) {
            openPgpFail("$label byte length is outside the supported bound")
        }
    }

    private fun requireFingerprint(value: String, label: String) {
        if (!value.matches(FINGERPRINT)) openPgpFail("$label is invalid")
    }

    private fun fingerprint(key: PGPPublicKey): String = key.fingerprint.toHex()

    private fun keyId(value: Long): String = java.lang.Long.toUnsignedString(value, 16).uppercase().padStart(16, '0')

    private fun epochSeconds(milliseconds: Long): Long {
        if (milliseconds % 1000L != 0L) openPgpFail("OpenPGP timestamp is not integral seconds")
        return milliseconds / 1000L
    }

    private inline fun <T> openPgpOperation(label: String, action: () -> T): T = try {
        action()
    } catch (failure: LlvmSourceProvenanceException) {
        throw failure
    } catch (failure: Exception) {
        throw LlvmSourceProvenanceException("cannot verify $label", failure)
    }

    private val VERIFIER_PROVIDER = BcPGPContentVerifierBuilderProvider()
    private val FINGERPRINT = Regex("[0-9A-F]{40}")
    private val SHA256 = Regex("[0-9a-f]{64}")
    private val ARMOR_DATA = Regex("[A-Za-z0-9+/]+={0,2}")
    private val ARMOR_CRC = Regex("=[A-Za-z0-9+/]{4}")
    private val SELF_CERTIFICATION_HASHED_TAGS = listOf(33, 2, 27, 11, 34, 21, 22, 30, 23)
    private val SELF_CERTIFICATION_HASHED_DATA = linkedMapOf(
        33 to "04ffb3368980f3e6bb5737145a316c56d064cacba5",
        2 to "68c83684",
        27 to "03",
        11 to "09080702",
        34 to "02",
        21 to "0a09080b02",
        22 to "020301",
        30 to "07",
        23 to "80",
    )
    private val SUBKEY_BINDING_HASHED_TAGS = listOf(33, 2, 27)
    private val SUBKEY_BINDING_HASHED_DATA = linkedMapOf(
        33 to "04ffb3368980f3e6bb5737145a316c56d064cacba5",
        2 to "68c83684",
        27 to "0c",
    )
    private const val MAXIMUM_OPENPGP_OBJECTS = 2
    private const val MAXIMUM_OPENPGP_EVIDENCE_BYTES = 64 * 1024
    private const val MAXIMUM_SOURCE_ARCHIVE_BYTES = 512L * 1024 * 1024
    private const val STREAM_BUFFER_BYTES = 1024 * 1024
    private const val OPENPGP_V4 = 4
    private const val REVIEWED_PRIMARY_FINGERPRINT = "FFB3368980F3E6BB5737145A316C56D064CACBA5"
    private const val REVIEWED_PRIMARY_KEY_ID = "316C56D064CACBA5"
    private const val REVIEWED_PRIMARY_KEY_ID_LONG = 0x316C56D064CACBA5L
    private const val REVIEWED_ENCRYPTION_SUBKEY_FINGERPRINT = "1FE1C822C37D38862D36BBE9B977855DC9580AA9"
    private const val REVIEWED_ENCRYPTION_SUBKEY_ID = "B977855DC9580AA9"
    private const val REVIEWED_USER_ID = "Douglas Yung <douglas.yung@sony.com>"
    private const val REVIEWED_TAG_SIGNER_USER_ID = "douglas.yung@sony.com"
    private const val LEGACY_ED25519_OID = "1.3.6.1.4.1.11591.15.1"
    private const val LEGACY_CV25519_OID = "1.3.6.1.4.1.3029.1.5.1"
    private const val KEY_CREATION_EPOCH_SECONDS = 1_757_951_620L
    private const val TAG_SIGNATURE_EPOCH_SECONDS = 1_779_182_222L
    private const val ARCHIVE_SIGNATURE_EPOCH_SECONDS = 1_779_316_752L
}

private fun ByteArray.toHex(): String = joinToString(separator = "") { byte ->
    (byte.toInt() and 0xff).toString(16).padStart(2, '0')
}.uppercase()

private fun ByteArray.toLowerHex(): String = joinToString(separator = "") { byte ->
    (byte.toInt() and 0xff).toString(16).padStart(2, '0')
}

private fun openPgpFail(message: String): Nothing = throw LlvmSourceProvenanceException(message)
