package decompengine.oracle.gcc

import java.io.ByteArrayInputStream
import java.io.InputStream
import java.nio.ByteBuffer
import java.nio.charset.CodingErrorAction
import java.nio.charset.StandardCharsets
import java.security.MessageDigest
import org.bouncycastle.bcpg.ArmoredInputStream
import org.bouncycastle.bcpg.BCPGInputStream
import org.bouncycastle.bcpg.HashAlgorithmTags
import org.bouncycastle.bcpg.PacketTags
import org.bouncycastle.bcpg.PublicKeyAlgorithmTags
import org.bouncycastle.openpgp.PGPPublicKey
import org.bouncycastle.openpgp.PGPPublicKeyRing
import org.bouncycastle.openpgp.PGPSignature
import org.bouncycastle.openpgp.PGPSignatureList
import org.bouncycastle.openpgp.PGPSignatureSubpacketVector
import org.bouncycastle.openpgp.bc.BcPGPObjectFactory
import org.bouncycastle.openpgp.operator.bc.BcPGPContentVerifierBuilderProvider

internal class GccSourceOpenPgpException(message: String, cause: Throwable? = null) :
    IllegalArgumentException(message, cause)

internal typealias GccVerifiedSourceKey = GccSourceOpenPgp.VerifiedKey

/** A cryptographic observation only; source lifecycle admission belongs to the held-input owner. */
internal data class GccSourceSignatureInfo(
    val primaryFingerprint: String,
    val signerFingerprint: String,
    val creationEpochSeconds: Long,
    val hashAlgorithm: Int,
    val bytes: Long,
    val sha256: String,
)

/** Closed verifier for the existing GCC release key. No provider registration or key discovery. */
internal object GccSourceOpenPgp {
    class VerifiedKey private constructor(private val signingKey: PGPPublicKey) {
        val primaryFingerprint: String get() = PRIMARY_FINGERPRINT
        val signingFingerprint: String get() = SIGNING_FINGERPRINT

        internal fun initialize(signature: PGPSignature) {
            signature.init(BcPGPContentVerifierBuilderProvider(), signingKey)
        }

        companion object {
            /** The only construction path performs the complete closed key verification. */
            internal fun verify(bytes: ByteArray, primary: String, signing: String): VerifiedKey =
                VerifiedKey(checkedSigningKey(bytes, primary, signing))
        }
    }

    fun verifyKey(armoredKey: ByteArray, expectedPrimaryFingerprint: String,
        expectedSigningFingerprint: String): GccVerifiedSourceKey = operation("release key") {
        VerifiedKey.verify(armoredKey, expectedPrimaryFingerprint, expectedSigningFingerprint)
    }

    fun verifyTagSignature(key: GccVerifiedSourceKey, payload: ByteArray,
        armoredSignature: ByteArray): GccSourceSignatureInfo = operation("tag signature") {
        bounded(payload, "tag payload")
        val signature = singleSignature(decodeArmor(armoredSignature, "SIGNATURE"))
        documentProfile(signature, TAG_EPOCH, true)
        key.initialize(signature)
        signature.update(payload)
        check(signature.verify(), "tag signature is cryptographically invalid")
        info(TAG_EPOCH, payload.size.toLong(), sha256(payload))
    }

    /** Reads at most the declared length plus one byte, and never closes the owner's stream. */
    fun verifyArchiveSignature(key: GccVerifiedSourceKey, binarySignature: ByteArray,
        archive: InputStream, expectedBytes: Long, expectedSha256: String,
        checkpoint: () -> Unit = {}): GccSourceSignatureInfo = operation("archive signature") {
        check(expectedBytes in 1..MAXIMUM_ARCHIVE_BYTES, "archive byte length is outside its bound")
        check(expectedSha256.matches(Regex("[0-9a-f]{64}")), "archive digest is invalid")
        bounded(binarySignature, "archive signature")
        val signature = singleSignature(binarySignature)
        documentProfile(signature, ARCHIVE_EPOCH, false)
        key.initialize(signature)
        val digest = MessageDigest.getInstance("SHA-256")
        val buffer = ByteArray(64 * 1024)
        var total = 0L
        checkpoint()
        while (total < expectedBytes) {
            val requested = minOf(buffer.size.toLong(), expectedBytes - total).toInt()
            val count = archive.read(buffer, 0, requested)
            check(count in 1..requested, if (count < 0) "archive ended before its locked length" else "archive stream made invalid progress")
            digest.update(buffer, 0, count)
            signature.update(buffer, 0, count)
            total += count
            checkpoint()
        }
        check(archive.read() == -1, "archive exceeds its locked length")
        checkpoint()
        val observed = digest.digest().hex()
        check(observed == expectedSha256, "archive digest differs from its lock")
        check(signature.verify(), "archive signature is cryptographically invalid")
        checkpoint()
        info(ARCHIVE_EPOCH, total, observed)
    }

    private fun checkedSigningKey(armoredKey: ByteArray, expectedPrimary: String, expectedSigning: String): PGPPublicKey {
        check(expectedPrimary == PRIMARY_FINGERPRINT && expectedSigning == SIGNING_FINGERPRINT,
            "locked release fingerprints differ from the reviewed distinct primary and signing keys")
        val binary = decodeArmor(armoredKey, "PUBLIC KEY BLOCK")
        val tags = listOf(PacketTags.PUBLIC_KEY) + List(6) { listOf(PacketTags.USER_ID, PacketTags.SIGNATURE) }.flatten() +
            List(3) { listOf(PacketTags.PUBLIC_SUBKEY, PacketTags.SIGNATURE) }.flatten()
        packets(binary, tags)
        val factory = BcPGPObjectFactory(binary).setThrowForUnknownCriticalPackets(true)
        val ring = factory.nextObject() as? PGPPublicKeyRing ?: fail("release key is not one public keyring")
        check(factory.nextObject() == null, "release key contains extra objects")
        val keys = ring.publicKeys.asSequence().toList()
        check(keys.size == 4, "release key population differs")
        val primary = keys[0]
        keyProfile(primary, PRIMARY_FINGERPRINT, PublicKeyAlgorithmTags.DSA, 1024, 993555805L, true)
        check(primary.userIDs.asSequence().toList() == USER_IDS, "release user identities differ")
        check(!primary.userAttributes.asSequence().any(), "release key contains user attributes")
        check(primary.signatures.asSequence().count() == 6, "release key certification population differs")
        USER_IDS.forEachIndexed { index, uid ->
            val signatures = primary.getSignaturesForID(uid).asSequence().toList()
            check(signatures.size == 1, "release identity certification population differs")
            val signature = signatures.single()
            val active = index < 4
            val epoch = UID_EPOCHS[index]
            signatureProfile(signature, if (active) PGPSignature.POSITIVE_CERTIFICATION else PGPSignature.CERTIFICATION_REVOCATION,
                PublicKeyAlgorithmTags.DSA, HashAlgorithmTags.SHA1, epoch)
            val expected = if (active) buildList {
                add(27 to "03"); add(30 to "01"); add(23 to "80")
                if (index == 0) add(25 to "01")
                add(2 to epochHex(epoch)); add(11 to "0908070302"); add(21 to "0802090a0b"); add(22 to "020301")
            } else listOf(2 to epochHex(epoch), 29 to "204163636f756e742064697361626c65642e")
            subpackets(signature.hashedSubPackets, expected)
            subpackets(signature.unhashedSubPackets, listOf(16 to PRIMARY_ID))
            signature.init(BcPGPContentVerifierBuilderProvider(), primary)
            check(signature.verifyCertification(uid, primary), "release identity certification is cryptographically invalid")
        }
        keys.drop(1).forEachIndexed { index, subkey ->
            keyProfile(subkey, SUBKEY_FINGERPRINTS[index], SUBKEY_ALGORITHMS[index],
                if (index == 2) 1024 else 2048, SUBKEY_EPOCHS[index], false)
            check(!subkey.userIDs.asSequence().any() && !subkey.userAttributes.asSequence().any(), "subkey contains identities")
            val signatures = subkey.signatures.asSequence().toList()
            check(signatures.size == 1, "subkey binding population differs")
            val binding = signatures.single()
            signatureProfile(binding, PGPSignature.SUBKEY_BINDING, PublicKeyAlgorithmTags.DSA,
                HashAlgorithmTags.SHA1, BINDING_EPOCHS[index])
            subpackets(binding.hashedSubPackets, when (index) {
                0 -> listOf(27 to "02", 2 to epochHex(BINDING_EPOCHS[index]))
                1 -> listOf(2 to epochHex(BINDING_EPOCHS[index]), 27 to "0c")
                else -> listOf(2 to epochHex(BINDING_EPOCHS[index]))
            })
            if (index == 0) {
                val unhashed = binding.unhashedSubPackets ?: fail("signing binding lacks cross-certification")
                val packets = unhashed.toArray().toList()
                check(packets.map { it.type } == listOf(32, 16) && packets.none { it.isCritical || it.isLongLength },
                    "signing binding cross-certification profile differs")
                check(packets[1].data.hex() == PRIMARY_ID, "signing binding issuer differs")
                val embedded = unhashed.embeddedSignatures
                check(embedded.size() == 1, "signing subkey requires one cross-certification")
                val cross = embedded[0]
                signatureProfile(cross, PGPSignature.PRIMARYKEY_BINDING, PublicKeyAlgorithmTags.RSA_GENERAL,
                    HashAlgorithmTags.SHA1, SUBKEY_EPOCHS[0])
                subpackets(cross.hashedSubPackets, listOf(2 to epochHex(SUBKEY_EPOCHS[0])))
                subpackets(cross.unhashedSubPackets, listOf(16 to SIGNING_ID))
                cross.init(BcPGPContentVerifierBuilderProvider(), subkey)
                check(cross.verifyCertification(primary, subkey), "signing subkey cross-certification is cryptographically invalid")
            } else subpackets(binding.unhashedSubPackets, listOf(16 to PRIMARY_ID))
            binding.init(BcPGPContentVerifierBuilderProvider(), primary)
            check(binding.verifyCertification(primary, subkey), "subkey binding is cryptographically invalid")
        }
        return keys[1]
    }

    private fun keyProfile(key: PGPPublicKey, fingerprint: String, algorithm: Int, bits: Int, expectedEpoch: Long, primary: Boolean) {
        check(key.isMasterKey == primary && key.version == 4 && key.algorithm == algorithm && key.bitStrength == bits &&
            key.fingerprint.hex().uppercase() == fingerprint && epoch(key.creationTime.time) == expectedEpoch &&
            key.validSeconds == 0L && !key.hasRevocation() && key.trustData == null,
            "release key material, creation, validity or revocation differs")
    }

    private fun documentProfile(signature: PGPSignature, creation: Long, tag: Boolean) {
        signatureProfile(signature, PGPSignature.BINARY_DOCUMENT, PublicKeyAlgorithmTags.RSA_GENERAL,
            HashAlgorithmTags.SHA256, creation)
        subpackets(signature.hashedSubPackets, buildList {
            add(33 to "04${SIGNING_FINGERPRINT.lowercase()}")
            add(2 to epochHex(creation))
            if (tag) add(28 to "rguenther@suse.de".toByteArray(StandardCharsets.US_ASCII).hex())
        })
        subpackets(signature.unhashedSubPackets, listOf(16 to SIGNING_ID))
    }

    private fun signatureProfile(signature: PGPSignature, type: Int, algorithm: Int, hash: Int, creation: Long) {
        check(signature.version == 4 && signature.signatureType == type && signature.keyAlgorithm == algorithm &&
            signature.hashAlgorithm == hash && epoch(signature.creationTime.time) == creation,
            "signature version, type, algorithm or creation differs")
    }

    private fun subpackets(vector: PGPSignatureSubpacketVector?, expected: List<Pair<Int, String>>) {
        val actual = vector?.toArray()?.toList() ?: fail("signature lacks required subpackets")
        check(actual.map { it.type to it.data.hex() } == expected && actual.none { it.isCritical || it.isLongLength },
            "signature subpackets differ from the closed profile")
    }

    private fun singleSignature(binary: ByteArray): PGPSignature {
        packets(binary, listOf(PacketTags.SIGNATURE))
        val factory = BcPGPObjectFactory(binary).setThrowForUnknownCriticalPackets(true)
        val signatures = factory.nextObject() as? PGPSignatureList ?: fail("expected one signature object")
        check(signatures.size() == 1 && factory.nextObject() == null, "signature population differs")
        return signatures[0]
    }

    private fun packets(binary: ByteArray, expected: List<Int>) {
        // Reject oversized/partial/indeterminate packet framing before a library parser can use
        // a declared packet length for allocation. This release has only finite packets.
        var offset = 0
        val observed = ArrayList<Int>(expected.size)
        fun octet(): Int {
            check(offset < binary.size, "truncated OpenPGP packet header")
            return binary[offset++].toInt() and 255
        }
        while (offset < binary.size) {
            check(observed.size < expected.size, "extra OpenPGP packets")
            val header = octet()
            check(header and 128 != 0, "invalid OpenPGP packet header")
            val tag: Int
            var length: Long
            if (header and 64 != 0) {
                tag = header and 63
                val first = octet()
                length = when {
                    first < 192 -> first.toLong()
                    first < 224 -> ((first - 192) * 256 + octet() + 192).toLong()
                    first == 255 -> {
                        var value = 0L
                        repeat(4) { value = (value shl 8) or octet().toLong() }
                        value
                    }
                    else -> fail("partial OpenPGP packet length is outside the release profile")
                }
            } else {
                tag = (header ushr 2) and 15
                val lengthKind = header and 3
                check(lengthKind != 3, "indeterminate OpenPGP packet length is outside the release profile")
                length = 0
                repeat(1 shl lengthKind) { length = (length shl 8) or octet().toLong() }
            }
            check(length > 0 && length <= binary.size - offset, "OpenPGP packet length exceeds retained bytes")
            observed += tag
            offset += length.toInt()
        }
        check(observed == expected, "OpenPGP packet sequence differs")
        val input = BCPGInputStream(ByteArrayInputStream(binary))
        expected.forEach { tag ->
            check(input.nextPacketTag() == tag, "OpenPGP packet sequence differs")
            check(input.readPacket() != null, "unreadable OpenPGP packet")
        }
        check(input.nextPacketTag() == -1, "extra OpenPGP packets")
    }

    private fun decodeArmor(bytes: ByteArray, kind: String): ByteArray {
        bounded(bytes, "armored evidence")
        val text = StandardCharsets.US_ASCII.newDecoder().onMalformedInput(CodingErrorAction.REPORT)
            .onUnmappableCharacter(CodingErrorAction.REPORT).decode(ByteBuffer.wrap(bytes)).toString()
        val begin = "-----BEGIN PGP $kind-----"
        val end = "-----END PGP $kind-----"
        val lines = text.split('\n')
        check('\r' !in text && lines.size >= 6 && lines.first() == begin && lines[1].isEmpty() &&
            lines.last().isEmpty() && lines[lines.lastIndex - 1] == end, "armor framing differs")
        val body = lines.subList(2, lines.lastIndex - 1)
        val data = body.dropLast(1)
        check(body.size >= 2 && body.last().matches(Regex("=[A-Za-z0-9+/]{4}")) &&
            data.all { it.length in 1..64 && it.matches(Regex("[A-Za-z0-9+/]+={0,2}")) } &&
            data.dropLast(1).all { it.length == 64 && '=' !in it }, "armor body differs")
        val raw = ByteArrayInputStream(bytes)
        val armor = ArmoredInputStream(raw)
        check(armor.armorHeaderLine == begin && armor.armorHeaders == null && !armor.isClearText, "armor headers differ")
        val decoded = armor.readAllBytes()
        check(raw.available() == 0 && decoded.size <= MAXIMUM_EVIDENCE_BYTES, "armored evidence has trailing or oversized data")
        return decoded
    }

    private fun bounded(bytes: ByteArray, label: String) = check(bytes.size in 1..MAXIMUM_EVIDENCE_BYTES, "$label exceeds byte bounds")
    private fun info(creation: Long, bytes: Long, sha: String) =
        GccSourceSignatureInfo(PRIMARY_FINGERPRINT, SIGNING_FINGERPRINT, creation, HashAlgorithmTags.SHA256, bytes, sha)
    private fun epoch(milliseconds: Long): Long {
        check(milliseconds % 1000 == 0L, "nonintegral OpenPGP timestamp")
        return milliseconds / 1000
    }
    private fun epochHex(seconds: Long): String = seconds.toString(16).padStart(8, '0')
    private fun sha256(bytes: ByteArray): String = MessageDigest.getInstance("SHA-256").digest(bytes).hex()
    private fun ByteArray.hex(): String = joinToString("") { "%02x".format(it.toInt() and 255) }
    private fun check(condition: Boolean, message: String) { if (!condition) fail(message) }
    private fun fail(message: String): Nothing = throw GccSourceOpenPgpException("GCC source OpenPGP: $message")
    private inline fun <T> operation(label: String, block: () -> T): T = try { block() }
        catch (failure: GccSourceOpenPgpException) { throw failure }
        catch (failure: Exception) { throw GccSourceOpenPgpException("Cannot verify GCC source $label", failure) }

    private const val MAXIMUM_EVIDENCE_BYTES = 64 * 1024
    private const val MAXIMUM_ARCHIVE_BYTES = 512L * 1024 * 1024
    private const val PRIMARY_FINGERPRINT = "13975A70E63C361C73AE69EF6EEB81F8981C74C7"
    private const val SIGNING_FINGERPRINT = "7F74F97C103468EE5D750B583AB00996FC26A641"
    private const val PRIMARY_ID = "6eeb81f8981c74c7"
    private const val SIGNING_ID = "3ab00996fc26a641"
    private const val TAG_EPOCH = 1786088838L
    private const val ARCHIVE_EPOCH = 1786091352L
    private val USER_IDS = listOf(
        "Richard Guenther <richard.guenther@gmail.com>", "Richard Guenther (Work) <rguenther@suse.de>",
        "Richard Guenther <richard.guenther@gmx.net>", "Richard Guenther (GCC) <rguenth@gcc.gnu.org>",
        "Richard Guenther <rguenth@tat.physik.uni-tuebingen.de>", "Richard Guenther <richard.guenther@uni-tuebingen.de>",
    )
    private val UID_EPOCHS = listOf(1449320083L, 1449320088L, 1449320088L, 1449320088L, 1236766349L, 1236766190L)
    private val SUBKEY_FINGERPRINTS = listOf(SIGNING_FINGERPRINT, "4CE32C24C63D3E55798B1126C0DD42AF3510072D", "4E87C5A8B02202B884DE1BF23B927C4C7B4F41D5")
    private val SUBKEY_ALGORITHMS = listOf(PublicKeyAlgorithmTags.RSA_GENERAL, PublicKeyAlgorithmTags.RSA_GENERAL, PublicKeyAlgorithmTags.ELGAMAL_ENCRYPT)
    private val SUBKEY_EPOCHS = listOf(1126625745L, 1126625788L, 993555806L)
    private val BINDING_EPOCHS = listOf(1232804905L, 1126625788L, 993555806L)
}
