package decompengine.oracle.gcc

import java.io.ByteArrayInputStream
import java.io.ByteArrayOutputStream
import java.io.InputStream
import java.nio.file.Files
import java.nio.file.Path
import java.security.MessageDigest
import java.util.Base64
import kotlin.test.*
import org.bouncycastle.bcpg.ArmoredInputStream
import org.bouncycastle.bcpg.ArmoredOutputStream
import org.bouncycastle.openpgp.PGPPublicKey
import org.bouncycastle.openpgp.PGPPublicKeyRing
import org.bouncycastle.openpgp.bc.BcPGPObjectFactory

class GccSourceOpenPgpTest {
    @Test
    fun `actual vendored key verifies all retained certifications and distinct signing subkey`() {
        val bytes = keyBytes()
        assertEquals("2408f24e68b0f5530bfb02fdc2906524f6e143ed2f1d5af6e5a38d505f8f602b", sha(bytes))
        val key = verifyKey(bytes)
        assertEquals(PRIMARY, key.primaryFingerprint)
        assertEquals(SIGNING, key.signingFingerprint)
        assertNotEquals(key.primaryFingerprint, key.signingFingerprint)
        bytes.fill(0)
        val info = GccSourceOpenPgp.verifyTagSignature(key, payload(), tagSignature())
        assertEquals(PRIMARY, info.primaryFingerprint)
        assertEquals(SIGNING, info.signerFingerprint)
        assertEquals(1786088838L, info.creationEpochSeconds)
        assertEquals(8, info.hashAlgorithm)
        assertEquals(163L, info.bytes)
        assertEquals("bfc082efedb5324641d89cbdc3fbce067a2524e4faf69ae6e17fe5eb40b9281a", info.sha256)
    }

    @Test
    fun `primary signing and encryption fingerprints cannot be interchanged or replaced`() {
        for ((primary, signing) in listOf(PRIMARY to PRIMARY, SIGNING to PRIMARY,
            PRIMARY.lowercase() to SIGNING, PRIMARY to "4CE32C24C63D3E55798B1126C0DD42AF3510072D",
            "0".repeat(40) to SIGNING)) {
            assertFailsWith<GccSourceOpenPgpException> { GccSourceOpenPgp.verifyKey(keyBytes(), primary, signing) }
        }
    }

    @Test
    fun `key packet census refuses omitted repeated and substituted subkey bindings`() {
        val keys = ring().publicKeys.asSequence().toList()
        val signing = keys[1]
        val binding = signing.signatures.next()
        val otherBinding = keys[2].signatures.next()
        val removed = PGPPublicKey.removeCertification(signing, binding)
        val altered = listOf(
            keys.dropLast(1),
            keys + keys[1],
            listOf(keys[0], PGPPublicKey.addCertification(signing, binding), keys[2], keys[3]),
            listOf(keys[0], removed, keys[2], keys[3]),
            listOf(keys[0], PGPPublicKey.addCertification(removed, otherBinding), keys[2], keys[3]),
        )
        altered.forEach { assertFailsWith<GccSourceOpenPgpException> { verifyKey(armor(PGPPublicKeyRing(it).encoded)) } }
    }

    @Test
    fun `retained active and revoked identity certifications are mandatory and cryptographically checked`() {
        val keys = ring().publicKeys.asSequence().toList()
        val primary = keys[0]
        primary.userIDs.asSequence().forEach { uid ->
            val removed = PGPPublicKey.removeCertification(primary, uid, primary.getSignaturesForID(uid).next())
            assertFailsWith<GccSourceOpenPgpException> { verifyKey(armor(PGPPublicKeyRing(listOf(removed) + keys.drop(1)).encoded)) }
        }
        // Alter signature MPI bytes while preserving the exact public keys and every metadata field.
        for (packetIndex in listOf(2, 4, 6, 8, 10, 12, 14, 16, 18)) {
            val binary = decoded(keyBytes())
            val packet = packetRanges(binary)[packetIndex]
            binary[packet.last] = (binary[packet.last].toInt() xor 1).toByte()
            val failure = assertFailsWith<GccSourceOpenPgpException> { verifyKey(armor(binary)) }
            assertTrue(failure.message.orEmpty().contains("cryptographically invalid"), failure.message)
        }
    }

    @Test
    fun `unhashed embedded signing cross certification must independently verify the exact key pair`() {
        val signing = ring().publicKeys.asSequence().toList()[1]
        val binding = signing.signatures.next()
        val embedded = binding.unhashedSubPackets.toArray().single { it.type == 32 }.data
        val binary = decoded(keyBytes())
        val start = sequenceOffset(binary, embedded)
        binary[start + embedded.lastIndex] = (binary[start + embedded.lastIndex].toInt() xor 1).toByte()
        val failure = assertFailsWith<GccSourceOpenPgpException> { verifyKey(armor(binary)) }
        assertTrue(failure.message.orEmpty().contains("cross-certification is cryptographically invalid"), failure.message)
    }

    @Test
    fun `key and document critical metadata and extra packet material refuse`() {
        val binary = decoded(keyBytes())
        // The first UID certification's hashed key-flags subpacket starts with 02 1b 03.
        val flags = sequenceOffset(binary, byteArrayOf(2, 27, 3))
        binary[flags + 1] = (27 or 128).toByte()
        assertFailsWith<GccSourceOpenPgpException> { verifyKey(armor(binary)) }
        val tag = decoded(tagSignature())
        val issuer = sequenceOffset(tag, byteArrayOf(22, 33, 4))
        tag[issuer + 1] = (33 or 128).toByte()
        assertFailsWith<GccSourceOpenPgpException> { GccSourceOpenPgp.verifyTagSignature(verifyKey(), payload(), armor(tag)) }
        for (extra in listOf(byteArrayOf(0), decoded(tagSignature()))) {
            assertFailsWith<GccSourceOpenPgpException> { verifyKey(armor(decoded(keyBytes()) + extra)) }
            assertFailsWith<GccSourceOpenPgpException> {
                GccSourceOpenPgp.verifyTagSignature(verifyKey(), payload(), armor(decoded(tagSignature()) + extra))
            }
        }
        for (framing in listOf(byteArrayOf(0xc2.toByte(), 0xff.toByte(), -1, -1, -1, -1),
            byteArrayOf(0xc2.toByte(), 0xe0.toByte(), 0), byteArrayOf(0x8b.toByte(), 0))) {
            assertFailsWith<GccSourceOpenPgpException> {
                GccSourceOpenPgp.verifyTagSignature(verifyKey(), payload(), armor(framing))
            }
        }
    }

    @Test
    fun `tag payload signature issuer and creation mutations refuse`() {
        val key = verifyKey()
        val changedPayload = payload().also { it[0] = (it[0].toInt() xor 1).toByte() }
        assertFailsWith<GccSourceOpenPgpException> { GccSourceOpenPgp.verifyTagSignature(key, changedPayload, tagSignature()) }
        val original = decoded(tagSignature())
        for (index in listOf(3, 5, 14, 40, original.lastIndex)) {
            val changed = original.copyOf().also { it[index] = (it[index].toInt() xor 1).toByte() }
            assertFailsWith<GccSourceOpenPgpException> { GccSourceOpenPgp.verifyTagSignature(key, payload(), armor(changed)) }
        }
    }

    @Test
    fun `armor framing headers CRC nonASCII and byte limits are closed`() {
        val original = keyBytes()
        val text = original.decodeToString()
        val changed = listOf(byteArrayOf(), ByteArray(65537), original + 10,
            text.replace("\n", "\r\n").toByteArray(), text.replace("\n\n", "\nVersion: other\n\n").toByteArray(),
            original.copyOf().also { it[60] = 0xff.toByte() }, original.dropLast(1).toByteArray(),
            text.replace(Regex("(?m)^=[A-Za-z0-9+/]{4}$"), "=AAAA").toByteArray())
        changed.forEach { assertFailsWith<GccSourceOpenPgpException> { verifyKey(it) } }
        assertFailsWith<GccSourceOpenPgpException> { GccSourceOpenPgp.verifyTagSignature(verifyKey(), ByteArray(65537), tagSignature()) }
    }

    @Test
    fun `archive streams retain byte digest and signature checks without closing owner input`() {
        val key = verifyKey()
        val signature = archiveSignature()
        assertEquals(310, signature.size)
        assertEquals("43d73202dcede15d31001c6ba0d28723014ef57e4dc815631772daadbe23bcd2", sha(signature))
        var checkpoints = 0
        var closed = false
        val stream = object : ByteArrayInputStream(byteArrayOf(1, 2, 3)) {
            override fun close() { closed = true; super.close() }
        }
        // Even a matching supplied length/digest cannot replace the signed payload.
        val failure = assertFailsWith<GccSourceOpenPgpException> {
            GccSourceOpenPgp.verifyArchiveSignature(key, signature, stream, 3, sha(byteArrayOf(1, 2, 3))) { checkpoints++ }
        }
        assertTrue(failure.message.orEmpty().contains("signature is cryptographically invalid"), failure.message)
        assertTrue(checkpoints >= 3)
        assertFalse(closed)
        assertFailsWith<GccSourceOpenPgpException> {
            GccSourceOpenPgp.verifyArchiveSignature(key, signature, ByteArrayInputStream(byteArrayOf(1)), 1, "0".repeat(64))
        }
    }

    @Test
    fun `archive exact one over short nonprogress and interruption controls are bounded`() {
        val key = verifyKey()
        val signature = archiveSignature()
        for ((input, count) in listOf(byteArrayOf(1, 2) to 1L, byteArrayOf(1) to 2L)) {
            assertFailsWith<GccSourceOpenPgpException> {
                GccSourceOpenPgp.verifyArchiveSignature(key, signature, ByteArrayInputStream(input), count, "0".repeat(64))
            }
        }
        val noProgress = object : InputStream() {
            override fun read(): Int = error("single byte read must not happen")
            override fun read(b: ByteArray, off: Int, len: Int): Int = 0
        }
        assertFailsWith<GccSourceOpenPgpException> { GccSourceOpenPgp.verifyArchiveSignature(key, signature, noProgress, 1, "0".repeat(64)) }
        var reads = 0
        val neverRead = object : InputStream() { override fun read(): Int { reads++; return -1 } }
        for (count in listOf(0L, -1L, 512L * 1024 * 1024 + 1)) {
            assertFailsWith<GccSourceOpenPgpException> { GccSourceOpenPgp.verifyArchiveSignature(key, signature, neverRead, count, "0".repeat(64)) }
        }
        assertFailsWith<GccSourceOpenPgpException> {
            GccSourceOpenPgp.verifyArchiveSignature(key, signature, neverRead, 1, "0".repeat(64)) { throw IllegalStateException("cancelled") }
        }
        assertEquals(0, reads)
        assertFailsWith<GccSourceOpenPgpException> {
            GccSourceOpenPgp.verifyArchiveSignature(key, decoded(tagSignature()), neverRead, 1, "0".repeat(64))
        }
        assertEquals(0, reads)
    }

    private fun verifyKey(bytes: ByteArray = keyBytes()) = GccSourceOpenPgp.verifyKey(bytes, PRIMARY, SIGNING)
    private fun keyBytes() = Files.readAllBytes(PROFILE.resolve("keys/richard-guenther-gcc-release.asc"))
    private fun payload() = Files.readAllBytes(PROFILE.resolve("tag/releases-gcc-16.2.0.payload"))
    private fun tagSignature() = Files.readAllBytes(PROFILE.resolve("tag/releases-gcc-16.2.0.sig"))
    private fun ring() = BcPGPObjectFactory(decoded(keyBytes())).nextObject() as PGPPublicKeyRing
    private fun decoded(bytes: ByteArray) = ArmoredInputStream(ByteArrayInputStream(bytes)).use { it.readAllBytes() }
    private fun armor(bytes: ByteArray): ByteArray = ByteArrayOutputStream().also { output ->
        ArmoredOutputStream.builder().clearHeaders().build(output).use { it.write(bytes) }
    }.toByteArray()
    private fun sha(bytes: ByteArray) = MessageDigest.getInstance("SHA-256").digest(bytes).joinToString("") { "%02x".format(it.toInt() and 255) }
    private fun sequenceOffset(haystack: ByteArray, needle: ByteArray): Int =
        (0..haystack.size - needle.size).firstOrNull { offset -> needle.indices.all { haystack[offset + it] == needle[it] } }
            ?: error("fixture byte sequence is absent")

    /** Fixture-only packet offsets; production uses the bounded Bouncy Castle packet reader. */
    private fun packetRanges(bytes: ByteArray): List<IntRange> {
        var offset = 0
        val ranges = arrayListOf<IntRange>()
        while (offset < bytes.size) {
            val start = offset
            val header = bytes[offset++].toInt() and 255
            check(header and 0x40 == 0)
            val lengthBytes = 1 shl (header and 3)
            check(lengthBytes <= 4)
            var length = 0
            repeat(lengthBytes) { length = (length shl 8) or (bytes[offset++].toInt() and 255) }
            offset += length
            check(offset <= bytes.size)
            ranges += start until offset
        }
        return ranges
    }

    private fun archiveSignature() = Base64.getDecoder().decode(ARCHIVE_SIGNATURE_BASE64)

    companion object {
        private val PROFILE = Path.of("oracle/gcc/16.2.0")
        private const val PRIMARY = "13975A70E63C361C73AE69EF6EEB81F8981C74C7"
        private const val SIGNING = "7F74F97C103468EE5D750B583AB00996FC26A641"
        // Exact locked detached signature, retained here only to test streaming refusal without the 107 MB archive.
        private const val ARCHIVE_SIGNATURE_BASE64 = "iQEzBAABCAAdFiEEf3T5fBA0aO5ddQtYOrAJlvwmpkEFAmp1l1gACgkQOrAJlvwmpkGChAgAtu0sRF51OkBjwLfopAjg91FhJATt8gXHnrDEGfYS/kasWEhSv4OETAxEAqS7t/fgDuSoSZxTo8BTEDi1NAaeYaIVyF00KQca+yBoby9q1dlIUDKXLDcLQmYyX112Zd2ds+RD7g5S5WgMmVpZeEY+Ar91xY22+L35oc8eiNWNEntgI/hRT3fEMLLR9j9uZ3RdP8IL4ajsP03YbdueMpv/nnJ5IAWpAFw+xx++iGyFapZ50u+p1cZS7YeCOg2lNbSDf0R9VUGTFWZvVWaFVNwrMv7F3e9rdY6DGBlpBgxGjHe2tUa0ZKgrFn1ogcR19Gh0dqivvrgX3R+iQX5vuNRlqg=="
    }
}
