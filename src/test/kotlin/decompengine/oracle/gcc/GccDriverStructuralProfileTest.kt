package decompengine.oracle.gcc

import decompengine.oracle.core.OracleJson
import java.nio.file.Files
import java.nio.file.Path
import kotlin.test.Test
import kotlin.test.assertEquals
import kotlin.test.assertFailsWith
import kotlin.test.assertTrue
import kotlinx.serialization.json.JsonObject
import kotlinx.serialization.json.JsonPrimitive
import kotlinx.serialization.json.jsonObject

class GccDriverStructuralProfileTest {
    @Test
    fun `fixed profile authenticates GCC source build ELF twins target and image base`() {
        val root = Path.of("oracle/gcc/16.2.0").toAbsolutePath().normalize()

        val profile = GccDriverStructuralInputsV1.load(root)

        assertEquals("gcc-driver-16.2.0", profile.profileId)
        assertEquals("16.2.0", profile.version)
        assertEquals("78d4ac73dd391005b895a6148cd9831e28e1208b", profile.sourceRevision)
        assertEquals("c9e21c5a6422c65572ee4c4de5578107b82ae92b6730536c4fc76490fe2ecad9", profile.artifactManifestSha256)
        assertEquals("8009c7cfc4f66017aa932d86a6d4ec7f374e6ab7a01b3ef5ab3d2fcc78c2378b", profile.fullBinary.sha256)
        assertEquals("3c0cfef73a02b06b40456e89d9d9e33727144c2f473b8b7256b361a7699d48a4", profile.strippedBinary.sha256)
        assertEquals("x86_64-sysv-amd64-v1", profile.targetAbi.id)
        assertEquals("sysv-amd64", profile.targetAbi.abi)
        assertEquals(62, profile.targetAbi.machine)
        assertEquals(3, profile.targetAbi.osAbi)
        assertEquals(64, profile.targetAbi.pointerBits)
        assertEquals("ELF64", profile.targetAbi.elfClass)
        assertEquals("little-endian", profile.targetAbi.dataEncoding)
        assertEquals("ET_EXEC", profile.strippedBinary.elfType)
        assertEquals("ET_EXEC", profile.targetAbi.elfType)
        assertEquals(0x400000UL, profile.imageBase)
        assertEquals(1, profile.executableRanges.size)
        assertEquals(0x3000UL, profile.executableRanges.single().startRva)
        assertEquals(0x10eac9UL, profile.executableRanges.single().endExclusiveRva)
        assertEquals("0x400000", profile.inputBinary.imageBase)
        assertEquals(profile.strippedBinary.sha256, profile.inputBinary.sha256)
        assertTrue(profile.inputBinary.executableRangesSha256.matches(Regex("[a-f0-9]{64}")))
    }

    @Test
    fun `manifest substitution that repeats expected binary hashes is rejected`() {
        val parent = Files.createTempDirectory("gcc-driver-structural-profile-")
        val root = Files.createDirectory(parent.resolve("16.2.0"))
        try {
            val original = OracleJson.parse(Files.readAllBytes(Path.of("oracle/gcc/16.2.0/oracle-manifest.json")))
                .jsonObject
            val changedOracle = JsonObject(original.getValue("oracle").jsonObject +
                ("id" to JsonPrimitive("attacker-profile")))
            Files.write(root.resolve("oracle-manifest.json"), OracleJson.canonicalBytes(
                JsonObject(original + ("oracle" to changedOracle)),
            ))

            val failure = assertFailsWith<GccDriverStructuralProfileException> {
                GccDriverStructuralInputsV1.load(root)
            }

            assertTrue(failure.message.orEmpty().contains("cannot authenticate"))
        } finally {
            Files.walk(parent).use { paths -> paths.sorted(Comparator.reverseOrder()).forEach(Files::delete) }
        }
    }
}
