package decompengine.oracle.reference

import decompengine.oracle.core.OracleArtifacts
import decompengine.oracle.core.OracleJson
import decompengine.oracle.gcc.GccMetadataReferenceProfile
import java.io.ByteArrayOutputStream
import java.nio.file.Files
import java.nio.file.Path
import java.nio.file.StandardCopyOption
import java.util.Base64
import kotlin.test.Test
import kotlin.test.assertContentEquals
import kotlin.test.assertEquals
import kotlin.test.assertFailsWith
import kotlin.test.assertFalse
import kotlin.test.assertTrue
import kotlinx.serialization.json.JsonArray
import kotlinx.serialization.json.JsonObject
import kotlinx.serialization.json.JsonPrimitive
import org.tukaani.xz.LZMA2Options
import org.tukaani.xz.XZOutputStream

class ReferenceCorpusProfileTest {
    @Test
    fun `fixed registration authenticates exact original artifacts and nineteen input-only cases`() {
        GccMetadataReferenceProfile.open(PROFILE_ROOT).use { profile ->
            assertEquals("gcc-metadata-v1", profile.registrationId)
            assertEquals("49c15a75ddcf88d57d5c2d0de103be91b8c95c5f701c9d4b3d18118113a78d7b", profile.profileSha256)
            assertEquals(19, profile.definition.cases.size)
            assertEquals(16, profile.definition.cases.count { it.batchId == "driver" })
            assertEquals(listOf("missing-input-file", "option-invalid-frontend-value", "malformed-source"),
                profile.definition.cases.filter { it.batchId == "frontend" }.map { it.id })
            assertEquals(setOf("driver"), profile.artifactRolesForBatch("driver"))
            assertEquals(setOf("driver", "frontend"), profile.artifactRolesForBatch("frontend"))
            assertFailsWith<IllegalArgumentException> { profile.artifactRolesForBatch("other") }
            assertEquals("3c0cfef73a02b06b40456e89d9d9e33727144c2f473b8b7256b361a7699d48a4", profile.executable.sha256)
            assertEquals("e51bf6e3f3300d31ce9713e2160c6fe5895d1e4914fb25562c3542b161427905", profile.artifact("frontend").sha256)
            assertEquals(41_935_768, profile.artifact("frontend").content.size)
            assertEquals(profile.artifact("frontend").sha256, OracleArtifacts.sha256(profile.artifact("frontend").content))
            assertEquals(11, profile.inputBindings.size)
            assertEquals(profile.imageConfigSha256, profile.nativeRuntimeSelection.imageConfigSha256)
            assertEquals("5cfe8f249600c95e14577138881a6f509e848a0c8e3420ed3ea0bec8fdb62520", profile.nativeRuntimeSelection.sha256)
            assertEquals(44, profile.nativeRuntimeSelection.configurationTreeRoots.size)
            assertEquals(59, profile.nativeRuntimeSelection.configurationNodes.size)
            assertTrue(profile.definition.cases.all { "PATH" in it.environment })
            assertFalse(profile.canonicalBytes.decodeToString().contains("\"expected\""))
            profile.requireCurrent("positive profile test")
        }
    }

    @Test
    fun `parsed profile independently matches retained input identities and category coverage`() {
        val definition = ReferenceCorpusDefinition.parse(Files.readAllBytes(PROFILE))
        val retained = OracleJson.parse(Files.readAllBytes(PROFILE_ROOT.resolve("metadata-diagnostic-reference.json"))) as JsonObject
        val expectedCases = retained.getValue("cases") as JsonArray
        assertEquals(expectedCases.size, definition.cases.size)
        for ((observed, rawExpected) in definition.cases.zip(expectedCases)) {
            val expected = rawExpected as JsonObject
            assertEquals(expected.getValue("id"), JsonPrimitive(observed.id))
            assertEquals(expected.getValue("arguments"), JsonArray(observed.arguments.map(::JsonPrimitive)))
            assertEquals(expected.getValue("categories"), JsonArray(observed.categories.map(::JsonPrimitive)))
            val expectedStdin = expected.getValue("stdin") as JsonObject
            assertEquals(expectedStdin.getValue("bytes"), JsonPrimitive(observed.stdin.size))
            assertEquals(expectedStdin.getValue("sha256"), JsonPrimitive(OracleArtifacts.sha256(observed.stdin)))
            val expectedEnvironment = expected.getValue("environment") as JsonObject
            for ((key, value) in expectedEnvironment) assertEquals(value, JsonPrimitive(observed.environment.getValue(key)))
            val expectedInputs = expected.getValue("inputs") as JsonArray
            assertEquals(expectedInputs.size, observed.inputs.size)
            for ((input, raw) in observed.inputs.zip(expectedInputs)) {
                val expectedInput = raw as JsonObject
                assertEquals(expectedInput.getValue("path"), JsonPrimitive(input.path))
                assertEquals(expectedInput.getValue("bytes"), JsonPrimitive(input.bytes))
                assertEquals(expectedInput.getValue("sha256"), JsonPrimitive(input.sha256))
            }
        }
        val categories = definition.cases.flatMap { it.categories }.toSet()
        assertTrue(categories.containsAll(setOf("version", "target", "search-directory", "help", "option-validation",
            "missing-input", "malformed-input", "unsupported-option")))
    }

    @Test
    fun `all registered input substitutions fail before profile authority is returned`() {
        val registration = registration()
        for (binding in registration.getValue("bindings") as JsonArray) {
            val item = binding as JsonObject
            val relative = (item.getValue("path") as JsonPrimitive).content
            withFixture { fixture ->
                val target = fixture.resolve(relative)
                val bytes = Files.readAllBytes(target)
                bytes[0] = (bytes[0].toInt() xor 1).toByte()
                Files.write(target, bytes)
                assertFailsWith<ReferenceCorpusProfileException>(relative) { GccMetadataReferenceProfile.open(fixture) }
            }
        }
        assertFailsWith<ReferenceCorpusProfileException> { AuthenticatedReferenceCorpusProfile.open(PROFILE_ROOT, "../gcc-metadata-v1") }
        assertFailsWith<ReferenceCorpusProfileException> { AuthenticatedReferenceCorpusProfile.open(PROFILE_ROOT, "unknown-profile") }
    }

    @Test
    fun `retained profile rejects path replacement and cannot be used after close`() {
        withFixture { fixture ->
            val profile = GccMetadataReferenceProfile.open(fixture)
            try {
                val selected = fixture.resolve("metadata-reference-profile-v1.json")
                val replacement = fixture.resolve("replacement.json")
                Files.copy(selected, replacement)
                Files.move(replacement, selected, StandardCopyOption.ATOMIC_MOVE, StandardCopyOption.REPLACE_EXISTING)
                assertFailsWith<Exception> { profile.requireCurrent("after path replacement") }
            } finally {
                profile.close()
            }
            assertFailsWith<IllegalStateException> { profile.requireCurrent("after close") }
        }
    }

    @Test
    fun `case blobs lists maps and admitted artifact bytes are defensive`() {
        GccMetadataReferenceProfile.open(PROFILE_ROOT).use { profile ->
            val case = profile.definition.cases.first { it.inputs.isNotEmpty() }
            val input = case.inputs.first()
            val original = input.content
            val borrowed = input.content
            borrowed[0] = (borrowed[0].toInt() xor 1).toByte()
            assertContentEquals(original, input.content)
            assertFailsWith<UnsupportedOperationException> { (case.arguments as MutableList<String>).add("--injected") }
            assertFailsWith<UnsupportedOperationException> { (case.environment as MutableMap<String, String>)["LD_PRELOAD"] = "/bad" }
            assertFailsWith<UnsupportedOperationException> {
                (profile.definition.artifacts as MutableMap<String, ReferenceCorpusArtifactIdentity>).clear()
            }
            assertFailsWith<UnsupportedOperationException> {
                (profile.definition.artifactRolesForBatch("driver") as MutableSet<String>).add("injected")
            }
            val artifact = profile.artifact("frontend").content
            artifact[0] = 0
            assertEquals(profile.artifact("frontend").sha256, OracleArtifacts.sha256(profile.artifact("frontend").content))
            val canonical = profile.canonicalBytes
            canonical[0] = 0
            assertEquals(profile.profileSha256, OracleArtifacts.sha256(profile.canonicalBytes))
            val selection = profile.nativeRuntimeSelection
            selection.canonicalBytes.fill(0)
            assertEquals(selection.sha256, OracleArtifacts.sha256(selection.canonicalBytes))
            assertFailsWith<UnsupportedOperationException> { (selection.configurationNodes as MutableList<String>).add("/etc/shadow") }
            assertFailsWith<UnsupportedOperationException> { (selection.configurationTreeRoots as MutableList<String>).clear() }
        }
    }

    @Test
    fun `native runtime selection rejects widening ambiguous paths and unbounded definitions`() {
        val bytes = Files.readAllBytes(PROFILE_ROOT.resolve("native-runtime-selection-v1.json"))
        val raw = OracleJson.parse(bytes) as JsonObject
        val mutations = listOf<(JsonObject) -> JsonObject>(
            { JsonObject(it + ("expected" to JsonObject(emptyMap()))) },
            { JsonObject(it + ("imageConfigSha256" to JsonPrimitive("unbound"))) },
            { JsonObject(it + ("treePrefixes" to JsonArray(listOf(JsonPrimitive("/usr"))))) },
            { JsonObject(it + ("configurationTreeRoots" to JsonArray(listOf(JsonPrimitive("/etc"))))) },
            { JsonObject(it + ("configurationNodes" to JsonArray(listOf(JsonPrimitive("/etc/../etc/passwd"))))) },
            { JsonObject(it + ("configurationNodes" to JsonArray(listOf(JsonPrimitive("/etc"), JsonPrimitive("/etc"))))) },
            { JsonObject(it + ("configurationNodes" to JsonArray(listOf(JsonPrimitive("/etc"), JsonPrimitive("/etc/absent/child"))))) },
            { JsonObject(it + ("configurationNodes" to JsonArray(listOf(JsonPrimitive("/etc"), JsonPrimitive("/etc/alternatives"))))) },
            { JsonObject(it + ("configurationTreeRoots" to JsonArray(listOf(JsonPrimitive("/etc/a"), JsonPrimitive("/etc/a/child"))))) },
            { JsonObject(it + ("configurationNodes" to JsonArray((0..2048).map { n -> JsonPrimitive("/etc/node$n") }))) },
        )
        mutations.forEachIndexed { index, mutation ->
            assertFailsWith<ReferenceCorpusProfileException>("selection mutation $index") {
                ReferenceNativeRuntimeSelection.parse(OracleJson.canonicalBytes(mutation(raw)))
            }
        }
        assertFailsWith<ReferenceCorpusProfileException> { ReferenceNativeRuntimeSelection.parse(bytes + byteArrayOf(10)) }
        withFixture { fixture ->
            GccMetadataReferenceProfile.open(fixture).use { profile ->
                val selected = fixture.resolve("native-runtime-selection-v1.json")
                val replacement = fixture.resolve("replacement-selection.json")
                Files.copy(selected, replacement)
                Files.move(replacement, selected, StandardCopyOption.ATOMIC_MOVE, StandardCopyOption.REPLACE_EXISTING)
                assertFailsWith<Exception> { profile.requireCurrent("after runtime selection path replacement") }
            }
        }
    }

    @Test
    fun `profile schema rejects expected output injected commands traversal and altered blob identities`() {
        val raw = OracleJson.parse(Files.readAllBytes(PROFILE)) as JsonObject
        val mutations = listOf<(JsonObject) -> JsonObject>(
            { JsonObject(it + ("expected" to JsonObject(emptyMap()))) },
            { root -> changeFirstCase(root) { JsonObject(it + ("commands" to JsonArray(emptyList()))) } },
            { root -> changeFirstInput(root) { JsonObject(it + ("path" to JsonPrimitive("../outside"))) } },
            { root -> changeFirstInput(root) { JsonObject(it + ("base64" to JsonPrimitive(Base64.getEncoder().encodeToString("different".toByteArray())))) } },
            { root -> JsonObject(root + ("cases" to JsonArray((root.getValue("cases") as JsonArray).toList() + (root.getValue("cases") as JsonArray)[0]))) },
            { root -> JsonObject(root + ("limits" to JsonObject((root.getValue("limits") as JsonObject) + ("maximumStdoutBytes" to JsonPrimitive(1_048_577))))) },
            { root -> JsonObject(root + ("executableRole" to JsonPrimitive("unregistered"))) },
            { root -> changeFirstCase(root) { JsonObject(it + ("batchId" to JsonPrimitive("unregistered"))) } },
            { root ->
                val batch = JsonObject(mapOf("id" to JsonPrimitive("driver"),
                    "artifactRoles" to JsonArray(listOf(JsonPrimitive("frontend")))))
                JsonObject(root + ("batches" to JsonArray(listOf(batch))))
            },
            { root -> JsonObject(root + ("batches" to JsonArray((root.getValue("batches") as JsonArray).toList() +
                (root.getValue("batches") as JsonArray)[0]))) },
        )
        for ((ordinal, mutation) in mutations.withIndex()) {
            assertFailsWith<ReferenceCorpusProfileException>("mutation $ordinal") {
                ReferenceCorpusDefinition.parse(OracleJson.canonicalBytes(mutation(raw)))
            }
        }
        assertFailsWith<ReferenceCorpusProfileException> { ReferenceCorpusDefinition.parse(Files.readAllBytes(PROFILE) + byteArrayOf(10)) }
    }

    @Test
    fun `definition supports one arbitrary executable role without compiler roles or substitutions`() {
        val raw = OracleJson.parse(Files.readAllBytes(PROFILE)) as JsonObject
        val identity = (raw.getValue("artifactIdentities") as JsonObject).getValue("driver")
        val cases = (raw.getValue("cases") as JsonArray).map { case ->
            JsonObject((case as JsonObject) + ("batchId" to JsonPrimitive("standard")))
        }
        val unrelated = JsonObject(raw + mapOf(
            "artifactIdentities" to JsonObject(mapOf("program" to identity)),
            "executableRole" to JsonPrimitive("program"),
            "batches" to JsonArray(listOf(JsonObject(mapOf("id" to JsonPrimitive("standard"),
                "artifactRoles" to JsonArray(listOf(JsonPrimitive("program"))))))),
            "cases" to JsonArray(cases),
            "identitySubstitutions" to JsonArray(emptyList()),
        ))
        val definition = ReferenceCorpusDefinition.parse(OracleJson.canonicalBytes(unrelated))
        assertEquals("program", definition.executableRole)
        assertEquals(setOf("program"), definition.artifacts.keys)
        assertEquals(setOf("program"), definition.artifactRolesForBatch("standard"))
        assertTrue(definition.cases.all { it.batchId == "standard" })
        assertTrue(definition.alternateSubstitutionValues("/work/candidate-cc").isEmpty())
    }

    @Test
    fun `identity rules replace only bound spans and preserve unmatched arbitrary octets`() {
        val definition = ReferenceCorpusDefinition.parse(Files.readAllBytes(PROFILE))
        val bytes = byteArrayOf(0xff.toByte(), 0xfe.toByte()) + "\ngcc (GCC) 16.2.0\nConfigured with: /source/configure --prefix=/oracle/install --enable-languages=c\nConfigured with: /source/configure --prefix=/oracle/install-extra\ngcc: error: bad --prefix=/oracle/install\n".toByteArray()
        val expected = byteArrayOf(0xff.toByte(), 0xfe.toByte()) + "\ncc (GCC) 16.2.0\nConfigured with: /source/configure --prefix=/candidate --enable-languages=c\nConfigured with: /source/configure --prefix=/oracle/install-extra\ncc: error: bad --prefix=/oracle/install\n".toByteArray()
        assertContentEquals(expected, definition.substitute(bytes, mapOf("driver-basename" to "cc", "install-prefix" to "/candidate")))
        assertFailsWith<IllegalArgumentException> { definition.substitute(bytes, mapOf("unknown" to "value")) }
        assertEquals(mapOf("driver-basename" to "candidate-cc", "driver-argv0" to "/work/candidate-cc"),
            definition.alternateSubstitutionValues("/work/candidate-cc"))
        assertFailsWith<IllegalArgumentException> { definition.alternateSubstitutionValues("/work/another-name") }
    }

    @Test
    fun `single xz stream requires exact expansion and no trailing data`() {
        val expected = "bounded artifact".toByteArray()
        val output = ByteArrayOutputStream()
        XZOutputStream(output, LZMA2Options()).use { it.write(expected) }
        val archive = output.toByteArray()
        assertContentEquals(expected, decodeReferenceXz(archive, expected.size.toLong()))
        assertFailsWith<Exception> { decodeReferenceXz(archive + byteArrayOf(0), expected.size.toLong()) }
        assertFailsWith<Exception> { decodeReferenceXz(archive + archive, expected.size.toLong()) }
        assertFailsWith<Exception> { decodeReferenceXz(archive.copyOf(archive.size - 1), expected.size.toLong()) }
        assertFailsWith<Exception> { decodeReferenceXz(archive, expected.size.toLong() - 1) }
        assertFailsWith<Exception> { decodeReferenceXz(archive, expected.size.toLong() + 1) }
    }

    private fun registration(): JsonObject = checkNotNull(javaClass.getResourceAsStream("/oracle-reference-profiles/gcc-metadata-v1.json"))
        .use { OracleJson.parse(it.readBytes()) as JsonObject }

    private fun withFixture(action: (Path) -> Unit) {
        val parent = Path.of("build", "reference-profile-tests").toAbsolutePath()
        Files.createDirectories(parent)
        val root = Files.createTempDirectory(parent, "profile-")
        try {
            for (raw in registration().getValue("bindings") as JsonArray) {
                val relative = ((raw as JsonObject).getValue("path") as JsonPrimitive).content
                val target = root.resolve(relative)
                Files.createDirectories(target.parent)
                Files.copy(PROFILE_ROOT.resolve(relative), target)
            }
            action(root)
        } finally {
            Files.walk(root).use { paths -> paths.sorted(Comparator.reverseOrder()).forEach(Files::deleteIfExists) }
        }
    }

    private fun changeFirstCase(root: JsonObject, transform: (JsonObject) -> JsonObject): JsonObject {
        val cases = (root.getValue("cases") as JsonArray).toMutableList()
        cases[0] = transform(cases[0] as JsonObject)
        return JsonObject(root + ("cases" to JsonArray(cases)))
    }

    private fun changeFirstInput(root: JsonObject, transform: (JsonObject) -> JsonObject): JsonObject {
        val cases = (root.getValue("cases") as JsonArray).toMutableList()
        val index = cases.indexOfFirst { ((it as JsonObject).getValue("inputs") as JsonArray).isNotEmpty() }
        val case = cases[index] as JsonObject
        val inputs = (case.getValue("inputs") as JsonArray).toMutableList()
        inputs[0] = transform(inputs[0] as JsonObject)
        cases[index] = JsonObject(case + ("inputs" to JsonArray(inputs)))
        return JsonObject(root + ("cases" to JsonArray(cases)))
    }

    private companion object {
        val PROFILE_ROOT = Path.of("oracle/gcc/16.2.0").toAbsolutePath().normalize()
        val PROFILE = PROFILE_ROOT.resolve("metadata-reference-profile-v1.json")
    }
}
