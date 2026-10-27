package decompengine.project

import decompengine.oracle.core.OracleArtifacts
import decompengine.oracle.core.OracleJson
import java.nio.file.Path
import kotlin.io.path.readText
import kotlin.test.Test
import kotlin.test.assertContentEquals
import kotlin.test.assertEquals
import kotlin.test.assertFailsWith
import kotlin.test.assertFalse
import kotlin.test.assertNotEquals
import kotlin.test.assertTrue
import kotlinx.serialization.json.jsonObject
import kotlinx.serialization.json.jsonPrimitive

class StableCppNameCandidateTableTest {
    @Test
    fun `candidate table is order independent frozen and resolves only identity candidates`() {
        val authored = mutableListOf(
            input("meter-add", "operator+", StableCppNameEntityKind.FUNCTION, scope = namespaceScope("engine")),
            input("meter-subtract", "operator-", StableCppNameEntityKind.FUNCTION, scope = namespaceScope("engine")),
            input("parse", "parse", StableCppNameEntityKind.FUNCTION, module = "module-b", path = "src/module-b.cpp"),
        )
        val first = StableCppNameCandidateTable.build(authored)
        val shuffled = StableCppNameCandidateTable.build(authored.shuffled(kotlin.random.Random(73)))

        assertContentEquals(first.canonicalBytes, shuffled.canonicalBytes)
        assertEquals(first.reportSha256, shuffled.reportSha256)
        assertEquals(authored.size, first.entries.size)
        for (entry in first.entries) {
            assertTrue(entry.generatedName.matches(Regex("decomp_[A-Za-z0-9_]+_[0-9a-f]{64}")))
            assertEquals(entry.generatedName, first.resolve(entry.identityCandidateId))
        }
        val canonicalBeforeCallerMutation = first.canonicalBytes
        authored.clear()
        canonicalBeforeCallerMutation[0] = 0
        assertContentEquals(shuffled.canonicalBytes, first.canonicalBytes, "returned report bytes are defensive copies")
        assertFailsWith<IllegalArgumentException> { first.resolve(hex("unknown-reference")) }
    }

    @Test
    fun `sanitization collisions receive stable identity suffixes and a sorted report`() {
        val collision = StableCppNameCandidateTable.build(
            listOf(
                input("operator-plus", "operator+", StableCppNameEntityKind.FUNCTION, scope = namespaceScope("engine")),
                input("operator-minus", "operator-", StableCppNameEntityKind.FUNCTION, scope = namespaceScope("engine")),
                input("plain", "plain", StableCppNameEntityKind.FUNCTION, scope = namespaceScope("engine")),
            ),
        )

        assertEquals(1, collision.collisionGroups.size)
        assertEquals("operator", collision.collisionGroups.single().sanitizedStem)
        assertEquals(
            listOf(hex("entity:operator-minus"), hex("entity:operator-plus")).sorted(),
            collision.collisionGroups.single().sourceEntityIds,
        )
        assertEquals(collision.entries.size, collision.entries.map { it.generatedName }.distinct().size)
        assertTrue(collision.entries.filter { it.rawName?.startsWith("operator") == true }
            .all { it.generatedName.startsWith("decomp_operator_") })
    }

    @Test
    fun `anonymous local and local static candidates require explicit owner and scope`() {
        val anonymousScope = listOf(
            StableCppNameScopeComponent(StableCppScopeKind.ANONYMOUS_NAMESPACE, hex("anon-scope"), null),
        )
        val functionScopeOne = namespaceScope("engine") +
            StableCppNameScopeComponent(StableCppScopeKind.FUNCTION, hex("function-one"), "render")
        val functionScopeTwo = namespaceScope("engine") +
            StableCppNameScopeComponent(StableCppScopeKind.FUNCTION, hex("function-two"), "render")
        val candidates = StableCppNameCandidateTable.build(
            listOf(
                input("anonymous-helper", "helper", StableCppNameEntityKind.FUNCTION,
                    ownership = StableCppNameOwnership.ANONYMOUS_NAMESPACE, owner = "anonymous-tu", scope = anonymousScope),
                input("local-one", "state", StableCppNameEntityKind.VARIABLE,
                    ownership = StableCppNameOwnership.FUNCTION_LOCAL, owner = "function-one", scope = functionScopeOne),
                input("static-two", "state", StableCppNameEntityKind.VARIABLE,
                    ownership = StableCppNameOwnership.LOCAL_STATIC, owner = "function-two", scope = functionScopeTwo),
            ),
        )

        assertEquals(3, candidates.entries.map { it.generatedName }.distinct().size)
        assertFailsWith<IllegalArgumentException> {
            StableCppNameCandidateTable.build(listOf(
                input("anonymous-owner-missing", "helper", StableCppNameEntityKind.FUNCTION,
                    ownership = StableCppNameOwnership.ANONYMOUS_NAMESPACE, scope = anonymousScope),
            ))
        }
        assertFailsWith<IllegalArgumentException> {
            StableCppNameCandidateTable.build(listOf(
                input("static-scope-missing", "state", StableCppNameEntityKind.VARIABLE,
                    ownership = StableCppNameOwnership.LOCAL_STATIC, owner = "function-one"),
            ))
        }
    }

    @Test
    fun `scope moves change generated names and module moves change canonical mapping evidence`() {
        val original = input("moving-function", "render", StableCppNameEntityKind.FUNCTION,
            module = "module-a", path = "src/module-a.cpp", scope = namespaceScope("legacy"))
        val movedModule = original.withLocation(module = "module-b", path = "src/module-b.cpp")
        val movedNamespace = original.withScope(namespaceScope("modern"))

        val before = StableCppNameCandidateTable.build(listOf(original))
        val afterModuleMove = StableCppNameCandidateTable.build(listOf(movedModule))
        val afterNamespaceMove = StableCppNameCandidateTable.build(listOf(movedNamespace))

        assertEquals(before.entries.single().generatedName, afterModuleMove.entries.single().generatedName,
            "module placement is reported without perturbing semantic naming")
        assertNotEquals(before.reportSha256, afterModuleMove.reportSha256,
            "the canonical row binds module owner and source path")
        assertNotEquals(before.entries.single().generatedName, afterNamespaceMove.entries.single().generatedName)
        assertNotEquals(before.reportSha256, afterNamespaceMove.reportSha256)
        assertTrue(afterModuleMove.entries.single().canonicalJson().toString().contains("module-b"))

        val internalBefore = StableCppNameCandidateTable.build(listOf(
            input("file-static", "cache", StableCppNameEntityKind.VARIABLE, ownership = StableCppNameOwnership.INTERNAL),
        ))
        val internalAfter = StableCppNameCandidateTable.build(listOf(
            input("file-static", "cache", StableCppNameEntityKind.VARIABLE, ownership = StableCppNameOwnership.INTERNAL,
                module = "module-b", path = "src/module-b.cpp"),
        ))
        assertNotEquals(internalBefore.entries.single().generatedName, internalAfter.entries.single().generatedName,
            "translation-unit internal linkage includes its module owner in the naming scope")
    }

    @Test
    fun `duplicate identities conflicting owners and unknown resolutions fail closed`() {
        val duplicateSource = input("same-source", "first", StableCppNameEntityKind.FUNCTION)
        val duplicateCandidate = input("other-source", "second", StableCppNameEntityKind.FUNCTION)
            .withIdentityCandidate(duplicateSource.identityCandidateId)
        assertFailsWith<IllegalArgumentException> {
            StableCppNameCandidateTable.build(listOf(duplicateSource, duplicateSource))
        }
        assertFailsWith<IllegalArgumentException> {
            StableCppNameCandidateTable.build(listOf(duplicateSource, duplicateCandidate))
        }
        assertFailsWith<IllegalArgumentException> {
            StableCppNameCandidateTable.build(listOf(
                input("external-owner", "first", StableCppNameEntityKind.FUNCTION,
                    ownership = StableCppNameOwnership.EXTERNAL, owner = "unexpected-owner"),
            ))
        }
        assertFailsWith<IllegalArgumentException> {
            StableCppNameCandidateTable.build(listOf(
                input("anonymous-scope-owner-bypass", "helper", StableCppNameEntityKind.FUNCTION,
                    ownership = StableCppNameOwnership.EXTERNAL, scope = listOf(
                        StableCppNameScopeComponent(StableCppScopeKind.ANONYMOUS_NAMESPACE, hex("anon-scope"), null),
                    )),
            ))
        }
        assertFailsWith<IllegalArgumentException> {
            StableCppNameCandidateTable.build(listOf(
                input("local-scope-owner-bypass", "helper", StableCppNameEntityKind.FUNCTION,
                    ownership = StableCppNameOwnership.INTERNAL, scope = namespaceScope("engine") +
                        StableCppNameScopeComponent(StableCppScopeKind.FUNCTION, hex("function"), "outer")),
            ))
        }
    }

    @Test
    fun `anonymous namespace declaration can receive an explicit generated stem`() {
        val anonymousScope = listOf(
            StableCppNameScopeComponent(StableCppScopeKind.ANONYMOUS_NAMESPACE, hex("unnamed-namespace"), null),
        )
        val table = StableCppNameCandidateTable.build(listOf(
            input("unnamed-namespace", null, StableCppNameEntityKind.NAMESPACE,
                ownership = StableCppNameOwnership.ANONYMOUS_NAMESPACE, owner = "translation-unit", scope = anonymousScope),
        ))

        assertEquals(null, table.entries.single().rawName)
        assertTrue(table.entries.single().generatedName.startsWith("decomp_anonymous_"))
    }

    @Test
    fun `candidate and report limits reject oversized or malformed inputs`() {
        assertFailsWith<IllegalArgumentException> {
            StableCppNameCandidateTable.build(
                listOf(input("too-long", "x".repeat(16 * 1024 + 1), StableCppNameEntityKind.FUNCTION)),
            )
        }
        assertFailsWith<IllegalArgumentException> {
            StableCppNameCandidateTable.build(listOf(input("bad-unicode", "broken\uD800", StableCppNameEntityKind.FUNCTION)))
        }
        assertFailsWith<IllegalArgumentException> {
            StableCppNameCandidateTable.build(
                listOf(input("first", "one", StableCppNameEntityKind.FUNCTION), input("second", "two", StableCppNameEntityKind.FUNCTION)),
                StableCppNameCandidateLimits(maximumEntities = 1),
            )
        }
        assertFailsWith<IllegalArgumentException> { requireUniqueGeneratedNames(listOf("same-name", "same-name")) }
    }

    @Test
    fun `entity count is bounded by traversal even when caller size underreports`() {
        var consumed = 0
        val endless = object : AbstractList<StableCppNameCandidateInput>() {
            override val size: Int get() = 0
            override fun get(index: Int): StableCppNameCandidateInput =
                input("entity:$index", "f", StableCppNameEntityKind.FUNCTION)

            override fun iterator(): Iterator<StableCppNameCandidateInput> = object : Iterator<StableCppNameCandidateInput> {
                override fun hasNext(): Boolean = true
                override fun next(): StableCppNameCandidateInput {
                    check(consumed < 2) { "candidate traversal exceeded the entity bound" }
                    return get(consumed++)
                }
            }
        }

        val failure = assertFailsWith<IllegalArgumentException> {
            StableCppNameCandidateTable.build(endless, StableCppNameCandidateLimits(maximumEntities = 2))
        }
        assertEquals("C++ name candidate count exceeds its bound", failure.message)
        assertEquals(2, consumed, "refuse the extra element before consuming it")
    }

    @Test
    fun `candidate generation uses the same snapshot that was validated`() {
        val validated = input("validated", "safe", StableCppNameEntityKind.FUNCTION)
        val replacement = input("replacement", "unvalidated", StableCppNameEntityKind.FUNCTION,
            path = "../outside.cpp")
        var traversals = 0
        val changing = object : AbstractList<StableCppNameCandidateInput>() {
            override val size: Int get() = 1
            override fun get(index: Int): StableCppNameCandidateInput = replacement
            override fun iterator(): Iterator<StableCppNameCandidateInput> =
                listOf(if (traversals++ == 0) validated else replacement).iterator()
        }

        val actual = StableCppNameCandidateTable.build(changing)
        val expected = StableCppNameCandidateTable.build(listOf(validated))
        assertContentEquals(expected.canonicalBytes, actual.canonicalBytes)
        assertEquals(1, traversals, "never re-read the caller list after validation")
    }

    @Test
    fun `scope depth is bounded before caller list traversal and names are length checked`() {
        val endless = object : AbstractList<StableCppNameScopeComponent>() {
            override val size: Int get() = 0
            override fun get(index: Int): StableCppNameScopeComponent =
                StableCppNameScopeComponent(StableCppScopeKind.NAMESPACE, hex("scope:$index"), "scope")

            override fun iterator(): Iterator<StableCppNameScopeComponent> = object : Iterator<StableCppNameScopeComponent> {
                private var index = 0
                override fun hasNext(): Boolean = true
                override fun next(): StableCppNameScopeComponent = get(index++)
            }
        }
        assertFailsWith<IllegalArgumentException> {
            StableCppNameCandidateInput(
                sourceEntityId = hex("bounded-scope"),
                identityCandidateId = hex("bounded-scope-candidate"),
                kind = StableCppNameEntityKind.FUNCTION,
                ownership = StableCppNameOwnership.EXTERNAL,
                rawName = "f",
                scope = endless,
                ownerIdentityCandidateId = null,
                moduleOwnerId = "module-a",
                sourcePath = "src/a.cpp",
            )
        }
        assertFailsWith<IllegalArgumentException> {
            StableCppNameScopeComponent(StableCppScopeKind.NAMESPACE, "x".repeat(1_000_000), "scope")
        }
        assertFailsWith<IllegalArgumentException> {
            StableCppNameScopeComponent(StableCppScopeKind.NAMESPACE, hex("scope-id"), "x".repeat(1_000_000))
        }
    }

    @Test
    fun `authored multi translation unit fixture stays explicitly candidate only`() {
        val root = Path.of("src/test/resources/cpp-name-candidate-v1")
        val moduleA = root.resolve("module-a.cpp").readText()
        val moduleB = root.resolve("module-b.cpp").readText()
        assertTrue(moduleA.contains("operator+"))
        assertTrue(moduleA.contains("operator-"))
        assertTrue(moduleA.contains("static int state"))
        assertTrue(moduleA.contains("namespace {"))
        assertTrue(moduleB.contains("namespace engine"))

        val table = StableCppNameCandidateTable.build(
            listOf(
                input("fixture-plus", "operator+", StableCppNameEntityKind.FUNCTION,
                    module = "fixture-module-a", path = "src/module-a.cpp", scope = namespaceScope("engine")),
                input("fixture-minus", "operator-", StableCppNameEntityKind.FUNCTION,
                    module = "fixture-module-a", path = "src/module-a.cpp", scope = namespaceScope("engine")),
                input("fixture-local-static", "state", StableCppNameEntityKind.VARIABLE,
                    ownership = StableCppNameOwnership.LOCAL_STATIC, owner = "fixture-owner",
                    module = "fixture-module-a", path = "src/module-a.cpp",
                    scope = namespaceScope("engine") + StableCppNameScopeComponent(
                        StableCppScopeKind.FUNCTION, hex("fixture-owner"), "counter",
                    )),
                input("fixture-anon", "helper", StableCppNameEntityKind.FUNCTION,
                    ownership = StableCppNameOwnership.ANONYMOUS_NAMESPACE, owner = "fixture-tu-a",
                    module = "fixture-module-a", path = "src/module-a.cpp",
                    scope = listOf(StableCppNameScopeComponent(
                        StableCppScopeKind.ANONYMOUS_NAMESPACE, hex("fixture-anon-scope"), null,
                    ))),
                input("fixture-module-b", "convert", StableCppNameEntityKind.FUNCTION,
                    module = "fixture-module-b", path = "src/module-b.cpp", scope = namespaceScope("engine")),
            ),
        )

        assertEquals(5, table.entries.size)
        val canonical = OracleJson.parseCanonical(table.canonicalBytes).jsonObject
        assertEquals("none", canonical.getValue("authority").jsonPrimitive.content)
        assertEquals("candidate-only", canonical.getValue("status").jsonPrimitive.content)
        assertTrue(canonical.getValue("entries").toString().contains("source-anchor-candidate"))
        assertFalse(canonical.toString().contains("authenticated-semantic-identity"))
    }

    private fun input(
        key: String,
        rawName: String?,
        kind: StableCppNameEntityKind,
        ownership: StableCppNameOwnership = StableCppNameOwnership.EXTERNAL,
        owner: String? = null,
        module: String = "module-a",
        path: String = "src/module-a.cpp",
        scope: List<StableCppNameScopeComponent> = emptyList(),
    ): StableCppNameCandidateInput = StableCppNameCandidateInput(
        sourceEntityId = hex("entity:$key"),
        identityCandidateId = hex("candidate:$key"),
        kind = kind,
        ownership = ownership,
        rawName = rawName,
        scope = scope,
        ownerIdentityCandidateId = owner?.let { hex("owner:$it") },
        moduleOwnerId = module,
        sourcePath = path,
    )

    private fun namespaceScope(name: String): List<StableCppNameScopeComponent> = listOf(
        StableCppNameScopeComponent(StableCppScopeKind.NAMESPACE, hex("namespace:$name"), name),
    )

    private fun hex(value: String): String = OracleArtifacts.sha256(value.toByteArray(Charsets.UTF_8))

    private fun StableCppNameCandidateInput.withLocation(module: String, path: String) = StableCppNameCandidateInput(
        sourceEntityId, identityCandidateId, kind, ownership, rawName, scope, ownerIdentityCandidateId, module, path,
    )

    private fun StableCppNameCandidateInput.withScope(scope: List<StableCppNameScopeComponent>) = StableCppNameCandidateInput(
        sourceEntityId, identityCandidateId, kind, ownership, rawName, scope, ownerIdentityCandidateId, moduleOwnerId, sourcePath,
    )

    private fun StableCppNameCandidateInput.withIdentityCandidate(identityCandidateId: String) = StableCppNameCandidateInput(
        sourceEntityId, identityCandidateId, kind, ownership, rawName, scope, ownerIdentityCandidateId, moduleOwnerId, sourcePath,
    )
}
