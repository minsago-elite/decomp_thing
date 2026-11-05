package decompengine.web

import decompengine.acp.LinuxFileIdentity
import decompengine.acp.LinuxFileKey
import decompengine.project.*
import decompengine.repair.RepairBudgetExceededException
import decompengine.repair.StableRegularFile
import decompengine.repair.StableComparison
import io.github.optimumcode.json.schema.JsonSchema
import io.github.optimumcode.json.schema.ValidationError
import java.nio.file.Files
import java.nio.file.Path
import java.security.MessageDigest
import kotlinx.serialization.json.*
import kotlin.test.*

/** Synthetic committed records and synchronous callbacks only; no store, listener, compiler or browser is opened. */
class WebProgramStructureTest {
    private val jobId = "a".repeat(32)
    private val runId = "run_1"
    private val revisionId = "revision_1"
    private val profile = GeneratedCMakeReconstructionProfile.descriptor
    private val inputBytes = "input".toByteArray()
    private val inputSha = sha(inputBytes)
    private var inode = 10L

    private fun sha(bytes: ByteArray) = MessageDigest.getInstance("SHA-256").digest(bytes).joinToString("") { "%02x".format(it) }
    private fun captured(bytes: ByteArray) = StableRegularFile(bytes, sha(bytes),
        LinuxFileIdentity(LinuxFileKey(1, inode++), 0x8180, 1000, 1000, 1, 1, true, false, false))

    /** One revision: build inputs, evidence records and a candidate reference that binds them. */
    private inner class Revision(
        val model: ByteArray?,
        val plan: ByteArray?,
        modules: List<String>,
        val acceptedModules: Set<String> = emptySet(),
        val unresolvedImplementations: List<String> = emptyList(),
        val modelInput: String = inputSha,
    ) {
        val sources = (listOf("Makefile", "include/decomp_types.h") + modules.flatMap { listOf("src/modules/$it.c", "include/modules/$it.h") })
            .associateWith { "// $it\n".toByteArray() }
        val records = buildMap {
            putAll(sources)
            model?.let { put("reports/program_model.json", it) }
            plan?.let { put("reports/module_plan.json", it) }
        }
        val sourceSha = revisionSourceDigest(sources.toSortedMap().entries.joinToString("") { (path, bytes) ->
            "${path.length}:$path:${bytes.size}:${sha(bytes)}\n" })
        val reference = WebRevisionSourceReference(jobId, runId, revisionId, sourceSha, "version_1")
        val manifest = SourceTreeManifest(profileId = profile.id, profileSha256 = profile.sha256, inputSha256 = inputSha,
            files = records.map { (path, bytes) ->
                val declaration = profile.layout.declarationForPath(path)
                val module = path.removePrefix("src/modules/").removeSuffix(".c")
                GeneratedFileEvidence(path, sha(bytes), "fixture",
                    acceptedImplementation = if (ProjectFileRole.MODULE_IMPLEMENTATION in declaration.roles) module in acceptedModules else null,
                    roles = declaration.roles, contentKind = declaration.contentKind)
            }, unresolvedEntityIds = emptyList(), unresolvedImplementationIds = unresolvedImplementations).toJson().toByteArray()
        val descriptor = buildJsonObject {
            put("schemaVersion", 3); put("sourceRevisionSha256", sourceSha)
            put("sourceInputs", JsonArray(sources.toSortedMap().map { (path, bytes) -> buildJsonObject {
                put("path", path); put("bytes", bytes.size); put("sha256", sha(bytes))
            } }))
        }.toString().toByteArray()
        val files = (records.mapKeys { "reports/runs/$runId/source-tree/${it.key}" } + mapOf(
            "reports/runs/$runId/source-tree/source_tree_manifest.json" to manifest,
            "reports/runs/$runId/source-tree/reports/build_contract.json" to descriptor,
        )).mapValues { captured(it.value) }.toMutableMap()
        val reads = mutableListOf<String>()
        val evidence = WebSourceCatalogEvidence(listOf(profile), { captured(inputBytes).copy(identity = INPUT_IDENTITY) }) { _, path, maximum ->
            reads += path
            val file = files[path] ?: error("Unexpected read $path")
            if (file.bytes.size > maximum) throw RepairBudgetExceededException("fixture exceeds $maximum")
            file
        }
        val cache = WebProgramStructureCache()
        fun pagesWithCache(cache: WebProgramStructureCache, timing: ((String, Long) -> Unit)? = null): WebProgramStructurePages {
            return WebProgramStructurePages { job, run, revision, project ->
                assertEquals(Triple(jobId, runId, revisionId), Triple(job, run, revision))
                if (timing == null) evidence.readStructure(reference, cache, project)
                else evidence.readStructureMeasured(reference, cache, timing, project)
            }
        }
        fun pagesWithFreshCache(timing: ((String, Long) -> Unit)? = null) = pagesWithCache(WebProgramStructureCache(), timing)
        val pages = pagesWithCache(cache)
    }

    private fun model(functions: List<RecoveredFunction>, globals: List<RecoveredGlobal> = emptyList(),
        types: List<RecoveredType> = emptyList(), schema: Int = 2, input: String = inputSha) =
        RecoveredProgramModel(schema, input, functions, globals, types).toJson().toByteArray()

    private fun plan(vararg modules: PlannedModule, cycles: List<List<String>> = emptyList()) =
        ModulePlan(modules = modules.toList(), dependencyCycles = cycles).toJson().toByteArray()

    private fun planned(id: String, functions: List<String>, globals: List<String> = emptyList(), types: List<String> = emptyList(),
        evidence: List<String> = emptyList()) =
        PlannedModule(id, "src/modules/$id.c", "include/modules/$id.h", functions, globals, types, evidence)

    private val functions = listOf(
        RecoveredFunction("fn_0000000000401000", "main", 0x401000u, "int main(void)", "int main(void) { return helper(); }",
            calls = setOf("fn_0000000000401100", "fn_00000000deadbeef"), referencedGlobals = setOf("global_0000000000404000", "global_missing"),
            strings = setOf("hello")),
        RecoveredFunction("fn_0000000000401100", "helper", 0x401100u, "int helper(void)", "x".repeat(5000)),
        RecoveredFunction("fn_ffffffffffffffff", "helper", ULong.MAX_VALUE, "void top(void)", null, status = RecoveryStatus.PARTIAL),
        RecoveredFunction("fn_0000000000402000", "broken", 0x402000u, "void broken(void)", null, status = RecoveryStatus.FAILED),
        RecoveredFunction("fn_0000000000403000", "orphan", 0x403000u, "void orphan(void)", null, status = RecoveryStatus.SYNTHETIC),
    )
    private val globals = listOf(RecoveredGlobal("global_0000000000404000", "helper", 0x404000u, "int", "{ 1 }"))
    private val types = listOf(RecoveredType("type_${"c".repeat(64)}", "struct point { int x; int y; };", 0x405000u))

    private fun standard(acceptedModules: Set<String> = setOf("core")) = Revision(model(functions, globals, types),
        plan(planned("core", listOf("fn_0000000000401000", "fn_0000000000401100", "fn_ffffffffffffffff"),
                listOf("global_0000000000404000"), listOf("type_${"c".repeat(64)}"), listOf("calls:fn_0000000000401100")),
            planned("extra", listOf("fn_0000000000402000", "fn_ffffffffffffffff", "fn_unrecorded"))),
        listOf("core", "extra"), acceptedModules, unresolvedImplementations = listOf("fn_0000000000401100"))

    private val schema: JsonObject = Json.parseToJsonElement(Files.readString(Path.of("contracts/web/v1/contract.schema.json"))).jsonObject

    /** Validate the produced DTO with the shared producer schema, the same definition the browser decoder uses. */
    private fun assertContract(kind: String, data: JsonObject) {
        val document = JsonObject(schema - "oneOf" + ("allOf" to JsonArray(listOf(buildJsonObject { put("\$ref", "#/definitions/$kind") }))))
        val validator = JsonSchema.fromDefinition(document.toString())
        val errors = mutableListOf<ValidationError>()
        assertTrue(validator.validate(data, errors::add), "$kind: ${errors.take(3)}")
    }

    private fun JsonObject.items() = getValue("items").jsonArray.map { it.jsonObject }
    private fun JsonObject.text(name: String) = getValue(name).jsonPrimitive.contentOrNull
    private fun next(page: JsonObject) = page.getValue("page").jsonObject.text("nextCursor")

    private fun columnTable(kind: WebStructureKind, names: List<String?>,
        ids: Array<String> = Array(names.size) { "${kind.wire}_$it" },
        addresses: LongArray = LongArray(names.size), hasAddress: BooleanArray = BooleanArray(names.size) { true },
    ) = WebStructureTable(kind, ids, names.toTypedArray(), addresses, hasAddress,
        Array(names.size) { WebExtractionStatus.RECOVERED }, LongArray(names.size), IntArray(names.size),
        BooleanArray(names.size), BooleanArray(names.size), Array(names.size) { emptyArray<String>() },
        Array(names.size) { emptyArray<String>() }, IntArray(names.size))

    private fun collisionIndex(functionNames: List<String?>, globalNames: List<String?>, typeNames: List<String?>) =
        WebProgramStructureIndex(WebRevisionSourceReference(jobId, runId, revisionId, inputSha, "version_1"),
            inputSha, inputSha, inputSha, "metadata", WebStructureOutcome.AVAILABLE, null, null,
            WebStructureOutcome.AVAILABLE, null,
            listOf(columnTable(WebStructureKind.FUNCTION, functionNames), columnTable(WebStructureKind.GLOBAL, globalNames),
                columnTable(WebStructureKind.TYPE, typeNames)), emptyList(), emptyMap(), null, 0, 0L)

    /** Original allocation-heavy implementation, retained here as an independent result oracle. */
    private fun oldCollisionGroups(index: WebProgramStructureIndex) =
        HashMap<String, MutableList<Pair<WebStructureKind, Int>>>().also { groups ->
            for (table in index.tables) if (table.kind != WebStructureKind.TYPE) {
                for (row in 0 until table.size) table.names[row]?.let {
                    groups.getOrPut(it) { ArrayList(1) } += table.kind to row
                }
            }
        }.filterValues { it.size > 1 }

    @Test fun `module inventory counts shared cycles without hashing their members`() {
        val large = (0 until 64).map { "m$it" }.reversed()
        val small = listOf("small_b", "small_a")
        val ids = large + small + "acyclic"
        val revision = Revision(model(emptyList()), plan(*ids.map { planned(it, emptyList()) }.toTypedArray(),
            cycles = listOf(large, small)), ids)
        val original = revision.evidence.readStructure(revision.reference, revision.cache) { index, _ -> index }
        assertEquals("available", original.planOutcome.state)
        val modules = original.modules.map { module ->
            val guarded = object : List<String> by module.cycle {
                override fun hashCode(): Int = error("Cycle members must not be hashed by inventory summaries.")
            }
            WebStructureModule(module.id, module.sourcePath, module.headerPath, module.functionIds,
                module.globalIds, module.typeIds, module.boundaryEvidence, module.implementationDeclaration, guarded)
        }
        val index = WebProgramStructureIndex(original.reference, original.manifestSha256, original.descriptorSha256,
            original.inputSha256, original.metadataVersion, original.outcome, original.model, original.modelSchemaVersion,
            original.planOutcome, original.plan, original.tables, modules, original.sourceFileIds,
            original.sharedInterfacePath, original.unknownPlanReferences, original.retainedBytes)
        val pages = WebProgramStructurePages { _, _, _, project -> project(index) { revision.model!! } }
        val first = pages.modules("owner", jobId, runId, revisionId, "limit=1")
        assertContract("moduleInventory", first)
        assertEquals(2, first.getValue("summary").jsonObject.getValue("dependencyCycles").jsonPrimitive.int)
        val cursor = first.getValue("page").jsonObject.getValue("nextCursor").jsonPrimitive.content
        val second = pages.modules("owner", jobId, runId, revisionId, "limit=1&cursor=$cursor")
        assertEquals(first["summary"], second["summary"])
    }

    @Test fun `collision prepass matches original exact groups and function then global row order`() {
        val index = collisionIndex(
            listOf(null, "unique", "same", "intra", "same", "intra", "", "Case", "type-peer", "é"),
            listOf("same", null, "global-only", "global-only", "", "unique-global", "case", "e\u0301",
                String(charArrayOf('s', 'a', 'm', 'e'))),
            listOf("unique", "type-peer", "type-peer", "same", "unique-global"))
        assertEquals(oldCollisionGroups(index), index.collisions)
        assertEquals(setOf("same", "intra", "global-only", ""), index.collisions.keys)
        assertEquals(listOf(WebStructureKind.FUNCTION to 2, WebStructureKind.FUNCTION to 4,
            WebStructureKind.GLOBAL to 0, WebStructureKind.GLOBAL to 8), index.collisions.getValue("same"))
        assertSame(index.collisions, index.collisions)
    }

    @Test fun `collision prepass resolves long equal hash probe chains by string equality`() {
        // Every concatenation of eight Aa/BB pairs has the same String hash, but a distinct name.
        val names = (0 until 256).map { bits -> (0 until 8).joinToString("") { if (bits and (1 shl it) == 0) "Aa" else "BB" } }
        assertEquals(1, names.map { it.hashCode() }.toSet().size)
        assertEquals(256, names.toSet().size)
        val index = collisionIndex(names + names.take(12).reversed(), names.filterIndexed { i, _ -> i % 3 == 0 }, names)
        assertEquals(oldCollisionGroups(index), index.collisions)
        assertFalse(names[13] in index.collisions)
        assertEquals(listOf(WebStructureKind.FUNCTION to 0, WebStructureKind.FUNCTION to 267,
            WebStructureKind.GLOBAL to 0), index.collisions.getValue(names[0]))
    }

    @Test fun `collision prepass keeps empty singleton null and unique inventories empty`() {
        val unavailable = Revision(null, null, emptyList())
        unavailable.evidence.readStructure(unavailable.reference, unavailable.cache) { index, _ ->
            assertTrue(index.tables.isEmpty())
            assertEquals(oldCollisionGroups(index), index.collisions)
        }
        for ((functions, globals) in listOf(emptyList<String?>() to emptyList(), listOf("one") to emptyList(),
            emptyList<String?>() to listOf("one"), listOf(null, null) to listOf(null),
            listOf("Aa", "unique") to listOf("BB", "other"))) {
            val index = collisionIndex(functions, globals, listOf("one", "one", "Aa", "BB"))
            assertEquals(oldCollisionGroups(index), index.collisions)
            assertTrue(index.collisions.isEmpty())
        }
    }

    @Test fun `primitive address order preserves unsigned ties and absent addresses on both paths`() {
        val ids = arrayOf("zero", "tie-a", "tie-b", "signed-max", "unsigned-high", "unsigned-max",
            "absent-a", "absent-b", "absent-high")
        val addresses = longArrayOf(0, 7, 7, Long.MAX_VALUE, Long.MIN_VALUE, -1, 0, 0, -1)
        val present = BooleanArray(ids.size) { it < 6 }
        for (permutation in listOf(ids.indices.toList(), ids.indices.reversed().toList(), listOf(6, 2, 4, 0, 8, 1, 5, 7, 3))) {
            val table = columnTable(WebStructureKind.TYPE, List(ids.size) { null },
                permutation.map { ids[it] }.toTypedArray(), permutation.map { addresses[it] }.toLongArray(),
                permutation.map { present[it] }.toBooleanArray())
            assertEquals(ids.toList(), table.byAddress.map { table.ids[it] })
            assertSame(table.byAddress, table.byAddress)
        }
        for (count in 0..1) {
            val table = columnTable(WebStructureKind.FUNCTION, List(count) { null })
            assertContentEquals(IntArray(count) { it }, table.byAddress)
        }
    }

    @Test fun `functions keep recorded identity exact addresses ownership and evidence references`() {
        val revision = standard()
        val page = revision.pages.functions("owner", jobId, runId, revisionId, null)
        assertContract("functionInventory", page)
        assertEquals("available", page.text("state"))
        assertEquals("recorded-program-model", page.text("authority"))
        assertEquals(revision.sourceSha, page.text("sourceSha256"))
        val model = page.getValue("model").jsonObject
        assertEquals(sha(revision.model!!), model.text("sha256"))
        assertEquals("reports/program_model.json", model.text("path"))
        assertEquals(2, model.getValue("schemaVersion").jsonPrimitive.int)
        assertEquals("unassessed", page.text("recoveryAssessment"))
        assertEquals(sha(revision.plan!!), page.getValue("plan").jsonObject.text("sha256"))
        assertEquals(5, page.getValue("totalFunctions").jsonPrimitive.int)
        val rows = page.items()
        assertEquals(listOf("0x401000", "0x401100", "0x402000", "0x403000", "0xffffffffffffffff"), rows.map { it.text("address") })
        val main = rows.first()
        assertEquals("fn_0000000000401000", main.text("entityId")); assertEquals("fn_0000000000401000", main.text("selector"))
        assertEquals("main", main.text("name")); assertEquals("core", main.text("moduleId"))
        assertEquals(2, main.getValue("callCount").jsonPrimitive.int)
        // Evidence classes are distinguishable and derive only from recorded fields.
        assertEquals(mapOf("0x401000" to "recovered", "0x401100" to "unresolved", "0x402000" to "unresolved",
            "0x403000" to "excluded", "0xffffffffffffffff" to "unresolved"), rows.associate { it.text("address")!! to it.text("evidenceState")!! })
        assertEquals(mapOf("0x401000" to "owned", "0x401100" to "owned", "0x402000" to "owned", "0x403000" to "unowned",
            "0xffffffffffffffff" to "ambiguous"), rows.associate { it.text("address")!! to it.text("ownership")!! })
        assertTrue(rows[1].getValue("implementationUnresolved").jsonPrimitive.boolean)
        assertTrue(rows[1].getValue("nameCollision").jsonPrimitive.boolean)
        assertEquals("synthetic", rows[3].text("extractionStatus"))
        // No acceptance or source text is projected into the inventory.
        assertFalse(page.toString().contains("return helper")); assertFalse(page.containsKey("acceptance"))
    }

    @Test fun `case insensitive search preserves displayed Unicode names and identifiers`() {
        val dotted = "fn_dotted_İ"
        val revision = Revision(model(listOf(
            RecoveredFunction(dotted, "İşlev", 0x401000u, "int dotted(void)"),
            RecoveredFunction("fn_other", "Other", 0x401100u, "int other(void)"),
        )), null, emptyList())
        for ((search, expected) in listOf(
            "İşlev" to dotted, "işlev" to dotted, "İŞLEV" to dotted,
            dotted to dotted, "FN_DOTTED_i" to dotted,
            "0X4010" to dotted, "0X4011" to "fn_other",
        )) {
            val encoded = java.net.URLEncoder.encode(search, Charsets.UTF_8)
            val page = revision.pages.functions("owner", jobId, runId, revisionId, "search=$encoded")
            assertEquals(listOf(expected), page.items().map { it.text("entityId") }, search)
            assertEquals(1, page.getValue("matchedFunctions").jsonPrimitive.int, search)
            assertEquals(search, page.getValue("query").jsonObject.getValue("search").jsonPrimitive.content)
        }
    }

    @Test fun `sorting and filtering stay stable across page boundaries and report exact scope`() {
        val revision = standard()
        for ((query, expected) in listOf(
            "sort=name&order=desc&limit=2" to listOf("fn_0000000000403000", "fn_0000000000401000", "fn_ffffffffffffffff", "fn_0000000000401100", "fn_0000000000402000"),
            "sort=address&order=desc&limit=2" to listOf("fn_ffffffffffffffff", "fn_0000000000403000", "fn_0000000000402000", "fn_0000000000401100", "fn_0000000000401000"),
            "search=HELP&limit=1" to listOf("fn_0000000000401100", "fn_ffffffffffffffff"),
            "search=0x4011&limit=1" to listOf("fn_0000000000401100"),
            "evidence=unresolved&sort=id&limit=1" to listOf("fn_0000000000401100", "fn_0000000000402000", "fn_ffffffffffffffff"),
            "module=core&ownership=owned&limit=1" to listOf("fn_0000000000401000", "fn_0000000000401100"),
            "status=failed" to listOf("fn_0000000000402000"),
            "module=absent" to emptyList(),
        )) {
            val seen = mutableListOf<String>()
            var cursor: String? = null
            var pages = 0
            do {
                val page = revision.pages.functions("owner", jobId, runId, revisionId, query + (cursor?.let { "&cursor=$it" } ?: ""))
                assertContract("functionInventory", page)
                assertEquals(5, page.getValue("totalFunctions").jsonPrimitive.int, query)
                assertEquals(expected.size, page.getValue("matchedFunctions").jsonPrimitive.int, query)
                seen += page.items().map { it.text("entityId")!! }
                cursor = next(page); pages++
            } while (cursor != null && pages < 10)
            assertEquals(expected, seen, query)
        }
        val first = revision.pages.functions("owner", jobId, runId, revisionId, "sort=name&limit=2")
        val cursor = next(first)!!
        // A cursor belongs to one session, filter set and page size.
        for ((owner, query) in listOf("other" to "sort=name&limit=2", "owner" to "sort=id&limit=2", "owner" to "sort=name&limit=3")) {
            assertEquals("INVALID_CURSOR", assertFailsWith<WebAccessDenied> {
                revision.pages.functions(owner, jobId, runId, revisionId, "$query&cursor=$cursor")
            }.code)
        }
        for (query in listOf("sort=size", "order=up", "status=verified", "evidence=verified", "limit=201", "unknown=1", "search=")) {
            assertEquals(422, assertFailsWith<WebAccessDenied> { revision.pages.functions("owner", jobId, runId, revisionId, query) }.status, query)
        }
    }

    @Test fun `changed structure records expire cursors and pinned reads`() {
        val revision = standard()
        val first = revision.pages.functions("owner", jobId, runId, revisionId, "limit=2")
        val version = first.text("structureVersion")!!
        assertEquals(version, first.getValue("page").jsonObject.text("snapshotVersion"))
        val other = WebProgramStructurePages { _, _, _, project -> standard(acceptedModules = emptySet()).let { it.evidence.readStructure(it.reference, it.cache, project) } }
        // A different signer rejects the cursor before comparing versions.
        assertEquals("INVALID_CURSOR", assertFailsWith<WebAccessDenied> { other.functions("owner", jobId, runId, revisionId, "limit=2&cursor=${next(first)}") }.code)
        assertEquals("STRUCTURE_CHANGED", assertFailsWith<WebAccessDenied> {
            other.modules("owner", jobId, runId, revisionId, "structureVersion=$version")
        }.code)
        assertEquals(version, revision.pages.modules("owner", jobId, runId, revisionId, "structureVersion=$version").text("structureVersion"))
    }

    @Test fun `unsupported incomplete or foreign records never appear as an empty successful inventory`() {
        val duplicateFunctionId = model(functions).toString(Charsets.UTF_8).replace(
            "\"id\": \"fn_0000000000401100\"", "\"id\": \"fn_0000000000401000\"")
        assertNotEquals(model(functions).toString(Charsets.UTF_8), duplicateFunctionId)
        val nonCanonicalAddress = model(functions).toString(Charsets.UTF_8).replace(
            "\"address\": \"0x401000\"", "\"address\": \"0x0401000\"")
        assertNotEquals(model(functions).toString(Charsets.UTF_8), nonCanonicalAddress)
        val nonStringPrototype = model(functions).toString(Charsets.UTF_8).replace(
            "\"prototype\": \"int main(void)\"", "\"prototype\": 1")
        assertNotEquals(model(functions).toString(Charsets.UTF_8), nonStringPrototype)
        val duplicatePrototypeField = model(functions).toString(Charsets.UTF_8).replace(
            "\"prototype\": \"int main(void)\"", "\"prototype\": \"int main(void)\", \"prototype\": \"other\"")
        assertNotEquals(model(functions).toString(Charsets.UTF_8), duplicatePrototypeField)
        val cases = listOf(
            Revision(null, null, listOf("core")) to ("not-recorded" to "MODEL_NOT_RECORDED"),
            Revision("{\"schemaVersion\": 9, \"inputSha256\": \"$inputSha\"}".toByteArray(), null, listOf("core")) to ("unsupported" to "MODEL_SCHEMA_UNSUPPORTED"),
            Revision("{\"schemaVersion\": 2, \"inputSha256\": \"$inputSha\", \"functions\": [".toByteArray(), null, listOf("core")) to ("invalid" to "MODEL_MALFORMED"),
            Revision(duplicateFunctionId.toByteArray(), null, listOf("core")) to ("invalid" to "MODEL_MALFORMED"),
            Revision(nonCanonicalAddress.toByteArray(), null, listOf("core")) to ("invalid" to "MODEL_MALFORMED"),
            Revision(nonStringPrototype.toByteArray(), null, listOf("core")) to ("invalid" to "MODEL_MALFORMED"),
            Revision(duplicatePrototypeField.toByteArray(), null, listOf("core")) to ("invalid" to "MODEL_MALFORMED"),
            Revision(model(functions, schema = 2).toString(Charsets.UTF_8).replace("\"unassessed\"", "\"exact\"").toByteArray(), null, listOf("core")) to ("invalid" to "MODEL_MALFORMED"),
            Revision(model(functions, input = "f".repeat(64)), null, listOf("core")) to ("invalid" to "MODEL_INPUT_MISMATCH"),
            Revision(ByteArray(WebProgramStructureBuilder.MAXIMUM_MODEL_BYTES + 1) { ' '.code.toByte() }, null, listOf("core")) to ("limit-exceeded" to "MODEL_BYTES_EXCEEDED"),
        )
        for ((revision, expected) in cases) {
            val page = revision.pages.functions("owner", jobId, runId, revisionId, null)
            assertContract("functionInventory", page)
            assertEquals(expected.first, page.text("state")); assertEquals(expected.second, page.text("stateReason"))
            assertEquals(JsonNull, page["totalFunctions"]); assertEquals(JsonNull, page["matchedFunctions"])
            assertTrue(page.items().isEmpty()); assertNull(next(page))
            assertEquals("not-recorded", page.text("recoveryAssessment"))
            val modules = revision.pages.modules("owner", jobId, runId, revisionId, null)
            assertContract("moduleInventory", modules)
            assertEquals(JsonNull, modules["summary"]); assertEquals(JsonNull, modules["totalModules"])
            assertEquals(JsonNull, revision.pages.entity(WebStructureKind.FUNCTION, jobId, runId, revisionId, "fn_0000000000401000", null)["entity"])
            assertEquals(expected.first, page.getValue("capabilities").jsonArray.first().jsonObject.text("state"))
        }
        // The schema itself refuses an unavailable document that carries rows.
        val invalid = JsonObject(standard().pages.functions("owner", jobId, runId, revisionId, null) + ("state" to JsonPrimitive("unsupported")))
        assertFailsWith<AssertionError> { assertContract("functionInventory", invalid) }
    }

    @Test fun `unsupported plans leave ownership explicitly not recorded`() {
        val unsupported = Revision(model(functions), "{\"schemaVersion\": 3}\n".toByteArray(), listOf("core"))
        val page = unsupported.pages.functions("owner", jobId, runId, revisionId, null)
        assertEquals("available", page.text("state"))
        assertEquals("unsupported", page.getValue("plan").jsonObject.text("state"))
        assertEquals(setOf("not-recorded"), page.items().map { it.text("ownership") }.toSet())
        val modules = unsupported.pages.modules("owner", jobId, runId, revisionId, null)
        assertContract("moduleInventory", modules)
        assertEquals(JsonNull, modules["totalModules"]); assertTrue(modules.items().isEmpty())
        assertEquals("unsupported", modules.getValue("capabilities").jsonArray.single { it.jsonObject.text("id") == "module-ownership" }.jsonObject.text("state"))
        val detail = unsupported.pages.module("owner", jobId, runId, revisionId, "core", null)
        assertContract("moduleDetail", detail); assertEquals(JsonNull, detail["module"])
        val absent = Revision(model(functions), null, listOf("core")).pages.functions("owner", jobId, runId, revisionId, null)
        assertEquals("not-recorded", absent.getValue("plan").jsonObject.text("state"))
    }

    @Test fun `module detail lists owned entities progress and revision source links`() {
        val revision = standard()
        val modules = revision.pages.modules("owner", jobId, runId, revisionId, "limit=1")
        assertContract("moduleInventory", modules)
        assertEquals(2, modules.getValue("totalModules").jsonPrimitive.int)
        val summary = modules.getValue("summary").jsonObject
        assertEquals(1, summary.getValue("modulesDeclaredAccepted").jsonPrimitive.int)
        assertEquals(1, summary.getValue("unknownPlanReferences").jsonPrimitive.int)
        assertEquals(1, summary.getValue("unresolvedCallTargets").jsonPrimitive.int)
        assertEquals(1, summary.getValue("unresolvedGlobalReferences").jsonPrimitive.int)
        assertEquals(1, summary.getValue("nameCollisions").jsonPrimitive.int)
        assertEquals(1, summary.getValue("functions").jsonObject.getValue("ownership").jsonObject.getValue("ambiguous").jsonPrimitive.int)
        val core = modules.items().single()
        assertEquals("core", core.text("moduleId")); assertEquals("accepted", core.text("implementationDeclaration"))
        assertEquals(mapOf("recovered" to 1, "inferred" to 0, "unresolved" to 2, "excluded" to 0),
            core.getValue("functionEvidence").jsonObject.mapValues { it.value.jsonPrimitive.int })
        assertEquals(listOf("extra"), revision.pages.modules("owner", jobId, runId, revisionId, "limit=1&cursor=${next(modules)}").items().map { it.text("moduleId") })

        val detail = revision.pages.module("owner", jobId, runId, revisionId, "extra", "kind=functions&limit=2")
        assertContract("moduleDetail", detail)
        val module = detail.getValue("module").jsonObject
        assertEquals("unaccepted", module.text("implementationDeclaration"))
        val snapshot = revision.evidence.readRevision(revision.reference)
        val implementation = snapshot.files.indexOfFirst { it.evidence.path == "src/modules/extra.c" }
        assertEquals(revisionSourceFileId(revision.reference, implementation, "src/modules/extra.c"), module.text("implementationFileId"))
        assertEquals("include/modules/extra.h", module.text("interfacePath"))
        val owned = detail.getValue("owned").jsonObject
        assertEquals(3, owned.getValue("total").jsonPrimitive.int)
        assertEquals(listOf("fn_0000000000402000", "fn_ffffffffffffffff"), owned.items().map { it.text("entityId") })
        val rest = revision.pages.module("owner", jobId, runId, revisionId, "extra", "kind=functions&limit=2&cursor=${next(owned)}")
        val unrecorded = rest.getValue("owned").jsonObject.items().single()
        assertEquals("fn_unrecorded", unrecorded.text("entityId")); assertFalse(unrecorded.getValue("recorded").jsonPrimitive.boolean)
        assertContract("moduleDetail", rest)
        val coreTypes = revision.pages.module("owner", jobId, runId, revisionId, "core", "kind=types")
        assertEquals(listOf("type_${"c".repeat(64)}"), coreTypes.getValue("owned").jsonObject.items().map { it.text("entityId") })
        val boundary = coreTypes.getValue("module").jsonObject.getValue("boundaryEvidence").jsonObject
        assertEquals("calls:fn_0000000000401100", boundary.items().single().text("text"))
        assertEquals("MODULE_NOT_FOUND", assertFailsWith<WebAccessDenied> { revision.pages.module("owner", jobId, runId, revisionId, "absent", null) }.code)
        // Module progress uses recorded counts; it never reads module source bodies.
        assertTrue(revision.reads.none { it.endsWith(".c") || it.endsWith(".h") })
    }

    @Test fun `entity facts keep bounded previews cross links collisions and explicit unrecorded families`() {
        val revision = standard()
        val main = revision.pages.entity(WebStructureKind.FUNCTION, jobId, runId, revisionId, "fn_0000000000401000", null)
        assertContract("entityDetail", main)
        val entity = main.getValue("entity").jsonObject
        assertEquals("int main(void)", entity.getValue("texts").jsonArray.first().jsonObject.getValue("preview").jsonObject.text("text"))
        val calls = entity.getValue("calls").jsonObject.items()
        assertEquals(listOf("recorded" to "fn_0000000000401100", "no-record" to "fn_00000000deadbeef"), calls.map { it.text("resolution")!! to it.text("entityId")!! })
        assertEquals(JsonNull, calls[1]["selector"])
        assertEquals(listOf("recorded", "no-record"), entity.getValue("referencedGlobals").jsonObject.items().map { it.text("resolution") })
        assertEquals("hello", entity.getValue("strings").jsonObject.items().single().text("text"))
        val sources = entity.getValue("sources").jsonObject
        assertEquals("src/modules/core.c", sources.text("implementationPath")); assertNotNull(sources.text("implementationFileId"))
        assertEquals("include/decomp_types.h", sources.text("sharedInterfacePath")); assertNotNull(sources.text("sharedInterfaceFileId"))

        val helper = revision.pages.entity(WebStructureKind.FUNCTION, jobId, runId, revisionId, "fn_0000000000401100", null)
        assertContract("entityDetail", helper)
        val body = helper.getValue("entity").jsonObject.getValue("texts").jsonArray[1].jsonObject
        assertEquals("decompiledC", body.text("field"))
        val preview = body.getValue("preview").jsonObject
        assertEquals("5000", preview.text("characters")); assertTrue(preview.getValue("truncated").jsonPrimitive.boolean)
        assertEquals(WebStructureText.PREVIEW_CHARACTERS, preview.text("text")!!.length)
        val helperEntity = helper.getValue("entity").jsonObject
        assertEquals(listOf("fn_0000000000401000"), helperEntity.getValue("calledBy").jsonObject.items().map { it.text("entityId") })
        // Name collisions span functions and globals.
        assertEquals(setOf("fn_ffffffffffffffff", "global_0000000000404000"),
            helperEntity.getValue("collisions").jsonObject.items().map { it.text("entityId") }.toSet())

        val global = revision.pages.entity(WebStructureKind.GLOBAL, jobId, runId, revisionId, "global_0000000000404000", null)
        assertContract("entityDetail", global)
        val globalEntity = global.getValue("entity").jsonObject
        assertEquals("unsupported-schema", globalEntity.text("byteEvidence"))
        assertEquals(listOf("fn_0000000000401000"), globalEntity.getValue("referencedBy").jsonObject.items().map { it.text("entityId") })
        assertEquals(listOf("type", "initializer"), globalEntity.getValue("texts").jsonArray.map { it.jsonObject.text("field") })

        val type = revision.pages.entity(WebStructureKind.TYPE, jobId, runId, revisionId, "type_${"c".repeat(64)}", null)
        assertContract("entityDetail", type)
        assertEquals("0x405000", type.getValue("entity").jsonObject.text("address"))
        val capabilities = type.getValue("capabilities").jsonArray.associate { it.jsonObject.text("id")!! to it.jsonObject.text("state")!! }
        for (family in listOf("type-layouts", "abi-interfaces", "cpp-object-model", "type-references", "recovery-assessment")) {
            assertEquals("not-recorded", capabilities[family], family)
        }
        assertEquals("available", capabilities["generated-headers"])
        for ((kind, selector) in listOf(WebStructureKind.GLOBAL to "fn_0000000000401000", WebStructureKind.FUNCTION to "fn_unrecorded")) {
            assertEquals("ENTITY_NOT_FOUND", assertFailsWith<WebAccessDenied> { revision.pages.entity(kind, jobId, runId, revisionId, selector, null) }.code)
        }
        assertEquals(422, assertFailsWith<WebAccessDenied> { revision.pages.entity(WebStructureKind.TYPE, jobId, runId, revisionId, "x", "limit=1") }.status)
    }

    @Test fun `long multi-byte names keep entity details and owned pages within the browser response limit`() {
        val name = { index: Int -> "名".repeat(WebProgramStructureBuilder.MAXIMUM_IDENTIFIER_CHARACTERS - 8) + index }
        val peers = (0 until 100).map { 0x401000uL + it.toULong() * 16uL }
        val hubAddress = 0x500000uL
        val globals = (0 until 60).map { RecoveredGlobal("global_$it", name(1000 + it), 0x600000uL + it.toULong() * 8uL, "int") }
        val functions = peers.mapIndexed { index, address ->
            RecoveredFunction(stableFunctionId(address), name(index), address, "void f(void)", null, calls = setOf(stableFunctionId(hubAddress)))
        } + RecoveredFunction(stableFunctionId(hubAddress), "hub", hubAddress, "void hub(void)", null,
            calls = peers.map(::stableFunctionId).toSet(), referencedGlobals = globals.map { it.id }.toSet())
        val revision = Revision(model(functions, globals), plan(planned("core", functions.map { it.id }, globals.map { it.id })), listOf("core"))
        fun bytes(value: JsonObject) = value.toString().toByteArray(Charsets.UTF_8).size

        val detail = revision.pages.entity(WebStructureKind.FUNCTION, jobId, runId, revisionId, stableFunctionId(hubAddress), null)
        assertContract("entityDetail", detail)
        assertTrue(bytes(detail) < 1_048_576, "entity detail bytes ${bytes(detail)}")
        val entity = detail.getValue("entity").jsonObject
        for (field in listOf("calls", "calledBy", "referencedGlobals")) {
            val references = entity.getValue(field).jsonObject
            assertEquals(if (field == "referencedGlobals") 60 else 100, references.getValue("total").jsonPrimitive.int, field)
            assertTrue(references.items().size <= 50, field)
        }
        assertTrue(listOf("calls", "calledBy", "referencedGlobals").sumOf { entity.getValue(it).jsonObject.items().size } < 150,
            "some reference list was shortened to fit")

        var cursor: String? = null
        var pages = 0
        val seen = mutableListOf<String>()
        do {
            val page = revision.pages.module("owner", jobId, runId, revisionId, "core", "kind=functions&limit=200" + (cursor?.let { "&cursor=$it" } ?: ""))
            assertContract("moduleDetail", page)
            assertTrue(bytes(page) < 1_048_576, "owned page bytes ${bytes(page)}")
            val owned = page.getValue("owned").jsonObject
            seen += owned.items().map { it.text("entityId")!! }
            cursor = next(owned)
            pages++
        } while (cursor != null)
        assertEquals(functions.map { it.id }, seen)
        assertTrue(pages > 1, "a 200-row owned page must split by bytes")
    }

    @Test fun `owned pages charge escaped module metadata and the complete response envelope`() {
        val functions = (0 until 25).map { index ->
            RecoveredFunction("\u0001".repeat(4090) + "id_$index", "\u0001".repeat(4096), index.toULong(), "void f(void)")
        }
        val moduleId = "m".repeat(128)
        val ids = functions.map { it.id } + listOf("\u0002".repeat(4096), "fn_missing")
        val module = PlannedModule(moduleId, "\u0800".repeat(4096), "\u0801".repeat(4096),
            ids, emptyList(), emptyList(), List(20) { "\u0001".repeat(256) + it })
        val revision = Revision(model(functions), plan(module), emptyList())
        for (limit in listOf(20, 200)) {
            var cursor: String? = null
            var pages = 0
            val seen = mutableListOf<String>()
            do {
                val data = revision.pages.module("owner", jobId, runId, revisionId, moduleId,
                    "kind=functions&limit=$limit" + (cursor?.let { "&cursor=$it" } ?: ""))
                assertContract("moduleDetail", data)
                assertEquals("available", data.text("state"))
                assertEquals("available", data.getValue("plan").jsonObject.text("state"))
                val metadata = data.getValue("module").jsonObject
                assertEquals(module.sourcePath, metadata.text("implementationPath"))
                assertEquals(module.headerPath, metadata.text("interfacePath"))
                assertEquals(20, metadata.getValue("boundaryEvidence").jsonObject.items().size)
                val envelope = buildJsonObject {
                    put("apiVersion", 1); put("kind", "moduleDetail")
                    put("requestId", "00000000-0000-0000-0000-000000000000"); put("data", data)
                }
                val bytes = envelope.toString().toByteArray(Charsets.UTF_8).size
                assertTrue(bytes <= 1_048_576, "complete module response bytes $bytes")
                val owned = data.getValue("owned").jsonObject
                assertEquals(ids.size, owned.getValue("total").jsonPrimitive.int)
                assertTrue(owned.items().size in 1..limit)
                for (item in owned.items()) {
                    assertEquals(item.text("entityId") in functions.map { it.id }, item.getValue("recorded").jsonPrimitive.boolean)
                }
                seen += owned.items().map { it.text("entityId")!! }
                cursor = next(owned)
                if (cursor != null) assertEquals(seen.size, cursor.split('_')[1].toInt())
                pages++
                assertTrue(pages < 10, "owned pagination must make progress")
            } while (cursor != null)
            assertEquals(ids, seen)
            assertTrue(pages > 1, "owned pages split by bytes, not just the requested row limit")
        }
        val empty = revision.pages.module("owner", jobId, runId, revisionId, moduleId, "kind=types&limit=200")
        assertContract("moduleDetail", empty)
        assertTrue(empty.getValue("owned").jsonObject.items().isEmpty())
        assertNull(next(empty.getValue("owned").jsonObject))
    }

    @Test fun `retained projections stay readable after an attempt version change with identical commitments`() {
        val revision = standard()
        assertEquals("available", revision.pages.functions("owner", jobId, runId, revisionId, null).text("state"))
        // A progress-retention pin changes only the attempt version of the same candidate.
        val pinned = WebProgramStructurePages { _, _, _, project ->
            revision.evidence.readStructure(revision.reference.copy(attemptVersion = "version_2"), revision.cache, project)
        }
        repeat(2) {
            val page = pinned.functions("owner", jobId, runId, revisionId, null)
            assertEquals("available", page.text("state")); assertEquals(5, page.getValue("totalFunctions").jsonPrimitive.int)
        }
        assertEquals(1, revision.reads.count { it == "reports/runs/$runId/source-tree/reports/program_model.json" })
    }

    @Test fun `canonical plans must satisfy projection bounds before assigning any ownership`() {
        val owned = listOf(functions.first().id)
        val valid = planned("core", owned)
        val cases = listOf(
            valid.copy(id = "bad module") to "invalid",
            valid.copy(id = "m".repeat(129)) to "limit-exceeded",
            valid.copy(id = "m".repeat(2 * 1024 * 1024)) to "limit-exceeded",
            valid.copy(sourcePath = "../core.c") to "invalid",
            valid.copy(headerPath = "include/invalid:header.h") to "invalid",
            valid.copy(headerPath = "h".repeat(4097)) to "limit-exceeded",
            valid.copy(functionIds = owned + "unknown".repeat(600)) to "limit-exceeded",
            valid.copy(globalIds = listOf("")) to "invalid",
        ).map { (module, state) -> plan(module) to state } + listOf(
            plan(valid, cycles = listOf(listOf("core", "missing"))) to "invalid",
            plan(valid, cycles = listOf(listOf("core", "m".repeat(129)))) to "limit-exceeded",
            plan(valid, valid) to "invalid",
        )
        for ((bytes, state) in cases) {
            val revision = Revision(model(functions.take(1)), bytes, listOf("core"))
            val page = revision.pages.functions("owner", jobId, runId, revisionId, null)
            assertContract("functionInventory", page)
            assertEquals("available", page.text("state"))
            assertEquals(state, page.getValue("plan").jsonObject.text("state"))
            assertEquals("not-recorded", page.items().single().text("ownership"))
            assertEquals(JsonNull, page.items().single()["moduleId"])
            val modules = revision.pages.modules("owner", jobId, runId, revisionId, null)
            assertContract("moduleInventory", modules)
            assertEquals(JsonNull, modules["totalModules"])
            assertTrue(modules.items().isEmpty())
        }
    }

    @Test fun `schema three and four byte evidence uses the producer closed shape and generation contract`() {
        val window = Json.parseToJsonElement("""{"address":"0x404000","requestedLength":null,"origin":{"instructionAddress":"0x401000","referenceAddress":"0x404000","operandIndex":null,"widthBasis":"unknown_width"},"availability":"unknown","segments":[]}""")
        fun evidence(version: Int) = buildJsonObject {
            put("schemaVersion", version); put("windows", JsonArray(listOf(window))); put("omissionReason", "unknown_access_width")
            if (version == 2) put("collectionOmissions", JsonArray(emptyList()))
        }
        fun revision(version: Int, evidence: JsonElement): Revision {
            val root = Json.parseToJsonElement(model(emptyList(), globals).decodeToString()).jsonObject
            val global = JsonObject(root.getValue("globals").jsonArray.single().jsonObject + ("byteEvidence" to evidence))
            val bytes = JsonObject(root + mapOf("schemaVersion" to JsonPrimitive(version), "globals" to JsonArray(listOf(global)))).toString().toByteArray()
            return Revision(bytes, null, emptyList())
        }
        for ((version, value) in listOf(3 to evidence(1), 4 to evidence(2), 4 to JsonNull)) {
            val record = revision(version, value)
            val detail = record.pages.entity(WebStructureKind.GLOBAL, jobId, runId, revisionId, globals.single().id, null)
            assertContract("entityDetail", detail)
            assertEquals("available", detail.text("state"))
            assertEquals(if (value == JsonNull) "not-recorded" else "recorded", detail.getValue("entity").jsonObject.text("byteEvidence"))
        }
        for (version in 3..4) {
            val good = evidence(version - 2)
            val bad = listOf(JsonPrimitive(false), JsonPrimitive(1), JsonPrimitive("recorded"), JsonArray(emptyList()),
                evidence(if (version == 3) 2 else 1), JsonObject(good + ("unknown" to JsonNull)),
                JsonObject(good + ("windows" to JsonArray(listOf(JsonObject(window.jsonObject + ("unknown" to JsonNull))))))) +
                if (version == 3) listOf(JsonNull) else emptyList()
            for (value in bad) {
                val page = revision(version, value).pages.functions("owner", jobId, runId, revisionId, null)
                assertContract("functionInventory", page)
                assertEquals("invalid", page.text("state"), "schema=$version value=$value")
                assertEquals("MODEL_MALFORMED", page.text("stateReason"))
                assertTrue(page.items().isEmpty())
            }
        }
    }

    private fun rawModelOutcome(raw: String): JsonObject =
        Revision(raw.toByteArray(), null, emptyList()).pages.functions("owner", jobId, runId, revisionId, null)

    private fun assertRawModelOutcome(raw: String, state: String = "invalid", reason: String? = "MODEL_MALFORMED") {
        val page = rawModelOutcome(raw)
        assertEquals(state, page.text("state"))
        assertEquals(reason, page.text("stateReason"))
        if (state != "available") assertTrue(page.items().isEmpty())
    }

    @Test fun `decoded scalar buffers accept escaped wire values and preserve unsigned addresses`() {
        for (version in 1..2) {
            val raw = Json.parseToJsonElement(model(functions, globals, types +
                RecoveredType("no_address", "struct NoAddress {};", null), schema = version).decodeToString()).jsonObject.toString()
            var escaped = raw
            for (value in listOf("recovered", "partial", "failed", "synthetic", "unassessed",
                "0x401000", "0x401100", "0xffffffffffffffff", "0x402000", "0x403000", "0x404000", "0x405000")) {
                val encoded = value.map { "\\u%04x".format(it.code) }.joinToString("")
                escaped = escaped.replace("\"$value\"", "\"$encoded\"")
            }
            assertNotEquals(raw, escaped)
            fun index(value: String): WebProgramStructureIndex {
                val revision = Revision(value.toByteArray(), null, emptyList())
                return revision.evidence.readStructure(revision.reference, revision.cache) { index, _ -> index }
            }
            val plain = index(raw); val decoded = index(escaped)
            for (kind in WebStructureKind.entries) {
                val expected = plain.table(kind); val actual = decoded.table(kind)
                assertContentEquals(expected.ids, actual.ids)
                assertContentEquals(expected.addresses, actual.addresses)
                assertContentEquals(expected.hasAddress, actual.hasAddress)
                assertContentEquals(expected.status, actual.status)
                assertContentEquals(expected.byAddress, actual.byAddress)
            }
            val decodedFunctions = decoded.table(WebStructureKind.FUNCTION)
            val decodedTypes = decoded.table(WebStructureKind.TYPE)
            assertEquals(-1L, decodedFunctions.addresses[decodedFunctions.index.getValue("fn_ffffffffffffffff")])
            assertFalse(decodedTypes.hasAddress[decodedTypes.index.getValue("no_address")])
            assertEquals(plain.retainedBytes, decoded.retainedBytes)
        }
        for (value in listOf("0x0", "0x1", "0x7fffffffffffffff", "0x8000000000000000", "0xffffffffffffffff")) {
            val raw = Json.parseToJsonElement(model(functions.take(1)).decodeToString()).jsonObject.toString()
                .replace("\"0x401000\"", "\"$value\"")
            val row = rawModelOutcome(raw).items().single()
            assertEquals(value, row.text("address"))
        }
    }

    @Test fun `scalar semantic validation remains exact for every entity family and schema fieldset`() {
        for (version in 1..2) {
            val root = Json.parseToJsonElement(model(functions.take(1), globals, types, schema = version).decodeToString()).jsonObject
            val statusKey = if (version == 1) "status" else "extractionStatus"
            for (family in listOf("functions", "globals", "types")) {
                val entity = root.getValue(family).jsonArray.single().jsonObject
                val addressKey = if (family == "types") "sourceAddress" else "address"
                fun changed(key: String, value: JsonElement) = root.toString().replace(entity.toString(),
                    JsonObject(entity + (key to value)).toString())
                for (value in listOf("", "0x", "0X1", "0x00", "0x0401000", "0xA", "0xabcdefABC", "0x10000000000000000", "0x-1", "0x1 ")) {
                    assertRawModelOutcome(changed(addressKey, JsonPrimitive(value)))
                }
                for (value in listOf("recovered ", "Recovered", "", "unknown")) {
                    assertRawModelOutcome(changed(statusKey, JsonPrimitive(value)))
                }
                if (version == 2) for (value in listOf("exact", "unassessed ", "Unassessed", "")) {
                    assertRawModelOutcome(changed("recoveryAssessment", JsonPrimitive(value)))
                }
                for (value in listOf(JsonNull, JsonPrimitive(1), JsonPrimitive(true), JsonArray(emptyList()), JsonObject(emptyMap()))) {
                    assertRawModelOutcome(changed(statusKey, value))
                    if (version == 2) assertRawModelOutcome(changed("recoveryAssessment", value))
                    if (family == "types" && value == JsonNull) assertRawModelOutcome(changed(addressKey, value), "available", null)
                    else assertRawModelOutcome(changed(addressKey, value))
                }
                val otherStatus = if (version == 1) "extractionStatus" else "status"
                assertRawModelOutcome(root.toString().replace(entity.toString(),
                    JsonObject(entity - statusKey + (otherStatus to entity.getValue(statusKey))).toString()))
                if (version == 1) assertRawModelOutcome(changed("recoveryAssessment", JsonPrimitive("unassessed")))
            }
        }
    }

    @Test fun `invalid scalar semantics defer to oversized identifiers but token errors remain immediate`() {
        for (version in 1..2) {
            val root = Json.parseToJsonElement(model(functions.take(1), globals, types, schema = version).decodeToString()).jsonObject
            for (family in listOf("functions", "globals", "types")) {
                val entity = root.getValue(family).jsonArray.single().jsonObject
                val keys = listOf(if (version == 1) "status" else "extractionStatus",
                    if (family == "types") "sourceAddress" else "address") +
                    if (version == 2) listOf("recoveryAssessment") else emptyList()
                for (key in keys) {
                    fun reordered(value: JsonElement, oversized: Boolean): String {
                        val fields = linkedMapOf(key to value, "id" to if (oversized) JsonPrimitive("x".repeat(4097)) else entity.getValue("id"))
                        fields.putAll(entity - key - "id")
                        return root.toString().replace(entity.toString(), JsonObject(fields).toString())
                    }
                    assertRawModelOutcome(reordered(JsonPrimitive("invalid"), false))
                    assertRawModelOutcome(reordered(JsonPrimitive("invalid"), true), "limit-exceeded", "MODEL_IDENTIFIER_EXCEEDED")
                    for (token in listOf(JsonNull, JsonPrimitive(1), JsonPrimitive(true), JsonArray(emptyList()), JsonObject(emptyMap()))) {
                        if (key == "sourceAddress" && token == JsonNull) {
                            assertRawModelOutcome(reordered(token, true), "limit-exceeded", "MODEL_IDENTIFIER_EXCEEDED")
                        } else assertRawModelOutcome(reordered(token, true))
                    }
                }
            }
        }
    }

    @Test fun `identifier scratch arrays stay detached between rows families and reader invocations`() {
        val rows = listOf(
            RecoveredFunction("first", "First", 1u, "void first(void)", null,
                calls = linkedSetOf("a", "b"), referencedGlobals = linkedSetOf("g", "h")),
            RecoveredFunction("second", "Second", 2u, "void second(void)", null,
                calls = setOf("c"), referencedGlobals = setOf("i")),
            RecoveredFunction("third", "Third", 3u, "void third(void)", null),
        )
        val revision = Revision(model(rows, listOf(RecoveredGlobal("g", "G", 4u, "int", null))), null, emptyList())
        fun read(): WebProgramStructureIndex = revision.evidence.readStructure(revision.reference, WebProgramStructureCache()) { index, _ -> index }
        val first = read(); val second = read()
        val table = first.table(WebStructureKind.FUNCTION)
        assertContentEquals(arrayOf("a", "b"), table.calls[0])
        assertContentEquals(arrayOf("c"), table.calls[1])
        assertContentEquals(arrayOf("g", "h"), table.referencedGlobals[0])
        assertContentEquals(arrayOf("i"), table.referencedGlobals[1])
        assertSame(table.calls[2], table.referencedGlobals[2])
        assertSame(table.calls[2], first.table(WebStructureKind.GLOBAL).calls[0])
        assertNotSame(table.calls[0], table.calls[1])
        assertNotSame(table.calls[0], table.referencedGlobals[0])
        assertNotSame(table.calls[0], second.table(WebStructureKind.FUNCTION).calls[0])
        table.calls[0][0] = "changed"
        table.referencedGlobals[0][0] = "changed global"
        assertContentEquals(arrayOf("c"), table.calls[1])
        assertContentEquals(arrayOf("i"), table.referencedGlobals[1])
        assertContentEquals(arrayOf("a", "b"), second.table(WebStructureKind.FUNCTION).calls[0])
        assertContentEquals(arrayOf("g", "h"), second.table(WebStructureKind.FUNCTION).referencedGlobals[0])
        assertContentEquals(arrayOf("g"), first.table(WebStructureKind.GLOBAL).ids)
    }

    @Test fun `fixed entity duplicate names and escaped aliases fail before consuming their values`() {
        val root = Json.parseToJsonElement(model(functions.take(1)).decodeToString()).jsonObject
        val entity = root.getValue("functions").jsonArray.single().jsonObject
        fun withEntity(raw: String) = root.toString().replace(entity.toString(), raw)
        for ((key, alias, value) in listOf(
            Triple("id", "id", "\"replacement\""),
            Triple("id", "\\u0069d", "\"replacement\""),
            Triple("id", "id", "\"${"x".repeat(4097)}\""),
            Triple("extractionStatus", "extractionStatus", "\"failed\""),
            Triple("decompiledC", "decompiledC", "null"),
            Triple("prototype", "prototype", "\"other\""),
        )) {
            // Put the duplicate immediately after a valid first value, before any subsequent fields.
            val first = "\"$key\":${entity.getValue(key)}"
            val changed = entity.toString().replace(first, "$first,\"$alias\":$value")
            assertNotEquals(entity.toString(), changed, key)
            assertRawModelOutcome(withEntity(changed))
        }
        // A decoded alias on its own is still a recognized field.
        assertRawModelOutcome(withEntity(entity.toString().replace("\"id\":", "\"\\u0069d\":")), "available", null)
    }

    @Test fun `closed entity masks reject unknown missing and wrong family fields across model generations`() {
        for (version in 1..4) {
            val evidence = if (version == 3) ReferencedDataByteEvidenceJson.parse(Json.parseToJsonElement(
                """{"schemaVersion":1,"windows":[${rawByteWindow()}],"omissionReason":null}""").jsonObject) else null
            val versionGlobals = globals.map { it.copy(byteEvidence = evidence) }
            val root = Json.parseToJsonElement(model(functions.take(1), versionGlobals, types, schema = version).decodeToString()).jsonObject
            assertRawModelOutcome(root.toString(), "available", null)
            for (family in listOf("functions", "globals", "types")) {
                val entity = root.getValue(family).jsonArray.single().jsonObject
                for (key in entity.keys) {
                    assertRawModelOutcome(root.toString().replace(entity.toString(), JsonObject(entity - key).toString()))
                    val duplicate = entity.toString().dropLast(1) + ",\"$key\":null}"
                    assertRawModelOutcome(root.toString().replace(entity.toString(), duplicate))
                }
                for (key in listOf("unknown", if (family == "functions") "initializer" else "prototype")) {
                    val unknown = "{\"$key\":\"${"x".repeat(4097)}\"," + entity.toString().drop(1)
                    assertRawModelOutcome(root.toString().replace(entity.toString(), unknown))
                }
            }
        }
    }

    @Test fun `root duplicate fields preserve first unsupported schema precedence`() {
        val good = Json.parseToJsonElement(model(emptyList()).decodeToString()).jsonObject.toString()
        for (key in listOf("schemaVersion", "inputSha256", "functions", "globals", "types")) {
            val value = Json.parseToJsonElement(good).jsonObject.getValue(key)
            assertRawModelOutcome(good.replace("\"$key\":$value", "\"$key\":$value,\"$key\":$value"))
        }
        assertRawModelOutcome(good.replace("\"schemaVersion\":2", "\"schemaVersion\":9,\"schemaVersion\":2"),
            "unsupported", "MODEL_SCHEMA_UNSUPPORTED")
    }

    private fun rawByteEvidenceModel(evidence: String, version: Int = 3): String {
        val root = Json.parseToJsonElement(model(emptyList(), globals).decodeToString()).jsonObject
        val global = root.getValue("globals").jsonArray.single().jsonObject.toString().dropLast(1) +
            ",\"byteEvidence\":$evidence}"
        return root.toString().replace("\"schemaVersion\":2", "\"schemaVersion\":$version")
            .replace(root.getValue("globals").toString(), "[$global]")
    }

    private fun rawByteWindow(address: String = "0x404000"): String =
        """{"address":"$address","requestedLength":2,"origin":{"instructionAddress":"0x401000","referenceAddress":"$address","operandIndex":null,"widthBasis":"pcode_load"},"availability":"partial","segments":[{"offset":0,"length":1,"availability":"available","hex":"01","reason":null},{"offset":1,"length":1,"availability":"unavailable","hex":null,"reason":"unmapped"}]}"""

    @Test fun `byte evidence objects reject top nested origin and escaped duplicate names`() {
        for (version in 3..4) {
            val evidence = """{"schemaVersion":${version - 2},"windows":[${rawByteWindow()}],"omissionReason":null${if (version == 4) ",\"collectionOmissions\":[]" else ""}}"""
            assertRawModelOutcome(rawByteEvidenceModel(evidence, version), "available", null)
            for ((first, duplicate) in listOf(
                "\"schemaVersion\":${version - 2}" to "\"schemaVersion\":${version - 2}",
                "\"schemaVersion\":${version - 2}" to "\"\\u0073chemaVersion\":${version - 2}",
                "\"address\":\"0x404000\"" to "\"address\":\"0x404000\"",
                "\"instructionAddress\":\"0x401000\"" to "\"instructionAddress\":\"0x401000\"",
                "\"instructionAddress\":\"0x401000\"" to "\"\\u0069nstructionAddress\":\"0x401000\"",
                "\"offset\":0" to "\"offset\":0",
            )) {
                val changed = evidence.replace(first, "$first,$duplicate")
                assertNotEquals(evidence, changed)
                assertRawModelOutcome(rawByteEvidenceModel(changed, version))
            }
        }
    }

    @Test fun `byte evidence accepts repeated names in siblings arrays and different object depths`() {
        // Window and segment availability repeat at different depths; both windows and segments have siblings.
        val evidence = """{"schemaVersion":1,"windows":[${rawByteWindow()},${rawByteWindow("0x404002")}],"omissionReason":null}"""
        assertRawModelOutcome(rawByteEvidenceModel(evidence), "available", null)
    }

    @Test fun `byte evidence duplicate token wins over token and byte scan limits`() {
        // Excluding START_OBJECT: schema name/value (2), windows name/array (2), values (199995), END_ARRAY (1).
        val prefix = "{\"schemaVersion\":1,\"windows\":[" + List(199_995) { "0" }.joinToString(",") + "],"
        val duplicate = prefix + "\"schemaVersion\":1}"
        WebProgramStructureBuilder.MODEL_JSON.createParser(duplicate).use { parser ->
            assertEquals(com.fasterxml.jackson.core.JsonToken.START_OBJECT, parser.nextToken())
            repeat(200_001) { assertNotNull(parser.nextToken()) }
            assertEquals(com.fasterxml.jackson.core.JsonToken.FIELD_NAME, parser.currentToken())
            assertEquals("schemaVersion", parser.currentName())
        }
        assertRawModelOutcome(rawByteEvidenceModel(duplicate))
        assertRawModelOutcome(rawByteEvidenceModel(prefix + "\"omissionReason\":null}"),
            "limit-exceeded", "MODEL_BYTE_EVIDENCE_EXCEEDED")
        val bytePrefix = "{\"schemaVersion\":1," + " ".repeat(2 * 1024 * 1024)
        assertRawModelOutcome(rawByteEvidenceModel(bytePrefix + "\"schemaVersion\":1}"))
        assertRawModelOutcome(rawByteEvidenceModel(bytePrefix + "\"windows\":[]}"),
            "limit-exceeded", "MODEL_BYTE_EVIDENCE_EXCEEDED")
    }

    @Test fun `model parser shares strict stream constraints while detail parser retains duplicate detection`() {
        val strict = WebProgramStructureBuilder.JSON
        val model = WebProgramStructureBuilder.MODEL_JSON
        assertSame(strict.streamReadConstraints(), model.streamReadConstraints())
        assertTrue(strict.isEnabled(com.fasterxml.jackson.core.StreamReadFeature.STRICT_DUPLICATE_DETECTION.mappedFeature()))
        assertFalse(model.isEnabled(com.fasterxml.jackson.core.StreamReadFeature.STRICT_DUPLICATE_DETECTION.mappedFeature()))
        for (raw in listOf(
            """{"prototype":"first","prototype":"second"}""",
            """{"id":"first","\u0069d":"second"}""",
            """{"byteEvidence":{"origin":{"address":1,"address":2}}}""",
        )) {
            assertFailsWith<com.fasterxml.jackson.core.JsonParseException> { readWebStructureEntity(raw.toByteArray(), 0) }
        }
    }

    @Test fun `aggregate references are charged across functions and reference families`() {
        val targets = (0 until 1000).map { "r$it" }.toSet()
        val dense = (0..WebProgramStructureBuilder.MAXIMUM_MODEL_REFERENCES / targets.size).map { i ->
            RecoveredFunction("fn_$i", "dense_$i", i.toULong(), "void f(void)", null,
                calls = targets.take(500).toSet(), referencedGlobals = targets.drop(500).toSet())
        }
        val bytes = model(dense)
        assertTrue(bytes.size < WebProgramStructureBuilder.MAXIMUM_MODEL_BYTES)
        val revision = Revision(bytes, null, emptyList())
        val page = revision.pages.functions("owner", jobId, runId, revisionId, null)
        assertContract("functionInventory", page)
        assertEquals("limit-exceeded", page.text("state"))
        assertEquals("MODEL_REFERENCES_EXCEEDED", page.text("stateReason"))
        assertTrue(page.items().isEmpty())
    }

    @Test fun `retained allocation charges reject overflow without retaining the rejected string`() {
        val maximum = WebProgramStructureBuilder.MAXIMUM_RETAINED_BYTES
        val budget = WebProgramStructureBuilder.RetainedBudget(maximum - 66)
        val failure = assertFailsWith<WebProgramStructureBuilder.WebStructureFailure> { budget.string("ab") }
        assertEquals("limit-exceeded", failure.state)
        assertEquals("MODEL_RETAINED_BYTES_EXCEEDED", failure.reason)
        assertEquals(maximum - 66, budget.bytes)
        budget.string("a")
        assertEquals(maximum, budget.bytes)
        val planBudget = WebProgramStructureBuilder.RetainedBudget(maximum, "PLAN_RETAINED_BYTES_EXCEEDED")
        assertEquals("PLAN_RETAINED_BYTES_EXCEEDED",
            assertFailsWith<WebProgramStructureBuilder.WebStructureFailure> { planBudget.charge(1) }.reason)
    }

    @Test fun `canonical identifiers reuse only the matching kind and retain exact mixed charges`() {
        val f = RecoveredFunction("f", "F", 1u, "void F(void)", null)
        val same = RecoveredFunction("same", "S", 2u, "void S(void)", null)
        val gs = listOf(RecoveredGlobal("g", "G", 3u, "int", null), RecoveredGlobal("same", "S", 4u, "int", null))
        val ts = listOf(RecoveredType("t", "struct T {};", null))
        val raw = Json.parseToJsonElement(model(listOf(f, same), gs, ts).decodeToString()).jsonObject
        val rows = raw.getValue("functions").jsonArray.toMutableList()
        rows[0] = JsonObject(rows[0].jsonObject + mapOf(
            "calls" to JsonArray(listOf("same", "g", "missing", "same", "f").map(::JsonPrimitive)),
            "referencedGlobals" to JsonArray(listOf("same", "f", "missing", "same", "g").map(::JsonPrimitive))))
        val modelBytes = JsonObject(raw + ("functions" to JsonArray(rows))).toString().toByteArray()
        val modules = listOf(planned("b", emptyList()), planned("a", listOf("same", "g", "missing", "same", "f"),
            listOf("same", "f", "missing", "g"), listOf("t", "f", "missing"), listOf("evidence")))
        val revision = Revision(modelBytes, plan(*modules.toTypedArray(), cycles = listOf(listOf("b", "a"))), listOf("a", "b"))
        var charge: WebStructureRetention? = null
        val index = revision.evidence.readStructureDiagnosed(revision.reference, revision.cache, null, { charge = it }) { index, _ -> index }
        val functions = index.table(WebStructureKind.FUNCTION)
        val globals = index.table(WebStructureKind.GLOBAL)
        val types = index.table(WebStructureKind.TYPE)
        val called = functions.calls[0]
        val referenced = functions.referencedGlobals[0]
        assertEquals(listOf("same", "g", "missing", "same", "f"), called.toList())
        assertEquals(listOf("same", "f", "missing", "same", "g"), referenced.toList())
        for (slot in listOf(0, 3)) {
            assertSame(functions.ids[1], called[slot])
            assertSame(globals.ids[1], referenced[slot])
        }
        assertSame(functions.ids[0], called[4]); assertSame(globals.ids[0], referenced[4])
        assertNotSame(globals.ids[0], called[1]); assertNotSame(functions.ids[0], referenced[1])
        assertNotSame(functions.ids[1], globals.ids[1])
        assertTrue(functions.calls[1].isEmpty()); assertTrue(functions.referencedGlobals[1].isEmpty())
        assertEquals(listOf("a", "b"), index.modules.map { it.id })
        val module = index.modules[0]
        for ((table, owned, original) in listOf(Triple(functions, module.functionIds, modules[1].functionIds),
            Triple(globals, module.globalIds, modules[1].globalIds), Triple(types, module.typeIds, modules[1].typeIds))) {
            assertEquals(original, owned)
            for (id in owned) table.index[id]?.let { assertSame(table.ids[it], id) }
        }
        assertEquals(6, index.unknownPlanReferences)
        assertEquals(OWNER_AMBIGUOUS, functions.owners[1])
        assertEquals(listOf("b", "a"), module.cycle)
        assertSame(module.cycle, index.modules[1].cycle)
        assertEquals(listOf("evidence"), module.boundaryEvidence)
        assertTrue(index.modules[1].functionIds.isEmpty())
        fun strings(vararg values: String) = values.sumOf { 64L + 2L * it.length }
        val expected = mapOf(
            WebStructureCharge.BASELINE to 65536L,
            WebStructureCharge.SOURCE_FILES to index.sourceFileIds.entries.sumOf { 128L + 2L * (it.key.length + it.value.length) },
            WebStructureCharge.MODEL_ENTITIES to 5 * 512L,
            WebStructureCharge.MODEL_STRINGS to strings("f", "F", "same", "S", "g", "G", "same", "S", "t"),
            WebStructureCharge.MODEL_REFERENCE_STRINGS to strings("g", "missing", "f", "missing"),
            WebStructureCharge.MODEL_REFERENCE_SLOTS to 10 * 8L,
            WebStructureCharge.MODEL_REFERENCE_ARRAYS to 2 * 24L,
            WebStructureCharge.PLAN_MODULES to 2 * 512L,
            WebStructureCharge.PLAN_MODULE_STRINGS to modules.sumOf { strings(it.id, it.sourcePath, it.headerPath) },
            WebStructureCharge.PLAN_REFERENCE_STRINGS to strings("g", "missing", "f", "missing", "f", "missing"),
            WebStructureCharge.PLAN_REFERENCE_SLOTS to 12 * 8L,
            WebStructureCharge.PLAN_REFERENCE_LISTS to 3 * 64L,
            WebStructureCharge.PLAN_BOUNDARY_STRINGS to strings("evidence"),
            WebStructureCharge.PLAN_CYCLE_STRINGS to strings("b", "a"),
        )
        for (category in WebStructureCharge.entries) assertEquals(expected.getValue(category), charge!![category], category.name)
        assertEquals(expected.values.sum(), index.retainedBytes)
        assertEquals(index.retainedBytes, charge!!.bytes)
    }

    @Test fun `reference release requires actual replacement and cannot cross a budget floor`() {
        val revision = standard()
        val index = revision.evidence.readStructure(revision.reference, revision.cache) { index, _ -> index }
        val table = index.table(WebStructureKind.FUNCTION)
        val canonical = table.ids[0]
        val duplicate = String(canonical.toCharArray())
        val budget = WebProgramStructureBuilder.RetainedBudget(100)
        budget.string(duplicate, WebStructureCharge.MODEL_REFERENCE_STRINGS)
        val values = arrayOf(canonical, duplicate, "unknown")
        WebProgramStructureBuilder.canonicalizeReferences(values, table, budget)
        assertSame(canonical, values[0]); assertSame(canonical, values[1]); assertEquals("unknown", values[2])
        assertEquals(100L, budget.bytes)
        WebProgramStructureBuilder.canonicalizeReferences(values, table, budget)
        assertEquals(100L, budget.bytes)
        for (amount in listOf(-1L, 1L, Long.MAX_VALUE)) assertFailsWith<IllegalArgumentException> { budget.release(amount) }
        budget.charge(10)
        assertFailsWith<IllegalArgumentException> { budget.release(10, WebStructureCharge.MODEL_REFERENCE_STRINGS) }
        budget.release(10)
        assertFailsWith<IllegalArgumentException> { budget.release(1) }
        assertFailsWith<IllegalArgumentException> { WebProgramStructureBuilder.RetainedBudget(-1) }
        // A future canonical match cannot discount the parse's peak admission charge.
        val peak = WebProgramStructureBuilder.RetainedBudget(WebProgramStructureBuilder.MAXIMUM_RETAINED_BYTES - 8)
        peak.charge(8, WebStructureCharge.MODEL_REFERENCE_SLOTS)
        assertEquals("MODEL_RETAINED_BYTES_EXCEEDED", assertFailsWith<WebProgramStructureBuilder.WebStructureFailure> {
            peak.string(duplicate, WebStructureCharge.MODEL_REFERENCE_STRINGS)
        }.reason)
    }

    @Test fun `known references must pass peak parse admission before canonical discounts`() {
        val id = "f".repeat(512)
        val original = model(listOf(RecoveredFunction(id, "F", 1u, "void F(void)", null))).decodeToString()
        val raw = Json.parseToJsonElement(original).jsonObject
        val row = raw.getValue("functions").jsonArray.single().jsonObject
        val repeated = JsonArray(List(100_000) { JsonPrimitive(id) })
        val bytes = JsonObject(raw + ("functions" to JsonArray(listOf(JsonObject(row + ("calls" to repeated)))))).toString().toByteArray()
        assertTrue(bytes.size < WebProgramStructureBuilder.MAXIMUM_MODEL_BYTES)
        val revision = Revision(bytes, null, emptyList())
        val phases = mutableListOf<String>()
        var charge: WebStructureRetention? = null
        val index = revision.evidence.readStructureDiagnosed(revision.reference, revision.cache, { phase, _ -> phases += phase },
            { charge = it }) { index, _ -> index }
        assertEquals("limit-exceeded", index.outcome.state)
        assertEquals("MODEL_RETAINED_BYTES_EXCEEDED", index.outcome.reason)
        assertFalse("canonicalize-references" in phases)
        assertTrue(index.tables.isEmpty())
        assertEquals(index.retainedBytes, charge!!.bytes)
        for (category in WebStructureCharge.entries.filter { it.name.startsWith("MODEL_") }) assertEquals(0L, charge!![category])
    }

    @Test fun `discarded malformed model and plan charges never appear as retained diagnostics`() {
        val validModel = model(functions.take(1))
        val cases = listOf(
            validModel.copyOf(validModel.size - 2) to plan(planned("core", listOf(functions[0].id))),
            model(functions.take(1), input = "d".repeat(64)) to plan(planned("core", listOf(functions[0].id))),
            validModel to plan(planned("core", listOf(functions[0].id)), planned("core", emptyList())),
            validModel to plan(planned("core", listOf(functions[0].id, "x".repeat(4097)))),
            validModel to plan(planned("core", List(100001) { functions[0].id })),
        )
        for ((modelBytes, planBytes) in cases) {
            val revision = Revision(modelBytes, planBytes, listOf("core"))
            var charge: WebStructureRetention? = null
            val index = revision.evidence.readStructureDiagnosed(revision.reference, revision.cache, null, { charge = it }) { index, _ -> index }
            val retained = assertNotNull(charge)
            assertEquals(index.retainedBytes, retained.bytes)
            for (category in WebStructureCharge.entries.filter { it.name.startsWith("PLAN_") }) assertEquals(0L, retained[category])
            if (!index.available) {
                for (category in WebStructureCharge.entries.filter { it.name.startsWith("MODEL_") }) assertEquals(0L, retained[category])
                assertTrue(index.tables.isEmpty())
            } else {
                assertTrue(index.tables.all { it.owners.all { owner -> owner == OWNER_NOT_RECORDED } })
                assertTrue(retained[WebStructureCharge.MODEL_ENTITIES] > 0)
            }
            assertTrue(index.modules.isEmpty()); assertEquals(0, index.unknownPlanReferences)
        }
    }

    @Test fun `retained cache evicts by total charged bytes as well as entry count`() {
        val revision = standard()
        val index = revision.evidence.readStructure(revision.reference, revision.cache) { index, _ -> index }
        assertTrue(index.retainedBytes > 0)
        val key = WebProgramStructureCache.Key(jobId, runId, revisionId, revision.sourceSha, index.manifestSha256, index.descriptorSha256, inputSha)
        val entry = checkNotNull(revision.cache.peek(key))
        assertEquals(index.retainedBytes + revision.manifest.size + revision.descriptor.size + 1024L, entry.retainedBytes)
        val cache = WebProgramStructureCache(maximumRetainedBytes = entry.retainedBytes - 1)
        cache.put(entry)
        assertNull(cache.get(key))
        val tooSmall = WebProgramStructureCache(maximumEntryBytes = entry.retainedBytes - 1)
        tooSmall.put(entry)
        assertNull(tooSmall.get(key))

    }

    @Test fun `cache copies metadata validates bindings and touches only current objects`() {
        val revision = standard()
        revision.evidence.readStructure(revision.reference, revision.cache) { _, _ -> Unit }
        val prefix = WebProgramStructureCache.Prefix(jobId, runId, revisionId, revision.sourceSha, inputSha)
        val original = revision.cache.candidates(prefix).single()
        val manifest = original.manifest.copy(bytes = original.manifest.bytes.copyOf())
        val entry = WebProgramStructureCache.Entry(original.key, original.index, manifest, original.descriptor)
        manifest.bytes[0] = 0
        assertContentEquals(original.manifest.bytes, entry.manifest.bytes)
        assertFailsWith<IllegalArgumentException> { WebProgramStructureCache.Entry(original.key.copy(inputSha256 = "bad"), original.index, original.manifest, original.descriptor) }
        assertFailsWith<IllegalArgumentException> { WebProgramStructureCache.Entry(original.key.copy(revisionId = "bad"), original.index, original.manifest, original.descriptor) }
        assertFailsWith<IllegalArgumentException> { WebProgramStructureCache.Entry(original.key, original.index, manifest, original.descriptor) }
        assertFailsWith<IllegalArgumentException> { WebProgramStructureCache.Entry(original.key, original.index, original.manifest.copy(identity = original.manifest.identity.copy(linkCount = 2)), original.descriptor) }
        revision.cache.put(entry)
        revision.cache.touch(original)
        assertSame(entry, revision.cache.peek(entry.key))
        assertTrue(revision.cache.candidates(prefix.copy(inputSha256 = "other")).isEmpty())
        assertFailsWith<IllegalArgumentException> { WebProgramStructureCache(capacity = 3) }
        assertFailsWith<IllegalArgumentException> { WebProgramStructureCache(maximumEntryBytes = 96L * 1024 * 1024 + 1) }
    }

    @Test fun `candidate order is detached nonpromoting and total charge evicts LRU`() {
        val revision = standard()
        val prefix = WebProgramStructureCache.Prefix(jobId, runId, revisionId, revision.sourceSha, inputSha)
        fun capture(): WebProgramStructureCache.Entry {
            revision.evidence.readStructure(revision.reference, revision.cache) { _, _ -> Unit }
            return revision.cache.candidates(prefix).first()
        }
        val first = capture()
        val path = "reports/runs/$runId/source-tree/source_tree_manifest.json"
        revision.files[path] = captured(revision.manifest + " ".toByteArray())
        val second = capture()
        val detached = revision.cache.candidates(prefix)
        assertEquals(listOf(second, first), detached)
        revision.cache.peek(first.key)
        revision.cache.getEntry(first.key)
        assertEquals(detached, revision.cache.candidates(prefix))
        revision.cache.touch(first)
        assertEquals(listOf(first, second), revision.cache.candidates(prefix))
        assertEquals(listOf(second, first), detached)
        val replacement = WebProgramStructureCache.Entry(first.key, first.index, first.manifest, first.descriptor)
        revision.cache.put(replacement)
        revision.cache.touch(second)
        revision.cache.touch(first)
        assertEquals(listOf(second, replacement), revision.cache.candidates(prefix))
        val bounded = WebProgramStructureCache(maximumRetainedBytes = first.retainedBytes + second.retainedBytes - 1)
        bounded.put(first)
        bounded.put(second)
        assertNull(bounded.peek(first.key))
        assertSame(second, bounded.peek(second.key))
        revision.files[path] = captured(revision.manifest + "  ".toByteArray())
        val third = capture()
        assertEquals(listOf(third, second), revision.cache.candidates(prefix))
    }

    @Test fun `failed projection and after verification publish no candidate`() {
        val revision = standard()
        val prefix = WebProgramStructureCache.Prefix(jobId, runId, revisionId, revision.sourceSha, inputSha)
        assertFailsWith<IllegalStateException> {
            revision.evidence.readStructure(revision.reference, revision.cache) { _, _ -> error("project failed") }
        }
        assertTrue(revision.cache.candidates(prefix).isEmpty())
        assertFails {
            revision.evidence.readStructure(revision.reference, revision.cache) { _, _ ->
                val path = "reports/runs/$runId/source-tree/source_tree_manifest.json"
                revision.files[path] = captured(revision.manifest)
            }
        }
        assertTrue(revision.cache.candidates(prefix).isEmpty())
    }

    private inner class StreamingCapture(val revision: Revision = standard()) {
        val events = mutableListOf<String>()
        val phases = mutableListOf<String>()
        var compareFailure: Exception? = null
        var fenceFailure: String? = null
        private val input = captured(inputBytes).copy(identity = INPUT_IDENTITY)
        private fun same(expected: StableRegularFile, current: StableRegularFile) =
            expected.identity == current.identity && expected.sha256 == current.sha256 && expected.bytes.contentEquals(current.bytes)
        val evidence = WebSourceCatalogEvidence(listOf(profile), { events += "read-input"; input },
            { _, path, _ -> events += "read:$path"; revision.files.getValue(path) },
            { _, expected ->
                events += "verify-input"
                if (fenceFailure == "input") error("input fence")
                assertTrue(same(expected, input))
            },
            { _, path, _, expected ->
                events += "verify:$path"
                if (fenceFailure == path) error("artifact fence")
                assertTrue(same(expected, revision.files.getValue(path)))
            },
            { _, path, _, expected ->
                events += "compare:$path"
                compareFailure?.let { throw it }
                if (same(expected, revision.files.getValue(path))) StableComparison.SAME else StableComparison.DIFFERENT
            })
        fun read(project: (WebProgramStructureIndex, () -> ByteArray) -> WebProgramStructureIndex = { index, _ -> index }) =
            evidence.readStructureMeasured(revision.reference, revision.cache, { phase, _ -> phases += phase }, project)
        fun clear() { events.clear(); phases.clear() }
        val prefix get() = WebProgramStructureCache.Prefix(jobId, runId, revisionId, revision.sourceSha, inputSha)
        val manifestPath = "reports/runs/$runId/source-tree/source_tree_manifest.json"
        val descriptorPath = "reports/runs/$runId/source-tree/reports/build_contract.json"
    }

    @Test fun `streaming warm hit compares twice without full metadata reads or parsing`() {
        val capture = StreamingCapture()
        val first = capture.read()
        capture.clear()
        assertSame(first, capture.read())
        assertEquals(listOf("read-input", "compare:${capture.manifestPath}", "compare:${capture.descriptorPath}",
            "verify:${capture.descriptorPath}", "verify:${capture.manifestPath}", "verify-input"), capture.events)
        assertEquals(listOf("read-input", "compare-manifest", "compare-descriptor", "project-page", "verify-descriptor",
            "verify-manifest", "verify-input"), capture.phases)
    }

    @Test fun `stable metadata changes rebuild and byte identical replacement rebinds before hitting`() {
        for (descriptor in listOf(false, true)) {
            val capture = StreamingCapture()
            val path = if (descriptor) capture.descriptorPath else capture.manifestPath
            val first = capture.read()
            val original = capture.revision.files.getValue(path)
            capture.revision.files[path] = captured(original.bytes + byteArrayOf(10))
            val changed = capture.read()
            assertNotSame(first, changed)
            assertNotEquals(first.structureVersion, changed.structureVersion)
            capture.clear()
            capture.revision.files[path] = captured(capture.revision.files.getValue(path).bytes)
            val replaced = capture.read()
            assertNotSame(changed, replaced)
            assertEquals(changed.structureVersion, replaced.structureVersion)
            assertEquals(1, capture.phases.count { it == "build-projection" })
            assertEquals(1, capture.events.count { it == "read:${capture.manifestPath}" })
            assertEquals(1, capture.events.count { it == "read:${capture.descriptorPath}" })
            capture.clear()
            assertSame(replaced, capture.read())
            assertEquals(2, capture.events.count { it.startsWith("compare:") })
            assertFalse(capture.phases.contains("build-projection"))
        }
    }

    @Test fun `candidate search checks MRU first and can select the second without reparsing`() {
        val capture = StreamingCapture()
        val original = capture.revision.files.getValue(capture.manifestPath)
        val first = capture.read()
        capture.revision.files[capture.manifestPath] = captured(original.bytes + byteArrayOf(10))
        capture.read()
        capture.revision.files[capture.manifestPath] = original
        val before = capture.revision.cache.candidates(capture.prefix)
        capture.clear()
        assertSame(first, capture.read { index, _ ->
            assertEquals(before, capture.revision.cache.candidates(capture.prefix))
            index
        })
        assertEquals(3, capture.events.count { it.startsWith("compare:") })
        assertFalse(capture.phases.contains("build-projection"))
        assertSame(first, capture.revision.cache.candidates(capture.prefix).first().index)
    }

    @Test fun `comparison failures never fallback retry or touch and all fences precede publication`() {
        val capture = StreamingCapture()
        capture.read()
        val original = capture.revision.files.getValue(capture.manifestPath)
        capture.revision.files[capture.manifestPath] = captured(original.bytes + byteArrayOf(10))
        capture.read()
        capture.revision.files[capture.manifestPath] = original
        val before = capture.revision.cache.candidates(capture.prefix)
        for (failure in listOf(WebAccessDenied(409, "SOURCE_CATALOG_CHANGED", "changed"),
            RepairBudgetExceededException("budget"), IllegalStateException("unavailable"), InterruptedException("interrupt"))) {
            capture.clear(); capture.compareFailure = failure
            assertSame(failure, assertFails { capture.read() })
            assertEquals(listOf("read-input", "compare:${capture.manifestPath}"), capture.events)
            assertEquals(before, capture.revision.cache.candidates(capture.prefix))
        }
        capture.compareFailure = null
        assertFails { capture.read { _, _ -> error("project failed") } }
        assertEquals(before, capture.revision.cache.candidates(capture.prefix))
        for (fence in listOf(capture.descriptorPath, capture.manifestPath, "input")) {
            capture.fenceFailure = fence
            assertFails { capture.read() }
            assertEquals(before, capture.revision.cache.candidates(capture.prefix))
            val cold = StreamingCapture()
            cold.fenceFailure = if (fence == "input") "input" else fence
            assertFails { cold.read() }
            assertTrue(cold.revision.cache.candidates(cold.prefix).isEmpty())
        }
    }

    @Test fun `three and five argument adapters really read metadata for comparison`() {
        for (fiveArguments in listOf(false, true)) {
            val revision = standard()
            val evidence = if (!fiveArguments) revision.evidence else WebSourceCatalogEvidence(listOf(profile),
                { captured(inputBytes).copy(identity = INPUT_IDENTITY) },
                { _, path, _ -> revision.reads += path; revision.files.getValue(path) }, { _, _ -> }, { _, _, _, _ -> })
            val phases = mutableListOf<String>()
            fun read() = evidence.readStructureMeasured(revision.reference, revision.cache, { phase, _ -> phases += phase }) { index, _ -> index }
            val first = read()
            revision.reads.clear(); phases.clear()
            assertSame(first, read())
            val manifestPath = "reports/runs/$runId/source-tree/source_tree_manifest.json"
            val descriptorPath = "reports/runs/$runId/source-tree/reports/build_contract.json"
            assertEquals(if (fiveArguments) 1 else 2, revision.reads.count { it == manifestPath })
            assertEquals(if (fiveArguments) 1 else 2, revision.reads.count { it == descriptorPath })
            assertFalse(phases.contains("build-projection"))
            revision.files[manifestPath] = captured(revision.manifest)
            assertNotSame(first, read())
            assertTrue(phases.contains("build-projection"))
        }
    }

    @Test fun `cursor filters cannot collide through map display delimiters`() {
        val records = (0 until 3).map { i ->
            RecoveredFunction("fn_$i", "x, status=recovered $i", i.toULong(), "void f(void)", null)
        }
        val revision = Revision(model(records), null, emptyList())
        val literal = "search=x%2C+status%3Drecovered&limit=1"
        val first = revision.pages.functions("owner", jobId, runId, revisionId, literal)
        val cursor = next(first)!!
        assertEquals("fn_1", revision.pages.functions("owner", jobId, runId, revisionId, "$literal&cursor=$cursor").items().single().text("entityId"))
        assertEquals("INVALID_CURSOR", assertFailsWith<WebAccessDenied> {
            revision.pages.functions("owner", jobId, runId, revisionId, "search=x&status=recovered&limit=1&cursor=$cursor")
        }.code)
    }

    @Test fun `historical schema one models remain extraction labels without an assessment`() {
        val revision = Revision(model(functions.take(1), schema = 1), plan(planned("core", listOf("fn_0000000000401000"))), listOf("core"))
        val page = revision.pages.functions("owner", jobId, runId, revisionId, null)
        assertEquals("available", page.text("state")); assertEquals("not-recorded", page.text("recoveryAssessment"))
        assertEquals(1, page.getValue("model").jsonObject.getValue("schemaVersion").jsonPrimitive.int)
    }

    @Test fun `retained projections are reused only for identical commitments`() {
        val revision = standard()
        revision.pages.functions("owner", jobId, runId, revisionId, null)
        val modelPath = "reports/runs/$runId/source-tree/reports/program_model.json"
        assertEquals(1, revision.reads.count { it == modelPath })
        revision.pages.functions("owner", jobId, runId, revisionId, "sort=name")
        revision.pages.modules("owner", jobId, runId, revisionId, null)
        assertEquals(1, revision.reads.count { it == modelPath })
        revision.pages.entity(WebStructureKind.FUNCTION, jobId, runId, revisionId, "fn_0000000000401000", null)
        assertEquals(2, revision.reads.count { it == modelPath })
        // A changed committed model is refused rather than merged with the retained projection.
        val replaced = revision.files.getValue(modelPath).let { it.copy(bytes = it.bytes.copyOf().also { bytes -> bytes[bytes.size - 2] = ' '.code.toByte() }) }
        revision.files[modelPath] = replaced.copy(sha256 = sha(replaced.bytes))
        assertEquals("SOURCE_REVISION_CHANGED", assertFailsWith<WebAccessDenied> {
            revision.pages.entity(WebStructureKind.FUNCTION, jobId, runId, revisionId, "fn_0000000000401000", null)
        }.code)
    }

    @Test fun `a 100000 function model stays within bounded request and retained memory budgets`() {
        val count = 100_000
        val synthetic = (0 until count).map { index ->
            val address = 0x400000uL + index.toULong() * 16uL
            RecoveredFunction(stableFunctionId(address), "synthetic_function_$index", address, "void synthetic_function_$index(void)", null,
                calls = setOf(stableFunctionId(0x400000uL + ((index + 1) % count).toULong() * 16uL)),
                status = if (index % 17 == 0) RecoveryStatus.PARTIAL else RecoveryStatus.RECOVERED)
        }
        val modules = synthetic.chunked(24).mapIndexed { index, chunk -> planned("module_$index", chunk.map { it.id }) }
        val revision = Revision(model(synthetic), plan(*modules.toTypedArray()), modules.map { it.id })
        val runtime = Runtime.getRuntime()
        System.gc(); val before = runtime.totalMemory() - runtime.freeMemory()
        val coldPhases = mutableListOf<Map<String, Long>>()
        fun timingCollector(): (String, Long) -> Unit {
            val phases = linkedMapOf<String, Long>()
            coldPhases += phases
            return { phase, nanos -> phases[phase] = (phases[phase] ?: 0L) + nanos }
        }
        var started = System.nanoTime()
        val measuredCache = WebProgramStructureCache()
        val measuredPages = revision.pagesWithCache(measuredCache, timingCollector())
        val first = measuredPages.functions("owner", jobId, runId, revisionId, "limit=200")
        val coldMs = (System.nanoTime() - started) / 1_000_000
        val retainedEntry = measuredCache.candidates(WebProgramStructureCache.Prefix(jobId, runId, revisionId, revision.sourceSha, inputSha)).single()
        assertTrue(retainedEntry.retainedBytes <= 96L * 1024 * 1024)
        assertSame(retainedEntry, measuredCache.getEntry(retainedEntry.key))
        val coldSamples = mutableListOf(coldMs)
        System.gc(); val retained = runtime.totalMemory() - runtime.freeMemory() - before
        assertEquals(count, first.getValue("totalFunctions").jsonPrimitive.int)
        assertEquals(200, first.items().size)
        repeat(19) {
            System.gc()
            started = System.nanoTime()
            val freshPages = revision.pagesWithFreshCache(timingCollector())
            val sample = freshPages.functions("owner", jobId, runId, revisionId, "limit=200")
            coldSamples += (System.nanoTime() - started) / 1_000_000
            assertEquals(count, sample.getValue("totalFunctions").jsonPrimitive.int)
            assertEquals(first.items(), sample.items())
        }
        val orderedCold = coldSamples.sorted()
        val coldP50 = orderedCold[orderedCold.size / 2]
        val coldP95 = orderedCold[((orderedCold.size * 95 + 99) / 100 - 1).coerceAtMost(orderedCold.lastIndex)]
        val slowestIndex = coldSamples.indices.maxBy { coldSamples[it] }
        val warm = mutableListOf<Long>()
        var cursor = next(first)
        var bytes = first.toString().length
        val modelReadsBeforeWarm = revision.reads.count { it.endsWith("/program_model.json") }
        repeat(20) {
            started = System.nanoTime()
            val page = measuredPages.functions("owner", jobId, runId, revisionId, "limit=200&cursor=$cursor")
            warm += (System.nanoTime() - started) / 1_000_000
            assertTrue(page.items().size <= 200)
            bytes = maxOf(bytes, page.toString().length)
            cursor = next(page)
        }
        assertEquals(modelReadsBeforeWarm, revision.reads.count { it.endsWith("/program_model.json") })
        assertSame(retainedEntry, measuredCache.getEntry(retainedEntry.key))
        for (query in listOf("sort=name&order=desc&limit=200", "search=synthetic_function_99999", "status=partial&limit=200", "module=module_4166")) {
            started = System.nanoTime()
            val page = revision.pages.functions("owner", jobId, runId, revisionId, query)
            warm += (System.nanoTime() - started) / 1_000_000
            bytes = maxOf(bytes, page.toString().length)
            assertTrue(page.items().size <= 200)
        }
        val searched = revision.pages.functions("owner", jobId, runId, revisionId, "search=synthetic_function_99999")
        assertEquals(listOf("synthetic_function_99999"), searched.items().map { it.text("name") })
        started = System.nanoTime()
        val detail = revision.pages.entity(WebStructureKind.FUNCTION, jobId, runId, revisionId, stableFunctionId(0x400000uL + 16uL * 99_999uL), null)
        val detailMs = (System.nanoTime() - started) / 1_000_000
        assertEquals(1, detail.getValue("entity").jsonObject.getValue("calledBy").jsonObject.getValue("total").jsonPrimitive.int)
        val modulePage = revision.pages.modules("owner", jobId, runId, revisionId, "limit=200")
        assertEquals(modules.size, modulePage.getValue("totalModules").jsonPrimitive.int)
        warm.sort()
        println("program-structure-scale functions=$count modelBytes=${revision.model!!.size} coldMs=$coldSamples " +
            "coldP50Ms=$coldP50 coldP95Ms=$coldP95 coldMaxMs=${orderedCold.last()} " +
            "slowestPhases=${coldPhases[slowestIndex].mapValues { (_, nanos) -> nanos / 1_000_000 }} " +
            "warmP50Ms=${warm[warm.size / 2]} warmMaxMs=${warm.last()} detailMs=$detailMs retainedBytes=$retained maxPageChars=$bytes")
        val evidence = buildJsonObject {
            put("schemaVersion", 1)
            put("functions", count)
            put("modelBytes", revision.model!!.size)
            put("coldSamplesMs", JsonArray(coldSamples.map { JsonPrimitive(it) }))
            put("coldPhaseSamplesNanos", JsonArray(coldPhases.map { phases ->
                buildJsonObject { phases.forEach { (phase, nanos) -> put(phase, nanos) } }
            }))
            put("warmSamplesMs", JsonArray(warm.map { JsonPrimitive(it) }))
            put("coldP50Ms", coldP50); put("coldP95Ms", coldP95); put("coldMaxMs", orderedCold.last())
            put("warmP50Ms", warm[warm.size / 2]); put("warmMaxMs", warm.last())
            put("detailMs", detailMs); put("retainedBytes", retained); put("maxPageChars", bytes)
            put("chargedIndexBytes", retainedEntry.index.retainedBytes); put("chargedEntryBytes", retainedEntry.retainedBytes)
            put("cacheRetained", true)
            put("thresholds", buildJsonObject {
                put("coldP95MsExclusive", 500); put("warmP50MsExclusive", 500)
                put("pageRowsInclusive", 200); put("pageCharsExclusive", 1_000_000)
                put("retainedBytesExclusive", 256L * 1024 * 1024)
            })
            put("outcomes", buildJsonObject {
                put("coldP95Passed", coldP95 < 500)
                put("warmP50Passed", warm[warm.size / 2] < 500)
                put("pageCharsPassed", bytes < 1_000_000)
                put("pageRowsPassed", true) // All measured pages passed their structural assertions.
                put("retainedBytesPassed", retained < 256L * 1024 * 1024)
                put("totalFunctions", first.getValue("totalFunctions"))
                put("totalModules", modulePage.getValue("totalModules"))
                put("detailCalledByTotal", detail.getValue("entity").jsonObject.getValue("calledBy").jsonObject.getValue("total"))
                put("searchMatched", searched.items().single().text("name"))
            })
        }
        val evidencePath = Path.of(System.getProperty("decompengine.structure.scaleEvidence", "build/test-results/program-structure-scale.json"))
        Files.createDirectories(evidencePath.parent)
        Files.writeString(evidencePath, evidence.toString() + "\n")
        assertTrue(coldP95 < 500, "cold first-page p95 exceeded 500 ms: $coldSamples; " +
            "slowestPhases=${coldPhases[slowestIndex].mapValues { (_, nanos) -> nanos / 1_000_000 }}")
        // D0 budgets: bounded responses (≤200 rows, <1 MiB), first-data-page latency and incremental JVM memory.
        assertTrue(bytes < 1_000_000, "page bytes $bytes")
        assertTrue(warm[warm.size / 2] < 500, "warm page latency $warm")
        assertTrue(retained < 256L * 1024 * 1024, "retained projection bytes $retained")
    }

    /** The packaged-browser structure seed writes manifests directly; its pinned profile facts must stay current. */
    @Test fun `packaged browser structure seed pins the current generated-C profile declarations`() {
        val pinned = Json.parseToJsonElement(Files.readString(Path.of("scripts/packaged-browser-structure-profile.json"))).jsonObject
        val expected = buildJsonObject {
            put("profileId", profile.id); put("profileSha256", profile.sha256)
            put("declarations", buildJsonObject {
                for (template in pinned.getValue("declarations").jsonObject.keys) {
                    val declaration = profile.layout.declarationForPath(template.replace("{module}", "module_0000"))
                    assertEquals(ProjectContentKind.UTF8_TEXT, declaration.contentKind, template)
                    put(template, JsonArray(declaration.roles.map { JsonPrimitive(it.wireName) }.sortedBy { it.content }))
                }
            })
        }
        assertEquals(expected, pinned, "Update scripts/packaged-browser-structure-profile.json to $expected")
    }

    private companion object {
        val INPUT_IDENTITY = LinuxFileIdentity(LinuxFileKey(1, 1), 0x8180, 1000, 1000, 1, 1, true, false, false)
    }
}
