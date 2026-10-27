package decompengine.web

import decompengine.acp.LinuxFileIdentity
import decompengine.acp.LinuxFileKey
import decompengine.project.*
import decompengine.repair.RepairBudgetExceededException
import decompengine.repair.StableRegularFile
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
        val reads: MutableList<String> = java.util.Collections.synchronizedList(mutableListOf())
        val evidence = WebSourceCatalogEvidence(listOf(profile), { captured(inputBytes).copy(identity = INPUT_IDENTITY) }) { _, path, maximum ->
            reads += path
            val file = files[path] ?: error("Unexpected read $path")
            if (file.bytes.size > maximum) throw RepairBudgetExceededException("fixture exceeds $maximum")
            file
        }
        val cache = WebProgramStructureCache()
        val pages = pages(cache)

        /** Pages over an empty projection cache, so the next read is a first read of this revision. */
        fun pages(cache: WebProgramStructureCache) = WebProgramStructurePages { job, run, revision, project ->
            assertEquals(Triple(jobId, runId, revisionId), Triple(job, run, revision))
            evidence.readStructure(reference, cache, project)
        }
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
        val cases = listOf(
            Revision(null, null, listOf("core")) to ("not-recorded" to "MODEL_NOT_RECORDED"),
            Revision("{\"schemaVersion\": 9, \"inputSha256\": \"$inputSha\"}".toByteArray(), null, listOf("core")) to ("unsupported" to "MODEL_SCHEMA_UNSUPPORTED"),
            Revision("{\"schemaVersion\": 2, \"inputSha256\": \"$inputSha\", \"functions\": [".toByteArray(), null, listOf("core")) to ("invalid" to "MODEL_MALFORMED"),
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

    @Test fun `speculative model charges join snapshot and plan admission before projection publication`() {
        val revision = standard()
        val snapshot = revision.evidence.readRevision(revision.reference)
        val manifest = SourceTreeManifestReader.parse(revision.manifest.decodeToString(), profile)
        val bytes = revision.model!!
        val parsed = WebProgramStructureBuilder.parseModel(bytes).value!!
        assertTrue(parsed.retainedBytes > 0)
        val snapshotCharge = 64 * 1024L + snapshot.files.withIndex().sumOf { (row, file) ->
            128L + 2L * (file.evidence.path.length + revisionSourceFileId(revision.reference, row, file.evidence.path).length)
        }
        fun build(charge: Long) = WebProgramStructureBuilder.build(snapshot, profile, manifest, {
            WebStructureEvidence(captured(bytes), sha(bytes), WebStructureParse(
                WebProgramStructureBuilder.ParsedModel(parsed.schemaVersion, parsed.inputSha256, parsed.tables, charge),
                WebStructureOutcome.AVAILABLE))
        }, {
            val planBytes = revision.plan!!
            WebStructureEvidence(captured(planBytes), sha(planBytes), WebProgramStructureBuilder.parsePlan(planBytes))
        })
        val admitted = build(parsed.retainedBytes)
        assertTrue(admitted.available)
        assertEquals("available", admitted.planOutcome.state)
        assertTrue(admitted.retainedBytes > snapshotCharge + parsed.retainedBytes)
        val maximum = WebProgramStructureBuilder.MAXIMUM_RETAINED_BYTES
        val modelOverflow = build(maximum)
        assertEquals("MODEL_RETAINED_BYTES_EXCEEDED", modelOverflow.outcome.reason)
        assertTrue(modelOverflow.tables.isEmpty())
        val planOverflow = build(maximum - snapshotCharge)
        assertTrue(planOverflow.available)
        assertEquals("PLAN_RETAINED_BYTES_EXCEEDED", planOverflow.planOutcome.reason)
        assertTrue(planOverflow.modules.isEmpty())
        assertTrue(planOverflow.tables.all { table -> table.owners.all { it == OWNER_NOT_RECORDED } })
    }

    @Test fun `retained cache evicts by total charged bytes as well as entry count`() {
        val revision = standard()
        val index = revision.evidence.readStructure(revision.reference, revision.cache) { index, _ -> index }
        assertTrue(index.retainedBytes > 0)
        val key = WebProgramStructureCache.Key(jobId, runId, revisionId, revision.sourceSha, index.manifestSha256, index.descriptorSha256, inputSha)
        val other = key.copy(revisionId = "other")
        val cache = WebProgramStructureCache(maximumRetainedBytes = index.retainedBytes * 2 - 1)
        cache.put(key, index); cache.put(other, index)
        assertNull(cache.get(key)); assertSame(index, cache.get(other))
        val tooSmall = WebProgramStructureCache(maximumRetainedBytes = index.retainedBytes - 1)
        tooSmall.put(key, index)
        assertNull(tooSmall.get(key))
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
        var started = System.nanoTime()
        val first = revision.pages.functions("owner", jobId, runId, revisionId, "limit=200")
        val coldMs = (System.nanoTime() - started) / 1_000_000
        System.gc(); val retained = runtime.totalMemory() - runtime.freeMemory() - before
        assertEquals(count, first.getValue("totalFunctions").jsonPrimitive.int)
        assertEquals(200, first.items().size)
        val warm = mutableListOf<Long>()
        var cursor = next(first)
        var bytes = first.toString().length
        repeat(20) {
            started = System.nanoTime()
            val page = revision.pages.functions("owner", jobId, runId, revisionId, "limit=200&cursor=$cursor")
            warm += (System.nanoTime() - started) / 1_000_000
            bytes = maxOf(bytes, page.toString().length)
            cursor = next(page)
        }
        for (query in listOf("sort=name&order=desc&limit=200", "search=synthetic_function_99999", "status=partial&limit=200", "module=module_4166")) {
            started = System.nanoTime()
            val page = revision.pages.functions("owner", jobId, runId, revisionId, query)
            warm += (System.nanoTime() - started) / 1_000_000
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
        // First reads of the same revision with an empty projection cache: the full manifest, model and plan build.
        val firstReads = (1..3).map {
            val fresh = revision.pages(WebProgramStructureCache())
            started = System.nanoTime()
            assertEquals(200, fresh.functions("owner", jobId, runId, revisionId, "limit=200").items().size)
            (System.nanoTime() - started) / 1_000_000
        }.sorted()
        warm.sort()
        println("program-structure-scale functions=$count modelBytes=${revision.model!!.size} coldMs=$coldMs firstReadMs=$firstReads " +
            "firstReadBudgetMs=$FIRST_READ_BUDGET_MS firstReadWithinBudget=${firstReads[1] < FIRST_READ_BUDGET_MS} " +
            "warmP50Ms=${warm[warm.size / 2]} warmMaxMs=${warm.last()} detailMs=$detailMs retainedBytes=$retained maxPageChars=$bytes")
        // D0 budgets: bounded responses (≤200 rows, <1 MiB), first-data-page latency and incremental JVM memory.
        assertTrue(bytes < 1_000_000, "page bytes $bytes")
        // Shared CI hosts are noisy: the 500 ms budget is reported above and qualified in the packaged journey, while
        // this ceiling only catches a regression to the earlier multi-second rebuild.
        assertTrue(firstReads[1] < 3 * FIRST_READ_BUDGET_MS, "first-read latency $firstReads")
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
        const val FIRST_READ_BUDGET_MS = 500L
        val INPUT_IDENTITY = LinuxFileIdentity(LinuxFileKey(1, 1), 0x8180, 1000, 1000, 1, 1, true, false, false)
    }
}
