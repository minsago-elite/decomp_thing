package decompengine.project

import java.nio.file.Files
import java.nio.file.Path
import kotlin.io.path.*
import kotlin.test.*
import kotlinx.serialization.json.*

class GeneratedCGlobalAdmissionTest {
    private val item = RecoveredGlobal("g", "item", 16UL, "pointer", "00105048")
    private fun function(name: String, calls: Set<String> = emptySet(), refs: Set<String> = emptySet()) =
        RecoveredFunction(name, name, name.length.toULong(), "int $name(void)", "int $name(void) { return 0; }", calls, refs)
    private val functions = listOf(function("main", setOf("direct")), function("direct", setOf("main"), setOf("g")),
        function("sibling"))
    private val base = RecoveredProgramModel(2, "a".repeat(64), functions, listOf(item))
    private val owners = functions.associate { it.id to it.id } + ("g" to "owner")
    private fun root() = Files.createTempDirectory(Path.of("build", "global-admission").createDirectories(), "case-")
    private fun header(model: RecoveredProgramModel): String {
        val plan = DeterministicModulePlanner().plan(model, owners)
        return GeneratedCProjectRendering(model, plan).moduleInterface(plan.modules.single { "g" in it.globalIds })
    }

    @Test fun schemasPreserveEvidence() {
        for (version in 1..4) {
            val evidence = if (version >= 3) ReferencedDataByteEvidence(version - 2, listOf(ReferencedDataByteWindow(
                16UL, 1, ReferencedDataByteOrigin(3UL, 16UL, 0, "pcode_load"), "available",
                listOf(ReferencedDataByteSegment(0, 1, "available", "bd", null))))) else null
            val model = base.copy(schemaVersion = version, globals = listOf(item.copy(byteEvidence = evidence)))
            val bytes = model.toJson().toByteArray()
            val read = ProgramModelJson.readCanonical(bytes)
            assertContains(header(read), "declaration-refused g @ 0x10; refusal=UNDECLARED_TYPE_NAME; type-name=pointer")
            assertContentEquals(bytes, read.toJson().toByteArray())
        }
    }

    @Test fun assessmentUsesRetainedReferencesAndCalls() {
        val plan = DeterministicModulePlanner().plan(base, owners)
        for (module in plan.modules) {
            val source = module.functionIds.joinToString("\n") { "/* $it */ int $it(void) { return 0; }" } +
                if ("g" in module.globalIds) "\n/* g */ typedef void *pointer; pointer item = 0;" else ""
            for (prefix in listOf("", "#define X 1\n")) {
                val issues = GeneratedCCandidateValidation.assess(module, base, "recovered-c", prefix + source)
                assertEquals(module.id != "sibling", issues.any { it.code.contains("declaration-refused") }, module.id)
                if (prefix.isEmpty() && module.id == "sibling") assertTrue(issues.isEmpty())
            }
        }
    }

    @Test fun previousCompilerAcceptedSourceCannotBeReusedOrRestored() {
        val fixture = Path.of("src/test/resources/generated-c/global-admission")
        val model = ProgramModelJson.readCanonical(fixture.resolve("model.json").readBytes())
        val project = root()
        val checkpoint = project.resolve("reports/modules/entry.json")
        val source = project.resolve("src/modules/entry.c")
        checkpoint.parent.createDirectories()
        source.parent.createDirectories()
        fixture.resolve("accepted.json").copyTo(checkpoint)
        fixture.resolve("entry.c").copyTo(source)
        var dispatched = false
        val result = SourceTreeGenerator.generate(model, project, overrides = mapOf("fn_main" to "entry",
            "global_pointer" to "entry"), reconstructor = ModuleReconstructor {
            dispatched = true
            assertNull(it.acceptedSourceSha256)
            ReconstructedModule("/* attempted */\n" + source.readText(), "recovered-c", "0".repeat(64))
        })
        assertTrue(dispatched)
        assertContains(source.readText(), "attempted")
        assertFalse(Json.parseToJsonElement(checkpoint.readText()).jsonObject.getValue("accepted").jsonPrimitive.boolean)
        assertContains(checkpoint.readText(), "global-declaration-refused")
        assertContains(result.unresolvedImplementationIds, "global_pointer")
        assertContentEquals(model.toJson().toByteArray(), project.resolve("reports/program_model.json").readBytes())
    }

    @Test fun admissionDependsOnTheEmittedNameInventory() {
        val missing = listOf("pointer", "const unseen *", "_Atomic(unseen)", "int (*)(int (*)(unseen))",
            "int (*(*)(int))(unseen)", "FILE *", "va_list", "bool")
        for (type in missing) {
            val text = header(base.copy(globals = listOf(item.copy(type = type))))
            assertContains(text, "refusal=UNDECLARED_TYPE_NAME")
            assertFalse(text.contains("extern "), text)
        }
        val eligible = listOf("void *", "struct Opaque *", "__int128", "__not_a_compiler_type", "size_t",
            "max_align_t", "uint_fast16_t", "_Atomic(pointer)", "int (*)(pointer)")
        for (type in eligible) {
            val model = base.copy(globals = listOf(item.copy(type = type)), types = listOf(RecoveredType("t", "typedef void *pointer;")))
            assertContains(header(model), globalDeclaration(model.globals.single(), true))
        }
        val longName = "unavailable".repeat(16)
        val bounded = header(base.copy(globals = listOf(item.copy(type = longName))))
        assertContains(bounded, "type-name=sha256:${sha256(longName.toByteArray())}")
        assertFalse(bounded.contains(longName))
        val hostile = item.copy(type = "missing /* raw payload */")
        assertFalse(header(base.copy(globals = listOf(hostile))).contains("payload"))
        val bad = assertFailsWith<IllegalArgumentException> { header(base.copy(globals = listOf(item.copy(type = "int [")))) }
        assertContains(bad.message.orEmpty(), "for g")
    }

    @Test fun cleanedInterfacesAndEligibleDefinitionsCompile() {
        val project = root()
        val types = listOf(RecoveredType("t1", "typedef int word, other;"), RecoveredType("t2", "typedef word result;"))
        val callback = item.copy(id = "cb", name = "callback", type = "int (*)(result (*)(other))", initializer = "0")
        val explicit = item.copy(id = "p", name = "address", type = "void *", initializer = "0")
        val m = base.copy(globals = listOf(item, callback, explicit), types = types,
            functions = functions.map { if (it.id == "direct") it.copy(referencedGlobals = setOf("cb", "g")) else it })
        val plan = DeterministicModulePlanner().plan(m, owners + mapOf("cb" to "owner", "p" to "owner"))
        val full = GeneratedCProjectRendering(m, plan)
        val inputs = ProfileModulePromptInputs(m, plan, GeneratedCMakeReconstructionProfile.descriptor)
        val manifest = SourceTreeGenerator.generate(m, project, reconstructor = RecoveredCModuleReconstructor(),
            overrides = owners + mapOf("cb" to "owner", "p" to "owner"))
        assertEquals(setOf("main", "direct", "cb", "p", "g"), manifest.unresolvedImplementationIds.toSet())
        assertContentEquals(m.toJson().toByteArray(), project.resolve("reports/program_model.json").readBytes())
        val owner = plan.modules.single { it.id == "owner" }
        val ownerHeader = full.moduleInterface(owner)
        val lines = ownerHeader.lines().filter { it.startsWith("extern ") || "declaration-refused" in it }
        assertEquals(3, lines.size)
        assertContains(lines, "extern void * address; /* p @ 0x10; extraction-status=recovered; recovery-assessment=unassessed */")
        for (id in listOf("owner", "direct")) {
            val context = GeneratedCModuleContext.select(inputs.request(id, project, null))
            val selected = context.interfaces.getValue(owner.headerPath)
            assertTrue(lines.filter { " p @ " !in it }.all(selected::contains), selected)
            assertContains(context.interfaces.getValue("include/decomp_types.h"), "typedef word result;")
        }
        val src = project.resolve(owner.sourcePath).readText()
        assertContains(src, "void * address = 0;")
        assertFalse(src.contains("00105048"))
        val files = Files.walk(project).use { paths ->
            paths.filter { it.extension in setOf("h", "c") }.toList()
        }
        for (compiler in compilers()) for (file in files) {
            val process = ProcessBuilder(compiler, "-std=c11", "-Wall", "-Wextra", "-Werror", "-Iinclude",
                "-x", "c", "-fsyntax-only", file.toAbsolutePath().toString()).directory(project.toFile())
                .redirectErrorStream(true).start()
            val diagnostics = process.inputStream.bufferedReader().readText()
            assertEquals(0, process.waitFor(), "$compiler $file: $diagnostics")
        }
    }

    private fun compilers(): List<String> {
        val clangAvailable = runCatching {
            ProcessBuilder("clang", "--version").redirectOutput(ProcessBuilder.Redirect.DISCARD).start().waitFor() == 0
        }.getOrDefault(false)
        return if (clangAvailable) listOf("gcc", "clang") else listOf("gcc")
    }

    @Test fun compilerStillChecksReservedAndTaggedTypes() {
        val dir = root()
        for ((type, accepted) in listOf("struct Opaque *" to true, "__int128" to true,
            "__not_a_compiler_type" to false, "struct Opaque" to false, "int (*)(struct Hidden *)" to false)) {
            val model = base.copy(globals = listOf(item.copy(type = type, initializer = null)))
            val plan = DeterministicModulePlanner().plan(model, owners)
            val owner = plan.modules.single { "g" in it.globalIds }
            val rendering = GeneratedCProjectRendering(model, plan)
            val request = ModuleReconstructionRequest(owner, model, "", "", "", emptyMap(), dir, modulePlan = plan)
            val source = EvidenceModuleReconstructor(true).reconstruct(request)
            assertTrue(source.issues.isEmpty(), type)
            dir.resolve("modules").createDirectories()
            dir.resolve("modules/${owner.id}.h").writeText(rendering.moduleInterface(owner))
            dir.resolve("${owner.id}_internal.h").writeText(rendering.privateInterface(owner))
            dir.resolve("decomp_types.h").writeText(rendering.sharedInterface())
            dir.resolve("unit.c").writeText(source.source)
            for (compiler in compilers()) {
                val process = ProcessBuilder(compiler, "-std=c11", "-Wall", "-Wextra", "-Werror", "-I.", "-fsyntax-only", "unit.c")
                    .directory(dir.toFile()).redirectErrorStream(true).start()
                val diagnostics = process.inputStream.bufferedReader().readText()
                assertEquals(accepted, process.waitFor() == 0, "$compiler $type: $diagnostics")
            }
        }
    }

    @Test fun matchingTransitiveCheckpointStillNeedsCurrentAssessment() {
        val project = root()
        val good = item.copy(id = "good", name = "valid", type = "int", initializer = "1")
        val withBoth = base.copy(globals = listOf(good, item))
        val earlier = withBoth.copy(functions = functions.map {
            if (it.id == "direct") it.copy(referencedGlobals = setOf("good")) else it
        })
        val ownership = owners + ("good" to "owner")
        val invoked = mutableListOf<String>()
        val worker = ModuleReconstructor { request ->
            invoked += request.module.id
            if (request.module.id == "main") assertNull(request.acceptedSourceSha256)
            RecoveredCModuleReconstructor().reconstruct(request)
        }
        fun checkpoint() = Json.parseToJsonElement(project.resolve("reports/modules/main.json").readText()).jsonObject
        val first = SourceTreeGenerator.generate(earlier, project, overrides = ownership, reconstructor = worker)
        assertFalse("main" in first.unresolvedImplementationIds)
        val old = checkpoint()
        assertTrue(old.getValue("accepted").jsonPrimitive.boolean)
        invoked.clear()
        val second = SourceTreeGenerator.generate(withBoth, project, overrides = ownership, reconstructor = worker)
        assertContains(invoked, "main")
        assertContains(second.unresolvedImplementationIds, "main")
        val current = checkpoint()
        assertEquals(old.getValue("fingerprint"), current.getValue("fingerprint"))
        assertFalse(current.getValue("accepted").jsonPrimitive.boolean)
    }

    @Test fun admissionChangesReachableFingerprintsAndPreservesUnrelatedReuse() {
        val dir = root()
        val admitted = base.copy(globals = listOf(item.copy(type = "void *", initializer = "0")))
        fun inputs(m: RecoveredProgramModel) = ProfileModulePromptInputs(m, DeterministicModulePlanner().plan(m, owners),
            GeneratedCMakeReconstructionProfile.descriptor)
        val before = inputs(admitted)
        val after = inputs(base)
        for (id in listOf("main", "direct", "owner", "sibling")) for (legacy in listOf(true, false)) {
            assertEquals(id == "sibling", before.fingerprint(before.request(id, dir, null), legacy) ==
                after.fingerprint(after.request(id, dir, null), legacy), "$id legacy=$legacy")
        }
        val invoked = mutableListOf<String>()
        val worker = ModuleReconstructor {
            invoked += it.module.id
            RecoveredCModuleReconstructor().reconstruct(it)
        }
        SourceTreeGenerator.generate(admitted, dir, overrides = owners, reconstructor = worker)
        assertContains(invoked, "sibling")
        invoked.clear()
        val manifest = SourceTreeGenerator.generate(base, dir, overrides = owners, reconstructor = worker)
        assertFalse("sibling" in invoked)
        assertEquals(setOf("g", "direct", "main"), manifest.unresolvedImplementationIds.toSet())
    }
}
