package decompengine.project

import java.nio.file.Files
import java.nio.file.Path
import java.util.concurrent.TimeUnit
import kotlin.io.path.createDirectories
import kotlin.io.path.readText
import kotlin.test.Test
import kotlin.test.assertEquals
import kotlin.test.assertFailsWith
import kotlin.test.assertTrue
import org.junit.jupiter.api.Assumptions.assumeTrue

class GeneratedCSyntheticDefinitionTest {
    @Test
    fun `atomic aggregate synthesis rejects without breaking declarations retained evidence or placeholder recognition`() = fixture { root ->
        val context = GeneratedCDeclarationContext(TYPES)
        for (type in listOf("_Atomic(struct Pair)", "_Atomic struct Pair", "_Atomic(Pair)", "_Atomic Pair",
            "AtomicPair", "AtomicAlias", "AtomicAnonymous", "_Atomic(union Choice)",
            "AtomicPair[2]", "_Atomic(struct Pair)[2][3]", "Matrix")) {
            val global = RecoveredGlobal("global_atomic", "item", 300UL, type)
            assertTrue(globalDeclaration(global, true, context).startsWith("extern "), type)
            val failure = assertFailsWith<IllegalArgumentException>(type) { globalDeclaration(global, false, context) }
            assertTrue(failure.message.orEmpty().contains("global_atomic") && failure.message.orEmpty().contains("atomic aggregate"), failure.message)
            val retained = when {
                "union" in type -> "(union Choice){.value = 7}"
                type == "AtomicAnonymous" -> "(Anonymous){7}"
                "[2][3]" in type -> "{{(Pair){7}}}"
                "[" in type || type == "Matrix" -> "{(Pair){7}}"
                else -> "(Pair){7}"
            } + " /* retained expression */"
            assertTrue(globalDeclaration(global.copy(initializer = retained), false, context).endsWith(" = $retained;"), type)
        }
        for (returnType in listOf("_Atomic(struct Pair)", "AtomicAlias", "AtomicAnonymous")) {
            val valueType = if (returnType == "AtomicAnonymous") "Anonymous" else "Pair"
            val function = convert("$returnType convert(void)", "$returnType convert(void) { return ($valueType){7}; }")
            val declaration = recoveredDeclaration(function, context)
            assertEquals(function.prototype, declaration.prototype)
            val body = declaration.placeholderBody()
            assertTrue(isGeneratedCPlaceholderBody(function, body, context), body)
            val failure = assertFailsWith<IllegalArgumentException> { declaration.placeholderDefinition() }
            assertTrue(failure.message.orEmpty().contains(function.id) && failure.message.orEmpty().contains("atomic aggregate"), failure.message)
            val model = model(function).copy(types = TYPES)
            val request = request(model, root)
            assertTrue(RecoveredCModuleReconstructor().reconstruct(request).source.contains("return ($valueType){7};"))
            val issues = GeneratedCCandidateValidation.assess(request.module, model, "scripted-agent",
                "/* ${function.id} */ ${function.prototype} { $body }")
            assertTrue(issues.any { it.code == "generic-return-placeholder" && function.id in it.entityIds }, issues.toString())
        }
        // A pointer to an atomic aggregate is an ordinary pointer object; no aggregate value is invented.
        for (type in listOf("AtomicPair *", "_Atomic(struct Pair) *", "AtomicPair *[2]", "_Atomic(AtomicPair *)", "_Atomic(int)[2]")) {
            assertTrue(globalDeclaration(RecoveredGlobal("global_pointer", "item", 300UL, type), false, context).contains(" = "), type)
        }
    }

    @Test
    fun `prototype-only array stars are rejected only when synthesizing a definition`() = fixture { root ->
        for (prototype in listOf("int convert(int values[*])", "int convert(int values[const /* retained */ *])",
            "int convert(int values[*][4])", "int convert(int values[4][*])", "int convert(int (*values)[*])")) {
            val function = convert(prototype, "int convert(int values[]) { return values[0] + 1; }")
            val declaration = recoveredDeclaration(function)
            assertEquals(prototype, declaration.prototype)
            val body = declaration.placeholderBody()
            assertTrue(isGeneratedCPlaceholderBody(function, body), prototype)
            val error = assertFailsWith<IllegalArgumentException> { declaration.placeholderDefinition() }
            assertTrue(error.message.orEmpty().contains(function.id) && error.message.orEmpty().contains("prototype-only [*]"), error.message)
            val model = model(function)
            val request = request(model, root)
            assertTrue(RecoveredCModuleReconstructor().reconstruct(request).source.contains("int convert(int values[])"))
            val issues = GeneratedCCandidateValidation.assess(request.module, model, "scripted-agent",
                "/* ${function.id} */ int convert(int values[]) { $body }")
            assertTrue(issues.any { it.code == "generic-return-placeholder" && function.id in it.entityIds }, issues.toString())
            val generationError = assertFailsWith<IllegalArgumentException> {
                SourceTreeGenerator.generate(model, root.resolve("rejected-${prototype.hashCode()}"), reconstructor = EvidenceModuleReconstructor())
            }
            assertTrue(generationError.message.orEmpty().contains(function.id), generationError.message)
        }
    }

    @Test
    fun `retained atomic aggregate values and nested prototype stars build with GCC`() = supportedBuild("gcc")

    @Test
    fun `retained atomic aggregate values and nested prototype stars build with Clang`() = supportedBuild("clang")

    @Test
    fun `strict compilers demonstrate unsupported synthetic shapes without weakening flags`() = fixture { root ->
        for (compiler in listOf("gcc", "clang")) {
            requireCompiler(compiler)
            assertTrue(syntax(compiler, "int scan(int values[*]) { (void)values; return 0; }", root).first != 0)
            val adjusted = syntax(compiler, "int scan(int values[*]); int scan(int values[]) { (void)values; return 0; }", root)
            if (compiler == "gcc") {
                assertTrue(adjusted.first != 0 && adjusted.second.contains("vla-parameter"), adjusted.second)
            } else assertEquals(0, adjusted.first, adjusted.second)
            val invalidAtomic = syntax(compiler, "struct Pair { int value; }; _Atomic(struct Pair) item = {0};", root)
            if (compiler == "clang") assertTrue(invalidAtomic.first != 0, invalidAtomic.second)
            val retained = syntax(compiler, "struct Pair { int value; }; _Atomic(struct Pair) item = (struct Pair){7};", root)
            assertEquals(0, retained.first, retained.second)
        }
    }

    private fun supportedBuild(compiler: String) = fixture { root ->
        requireCompiler(compiler)
        val functions = listOf(
            main(),
            convert("int convert(int (*callback)(int values[*]))"),
            RecoveredFunction("fn_factory", "factory", 210UL, "int (*factory(void))(int values[*])"),
            RecoveredFunction("fn_deref", "deref", 220UL, "int deref(int *count, int values[*count])"),
        )
        val globals = listOf(
            "_Atomic(struct Pair)" to "(struct Pair){7}",
            "_Atomic Pair" to "(Pair){8}",
            "AtomicAlias" to "(Pair){9}",
            "_Atomic(union Choice)" to "(union Choice){.value = 10}",
            "AtomicPair[2]" to "{(Pair){1}, (Pair){2}}",
        ).mapIndexed { index, (type, value) -> RecoveredGlobal("global_$index", "value_$index", (300 + index * 16).toULong(), type, initializer = value) }
        val program = RecoveredProgramModel(inputSha256 = "synthetic-declarations", functions = functions, globals = globals, types = TYPES)
        val canonical = program.toJson()
        val base = GeneratedCMakeReconstructionProfile.descriptor
        val profile = ReconstructionProfile(base.schemaVersion, base.id, base.layout, base.budgets,
            base.adapterConfiguration + ("compiler-driver" to listOf(compiler)))
        val project = root.resolve("project")
        val manifest = SourceTreeGenerator.generate(program, project, reconstructor = EvidenceModuleReconstructor(), profile = profile)
        assertEquals(canonical, program.toJson())
        assertTrue(manifest.unresolvedImplementationIds.containsAll(functions.map { it.id } + globals.map { it.id }))
        val source = Files.walk(project.resolve("src")).use { paths ->
            paths.filter { it.toString().endsWith(".c") }.toList().joinToString("\n") { it.readText() }
        }
        assertTrue(source.contains("int values[*]"), source)
        assertTrue(source.contains("int values[*count]"), source)
        globals.forEach { assertTrue(source.contains(requireNotNull(it.initializer)), it.type) }
        assertEquals(0, MakeProjectBuilder.build(project, ProjectBuildConfiguration(compilerExecutable = compiler), profile).returnCode)
    }

    private fun syntax(compiler: String, source: String, root: Path): Pair<Int, String> {
        val diagnostic = root.resolve("compiler-control.log")
        val process = ProcessBuilder(compiler, "-std=c11", "-Wall", "-Wextra", "-Werror", "-x", "c", "-fsyntax-only", "-")
            .redirectErrorStream(true).redirectOutput(diagnostic.toFile()).apply { environment()["TMPDIR"] = root.toString() }.start()
        try {
            process.outputStream.bufferedWriter().use { it.write(source) }
            assertTrue(process.waitFor(10, TimeUnit.SECONDS), "compiler syntax probe timed out")
            return process.exitValue() to diagnostic.readText()
        } finally { if (process.isAlive) process.destroyForcibly() }
    }

    private fun requireCompiler(compiler: String) {
        val available = runCatching {
            val process = ProcessBuilder(compiler, "--version").redirectOutput(ProcessBuilder.Redirect.DISCARD)
                .redirectError(ProcessBuilder.Redirect.DISCARD).start()
            try { process.waitFor(5, TimeUnit.SECONDS) && process.exitValue() == 0 }
            finally { if (process.isAlive) process.destroyForcibly() }
        }.getOrDefault(false)
        assumeTrue(available, "$compiler compiler qualification requires the compiler")
    }

    private fun request(model: RecoveredProgramModel, root: Path): ModuleReconstructionRequest {
        val plan = DeterministicModulePlanner().plan(model, model.functions.associate { it.id to "core" })
        return ModuleReconstructionRequest(plan.modules.single(), model, "", "", "", emptyMap(), root)
    }
    private fun main() = RecoveredFunction("fn_main", "main", 100UL, "int main(void)", "int main(void) { return 0; }")
    private fun convert(prototype: String, body: String? = null) = RecoveredFunction("fn_convert", "convert", 200UL, prototype, body)
    private fun model(function: RecoveredFunction) = RecoveredProgramModel(inputSha256 = "synthetic-declarations", functions = listOf(main(), function))
    private fun fixture(block: (Path) -> Unit) {
        val root = Files.createTempDirectory(Path.of("build", "generated-c-synthetic-tests").createDirectories(), "case-").toAbsolutePath()
        try { block(root) } finally { Files.walk(root).use { paths -> paths.sorted(Comparator.reverseOrder()).forEach(Files::deleteIfExists) } }
    }
    private companion object {
        val TYPES = listOf(RecoveredType("aggregate_types", "struct Pair { int value; }; union Choice { int value; double real; }; " +
            "typedef struct Pair Pair; typedef _Atomic(Pair) AtomicPair; typedef AtomicPair AtomicAlias; typedef AtomicPair Matrix[2]; " +
            "typedef struct { int value; } Anonymous; typedef _Atomic(Anonymous) AtomicAnonymous;"))
    }
}
