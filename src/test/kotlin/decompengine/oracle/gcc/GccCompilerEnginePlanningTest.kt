package decompengine.oracle.gcc

import decompengine.oracle.core.OracleArtifacts
import decompengine.oracle.core.OracleJson
import decompengine.oracle.core.OracleSchemas
import decompengine.project.ProgramModelAnalyzer
import decompengine.project.RecoveredFunction
import decompengine.project.RecoveredGlobal
import decompengine.project.RecoveredProgramModel
import decompengine.project.RecoveredType
import java.nio.file.Path
import java.util.concurrent.atomic.AtomicInteger
import kotlin.io.path.createDirectories
import kotlin.io.path.createTempDirectory
import kotlin.io.path.exists
import kotlin.io.path.readBytes
import kotlin.io.path.writeBytes
import kotlin.io.path.writeText
import kotlin.test.Test
import kotlin.test.assertEquals
import kotlin.test.assertFailsWith
import kotlin.test.assertFalse
import kotlin.test.assertTrue
import kotlinx.serialization.json.JsonObject
import kotlinx.serialization.json.jsonObject
import kotlinx.serialization.json.jsonPrimitive

class GccCompilerEnginePlanningTest {
    @Test
    fun `current exporter contract rejects a historical model before plan publication`() {
        val temporary = createTempDirectory("gcc-engine-model-version-").toAbsolutePath().normalize()
        val bytes = "authored model version fixture".toByteArray()
        val input = temporary.resolve("input").also { it.writeBytes(bytes) }
        val output = temporary.resolve("output")
        val service = GccCompilerEnginePlanningService.diagnostic(ProgramModelAnalyzer { _, _ ->
            model(OracleArtifacts.sha256(bytes)).copy(schemaVersion = 1)
        })
        val failure = assertFailsWith<GccCompilerEnginePlanningException> {
            service.plan(suite(bytes), "cc1", input, output)
        }
        assertTrue(failure.message.orEmpty().contains("requires program model schema 2"))
        assertFalse(output.resolve("planning/compiler_engine_plan_assessment.json").exists())
    }

    @Test
    fun `planning authenticates input publishes exact ownership and resumes deterministically`() {
        val temporary = createTempDirectory("gcc-engine-plan-").toAbsolutePath().normalize()
        val input = temporary.resolve("cc1.stripped")
        val inputBytes = "authenticated compiler engine".toByteArray()
        input.writeBytes(inputBytes)
        val suite = suite(inputBytes)
        val invocations = AtomicInteger()
        val analyzer = ProgramModelAnalyzer { _, work ->
            val reports = work.resolve("reports").createDirectories()
            val reused = if (reports.resolve("program_model.json").exists()) 2 else 0
            val model = model(OracleArtifacts.sha256(inputBytes))
            reports.resolve("program_model.json").writeText(model.toJson())
            reports.resolve("program_model.json.progress.json").writeText(
                "{\"schemaVersion\":1,\"phase\":\"complete\",\"completed\":2,\"total\":2," +
                    "\"recovered\":2,\"partial\":0,\"failed\":0,\"reused\":$reused,\"currentFunction\":null}\n",
            )
            invocations.incrementAndGet()
            model
        }
        val output = temporary.resolve("output")
        val service = GccCompilerEnginePlanningService.diagnostic(analyzer)

        val first = service.plan(suite, "cc1", input, output)
        val firstPlan = first.modulePlanPath.readBytes()
        val firstModel = first.programModelPath.readBytes()
        val firstEvidence = readAssessment(first.assessmentPath)

        assertEquals(false, firstEvidence.getValue("complete").jsonPrimitive.content.toBooleanStrict())
        assertEquals(false, firstEvidence.getValue("releaseEligible").jsonPrimitive.content.toBooleanStrict())
        assertEquals(
            "non-authoritative-caller-supplied-analyzer-v1",
            firstEvidence.getValue("authority").jsonPrimitive.content,
        )
        assertEquals(2, firstEvidence.getValue("schemaVersion").jsonPrimitive.content.toInt())
        assertFailsWith<IllegalArgumentException> {
            OracleSchemas.validate(
                "gcc/compiler-engine-plan-evidence",
                JsonObject(firstEvidence + ("schemaVersion" to kotlinx.serialization.json.JsonPrimitive(1))),
            )
        }
        assertEquals(2, firstEvidence.getValue("results").jsonObject.getValue("ownership").jsonObject
            .getValue("functions").jsonPrimitive.content.toInt())
        assertEquals(1, firstEvidence.getValue("results").jsonObject.getValue("ownership").jsonObject
            .getValue("types").jsonPrimitive.content.toInt())
        assertEquals(0, firstEvidence.getValue("results").jsonObject.getValue("export").jsonObject
            .getValue("reused").jsonPrimitive.content.toInt())
        assertTrue(first.wallClockMillis <= suite.budgets.exportWallClockMillis)

        val second = service.plan(suite, "cc1", input, output)
        val secondEvidence = readAssessment(second.assessmentPath)
        assertTrue(firstPlan.contentEquals(second.modulePlanPath.readBytes()))
        assertTrue(firstModel.contentEquals(second.programModelPath.readBytes()))
        assertEquals(first.modulePlanSha256, second.modulePlanSha256)
        assertEquals(first.programModelSha256, second.programModelSha256)
        assertEquals(2, secondEvidence.getValue("results").jsonObject.getValue("export").jsonObject
            .getValue("reused").jsonPrimitive.content.toInt())
        assertEquals(2, invocations.get())

        second.modulePlanPath.writeText("{}")
        assertFailsWith<GccCompilerEnginePlanningException> {
            service.plan(suite, "cc1", input, output)
        }
    }

    @Test
    fun `input substitution fails before analysis and cannot publish completion evidence`() {
        val temporary = createTempDirectory("gcc-engine-plan-substitution-").toAbsolutePath().normalize()
        val expected = "expected".toByteArray()
        val input = temporary.resolve("cc1.stripped")
        input.writeBytes("replaced".toByteArray())
        var invoked = false
        val service = GccCompilerEnginePlanningService.diagnostic(ProgramModelAnalyzer { _, _ ->
            invoked = true
            model(OracleArtifacts.sha256(expected))
        })
        val output = temporary.resolve("output")

        assertFailsWith<GccCompilerEngineProfileException> {
            service.plan(suite(expected), "cc1", input, output)
        }

        assertFalse(invoked)
        assertFalse(output.resolve("planning/compiler_engine_plan_assessment.json").exists())
    }

    @Test
    fun `legacy schema one completion evidence blocks diagnostic analysis`() {
        val temporary = createTempDirectory("gcc-engine-plan-legacy-").toAbsolutePath().normalize()
        val inputBytes = "authenticated compiler engine".toByteArray()
        val input = temporary.resolve("cc1.stripped")
        input.writeBytes(inputBytes)
        val output = temporary.resolve("output")
        output.resolve("planning").createDirectories()
        output.resolve("planning/compiler_engine_plan_evidence.json").writeText(
            "{\"schemaVersion\":1,\"complete\":true}\n",
        )
        var invoked = false
        val service = GccCompilerEnginePlanningService.diagnostic(ProgramModelAnalyzer { _, _ ->
            invoked = true
            model(OracleArtifacts.sha256(inputBytes))
        })

        assertFailsWith<GccCompilerEnginePlanningException> {
            service.plan(suite(inputBytes), "cc1", input, output)
        }
        assertFalse(invoked)
        assertFalse(output.resolve("planning/compiler_engine_plan_assessment.json").exists())
    }

    @Test
    fun `program model substitution after parsing cannot bind an ownership plan`() {
        val temporary = createTempDirectory("gcc-engine-model-substitution-").toAbsolutePath().normalize()
        val inputBytes = "authenticated compiler engine".toByteArray()
        val input = temporary.resolve("cc1.stripped")
        input.writeBytes(inputBytes)
        val parsed = model(OracleArtifacts.sha256(inputBytes))
        val service = GccCompilerEnginePlanningService.diagnostic(ProgramModelAnalyzer { _, work ->
            val reports = work.resolve("reports").createDirectories()
            reports.resolve("program_model.json").writeText(
                parsed.copy(functions = parsed.functions.map { it.copy(name = "substituted_${it.name}") }).toJson(),
            )
            reports.resolve("program_model.json.progress.json").writeText(
                "{\"schemaVersion\":1,\"phase\":\"complete\",\"completed\":2,\"total\":2," +
                    "\"recovered\":2,\"partial\":0,\"failed\":0,\"reused\":0,\"currentFunction\":null}\n",
            )
            parsed
        })

        assertFailsWith<GccCompilerEnginePlanningException> {
            service.plan(suite(inputBytes), "cc1", input, temporary.resolve("output"))
        }
        assertFalse(temporary.resolve("output/planning/compiler_engine_plan_assessment.json").exists())
    }

    @Test
    fun `completed progress must have the exporter shape and agree with model statuses`() {
        val temporary = createTempDirectory("gcc-engine-plan-progress-").toAbsolutePath().normalize()
        val inputBytes = "authenticated compiler engine".toByteArray()
        val input = temporary.resolve("cc1.stripped")
        input.writeBytes(inputBytes)
        val model = model(OracleArtifacts.sha256(inputBytes))

        fun service(progress: String) = GccCompilerEnginePlanningService.diagnostic(ProgramModelAnalyzer { _, work ->
            val reports = work.resolve("reports").createDirectories()
            reports.resolve("program_model.json").writeText(model.toJson())
            reports.resolve("program_model.json.progress.json").writeText(progress)
            model
        })

        val extraField = "{" +
            "\"schemaVersion\":1,\"phase\":\"complete\",\"completed\":2,\"total\":2," +
            "\"recovered\":2,\"partial\":0,\"failed\":0,\"reused\":0,\"currentFunction\":null," +
            "\"untrusted\":true}\n"
        assertFailsWith<GccCompilerEnginePlanningException> {
            service(extraField).plan(suite(inputBytes), "cc1", input, temporary.resolve("extra-output"))
        }

        val mismatchedStatuses = "{" +
            "\"schemaVersion\":1,\"phase\":\"complete\",\"completed\":2,\"total\":2," +
            "\"recovered\":1,\"partial\":1,\"failed\":0,\"reused\":0,\"currentFunction\":null}\n"
        assertFailsWith<GccCompilerEnginePlanningException> {
            service(mismatchedStatuses).plan(suite(inputBytes), "cc1", input, temporary.resolve("status-output"))
        }
    }

    @Test
    fun `shared wall clock budget is enforced while analysis is running`() {
        val temporary = createTempDirectory("gcc-engine-plan-deadline-").toAbsolutePath().normalize()
        val inputBytes = "authenticated compiler engine".toByteArray()
        val input = temporary.resolve("cc1.stripped")
        input.writeBytes(inputBytes)
        val service = GccCompilerEnginePlanningService.diagnostic(ProgramModelAnalyzer { _, _ ->
            Thread.sleep(75)
            model(OracleArtifacts.sha256(inputBytes))
        })

        assertFailsWith<GccCompilerEnginePlanningException> {
            service.plan(suite(inputBytes, wallClockMillis = 1), "cc1", input, temporary.resolve("output"))
        }
    }

    private fun readAssessment(path: Path): JsonObject {
        val document = OracleJson.parseCanonical(path.readBytes()) as JsonObject
        OracleSchemas.validate("gcc/compiler-engine-plan-evidence", document)
        val reportSha256 = document.getValue("reportSha256").jsonPrimitive.content
        val unsigned = JsonObject(document - "reportSha256")
        assertEquals(reportSha256, OracleArtifacts.sha256(OracleJson.canonicalBytes(unsigned)))
        return document
    }

    private fun suite(input: ByteArray, wallClockMillis: Long = 60_000): GccCompilerEngineSuite {
        val digest = OracleArtifacts.sha256(input)
        val binding = GccCompilerEngineArtifactBinding("artifacts/gcc-cc1.stripped", input.size.toLong(), digest)
        val fullBinding = GccCompilerEngineArtifactBinding("artifacts/gcc-cc1.full", input.size.toLong(), digest)
        val ltoBinding = GccCompilerEngineArtifactBinding("artifacts/gcc-lto1.stripped", input.size.toLong(), digest)
        val ltoFullBinding = GccCompilerEngineArtifactBinding("artifacts/gcc-lto1.full", input.size.toLong(), digest)
        return GccCompilerEngineSuite(
            id = "gcc-compiler-engines-16.2.0",
            version = "16.2.0",
            target = "x86_64-linux-gnu",
            profilePath = Path.of("compiler-engines.json"),
            profileSha256 = SHA_A,
            sourceLockPath = Path.of("source-lock.json"),
            sourceLockSha256 = SHA_B,
            baseBuildRecordPath = Path.of("build-record.json"),
            baseBuildRecordSha256 = SHA_C,
            toolchainReproductionPath = Path.of("toolchain-reproduction.json"),
            toolchainReproductionSha256 = SHA_D,
            sourceRevision = "78d4ac73dd391005b895a6148cd9831e28e1208b",
            analysis = GccCompilerEngineAnalysisToolchain(
                exporterId = "decompengine-ghidra-program-model",
                exporterVersion = 10,
                exporterSha256 = SHA_E,
                exporterMode = "planning",
                ghidraVersion = "12.1.3",
                ghidraRelease = "PUBLIC",
                ghidraArchive = GccCompilerEngineArtifactBinding("ghidra.zip", 1, SHA_F),
                plannerId = "deterministic-module-planner",
                plannerVersion = 1,
            ),
            budgets = GccCompilerEngineBudgets(
                exportWallClockMillis = wallClockMillis,
                exportMaximumResidentBytes = 2L * 1024 * 1024 * 1024,
                plannerMaximumEntities = 100,
                plannerMaximumDependencyEdges = 100,
                plannerMaximumWorkUnits = 10_000,
            ),
            engines = listOf(
                engine("cc1", binding, fullBinding, SHA_B),
                engine("lto1", ltoBinding, ltoFullBinding, SHA_C),
            ),
        )
    }

    private fun engine(
        id: String,
        stripped: GccCompilerEngineArtifactBinding,
        full: GccCompilerEngineArtifactBinding,
        manifestSha256: String,
    ) = GccCompilerEngine(
        id = id,
        buildOutput = "/oracle/build/gcc/$id",
        buildRecordPath = Path.of("$id-build-record.json"),
        buildRecordSha256 = SHA_A,
        oracleManifestPath = Path.of("$id-oracle-manifest.json"),
        oracleManifestSha256 = manifestSha256,
        functionOracleRelativePath = "$id-function-recovery-oracle.json",
        reconstructionArchiveRelativePath = "$id-reconstruction.zip",
        fullArtifact = full,
        strippedArtifact = stripped,
    )

    private fun model(inputSha256: String) = RecoveredProgramModel(
        schemaVersion = 2,
        inputSha256 = inputSha256,
        functions = listOf(
            RecoveredFunction(
                id = "fn_0000000000001000",
                name = "parse_input",
                address = 0x1000u,
                prototype = "int parse_input(void)",
                referencedGlobals = setOf("global_0000000000003000"),
            ),
            RecoveredFunction(
                id = "fn_0000000000002000",
                name = "parse_finish",
                address = 0x2000u,
                prototype = "int parse_finish(void)",
                calls = setOf("fn_0000000000001000"),
            ),
        ),
        globals = listOf(
            RecoveredGlobal(
                id = "global_0000000000003000",
                name = "parse_state",
                address = 0x3000u,
                type = "int",
            ),
        ),
        types = listOf(
            RecoveredType(
                id = "type_parse_state",
                declaration = "typedef int parse_state_t;",
                sourceAddress = 0x1000u,
            ),
        ),
    )

    private companion object {
        const val SHA_A = "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"
        const val SHA_B = "bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb"
        const val SHA_C = "cccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccc"
        const val SHA_D = "dddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddd"
        const val SHA_E = "eeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeee"
        const val SHA_F = "ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff"
    }
}
