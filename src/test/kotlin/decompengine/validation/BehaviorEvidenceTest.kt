package decompengine.validation

import decompengine.oracle.core.OracleArtifacts
import decompengine.oracle.core.OracleJson
import decompengine.project.ArchivalProjectAuditor
import decompengine.project.MakeProjectBuilder
import decompengine.project.RecoveredCModuleReconstructor
import decompengine.project.RecoveredFunction
import decompengine.project.RecoveredProgramModel
import decompengine.project.SourceTreeGenerator
import java.nio.file.Files
import java.nio.file.Path
import java.nio.file.StandardOpenOption
import kotlin.io.path.readBytes
import kotlin.io.path.readText
import kotlin.io.path.writeText
import kotlin.test.Test
import kotlin.test.assertEquals
import kotlin.test.assertFails
import kotlin.test.assertFalse
import kotlin.test.assertTrue
import kotlinx.serialization.json.JsonArray
import kotlinx.serialization.json.JsonObject
import kotlinx.serialization.json.JsonPrimitive
import kotlinx.serialization.json.jsonArray
import kotlinx.serialization.json.jsonObject
import kotlinx.serialization.json.jsonPrimitive

class BehaviorEvidenceTest {
    @Test
    fun `historical schema one records remain readable without file declarations`() {
        val fixture = fixture()
        val current = BehaviorEvidence.decode(fixture.evaluate().reportPath.readBytes())
        val cases = JsonArray(current.getValue("cases").jsonArray.map { JsonObject(it.jsonObject - "fileInputs") })
        val corpus = JsonArray(cases.map { JsonObject(it.jsonObject.filterKeys { key -> key in setOf("id", "args", "stdinHex") }) })
        val legacy = JsonObject(current + mapOf(
            "schemaVersion" to JsonPrimitive(1),
            "provider" to JsonPrimitive("local-revision-bound-behavior-v1"),
            "cases" to cases,
            "corpusSha256" to JsonPrimitive(OracleArtifacts.sha256(OracleJson.canonicalBytes(corpus))),
            "observationsSha256" to JsonPrimitive(OracleArtifacts.sha256(OracleJson.canonicalBytes(cases))),
        ))
        val record = JsonObject(legacy + ("reportSha256" to JsonPrimitive(OracleArtifacts.sha256(OracleJson.canonicalBytes(JsonObject(legacy - "reportSha256"))))))
        assertEquals(1, BehaviorEvidence.decode(record.toString().toByteArray()).integer("schemaVersion"))
    }

    @Test
    fun `declared file inputs retain exact bytes and commit read-only sandbox mappings`() {
        val fixture = fixture()
        val input = fixture.original.parent.resolve("case-input.bin")
        val bytes = byteArrayOf(0, 1, 127, -1)
        Files.write(input, bytes)
        val report = BehaviorComparator(fixture.sandbox).evaluate(
            "files", fixture.original, fixture.rebuilt, listOf(ProcessInput("file", listOf("/inputs/nested/input.bin"))),
            fixture.project.resolve("reports"), BehaviorProjectContext(fixture.project),
            fileInputs = mapOf("file" to mapOf("nested/input.bin" to input)),
        )
        val record = BehaviorEvidence.decode(report.reportPath.readBytes())
        assertEquals(2, record.integer("schemaVersion"))
        val case = record.getValue("cases").jsonArray.single().jsonObject
        val retained = case.getValue("fileInputs").jsonArray.single().jsonObject
        assertEquals("00017fff", retained.string("contentHex"))
        assertEquals(OracleArtifacts.sha256(bytes), retained.string("sha256"))
        assertEquals(4L, retained.count("bytes"))
        val command = case.getValue("original").jsonObject.getValue("sandboxCommand").jsonArray.map { it.jsonPrimitive.content }
        assertTrue(command.windowed(3).any { it == listOf("--ro-bind", input.toString(), "/inputs/nested/input.bin") })
        assertTrue(command.windowed(2).any { it == listOf("--dir", "/inputs/nested") })
        Files.delete(input)
        BehaviorEvidence.requireProjectCurrent(record, BehaviorProjectContext(fixture.project))
        assertEquals(true, ArchivalProjectAuditor.audit(fixture.project).behaviorMatched)

        val changedFile = JsonObject(retained + ("contentHex" to JsonPrimitive("00017ffe")))
        val changedCase = JsonObject(case + ("fileInputs" to JsonArray(listOf(changedFile))))
        val changedCases = JsonArray(listOf(changedCase))
        val corpus = JsonArray(listOf(JsonObject(changedCase.filterKeys { it in setOf("id", "args", "stdinHex", "fileInputs") })))
        val changed = JsonObject(record + mapOf(
            "cases" to changedCases,
            "corpusSha256" to JsonPrimitive(OracleArtifacts.sha256(OracleJson.canonicalBytes(corpus))),
            "observationsSha256" to JsonPrimitive(OracleArtifacts.sha256(OracleJson.canonicalBytes(changedCases))),
        ))
        val rehashed = JsonObject(changed + ("reportSha256" to JsonPrimitive(OracleArtifacts.sha256(OracleJson.canonicalBytes(JsonObject(changed - "reportSha256"))))))
        assertFails { BehaviorEvidence.decode(rehashed.toString().toByteArray()) }
    }

    @Test
    fun `file mutation during execution preserves earlier behavior evidence`() {
        val fixture = fixture()
        val input = fixture.original.parent.resolve("case-input")
        input.writeText("retained")
        fun evaluate() = BehaviorComparator(fixture.sandbox).evaluate("files", fixture.original, fixture.rebuilt,
            listOf(ProcessInput("file")), fixture.project.resolve("reports"), BehaviorProjectContext(fixture.project),
            fileInputs = mapOf("file" to mapOf("input" to input)))
        val prior = evaluate().reportPath.readBytes()
        val shim = fixture.original.parent.resolve("authored-runner-shim")
        val command = "shift; exec \"${'$'}program\" \"${'$'}@\""
        val mutation = "shift; printf x >> '${input}'; exec \"${'$'}program\" \"${'$'}@\""
        check(command in shim.readText())
        shim.writeText(shim.readText().replace(command, mutation))
        assertFails { evaluate() }
        assertTrue(prior.contentEquals(fixture.project.resolve("reports/files.behavior.json").readBytes()))
    }

    @Test
    fun `current source build executable and corpus have closed independently checked commitments`() {
        val fixture = fixture()
        val report = fixture.evaluate()
        val record = BehaviorEvidence.decode(report.reportPath.readBytes())
        BehaviorEvidence.requireProjectCurrent(record, BehaviorProjectContext(fixture.project))
        val audit = ArchivalProjectAuditor.audit(fixture.project)
        assertEquals(true, audit.behaviorMatched)
        assertEquals(listOf("reports/probe.behavior.json"), audit.projectBehaviorReportIds)
        assertEquals(emptyList(), audit.unresolvedBehaviorReportIds)
        assertTrue(audit.networkIsolation.isEmpty())
        assertTrue(audit.toJson().contains("\"moduleBehaviorEvidence\": []"))
        assertTrue(record.getValue("executionPolicy").jsonObject.string("assurance").contains("not-production-authority"))
    }

    @Test
    fun `a passing report cannot validate changed source or rebuilt executable bytes`() {
        for (change in listOf("source", "bytes", "mode")) {
            val fixture = fixture()
            fixture.evaluate()
            if (change == "source") {
                val manifestPath = fixture.project.resolve("source_tree_manifest.json")
                val manifest = OracleJson.parse(manifestPath.readBytes()).jsonObject
                val source = manifest.getValue("files").jsonArray.map { it.jsonObject }
                    .first { it.string("path").startsWith("src/modules/") }.string("path")
                Files.writeString(fixture.project.resolve(source), "\n", StandardOpenOption.APPEND)
                val files = manifest.getValue("files").jsonArray.map { file ->
                    val item = file.jsonObject
                    if (item.string("path") != source) item else JsonObject(item + (
                        "sha256" to JsonPrimitive(OracleArtifacts.sha256(fixture.project.resolve(source).readBytes()))
                    ))
                }
                manifestPath.writeText(JsonObject(manifest + ("files" to JsonArray(files))).toString())
            } else if (change == "bytes") {
                Files.write(fixture.rebuilt, byteArrayOf(0), StandardOpenOption.APPEND)
            } else {
                assertTrue(fixture.rebuilt.toFile().setExecutable(false, false))
            }
            val audit = ArchivalProjectAuditor.audit(fixture.project)
            assertEquals(null, audit.behaviorMatched)
            assertEquals(listOf("reports/probe.behavior.json"), audit.unresolvedBehaviorReportIds)
            assertTrue(audit.projectBehaviorReportIds.isEmpty())
        }
    }

    @Test
    fun `new indirect or excessively deep source inputs cannot retain prior validation`() {
        for (linked in listOf(false, true)) {
            val fixture = fixture()
            val report = fixture.evaluate()
            val prior = report.reportPath.readBytes()
            if (linked) {
                Files.createSymbolicLink(fixture.project.resolve("src/extra.c"), fixture.original.parent.resolve("original.c"))
            } else {
                var directory = fixture.project.resolve("src")
                repeat(33) { depth -> directory = Files.createDirectory(directory.resolve("level-$depth")) }
                directory.resolve("extra.c").writeText("int extra(void) { return 0; }\n")
            }
            assertFails { fixture.evaluate() }
            assertTrue(prior.contentEquals(report.reportPath.readBytes()))
            val audit = ArchivalProjectAuditor.audit(fixture.project)
            assertEquals(null, audit.behaviorMatched)
            assertTrue("reports/probe.behavior.json" in audit.behaviorEvidenceProblems)
        }
    }

    @Test
    fun `malformed linked and legacy reports alongside a passing report cannot disappear`() {
        for (variant in listOf("malformed", "legacy", "symlink", "duplicate-key")) {
            val fixture = fixture()
            val report = fixture.evaluate()
            val foreign = fixture.project.resolve("reports/foreign.behavior.json")
            when (variant) {
                "malformed" -> foreign.writeText("{")
                "legacy" -> foreign.writeText("{\"id\":\"old\",\"matches\":true,\"sandbox\":\"bubblewrap\"}")
                "symlink" -> Files.createSymbolicLink(foreign, report.reportPath)
                else -> foreign.writeText(report.reportPath.readText().replaceFirst("{", "{\"id\":\"duplicate\","))
            }
            val audit = ArchivalProjectAuditor.audit(fixture.project)
            assertEquals(2, audit.behaviorReportCount)
            assertEquals(null, audit.behaviorMatched)
            assertTrue("reports/foreign.behavior.json" in audit.behaviorEvidenceProblems)
            assertFalse(audit.sandboxReported)
        }
    }

    @Test
    fun `rehashed flags corpus and unknown fields are rejected independently of the self hash`() {
        val fixture = fixture()
        val report = fixture.evaluate()
        val record = BehaviorEvidence.decode(report.reportPath.readBytes())
        val variants = listOf(
            JsonObject(record + ("matches" to JsonPrimitive(false))),
            JsonObject(record + ("unknown" to JsonPrimitive(true))),
            JsonObject(record + ("corpusSha256" to JsonPrimitive("0".repeat(64)))),
        )
        for (variant in variants) {
            val rehashed = JsonObject(variant + ("reportSha256" to JsonPrimitive(
                OracleArtifacts.sha256(OracleJson.canonicalBytes(JsonObject(variant - "reportSha256"))),
            )))
            assertFails { BehaviorEvidence.decode(rehashed.toString().toByteArray()) }
        }
    }

    @Test
    fun `rehashed command and output-limit contradictions are rejected`() {
        val fixture = fixture()
        val record = BehaviorEvidence.decode(fixture.evaluate().reportPath.readBytes())
        val cases = record.getValue("cases").jsonArray
        val first = cases.first().jsonObject
        val original = first.getValue("original").jsonObject
        val variants = listOf(
            JsonObject(original + ("sandboxCommand" to JsonArray(listOf(JsonPrimitive("/usr/bin/true"))))),
            JsonObject(original + ("networkIsolated" to JsonPrimitive(true))),
        )
        for (observation in variants) {
            val changedCases = JsonArray(listOf(JsonObject(first + ("original" to observation))) + cases.drop(1))
            val changed = JsonObject(record + mapOf(
                "cases" to changedCases,
                "observationsSha256" to JsonPrimitive(OracleArtifacts.sha256(OracleJson.canonicalBytes(changedCases))),
            ))
            val rehashed = JsonObject(changed + ("reportSha256" to JsonPrimitive(
                OracleArtifacts.sha256(OracleJson.canonicalBytes(JsonObject(changed - "reportSha256"))),
            )))
            assertFails { BehaviorEvidence.decode(rehashed.toString().toByteArray()) }
        }
        val policy = record.getValue("executionPolicy").jsonObject
        val oversized = JsonObject(record + ("executionPolicy" to JsonObject(policy + (
            "maximumComparisonOutputBytes" to JsonPrimitive(Long.MAX_VALUE)
        ))))
        val rehashed = JsonObject(oversized + ("reportSha256" to JsonPrimitive(
            OracleArtifacts.sha256(OracleJson.canonicalBytes(JsonObject(oversized - "reportSha256"))),
        )))
        assertFails { BehaviorEvidence.decode(rehashed.toString().toByteArray()) }
    }

    @Test
    fun `project binding and safe report identity are required before comparison publication`() {
        val fixture = fixture()
        assertFails { fixture.evaluate("../escaped") }
        assertTrue(Files.notExists(fixture.project.resolve("escaped.behavior.json")))
        val report = fixture.evaluate()
        val prior = report.reportPath.readBytes()
        Files.write(fixture.original, byteArrayOf(0), StandardOpenOption.APPEND)
        assertFails { fixture.evaluate() }
        assertTrue(prior.contentEquals(report.reportPath.readBytes()))
    }

    @Test
    fun `current-format observations without a project binding remain unresolved`() {
        val fixture = fixture()
        val report = BehaviorComparator(fixture.sandbox).evaluate(
            "unbound", fixture.original, fixture.rebuilt, listOf(ProcessInput("empty")), fixture.project.resolve("reports"),
        )
        assertTrue(report.matches)
        BehaviorEvidence.decode(report.reportPath.readBytes())
        val audit = ArchivalProjectAuditor.audit(fixture.project)
        assertEquals(null, audit.behaviorMatched)
        assertEquals(listOf("reports/unbound.behavior.json"), audit.unresolvedBehaviorReportIds)
    }

    @Test
    fun `executable mutation during comparison cannot replace earlier passing evidence`() {
        val fixture = fixture()
        val prior = fixture.evaluate().reportPath.readBytes()
        val shim = fixture.original.parent.resolve("authored-runner-shim")
        val command = "shift; exec \"${'$'}program\" \"${'$'}@\""
        val mutated = "shift; \"${'$'}program\" \"${'$'}@\"; status=${'$'}?; printf x >> '${fixture.original}'; exit \"${'$'}status\""
        val oldShim = shim.readText()
        check(command in oldShim)
        shim.writeText(oldShim.replace(command, mutated))
        assertFails { fixture.evaluate() }
        assertTrue(prior.contentEquals(fixture.project.resolve("reports/probe.behavior.json").readBytes()))
    }

    @Test
    fun `missing evidence stays explicitly unresolved without per-module execution claims`() {
        val fixture = fixture()
        val audit = ArchivalProjectAuditor.audit(fixture.project)
        assertEquals(null, audit.behaviorMatched)
        assertEquals(listOf("no-behavior-evidence"), audit.unresolvedBehaviorReportIds)
        assertTrue(audit.projectBehaviorReportIds.isEmpty())
    }

    private data class Fixture(val project: Path, val original: Path, val rebuilt: Path, val sandbox: SandboxRunner) {
        fun evaluate(identifier: String = "probe") = BehaviorComparator(sandbox).evaluate(
            identifier, original, rebuilt,
            listOf(ProcessInput("empty"), ProcessInput("argv", listOf("hello"), byteArrayOf(0, 1, 2))),
            project.resolve("reports"), BehaviorProjectContext(project),
        )
    }

    private fun fixture(): Fixture {
        val root = Files.createTempDirectory("behavior-evidence-")
        val original = root.resolve("original")
        val source = "#include <stdio.h>\nint main(int argc, char **argv) { (void)argc; (void)argv; while (getchar() != EOF) {} return 0; }\n"
        val sourceFile = root.resolve("original.c").also { it.writeText(source) }
        val compile = ProcessBuilder("gcc", sourceFile.toString(), "-o", original.toString()).redirectErrorStream(true).start()
        val output = compile.inputStream.readAllBytes().decodeToString()
        check(compile.waitFor() == 0) { output }
        val project = root.resolve("project")
        SourceTreeGenerator.generate(
            RecoveredProgramModel(
                inputSha256 = OracleArtifacts.sha256(original.readBytes()),
                functions = listOf(RecoveredFunction("fn_1000", "main", 0x1000UL,
                    "int main(int argc, char **argv)", decompiledC = source)),
            ),
            project, reconstructor = RecoveredCModuleReconstructor(),
        )
        MakeProjectBuilder.build(project)
        val runner = root.resolve("authored-runner-shim").also { path ->
            path.writeText("""
                #!/bin/sh
                program=
                while [ "${'$'}#" -gt 0 ]; do
                    case "${'$'}1" in
                        --ro-bind)
                            if [ "${'$'}3" = /program/executable ]; then program=${'$'}2; fi
                            shift 3 ;;
                        /program/executable) shift; exec "${'$'}program" "${'$'}@" ;;
                        *) shift ;;
                    esac
                done
                exit 99
            """.trimIndent() + "\n")
            check(path.toFile().setExecutable(true, true))
        }
        return Fixture(project, original, project.resolve("build/reconstructed"), SandboxRunner(
            bwrapPath = runner, networkIsolation = false,
        ))
    }
}
