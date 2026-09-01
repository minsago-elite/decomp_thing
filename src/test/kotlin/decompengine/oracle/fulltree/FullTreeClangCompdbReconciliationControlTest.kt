package decompengine.oracle.fulltree

import decompengine.oracle.core.OracleArtifacts
import decompengine.oracle.core.OracleJson
import decompengine.oracle.core.OracleSchemas
import java.lang.reflect.Modifier
import java.nio.charset.StandardCharsets
import java.nio.file.Files
import java.nio.file.Path
import kotlin.test.Test
import kotlin.test.assertContentEquals
import kotlin.test.assertEquals
import kotlin.test.assertFailsWith
import kotlin.test.assertFalse
import kotlin.test.assertTrue
import kotlinx.serialization.json.JsonArray
import kotlinx.serialization.json.JsonElement
import kotlinx.serialization.json.JsonObject
import kotlinx.serialization.json.JsonPrimitive

class FullTreeClangCompdbReconciliationControlTest {
    @Test
    fun `external compdb reconciles deterministically without replay authority`() =
        inControlTemporaryDirectory { directory ->
            val fixture = createCompdbFixture(directory.resolve("valid"), includeIgnored = true)
            val generated = generateCompdb(fixture)
            val first = loadCompdb(fixture)
            val second = loadCompdb(fixture)
            val document = parseControlObject(fixture.reconciliation)

            assertEquals(generated.artifactSha256, first.artifactSha256)
            assertEquals(fixtureSha256(fixture.reconciliation), first.artifactSha256)
            assertEquals(Files.size(fixture.reconciliation), first.artifactBytes)
            assertEquals(2, first.matches.size)
            assertEquals(EXPECTED_COMPDB_BLOCKERS, first.blockerCodes)
            assertEquals(fixtureSha256(fixture.compdb), first.compdbSha256)
            assertEquals(fixture.capture.captureContextSha256, first.captureContextSha256)
            assertContentEquals(first.canonicalBytes, second.canonicalBytes)
            first.matches.forEach { match ->
                assertEquals(match, first.requireMatchForCaptureAction(match.captureActionSha256))
                assertEquals("/oracle/build", match.directory)
                assertEquals(match.output, match.resolvedOutput.removePrefix("/oracle/build/"))
                assertTrue(match.commandWords >= 10)
            }

            val counts = document.controlObject("counts")
            assertEquals(2L, counts.controlLong("captureActions"))
            assertEquals(3L, counts.controlLong("compdbRecords"))
            assertEquals(2L, counts.controlLong("matches"))
            assertEquals(1L, counts.controlLong("ignoredCompdbRecords"))
            assertEquals(10L, counts.controlLong("outputRecords"))
            assertTrue(counts.controlLong("compdbCommandBytes") > counts.controlLong("selectedCommandBytes"))
            assertTrue(counts.controlLong("compdbCommandWords") > counts.controlLong("selectedCommandWords"))
            assertEquals(
                "external-raw-filtered-compdb-sidecar",
                document.controlObject("evidence").controlString("transport"),
            )
            assertEquals(
                "caller-supplied-compiler-rule-filtered-population-filter-origin-unreceipted",
                document.controlObject("reconciliationPolicy")
                    .controlString("recordPopulationDisposition"),
            )
            val authority = document.controlObject("authority")
            assertEquals(
                "external-unreceipted-compdb-reconciliation",
                authority.controlString("status"),
            )
            listOf(
                "predecessorBindingsReconciled",
                "rawEvidenceIntegrityVerified",
                "captureActionExternalCompdbMatchExact",
                "strictArgumentTransformationVerified",
            ).forEach { field -> assertTrue(authority.getValue(field).toString().toBoolean(), field) }
            listOf(
                "captureInputAuthenticated",
                "compilerOptionArityValidated",
                "compilerActionsAuthenticated",
                "externalEvidenceAuthenticated",
                "compdbExecutionAuthenticated",
                "buildGraphOriginAuthenticated",
                "compilerExecuted",
                "captureStarted",
                "captureOutputsPresent",
                "exitStatusesPresent",
                "compilerCaptureAuthenticated",
                "compilerWriteSetContained",
                "generatedSnapshotAuthenticated",
                "headerPopulationComplete",
                "headerPlanReady",
                "cleanCompilationProven",
                "releaseEligible",
            ).forEach { field -> assertFalse(authority.getValue(field).toString().toBoolean(), field) }
            val acp = document.controlObject("acpBoundary")
            assertEquals("first-class-candidate-producer-operator", acp.controlString("role"))
            assertEquals("read-only-oracle-input", acp.controlString("candidateProvenanceAccess"))
            listOf(
                "captureInputAuthoringAuthority",
                "graphEvidenceAuthoringAuthority",
                "compdbEvidenceAuthoringAuthority",
                "compilerActionAuthoringAuthority",
                "captureAuthority",
                "executionAuthority",
                "oracleAuthority",
                "referenceAuthoringAuthority",
                "policyAuthoringAuthority",
                "validationAuthority",
                "observationAuthoringAuthority",
                "startAuthority",
                "containmentAuthority",
                "terminalAbsenceAuthority",
                "scoringAuthority",
                "certificationAuthority",
                "releaseAuthority",
            ).forEach { field -> assertFalse(acp.getValue(field).toString().toBoolean(), field) }
        }

    @Test
    fun `registry is immutable and public construction is raw-path Kotlin only`() =
        inControlTemporaryDirectory { directory ->
            val fixture = createCompdbFixture(directory.resolve("surface"))
            val registry = generateCompdb(fixture)

            assertFailsWith<UnsupportedOperationException> {
                @Suppress("UNCHECKED_CAST")
                (registry.matches as MutableList<FullTreeClangCompdbMatch>).clear()
            }
            assertFailsWith<UnsupportedOperationException> {
                @Suppress("UNCHECKED_CAST")
                (registry.blockerCodes as MutableList<String>).clear()
            }
            val copy = registry.canonicalBytes
            copy[0] = (copy[0].toInt() xor 1).toByte()
            assertFalse(copy.contentEquals(registry.canonicalBytes))
            assertFailsWith<FullTreeControlException> {
                registry.requireMatchForCaptureAction("not-a-sha")
            }

            val publicMethods = FullTreeClangCompdbReconciliationControl::class.java.declaredMethods
                .filter { Modifier.isPublic(it.modifiers) && !it.isSynthetic }
            assertEquals(
                setOf("generateAndPublish", "getConfigurationSha256", "loadAndValidate"),
                publicMethods.map { it.name }.toSet(),
            )
            publicMethods.filter { it.name != "getConfigurationSha256" }.forEach { method ->
                assertTrue(method.parameterTypes.all { type ->
                    type == Path::class.java || type == FullTreeClangCompdbReconciliationLimits::class.java
                })
            }
            val production = Path.of(
                "src/main/kotlin/decompengine/oracle/fulltree/FullTreeClangCompdbReconciliationControl.kt",
            ).toFile().readText()
            listOf("ProcessBuilder", "Runtime.getRuntime", "python", "java.util.function").forEach { forbidden ->
                assertFalse(production.contains(forbidden), forbidden)
            }
        }

    @Test
    fun `ambiguous paths commands and transformations fail closed`() =
        inControlTemporaryDirectory { directory ->
            val fixture = createCompdbFixture(directory.resolve("invalid"), includeIgnored = true)
            val valid = readCompdbRecords(fixture.compdb)
            val first = valid.first()
            val second = valid[1]
            val variants = listOf(
                JsonArray(valid.drop(1)),
                JsonArray(listOf(first, first) + valid.drop(1)),
                JsonArray(
                    listOf(
                        JsonObject(first + ("output" to JsonPrimitive("capture/other.o"))),
                    ) + valid.drop(1),
                ),
                JsonArray(
                    listOf(
                        JsonObject(first + ("directory" to JsonPrimitive("/oracle/other-build"))),
                    ) + valid.drop(1),
                ),
                JsonArray(
                    listOf(
                        JsonObject(first + ("file" to JsonPrimitive("relative/source.cpp"))),
                    ) + valid.drop(1),
                ),
                JsonArray(
                    listOf(
                        JsonObject(first + ("output" to JsonPrimitive("capture/../capture/object.o"))),
                    ) + valid.drop(1),
                ),
                replaceCompdbCommand(valid, 0) { "$it " },
                replaceCompdbCommand(valid, 0) { it.replace(" ", "  ") },
                replaceCompdbCommand(valid, 0) { "ENV=value $it" },
                replaceCompdbCommand(valid, 0) { "wrapper $it" },
                replaceCompdbCommand(valid, 0) { it.replace("-DTEST_CAPTURE=1", "'-DTEST_CAPTURE=1'") },
                replaceCompdbCommand(valid, 0) { it.replace("-DTEST_CAPTURE=1", "-DTEST_CAPTURE=2") },
                replaceCompdbCommand(valid, 0) { it.replace("-MD -MT", "-MMD -MT") },
                replaceCompdbCommand(valid, 0) { it.replace(" -c ", " -S ") },
                replaceCompdbCommand(valid, valid.lastIndex) { it.replace("-DIGNORED=1", "--") },
                replaceCompdbCommand(valid, valid.lastIndex) { it.replace("-DIGNORED=1", "-S") },
                replaceCompdbCommand(valid, valid.lastIndex) { it.replace("-DIGNORED=1", "-Xclang") },
                replaceCompdbCommand(valid, valid.lastIndex) {
                    it.replace("/usr/lib/llvm-22/bin/clang++", "clang++")
                },
                JsonArray(
                    valid.mapIndexed { index, record ->
                        if (index != valid.lastIndex) record else JsonObject(
                            record + ("command" to first.getValue("command")),
                        )
                    },
                ),
                JsonArray(
                    valid.mapIndexed { index, record ->
                        if (index != valid.lastIndex) record else JsonObject(
                            record + ("command" to JsonPrimitive(
                                record.controlString("command").replace(
                                    " -MD ",
                                    " ${first.controlString("file")} -MD ",
                                ),
                            )),
                        )
                    },
                ),
                JsonArray(
                    valid.mapIndexed { index, record ->
                        if (index != valid.lastIndex) record else JsonObject(
                            record + ("output" to second.getValue("output")),
                        )
                    },
                ),
            )
            variants.forEachIndexed { index, variant ->
                writeRawCompdb(fixture.compdb, variant)
                assertFailsWith<FullTreeControlException>("variant $index was accepted") {
                    generateCompdb(fixture, directory.resolve("invalid-$index.json"))
                }
            }
        }

    @Test
    fun `artifact forgery raw mutation aliases and every populated lowering bound fail closed`() =
        inControlTemporaryDirectory { directory ->
            val fixture = createCompdbFixture(directory.resolve("bounds"), includeIgnored = true)
            val registry = generateCompdb(fixture)
            val validArtifact = parseControlObject(fixture.reconciliation)
            val validCompdb = Files.readAllBytes(fixture.compdb)

            val forgedAuthority = JsonObject(
                validArtifact.controlObject("authority") +
                    ("compdbExecutionAuthenticated" to JsonPrimitive(true)),
            )
            assertFailsWith<IllegalArgumentException> {
                OracleSchemas.validate(
                    "full-tree-clang-compdb-reconciliation",
                    JsonObject(validArtifact + ("authority" to forgedAuthority)),
                )
            }
            val forgedCommitments = JsonObject(
                validArtifact.controlObject("commitments") +
                    ("matchManifestSha256" to JsonPrimitive("f".repeat(64))),
            )
            val forgedPath = directory.resolve("forged.json")
            writeControlObject(
                forgedPath,
                rehashCompdbArtifact(JsonObject(validArtifact + ("commitments" to forgedCommitments))),
            )
            assertFailsWith<FullTreeControlException> { loadCompdb(fixture, forgedPath) }

            Files.write(fixture.compdb, validCompdb + ' '.code.toByte())
            assertFailsWith<FullTreeControlException> { loadCompdb(fixture) }
            Files.write(fixture.compdb, validCompdb)

            val counts = validArtifact.controlObject("counts")
            val maximumCommandBytes = registry.matches.maxOf { it.commandBytes }
            val maximumCommandWords = registry.matches.maxOf { it.commandWords }
            val paths = registry.matches.flatMap { listOf(it.directory, it.file, it.output, it.resolvedOutput) }
            val maximumPathBytes = paths.maxOf { it.toByteArray(StandardCharsets.UTF_8).size }
            val maximumComponentBytes = paths.flatMap { it.removePrefix("/").split('/') }
                .maxOf { it.toByteArray(StandardCharsets.UTF_8).size }
            val lowerings = listOf(
                FullTreeClangCompdbReconciliationLimits(maximumActions = 1),
                FullTreeClangCompdbReconciliationLimits(
                    maximumCanonicalBytes = Files.size(fixture.reconciliation).toInt() - 1,
                ),
                FullTreeClangCompdbReconciliationLimits(maximumCommandBytes = maximumCommandBytes - 1),
                FullTreeClangCompdbReconciliationLimits(
                    maximumCommandWordsPerAction = maximumCommandWords - 1,
                ),
                FullTreeClangCompdbReconciliationLimits(
                    maximumCompdbBytes = Files.size(fixture.compdb).toInt() - 1,
                ),
                FullTreeClangCompdbReconciliationLimits(maximumCompdbRecords = 2),
                FullTreeClangCompdbReconciliationLimits(
                    maximumOutputRecords = counts.controlLong("outputRecords") - 1,
                ),
                FullTreeClangCompdbReconciliationLimits(maximumPathBytes = maximumPathBytes - 1),
                FullTreeClangCompdbReconciliationLimits(
                    maximumPathComponentBytes = maximumComponentBytes - 1,
                ),
                FullTreeClangCompdbReconciliationLimits(
                    maximumRawStringBytes = counts.controlLong("rawStringBytes").toInt() - 1,
                ),
                FullTreeClangCompdbReconciliationLimits(
                    maximumTotalCommandBytes = counts.controlLong("compdbCommandBytes") - 1,
                ),
                FullTreeClangCompdbReconciliationLimits(
                    maximumTotalCommandWords = counts.controlLong("compdbCommandWords") - 1,
                ),
                FullTreeClangCompdbReconciliationLimits(
                    maximumWorkUnits = counts.controlLong("workUnits") - 1,
                ),
            )
            lowerings.forEachIndexed { index, limits ->
                assertFailsWith<FullTreeControlException>(
                    "lowering $index was accepted; maximumPathBytes=$maximumPathBytes paths=$paths",
                ) {
                    loadCompdb(fixture, limits = limits)
                }
            }

            val alias = directory.resolve("compdb-alias.json")
            Files.createLink(alias, fixture.compdb)
            assertFailsWith<FullTreeControlException> {
                loadCompdb(fixture.copy(compdb = alias))
            }
            Unit
        }
}

internal data class CompdbFixture(
    val captureFixture: CaptureFixture,
    val capture: FullTreeClangCaptureInputRegistry,
    val compdb: Path,
    val reconciliation: Path,
)

internal fun createCompdbFixture(
    root: Path,
    includeIgnored: Boolean = false,
    ninjaManifestBytes: ByteArray = "ninja".toByteArray(StandardCharsets.US_ASCII),
): CompdbFixture {
    Files.createDirectories(root)
    val captureFixture = createCaptureFixture(root.resolve("capture"), ninjaManifestBytes)
    val capture = loadCapture(captureFixture)
    val records = capture.actions.map { action -> compdbRecord(action) }.toMutableList()
    if (includeIgnored) {
        records += JsonObject(
            mapOf(
                "command" to JsonPrimitive(
                    "/usr/lib/llvm-22/bin/clang++ -DIGNORED=1 -MD -MT unrelated/ignored.o " +
                        "-MF unrelated/ignored.o.d -o unrelated/ignored.o -c /oracle/other/ignored.cpp",
                ),
                "directory" to JsonPrimitive("/oracle/build"),
                "file" to JsonPrimitive("/oracle/other/ignored.cpp"),
                "output" to JsonPrimitive("unrelated/ignored.o"),
            ),
        )
    }
    val compdb = root.resolve("compdb.json")
    writeRawCompdb(compdb, JsonArray(records))
    return CompdbFixture(captureFixture, capture, compdb, root.resolve("reconciliation.json"))
}

private fun compdbRecord(action: FullTreeClangCaptureAction): JsonObject {
    val rawArguments = buildList {
        add(action.arguments.first())
        addAll(action.arguments.drop(11))
        addAll(action.arguments.subList(2, 11))
    }
    return JsonObject(
        mapOf(
            "command" to JsonPrimitive(rawArguments.joinToString(" ")),
            "directory" to JsonPrimitive(action.workingDirectory),
            "file" to JsonPrimitive(action.mainInput),
            "output" to JsonPrimitive(action.arguments[8]),
        ),
    )
}

internal fun generateCompdb(
    fixture: CompdbFixture,
    output: Path = fixture.reconciliation,
    limits: FullTreeClangCompdbReconciliationLimits = FullTreeClangCompdbReconciliationLimits(),
): FullTreeClangCompdbReconciliationRegistry = FullTreeClangCompdbReconciliationControl.generateAndPublish(
    fixture.compdb,
    fixture.captureFixture.captureInput,
    fixture.captureFixture.readiness,
    fixture.captureFixture.generatedInventory,
    fixture.captureFixture.generated.control.sourceArchive,
    fixture.captureFixture.generated.archive,
    fixture.captureFixture.generated.provenance,
    fixture.captureFixture.generated.control.scope,
    fixture.captureFixture.generated.control.sourceLock,
    fixture.captureFixture.generated.control.manifest,
    fixture.captureFixture.generated.control.buildRecord,
    fixture.captureFixture.generated.control.inventory,
    fixture.captureFixture.generated.control.sourceInventory,
    fixture.captureFixture.generated.planning,
    output,
    limits,
)

internal fun loadCompdb(
    fixture: CompdbFixture,
    path: Path = fixture.reconciliation,
    limits: FullTreeClangCompdbReconciliationLimits = FullTreeClangCompdbReconciliationLimits(),
): FullTreeClangCompdbReconciliationRegistry = FullTreeClangCompdbReconciliationControl.loadAndValidate(
    path,
    fixture.compdb,
    fixture.captureFixture.captureInput,
    fixture.captureFixture.readiness,
    fixture.captureFixture.generatedInventory,
    fixture.captureFixture.generated.control.sourceArchive,
    fixture.captureFixture.generated.archive,
    fixture.captureFixture.generated.provenance,
    fixture.captureFixture.generated.control.scope,
    fixture.captureFixture.generated.control.sourceLock,
    fixture.captureFixture.generated.control.manifest,
    fixture.captureFixture.generated.control.buildRecord,
    fixture.captureFixture.generated.control.inventory,
    fixture.captureFixture.generated.control.sourceInventory,
    fixture.captureFixture.generated.planning,
    limits,
)

private fun readCompdbRecords(path: Path): List<JsonObject> =
    (OracleJson.parse(Files.readAllBytes(path)) as JsonArray).map { it as JsonObject }

private fun writeRawCompdb(path: Path, records: JsonArray) {
    Files.write(path, OracleJson.canonicalBytes(records, controlJsonLimits(64 * 1024 * 1024)))
}

private fun replaceCompdbCommand(
    records: List<JsonObject>,
    index: Int,
    mutation: (String) -> String,
): JsonArray = JsonArray(records.mapIndexed { recordIndex, record ->
    if (recordIndex != index) {
        record
    } else {
        JsonObject(record + ("command" to JsonPrimitive(mutation(record.controlString("command")))))
    }
})

private fun rehashCompdbArtifact(document: JsonObject): JsonObject {
    val withoutHash = JsonObject(document.filterKeys { it != "reportSha256" })
    return JsonObject(
        withoutHash + ("reportSha256" to JsonPrimitive(
            OracleArtifacts.sha256(
                OracleJson.canonicalBytes(withoutHash, controlJsonLimits(32 * 1024 * 1024)),
            ),
        )),
    )
}

private val EXPECTED_COMPDB_BLOCKERS = listOf(
    "complete-project-header-inventory-missing",
    "compiler-capture-provenance-missing",
    "compiler-option-arity-unvalidated",
    "generated-generation-receipt-missing",
    "generated-snapshot-completeness-unproven",
    "ninja-live-edge-replay-missing",
    "physical-build-root-unverified",
    "physical-project-roots-unverified",
)
