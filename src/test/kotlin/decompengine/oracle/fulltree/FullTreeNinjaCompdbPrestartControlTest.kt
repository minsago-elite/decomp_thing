package decompengine.oracle.fulltree

import decompengine.oracle.core.OracleArtifacts
import decompengine.oracle.core.OracleJson
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
import kotlinx.serialization.json.JsonObject
import kotlinx.serialization.json.JsonPrimitive

class FullTreeNinjaCompdbPrestartControlTest {
    @Test
    fun `two-file compiler-rule closure derives deterministic unexecuted prestart`() =
        inControlTemporaryDirectory { directory ->
            val fixture = createNinjaPrestartFixture(directory.resolve("valid"))
            val generated = generateNinjaPrestart(fixture)
            val first = loadNinjaPrestart(fixture)
            val second = loadNinjaPrestart(fixture)
            val document = parseControlObject(fixture.artifact)
            val manifestClosure = document.controlObject("manifestClosure")
            val execution = document.controlObject("execution")

            assertEquals(generated.artifactSha256, first.artifactSha256)
            assertEquals(fixtureSha256(fixture.artifact), first.artifactSha256)
            assertEquals(Files.size(fixture.artifact), first.artifactBytes)
            assertEquals(FullTreeNinjaCompdbPrestartControl.configurationSha256, first.configurationSha256)
            assertEquals(fixture.reconciliation.artifactSha256, first.reconciliationArtifactSha256)
            assertEquals(fixtureSha256(fixture.archive), first.manifestArchiveSha256)
            assertContentEquals(first.canonicalBytes, second.canonicalBytes)
            assertEquals(first.prestartContextSha256, second.prestartContextSha256)
            assertEquals(2L, manifestClosure.controlLong("files"))
            assertEquals(1L, manifestClosure.controlLong("edges"))
            assertEquals(3L, manifestClosure.controlLong("rules"))
            assertEquals(
                listOf(
                    "ASM_COMPILER__fixture_unscanned_RelWithDebInfo",
                    "CXX_COMPILER__fixture_unscanned_RelWithDebInfo",
                    "C_COMPILER__fixture_unscanned_RelWithDebInfo",
                ),
                first.compilerRuleNames,
            )
            assertEquals(
                listOf(
                    "/usr/bin/ninja",
                    "-f",
                    "build.ninja",
                    "-t",
                    "compdb",
                ) + first.compilerRuleNames,
                first.argv,
            )
            assertEquals("/oracle/build", first.workingDirectory)
            assertEquals(expectedNinjaPrestartEnvironment(fixture), first.environment)
            assertEquals(first.environment.keys.sorted(), first.environment.keys.toList())
            assertEquals(Files.size(fixture.compdbFixture.compdb), first.expectedStdoutBytes)
            assertEquals(fixtureSha256(fixture.compdbFixture.compdb), first.expectedStdoutSha256)
            assertEquals(fixture.reconciliation.blockerCodes, first.blockerCodes)
            assertFalse(first.startAuthorized)
            assertFalse(first.processAuthority)

            assertEquals("pre-start", execution.controlString("phase"))
            listOf("startAuthorized", "runtimeProvisioned", "processStarted").forEach { field ->
                assertFalse(execution.getValue(field).toString().toBoolean(), field)
            }
            listOf(
                "stdoutBytes",
                "stdoutSha256",
                "stdoutCanonicalSha256",
                "stderrBytes",
                "stderrSha256",
                "exitStatus",
                "timedOut",
                "outputLimitExceeded",
                "cleanupComplete",
                "terminalAbsenceProven",
                "containmentReceiptSha256",
                "compdbReceiptSha256",
            ).forEach { field -> assertEquals("null", execution.getValue(field).toString(), field) }

            val authority = document.controlObject("authority")
            assertEquals(
                "kotlin-bound-unexecuted-ninja-compdb-prestart",
                authority.controlString("status"),
            )
            assertTrue(
                authority.getValue("recordedNinjaExecutableIdentityBound").toString().toBoolean(),
            )
            listOf(
                "liveNinjaExecutableAuthenticated",
                "manifestClosureOriginAuthenticated",
                "compilerRuleDeclarationsOriginAuthenticated",
                "ninjaRuntimeClosureAuthenticated",
                "runtimeProvisioned",
                "retainedRuntimeHandlesPresent",
                "startAuthorized",
                "executionStarted",
                "ninjaExecuted",
                "stdoutObserved",
                "stderrObserved",
                "exitStatusObserved",
                "compdbExecutionAuthenticated",
                "buildGraphOriginAuthenticated",
                "compilerActionGraphOriginAuthenticated",
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
                "prestartAuthoringAuthority",
                "manifestClosureAuthoringAuthority",
                "compilerRuleSelectionAuthority",
                "invocationAuthority",
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
    fun `public construction is sealed raw-path Kotlin only with no execution seam`() =
        inControlTemporaryDirectory { directory ->
            val fixture = createNinjaPrestartFixture(directory.resolve("surface"))
            val registry = generateNinjaPrestart(fixture)

            assertFailsWith<UnsupportedOperationException> {
                @Suppress("UNCHECKED_CAST")
                (registry.compilerRuleNames as MutableList<String>).clear()
            }
            assertFailsWith<UnsupportedOperationException> {
                @Suppress("UNCHECKED_CAST")
                (registry.argv as MutableList<String>).clear()
            }
            assertFailsWith<UnsupportedOperationException> {
                @Suppress("UNCHECKED_CAST")
                (registry.environment as MutableMap<String, String>).clear()
            }
            assertFailsWith<UnsupportedOperationException> {
                @Suppress("UNCHECKED_CAST")
                (registry.blockerCodes as MutableList<String>).clear()
            }
            val bytes = registry.canonicalBytes
            bytes[0] = (bytes[0].toInt() xor 1).toByte()
            assertFalse(bytes.contentEquals(registry.canonicalBytes))

            val methods = FullTreeNinjaCompdbPrestartControl::class.java.declaredMethods
                .filter { Modifier.isPublic(it.modifiers) && !it.isSynthetic }
            assertEquals(
                setOf("generateAndPublish", "getConfigurationSha256", "loadAndValidate"),
                methods.map { it.name }.toSet(),
            )
            methods.filter { it.name != "getConfigurationSha256" }.forEach { method ->
                assertTrue(method.parameterTypes.all { type ->
                    type == Path::class.java || type == FullTreeNinjaCompdbPrestartLimits::class.java
                })
            }
            val production = Path.of(
                "src/main/kotlin/decompengine/oracle/fulltree/FullTreeNinjaCompdbPrestartControl.kt",
            ).toFile().readText()
            listOf(
                "ProcessBuilder",
                "Runtime.getRuntime",
                "java.lang.Process",
                "java.util.function",
                "kotlin.io.path.createTempDirectory",
                "python",
            ).forEach { forbidden -> assertFalse(production.contains(forbidden), forbidden) }
        }

    @Test
    fun `wrong root dynamic missing extra cyclic and duplicate rule closures fail closed`() =
        inControlTemporaryDirectory { directory ->
            val fixture = createNinjaPrestartFixture(directory.resolve("invalid"))
            val invalidArchives = listOf(
                mapOf(
                    "build.ninja" to "# wrong authenticated root\ninclude CMakeFiles/rules.ninja\n".ninjaPrestartBytes(),
                    NINJA_PRESTART_RULES_PATH to NINJA_PRESTART_RULES_BYTES,
                ),
                mapOf("build.ninja" to NINJA_PRESTART_ROOT_BYTES),
                mapOf(
                    "build.ninja" to NINJA_PRESTART_ROOT_BYTES,
                    NINJA_PRESTART_RULES_PATH to NINJA_PRESTART_RULES_BYTES,
                    "unreachable.ninja" to "# unreachable\n".ninjaPrestartBytes(),
                ),
                mapOf(
                    "build.ninja" to NINJA_PRESTART_ROOT_BYTES,
                    NINJA_PRESTART_RULES_PATH to
                        (NINJA_PRESTART_RULES_TEXT + "include build.ninja\n").ninjaPrestartBytes(),
                ),
                mapOf(
                    "build.ninja" to NINJA_PRESTART_ROOT_BYTES,
                    NINJA_PRESTART_RULES_PATH to
                        (NINJA_PRESTART_RULES_TEXT +
                            "rule C_COMPILER__fixture_unscanned_RelWithDebInfo\n" +
                            "  command = duplicate\n").ninjaPrestartBytes(),
                ),
                mapOf(
                    "build.ninja" to NINJA_PRESTART_ROOT_BYTES,
                    NINJA_PRESTART_RULES_PATH to
                        ("rule CXX_COMPILER__fixture_unscanned_RelWithDebInfo\n" +
                            "  command = cxx\n").ninjaPrestartBytes(),
                ),
            )
            invalidArchives.forEachIndexed { index, files ->
                val archive = writeNinjaManifestArchiveForTest(
                    directory.resolve("invalid-$index.tar.xz"),
                    files,
                    fixture.sourceDateEpoch,
                )
                assertFailsWith<FullTreeControlException>("invalid archive $index was accepted") {
                    generateNinjaPrestart(
                        fixture,
                        archivePath = archive,
                        outputPath = directory.resolve("invalid-$index.json"),
                    )
                }
            }

            val dynamicRoot = "include \$rules_file\n".ninjaPrestartBytes()
            val dynamicFixture = createNinjaPrestartFixture(
                directory.resolve("dynamic"),
                mapOf(
                    "build.ninja" to dynamicRoot,
                    NINJA_PRESTART_RULES_PATH to NINJA_PRESTART_RULES_BYTES,
                ),
            )
            assertFailsWith<FullTreeControlException> {
                generateNinjaPrestart(dynamicFixture)
            }
            Unit
        }

    @Test
    fun `forged artifacts raw mutation lowering bounds and input aliases fail closed`() =
        inControlTemporaryDirectory { directory ->
            val fixture = createNinjaPrestartFixture(directory.resolve("forgery"))
            val registry = generateNinjaPrestart(fixture)
            val valid = parseControlObject(fixture.artifact)

            val forgedAuthority = JsonObject(
                valid.controlObject("authority") + ("ninjaExecuted" to JsonPrimitive(true)),
            )
            val authorityPath = directory.resolve("forged-authority.json")
            writeControlObject(
                authorityPath,
                rehashNinjaPrestartArtifact(JsonObject(valid + ("authority" to forgedAuthority))),
            )
            assertFailsWith<FullTreeControlException> {
                loadNinjaPrestart(fixture, artifactPath = authorityPath)
            }

            val forgedCommitments = JsonObject(
                valid.controlObject("commitments") +
                    ("compilerRulesSha256" to JsonPrimitive("f".repeat(64))),
            )
            val commitmentPath = directory.resolve("forged-commitment.json")
            writeControlObject(
                commitmentPath,
                rehashNinjaPrestartArtifact(JsonObject(valid + ("commitments" to forgedCommitments))),
            )
            assertFailsWith<FullTreeControlException> {
                loadNinjaPrestart(fixture, artifactPath = commitmentPath)
            }

            val rawMutation = directory.resolve("raw-mutation.json")
            Files.write(rawMutation, registry.canonicalBytes + ' '.code.toByte())
            assertFailsWith<FullTreeControlException> {
                loadNinjaPrestart(fixture, artifactPath = rawMutation)
            }

            val longestRuleBytes = registry.compilerRuleNames.maxOf {
                it.toByteArray(StandardCharsets.UTF_8).size
            }
            val lowerings = listOf(
                FullTreeNinjaCompdbPrestartLimits(
                    reconciliation = FullTreeClangCompdbReconciliationLimits(maximumActions = 1),
                ),
                FullTreeNinjaCompdbPrestartLimits(
                    manifestArchive = FullTreeNinjaManifestArchiveLimits(maximumManifestFiles = 1),
                ),
                FullTreeNinjaCompdbPrestartLimits(
                    maximumCanonicalBytes = registry.artifactBytes.toInt() - 1,
                ),
                FullTreeNinjaCompdbPrestartLimits(maximumCompilerRules = 2),
                FullTreeNinjaCompdbPrestartLimits(maximumEnvironmentBytes = 1),
                FullTreeNinjaCompdbPrestartLimits(maximumEnvironmentVariables = 3),
                FullTreeNinjaCompdbPrestartLimits(maximumPathBytes = 1),
                FullTreeNinjaCompdbPrestartLimits(maximumRuleNameBytes = longestRuleBytes - 1),
                FullTreeNinjaCompdbPrestartLimits(
                    maximumStdoutBytes = registry.expectedStdoutBytes.toInt() - 1,
                ),
                FullTreeNinjaCompdbPrestartLimits(maximumToolBytes = 1),
            )
            lowerings.forEachIndexed { index, limits ->
                assertFailsWith<FullTreeControlException>("lowering $index was accepted") {
                    loadNinjaPrestart(fixture, limits = limits)
                }
            }

            val hiddenScopeLink = directory.resolve("hidden-scope-link.json")
            Files.createLink(
                hiddenScopeLink,
                fixture.compdbFixture.captureFixture.generated.control.scope,
            )
            try {
                val descriptorsBefore = ninjaPrestartOpenDescriptorCount()
                repeat(4) {
                    assertFailsWith<FullTreeControlException> {
                        loadNinjaPrestart(fixture)
                    }
                }
                assertTrue(
                    ninjaPrestartOpenDescriptorCount() <= descriptorsBefore,
                    "rejected hidden hardlinks must not leak descriptor guards",
                )
            } finally {
                Files.delete(hiddenScopeLink)
            }

            val readinessAlias = directory.resolve("readiness-input-alias.json")
            Files.createLink(readinessAlias, fixture.compdbFixture.captureFixture.captureInput)
            assertFailsWith<FullTreeControlException> {
                loadNinjaPrestart(fixture, readinessPath = readinessAlias)
            }
            Unit
        }
}

private data class NinjaPrestartFixture(
    val compdbFixture: CompdbFixture,
    val reconciliation: FullTreeClangCompdbReconciliationRegistry,
    val archive: Path,
    val artifact: Path,
    val sourceDateEpoch: Long,
)

private fun createNinjaPrestartFixture(
    root: Path,
    manifestFiles: Map<String, ByteArray> = validNinjaPrestartManifestFiles(),
): NinjaPrestartFixture {
    Files.createDirectories(root)
    val rootBytes = manifestFiles.getValue("build.ninja")
    val compdbFixture = createCompdbFixture(
        root.resolve("compdb"),
        ninjaManifestBytes = rootBytes,
    )
    val reconciliation = generateCompdb(compdbFixture)
    val buildRecord = parseControlObject(compdbFixture.captureFixture.generated.control.buildRecord)
    val epoch = buildRecord.controlObject("environment").controlObject("variables")
        .controlString("SOURCE_DATE_EPOCH").toLong()
    val archive = writeNinjaManifestArchiveForTest(
        root.resolve("ninja-manifest.tar.xz"),
        manifestFiles,
        epoch,
    )
    return NinjaPrestartFixture(
        compdbFixture,
        reconciliation,
        archive,
        root.resolve("prestart.json"),
        epoch,
    )
}

private fun generateNinjaPrestart(
    fixture: NinjaPrestartFixture,
    archivePath: Path = fixture.archive,
    outputPath: Path = fixture.artifact,
    limits: FullTreeNinjaCompdbPrestartLimits = FullTreeNinjaCompdbPrestartLimits(),
): FullTreeNinjaCompdbPrestartRegistry {
    val compdb = fixture.compdbFixture
    val capture = compdb.captureFixture
    val generated = capture.generated
    val control = generated.control
    return FullTreeNinjaCompdbPrestartControl.generateAndPublish(
        archivePath,
        compdb.reconciliation,
        compdb.compdb,
        capture.captureInput,
        capture.readiness,
        capture.generatedInventory,
        control.sourceArchive,
        generated.archive,
        generated.provenance,
        control.scope,
        control.sourceLock,
        control.manifest,
        control.buildRecord,
        control.inventory,
        control.sourceInventory,
        generated.planning,
        outputPath,
        limits,
    )
}

private fun loadNinjaPrestart(
    fixture: NinjaPrestartFixture,
    artifactPath: Path = fixture.artifact,
    archivePath: Path = fixture.archive,
    readinessPath: Path = fixture.compdbFixture.captureFixture.readiness,
    limits: FullTreeNinjaCompdbPrestartLimits = FullTreeNinjaCompdbPrestartLimits(),
): FullTreeNinjaCompdbPrestartRegistry {
    val compdb = fixture.compdbFixture
    val capture = compdb.captureFixture
    val generated = capture.generated
    val control = generated.control
    return FullTreeNinjaCompdbPrestartControl.loadAndValidate(
        artifactPath,
        archivePath,
        compdb.reconciliation,
        compdb.compdb,
        capture.captureInput,
        readinessPath,
        capture.generatedInventory,
        control.sourceArchive,
        generated.archive,
        generated.provenance,
        control.scope,
        control.sourceLock,
        control.manifest,
        control.buildRecord,
        control.inventory,
        control.sourceInventory,
        generated.planning,
        limits,
    )
}

private fun expectedNinjaPrestartEnvironment(fixture: NinjaPrestartFixture): Map<String, String> =
    parseControlObject(fixture.compdbFixture.captureFixture.generated.control.buildRecord)
        .controlObject("environment")
        .controlObject("variables")
        .entries
        .sortedBy { it.key }
        .associate { (name, value) -> name to value.controlString("environment variable $name") }

private fun rehashNinjaPrestartArtifact(document: JsonObject): JsonObject {
    val withoutHash = JsonObject(document.filterKeys { it != "reportSha256" })
    return JsonObject(
        withoutHash + ("reportSha256" to JsonPrimitive(
            OracleArtifacts.sha256(
                OracleJson.canonicalBytes(withoutHash, controlJsonLimits(16 * 1024 * 1024)),
            ),
        )),
    )
}

private fun validNinjaPrestartManifestFiles(): Map<String, ByteArray> = mapOf(
    "build.ninja" to NINJA_PRESTART_ROOT_BYTES,
    NINJA_PRESTART_RULES_PATH to NINJA_PRESTART_RULES_BYTES,
)

private fun String.ninjaPrestartBytes(): ByteArray = toByteArray(StandardCharsets.UTF_8)

private fun ninjaPrestartOpenDescriptorCount(): Long =
    Files.list(Path.of("/proc/self/fd")).use { descriptors -> descriptors.count() }

private const val NINJA_PRESTART_RULES_PATH = "CMakeFiles/rules.ninja"
private const val NINJA_PRESTART_RULES_TEXT =
    "rule CXX_COMPILER__fixture_unscanned_RelWithDebInfo\n" +
        "  command = cxx\n" +
        "rule C_COMPILER__fixture_unscanned_RelWithDebInfo\n" +
        "  command = cc\n" +
        "rule ASM_COMPILER__fixture_unscanned_RelWithDebInfo\n" +
        "  command = asm\n"
private val NINJA_PRESTART_ROOT_BYTES =
    "include $NINJA_PRESTART_RULES_PATH\n".ninjaPrestartBytes()
private val NINJA_PRESTART_RULES_BYTES = NINJA_PRESTART_RULES_TEXT.ninjaPrestartBytes()
