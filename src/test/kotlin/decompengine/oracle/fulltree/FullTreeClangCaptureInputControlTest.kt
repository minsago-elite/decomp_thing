package decompengine.oracle.fulltree

import decompengine.oracle.core.OracleArtifacts
import decompengine.oracle.core.OracleJson
import decompengine.oracle.core.OracleSchemas
import java.lang.reflect.Modifier
import java.lang.reflect.Proxy
import java.nio.ByteBuffer
import java.nio.ByteOrder
import java.nio.charset.StandardCharsets
import java.nio.file.Files
import java.nio.file.Path
import java.security.MessageDigest
import java.util.TreeSet
import kotlin.test.Test
import kotlin.test.assertContentEquals
import kotlin.test.assertEquals
import kotlin.test.assertFailsWith
import kotlin.test.assertFalse
import kotlin.test.assertNotEquals
import kotlin.test.assertTrue
import kotlinx.serialization.json.JsonArray
import kotlinx.serialization.json.JsonElement
import kotlinx.serialization.json.JsonObject
import kotlinx.serialization.json.JsonPrimitive

class FullTreeClangCaptureInputControlTest {
    @Test
    fun `raw all-TU input loads deterministically without claiming capture authority`() =
        inControlTemporaryDirectory { directory ->
            val fixture = createCaptureFixture(directory.resolve("fixture"))
            val first = loadCapture(fixture)
            val second = loadCapture(fixture)
            val document = parseControlObject(fixture.captureInput)

            assertEquals(fixtureSha256(fixture.captureInput), first.artifactSha256)
            assertEquals(Files.size(fixture.captureInput), first.artifactBytes)
            assertEquals(document.controlString("reportSha256"), first.reportSha256)
            assertEquals(FullTreeClangCaptureInputControl.configurationSha256, first.configurationSha256)
            assertEquals(2, first.actions.size)
            assertEquals(1, first.actions.count { it.sourceKind == "handwritten" })
            assertEquals(1, first.actions.count { it.sourceKind == "generated" })
            assertEquals(
                listOf(
                    FullTreeGeneratedFileInventoryControlTest.GENERATED_HEADER,
                    FullTreeGeneratedFileInventoryControlTest.GENERATED_INC,
                ),
                first.canonicalCaptureHeaderCandidatePaths,
            )
            assertEquals(3, first.sourceOnlyUnits.size)
            assertEquals(4, first.baseEnvironment.size)
            assertEquals(EXPECTED_BLOCKERS, first.blockerCodes)
            assertContentEquals(first.canonicalBytes, second.canonicalBytes)
            assertEquals(first.captureActionsSha256, second.captureActionsSha256)
            assertEquals(first.captureContextSha256, second.captureContextSha256)
            assertEquals(
                document.controlObject("commitments").controlString("actionsSha256"),
                first.captureActionsSha256,
            )
            assertEquals(
                document.controlObject("commitments").controlString("captureContextSha256"),
                first.captureContextSha256,
            )
            val handwritten = first.actions.single { it.sourceKind == "handwritten" }
            val expectedHandwrittenIdentity = captureActionIdentityForTest(
                handwritten,
                first.captureContextSha256,
                document.controlObject("oracle").controlString("buildRecordSha256"),
                document.controlObject("environment").controlString("baseEnvironmentSha256"),
                document.controlObject("source").controlString("archiveSha256"),
            )
            assertEquals(expectedHandwrittenIdentity, handwritten.actionSha256)
            assertNotEquals(
                handwritten.actionSha256,
                captureActionIdentityForTest(
                    handwritten,
                    "f".repeat(64),
                    document.controlObject("oracle").controlString("buildRecordSha256"),
                    document.controlObject("environment").controlString("baseEnvironmentSha256"),
                    document.controlObject("source").controlString("archiveSha256"),
                ),
            )

            first.actions.forEach { action ->
                assertEquals(action, first.requireActionForOwnerModule(action.unitId))
                assertEquals(action.moduleId, action.unitId)
                assertEquals("/oracle/build", action.workingDirectory)
                assertEquals("traces/${action.actionSha256}.json", action.traceArtifactPath)
                assertTrue(action.objectOutput.startsWith("/oracle/build/capture/"))
                assertEquals("${action.objectOutput}.d", action.dependencyFile)
            }

            val authority = document.controlObject("authority")
            assertEquals("unexecuted-unreceipted-capture-input", authority.controlString("status"))
            assertTrue(authority.getValue("a13ModuleActionJoinExact").toString().toBoolean())
            assertTrue(authority.getValue("predecessorBindingsReconciled").toString().toBoolean())
            assertTrue(
                authority.getValue("sourceAndGeneratedHeaderCandidatesCombined").toString().toBoolean(),
            )
            listOf(
                "captureInputAuthenticated",
                "compilerActionsAuthenticated",
                "compilerOptionArityValidated",
                "captureStarted",
                "captureOutputsPresent",
                "exitStatusesPresent",
                "compilerCaptureAuthenticated",
                "compilerWriteSetContained",
                "headerPopulationComplete",
                "headerPlanReady",
                "cleanCompilationProven",
                "releaseEligible",
            ).forEach { field -> assertFalse(authority.getValue(field).toString().toBoolean()) }

            val acp = document.controlObject("acpBoundary")
            assertEquals("first-class-candidate-producer-operator", acp.controlString("role"))
            assertEquals("read-only-oracle-input", acp.controlString("candidateProvenanceAccess"))
            listOf(
                "captureInputAuthoringAuthority",
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
            ).forEach { field -> assertFalse(acp.getValue(field).toString().toBoolean()) }

            assertEquals(19L, document.controlObject("counts").controlLong("outputRecords"))
            assertEquals(220L, document.controlObject("counts").controlLong("workUnits"))
            assertEquals(
                fixture.headerPathBytes,
                document.controlObject("counts").controlLong("headerPathBytes"),
            )
        }

    @Test
    fun `registry is deeply immutable and exposes only a raw-path load boundary`() =
        inControlTemporaryDirectory { directory ->
            val fixture = createCaptureFixture(directory.resolve("immutable"))
            val registry = loadCapture(fixture)

            assertFailsWith<UnsupportedOperationException> {
                @Suppress("UNCHECKED_CAST")
                (registry.actions as MutableList<FullTreeClangCaptureAction>).clear()
            }
            assertFailsWith<UnsupportedOperationException> {
                @Suppress("UNCHECKED_CAST")
                (registry.actions.first().arguments as MutableList<String>).clear()
            }
            assertFailsWith<UnsupportedOperationException> {
                @Suppress("UNCHECKED_CAST")
                (registry.canonicalCaptureHeaderCandidatePaths as MutableList<String>) += "generated/forged.h"
            }
            assertFailsWith<UnsupportedOperationException> {
                @Suppress("UNCHECKED_CAST")
                (registry.sourceOnlyUnits as MutableList<FullTreePlanningSourceOnlyUnit>).clear()
            }
            assertFailsWith<UnsupportedOperationException> {
                @Suppress("UNCHECKED_CAST")
                (registry.baseEnvironment as MutableMap<String, String>)["FORGED"] = "1"
            }
            assertFailsWith<UnsupportedOperationException> {
                @Suppress("UNCHECKED_CAST")
                (registry.blockerCodes as MutableList<String>).clear()
            }
            val bytes = registry.canonicalBytes
            bytes[0] = 'x'.code.toByte()
            assertFalse(bytes.contentEquals(registry.canonicalBytes))
            assertFailsWith<FullTreeControlException> {
                registry.requireActionForOwnerModule("cu-00000000000000000000000000000000")
            }
            assertFailsWith<FullTreeControlException> {
                registry.requireActionForOwnerModule("../forged")
            }
            assertFailsWith<IllegalArgumentException> {
                Proxy.newProxyInstance(
                    FullTreeClangCaptureInputRegistry::class.java.classLoader,
                    arrayOf(FullTreeClangCaptureInputRegistry::class.java),
                ) { _, _, _ -> null }
            }
            assertFailsWith<IllegalArgumentException> {
                Proxy.newProxyInstance(
                    FullTreeClangCaptureAction::class.java.classLoader,
                    arrayOf(FullTreeClangCaptureAction::class.java),
                ) { _, _, _ -> null }
            }

            val implementation = Class.forName(
                "decompengine.oracle.fulltree.FullTreeClangCaptureInputControl\$ValidatedCaptureInputRegistry",
            )
            implementation.declaredConstructors.forEach { constructor ->
                assertFalse(constructor.parameterTypes.any { type ->
                    type == ByteArray::class.java ||
                        JsonObject::class.java.isAssignableFrom(type) ||
                        Collection::class.java.isAssignableFrom(type) ||
                        FullTreeClangCaptureInputRegistry::class.java.isAssignableFrom(type) ||
                        FullTreeClangCaptureAction::class.java.isAssignableFrom(type)
                })
            }
            val publicMethods = FullTreeClangCaptureInputControl::class.java.declaredMethods
                .filter { Modifier.isPublic(it.modifiers) }
            assertTrue(publicMethods.any { it.name == "loadAndValidate" })
            assertFalse(publicMethods.any { method ->
                listOf("generate", "publish", "execute", "process", "python", "rewrite")
                    .any { token -> method.name.contains(token, ignoreCase = true) }
            })
            publicMethods.filter { it.name == "loadAndValidate" }.forEach { method ->
                assertTrue(method.parameterTypes.all { type ->
                    type == Path::class.java || type == FullTreeClangCaptureInputLimits::class.java
                })
            }
        }

    @Test
    fun `action coverage argv and output mutations fail closed`(): Unit =
        inControlTemporaryDirectory { directory ->
            val fixture = createCaptureFixture(directory.resolve("commands"))
            val valid = parseControlObject(fixture.captureInput)
            val actions = valid.controlArray("actions").controlObjects("capture actions")

            val variants = listOf(
                JsonArray(actions.dropLast(1)),
                JsonArray(listOf(actions.first(), actions.first())),
                JsonArray(actions.reversed()),
                replaceAction(actions, 0, "workingDirectory", JsonPrimitive("/oracle/other-build")),
                replaceAction(actions, 0, "mainInput", JsonPrimitive(actions[1].controlString("mainInput"))),
                mutateArguments(actions, 0) { values -> values.also { it[0] = "/usr/bin/cc" } },
                mutateArguments(actions, 0) { values -> values.also { it[it.lastIndex] = "@capture.rsp" } },
                mutateArguments(actions, 0) { values -> values.also { it[it.lastIndex] = "--config=capture.cfg" } },
                mutateArguments(actions, 0) { values ->
                    values.also { it.remove("--no-default-config") }
                },
                mutateArguments(actions, 0) { values -> values.also { it.add(1, "-D") } },
                mutateArguments(actions, 0) { values ->
                    values.also { it.add(it.indexOf(actions[0].controlString("mainInput")), "-include") }
                },
                mutateArguments(actions, 0) { values -> values.also { it.add(it.indexOf("-c"), "-D") } },
                mutateArguments(actions, 0) { values -> values.also { it[it.lastIndex] = "-Xclang=@/dev/null" } },
                mutateArguments(actions, 0) { values ->
                    values.also { it[it.lastIndex] = "-Wp,-header-include-file,/outside/evil.json" }
                },
                mutateArguments(actions, 0) { values -> values.also { it[it.lastIndex] = "-cc1" } },
                mutateArguments(actions, 0) { values ->
                    values.also {
                        it += "-fno-integrated-as"
                        it += "-Wa,@/dev/null"
                    }
                },
                mutateArguments(actions, 0) { values ->
                    values.also {
                        it += "-I"
                        it += "/tmp/include"
                    }
                },
                mutateArguments(actions, 0) { values ->
                    values.also {
                        it += "-Xclang=-header-include-file"
                        it += "-Xclang=/outside/evil.json"
                    }
                },
                mutateArguments(actions, 0) { values -> values.also { it[it.indexOf("-MD")] = "-DMD=1" } },
                mutateArguments(actions, 0) { values -> values.also { it[it.indexOf("-MT")] = "-DMT=1" } },
                mutateArguments(actions, 0) { values -> values.also { it[it.indexOf("-MF")] = "-DMF=1" } },
                mutateArguments(actions, 0) { values -> values.also { it[it.indexOf("-o")] = "-oforged.o" } },
                mutateArguments(actions, 0) { values -> values.also { it[it.lastIndex] = "-E" } },
                mutateArguments(actions, 0) { values ->
                    values.also { it[it.lastIndex] = "-header-include-format=json" }
                },
                mutateArguments(actions, 0) { values ->
                    values.also { it[it.lastIndex] = actions[0].controlString("mainInput") }
                },
                mutateArguments(actions, 0) { values ->
                    values.also { it[it.indexOf("-MT") + 1] = "capture/wrong.o" }
                },
                mutateArguments(actions, 0) { values ->
                    values.also {
                        it[it.indexOf("-MT") + 1] = "../escape.o"
                        it[it.indexOf("-MF") + 1] = "../escape.o.d"
                        it[it.indexOf("-o") + 1] = "../escape.o"
                    }
                },
                mutateArguments(actions, 0) { values ->
                    values.also {
                        it[it.lastIndex] = "/oracle/llvm-project-22.1.6.src/clang/tools/Extra/tool.cpp"
                    }
                },
                mutateArguments(actions, 0) { values -> values.also { it[it.lastIndex] = "/tmp/extra.cc" } },
                mutateArguments(actions, 0) { values -> values.also { it[it.lastIndex] = "/tmp/extra.cxx" } },
                mutateArguments(actions, 0) { values -> values.also { it[it.lastIndex] = "/tmp/extra.C" } },
                mutateArguments(actions, 0) { values -> values.also { it[it.lastIndex] = "/tmp/extra.m" } },
                mutateArguments(actions, 0) { values -> values.also { it[it.lastIndex] = "/tmp/extra.mm" } },
                mutateArguments(actions, 0) { values -> values.also { it[it.lastIndex] = "/tmp/extra.i" } },
                mutateArguments(actions, 0) { values -> values.also { it[it.lastIndex] = "/tmp/extra.ii" } },
                mutateArguments(actions, 0) { values -> values.also { it[it.lastIndex] = "/tmp/extra.ll" } },
                mutateArguments(actions, 0) { values -> values.also { it[it.lastIndex] = "/tmp/extra.h" } },
                mutateArguments(actions, 0) { values ->
                    values.also {
                        it += "-xc"
                        it += "/tmp/extensionless"
                    }
                },
                mutateArguments(actions, 0) { values ->
                    values.also { it[it.lastIndex] = actions[1].controlString("mainInput") }
                },
                mutateArguments(actions, 1) { values ->
                    val firstArguments = actions.first().controlArray("arguments")
                        .map { it.controlString("capture argument") }
                    val firstOutput = firstArguments[firstArguments.indexOf("-o") + 1]
                    values.also {
                        it[it.indexOf("-MT") + 1] = firstOutput
                        it[it.indexOf("-MF") + 1] = "$firstOutput.d"
                        it[it.indexOf("-o") + 1] = firstOutput
                    }
                },
            )
            variants.forEachIndexed { index, variant ->
                val path = directory.resolve("invalid-action-$index.json")
                writeControlObject(path, rehashCapture(JsonObject(valid + ("actions" to variant))))
                assertFailsWith<FullTreeControlException>("variant $index was accepted") {
                    loadCapture(fixture, path)
                }
            }

            val appended = mutateArguments(actions, 0) { values -> values.also { it += "-DSECOND=1" } }
            val appendedPath = directory.resolve("too-many-per-action.json")
            writeControlObject(appendedPath, rehashCapture(JsonObject(valid + ("actions" to appended))))
            assertFailsWith<FullTreeControlException> {
                loadCapture(
                    fixture,
                    appendedPath,
                    FullTreeClangCaptureInputLimits(maximumArgumentsPerAction = 11),
                )
            }
        }

    @Test
    fun `schema forgery aliases and every populated capture lowering bound fail closed`(): Unit =
        inControlTemporaryDirectory { directory ->
            val fixture = createCaptureFixture(directory.resolve("bounds"))
            val valid = parseControlObject(fixture.captureInput)
            OracleSchemas.validate("full-tree-clang-capture-input", valid)

            val actions = valid.controlArray("actions").controlObjects("capture actions")
            val expandedAction = JsonObject(actions.first() + ("actionSha256" to JsonPrimitive("f".repeat(64))))
            assertFailsWith<IllegalArgumentException> {
                OracleSchemas.validate(
                    "full-tree-clang-capture-input",
                    JsonObject(valid + ("actions" to JsonArray(listOf(expandedAction) + actions.drop(1)))),
                )
            }
            val forgedAcp = JsonObject(
                valid.controlObject("acpBoundary") + ("captureAuthority" to JsonPrimitive(true)),
            )
            assertFailsWith<IllegalArgumentException> {
                OracleSchemas.validate(
                    "full-tree-clang-capture-input",
                    JsonObject(valid + ("acpBoundary" to forgedAcp)),
                )
            }

            val forgedCommitments = JsonObject(
                valid.controlObject("commitments") + ("actionsSha256" to JsonPrimitive("f".repeat(64))),
            )
            val forgedPath = directory.resolve("forged-commitment.json")
            writeControlObject(
                forgedPath,
                rehashCapture(JsonObject(valid + ("commitments" to forgedCommitments))),
            )
            assertFailsWith<FullTreeControlException> { loadCapture(fixture, forgedPath) }

            val baseVariables = valid.controlObject("environment").controlArray("baseVariables")
                .controlObjects("base environment").toMutableList()
            baseVariables[0] = JsonObject(
                baseVariables.first() + ("value" to JsonPrimitive("prefix\u0000suffix")),
            )
            val nulEnvironment = JsonObject(
                valid.controlObject("environment") + ("baseVariables" to JsonArray(baseVariables)),
            )
            assertFailsWith<IllegalArgumentException> {
                OracleSchemas.validate(
                    "full-tree-clang-capture-input",
                    JsonObject(valid + ("environment" to nulEnvironment)),
                )
            }
            val nulEnvironmentPath = directory.resolve("nul-environment.json")
            writeControlObject(
                nulEnvironmentPath,
                rehashCapture(JsonObject(valid + ("environment" to nulEnvironment))),
            )
            assertFailsWith<FullTreeControlException> { loadCapture(fixture, nulEnvironmentPath) }

            val counts = valid.controlObject("counts")
            val compilerBytes = valid.controlObject("compiler").controlObject("recordedTool")
                .controlLong("executableBytes")
            val paths = captureValidatedPaths(valid)
            val maximumPathBytes = paths.maxOf { it.toByteArray(StandardCharsets.UTF_8).size }
            val maximumComponentBytes = paths.flatMap { it.removePrefix("/").split('/') }
                .maxOf { it.toByteArray(StandardCharsets.UTF_8).size }
            val maximumArgumentBytes = actions.flatMap { action ->
                action.controlArray("arguments").map { it.controlString("capture argument") }
            }.maxOf { it.toByteArray(StandardCharsets.UTF_8).size }

            val lowered = listOf(
                FullTreeClangCaptureInputLimits(maximumActions = 1),
                FullTreeClangCaptureInputLimits(
                    maximumActionPathBytes = counts.controlLong("actionPathBytes") - 1,
                ),
                FullTreeClangCaptureInputLimits(maximumArgumentBytes = maximumArgumentBytes - 1),
                FullTreeClangCaptureInputLimits(maximumBaseEnvironmentVariables = 3),
                FullTreeClangCaptureInputLimits(maximumCanonicalBytes = Files.size(fixture.captureInput).toInt() - 1),
                FullTreeClangCaptureInputLimits(maximumCaptureHeaderCandidates = 1),
                FullTreeClangCaptureInputLimits(maximumCompilerBytes = compilerBytes - 1),
                FullTreeClangCaptureInputLimits(
                    maximumEnvironmentBytes = counts.controlLong("environmentBytes") - 1,
                ),
                FullTreeClangCaptureInputLimits(
                    maximumHeaderPathBytes = fixture.headerPathBytes - 1,
                ),
                FullTreeClangCaptureInputLimits(
                    maximumOutputRecords = counts.controlLong("outputRecords") - 1,
                ),
                FullTreeClangCaptureInputLimits(maximumPathBytes = maximumPathBytes - 1),
                FullTreeClangCaptureInputLimits(maximumPathComponentBytes = maximumComponentBytes - 1),
                FullTreeClangCaptureInputLimits(maximumSourceOnlyUnits = 2),
                FullTreeClangCaptureInputLimits(
                    maximumTotalArgumentBytes = counts.controlLong("argumentBytes") - 1,
                ),
                FullTreeClangCaptureInputLimits(
                    maximumTotalArguments = counts.controlLong("arguments") - 1,
                ),
                FullTreeClangCaptureInputLimits(maximumWorkUnits = counts.controlLong("workUnits") - 1),
            )
            lowered.forEachIndexed { index, limits ->
                assertFailsWith<FullTreeControlException>("lowered bound $index was accepted") {
                    loadCapture(fixture, limits = limits)
                }
            }
            assertFailsWith<IllegalArgumentException> {
                FullTreeClangCaptureInputLimits(maximumArgumentsPerAction = 10)
            }

            assertFailsWith<FullTreeControlException> {
                FullTreeClangCaptureInputControl.loadAndValidate(
                    fixture.readiness,
                    fixture.readiness,
                    fixture.generatedInventory,
                    fixture.generated.control.sourceArchive,
                    fixture.generated.archive,
                    fixture.generated.provenance,
                    fixture.generated.control.scope,
                    fixture.generated.control.sourceLock,
                    fixture.generated.control.manifest,
                    fixture.generated.control.buildRecord,
                    fixture.generated.control.inventory,
                    fixture.generated.control.sourceInventory,
                    fixture.generated.planning,
                )
            }
        }
}

private data class CaptureFixture(
    val generated: GeneratedFixture,
    val readiness: Path,
    val generatedInventory: Path,
    val captureInput: Path,
    val headerPathBytes: Long,
)

private fun createCaptureFixture(root: Path): CaptureFixture {
    Files.createDirectories(root)
    val generatedFixture = createGeneratedFixture(root.resolve("predecessors"))
    val control = generatedFixture.control
    val readinessPath = root.resolve("readiness.json")
    val readiness = FullTreeHeaderPlanReadinessControl.generateAndPublish(
        control.sourceArchive,
        control.scope,
        control.sourceLock,
        control.manifest,
        control.buildRecord,
        control.inventory,
        control.sourceInventory,
        generatedFixture.planning,
        readinessPath,
    )
    val generatedInventoryPath = root.resolve("generated-inventory.json")
    val generated = FullTreeGeneratedFileInventoryControl.generateAndPublish(
        generatedFixture.archive,
        generatedFixture.provenance,
        control.scope,
        control.sourceLock,
        control.manifest,
        control.buildRecord,
        control.inventory,
        control.sourceInventory,
        generatedFixture.planning,
        generatedInventoryPath,
    ).registry
    val captureInput = root.resolve("capture-input.json")
    val document = buildCaptureDocument(
        generatedFixture,
        readinessPath,
        readiness,
        generatedInventoryPath,
        generated,
    )
    writeControlObject(captureInput, document)
    val headerPathBytes = document.controlArray("canonicalCaptureHeaderCandidatePaths")
        .sumOf { it.controlString("capture header").toByteArray(StandardCharsets.UTF_8).size.toLong() }
    return CaptureFixture(
        generatedFixture,
        readinessPath,
        generatedInventoryPath,
        captureInput,
        headerPathBytes,
    )
}

private fun buildCaptureDocument(
    fixture: GeneratedFixture,
    readinessPath: Path,
    readiness: AuthenticatedFullTreeHeaderPlanReadiness,
    generatedInventoryPath: Path,
    generated: FullTreeGeneratedFileRegistry,
): JsonObject {
    val buildRecord = parseControlObject(fixture.control.buildRecord)
    val planning = parseControlObject(fixture.planning)
    val generatedInventory = parseControlObject(generatedInventoryPath)
    val planningOracle = planning.controlObject("oracle")
    val generatedProvenance = generatedInventory.controlObject("provenance")
    val generatedBuildGraph = generatedProvenance.controlObject("buildGraph")
    val directories = buildRecord.controlObject("directories")
    val sourceRoot = directories.controlString("source")
    val buildRoot = directories.controlString("build")
    val installRoot = directories.controlString("install")
    val commands = buildRecord.controlObject("commands")
    val configure = commands.controlArray("configure").map { it.controlString("configure argument") }
    val cDriver = configure.single { it.startsWith("-DCMAKE_C_COMPILER=") }.substringAfter('=')
    val cxxDriver = configure.single { it.startsWith("-DCMAKE_CXX_COMPILER=") }.substringAfter('=')
    val compilerTool = buildRecord.controlArray("tools").controlObjects("tools")
        .single { it.controlString("role") == "compiler" }
    val compilerBinding = captureToolBindingForTest(compilerTool, "compiler")
    val compilerIdentity = TestCaptureCommitment(COMPILER_IDENTITY_DOMAIN)
        .token(canonicalCaptureBytes(compilerBinding)).finish()

    val baseVariables = buildRecord.controlObject("environment").controlObject("variables")
        .entries.map { (name, value) ->
            JsonObject(mapOf("name" to JsonPrimitive(name), "value" to value))
        }.sortedWith(compareBy(FULL_TREE_CODE_POINT_ORDER) { it.controlString("name") })
    val baseVariablesArray = JsonArray(baseVariables)
    val baseEnvironmentSha256 = TestCaptureCommitment(BASE_ENVIRONMENT_DOMAIN)
        .token(canonicalCaptureBytes(baseVariablesArray)).finish()
    val environment = JsonObject(
        mapOf(
            "baseEnvironmentSha256" to JsonPrimitive(baseEnvironmentSha256),
            "baseVariables" to baseVariablesArray,
            "fixedCaptureVariables" to captureSchemaConst("environment", "fixedCaptureVariables"),
            "inheritedEnvironment" to JsonPrimitive("cleared"),
            "perActionHeaderOutput" to captureSchemaConst("environment", "perActionHeaderOutput"),
        ),
    )
    val headers = TreeSet(FULL_TREE_CODE_POINT_ORDER).apply {
        addAll(readiness.authenticatedSourceHeaderCandidatePaths)
        addAll(generated.canonicalGeneratedHeaderPaths)
    }.toList()
    val headerManifestSha256 = TestCaptureCommitment(HEADER_MANIFEST_DOMAIN).apply {
        long(headers.size.toLong())
        headers.forEach { token(it.utf8Bytes()) }
    }.finish()
    val buildRecordSha256 = fixtureSha256(fixture.control.buildRecord)
    val buildDocument = JsonObject(
        mapOf(
            "buildDirectory" to JsonPrimitive(buildRoot),
            "cmakeCacheBytes" to generatedBuildGraph.getValue("cmakeCacheBytes"),
            "cmakeCacheSha256" to generatedBuildGraph.getValue("cmakeCacheSha256"),
            "cmakeTool" to generatedBuildGraph.getValue("cmakeTool"),
            "compileCommandSha256" to JsonPrimitive(
                fullTreeGeneratedCompileCommandSha256(commands.controlArray("compile")),
            ),
            "configureCommandSha256" to JsonPrimitive(
                fullTreeGeneratedConfigureCommandSha256(commands.controlArray("configure")),
            ),
            "containerDigest" to buildRecord.controlObject("environment")
                .controlObject("container").getValue("digest"),
            "containerImage" to buildRecord.controlObject("environment")
                .controlObject("container").getValue("image"),
            "installDirectory" to JsonPrimitive(installRoot),
            "ninjaManifestBytes" to generatedBuildGraph.getValue("ninjaManifestBytes"),
            "ninjaManifestSha256" to generatedBuildGraph.getValue("ninjaManifestSha256"),
            "ninjaTool" to generatedBuildGraph.getValue("ninjaTool"),
            "platform" to buildRecord.controlObject("environment")
                .controlObject("container").getValue("platform"),
            "sourceDateEpoch" to generatedBuildGraph.getValue("sourceDateEpoch"),
            "sourceDirectory" to JsonPrimitive(sourceRoot),
        ),
    )
    val sourceDocument = JsonObject(
        mapOf(
            "archiveSha256" to JsonPrimitive(readiness.sourceArchiveSha256),
            "dependencyArtifactSha256" to JsonPrimitive(readiness.sourceDependencyArtifactSha256),
            "dependencyConfigurationSha256" to JsonPrimitive(readiness.sourceDependencyConfigurationSha256),
            "dependencyReportSha256" to JsonPrimitive(readiness.sourceDependencyReportSha256),
            "headerCandidateManifestSha256" to JsonPrimitive(readiness.sourceHeaderManifestSha256),
            "headerCandidates" to JsonPrimitive(readiness.authenticatedSourceHeaderCandidatePaths.size),
        ),
    )
    val generatedDocumentSummary = JsonObject(
        mapOf(
            "archiveSha256" to JsonPrimitive(generated.archiveSha256),
            "buildGraphProvenanceSha256" to JsonPrimitive(generated.buildGraphProvenanceSha256),
            "canonicalFileManifestSha256" to JsonPrimitive(generated.canonicalGeneratedFileManifestSha256),
            "canonicalHeaderManifestSha256" to JsonPrimitive(
                generated.canonicalGeneratedHeaderManifestSha256,
            ),
            "files" to JsonPrimitive(generated.generatedFiles.size),
            "generationReceiptBound" to JsonPrimitive(false),
            "headers" to JsonPrimitive(generated.generatedHeaders.size),
            "provenanceSha256" to JsonPrimitive(generated.provenanceSha256),
            "snapshotBytesAuthenticated" to JsonPrimitive(false),
            "snapshotBytesIntegrityVerified" to JsonPrimitive(true),
            "translationUnits" to JsonPrimitive(generated.generatedTranslationUnits.size),
        ),
    )
    val compilerDocument = JsonObject(
        mapOf(
            "cDriverPath" to JsonPrimitive(cDriver),
            "cxxDriverIdentityAuthenticated" to JsonPrimitive(false),
            "cxxDriverPath" to JsonPrimitive(cxxDriver),
            "recordedTool" to compilerBinding,
            "recordedToolIdentitySha256" to JsonPrimitive(compilerIdentity),
        ),
    )
    val oracleDocument = JsonObject(
        mapOf(
            "artifactManifestSha256" to planningOracle.getValue("artifactManifestSha256"),
            "buildRecordSha256" to JsonPrimitive(buildRecordSha256),
            "configurationSha256" to JsonPrimitive(FullTreeClangCaptureInputControl.configurationSha256),
            "generatedFileInventoryArtifactBytes" to JsonPrimitive(generated.artifactBytes),
            "generatedFileInventoryArtifactSha256" to JsonPrimitive(generated.artifactSha256),
            "generatedFileInventoryConfigurationSha256" to JsonPrimitive(generated.configurationSha256),
            "generatedFileInventoryReportSha256" to JsonPrimitive(generated.reportSha256),
            "headerPlanReadinessArtifactBytes" to JsonPrimitive(readiness.artifactBytes),
            "headerPlanReadinessArtifactSha256" to JsonPrimitive(readiness.artifactSha256),
            "headerPlanReadinessConfigurationSha256" to JsonPrimitive(readiness.configurationSha256),
            "headerPlanReadinessReportSha256" to JsonPrimitive(readiness.reportSha256),
            "id" to buildRecord.controlObject("oracle").getValue("id"),
            "inventoryArtifactSha256" to planningOracle.getValue("inventoryArtifactSha256"),
            "planningInventoryArtifactSha256" to JsonPrimitive(readiness.planningInventoryArtifactSha256),
            "planningInventoryConfigurationSha256" to JsonPrimitive(
                readiness.planningInventoryConfigurationSha256,
            ),
            "planningInventoryReportSha256" to JsonPrimitive(readiness.planningInventoryReportSha256),
            "scopeSha256" to planningOracle.getValue("scopeSha256"),
            "sourceInventoryArtifactSha256" to planningOracle.getValue("sourceInventoryArtifactSha256"),
            "sourceLockSha256" to planningOracle.getValue("sourceLockSha256"),
        ),
    )
    val captureContextSha256 = TestCaptureCommitment(CONTEXT_DOMAIN).token(
        canonicalCaptureBytes(
            JsonObject(
                mapOf(
                    "build" to buildDocument,
                    "canonicalCaptureHeaderCandidateManifestSha256" to JsonPrimitive(
                        headerManifestSha256,
                    ),
                    "compiler" to compilerDocument,
                    "environment" to environment,
                    "generated" to generatedDocumentSummary,
                    "oracle" to oracleDocument,
                    "source" to sourceDocument,
                ),
            ),
        ),
    ).finish()

    val generatedUnits = generated.generatedTranslationUnits.associateBy { it.unitId }
    val actionRecords = ArrayList<JsonObject>()
    val actionIdentities = ArrayList<String>()
    val actionPathValues = ArrayList<String>()
    var argumentBytes = 0L
    var argumentsCount = 0L
    readiness.sourceModules.forEach { module ->
        val mainInput = when (module.sourceKind) {
            "handwritten" -> "$sourceRoot/${module.sourcePath.removePrefix("source/")}"
            "generated" -> "$buildRoot/${module.sourcePath.removePrefix("generated/")}"
            else -> error("unexpected fixture source kind ${module.sourceKind}")
        }
        val driver = if (module.sourcePath.endsWith(".cpp")) cxxDriver else cDriver
        val objectRaw = "capture/${module.unitId}.o"
        val dependencyRaw = "$objectRaw.d"
        val arguments = listOf(
            driver,
            "--no-default-config",
            "-MD",
            "-MT",
            objectRaw,
            "-MF",
            dependencyRaw,
            "-o",
            objectRaw,
            "-c",
            mainInput,
            "-DTEST_CAPTURE=1",
        )
        val objectOutput = "$buildRoot/$objectRaw"
        val dependencyFile = "$buildRoot/$dependencyRaw"
        val actionIdentity = TestCaptureCommitment(ACTION_DOMAIN).apply {
            token(FullTreeClangCaptureInputControl.configurationSha256.asciiBytes())
            token(captureContextSha256.asciiBytes())
            token(fixtureSha256(fixture.control.buildRecord).asciiBytes())
            token(baseEnvironmentSha256.asciiBytes())
            token(module.moduleId.utf8Bytes())
            token(module.unitId.utf8Bytes())
            token(module.shardId.utf8Bytes())
            token(module.sourceKind.utf8Bytes())
            token(module.sourcePath.utf8Bytes())
            val generatedUnit = generatedUnits[module.unitId]
            if (generatedUnit == null) {
                token("source-archive".asciiBytes())
                token(readiness.sourceArchiveSha256.asciiBytes())
            } else {
                token("generated-file".asciiBytes())
                long(generatedUnit.bytes)
                token(generatedUnit.sha256.asciiBytes())
                token(generatedUnit.generatorActionSha256.asciiBytes())
            }
            token(buildRoot.utf8Bytes())
            token(mainInput.utf8Bytes())
            long(arguments.size.toLong())
            arguments.forEach { token(it.utf8Bytes()) }
            token(objectOutput.utf8Bytes())
            token(dependencyFile.utf8Bytes())
        }.finish()
        actionRecords += JsonObject(
            mapOf(
                "arguments" to JsonArray(arguments.map(::JsonPrimitive)),
                "mainInput" to JsonPrimitive(mainInput),
                "workingDirectory" to JsonPrimitive(buildRoot),
            ),
        )
        actionIdentities += actionIdentity
        argumentsCount += arguments.size
        argumentBytes += arguments.sumOf { it.utf8Bytes().size.toLong() }
        actionPathValues += listOf(buildRoot, mainInput, objectOutput, dependencyFile)
    }
    val actionsSha256 = TestCaptureCommitment(ACTION_MANIFEST_DOMAIN).apply {
        long(actionIdentities.size.toLong())
        actionIdentities.forEach { token(it.asciiBytes()) }
    }.finish()

    val environmentBytes = baseVariables.sumOf { record ->
        record.controlString("name").utf8Bytes().size.toLong() +
            record.controlString("value").utf8Bytes().size.toLong()
    }
    val headerPathBytes = headers.sumOf { it.utf8Bytes().size.toLong() }
    val outputRecords = actionRecords.size.toLong() + headers.size + readiness.sourceOnlyUnits.size +
        baseVariables.size + EXPECTED_BLOCKERS.size
    val workUnits = 64L + 12L * actionRecords.size + 4L * argumentsCount + 3L * headers.size +
        2L * readiness.sourceOnlyUnits.size + 2L * baseVariables.size + 2L * EXPECTED_BLOCKERS.size
    val withoutHash = JsonObject(
        mapOf(
            "acpBoundary" to captureSchemaConst("acpBoundary"),
            "actions" to JsonArray(actionRecords),
            "authority" to captureSchemaConst("authority"),
            "blockerDispositions" to captureSchemaConst("blockerDispositions"),
            "blockers" to captureSchemaConst("blockers"),
            "bounds" to captureSchemaConst("bounds"),
            "build" to buildDocument,
            "canonicalCaptureHeaderCandidatePaths" to JsonArray(headers.map(::JsonPrimitive)),
            "capturePolicy" to captureSchemaConst("capturePolicy"),
            "commitments" to JsonObject(
                mapOf(
                    "actionsSha256" to JsonPrimitive(actionsSha256),
                    "captureContextSha256" to JsonPrimitive(captureContextSha256),
                    "canonicalCaptureHeaderCandidateManifestSha256" to JsonPrimitive(
                        headerManifestSha256,
                    ),
                ),
            ),
            "compiler" to compilerDocument,
            "counts" to JsonObject(
                mapOf(
                    "actionPathBytes" to JsonPrimitive(actionPathValues.sumOf { it.utf8Bytes().size.toLong() }),
                    "actions" to JsonPrimitive(actionRecords.size),
                    "argumentBytes" to JsonPrimitive(argumentBytes),
                    "arguments" to JsonPrimitive(argumentsCount),
                    "baseEnvironmentVariables" to JsonPrimitive(baseVariables.size),
                    "blockers" to JsonPrimitive(EXPECTED_BLOCKERS.size),
                    "captureHeaderCandidates" to JsonPrimitive(headers.size),
                    "environmentBytes" to JsonPrimitive(environmentBytes),
                    "generatedActions" to JsonPrimitive(
                        readiness.sourceModules.count { it.sourceKind == "generated" },
                    ),
                    "generatedHeaderCandidates" to JsonPrimitive(generated.canonicalGeneratedHeaderPaths.size),
                    "handwrittenActions" to JsonPrimitive(
                        readiness.sourceModules.count { it.sourceKind == "handwritten" },
                    ),
                    "headerPathBytes" to JsonPrimitive(headerPathBytes),
                    "outputRecords" to JsonPrimitive(outputRecords),
                    "sourceHeaderCandidates" to JsonPrimitive(
                        readiness.authenticatedSourceHeaderCandidatePaths.size,
                    ),
                    "sourceModules" to JsonPrimitive(readiness.sourceModules.size),
                    "sourceOnlyUnits" to JsonPrimitive(readiness.sourceOnlyUnits.size),
                    "workUnits" to JsonPrimitive(workUnits),
                ),
            ),
            "environment" to environment,
            "generated" to generatedDocumentSummary,
            "kind" to JsonPrimitive("full-tree-clang-capture-input-v1"),
            "oracle" to oracleDocument,
            "schemaVersion" to JsonPrimitive(1),
            "source" to sourceDocument,
        ),
    )
    return rehashCapture(withoutHash)
}

private fun loadCapture(
    fixture: CaptureFixture,
    path: Path = fixture.captureInput,
    limits: FullTreeClangCaptureInputLimits = FullTreeClangCaptureInputLimits(),
): FullTreeClangCaptureInputRegistry = FullTreeClangCaptureInputControl.loadAndValidate(
    path,
    fixture.readiness,
    fixture.generatedInventory,
    fixture.generated.control.sourceArchive,
    fixture.generated.archive,
    fixture.generated.provenance,
    fixture.generated.control.scope,
    fixture.generated.control.sourceLock,
    fixture.generated.control.manifest,
    fixture.generated.control.buildRecord,
    fixture.generated.control.inventory,
    fixture.generated.control.sourceInventory,
    fixture.generated.planning,
    limits,
)

private fun captureToolBindingForTest(tool: JsonObject, role: String): JsonObject = JsonObject(
    mapOf(
        "executableBytes" to tool.getValue("executableBytes"),
        "executableSha256" to tool.getValue("executableSha256"),
        "path" to tool.getValue("path"),
        "role" to JsonPrimitive(role),
        "versionOutputSha256" to JsonPrimitive(
            OracleArtifacts.sha256(tool.controlString("versionOutput").utf8Bytes()),
        ),
    ),
)

private fun captureActionIdentityForTest(
    action: FullTreeClangCaptureAction,
    captureContextSha256: String,
    buildRecordSha256: String,
    baseEnvironmentSha256: String,
    sourceArchiveSha256: String,
): String = TestCaptureCommitment(ACTION_DOMAIN).apply {
    token(FullTreeClangCaptureInputControl.configurationSha256.asciiBytes())
    token(captureContextSha256.asciiBytes())
    token(buildRecordSha256.asciiBytes())
    token(baseEnvironmentSha256.asciiBytes())
    token(action.moduleId.utf8Bytes())
    token(action.unitId.utf8Bytes())
    token(action.shardId.utf8Bytes())
    token(action.sourceKind.utf8Bytes())
    token(action.sourcePath.utf8Bytes())
    token("source-archive".asciiBytes())
    token(sourceArchiveSha256.asciiBytes())
    token(action.workingDirectory.utf8Bytes())
    token(action.mainInput.utf8Bytes())
    long(action.arguments.size.toLong())
    action.arguments.forEach { token(it.utf8Bytes()) }
    token(action.objectOutput.utf8Bytes())
    token(action.dependencyFile.utf8Bytes())
}.finish()

private fun replaceAction(
    actions: List<JsonObject>,
    index: Int,
    field: String,
    value: JsonElement,
): JsonArray = JsonArray(actions.mapIndexed { actionIndex, action ->
    if (actionIndex == index) JsonObject(action + (field to value)) else action
})

private fun mutateArguments(
    actions: List<JsonObject>,
    index: Int,
    mutation: (MutableList<String>) -> Unit,
): JsonArray = JsonArray(actions.mapIndexed { actionIndex, action ->
    if (actionIndex != index) {
        action
    } else {
        val values = action.controlArray("arguments")
            .map { it.controlString("capture argument") }.toMutableList()
        mutation(values)
        JsonObject(action + ("arguments" to JsonArray(values.map(::JsonPrimitive))))
    }
})

private fun rehashCapture(document: JsonObject): JsonObject {
    val withoutHash = JsonObject(document.filterKeys { it != "reportSha256" })
    return JsonObject(
        withoutHash + ("reportSha256" to JsonPrimitive(
            OracleArtifacts.sha256(canonicalCaptureBytes(withoutHash)),
        )),
    )
}

private fun captureSchemaConst(field: String): JsonElement = captureSchemaDocument()
    .controlObject("properties").controlObject(field).getValue("const")

private fun captureSchemaConst(field: String, nestedField: String): JsonElement = captureSchemaDocument()
    .controlObject("properties").controlObject(field)
    .controlObject("properties").controlObject(nestedField).getValue("const")

private fun captureSchemaDocument(): JsonObject {
    val bytes = checkNotNull(
        FullTreeClangCaptureInputControlTest::class.java.classLoader
            .getResourceAsStream("oracle/full-tree-clang-capture-input.schema.json"),
    ).use { it.readAllBytes() }
    val canonical = OracleJson.parseAndCanonicalize(bytes, controlJsonLimits(1024 * 1024))
    return OracleJson.parseCanonical(canonical, controlJsonLimits(1024 * 1024)) as JsonObject
}

private fun captureValidatedPaths(document: JsonObject): List<String> {
    val compiler = document.controlObject("compiler")
    val build = document.controlObject("build")
    val actions = document.controlArray("actions").controlObjects("capture actions")
    return buildList {
        add(compiler.controlString("cDriverPath"))
        add(compiler.controlString("cxxDriverPath"))
        add(compiler.controlObject("recordedTool").controlString("path"))
        add(build.controlString("sourceDirectory"))
        add(build.controlString("buildDirectory"))
        add(build.controlString("installDirectory"))
        document.controlArray("canonicalCaptureHeaderCandidatePaths")
            .forEach { add(it.controlString("capture header")) }
        actions.forEach { action ->
            add(action.controlString("workingDirectory"))
            add(action.controlString("mainInput"))
            action.controlArray("arguments").forEach { argument ->
                val value = argument.controlString("capture argument")
                if (value.startsWith('/')) add(value)
            }
        }
    }
}

private fun canonicalCaptureBytes(value: JsonElement): ByteArray = OracleJson.canonicalBytes(
    value,
    controlJsonLimits(64 * 1024 * 1024),
)

private class TestCaptureCommitment(domain: String) {
    private val digest = MessageDigest.getInstance("SHA-256")

    init {
        token(domain.utf8Bytes())
    }

    fun long(value: Long): TestCaptureCommitment = apply {
        digest.update(ByteBuffer.allocate(Long.SIZE_BYTES).order(ByteOrder.BIG_ENDIAN).putLong(value).array())
    }

    fun token(bytes: ByteArray): TestCaptureCommitment = apply {
        long(bytes.size.toLong())
        digest.update(bytes)
    }

    fun finish(): String = digest.digest().joinToString("") { byte ->
        (byte.toInt() and 0xff).toString(16).padStart(2, '0')
    }
}

private fun String.utf8Bytes(): ByteArray = toByteArray(StandardCharsets.UTF_8)

private fun String.asciiBytes(): ByteArray = toByteArray(StandardCharsets.US_ASCII)

private const val COMPILER_IDENTITY_DOMAIN = "full-tree-clang-capture-compiler-identity-v1"
private const val BASE_ENVIRONMENT_DOMAIN = "full-tree-clang-capture-base-environment-v1"
private const val CONTEXT_DOMAIN = "full-tree-clang-capture-global-context-v1"
private const val ACTION_DOMAIN = "full-tree-clang-capture-action-v2"
private const val ACTION_MANIFEST_DOMAIN = "full-tree-clang-capture-action-manifest-v1"
private const val HEADER_MANIFEST_DOMAIN = "full-tree-clang-capture-header-candidate-manifest-v1"

private val EXPECTED_BLOCKERS = listOf(
    "complete-project-header-inventory-missing",
    "compiler-capture-provenance-missing",
    "compiler-option-arity-unvalidated",
    "generated-generation-receipt-missing",
    "generated-snapshot-completeness-unproven",
    "ninja-live-edge-replay-missing",
    "physical-build-root-unverified",
    "physical-project-roots-unverified",
)
