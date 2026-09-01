package decompengine.oracle.gcc

import decompengine.oracle.core.OracleArtifacts
import decompengine.oracle.core.OracleJson
import java.lang.reflect.InvocationTargetException
import java.lang.reflect.Modifier
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
import kotlinx.serialization.json.boolean
import kotlinx.serialization.json.jsonArray
import kotlinx.serialization.json.jsonObject
import kotlinx.serialization.json.jsonPrimitive

class GccCompilerEngineContainmentContractTest {
    @Test
    fun `definition binds exact command runtime inputs output lease and no START transition`() {
        val mutableArtifacts = artifacts().toMutableList()
        val mutableCommand = command(mutableArtifacts).toMutableList()
        val mutableEnvironment = linkedMapOf("LANG" to "C.UTF-8", "LC_ALL" to "C.UTF-8", "TZ" to "UTC")
        val request = request(mutableArtifacts, mutableCommand, mutableEnvironment)

        mutableArtifacts.clear()
        mutableCommand.clear()
        mutableEnvironment.clear()
        val assessment = GccCompilerEngineContainmentContract.assessDefinition(request)
        val first = assessment.canonicalBytes
        first[0] = '!'.code.toByte()
        val canonical = assessment.canonicalBytes
        val root = OracleJson.parseCanonical(canonical).jsonObject

        assertEquals("non-authoritative-caller-supplied-containment-bytes-v1", assessment.authority)
        assertFalse(assessment.releaseEligible)
        assertFalse(assessment.startAuthorized)
        assertEquals(assessment.bindingSha256, root.getValue("bindingSha256").jsonPrimitive.content)
        assertEquals(assessment.requestSha256, root.getValue("requestSha256").jsonPrimitive.content)
        assertEquals("decomp-gcc-cc1-${assessment.requestSha256.take(32)}.scope", assessment.unitName)
        assertEquals(false, root.getValue("releaseEligible").jsonPrimitive.boolean)
        assertEquals(false, root.getValue("startAuthorized").jsonPrimitive.boolean)
        val containment = root.getValue("containment").jsonObject
        assertEquals(
            listOf("PREPARED", "UNIT_ATTACHED_AT_BOOT", "TERMINAL_ABSENT"),
            containment.getValue("phaseOrder").jsonArray.map { it.jsonPrimitive.content },
        )
        assertFalse(containment.getValue("startTransitionPresent").jsonPrimitive.boolean)
        assertEquals("control-group", containment.getValue("killMode").jsonPrimitive.content)
        assertEquals(
            "sigkill-all-if-exact-retained-target-present",
            containment.getValue("terminalSystemdMutation").jsonPrimitive.content,
        )
        assertEquals("refuse", containment.getValue("replacementMutation").jsonPrimitive.content)
        assertEquals(
            "sigkill-retained-processes",
            containment.getValue("pidfdBackstop").jsonPrimitive.content,
        )
        assertTrue(containment.getValue("requireUnitAbsent").jsonPrimitive.boolean)
        assertTrue(containment.getValue("requireCgroupAbsent").jsonPrimitive.boolean)
        assertTrue(containment.getValue("requireAllReceiptPidfdsDead").jsonPrimitive.boolean)
        assertFalse(canonical.decodeToString().contains("\"START\""))
    }

    @Test
    fun `raw attachment and terminal absence assessments never authorize START or release`() {
        val definition = GccCompilerEngineContainmentContract.assessDefinition(request()).canonicalBytes
        val attached = GccCompilerEngineContainmentContract.renderUnitAttachedAtBootReceiptForTesting(
            definition,
            BOOT_ID,
            INVOCATION_ID,
            listOf(101L, 102L, 103L),
        )
        val attachedAssessment = GccCompilerEngineContainmentContract.assessUnitAttachedAtBoot(
            definition,
            attached,
        )
        assertEquals("non-authoritative-caller-supplied-containment-bytes-v1", attachedAssessment.authority)
        assertFalse(attachedAssessment.releaseEligible)
        assertFalse(attachedAssessment.startAuthorized)

        val absence = GccCompilerEngineContainmentContract.renderTerminalAbsenceReceiptForTesting(
            definition,
            attached,
        )
        val terminal = GccCompilerEngineContainmentContract.assessTerminalAbsence(
            definition,
            attached,
            absence,
        )
        assertEquals(attachedAssessment.bindingSha256, terminal.bindingSha256)
        assertEquals(attachedAssessment.receiptSha256, terminal.attachedReceiptSha256)
        assertEquals("non-authoritative-caller-supplied-containment-bytes-v1", terminal.authority)
        assertFalse(terminal.releaseEligible)
        assertFalse(terminal.startAuthorized)
    }

    @Test
    fun `attachment rejects alternate cgroup parents policy drift and unpinned processes`() {
        val definition = GccCompilerEngineContainmentContract.assessDefinition(request()).canonicalBytes
        val attached = GccCompilerEngineContainmentContract.renderUnitAttachedAtBootReceiptForTesting(
            definition,
            BOOT_ID,
            INVOCATION_ID,
            listOf(201L, 202L, 203L),
        )
        val original = OracleJson.parseCanonical(attached).jsonObject

        val alternateParent = rehash(
            JsonObject(
                original + ("systemd" to JsonObject(
                    original.getValue("systemd").jsonObject +
                        ("controlGroup" to JsonPrimitive("/foreign.slice/${original.getValue("unitName").jsonPrimitive.content}")),
                )) + ("cgroup" to JsonObject(
                    original.getValue("cgroup").jsonObject +
                        ("path" to JsonPrimitive("/sys/fs/cgroup/foreign.slice/${original.getValue("unitName").jsonPrimitive.content}")),
                )),
            ),
            "receiptSha256",
        )
        assertFailsWith<GccCompilerEngineContainmentContractException> {
            GccCompilerEngineContainmentContract.assessUnitAttachedAtBoot(definition, alternateParent)
        }

        val policyDrift = mutateAndRehash(attached, "cgroup", "killMode", JsonPrimitive("process"), "receiptSha256")
        assertFailsWith<GccCompilerEngineContainmentContractException> {
            GccCompilerEngineContainmentContract.assessUnitAttachedAtBoot(definition, policyDrift)
        }

        val processes = original.getValue("processes").jsonArray.toMutableList()
        processes[2] = JsonObject(processes[2].jsonObject + ("pidfdPinned" to JsonPrimitive(false)))
        val unpinned = rehash(JsonObject(original + ("processes" to JsonArray(processes))), "receiptSha256")
        assertFailsWith<GccCompilerEngineContainmentContractException> {
            GccCompilerEngineContainmentContract.assessUnitAttachedAtBoot(definition, unpinned)
        }
    }

    @Test
    fun `terminal assessment binds conditional cleanup policy and every independent absence proof`() {
        val definition = GccCompilerEngineContainmentContract.assessDefinition(request()).canonicalBytes
        val attached = GccCompilerEngineContainmentContract.renderUnitAttachedAtBootReceiptForTesting(
            definition,
            BOOT_ID,
            INVOCATION_ID,
            listOf(301L, 302L, 303L),
        )
        val absence = GccCompilerEngineContainmentContract.renderTerminalAbsenceReceiptForTesting(
            definition,
            attached,
        )
        val mutations = listOf(
            mutateAndRehash(
                absence,
                "cleanupPolicy",
                "systemdMutation",
                JsonPrimitive("sigkill-all"),
                "absenceReceiptSha256",
            ),
            mutateAndRehash(
                absence,
                "cleanupPolicy",
                "replacementAction",
                JsonPrimitive("mutate"),
                "absenceReceiptSha256",
            ),
            mutateAndRehash(
                absence,
                "cleanupPolicy",
                "pidfdBackstop",
                JsonPrimitive("none"),
                "absenceReceiptSha256",
            ),
            mutateAndRehash(absence, "unit", "loadState", JsonPrimitive("loaded"), "absenceReceiptSha256"),
            mutateAndRehash(absence, "cgroup", "pathPresent", JsonPrimitive(true), "absenceReceiptSha256"),
            mutateAndRehash(
                absence,
                "cgroup",
                "sameNameCandidates",
                JsonPrimitive(1),
                "absenceReceiptSha256",
            ),
            rehash(
                OracleJson.parseCanonical(absence).jsonObject.let { root ->
                    val processes = root.getValue("processes").jsonArray.toMutableList()
                    processes[0] = JsonObject(
                        processes[0].jsonObject + ("pidfdAlive" to JsonPrimitive(true)),
                    )
                    JsonObject(root + ("processes" to JsonArray(processes)))
                },
                "absenceReceiptSha256",
            ),
            rehash(
                JsonObject(
                    OracleJson.parseCanonical(absence).jsonObject +
                        ("independentAbsenceSweeps" to JsonPrimitive(1)),
                ),
                "absenceReceiptSha256",
            ),
        )
        mutations.forEach { mutation ->
            assertFailsWith<GccCompilerEngineContainmentContractException> {
                GccCompilerEngineContainmentContract.assessTerminalAbsence(definition, attached, mutation)
            }
        }
    }

    @Test
    fun `definition rejects incomplete identities path overlap and command substitution`() {
        assertFailsWith<IllegalArgumentException> {
            request(artifacts().dropLast(1), command(artifacts()))
        }
        val overlapping = request().let { valid ->
            GccCompilerEngineContainmentArtifactIdentity(
                GccCompilerEngineContainmentArtifactRole.ENGINE_BINARY,
                valid.outputLease.path.resolve("engine"),
                1L,
                SHA_A,
            )
        }
        assertFailsWith<IllegalArgumentException> {
            request(
                artifacts().map { artifact ->
                    if (artifact.role == GccCompilerEngineContainmentArtifactRole.ENGINE_BINARY) overlapping
                    else artifact
                },
            )
        }
        val artifacts = artifacts()
        assertFailsWith<IllegalArgumentException> {
            request(artifacts, listOf("/unbound/analyzeHeadless", "/trusted/engine", "/scratch/run/state", "/scratch/run"))
        }
        assertFailsWith<IllegalArgumentException> {
            GccCompilerEngineAnalysisStateIdentity(
                GccCompilerEngineAnalysisStateMode.RESUME_MANIFEST,
                Path.of("/scratch/run/state"),
                null,
                1,
                1,
            )
        }
    }

    @Test
    fun `run kind and analysis state form an exact closed matrix`() {
        val fresh = GccCompilerEngineAnalysisStateIdentity(
            GccCompilerEngineAnalysisStateMode.FRESH_EMPTY,
            Path.of("/scratch/run/state"),
            null,
            0,
            0,
        )
        val resumed = GccCompilerEngineAnalysisStateIdentity(
            GccCompilerEngineAnalysisStateMode.RESUME_MANIFEST,
            Path.of("/scratch/run/state"),
            SHA_A,
            1,
            1,
        )

        listOf(
            GccCompilerEngineContainmentRunKind.INTERRUPTED to fresh,
            GccCompilerEngineContainmentRunKind.FRESH_CONTROL to fresh,
            GccCompilerEngineContainmentRunKind.RESUMED to resumed,
        ).forEach { (runKind, state) ->
            GccCompilerEngineContainmentContract.assessDefinition(
                request(runKind = runKind, analysisState = state),
            )
        }
        listOf(
            GccCompilerEngineContainmentRunKind.INTERRUPTED to resumed,
            GccCompilerEngineContainmentRunKind.FRESH_CONTROL to resumed,
            GccCompilerEngineContainmentRunKind.RESUMED to fresh,
        ).forEach { (runKind, state) ->
            assertFailsWith<IllegalArgumentException>("$runKind must reject ${state.mode}") {
                request(runKind = runKind, analysisState = state)
            }
        }
    }

    @Test
    fun `JVM shape exposes no production START attach or authority constructor`() {
        assertTrue(
            GccCompilerEnginePlanningService::class.java.declaredConstructors.none {
                Modifier.isPublic(it.modifiers)
            },
        )
        listOf(
            GccCompilerEngineContainmentDefinitionAssessment::class.java,
            GccCompilerEngineUnitAttachedAtBootAssessment::class.java,
            GccCompilerEngineTerminalAbsenceAssessment::class.java,
        ).forEach { type -> assertEquals(0, type.declaredConstructors.size) }
        val implementationTypes = listOf(
            Class.forName("decompengine.oracle.gcc.DefinitionAssessmentImpl"),
            Class.forName("decompengine.oracle.gcc.UnitAttachedAssessmentImpl"),
            Class.forName("decompengine.oracle.gcc.TerminalAbsenceAssessmentImpl"),
        )
        implementationTypes.forEach { type ->
            assertTrue(type.declaredConstructors.isNotEmpty())
            type.declaredConstructors.forEach { constructor ->
                assertTrue(
                    constructor.parameterTypes.all { parameter ->
                        parameter == ByteArray::class.java ||
                            parameter == GccCompilerEngineContainmentRequest::class.java ||
                            parameter.name == "kotlin.jvm.internal.DefaultConstructorMarker"
                    },
                    "${type.name} accepts prevalidated constructor state",
                )
                assertFalse(constructor.parameterTypes.any { it == String::class.java })
            }
        }
        implementationTypes.drop(1).forEach { type ->
            type.declaredConstructors.forEach { constructor ->
                constructor.isAccessible = true
                val arguments = constructor.parameterTypes.map { parameter ->
                    when {
                        parameter == ByteArray::class.java -> "{}".encodeToByteArray()
                        parameter.name == "kotlin.jvm.internal.DefaultConstructorMarker" -> null
                        else -> error("unexpected constructor parameter $parameter")
                    }
                }.toTypedArray()
                val failure = assertFailsWith<InvocationTargetException> {
                    constructor.newInstance(*arguments)
                }
                assertTrue(failure.cause is GccCompilerEngineContainmentContractException)
            }
        }
        val forbidden = setOf("start", "launch", "attach", "adopt", "publish", "release")
        assertTrue(
            GccCompilerEngineContainmentContract::class.java.methods.none { method ->
                method.name.lowercase() in forbidden
            },
        )
        assertTrue(
            GccCompilerEngineUnitAttachedAtBootAssessment::class.java.methods.none { method ->
                method.returnType.name.contains("PlanningResult") || method.name.contains("publish", ignoreCase = true)
            },
        )
    }

    private fun request(
        artifacts: List<GccCompilerEngineContainmentArtifactIdentity> = artifacts(),
        command: List<String> = command(artifacts),
        environment: Map<String, String> =
            mapOf("LANG" to "C.UTF-8", "LC_ALL" to "C.UTF-8", "TZ" to "UTC"),
        runKind: GccCompilerEngineContainmentRunKind = GccCompilerEngineContainmentRunKind.INTERRUPTED,
        analysisState: GccCompilerEngineAnalysisStateIdentity = GccCompilerEngineAnalysisStateIdentity(
            GccCompilerEngineAnalysisStateMode.FRESH_EMPTY,
            Path.of("/scratch/run/state"),
            null,
            0,
            0,
        ),
    ): GccCompilerEngineContainmentRequest = GccCompilerEngineContainmentRequest(
        engineId = "cc1",
        runKind = runKind,
        artifacts = artifacts,
        analysisState = analysisState,
        command = command,
        environment = environment,
        outputLease = GccCompilerEngineOutputLeaseIdentity(
            path = Path.of("/scratch/run"),
            device = 1,
            inode = 2,
            mountId = 3,
            uid = 1000,
            gid = 1000,
            permissions = 0x1c0,
            requiredAvailableBytes = 1024,
            maximumFilesystemBytes = 2048,
            requiredAvailableInodes = 128,
            maximumFilesystemInodes = 256,
        ),
        budgets = GccCompilerEngineContainmentBudgets(
            wallClockMillis = 30L * 60 * 1000,
            maximumResidentBytes = 16L * 1024 * 1024 * 1024,
            pidsMax = 256,
        ),
    )

    private fun artifacts(): List<GccCompilerEngineContainmentArtifactIdentity> =
        GccCompilerEngineContainmentArtifactRole.entries.mapIndexed { index, role ->
            GccCompilerEngineContainmentArtifactIdentity(
                role,
                when (role) {
                    GccCompilerEngineContainmentArtifactRole.ENGINE_BINARY -> Path.of("/trusted/engine")
                    GccCompilerEngineContainmentArtifactRole.GHIDRA_ANALYZE_HEADLESS ->
                        Path.of("/trusted/ghidra/analyzeHeadless")
                    else -> Path.of("/trusted/${role.wireName}")
                },
                (index + 1).toLong(),
                (index + 1).toString(16).padStart(2, '0').repeat(32),
            )
        }

    private fun command(artifacts: List<GccCompilerEngineContainmentArtifactIdentity>): List<String> {
        val byRole = artifacts.associateBy(GccCompilerEngineContainmentArtifactIdentity::role)
        return listOf(
            byRole.getValue(GccCompilerEngineContainmentArtifactRole.GHIDRA_ANALYZE_HEADLESS).path.toString(),
            "/scratch/run/state",
            "-import",
            byRole.getValue(GccCompilerEngineContainmentArtifactRole.ENGINE_BINARY).path.toString(),
            "-scriptPath",
            "/trusted/exporter-classfile",
            "/scratch/run",
        )
    }

    private fun mutateAndRehash(
        bytes: ByteArray,
        objectName: String,
        fieldName: String,
        value: JsonElement,
        hashField: String,
    ): ByteArray {
        val root = OracleJson.parseCanonical(bytes).jsonObject
        val nested = root.getValue(objectName).jsonObject
        return rehash(JsonObject(root + (objectName to JsonObject(nested + (fieldName to value)))), hashField)
    }

    private fun rehash(root: JsonObject, hashField: String): ByteArray {
        val unsigned = JsonObject(root - hashField)
        val digest = OracleArtifacts.sha256(OracleJson.canonicalBytes(unsigned))
        return OracleJson.canonicalBytes(JsonObject(unsigned + (hashField to JsonPrimitive(digest))))
    }

    private companion object {
        const val BOOT_ID = "12345678-1234-1234-1234-123456789abc"
        const val INVOCATION_ID = "12345678123412341234123456789abc"
        const val SHA_A = "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"
    }
}
