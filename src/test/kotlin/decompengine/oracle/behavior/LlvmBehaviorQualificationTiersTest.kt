package decompengine.oracle.behavior

import decompengine.oracle.core.OracleJson
import java.lang.reflect.InvocationTargetException
import java.lang.reflect.Modifier
import java.nio.file.Files
import java.nio.file.Path
import java.nio.file.attribute.PosixFilePermissions
import kotlin.io.path.readBytes
import kotlin.io.path.readText
import kotlin.io.path.writeBytes
import kotlin.test.Test
import kotlin.test.assertEquals
import kotlin.test.assertFailsWith
import kotlin.test.assertFalse
import kotlin.test.assertTrue
import kotlinx.serialization.json.JsonArray
import kotlinx.serialization.json.JsonElement
import kotlinx.serialization.json.JsonObject
import kotlinx.serialization.json.JsonPrimitive

class LlvmBehaviorQualificationTiersTest {
    @Test
    fun `checked policy binds CI events to a bounded smoke subset and manual events to the full matrix`() {
        val policy = verify(PROFILE.resolve("behavior-qualification-tiers.json"))

        val smoke = policy.tierFor(LlvmBehaviorQualificationEvent.PULL_REQUEST)
        assertEquals(LlvmBehaviorQualificationTierKind.CI_SMOKE, smoke.kind)
        assertEquals(smoke, policy.tierFor(LlvmBehaviorQualificationEvent.PUSH))
        assertFalse(smoke.productionEvidenceEligible)
        assertEquals(1, smoke.repetitions)
        assertEquals(8, smoke.caseIds.size)
        assertTrue(smoke.caseIds.size < policy.corpusCaseIds.size)
        assertTrue(policy.corpusCaseIds.containsAll(smoke.caseIds))
        assertTrue(
            smoke.caseIds.containsAll(
                listOf("metadata-resource-dir", "target-x86-macros", "target-i386-object", "target-unsupported-aarch64"),
            ),
        )
        val worstCase = smoke.caseLimits.getValue("timeoutMilliseconds") * smoke.caseIds.size
        assertTrue(worstCase <= smoke.maximumAggregateWallMilliseconds!!)
        assertTrue(
            smoke.maximumAggregateWallMilliseconds!! <=
                LlvmBehaviorQualificationTierVerifier.MAXIMUM_SMOKE_AGGREGATE_WALL_MILLISECONDS,
        )

        val full = policy.tierFor(LlvmBehaviorQualificationEvent.WORKFLOW_DISPATCH)
        assertEquals(LlvmBehaviorQualificationTierKind.FULL_QUALIFICATION, full.kind)
        assertEquals(full, policy.tierFor(LlvmBehaviorQualificationEvent.SCHEDULE))
        assertTrue(full.productionEvidenceEligible)
        assertEquals(policy.corpusCaseIds, full.caseIds)
        assertEquals(48, full.caseIds.size)
        assertEquals(3, full.repetitions)
        assertEquals(full.caseLimits.keys, smoke.caseLimits.keys)
        smoke.caseLimits.forEach { (key, value) -> assertTrue(value <= full.caseLimits.getValue(key), key) }
    }

    @Test
    fun `run shapes must match the tier their event selects`() {
        val policy = verify(PROFILE.resolve("behavior-qualification-tiers.json"))
        val smokeCases = policy.smoke.caseIds
        val everyCase = policy.corpusCaseIds

        // Policy validation only: a matching declared shape returns nothing and admits no evidence.
        policy.validateRunShape(
            LlvmBehaviorQualificationTierKind.CI_SMOKE,
            LlvmBehaviorQualificationEvent.PULL_REQUEST,
            smokeCases.reversed(),
            1,
        )
        policy.validateRunShape(
            LlvmBehaviorQualificationTierKind.FULL_QUALIFICATION,
            LlvmBehaviorQualificationEvent.WORKFLOW_DISPATCH,
            everyCase,
            3,
        )
        val validateRunShape = LlvmBehaviorQualificationTierPolicy::class.java.methods.single {
            it.name == "validateRunShape"
        }
        assertEquals(Void.TYPE, validateRunShape.returnType)

        val rejected = listOf(
            // CI events cannot claim full qualification, even with the full matrix.
            Triple(LlvmBehaviorQualificationTierKind.FULL_QUALIFICATION, LlvmBehaviorQualificationEvent.PUSH, everyCase to 3),
            Triple(
                LlvmBehaviorQualificationTierKind.FULL_QUALIFICATION,
                LlvmBehaviorQualificationEvent.PULL_REQUEST,
                everyCase to 3,
            ),
            // The event alone selects the tier, even when the run shape matches the requested tier's.
            Triple(LlvmBehaviorQualificationTierKind.FULL_QUALIFICATION, LlvmBehaviorQualificationEvent.PUSH, smokeCases to 1),
            Triple(LlvmBehaviorQualificationTierKind.CI_SMOKE, LlvmBehaviorQualificationEvent.SCHEDULE, everyCase to 3),
            // Manual or periodic production evidence cannot be a smoke run.
            Triple(LlvmBehaviorQualificationTierKind.CI_SMOKE, LlvmBehaviorQualificationEvent.SCHEDULE, smokeCases to 1),
            // Smoke stays bounded: exact case set, exactly one repetition.
            Triple(LlvmBehaviorQualificationTierKind.CI_SMOKE, LlvmBehaviorQualificationEvent.PUSH, everyCase to 1),
            Triple(LlvmBehaviorQualificationTierKind.CI_SMOKE, LlvmBehaviorQualificationEvent.PUSH, smokeCases.drop(1) to 1),
            Triple(LlvmBehaviorQualificationTierKind.CI_SMOKE, LlvmBehaviorQualificationEvent.PUSH, smokeCases to 2),
            Triple(
                LlvmBehaviorQualificationTierKind.CI_SMOKE,
                LlvmBehaviorQualificationEvent.PUSH,
                (smokeCases + smokeCases.first()) to 1,
            ),
            // Full qualification is the complete matrix at three or more clean repetitions.
            Triple(
                LlvmBehaviorQualificationTierKind.FULL_QUALIFICATION,
                LlvmBehaviorQualificationEvent.WORKFLOW_DISPATCH,
                everyCase to 2,
            ),
            Triple(
                LlvmBehaviorQualificationTierKind.FULL_QUALIFICATION,
                LlvmBehaviorQualificationEvent.WORKFLOW_DISPATCH,
                everyCase.drop(1) to 3,
            ),
            Triple(
                LlvmBehaviorQualificationTierKind.FULL_QUALIFICATION,
                LlvmBehaviorQualificationEvent.SCHEDULE,
                smokeCases to 3,
            ),
        )
        rejected.forEach { (kind, event, run) ->
            assertFailsWith<LlvmBehaviorQualificationTierException>("$kind $event ${run.first.size}x${run.second}") {
                policy.validateRunShape(kind, event, run.first, run.second)
            }
        }
        assertFailsWith<LlvmBehaviorQualificationTierException> { LlvmBehaviorQualificationEvent.parse("merge_group") }
    }

    @Test
    fun `tampered policies are rejected`() {
        val mutations: List<Pair<String, (JsonObject) -> JsonObject>> = listOf(
            "smoke claims production" to { root -> root.setSmoke("productionEvidenceEligible", JsonPrimitive(true)) },
            "smoke repeats" to { root -> root.setSmoke("repetitions", JsonPrimitive(3)) },
            "smoke selects every case" to { root -> root.setSmoke("caseIds", strings(corpusCaseIds())) },
            "smoke selects unknown case" to { root ->
                root.setSmoke("caseIds", strings(listOf("compile-file", "forged-case")))
            },
            "smoke selects no case" to { root -> root.setSmoke("caseIds", JsonArray(emptyList())) },
            "smoke case order" to { root ->
                root.setSmoke("caseIds", strings(listOf("metadata-version", "compile-file")))
            },
            "smoke limit above corpus ceiling" to { root ->
                root.setSmoke(
                    "caseLimits",
                    JsonObject(root.smoke()["caseLimits"]!!.jsonObject() + ("memoryBytes" to JsonPrimitive(1073741825L))),
                )
            },
            "smoke limit below executable minimum" to { root -> root.setSmokeLimit("openFiles", 8) },
            "smoke file limit above workspace limit" to { root -> root.setSmokeLimit("workspaceBytes", 8L * 1024 * 1024) },
            "smoke artifact limit above file limit" to { root -> root.setSmokeLimit("fileBytes", 8L * 1024 * 1024) },
            "smoke limit missing" to { root ->
                root.setSmoke("caseLimits", JsonObject(root.smoke()["caseLimits"]!!.jsonObject() - "cpuSeconds"))
            },
            "smoke aggregate below worst case" to { root ->
                root.setSmoke("maximumAggregateWallMilliseconds", JsonPrimitive(79_999))
            },
            "smoke aggregate unbounded" to { root ->
                root.setSmoke("maximumAggregateWallMilliseconds", JsonPrimitive(180_001))
            },
            "smoke on manual event" to { root ->
                root.setSmoke("events", strings(listOf("pull_request", "push", "workflow_dispatch")))
            },
            "full on CI event" to { root -> root.setFull("events", strings(listOf("push", "schedule", "workflow_dispatch"))) },
            "full not production" to { root -> root.setFull("productionEvidenceEligible", JsonPrimitive(false)) },
            "full single run" to { root -> root.setFull("minimumRepetitions", JsonPrimitive(1)) },
            "full two runs" to { root -> root.setFull("minimumRepetitions", JsonPrimitive(2)) },
            "full partial matrix" to { root -> root.setFull("caseSelection", JsonPrimitive("ci-smoke")) },
            "full custom limits" to { root -> root.setFull("caseLimitSource", JsonPrimitive("policy")) },
            "wrong corpus" to { root ->
                JsonObject(
                    root + ("corpus" to JsonObject(root["corpus"]!!.jsonObject() + ("sha256" to JsonPrimitive("0".repeat(64))))),
                )
            },
            "extra tier" to { root ->
                JsonObject(root + ("tiers" to JsonObject(root.tiers() + ("nightly" to root.smoke()))))
            },
            "schema version" to { root -> JsonObject(root + ("schemaVersion" to JsonPrimitive(2))) },
        )
        val checked = OracleJson.parse(PROFILE.resolve("behavior-qualification-tiers.json").readBytes()).jsonObject()
        // The unmodified copy verifies, so each rejection below is caused by its mutation.
        verify(writePolicy("baseline", checked))
        mutations.forEach { (name, mutate) ->
            val path = writePolicy(name.replace(' ', '-'), mutate(checked))
            assertFailsWith<LlvmBehaviorQualificationTierException>(name) { verify(path) }
        }
        val noncanonical = writeRaw("noncanonical", PROFILE.resolve("behavior-qualification-tiers.json").readText().trimEnd().toByteArray())
        assertFailsWith<LlvmBehaviorQualificationTierException> { verify(noncanonical) }
    }

    @Test
    fun `a tighter consistent smoke tier verifies`() {
        val checked = OracleJson.parse(PROFILE.resolve("behavior-qualification-tiers.json").readBytes()).jsonObject()
        val tighter = checked.setSmokeLimit("timeoutMilliseconds", 5_000).setSmokeLimit("memoryBytes", 512L * 1024 * 1024)
        val smoke = verify(writePolicy("tighter", tighter)).smoke
        assertEquals(5_000L, smoke.caseLimits.getValue("timeoutMilliseconds"))
        assertEquals(512L * 1024 * 1024, smoke.caseLimits.getValue("memoryBytes"))
    }

    @Test
    fun `verified policy is immutable and only the verifier constructs it`() {
        val policy = verify(PROFILE.resolve("behavior-qualification-tiers.json"))
        listOf(policy.smoke, policy.full).forEach { tier ->
            @Suppress("UNCHECKED_CAST")
            assertFailsWith<UnsupportedOperationException> { (tier.caseIds as MutableList<String>).add("forged") }
            @Suppress("UNCHECKED_CAST")
            assertFailsWith<UnsupportedOperationException> { (tier.caseIds as MutableList<String>).clear() }
            @Suppress("UNCHECKED_CAST")
            assertFailsWith<UnsupportedOperationException> {
                (tier.events as MutableSet<LlvmBehaviorQualificationEvent>).add(LlvmBehaviorQualificationEvent.SCHEDULE)
            }
            @Suppress("UNCHECKED_CAST")
            assertFailsWith<UnsupportedOperationException> {
                (tier.caseLimits as MutableMap<String, Long>)["timeoutMilliseconds"] = Long.MAX_VALUE
            }
        }
        @Suppress("UNCHECKED_CAST")
        assertFailsWith<UnsupportedOperationException> { (policy.corpusCaseIds as MutableList<String>).removeAt(0) }
        // The smoke tier still selects for both CI events after the attempted tampering.
        assertEquals(LlvmBehaviorQualificationTierKind.CI_SMOKE, policy.tierFor(LlvmBehaviorQualificationEvent.PUSH).kind)
        assertEquals(8, policy.smoke.caseIds.size)
        assertEquals(48, policy.corpusCaseIds.size)

        assertTrue(LlvmBehaviorQualificationTierPolicy::class.java.isInterface)
        assertTrue(LlvmBehaviorQualificationTier::class.java.isInterface)
        listOf(policy.javaClass, policy.smoke.javaClass).forEach { implementation ->
            assertFalse(Modifier.isPublic(implementation.modifiers), implementation.name)
        }
        // The policy implementation accepts only raw paths and authenticated reference evidence, and
        // its constructor re-runs verification, so reflection cannot forge a verified policy.
        val constructor = policy.javaClass.declaredConstructors.single().also { it.isAccessible = true }
        assertEquals(
            listOf(Path::class.java, Path::class.java, LlvmBehaviorReferenceEvidence::class.java),
            constructor.parameterTypes.toList(),
        )
        val checked = OracleJson.parse(PROFILE.resolve("behavior-qualification-tiers.json").readBytes()).jsonObject()
        val forged = writePolicy("reflective-forgery", checked.setSmoke("repetitions", JsonPrimitive(5)))
        val failure = assertFailsWith<InvocationTargetException> {
            constructor.newInstance(forged, PROFILE.resolve("behavior-corpus.json"), reference)
        }
        assertTrue(failure.targetException is LlvmBehaviorQualificationTierException)
        val reconstructed = constructor.newInstance(
            PROFILE.resolve("behavior-qualification-tiers.json"),
            PROFILE.resolve("behavior-corpus.json"),
            reference,
        ) as LlvmBehaviorQualificationTierPolicy
        assertEquals(policy.policySha256, reconstructed.policySha256)
    }

    @Test
    fun `CLI reports the selected tier and refuses a mismatched tier`() {
        val policy = verify(PROFILE.resolve("behavior-qualification-tiers.json"))
        assertTrue(
            LlvmBehaviorQualificationTiersCli.describe(policy, LlvmBehaviorQualificationEvent.PULL_REQUEST)
                .startsWith("pull_request selects ci-smoke: 8 of 48 cases, 1 repetition"),
        )
        assertTrue(
            LlvmBehaviorQualificationTiersCli.describe(policy, LlvmBehaviorQualificationEvent.WORKFLOW_DISPATCH)
                .startsWith("workflow_dispatch selects full-qualification: all 48 corpus cases, at least 3"),
        )
        assertFailsWith<LlvmBehaviorQualificationTierException> {
            LlvmBehaviorQualificationTiersCli.main(arrayOf("--event", "push", "--tier", "full-qualification"))
        }
        assertFailsWith<LlvmBehaviorQualificationTierException> {
            LlvmBehaviorQualificationTiersCli.main(arrayOf("--event", "workflow_dispatch", "--tier", "ci-smoke"))
        }
        LlvmBehaviorQualificationTiersCli.main(arrayOf("--event", "push", "--tier", "ci-smoke"))
    }

    @Test
    fun `CI lane runs the smoke tier gate and is never a manual lane`() {
        val build = Path.of("build.gradle.kts").readText()
        val workflow = Path.of(".github/workflows/llvm-oracle-model.yml").readText()
        assertTrue(build.contains("taskName = \"verifyLlvmBehaviorQualificationTiers\""))
        assertTrue(build.contains("entryPoint = \"decompengine.oracle.behavior.LlvmBehaviorQualificationTiersCli\""))
        val step = "./gradlew --no-daemon verifyLlvmBehaviorQualificationTiers " +
            "--args=\"--event \$QUALIFICATION_EVENT --tier ci-smoke\""
        assertEquals(1, workflow.split(step).size - 1)
        assertTrue(workflow.contains("QUALIFICATION_EVENT: \${{ github.event_name }}"))
        val lane = workflow.substringAfter("  provenance-artifacts-and-ground-truth:\n").substringBefore("\n  llvm-required-contract:")
        assertTrue(lane.startsWith("    if: github.event_name != 'workflow_dispatch'\n"))
        assertTrue(lane.contains(step))
        val allowlist = lane.substringAfter("case \"\$QUALIFICATION_EVENT\" in\n").substringBefore("esac")
        assertTrue(allowlist.contains("push|pull_request) ;;"))
        assertTrue(allowlist.contains("*) echo"))
        assertTrue(lane.indexOf("push|pull_request) ;;") < lane.indexOf(step))
    }

    private fun verify(policyPath: Path): LlvmBehaviorQualificationTierPolicy =
        LlvmBehaviorQualificationTierVerifier.verify(policyPath, PROFILE.resolve("behavior-corpus.json"), reference)

    private fun writePolicy(name: String, root: JsonObject): Path = writeRaw(name, OracleJson.canonicalBytes(root))

    private fun writeRaw(name: String, bytes: ByteArray): Path {
        val directory = Files.createTempDirectory(
            "qualification-tiers-",
            PosixFilePermissions.asFileAttribute(PosixFilePermissions.fromString("rwx------")),
        )
        return directory.resolve("$name.json").also { it.writeBytes(bytes) }
    }

    private fun corpusCaseIds(): List<String> = reference.caseIds

    private companion object {
        val PROFILE: Path = Path.of("oracle/llvm/22.1.6").toAbsolutePath().normalize()
        val reference: LlvmBehaviorReferenceEvidence by lazy {
            LlvmBehaviorReferenceEvidenceVerifier.verify(
                corpusPath = PROFILE.resolve("behavior-corpus.json"),
                reportPath = PROFILE.resolve("behavior-corpus-evidence.json"),
                diagnosticMatrixPath = PROFILE.resolve("diagnostic-matrix.json"),
                artifactManifestPath = PROFILE.resolve("oracle-manifest.json"),
            )
        }
    }
}

private fun JsonElement.jsonObject(): JsonObject = this as JsonObject

private fun JsonObject.tiers(): JsonObject = this["tiers"]!!.jsonObject()

private fun JsonObject.smoke(): JsonObject = tiers()["ci-smoke"]!!.jsonObject()

private fun JsonObject.setTier(tier: String, key: String, value: JsonElement): JsonObject =
    JsonObject(this + ("tiers" to JsonObject(tiers() + (tier to JsonObject(tiers()[tier]!!.jsonObject() + (key to value))))))

private fun JsonObject.setSmoke(key: String, value: JsonElement) = setTier("ci-smoke", key, value)

private fun JsonObject.setSmokeLimit(key: String, value: Long): JsonObject =
    setSmoke("caseLimits", JsonObject(smoke()["caseLimits"]!!.jsonObject() + (key to JsonPrimitive(value))))

private fun JsonObject.setFull(key: String, value: JsonElement) = setTier("full-qualification", key, value)

private fun strings(values: List<String>) = JsonArray(values.map(::JsonPrimitive))
