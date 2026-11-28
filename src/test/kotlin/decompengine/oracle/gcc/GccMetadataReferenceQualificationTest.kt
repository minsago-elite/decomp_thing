package decompengine.oracle.gcc

import decompengine.oracle.core.OracleArtifacts
import decompengine.oracle.core.OracleJson
import decompengine.oracle.reference.ReferenceCorpusDefinition
import decompengine.oracle.reference.ReferenceCorpusDeployment
import decompengine.oracle.reference.ReferenceNativeRuntimeProvisioningEntry
import java.nio.file.Files
import java.nio.file.Path
import java.nio.file.attribute.PosixFilePermissions
import java.util.Base64
import kotlin.test.Test
import kotlin.test.assertContentEquals
import kotlin.test.assertEquals
import kotlin.test.assertFails
import kotlin.test.assertTrue
import kotlinx.serialization.json.JsonArray
import kotlinx.serialization.json.JsonObject
import kotlinx.serialization.json.JsonPrimitive
import kotlinx.serialization.json.jsonArray
import kotlinx.serialization.json.jsonObject

/** These synthetic JSON values exercise comparison only; no test value is an execution authority. */
class GccMetadataReferenceQualificationTest {
    @Test
    fun `all nineteen raw frozen cases compare without losing binary fields`() {
        val fixture = fixture()
        val result = compare(fixture, fixture.report)
        val expected = OracleJson.canonicalBytes(fixture.report.getValue("cases"))
        assertContentEquals(expected, result.stableCases)
        assertEquals(19, OracleJson.parseCanonical(result.stableCases).jsonArray.size)
        val mutable = result.stableCases
        mutable[0] = 0
        assertContentEquals(expected, result.stableCases)
    }

    @Test
    fun `changed independent fixture bytes refuse comparison even with matching cases`() {
        val fixture = fixture()
        val changed = fixture.frozen.copyOf()
        changed[changed.lastIndex] = 32
        assertFails { GccMetadataReferenceComparison.verify(fixture.definition, changed,
            OracleJson.canonicalBytes(fixture.report), RUNTIME_SHA) }
    }

    @Test
    fun `omitted reordered or duplicate cases cannot satisfy qualification`() {
        val fixture = fixture()
        val cases = fixture.report.getValue("cases").jsonArray
        for (changed in listOf(cases.dropLast(1), cases.reversed(), cases.dropLast(1) + cases[0])) {
            assertFails { compare(fixture, withCases(fixture.report, JsonArray(changed))) }
        }
    }

    @Test
    fun `arguments environment stdin and input identities must remain exact`() {
        val fixture = fixture()
        val attacks = listOf<(JsonObject) -> JsonObject>(
            { JsonObject(it + ("arguments" to JsonArray(listOf(JsonPrimitive("--different"))))) },
            { JsonObject(it + ("environment" to JsonObject(it.getValue("environment").jsonObject + ("PATH" to JsonPrimitive("/host/bin"))))) },
            { JsonObject(it + ("environment" to JsonObject(it.getValue("environment").jsonObject + ("LD_PRELOAD" to JsonPrimitive("/host.so"))))) },
            { JsonObject(it + ("stdin" to blob(byteArrayOf(0, -1)))) },
            { JsonObject(it + ("inputs" to JsonArray(emptyList()))) },
            { JsonObject(it + ("repetitions" to JsonPrimitive(1))) },
            { JsonObject(it + ("unexpected" to JsonPrimitive(true))) },
        )
        for (attack in attacks) {
            val cases = fixture.report.getValue("cases").jsonArray.toMutableList()
            val index = cases.indexOfFirst { it.jsonObject.getValue("inputs").jsonArray.isNotEmpty() }
            cases[index] = attack(cases[index].jsonObject)
            assertFails { compare(fixture, withCases(fixture.report, JsonArray(cases))) }
        }
    }

    @Test
    fun `changed exit streams and artifact membership cannot be normalized away`() {
        val fixture = fixture()
        val attacks = listOf<(JsonObject) -> JsonObject>(
            { JsonObject(it + ("exitCode" to JsonPrimitive(99))) },
            { JsonObject(it + ("stdout" to blob("changed\r\n".toByteArray()))) },
            { JsonObject(it + ("stderr" to blob(byteArrayOf(0, -1)))) },
            { JsonObject(it + ("artifacts" to JsonArray(listOf(JsonObject(blob(byteArrayOf(0, -1)) + ("path" to JsonPrimitive("extra.bin"))))))) },
            { JsonObject(it + ("stdout" to JsonObject(it.getValue("stdout").jsonObject + ("text" to JsonPrimitive("not an authority"))))) },
        )
        for (attack in attacks) {
            val cases = fixture.report.getValue("cases").jsonArray.toMutableList()
            val case = cases[0].jsonObject
            cases[0] = JsonObject(case + ("observed" to attack(case.getValue("observed").jsonObject)))
            assertFails { compare(fixture, withCases(fixture.report, JsonArray(cases))) }
        }
    }

    @Test
    fun `report bindings and scope flags are closed and exact`() {
        val fixture = fixture()
        val attacks = listOf(
            "casesSha256" to JsonPrimitive("f".repeat(64)),
            "profileSha256" to JsonPrimitive("f".repeat(64)),
            "nativeRuntimeSha256" to JsonPrimitive("f".repeat(64)),
            "operationId" to JsonPrimitive("unbound"),
            "candidateQualified" to JsonPrimitive(true),
            "releaseEligible" to JsonPrimitive(true),
            "executionAuthenticated" to JsonPrimitive(false),
            "referenceAuthority" to JsonPrimitive(false),
            "executionSha256ByBatch" to JsonObject(emptyMap()),
            "capturedOutputBytes" to JsonPrimitive(16_777_217),
            "unexpected" to JsonPrimitive(true),
        )
        for ((field, value) in attacks) assertFails { compare(fixture, JsonObject(fixture.report + (field to value))) }
        assertFails { GccMetadataReferenceComparison.verify(fixture.definition, fixture.frozen,
            OracleJson.canonicalBytes(fixture.report) + byteArrayOf(10), RUNTIME_SHA) }
    }

    @Test
    fun `qualification accepts no caller expected fixture or relative path switches`() {
        for (path in listOf("relative", "/", "/a/../b", "/a//b", "/a\nb")) assertFails { qualificationPath(path) }
        assertEquals(Path.of("/fixed/report.json"), qualificationPath("/fixed/report.json"))
        assertFails { GccMetadataReferenceQualificationCli.main(arrayOf("qualify", "--expected-sha256", "f".repeat(64))) }
        assertFails { GccMetadataReferenceQualificationCli.main(arrayOf("verify-report", "/caller/report.json")) }
        assertFails { GccMetadataReferenceInstalledController.open() }
    }

    @Test
    fun `typed provisioning plan handles root separately and rejects indirect descendants`() {
        val root = ReferenceNativeRuntimeProvisioningEntry(".", "directory", 0, 0, 493)
        val directory = ReferenceNativeRuntimeProvisioningEntry("image", "directory", 0, 0, 493)
        val file = ReferenceNativeRuntimeProvisioningEntry("image/file", "regular", 0, 0, 365)
        val (selected, descendants) = GccMetadataReferenceProvisioning.partitionProvisioningEntries(listOf(root, directory, file))
        assertEquals(root, selected)
        assertEquals(listOf(directory, file), descendants)
        assertFails { GccMetadataReferenceProvisioning.partitionProvisioningEntries(listOf(root, root, directory)) }
        assertFails { GccMetadataReferenceProvisioning.partitionProvisioningEntries(listOf(directory, file)) }
        assertFails { GccMetadataReferenceProvisioning.partitionProvisioningEntries(listOf(root.copy(mode = 511), directory)) }
        assertFails { GccMetadataReferenceProvisioning.partitionProvisioningEntries(listOf(root, directory.copy(kind = "symlink"), file)) }
        assertFails { GccMetadataReferenceProvisioning.partitionProvisioningEntries(listOf(root, file)) }
        assertFails { GccMetadataReferenceProvisioning.partitionProvisioningEntries(listOf(root, file.copy(relativePath = "../escape"))) }
    }

    @Test
    fun `installed sidecar predicate rejects nonroot writable multiplelink and indirect authority`() {
        requireRootMetadataSidecarIdentity(0, 420, 1, true, false)
        assertFails { requireRootMetadataSidecarIdentity(1000, 420, 1, true, false) }
        assertFails { requireRootMetadataSidecarIdentity(0, 438, 1, true, false) }
        assertFails { requireRootMetadataSidecarIdentity(0, 420, 2, true, false) }
        assertFails { requireRootMetadataSidecarIdentity(0, 420, 1, false, false) }
        assertFails { requireRootMetadataSidecarIdentity(0, 420, 1, false, true) }
    }

    @Test
    fun `qualification refuses root and binds both session identities to the ordinary controller`() {
        for (uid in listOf(0L, -1L, Int.MAX_VALUE.toLong() + 1)) {
            assertFails { GccMetadataReferenceControllerSession.forUid(uid) }
        }
        val session = GccMetadataReferenceControllerSession.forUid(1001)
        assertEquals(Path.of("/run/user/1001"), session.runtimeDirectory)
        assertEquals("/user.slice/user-1001.slice/user@1001.service/app.slice", session.cgroupParent)
        session.requireDeployment(deploymentForSession(1001, 1001))
        // The former root deployment, and either independently mismatched binding, must fail
        // before the qualifier can enter the production contained-command launcher.
        for ((runtimeUid, cgroupUid) in listOf(0 to 0, 0 to 1001, 1001 to 0, 1002 to 1001, 1001 to 1002)) {
            assertFails { session.requireDeployment(deploymentForSession(runtimeUid, cgroupUid)) }
        }
    }

    @Test
    fun `provisioning accepts only a closed positive controller uid argument`() {
        assertEquals(1001, metadataReferenceControllerUid("1001"))
        assertEquals(Int.MAX_VALUE, metadataReferenceControllerUid(Int.MAX_VALUE.toString()))
        for (value in listOf("0", "-1", "+1", "01", " 1", "1 ", "1\n", "1.0", "2147483648", "99999999999")) {
            assertFails(value) { metadataReferenceControllerUid(value) }
        }
        assertFails { GccMetadataReferenceQualificationCli.main(arrayOf("provision", "/p", "/o", "/r", "/j", "/d")) }
        assertFails { GccMetadataReferenceQualificationCli.main(arrayOf("provision", "/p", "/o", "/r", "/j", "/d", "0")) }
    }

    @Test
    fun `private qualifier state requires the controller owner exact mode and direct path`() {
        val uid = (Files.getAttribute(Path.of("/proc/self"), "unix:uid") as Number).toInt()
        require(uid > 0) { "this fixture exercises the ordinary qualification controller" }
        val parent = Path.of("build/task-tmp/metadata-controller-test").toAbsolutePath().normalize()
        Files.createDirectories(parent)
        val root = Files.createTempDirectory(parent, "private-", PosixFilePermissions.asFileAttribute(PosixFilePermissions.fromString("rwx------")))
        val alias = root.resolveSibling("${root.fileName}-alias")
        try {
            requirePrivateQualificationDirectory(root, uid)
            assertFails { requirePrivateQualificationDirectory(root, 0) }
            assertFails { requirePrivateQualificationDirectory(root, if (uid == 1001) 1002 else 1001) }
            Files.setPosixFilePermissions(root, PosixFilePermissions.fromString("rwx---r-x"))
            assertFails { requirePrivateQualificationDirectory(root, uid) }
            Files.setAttribute(root, "unix:mode", 0x3c0)
            assertFails { requirePrivateQualificationDirectory(root, uid) }
            Files.setPosixFilePermissions(root, PosixFilePermissions.fromString("rwx------"))
            Files.createSymbolicLink(alias, root.fileName)
            assertFails { requirePrivateQualificationDirectory(alias, uid) }
            val untrustedDeployment = Files.write(root.resolve("deployment.json"), byteArrayOf(1, 2, 3))
            Files.setPosixFilePermissions(untrustedDeployment, PosixFilePermissions.fromString("r--------"))
            assertFails { finalizeReadableMetadataDeployment(untrustedDeployment, byteArrayOf(1, 2, 3)) }
            assertEquals(PosixFilePermissions.fromString("r--------"), Files.getPosixFilePermissions(untrustedDeployment))
            assertEquals(PosixFilePermissions.fromString("rwx------"), Files.getPosixFilePermissions(root))
        } finally {
            Files.deleteIfExists(alias)
            Files.walk(root).use { paths -> paths.sorted(Comparator.reverseOrder()).forEach(Files::delete) }
        }
    }

    /** Shape-valid fixture only; no file, process, or installed deployment is authenticated here. */
    private fun deploymentForSession(runtimeUid: Int, cgroupUid: Int): ReferenceCorpusDeployment {
        val digest = JsonPrimitive("a".repeat(64))
        fun mount(name: String) = JsonObject(mapOf("source" to JsonPrimitive("/reference-test/$name"),
            "destination" to JsonPrimitive("/$name"), "expectedManifestSha256" to digest))
        val configuration = JsonObject(mapOf(
            "javaExecutable" to JsonPrimitive("/reference-test/jvm/bin/java"), "javaRuntime" to mount("jvm"),
            "systemLibraryMounts" to JsonArray(listOf(mount("lib"))),
            "bubblewrapExecutable" to JsonPrimitive("/reference-test/bwrap"),
            "resourceLimiterExecutable" to JsonPrimitive("/reference-test/prlimit"),
            "scopeSupervisorExecutable" to JsonPrimitive("/reference-test/systemd-run"),
            "scopeInspectorExecutable" to JsonPrimitive("/reference-test/systemctl"),
            "systemdBusControllerExecutable" to JsonPrimitive("/reference-test/busctl"),
            "systemdUserRuntimeDirectory" to JsonPrimitive("/run/user/$runtimeUid"),
            "workerClassPath" to JsonArray(listOf(JsonObject(mapOf("path" to JsonPrimitive("/reference-test/app.jar"),
                "expectedSha256" to digest)))),
            "expectedJavaSha256" to digest, "expectedBubblewrapSha256" to digest, "expectedResourceLimiterSha256" to digest,
            "expectedScopeSupervisorSha256" to digest, "expectedScopeInspectorSha256" to digest,
            "expectedSystemdBusControllerSha256" to digest))
        return ReferenceCorpusDeployment.parseCanonical(OracleJson.canonicalBytes(JsonObject(mapOf(
            "schemaVersion" to JsonPrimitive("reference-corpus-deployment-v1"), "configuration" to configuration,
            "expectedCgroupParent" to JsonPrimitive("/user.slice/user-$cgroupUid.slice/user@$cgroupUid.service/app.slice")))))
    }

    private fun compare(fixture: Fixture, report: JsonObject) = GccMetadataReferenceComparison.verify(
        fixture.definition, fixture.frozen, OracleJson.canonicalBytes(report), RUNTIME_SHA)

    private fun fixture(): Fixture {
        val root = Path.of("oracle/gcc/16.2.0")
        val frozen = Files.readAllBytes(root.resolve("metadata-diagnostic-reference.json"))
        assertEquals("e2b0af0f212f38fdc2dde56e7803f05e26cd87f2c8c412a2384e478d4cc839fb", OracleArtifacts.sha256(frozen))
        val definition = ReferenceCorpusDefinition.parse(Files.readAllBytes(root.resolve("metadata-reference-profile-v1.json")))
        val expected = OracleJson.parse(frozen).jsonObject.getValue("cases").jsonArray
        val cases = JsonArray(definition.cases.mapIndexed { index, policy ->
            val old = expected[index].jsonObject
            val observed = old.getValue("observed").jsonObject
            assertTrue(observed.getValue("artifacts").jsonArray.isEmpty())
            JsonObject(mapOf("id" to old.getValue("id"), "batchId" to JsonPrimitive(policy.batchId),
                "arguments" to old.getValue("arguments"), "environment" to JsonObject(policy.environment.mapValues { JsonPrimitive(it.value) }),
                "inputs" to old.getValue("inputs"), "stdin" to blob(policy.stdin), "repetitions" to JsonPrimitive(2),
                "observed" to JsonObject(observed + mapOf("stdout" to JsonObject(observed.getValue("stdout").jsonObject - "text"),
                    "stderr" to JsonObject(observed.getValue("stderr").jsonObject - "text")))))
        })
        val report = JsonObject(mapOf("schemaVersion" to JsonPrimitive(1), "provider" to JsonPrimitive("authenticated-reference-corpus-v1"),
            "registrationId" to JsonPrimitive(GccMetadataReferenceProfile.REGISTRATION_ID),
            "profileSha256" to JsonPrimitive(OracleArtifacts.sha256(definition.canonicalBytes)), "nativeRuntimeSha256" to JsonPrimitive(RUNTIME_SHA),
            "operationId" to JsonPrimitive("1".repeat(64)), "intentSha256" to JsonPrimitive("2".repeat(64)),
            "cases" to cases, "casesSha256" to JsonPrimitive(OracleArtifacts.sha256(OracleJson.canonicalBytes(cases))),
            "executionSha256ByBatch" to JsonObject(definition.batches.mapValues { JsonPrimitive("3".repeat(64)) }),
            "workerObservationsSha256ByBatch" to JsonObject(definition.batches.mapValues { JsonPrimitive("4".repeat(64)) }),
            "capturedOutputBytes" to JsonPrimitive(0), "executionAuthenticated" to JsonPrimitive(true), "referenceAuthority" to JsonPrimitive(true),
            "candidateQualified" to JsonPrimitive(false), "releaseEligible" to JsonPrimitive(false),
            "scratchDisposition" to JsonPrimitive("retained-for-trusted-reset"), "operationWallTime" to JsonObject(emptyMap())))
        return Fixture(definition, frozen, report)
    }
    private class Fixture(val definition: ReferenceCorpusDefinition, val frozen: ByteArray, val report: JsonObject)
    private fun withCases(root: JsonObject, cases: JsonArray): JsonObject = JsonObject(root + mapOf("cases" to cases,
        "casesSha256" to JsonPrimitive(OracleArtifacts.sha256(OracleJson.canonicalBytes(cases)))))
    private fun blob(bytes: ByteArray): JsonObject = JsonObject(mapOf("bytes" to JsonPrimitive(bytes.size),
        "sha256" to JsonPrimitive(OracleArtifacts.sha256(bytes)), "base64" to JsonPrimitive(Base64.getEncoder().encodeToString(bytes))))
    private companion object { const val RUNTIME_SHA = "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa" }
}
