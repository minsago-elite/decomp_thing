package decompengine.oracle.reference

import decompengine.oracle.core.OracleArtifacts
import decompengine.oracle.core.OracleJson
import java.nio.file.Files
import java.nio.file.Path
import java.nio.file.attribute.PosixFilePermissions
import java.util.Base64
import kotlin.test.Test
import kotlin.test.assertContentEquals
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

/** Real local processes exercise computation only; this fixture cannot become a registered oracle. */
class ReferenceCorpusWorkerTest {
    @Test
    fun `capture retains binary streams stdin artifacts and actual alternate identity`() = fixture { fixture ->
        val shell = fixture.executable
        val script = """
            printf '%s (fixture)\n' "${'$'}{0##*/}"
            printf 'ARGV0=%s\n' "${'$'}0"
            printf '\000\377payload\n'
            printf 'err\000\376' >&2
            cat > result.bin
            cat input.txt
            test "${'$'}LC_ALL" = C || exit 30
            test "${'$'}TMPDIR" != '' || exit 31
            exit 7
        """.trimIndent()
        val stdin = byteArrayOf(0, 1, 127, -128, -1)
        val input = "fixture input\n".toByteArray()
        val profile = fixture.definition(script, stdin = stdin, input = input, substitutions = listOf(
            substitution("name", shell.fileName.toString(), "^(${Regex.escape(shell.fileName.toString())})(?= \\(fixture\\)$)", "executable-basename"),
            substitution("argv", shell.toString(), "^ARGV0=(${Regex.escape(shell.toString())})$", "executable-argv0"),
        ))
        val request = fixture.request(profile)
        val bytes = ReferenceCorpusWorker.capture(request, profile)
        val checked = ReferenceCorpusWorkerObservations.verify(profile, request, bytes)
        assertFalse(checked.executionAuthenticated)
        assertFalse(checked.referenceAuthority)
        val report = OracleJson.parseCanonical(bytes).jsonObject
        val case = report.getValue("cases").jsonArray.single().jsonObject
        assertEquals(JsonPrimitive(7), case.getValue("observed").jsonObject.getValue("exitCode"))
        val observed = case.getValue("observed").jsonObject
        val expected = ("${shell.fileName} (fixture)\nARGV0=$shell\n").toByteArray() +
            byteArrayOf(0, -1) + "payload\n".toByteArray() + input
        assertContentEquals(expected, blobBytes(observed.getValue("stdout").jsonObject))
        assertContentEquals(byteArrayOf(101, 114, 114, 0, -2), blobBytes(observed.getValue("stderr").jsonObject))
        val artifact = observed.getValue("artifacts").jsonArray.single().jsonObject
        assertEquals(JsonPrimitive("result.bin"), artifact.getValue("path"))
        assertContentEquals(stdin, blobBytes(artifact))
        val invocations = case.getValue("invocations").jsonArray
        assertEquals(3, invocations.size)
        val alternate = invocations[2].jsonObject
        val alias = request.workingRoot.resolve("probe-case-alternate/alternate-probe")
        assertEquals(JsonPrimitive(alias.toString()), alternate.getValue("invokedAs"))
        assertTrue(blobBytes(alternate.getValue("observed").jsonObject.getValue("stdout").jsonObject)
            .toString(Charsets.ISO_8859_1).startsWith("alternate-probe (fixture)\nARGV0=$alias\n"))
        assertTrue(checked.cases.single().keys.none { it == "invocations" })
        val copy = checked.canonicalCasesBytes
        copy[0] = 0
        assertTrue(checked.canonicalCasesBytes[0] != 0.toByte())
        assertFalse(Files.exists(request.outputDirectory.resolve(ReferenceCorpusWorker.OBSERVATIONS_FILE)))
    }

    @Test
    fun `independent verifier rejects tampering with every authority relevant report binding`() = fixture { fixture ->
        val definition = fixture.definition("printf capture; printf error >&2; printf artifact > result.bin")
        val request = fixture.request(definition)
        val report = OracleJson.parseCanonical(ReferenceCorpusWorker.capture(request, definition)).jsonObject
        val attacks = listOf<(JsonObject) -> JsonObject>(
            { JsonObject(it + ("executionAuthenticated" to JsonPrimitive(true))) },
            { JsonObject(it + ("unknown" to JsonPrimitive(false))) },
            { JsonObject(it + ("requestSha256" to JsonPrimitive("f".repeat(64)))) },
            { JsonObject(it + ("operationRequestSha256" to JsonPrimitive("e".repeat(64)))) },
            { JsonObject(it + ("caseIds" to JsonArray(emptyList()))) },
            { JsonObject(it + ("capturedOutputBytes" to JsonPrimitive(1))) },
            { changeCase(it) { case -> JsonObject(case + ("repetitions" to JsonPrimitive(1))) } },
            { changeCase(it) { case -> JsonObject(case + ("invocations" to JsonArray(case.getValue("invocations").jsonArray.take(2)))) } },
            { changeRun(it, 0) { run -> JsonObject(run + ("invokedAs" to JsonPrimitive("/untrusted/program"))) } },
            { changeRun(it, 0) { run -> JsonObject(run + ("effectiveEnvironment" to JsonObject(mapOf("TMPDIR" to JsonPrimitive("/tmp"))))) } },
            { changeRun(it, 0) { run -> changeObserved(run) { observation ->
                val stdout = observation.getValue("stdout").jsonObject
                JsonObject(observation + ("stdout" to JsonObject(stdout + ("sha256" to JsonPrimitive("0".repeat(64))))))
            } } },
            { changeRun(it, 0) { run -> changeObserved(run) { observation ->
                val artifact = observation.getValue("artifacts").jsonArray.single().jsonObject
                JsonObject(observation + ("artifacts" to JsonArray(listOf(JsonObject(artifact + ("path" to JsonPrimitive("../escape")))))))
            } } },
            { changeRun(it, 1) { run -> changeObserved(run) { observation -> JsonObject(observation + ("stdout" to blob("different".toByteArray()))) } } },
            { changeRun(it, 2) { run -> changeObserved(run) { observation -> JsonObject(observation + ("stdout" to blob("different".toByteArray()))) } } },
        )
        attacks.forEachIndexed { index, attack ->
            assertFails("tamper $index must be refused") {
                ReferenceCorpusWorkerObservations.verify(definition, request, OracleJson.canonicalBytes(attack(report)))
            }
        }
    }

    @Test
    fun `nondeterministic observations refuse the whole capture`() = fixture { fixture ->
        val definition = fixture.definition("printf '%s' \"${'$'}${'$'}\"")
        assertFails { ReferenceCorpusWorker.capture(fixture.request(definition), definition) }
    }

    @Test
    fun `bounded stream and aggregate capture refuse excess bytes`() {
        fixture { fixture ->
            val definition = fixture.definition("printf '%01024d' 0", stdoutMaximum = 16)
            assertFails { ReferenceCorpusWorker.capture(fixture.request(definition), definition) }
        }
        fixture { fixture ->
            val definition = fixture.definition("printf 12345678", stdoutMaximum = 16, stderrMaximum = 16, aggregateMaximum = 16)
            assertFails { ReferenceCorpusWorker.capture(fixture.request(definition), definition) }
        }
    }

    @Test
    fun `native deadline refuses a still running process`() = fixture { fixture ->
        val definition = fixture.definition("sleep 10", wallMillis = 1000)
        val start = System.nanoTime()
        assertFails { ReferenceCorpusWorker.capture(fixture.request(definition), definition) }
        assertTrue(System.nanoTime() - start < 5_000_000_000L, "worker deadline must interrupt native capture")
    }

    @Test
    fun `native deadline does not block closing pipes retained by an orphan descendant`() {
        for (terminal in listOf("sleep 0.1; exit 0", "sleep 10")) fixture { fixture ->
            val definition = fixture.definition("exec 3<&0; (sleep 10 <&3 & printf '%s' \"${'$'}!\" > descendant.pid); $terminal",
                stdin = ByteArray(64 * 1024) { 1 }, wallMillis = 1000)
            val request = fixture.request(definition)
            val start = System.nanoTime()
            try {
                val failure = assertFails { ReferenceCorpusWorker.capture(request, definition) }
                assertTrue(generateSequence(failure as Throwable?) { it.cause }.any { it is java.util.concurrent.TimeoutException },
                    "retained pipes must fail at the invocation deadline")
                assertTrue(System.nanoTime() - start < 5_000_000_000L, "stream cleanup must not wait for an orphan pipe owner")
            } finally {
                // This test intentionally has no cgroup authority. Clean up only its exact fixture
                // descendant; production always delegates whole-tree absence to the outer owner.
                listOf("first", "repeat", "alternate").forEach { attempt ->
                    val pidFile = request.workingRoot.resolve("probe-case-$attempt/descendant.pid")
                    if (Files.exists(pidFile)) {
                        ProcessHandle.of(Files.readString(pidFile).toLong()).ifPresent { descendant ->
                            descendant.destroyForcibly()
                            runCatching { descendant.onExit().get(2, java.util.concurrent.TimeUnit.SECONDS) }
                        }
                    }
                }
            }
        }
    }

    @Test
    fun `verifier refuses impossible ordinary file topology and entry counts`() = fixture { fixture ->
        val definition = fixture.definition("printf capture")
        val request = fixture.request(definition)
        val report = OracleJson.parseCanonical(ReferenceCorpusWorker.capture(request, definition)).jsonObject
        val pathCases = listOf(listOf("a", "a/b"), (1..256).map { "f$it" }.sorted(), (1..128).map { "d$it/file" }.sorted())
        for (paths in pathCases) {
            val changed = changeRun(report, 0) { run -> changeObserved(run) { observed ->
                JsonObject(observed + ("artifacts" to JsonArray(paths.map { path -> JsonObject(blob(byteArrayOf(1)) + ("path" to JsonPrimitive(path))) })))
            } }
            val failure = assertFails { ReferenceCorpusWorkerObservations.verify(definition, request, OracleJson.canonicalBytes(changed)) }
            assertTrue(failure.message.orEmpty().let { "topology" in it || "membership" in it })
        }
    }

    @Test
    fun `artifact escape and retained temporary files refuse capture`() {
        fixture { fixture ->
            val definition = fixture.definition("ln -s /etc/passwd escape")
            assertFails { ReferenceCorpusWorker.capture(fixture.request(definition), definition) }
        }
        fixture { fixture ->
            val definition = fixture.definition("printf retained > \"${'$'}TMPDIR/leftover\"")
            assertFails { ReferenceCorpusWorker.capture(fixture.request(definition), definition) }
        }
    }

    @Test
    fun `regular file beyond artifact depth boundary refuses capture`() = fixture { fixture ->
        val directory = (1..16).joinToString("/") { "d$it" }
        val definition = fixture.definition("mkdir -p '$directory'; printf x > '$directory/too-deep'")
        val failure = assertFails { ReferenceCorpusWorker.capture(fixture.request(definition), definition) }
        assertTrue(failure.message.orEmpty().contains("artifact depth"))
    }

    @Test
    fun `worker main refuses its bound request inside writable control root`() = fixture { fixture ->
        val definition = fixture.definition("exit 0")
        val request = fixture.request(definition)
        val requestPath = request.controlRoot.resolve("request.json")
        Files.write(requestPath, request.canonicalBytes)
        val failure = assertFails {
            ReferenceCorpusWorker.main(arrayOf(requestPath.toString(), OracleArtifacts.sha256(request.canonicalBytes)))
        }
        assertTrue(failure.message.orEmpty().contains("inside the writable control root"))
        assertFalse(Files.exists(request.workingRoot), "request rejection must precede native staging")
    }

    @Test
    fun `artifact accounting excludes unchanged inputs even when their size exceeds artifact budget`() = fixture { fixture ->
        val definition = fixture.definition("printf x > result.bin", input = ByteArray(1024) { 42 }, artifactMaximum = 1)
        val request = fixture.request(definition)
        val report = ReferenceCorpusWorker.capture(request, definition)
        assertEquals(3L, ReferenceCorpusWorkerObservations.verify(definition, request, report).capturedOutputBytes)
    }

    @Test
    fun `ambiguous signal shaped status and semantic temporary directory overrides refuse capture`() {
        fixture { fixture ->
            val definition = fixture.definition("exit 137")
            assertFails { ReferenceCorpusWorker.capture(fixture.request(definition), definition) }
        }
        fixture { fixture ->
            val definition = fixture.definition("exit 0", extraEnvironment = mapOf("TMPDIR" to "/tmp"))
            assertFails { ReferenceCorpusWorker.capture(fixture.request(definition), definition) }
        }
    }

    @Test
    fun `batch refuses excluded registered artifact and wrong executable identity`() {
        fixture { fixture ->
            val definition = fixture.definition("exit 0", includeExcludedArtifact = true)
            assertFails { ReferenceCorpusWorker.capture(fixture.request(definition), definition) }
        }
        fixture { fixture ->
            val definition = fixture.definition("exit 0", executableSha256 = "f".repeat(64))
            assertFails { ReferenceCorpusWorker.capture(fixture.request(definition), definition) }
        }
    }

    @Test
    fun `request binding refuses changed profile and writable profile placement`() = fixture { fixture ->
        val definition = fixture.definition("exit 0")
        val request = fixture.request(definition)
        assertContentEquals(request.canonicalBytes, ReferenceCorpusWorkerRequest.parse(request.canonicalBytes).canonicalBytes)
        assertFails { ReferenceCorpusWorkerRequest(request.controlRoot.resolve("profile.json"), request.profileBytes,
            request.profileSha256, request.batchId, request.controlRoot, request.operationRequestSha256) }
        val changed = ReferenceCorpusWorkerRequest(request.profilePath, request.profileBytes, "f".repeat(64), request.batchId,
            request.controlRoot, request.operationRequestSha256)
        assertFails { ReferenceCorpusWorker.capture(changed, definition) }
        val root = OracleJson.parseCanonical(request.canonicalBytes).jsonObject
        assertFails { ReferenceCorpusWorkerRequest.parse(OracleJson.canonicalBytes(JsonObject(root + ("expected" to JsonPrimitive("forbidden"))))) }
    }

    private fun fixture(action: (Fixture) -> Unit) {
        val parent = Path.of(System.getProperty("user.dir")).toRealPath().resolve("build/tmp/reference-worker-tests")
        Files.createDirectories(parent)
        val root = Files.createTempDirectory(parent, "capture-", PRIVATE_DIRECTORY)
        try { action(Fixture(root)) } finally {
            Files.walk(root).use { paths -> paths.sorted(Comparator.reverseOrder()).forEach(Files::delete) }
        }
    }

    private class Fixture(val root: Path) {
        val executable: Path = Path.of("/bin/sh").toRealPath()
        val control: Path = root.resolve("control")
        init {
            Files.createDirectory(control, PRIVATE_DIRECTORY)
            listOf("state", "reports", "tmp").forEach { Files.createDirectory(control.resolve(it), PRIVATE_DIRECTORY) }
        }

        fun request(definition: ReferenceCorpusDefinition) = ReferenceCorpusWorkerRequest(root.resolve("profile.json"),
            definition.canonicalBytes.size, OracleArtifacts.sha256(definition.canonicalBytes), "probe", control, "a".repeat(64))

        fun definition(
            script: String,
            stdin: ByteArray = byteArrayOf(),
            input: ByteArray? = null,
            substitutions: List<JsonObject> = emptyList(),
            stdoutMaximum: Long = 4096,
            stderrMaximum: Long = 4096,
            artifactMaximum: Long = 4096,
            aggregateMaximum: Long = 65536,
            wallMillis: Long = 1000,
            extraEnvironment: Map<String, String> = emptyMap(),
            includeExcludedArtifact: Boolean = false,
            executableSha256: String = OracleArtifacts.sha256(Files.readAllBytes(executable)),
        ): ReferenceCorpusDefinition {
            val cases = mutableListOf(JsonObject(mapOf(
                "id" to JsonPrimitive("probe-case"), "arguments" to JsonArray(listOf(JsonPrimitive("-c"), JsonPrimitive(script))),
                "environment" to JsonObject((mapOf("PATH" to "/usr/bin:/bin", "LC_ALL" to "C") + extraEnvironment).mapValues { JsonPrimitive(it.value) }),
                "inputs" to JsonArray(if (input == null) emptyList() else listOf(JsonObject(blob(input) + ("path" to JsonPrimitive("input.txt"))))),
                "stdin" to blob(stdin), "batchId" to JsonPrimitive("probe"), "categories" to JsonArray(listOf(JsonPrimitive("test-fixture"))),
            )))
            val artifacts = mutableMapOf("executable" to JsonObject(mapOf("guestPath" to JsonPrimitive(executable.toString()),
                "bytes" to JsonPrimitive(Files.size(executable)), "sha256" to JsonPrimitive(executableSha256))))
            val batches = mutableListOf(JsonObject(mapOf("id" to JsonPrimitive("probe"), "artifactRoles" to JsonArray(listOf(JsonPrimitive("executable"))))))
            if (includeExcludedArtifact) {
                val helper = root.resolve("helper")
                Files.write(helper, byteArrayOf(1))
                artifacts["data"] = JsonObject(mapOf("guestPath" to JsonPrimitive(helper.toString()), "bytes" to JsonPrimitive(1),
                    "sha256" to JsonPrimitive(OracleArtifacts.sha256(byteArrayOf(1)))))
                batches += JsonObject(mapOf("id" to JsonPrimitive("with-data"), "artifactRoles" to JsonArray(listOf(JsonPrimitive("executable"), JsonPrimitive("data")))))
                cases += JsonObject(cases.single() + mapOf("id" to JsonPrimitive("data-case"), "batchId" to JsonPrimitive("with-data")))
            }
            val value = JsonObject(mapOf(
                "schemaVersion" to JsonPrimitive(1), "id" to JsonPrimitive("non-authoritative-process-fixture"),
                "imageConfigSha256" to JsonPrimitive("0".repeat(64)), "artifactIdentities" to JsonObject(artifacts),
                "executableRole" to JsonPrimitive("executable"), "batches" to JsonArray(batches),
                "alternateBasename" to JsonPrimitive("alternate-probe"), "cases" to JsonArray(cases),
                "identitySubstitutions" to JsonArray(substitutions), "limits" to JsonObject(mapOf(
                    "wallClockMillisPerInvocation" to JsonPrimitive(wallMillis), "maximumStdoutBytes" to JsonPrimitive(stdoutMaximum),
                    "maximumStderrBytes" to JsonPrimitive(stderrMaximum), "maximumArtifactBytes" to JsonPrimitive(artifactMaximum),
                    "maximumAggregateOutputBytes" to JsonPrimitive(aggregateMaximum),
                )),
            ))
            return ReferenceCorpusDefinition.parse(OracleJson.canonicalBytes(value))
        }
    }

    companion object {
        private val PRIVATE_DIRECTORY = PosixFilePermissions.asFileAttribute(PosixFilePermissions.fromString("rwx------"))
        private fun blob(bytes: ByteArray) = JsonObject(mapOf("bytes" to JsonPrimitive(bytes.size),
            "sha256" to JsonPrimitive(OracleArtifacts.sha256(bytes)), "base64" to JsonPrimitive(Base64.getEncoder().encodeToString(bytes))))
        private fun blobBytes(value: JsonObject): ByteArray = Base64.getDecoder().decode(value.getValue("base64").jsonPrimitive.content)
        private fun substitution(id: String, token: String, pattern: String, binding: String) = JsonObject(mapOf(
            "id" to JsonPrimitive(id), "token" to JsonPrimitive(token), "patterns" to JsonArray(listOf(JsonPrimitive(pattern))),
            "where" to JsonPrimitive("fixture identity line"), "permitted" to JsonPrimitive("exact invoked identity"), "alternateBinding" to JsonPrimitive(binding),
        ))
        private fun changeCase(root: JsonObject, transform: (JsonObject) -> JsonObject): JsonObject =
            JsonObject(root + ("cases" to JsonArray(listOf(transform(root.getValue("cases").jsonArray.single().jsonObject)))))
        private fun changeRun(root: JsonObject, index: Int, transform: (JsonObject) -> JsonObject): JsonObject = changeCase(root) { case ->
            JsonObject(case + ("invocations" to JsonArray(case.getValue("invocations").jsonArray.mapIndexed { ordinal, element ->
                if (ordinal == index) transform(element.jsonObject) else element
            })))
        }
        private fun changeObserved(run: JsonObject, transform: (JsonObject) -> JsonObject): JsonObject =
            JsonObject(run + ("observed" to transform(run.getValue("observed").jsonObject)))
    }
}
