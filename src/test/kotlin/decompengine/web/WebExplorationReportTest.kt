package decompengine.web

import kotlinx.serialization.json.*
import kotlin.test.*

class WebExplorationReportTest {
    private val valid = """{"candidateCount":1,"coverageIncreased":true,"baselineOutputSignatures":0,"expandedOutputSignatures":1,"newOutputSignatures":["sample"],"angr":null,"confidence":{"score":0.5,"inputCount":18446744073709551615,"sourceCount":1,"outputSignatureCount":1,"newOutputSignatureCount":1,"sandboxed":true,"networkIsolated":false},"candidates":[{}],"observations":[]}"""
    private fun report(text: String?) = webExplorationReport("a".repeat(32), "run_1", text?.toByteArray())
    @Test fun `known summary retains exact counts with observations authority and no acceptance`() {
        val result = report(valid)
        assertEquals("available", result.getValue("state").jsonPrimitive.content)
        assertEquals("18446744073709551615", result.getValue("summary").jsonObject.getValue("confidence").jsonObject.getValue("inputCount").jsonPrimitive.content)
        assertEquals("observations", result.getValue("authority").jsonPrimitive.content)
        assertEquals("not-evaluated", result.getValue("acceptance").jsonPrimitive.content)
        assertEquals("raw-evidence", result.getValue("sourceArtifact").jsonObject.getValue("role").jsonPrimitive.content)
        assertEquals(result, report(valid))
        assertNotEquals(result.getValue("reportId"), report(valid.replace("0.5", "0.4")).getValue("reportId"))
    }

    @Test fun `version one available payload keeps its exact serialized envelope`() {
        val jobId = "a".repeat(32)
        val digest = "f27b046267380691935cf4d19e40ba0a220991be7df1134caaea873887679d61"
        val artifactId = "exploration_22310e3ca71dbaace90d40ed264025a4_$digest"
        val expected = """{"reportId":"exploration_f27b046267380691935cf4d19e40ba0a","binding":{"jobId":"$jobId","runId":"run_1","revisionId":null},"reportType":"exploration","adapterVersion":1,"producerSchemaVersion":null,"state":"available","authority":"observations","sourceArtifact":{"artifactId":"$artifactId","binding":{"jobId":"$jobId","runId":"run_1","revisionId":null},"displayName":"exploration.json","mediaType":"application/json","sizeBytes":"355","sha256":"$digest","contentHref":"/api/v1/jobs/$jobId/artifacts/$artifactId/content","role":"raw-evidence","derivedFromArtifactId":null,"content":{"projection":"redacted"}},"acceptance":"not-evaluated","acceptanceArtifactId":null,"limitations":["Observed sample breadth and producer-reported isolation are not proof of equivalence or independent containment verification."],"summary":{"candidateCount":"1","expandedOutputSignatures":"1","confidence":{"score":0.5,"inputCount":"18446744073709551615","sourceCount":"1","outputSignatureCount":"1","newOutputSignatureCount":"1","sandboxed":true,"networkIsolated":false}},"validationCases":null,"validationFailure":null}"""
        assertEquals(expected, report(valid).toString())
    }

    @Test fun `versioned retained input report is available without granting acceptance authority`() {
        val fields = Json.parseToJsonElement(valid).jsonObject.toMutableMap()
        fields["schema"] = JsonPrimitive("decomp-exploration")
        fields["schemaVersion"] = JsonPrimitive(2)
        fields["state"] = JsonPrimitive("complete")
        fields["candidates"] = buildJsonArray {
            add(buildJsonObject {
                put("id", "candidate_case")
                put("source", "SEED")
                put("args", buildJsonArray { })
                put("stdinHex", "")
            })
        }
        fields["retainedInputs"] = buildJsonArray {
            add(buildJsonObject {
                put("id", "retained_case")
                put("args", buildJsonArray { add(JsonPrimitive("argument")) })
                put("stdinHex", "00ff")
            })
        }
        fields["retainedInputsOmitted"] = JsonPrimitive(0)
        val value = JsonObject(fields).toString()
        val result = report(value)
        assertEquals("available", result.getValue("state").jsonPrimitive.content)
        assertEquals(2, result.getValue("producerSchemaVersion").jsonPrimitive.int)
        assertEquals("not-evaluated", result.getValue("acceptance").jsonPrimitive.content)
        assertEquals(JsonNull, result.getValue("acceptanceArtifactId"))

        for (bad in listOf(value.replace("retained_case", ""), value.replace("00ff", "not-hex"),
            value.replace("\"retainedInputsOmitted\":0", "\"retainedInputsOmitted\":-1"))) {
            assertEquals("invalid", report(bad).getValue("state").jsonPrimitive.content)
        }
    }
    @Test fun `missing partial malformed future and invalid numeric values do not invent summaries`() {
        for ((bytes, state) in listOf(null to "unknown", "{}" to "partial", "{" to "invalid", "{\"schemaVersion\":2}" to "unsupported",
            valid.replace("0.5", "2.0") to "invalid", valid.replace("\"candidateCount\":1", "\"candidateCount\":2") to "invalid",
            valid.replace("18446744073709551615", "18446744073709551616") to "invalid", valid.replace("\"score\":0.5", "\"score\":0.5,\"score\":0.6") to "invalid")) {
            val result = report(bytes)
            assertEquals(state, result.getValue("state").jsonPrimitive.content)
            assertEquals(JsonNull, result.getValue("summary"))
        }
    }

    @Test fun `version two is recognized by schema and version before its state value`() {
        val v2 = """{"schema":"decomp-exploration","schemaVersion":2"""
        for ((text, expected, version) in listOf(
            Triple("$v2}", "partial", 2),
            Triple("$v2,\"candidateCount\":1}", "partial", 2),
            // `invalid` is not evidence of any producer version, so it never reports one.
            Triple("$v2,\"state\":7}", "invalid", null),
            Triple("$v2,\"state\":\"partial\"}", "invalid", null),
            Triple("$v2,\"state\":\"complete\"}", "invalid", null),
            Triple("$v2,\"candidateCount\":\"1\"}", "invalid", null),
            Triple("$v2,\"unexpected\":1}", "invalid", null),
            Triple("""{"schema":"decomp-exploration","schemaVersion":"2"}""", "invalid", null),
            Triple("""{"schema":2,"schemaVersion":2}""", "invalid", null),
            Triple("""{"confidence":[]}""", "invalid", null),
            Triple("""{"candidateCount":"1"}""", "invalid", null),
            Triple("""{"confidence":{"score":0.5}}""", "partial", null),
        )) {
            val result = report(text)
            assertEquals(expected, result.getValue("state").jsonPrimitive.content, text)
            assertEquals(version, result.getValue("producerSchemaVersion").jsonPrimitive.intOrNull, text)
            assertEquals(JsonNull, result.getValue("summary"), text)
        }
        assertEquals("Required producer fields are absent; no summary is inferred.",
            report("$v2}").getValue("limitations").jsonArray.single().jsonPrimitive.content)
    }

    @Test fun `legacy presentation rows come from the redacted projection while the classification uses the original bytes`() {
        val marker = "configured-exploration-credential-7f3a91"
        val policy = WebRedactionPolicy.create(emptyMap(), listOf(marker), emptyList())
        val text = valid.replace("\"candidates\":[{}]", "\"candidates\":[{\"id\":\"one\",\"args\":[\"$marker\"]}]")
        val presented = captureWebExplorationPresentation(policy) { text.toByteArray() }
        assertEquals("available", presented.state)
        assertTrue(presented.downloadAvailable)
        val row = assertNotNull(presented.rows).single()
        assertEquals("one", row.candidate?.getValue("id")?.jsonPrimitive?.content)
        assertTrue(marker !in presented.rows.toString())
        assertTrue(marker !in presented.toString())
        for (bytes in listOf("{".toByteArray(), byteArrayOf(0xff.toByte()))) {
            val withheld = captureWebExplorationPresentation(policy) { bytes }
            assertEquals("invalid", withheld.state)
            assertTrue(withheld.bytesCaptured && !withheld.downloadAvailable && withheld.rows == null)
        }
        val unavailable = captureWebExplorationPresentation(policy) { throw IllegalStateException("read unavailable") }
        assertEquals("unknown", unavailable.state)
        assertTrue(!unavailable.bytesCaptured && !unavailable.downloadAvailable)
    }

    @Test fun `every captured nonavailable state retains exact raw byte provenance without numeric fallback`() {
        for ((saved, expectedState) in listOf("{}" to "partial", "{" to "invalid",
            "{\"schemaVersion\":999}" to "unsupported")) {
            val bytes = saved.toByteArray(Charsets.UTF_8)
            val result = report(saved)
            assertEquals(expectedState, result.getValue("state").jsonPrimitive.content)
            assertEquals(JsonNull, result.getValue("summary"))
            val artifact = result.getValue("sourceArtifact").jsonObject
            assertEquals(bytes.size.toString(), artifact.getValue("sizeBytes").jsonPrimitive.content)
            val digest = java.security.MessageDigest.getInstance("SHA-256").digest(bytes)
                .joinToString("") { "%02x".format(it.toInt() and 255) }
            assertEquals(digest, artifact.getValue("sha256").jsonPrimitive.content)
            assertEquals("raw-evidence", artifact.getValue("role").jsonPrimitive.content)
            assertEquals("not-evaluated", result.getValue("acceptance").jsonPrimitive.content)
            assertEquals(JsonNull, result.getValue("acceptanceArtifactId"))
        }
        val missing = report(null)
        assertEquals("unknown", missing.getValue("state").jsonPrimitive.content)
        assertEquals(JsonNull, missing.getValue("sourceArtifact"))
    }

    @Test fun `legacy capture reads once and distinguishes unavailable bytes from malformed captures`() {
        var reads = 0
        val captured = captureWebExploration {
            reads++
            "{".toByteArray()
        }
        assertEquals(1, reads)
        assertEquals("invalid", captured.state)
        val unavailable = captureWebExploration { throw IllegalStateException("read unavailable") }
        assertEquals("unknown", unavailable.state)
        assertEquals(false, unavailable.bytesCaptured)
    }

    private fun versioned(fields: Map<String, JsonElement> = emptyMap(), omit: Set<String> = emptySet()): String {
        val root = Json.parseToJsonElement(valid).jsonObject.toMutableMap()
        root["schema"] = JsonPrimitive("decomp-exploration"); root["schemaVersion"] = JsonPrimitive(2)
        root["state"] = JsonPrimitive("complete")
        root["candidates"] = Json.parseToJsonElement("""[{"id":"candidate_case","source":"SEED","args":[],"stdinHex":""}]""")
        root["retainedInputs"] = Json.parseToJsonElement("""[{"id":"retained_case","args":["argument"],"stdinHex":"00ff"}]""")
        root["retainedInputsOmitted"] = JsonPrimitive(0)
        root.putAll(fields)
        omit.forEach(root::remove)
        return JsonObject(root).toString()
    }

    @Test fun `version two field types are checked identically in complete and partial reports`() {
        assertEquals("available", report(versioned()).getValue("state").jsonPrimitive.content)
        assertEquals("partial", report(versioned(omit = setOf("state", "observations"))).getValue("state").jsonPrimitive.content)
        assertEquals(2, report(versioned(omit = setOf("state", "observations"))).getValue("producerSchemaVersion").jsonPrimitive.int)
        val angrDiagnostics = Json.parseToJsonElement("""{"argvStates":1,"stdinStates":0,"argvSteps":2,"stdinSteps":0}""")
        assertEquals("available", report(versioned(mapOf("angr" to angrDiagnostics))).getValue("state").jsonPrimitive.content)
        val mistyped = listOf(
            mapOf("angr" to JsonPrimitive(false)),
            mapOf("angr" to JsonPrimitive("null")),
            mapOf("retainedInputs" to Json.parseToJsonElement("""[{"id":7,"args":[],"stdinHex":""}]""")),
            mapOf("retainedInputs" to Json.parseToJsonElement("""[{"id":"retained_case","args":[],"stdinHex":12}]""")),
            mapOf("candidates" to Json.parseToJsonElement("""[{"id":7,"source":"SEED","args":[],"stdinHex":""}]""")),
        )
        for (fields in mistyped) {
            // Complete: every field present. Partial: no `state`, one field absent, same mistyped value.
            for (text in listOf(versioned(fields), versioned(fields, omit = setOf("state", "observations")))) {
                assertTrue(text.contains("\"schemaVersion\":2"), text)
                val result = report(text)
                assertEquals("invalid", result.getValue("state").jsonPrimitive.content, text)
                assertEquals(JsonNull, result.getValue("producerSchemaVersion"), text)
                assertEquals(JsonNull, result.getValue("summary"), text)
            }
        }
        // The legacy shape shares the same producer types.
        assertEquals("invalid", report(valid.replace("\"angr\":null", "\"angr\":false")).getValue("state").jsonPrimitive.content)
        assertEquals("invalid", report("""{"angr":false}""").getValue("state").jsonPrimitive.content)
    }

    /** Applies one corpus patch: a path of object keys and array indexes, then a replacement value or a deletion. */
    private fun patch(element: JsonElement, path: List<JsonElement>, value: JsonElement?): JsonElement {
        val rest = path.drop(1)
        fun child(current: JsonElement?): JsonElement? = if (rest.isEmpty()) value else patch(requireNotNull(current), rest, value)
        return when (element) {
            is JsonObject -> {
                val name = path.first().jsonPrimitive.content
                JsonObject(element.toMutableMap().also { fields -> child(fields[name])?.let { fields[name] = it } ?: fields.remove(name) })
            }
            is JsonArray -> {
                val index = path.first().jsonPrimitive.int
                JsonArray(element.toMutableList().also { items -> items[index] = requireNotNull(child(items[index])) })
            }
            else -> error("corpus path does not address a container")
        }
    }

    @Test fun `version two rows match the producer types the SPA retained-case reader requires`() {
        // The same corpus drives `exploration-cases.test.tsx`, which requires the SPA to accept exactly the
        // complete reports classified `available` here.
        val corpus = Json.parseToJsonElement(requireNotNull(javaClass.getResource("/web/exploration-v2-agreement.json")).readText()).jsonObject
        val cases = corpus.getValue("cases").jsonArray
        assertTrue(cases.size >= 30)
        val expectedStates = mutableSetOf<String>()
        for (case in cases.map { it.jsonObject }) {
            val name = case.getValue("name").jsonPrimitive.content
            var root: JsonElement = corpus.getValue("base")
            for (item in case.getValue("patches").jsonArray.map { it.jsonObject }) {
                val delete = item["delete"]?.jsonPrimitive?.boolean == true
                root = patch(root, item.getValue("path").jsonArray, if (delete) null else item.getValue("value"))
            }
            val complete = root.toString()
            val partial = JsonObject(root.jsonObject - "state").toString()
            for ((text, key) in listOf(complete to "complete", partial to "partial")) {
                val expected = case.getValue(key).jsonPrimitive.content
                expectedStates += expected
                val result = report(text)
                assertEquals(expected, result.getValue("state").jsonPrimitive.content, "$name ($key)")
                assertEquals(if (expected == "invalid") null else 2, result.getValue("producerSchemaVersion").jsonPrimitive.intOrNull, "$name ($key)")
            }
        }
        assertEquals(setOf("available", "partial", "invalid"), expectedStates)
    }

    @Test fun `available reports are always projectable for depth so rows are never silently empty`() {
        val policy = WebRedactionPolicy.create(emptyMap(), emptyList(), emptyList())
        val states = (WebReportProjection.MAXIMUM_REPORT_DEPTH - 3..WebReportProjection.MAXIMUM_REPORT_DEPTH + 3).map { levels ->
            val nested = "{\"a\":".repeat(levels) + "null" + "}".repeat(levels)
            val text = valid.replace("\"angr\":null", "\"angr\":$nested")
            val presented = presentWebExploration(policy, text.toByteArray())
            if (presented.state == "available") {
                assertTrue(presented.downloadAvailable && presented.rows != null, "depth $levels")
            } else {
                assertEquals("invalid", presented.state, "depth $levels")
                assertEquals("invalid", report(text).getValue("state").jsonPrimitive.content, "depth $levels")
            }
            presented.state
        }
        assertTrue("available" in states && "invalid" in states, states.toString())
    }

    @Test fun `an available report the projection cannot supply keeps its validated metrics and withholds rows`() {
        val first = "configured-collision-credential-1a2b3c"
        val second = "configured-collision-credential-4d5e6f"
        val policy = WebRedactionPolicy.create(emptyMap(), listOf(first, second), emptyList())
        // Two distinct legacy extension keys redact to one public key, so the projection withholds the whole object.
        val text = valid.replace("\"baselineOutputSignatures\":0", "\"baselineOutputSignatures\":18446744073709551615")
            .replace("{\"candidateCount\"", "{\"x-$first\":1,\"x-$second\":2,\"candidateCount\"")
        assertEquals("[redacted]", Json.parseToJsonElement(WebReportProjection.project(false, text.toByteArray(), policy).decodeToString()).jsonPrimitive.content)
        val presented = presentWebExploration(policy, text.toByteArray())
        assertEquals("available", presented.state)
        assertNull(presented.rows)
        assertEquals(1, presented.candidateTotal)
        assertEquals("18446744073709551615", presented.baselineOutputSignatures)
        assertEquals("1", presented.summary?.getValue("candidateCount")?.jsonPrimitive?.content)
    }

    @Test fun `observations are paired by original identifiers even when distinct identifiers redact alike`() {
        val first = "configured-attribution-credential-1a2b3c"
        val second = "configured-attribution-credential-4d5e6f"
        val policy = WebRedactionPolicy.create(emptyMap(), listOf(first, second), emptyList())
        fun presented(candidates: String, observations: String, count: Int) = presentWebExploration(policy,
            valid.replace("\"candidateCount\":1", "\"candidateCount\":$count").replace("\"candidates\":[{}]", "\"candidates\":$candidates")
                .replace("\"observations\":[]", "\"observations\":$observations").toByteArray())
        val unrelated = presented("""[{"id":"case-$first"}]""", """[{"candidateId":"case-$second","exitCode":7,"stdoutHex":"77726f6e67"}]""", 1)
        val single = assertNotNull(unrelated.rows).single()
        assertEquals("case-[redacted]", single.candidate?.getValue("id")?.jsonPrimitive?.content)
        assertEquals(WebExplorationAttribution.UNMATCHED, single.attribution)
        assertNull(single.observation); assertNull(single.stdout)
        val both = assertNotNull(presented("""[{"id":"case-$first"},{"id":"case-$second"}]""",
            """[{"candidateId":"case-$second","exitCode":7,"stdoutHex":"77726f6e67"}]""", 2).rows)
        assertEquals(listOf(WebExplorationAttribution.UNMATCHED, WebExplorationAttribution.MATCHED), both.map { it.attribution })
        assertEquals("7", both[1].observation?.getValue("exitCode")?.jsonPrimitive?.content)
        assertEquals("wrong", both[1].stdout?.preview)
        assertTrue(first !in both.toString() && second !in both.toString())
    }

    @Test fun `decoded program output is redacted before it is clipped`() {
        val marker = "configured-stdout-credential-7f3a91"
        val policy = WebRedactionPolicy.create(emptyMap(), listOf(marker), emptyList())
        fun hex(text: String) = text.toByteArray().joinToString("") { "%02x".format(it.toInt() and 255) }
        for ((output, expectedBytes) in listOf("token: $marker\n" to marker.length + 8,
            "x".repeat(30) + marker to 30 + marker.length,
            marker.substring(0, 10) + "\r" + marker.substring(10) to marker.length + 1)) {
            val text = valid.replace("\"candidates\":[{}]", "\"candidates\":[{\"id\":\"case\"}]")
                .replace("\"observations\":[]", "\"observations\":[{\"candidateId\":\"case\",\"exitCode\":0,\"stdoutHex\":\"${hex(output)}\"}]")
            assertTrue(marker !in text)
            val stdout = assertNotNull(assertNotNull(presentWebExploration(policy, text.toByteArray()).rows).single().stdout)
            assertEquals(expectedBytes, stdout.byteCount)
            assertTrue(marker.take(12) !in stdout.preview, stdout.toString())
            assertTrue("[redacted]" in stdout.preview || stdout.preview.endsWith("[redac") || stdout.clipped, stdout.toString())
        }
        val empty = valid.replace("\"candidates\":[{}]", "\"candidates\":[{\"id\":\"case\"}]")
            .replace("\"observations\":[]", "\"observations\":[{\"candidateId\":\"case\",\"exitCode\":0,\"stdoutHex\":\"\"}]")
        assertEquals(WebExplorationOutput(0, "", false), presentWebExploration(policy, empty.toByteArray()).rows?.single()?.stdout)
    }

    private val failed = """{"schema":"decomp-exploration-failure","schemaVersion":1,"state":"partial","failure":{"phase":"expanded","candidateIndex":0,"kind":"timeout","code":"behavior-deadline-exceeded"},"samples":{"baselineInputs":1,"expandedInputs":1,"baselineObserved":1,"expandedObserved":0},"details":{"baselineInputs":[{"id":"seed","source":"SEED","args":[""],"stdinHex":"00"}],"expandedInputs":[{"id":"generated","source":"MUTATION","args":[],"stdinHex":""}],"baselineObservations":[{"candidateId":"seed","signature":"0::","exitCode":0,"stdoutHex":"","stderrHex":"","networkIsolated":false}],"expandedObservations":[]},"detailsOmitted":null,"coverage":null,"confidence":null}"""

    @Test fun `versioned producer failure retains artifact and attempt binding without a success summary`() {
        val result = report(failed)
        assertEquals("partial", result.getValue("state").jsonPrimitive.content)
        assertEquals(1, result.getValue("producerSchemaVersion").jsonPrimitive.int)
        assertEquals(JsonNull, result.getValue("summary"))
        assertEquals("observations", result.getValue("authority").jsonPrimitive.content)
        assertEquals("not-evaluated", result.getValue("acceptance").jsonPrimitive.content)
        assertEquals("run_1", result.getValue("binding").jsonObject.getValue("runId").jsonPrimitive.content)
        assertEquals("raw-evidence", result.getValue("sourceArtifact").jsonObject.getValue("role").jsonPrimitive.content)
        assertTrue(result.getValue("limitations").jsonArray.single().jsonPrimitive.content.contains("a timeout"))
        assertTrue(result.getValue("limitations").jsonArray.single().jsonPrimitive.content.contains("Coverage and confidence are unavailable"))
    }

    @Test fun `malformed failed progress is invalid and future producer versions remain unsupported`() {
        for (text in listOf(
            failed.replace("\"candidateIndex\":0", "\"candidateIndex\":1"),
            failed.replace("\"signature\":\"0::\"", "\"signature\":\"1::\""),
            failed.replace("\"confidence\":null", "\"confidence\":0"),
            failed.replace("\"baselineObserved\":1", "\"baselineObserved\":0"),
        )) {
            val result = report(text)
            assertEquals("invalid", result.getValue("state").jsonPrimitive.content)
            assertEquals(JsonNull, result.getValue("summary"))
        }
        val legacyWithFailureDeclaration = JsonObject(Json.parseToJsonElement(valid).jsonObject +
            ("schema" to JsonPrimitive("decomp-exploration-failure"))).toString()
        for (text in listOf(failed.replace("\"schemaVersion\":1", "\"schemaVersion\":2"),
            failed.replace("\"schemaVersion\":1,", ""), legacyWithFailureDeclaration)) {
            val result = report(text)
            assertEquals("unsupported", result.getValue("state").jsonPrimitive.content)
            assertEquals(JsonNull, result.getValue("summary"))
        }
    }
}
