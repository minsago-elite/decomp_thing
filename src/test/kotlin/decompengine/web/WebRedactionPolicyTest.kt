package decompengine.web

import kotlinx.serialization.json.Json
import kotlinx.serialization.json.JsonPrimitive
import kotlinx.serialization.json.buildJsonArray
import kotlinx.serialization.json.buildJsonObject
import kotlinx.serialization.json.jsonObject
import kotlinx.serialization.json.jsonPrimitive
import kotlinx.serialization.json.put
import java.nio.file.Path
import kotlin.test.Test
import kotlin.test.assertContentEquals
import kotlin.test.assertEquals
import kotlin.test.assertFalse
import kotlin.test.assertFailsWith
import kotlin.test.assertSame
import kotlin.test.assertTrue

class WebRedactionPolicyTest {
    private val canary = "CANARYtoken0123456789abcdef"
    private val policy = WebRedactionPolicy.create(
        environment = mapOf(
            "DECOMP_TEST_API_TOKEN" to canary,
            "AWS_SECRET_ACCESS_KEY" to "shortish9",
            "NODE_ENV" to "development",
            "SHLVL" to "1",
            "LANG" to "en_US.UTF-8",
        ),
        sensitiveValues = listOf(canary, "development", "1", "en_US.UTF-8", "LongOpaqueValue0123456789XYZ"),
        privateRoots = listOf(Path.of("/srv/decomp-private-store")),
    )

    @Test fun `credential literals, syntax and private paths are replaced while public vocabulary is untouched`() {
        assertEquals("key [redacted] end", policy.text("key $canary end"))
        assertEquals("[redacted]", policy.text("shortish9"))
        assertEquals("[redacted]", policy.text("LongOpaqueValue0123456789XYZ"))
        // Short generic environment values must never corrupt DTO vocabulary.
        assertEquals("development", policy.text("development"))
        assertEquals("1 of 1 en_US.UTF-8", policy.text("1 of 1 en_US.UTF-8"))
        assertEquals("Authorization: [redacted]", policy.text("Authorization: Bearer abcdefghijkl"))
        assertEquals("password=[redacted]&next", policy.text("password=hunter2&next"))
        assertEquals("password=[redacted] next", policy.text("password=\"hunter2 two\" next"))
        assertEquals("token=[redacted]", policy.text("token='abcdefghijk'"))
        assertEquals("{\"secret\": [redacted]}", policy.text("{\"secret\": \"s3cr3t value\"}"))
        assertEquals("api_key: [redacted], ok", policy.text("api_key: 'k-123', ok"))
        assertEquals("use [redacted] now", policy.text("use sk-abcdefghijklmnopqrstuvwx now"))
        assertEquals("https://[redacted]@example.test/x", policy.text("https://user:pa55@example.test/x"))
        assertEquals("open [private-path] failed", policy.text("open /srv/decomp-private-store/abc/input.elf failed"))
        assertEquals("[private-path]", policy.text("/home/someone/.config/agent.json"))
        assertEquals("see file://[private-path]", policy.text("see file:///home/someone/x.txt"))
        assertEquals("https://example.test/home/page", policy.text("https://example.test/home/page"))
        assertEquals("at [private-path]: denied", policy.text("at /tmp/decomp-123/work: denied"))
        assertEquals("[private-path]", policy.text("C:\\Users\\someone\\AppData\\token.txt"))
        // Relative and API paths are public.
        assertEquals("src/home/main.c", policy.text("src/home/main.c"))
        assertEquals("/workbench/api/v1/jobs/abc/runs", policy.text("/workbench/api/v1/jobs/abc/runs"))
        assertEquals("/rootkit/notes", policy.text("/rootkit/notes"))
        assertEquals("Context tokens: 5", policy.text("Context tokens: 5"))
    }

    @Test fun `quoted credential assignments consume escaped quotes and long or truncated values`() {
        val assignments = listOf(
            """password="alpha\"bravo"""" to "alpha",
            """token='alpha\'bravo'""" to "bravo",
            "password=\"${"x".repeat(4096)}\"" to "x".repeat(32),
            """secret="${"a\\\"".repeat(2048)}end"""" to "end",
            "password=\"unfinished credential" to "unfinished",
            "token='unfinished\\" to "unfinished",
        )
        for ((assignment, secretPart) in assignments) {
            val prefix = assignment.substringBefore('=') + "="
            val safe = policy.text(assignment)
            assertEquals(prefix + "[redacted]", safe, assignment.take(80))
            assertEquals(safe, policy.text(safe))
            val document = buildJsonObject { put("note", assignment) }.toString().toByteArray()
            val download = Json.parseToJsonElement(policy.document(document).decodeToString()).jsonObject
            assertEquals(safe, download.getValue("note").jsonPrimitive.content)
            assertFalse(download.toString().contains(secretPart))
        }
        // A truncated assignment stops at the line boundary, not at the end of the document.
        assertEquals("password=[redacted]\npublic note", policy.text("password=\"unfinished\npublic note"))
    }

    @Test fun `quoted authorization headers embedded in report strings conceal complete credentials`() {
        val credential = "dXNlcjpwYXNz"
        for (header in listOf(
            "\"Authorization\": \"Basic $credential\"",
            "'Proxy-Authorization': 'Basic $credential'",
            "\"Authorization\": Basic $credential",
            "Authorization: \"Bearer $credential\"",
            "\"Authorization\": \"Digest username=alpha, response=bravo charlie\"",
            "Authorization: Digest username=\"Mufasa\", nonce=\"nonce-secret\", response=\"response-secret\"",
            "Proxy-Authorization: Digest username=alice, realm=example, nonce=n-123, uri=/private, response=r-456, algorithm=MD5, qop=auth, nc=00000001, cnonce=c-789",
        )) {
            val report = "request headers: {$header}"
            val safe = policy.text(report)
            assertFalse(safe.contains(credential) || safe.contains("alpha") || safe.contains("bravo") || safe.contains("charlie"), safe)
            assertTrue(safe.contains("[redacted]"), safe)
            assertEquals(safe, policy.text(safe))
            assertEquals(safe, policy.json(buildJsonObject { put("note", report) }).jsonObject.getValue("note").jsonPrimitive.content)
            val downloaded = Json.parseToJsonElement(policy.document(buildJsonObject { put("note", report) }.toString().toByteArray()).decodeToString()).jsonObject
            assertEquals(safe, downloaded.getValue("note").jsonPrimitive.content)
        }
    }

    @Test fun `unknown authorization schemes conceal complete credentials in prose`() {
        val secret = "dGhpcy1pc19hX3NlY3JldA=="
        val cases = listOf(
            "Authorization: Negotiate $secret" to secret,
            "\"Authorization\": \"Negotiate $secret\"" to secret,
            "Proxy-Authorization: Custom proof with spaces" to "Custom proof with spaces",
        )
        for ((header, credential) in cases) {
            val report = "request headers: {$header}"
            val safe = policy.text(report)
            assertFalse(safe.contains(credential), safe)
            assertTrue(safe.contains("[redacted]"), safe)
            assertEquals(safe, policy.text(safe))
            assertEquals(safe, policy.json(buildJsonObject { put("note", report) }).jsonObject.getValue("note").jsonPrimitive.content)
            val document = buildJsonObject { put("note", report) }.toString().toByteArray()
            val downloaded = Json.parseToJsonElement(policy.document(document).decodeToString()).jsonObject
            assertEquals(safe, downloaded.getValue("note").jsonPrimitive.content)
        }
        val secondHeader = policy.text("Authorization: Negotiate $secret\r\nContent-Type: application/json")
        assertFalse(secondHeader.contains(secret), secondHeader)
        assertTrue(secondHeader.contains("Content-Type: application/json"), secondHeader)
    }

    @Test fun `web projection removes authorization tails left by progress redaction`() {
        val secret = "YIIFexampleCredential0123456789=="
        val partial = decompengine.jobs.ProgressRedactor(emptyList()).text("Authorization: Negotiate $secret")
        assertEquals("Authorization: [redacted] $secret", partial)

        val safe = policy.text(partial)
        assertEquals("Authorization: [redacted]", safe)
        assertFalse(safe.contains(secret), safe)
        assertEquals(safe, policy.text(safe))
        assertEquals(safe, policy.diagnostic(partial))

        val report = buildJsonObject { put("note", partial) }.toString().toByteArray()
        val downloaded = Json.parseToJsonElement(policy.document(report).decodeToString()).jsonObject
        assertEquals(safe, downloaded.getValue("note").jsonPrimitive.content)
    }

    @Test fun `redaction is stable when reapplied and never leaves a configured literal`() {
        val inputs = listOf("Authorization: Bearer $canary", "x${canary}y /home/a/b token=$canary", "[redacted]X")
        for (input in inputs) {
            val once = policy.text(input)
            assertEquals(once, policy.text(once), input)
            assertFalse(once.contains(canary))
            assertFalse(policy.leaks(once), once)
        }
    }

    @Test fun `opaque protocol fields keep exact bytes unless they carry a configured literal`() {
        val document = buildJsonObject {
            put("nextCursor", "sk-abcdefghijklmnopqrstuvwxyz012345")
            put("csrfToken", "token=abcdef")
            put("writerId", "writer_$canary")
            put("sha256", "a".repeat(64))
            put("message", "failed at /home/a/b with sk-abcdefghijklmnopqrstuvwxyz012345")
            put("items", buildJsonArray { add(JsonPrimitive("/tmp/x")); add(JsonPrimitive(3)) })
            put("nested", buildJsonObject { put("runId", "/home/escape") })
        }
        val safe = policy.json(document).jsonObject
        assertEquals("sk-abcdefghijklmnopqrstuvwxyz012345", safe.getValue("nextCursor").jsonPrimitive.content)
        assertEquals("token=abcdef", safe.getValue("csrfToken").jsonPrimitive.content)
        assertEquals("[redacted]", safe.getValue("writerId").jsonPrimitive.content)
        assertEquals("a".repeat(64), safe.getValue("sha256").jsonPrimitive.content)
        assertEquals("failed at [private-path] with [redacted]", safe.getValue("message").jsonPrimitive.content)
        assertEquals("[\"[private-path]\",3]", safe.getValue("items").toString())
        // An opaque key does not exempt a value outside closed token syntax.
        assertEquals("[private-path]", safe.getValue("nested").jsonObject.getValue("runId").jsonPrimitive.content)
        assertFalse(safe.toString().contains(canary))
    }

    @Test fun `structure selectors preserve opaque identities but never configured literals or private paths`() {
        val moduleId = "sk-abcdefghijklmnop"
        for (key in listOf("selector", "moduleSelector")) {
            val public = buildJsonObject { put(key, moduleId); put("moduleId", moduleId) }
            assertEquals(public, policy.json(public), key)
            assertEquals("[redacted]", policy.json(buildJsonObject { put(key, "prefix_$canary") })
                .jsonObject.getValue(key).jsonPrimitive.content, key)
            assertEquals("[private-path]", policy.json(buildJsonObject { put(key, "/home/private/record") })
                .jsonObject.getValue(key).jsonPrimitive.content, key)
            val absent = buildJsonObject { put(key, kotlinx.serialization.json.JsonNull) }
            assertEquals(absent, policy.json(absent), key)
            // Arbitrary downloaded JSON does not receive fixed-DTO field exemptions.
            val download = Json.parseToJsonElement(policy.document(public.toString().toByteArray()).decodeToString()).jsonObject
            assertEquals("[redacted]", download.getValue(key).jsonPrimitive.content, key)
        }
        // The exemption is exact, not a suffix match or an exception for ordinary prose.
        val prose = policy.json(buildJsonObject { put("functionSelector", moduleId); put("message", moduleId) }).jsonObject
        assertEquals("[redacted]", prose.getValue("functionSelector").jsonPrimitive.content)
        assertEquals("[redacted]", prose.getValue("message").jsonPrimitive.content)
        val configured = WebRedactionPolicy.create(mapOf("API_TOKEN" to moduleId), emptyList(), emptyList())
        val protected = configured.json(buildJsonObject {
            put("moduleId", moduleId); put("selector", moduleId); put("moduleSelector", moduleId)
        }).jsonObject
        assertTrue(protected.values.all { it.jsonPrimitive.content == "[redacted]" })
        assertFalse(protected.toString().contains(moduleId))
    }

    @Test fun `downloads keep identical bytes when clean and are rewritten structurally otherwise`() {
        val clean = "{\n  \"candidateCount\": 3,\n  \"note\": \"ok\"\n}\n".toByteArray()
        assertSame(clean, policy.document(clean))
        val dirty = "{\"note\": \"read /home/a/x\", \"count\": 18446744073709551615}".toByteArray()
        val rewritten = Json.parseToJsonElement(policy.document(dirty).decodeToString()).jsonObject
        assertEquals("read [private-path]", rewritten.getValue("note").jsonPrimitive.content)
        assertEquals("18446744073709551615", rewritten.getValue("count").toString())
        assertEquals("line [redacted]\n", policy.document("line $canary\n".toByteArray()).decodeToString())
        val binary = byteArrayOf(0xff.toByte(), 0xfe.toByte(), 1)
        assertContentEquals(binary, policy.document(binary))
    }

    @Test fun `escaped JSON values are judged after decoding, never by their serialized spelling`() {
        val quoted = WebRedactionPolicy.create(mapOf("DECOMP_TEST_TOKEN" to "ab\"cd\\ef0123"), emptyList(), emptyList())
        val document = buildJsonObject {
            put("note", "token ab\"cd\\ef0123 here")
            put("location", "C:\\Users\\someone\\report.json")
        }.toString().toByteArray()
        val safe = Json.parseToJsonElement(quoted.document(document).decodeToString()).jsonObject
        assertEquals("token [redacted] here", safe.getValue("note").jsonPrimitive.content)
        assertEquals("[private-path]", safe.getValue("location").jsonPrimitive.content)
    }

    @Test fun `public routing fields under a private-looking base path are preserved`() {
        val bootstrap = buildJsonObject {
            put("basePath", "/home/")
            put("snapshotHref", "/home/api/v1/jobs/abc/runs/r/snapshot")
            put("contentHref", "/tmp/api/v1/jobs/abc/artifacts/x/content?limit=1")
            put("message", "failed at /home/someone/private.txt")
            put("nextHref", "/home/someone/private.txt token=abcdef")
        }
        val safe = policy.json(bootstrap).jsonObject
        assertEquals("/home/", safe.getValue("basePath").jsonPrimitive.content)
        assertEquals("/home/api/v1/jobs/abc/runs/r/snapshot", safe.getValue("snapshotHref").jsonPrimitive.content)
        assertEquals("/tmp/api/v1/jobs/abc/artifacts/x/content?limit=1", safe.getValue("contentHref").jsonPrimitive.content)
        assertEquals("failed at [private-path]", safe.getValue("message").jsonPrimitive.content)
        // Text outside URL-route syntax is not exempt, even under a routing key.
        assertEquals("[private-path] token=[redacted]", safe.getValue("nextHref").jsonPrimitive.content)
        // Credential literals are never exempt.
        assertFalse(policy.json(buildJsonObject { put("basePath", "/w/$canary/") }).toString().contains(canary))
    }

    @Test fun `exact-byte validation previews keep their text consistent with their recorded bytes`() {
        val preview = buildJsonObject {
            put("totalBytes", "12"); put("prefixBytes", 12)
            put("hex", "2f 74 6d 70 2f 65 78 61 6d 70 6c 65"); put("text", "/tmp/example")
            put("textBytes", 12); put("truncated", false)
        }
        val report = buildJsonObject { put("message", "see /tmp/example"); put("expected", preview) }
        val safe = policy.json(report).jsonObject
        assertEquals(preview, safe.getValue("expected"))
        assertEquals("see [private-path]", safe.getValue("message").jsonPrimitive.content)
    }

    @Test fun `committed source tree names keep their exact unique ordered spellings`() {
        val directory = buildJsonObject {
            put("entries", buildJsonArray {
                add(buildJsonObject { put("displayName", "token=one.c") })
                add(buildJsonObject { put("displayName", "token=two.c") })
            })
        }
        assertEquals(directory, publicWebApiData("revisionDirectory", directory, policy))
        assertEquals(directory, publicWebApiData("revisionSources", directory, policy))
        // Server-produced documents still pass through the policy.
        assertEquals("token=[redacted]", publicWebApiData("report", directory, policy).jsonObject.getValue("entries")
            .let { (it as kotlinx.serialization.json.JsonArray)[0].jsonObject.getValue("displayName").jsonPrimitive.content })
    }

    @Test fun `source search and diff projections preserve committed text positions and query echoes`() {
        val committed = buildJsonObject {
            put("query", buildJsonObject { put("text", "/tmp/example"); put("path", "token=one.c") })
            put("before", "token=one "); put("match", "/tmp/example"); put("after", " $canary")
            put("text", "/tmp/example password=hunter2"); put("characters", 29)
            put("column", "11"); put("offsetBytes", "10")
        }
        for (kind in listOf("sourceSearch", "sourceFileDiff")) {
            assertSame(committed, publicWebApiData(kind, committed, policy), kind)
        }
        // This exemption is confined to authorized committed source; diagnostics are still redacted.
        assertFalse(publicWebApiData("report", committed, policy).toString().contains(canary))
        assertFalse(publicWebApiData("error", committed, policy).toString().contains("/tmp/example"))
    }

    @Test fun `source diff summaries preserve distinct committed filenames across redaction-like spellings`() {
        for ((baseName, headName) in listOf(
            "src/modules/sk-abcdefghijklmnopqrstuvwx.c" to "src/modules/sk-zyxwvutsrqponmlkjihgfedc.c",
            "src/modules/$canary.c" to "src/modules/shortish9.c",
        )) {
            val summary = buildJsonObject {
                put("renameDetection", "identical-digest")
                put("totalChanged", 3)
                put("items", buildJsonArray {
                    fun reference(name: String) = buildJsonObject {
                        put("fileId", if (name == baseName) "source_base" else "source_head")
                        put("displayName", name)
                    }
                    add(buildJsonObject {
                        put("status", "renamed")
                        put("baseFile", reference(baseName)); put("headFile", reference(headName))
                    })
                    add(buildJsonObject {
                        put("status", "added")
                        put("baseFile", kotlinx.serialization.json.JsonNull); put("headFile", reference(headName))
                    })
                    add(buildJsonObject {
                        put("status", "deleted")
                        put("baseFile", reference(baseName)); put("headFile", kotlinx.serialization.json.JsonNull)
                    })
                })
            }
            val rewritten = policy.json(summary).jsonObject.getValue("items") as kotlinx.serialization.json.JsonArray
            assertEquals(rewritten[0].jsonObject.getValue("baseFile").jsonObject.getValue("displayName"),
                rewritten[0].jsonObject.getValue("headFile").jsonObject.getValue("displayName"),
                "generic redaction would collapse the distinct committed names")
            assertEquals(summary, publicWebApiData("sourceDiff", summary, policy))
            for (kind in listOf("error", "report")) {
                val safe = publicWebApiData(kind, summary, policy).toString()
                assertFalse(safe.contains(baseName), kind)
                assertFalse(safe.contains(headName), kind)
            }
        }
    }

    @Test fun `committed source search snippets preserve text and code point positions`() {
        val snippet = buildJsonObject {
            put("before", "/tmp/x "); put("match", "needle"); put("after", " token=authored")
            put("column", 8); put("beforeTruncated", false)
        }
        val result = buildJsonObject { put("matches", buildJsonArray { add(snippet) }) }
        assertEquals(result, publicWebApiData("sourceSearch", result, policy))
        // The regression must include content that generic structural redaction would change.
        assertFalse(result == policy.json(result))
    }

    @Test fun `redacted near-limit names remain bounded without truncating secret replacements`() {
        val filename = "shortish9".repeat(28) + ".c"
        assertEquals(254, filename.length)
        for (key in listOf("displayFilename", "displayName", "filename")) {
            val safe = policy.json(buildJsonObject { put(key, filename) }).jsonObject
            assertEquals("[redacted]", safe.getValue(key).jsonPrimitive.content)
            assertEquals(safe, policy.json(safe))
            val download = Json.parseToJsonElement(policy.document(buildJsonObject { put(key, filename) }.toString().toByteArray()).decodeToString())
            assertEquals(safe, download)
        }
        val clean = buildJsonObject { put("displayName", "x".repeat(1024)) }
        assertEquals(clean, policy.json(clean), "clean longer Git ref names are unchanged")
    }

    @Test fun `an accepted filename of repeated credential assignments stays within its contract bound`() {
        val filename = "token=x;".repeat(30) + ".elf"
        assertEquals(244, filename.length)
        val safe = policy.json(buildJsonObject { put("displayFilename", filename) }).jsonObject
            .getValue("displayFilename").jsonPrimitive.content
        assertTrue(safe.length <= 255, "${safe.length}")
        assertFalse(safe.contains("token=x"))
    }

    @Test fun `unsupported short named credentials are refused instead of silently excluded`() {
        for (length in 1..7) {
            val secret = "s".repeat(length)
            val failure = assertFailsWith<IllegalArgumentException> {
                WebRedactionPolicy.create(mapOf("DB_PASSWORD" to secret), listOf(secret), emptyList())
            }
            assertEquals("nonempty credential-named environment values must contain 8 to 4096 characters", failure.message)
        }
        for (secret in listOf("hunter2", "s3cr3t!")) {
            assertFailsWith<IllegalArgumentException> {
                WebRedactionPolicy.create(mapOf("DECOMP_TEST_API_TOKEN" to secret), listOf(secret), emptyList())
            }
        }
        // Empty optional credentials and short generic environment values are not credentials.
        val generic = WebRedactionPolicy.create(mapOf("DB_PASSWORD" to "", "SHLVL" to "1"), emptyList(), emptyList())
        assertEquals("1", generic.text("1"))
    }

    @Test fun `diagnostics mask complete quoted spans before either redactor or preview truncation`() {
        val diagnostic = WebRedactionPolicy.create(emptyMap(), listOf("s3cr"), emptyList())
        for (assignment in listOf(
            "password=\"alpha bravo charlie\"",
            "client_secret='alpha bravo charlie'",
            "password=\"alpha\\\"bravo charlie\"",
            "password=\"${"x".repeat(4096)} tail\"",
            "password=\"unfinished credential",
            "password=\"s3cr bravo charlie\"",
        )) {
            val expected = assignment.substringBefore('=') + "=[redacted]"
            assertEquals(expected, diagnostic.diagnostic(assignment))
            assertEquals(expected, WebRedactionPolicy.BASELINE.diagnostic(assignment))
            assertFalse(diagnostic.diagnostic("public ".repeat(100) + assignment, 128).contains("charlie"))
        }
        // The earlier ACP inventory redactor must not destroy the context before web projection.
        val progress = decompengine.jobs.ProgressRedactor(emptyList())
        assertEquals("password=[redacted]", progress.text("password=\"alpha bravo charlie\""))
        assertEquals("password=[redacted]", progress.text("password=\"alpha\\\"bravo charlie\""))
    }

    @Test fun `configured literals cannot destroy complete quoted credential context`() {
        for (literal in listOf("password", "password=\"alpha", "alpha bravo", "bravo charlie\"")) {
            val overlapping = WebRedactionPolicy.create(mapOf("TEST_TOKEN" to literal), listOf(literal), emptyList())
            for (safe in listOf(overlapping.text("password=\"alpha bravo charlie\""),
                overlapping.diagnostic("password=\"alpha bravo charlie\""))) {
                assertFalse(safe.contains("alpha") || safe.contains("bravo") || safe.contains("charlie"), safe)
                assertFalse(safe.contains(literal), safe)
            }
        }
    }

    @Test fun `arbitrary JSON downloads redact decoded keys credential properties and DTO lookalikes`() {
        val input = buildJsonObject {
            put(canary, "public")
            put("password", "alpha bravo charlie")
            put("nested", buildJsonArray { add(buildJsonObject {
                put("client_secret", buildJsonObject { put("value", "hidden") })
                put("Authorization", "Basic arbitrary credential")
                put("nextCursor", "sk-abcdefghijklmnopqrstuvwxyz012345")
                put("snapshotHref", "/home/private/report")
            }) })
        }
        val safe = Json.parseToJsonElement(policy.document(input.toString().toByteArray()).decodeToString()).jsonObject
        assertFalse(safe.toString().contains(canary))
        assertEquals("public", safe.getValue("[redacted]").jsonPrimitive.content)
        assertEquals("[redacted]", safe.getValue("password").jsonPrimitive.content)
        assertFalse(safe.toString().contains("hidden") || safe.toString().contains("arbitrary credential"))
        assertFalse(safe.toString().contains("sk-abc") || safe.toString().contains("/home/private"))
        val escapedKey = WebRedactionPolicy.create(mapOf("TEST_TOKEN" to "ab\"cd\\ef0123"), emptyList(), emptyList())
        val escaped = buildJsonObject { put("ab\"cd\\ef0123", "public") }
        assertFalse(escapedKey.document(escaped.toString().toByteArray()).decodeToString().contains("ab\\\"cd"))
        val punctuation = WebRedactionPolicy.create(mapOf("TEST_TOKEN" to "\"password\""), emptyList(), emptyList())
        assertEquals("null", punctuation.document("{\"password\":\"alpha bravo charlie\"}".toByteArray()).decodeToString())
        val colliding = buildJsonObject { put(canary, "first"); put("[redacted]", "second") }
        val collision = policy.document(colliding.toString().toByteArray())
        assertEquals(JsonPrimitive("[redacted]"), Json.parseToJsonElement(collision.decodeToString()))
        assertContentEquals(collision, policy.document(collision))
    }

    @Test fun `persisted diagnostics also redact short configured values before storage`() {
        val diagnostic = WebRedactionPolicy.create(emptyMap(), listOf("s3cr"), emptyList())
        assertEquals("value [redacted] at [private-path]", diagnostic.diagnostic("value s3cr at /home/x/y"))
        assertTrue(diagnostic.diagnostic("x".repeat(1000)).length < 600)
    }

    @Test fun `necessary token metadata and actual production gates preserve rule spans`() {
        val policyClass = WebRedactionPolicy::class.java
        val rulesField = policyClass.getDeclaredField("CREDENTIAL_PATTERNS").apply { isAccessible = true }
        @Suppress("UNCHECKED_CAST")
        val rules = rulesField.get(null) as List<Any>
        assertEquals(11, rules.size)
        val required = listOf("COOKIE") + List(6) { "AUTHORIZATION" } + listOf("BEARER", "ALWAYS", "ALWAYS", "ALWAYS")
        val prefix = List(10) { true } + false
        val ruleClass = rules.first().javaClass
        val patternField = ruleClass.getDeclaredField("pattern").apply { isAccessible = true }
        val prefixField = ruleClass.getDeclaredField("keepPrefix").apply { isAccessible = true }
        val requiredField = ruleClass.getDeclaredField("required").apply { isAccessible = true }
        val nested = policyClass.declaredClasses.associateBy { it.simpleName }
        val tokenClass = nested.getValue("RequiredToken")
        val presenceClass = nested.getValue("SyntaxPresence")
        val constructor = presenceClass.getDeclaredConstructor(String::class.java).apply { isAccessible = true }
        val permits = presenceClass.getDeclaredMethod("permits", tokenClass).apply { isAccessible = true }
        val permitsUrl = presenceClass.getDeclaredMethod("permitsUrl").apply { isAccessible = true }
        val defaultMarker = Class.forName("kotlin.jvm.internal.DefaultConstructorMarker")
        val defaultConstructor = ruleClass.getDeclaredConstructor(
            Regex::class.java, java.lang.Boolean.TYPE, tokenClass, Integer.TYPE, defaultMarker,
        ).apply { isAccessible = true }
        val urlField = policyClass.getDeclaredField("URL_USER_INFO").apply { isAccessible = true }
        val urlPattern = urlField.get(null) as Regex
        assertEquals("""(?i)\b([a-z][a-z0-9+.-]{1,31}://)[^/\s:@"'<>]{1,256}(?::[^/\s@"'<>]{0,512})?@""", urlPattern.pattern)
        assertEquals(setOf(RegexOption.IGNORE_CASE), urlPattern.options)

        fun signature(match: MatchResult, keepPrefix: Boolean, endOffset: Int = 1): String {
            val groups = match.groups.map { group -> group?.let { "${it.value}@${it.range.first}:${it.range.last + 1}" } ?: "null" }
            val start = if (keepPrefix) match.groups[1]!!.range.last + 1 else match.range.first
            val end = match.range.last + endOffset
            return "${match.value}@${match.range.first}:${match.range.last + 1}|$groups|mark=$start:$end"
        }

        val defaultedRule = defaultConstructor.newInstance(patternField.get(rules[0]), true, null, 4, null)
        assertEquals("ALWAYS", requiredField.get(defaultedRule).toString(), "new-rule default remains unconditional")

        val witnesses = listOf(
            "Cookie: sid=alpha", "Authorization: \"alpha\"", "Authorization: 'alpha'",
            "Authorization: Custom alpha", "Authorization: Digest username=\"alpha\", nonce=\"bravo\"",
            "Authorization: Basic YWxwaGE=", "HTTP_AUTHORIZATION=Digest username=\"alpha\", nonce=\"bravo\"",
            "bearer abcdefgh", "PASSWORD=\"alpha bravo\"", "api_key=alpha", "sk-abcdefghijklmnop",
        )
        val expectedMatch = listOf(
            "Cookie: sid=alpha", "Authorization: \"alpha", "Authorization: 'alpha", "Authorization: Custom alpha",
            "Authorization: Digest username=\"alpha\", nonce=\"bravo\"", "Authorization: Basic YWxwaGE=",
            "AUTHORIZATION=Digest username=\"alpha\", nonce=\"bravo\"", "bearer abcdefgh",
            "PASSWORD=\"alpha bravo\"", "api_key=alpha", "sk-abcdefghijklmnop",
        )
        val expectedMatchStart = listOf(0, 0, 0, 0, 0, 0, 5, 0, 0, 0, 0)
        val expectedMatchEndExclusive = listOf(17, 21, 21, 27, 53, 29, 57, 15, 22, 13, 19)
        val expectedGroup1 = listOf("Cookie: ", "Authorization: \"", "Authorization: '", "Authorization: ",
            "Authorization: ", "Authorization: ", "AUTHORIZATION=", "bearer ", "PASSWORD=", "api_key=", null)
        val expectedGroupStart = listOf(0, 0, 0, 0, 0, 0, 5, 0, 0, 0, null)
        val expectedGroupEndExclusive = listOf(8, 16, 16, 15, 15, 15, 19, 7, 9, 8, null)
        val expectedMark = listOf(8 to 17, 16 to 21, 16 to 21, 15 to 27, 15 to 53, 15 to 29,
            19 to 57, 7 to 15, 9 to 22, 8 to 13, 0 to 19)
        val credentialKeys = "api[_-]?key|access[_-]?key|secret[_-]?key|access[_-]?token|refresh[_-]?token|" +
            "auth[_-]?token|client[_-]?secret|password|passwd|passphrase|secret|token|(?:proxy-)?authorization"
        val expectedPatterns = listOf(
            """(?i)(\b(?:set-cookie|cookie)["']?[\t ]*:[\t ]*)[^\r\n]*""",
            """(?i)\b((?:proxy-)?authorization["']?\s*[:=]\s*")(?:(?:[^"\\\r\n]|\\[^\r\n]?))*+""",
            """(?i)\b((?:proxy-)?authorization["']?\s*[:=]\s*')(?:(?:[^'\\\r\n]|\\[^\r\n]?))*+""",
            """(?i)\b((?:proxy-)?authorization["']?\s*[:=]\s*+)(?!["'])[^\r\n<>]+""",
            """(?i)\b((?:proxy-)?authorization["']?\s*[:=]\s*)digest\s+[^\r\n<>]+""",
            """(?i)\b((?:proxy-)?authorization["']?\s*[:=]\s*)(?:basic|bearer|token|digest)\s+[^\s,;"'<>]+""",
            """(?i)(?:\b|(?<=_))((?:proxy-)?authorization["']?\s*[:=][\t ]*)(?!["'])[^\r\n]+""",
            """(?i)\b(bearer\s+)[A-Za-z0-9._~+/=-]{8,}""",
            """(?i)(?:\b|(?<=_))((?:$credentialKeys)["']?\s*[:=]\s*)(?:"(?:[^"\\\r\n]|\\[^\r\n]?)*+(?:"|(?=[\r\n]|$))|'(?:[^'\\\r\n]|\\[^\r\n]?)*+(?:'|(?=[\r\n]|$)))""",
            """(?i)(?:\b|(?<=_))((?:$credentialKeys)["']?\s*[:=]\s*)(?!\[redacted])[^\s,;"'&<>]+""",
            """(?<![A-Za-z0-9_-])(?:sk-[A-Za-z0-9_-]{16,}|sk-ant-[A-Za-z0-9_-]{8,}|gh[pousr]_[A-Za-z0-9]{20,}|github_pat_[A-Za-z0-9_]{20,}|xox[abprs]-[A-Za-z0-9-]{10,}|AKIA[0-9A-Z]{16}|AIza[0-9A-Za-z_-]{35})""",
        )
        val corpus = buildList {
            add("plain opaque input")
            addAll(witnesses)
            for (witness in witnesses) for (code in 0..127) {
                val context = code.toChar()
                add("$context$witness$context")
            }
            addAll(listOf("no syntax words", "token=ordinary", "private path /home/person/file", "https://alpha@example.test/x"))
            for (left in witnesses) for (right in witnesses) add("$left\n$right")
            for (key in listOf("api_key", "apikey", "api-key", "access_key", "secret_key", "access_token",
                "refresh_token", "auth_token", "client_secret", "password", "passwd", "passphrase", "secret", "token",
                "authorization", "proxy-authorization", "DATABASE_PASSWORD", "CUSTOM_API_KEY", "HTTP_AUTHORIZATION", "_password")) {
                add("$key=alpha")
                add("$key=\"alpha bravo\"")
                add("$key='alpha bravo'")
                add("$key=\"alpha\\\" bravo")
            }
            addAll(listOf("sk-ant-abcdefgh", "github_pat_" + "a".repeat(20), "AKIA" + "A".repeat(16), "AIza" + "a".repeat(35)))
            for (kind in "pousr") add("gh${kind}_" + "a".repeat(20))
            for (kind in "abprs") add("xox$kind-" + "a".repeat(10))
        }
        for (index in rules.indices) {
            val rule = rules[index]
            val regex = patternField.get(rule) as Regex
            assertEquals(expectedPatterns[index], regex.pattern, "rule $index exact regex")
            assertEquals(if (index < 10) setOf(RegexOption.IGNORE_CASE) else emptySet(), regex.options, "rule $index effective options")
            val token = requiredField.get(rule)
            assertEquals(required[index], token.toString(), "rule $index required token")
            assertEquals(prefix[index], prefixField.getBoolean(rule), "rule $index prefix behavior")
            val positive = witnesses[index]
            val positivePresence = constructor.newInstance(positive)
            assertEquals(true, permits.invoke(positivePresence, token), "rule $index positive gate")
            val raw = regex.findAll(positive).map { signature(it, prefix[index]) }.toList()
            assertTrue(raw.isNotEmpty(), "rule $index positive production Regex witness")
            val first = regex.findAll(positive).first()
            assertEquals(expectedMatch[index], first.value, "rule $index hand-derived witness")
            assertEquals(expectedMatchStart[index], first.range.first, "rule $index witness start")
            assertEquals(expectedMatchEndExclusive[index], first.range.last + 1, "rule $index witness end")
            if (expectedGroup1[index] != null) {
                assertEquals(expectedGroup1[index], first.groups[1]!!.value, "rule $index group 1")
                assertEquals(expectedGroupStart[index], first.groups[1]!!.range.first, "rule $index group 1 start")
                assertEquals(expectedGroupEndExclusive[index], first.groups[1]!!.range.last + 1, "rule $index group 1 end")
            } else assertEquals(1, first.groups.size, "opaque rule has only the whole-match group")
            val actualMarkStart = if (prefix[index]) first.groups[1]!!.range.last + 1 else first.range.first
            assertEquals(expectedMark[index].first to expectedMark[index].second,
                actualMarkStart to (first.range.last + 1), "rule $index derived mark interval")
            assertEquals(raw, regex.findAll(positive).map { signature(it, prefix[index]) }.toList())
            for (source in corpus) {
                val sourcePresence = constructor.newInstance(source)
                val sourceAllowed = permits.invoke(sourcePresence, token) as Boolean
                val sourceRaw = regex.findAll(source).map { signature(it, prefix[index]) }.toList()
                val sourceSelected = if (sourceAllowed) regex.findAll(source).map { signature(it, prefix[index]) }.toList() else emptyList()
                assertEquals(sourceRaw, sourceSelected, "rule $index source-derived engine spans")
                if (!sourceAllowed) assertTrue(sourceRaw.isEmpty(), "disabled rule $index has no raw match")
            }

            val negative = "plain opaque input"
            val negativePresence = constructor.newInstance(negative)
            val allowed = permits.invoke(negativePresence, token) as Boolean
            assertEquals(index >= 8, allowed, "rule $index negative gate")
            val rawNegative = regex.findAll(negative).map { signature(it, prefix[index]) }.toList()
            val selected = if (allowed) rawNegative else emptyList()
            assertEquals(rawNegative, selected, "rule $index actual-engine selected spans")
            if (!allowed) assertTrue(rawNegative.isEmpty(), "skipped rule $index must have no raw matches")
        }
        assertEquals(true, permitsUrl.invoke(constructor.newInstance("https://alpha@example.test/x")))
        assertEquals(false, permitsUrl.invoke(constructor.newInstance("plain opaque input")))
        val urlMatch = urlPattern.find("https://alpha@example.test/x")!!
        assertEquals("https://alpha@", urlMatch.value)
        assertEquals(0..13, urlMatch.range)
        assertEquals("https://", urlMatch.groups[1]!!.value)
        assertEquals(0..7, urlMatch.groups[1]!!.range)
        assertEquals(8, urlMatch.groups[1]!!.range.last + 1)
        assertEquals(13, urlMatch.range.last)
        for (source in corpus) {
            val sourcePresence = constructor.newInstance(source)
            val sourceAllowed = permitsUrl.invoke(sourcePresence) as Boolean
            val sourceRaw = urlPattern.findAll(source).map { signature(it, true, 0) }.toList()
            val sourceSelected = if (sourceAllowed) urlPattern.findAll(source).map { signature(it, true, 0) }.toList() else emptyList()
            assertEquals(sourceRaw, sourceSelected, "URL source-derived engine spans")
            if (!sourceAllowed) assertTrue(sourceRaw.isEmpty(), "disabled URL search has no raw match")
        }

        val words = listOf("cookie", "authorization", "bearer")
        val tokens = listOf("COOKIE", "AUTHORIZATION", "BEARER")
        for (wordIndex in words.indices) {
            val word = words[wordIndex]
            val enumValue = tokenClass.enumConstants.first { it.toString() == tokens[wordIndex] }
            val masks = 1 shl word.length
            for (mask in 0 until masks) {
                val spelling = word.mapIndexed { position, char -> if (mask and (1 shl position) != 0) char.uppercaseChar() else char }.joinToString("")
                assertEquals(true, permits.invoke(constructor.newInstance("x$spelling-y"), enumValue), "$word case mask $mask")
            }
        }
        val nonAscii = listOf("é", "xİy", "xıy", "ſ", "K", "\uFFFD", "\uD83D\uDE00", "\uD800", "\uDC00")
        for (injection in nonAscii) {
            val samples = listOf("$injection plain", "plain $injection", "pl${injection}ain") +
                (witnesses + "https://alpha@example.test/x").flatMap { witness ->
                    listOf(injection + witness, witness + injection, witness.take(3) + injection + witness.drop(3))
                }
            for (sample in samples) {
                val presence = constructor.newInstance(sample)
                for (rule in rules) {
                    assertEquals(true, permits.invoke(presence, requiredField.get(rule)))
                    val regex = patternField.get(rule) as Regex
                    val raw = regex.findAll(sample).map { signature(it, prefix[rules.indexOf(rule)]) }.toList()
                    val selected = if (permits.invoke(presence, requiredField.get(rule)) as Boolean)
                        regex.findAll(sample).map { signature(it, prefix[rules.indexOf(rule)]) }.toList() else emptyList()
                    assertEquals(raw, selected)
                }
                assertEquals(true, permitsUrl.invoke(presence))
                val urlRaw = urlPattern.findAll(sample).map { signature(it, true, 0) }.toList()
                val urlSelected = if (permitsUrl.invoke(presence) as Boolean)
                    urlPattern.findAll(sample).map { signature(it, true, 0) }.toList() else emptyList()
                assertEquals(urlRaw, urlSelected)
            }
        }
        assertEquals("CoOkIe: [redacted]", WebRedactionPolicy.BASELINE.text("CoOkIe: sid=alpha"))
        assertEquals("AUTHORIZATION: [redacted]", WebRedactionPolicy.BASELINE.text("AUTHORIZATION: Custom alpha"))
        assertEquals("bEaReR [redacted]", WebRedactionPolicy.BASELINE.text("bEaReR abcdefgh"))
        assertEquals("password=[redacted]", WebRedactionPolicy.BASELINE.text("password=alpha"))
        assertEquals("[redacted]", WebRedactionPolicy.BASELINE.text("sk-abcdefghijklmnop"))
    }

    @Test fun `configured literals remain unconditional through replacement synthesis and final withholding`() {
        val literals = listOf("abcdefgh", "[redacted]X", "[redacted]Y", "[redacted]Z", "[redacted]W")
        val configured = WebRedactionPolicy.create(
            environment = literals.mapIndexed { index, literal -> "TEST_API_TOKEN_$index" to literal }.toMap(),
            sensitiveValues = emptyList(),
            privateRoots = emptyList(),
        )
        val once = configured.text("abcdefghXYZW")
        assertEquals("[redacted]", once)
        assertFalse(configured.leaks(once))
        assertEquals(once, configured.text(once))
        assertEquals("[redacted]", configured.text("abcdefghX"))
    }
}
