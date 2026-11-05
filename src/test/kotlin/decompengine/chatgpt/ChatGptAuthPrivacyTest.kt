package decompengine.chatgpt

import java.net.URLEncoder
import java.net.URI
import java.net.URLDecoder
import java.time.Instant
import java.util.Base64
import kotlin.test.*
import org.junit.jupiter.api.Test

internal class ChatGptAuthPrivacyTest {
    @Test fun secretCanariesNeverEnterSafeProjectionsExceptionsOrDiagnostics() {
        val secretKinds = listOf("access", "refresh", "id", "code", "state", "nonce", "verifier", "hint")
        val secrets = secretKinds.associateWith { kind -> "canary_${kind}_" + "z".repeat(13) }
        fun variantsOf(value: String): List<String> {
            val bytes = value.toByteArray(Charsets.UTF_8)
            return listOf(value, Base64.getEncoder().encodeToString(bytes), URLEncoder.encode(value, Charsets.UTF_8),
                value.chunked(3).joinToString("|"))
        }
        val variants = secrets.values.flatMap(::variantsOf).toMutableList()
        val tokenSet = ChatGptPlanTokenSet(secrets.getValue("access"), secrets.getValue("refresh"), secrets.getValue("id"),
            "Bearer", Instant.parse("2026-11-05T12:00:00Z"), Instant.parse("2026-11-05T13:00:00Z"), setOf("openid"), "nonce-digest")
        val json = ChatGptAuthJson.parse(
            ("{\"access_token\":\"${secrets.getValue("access")}\",\"refresh_token\":\"${secrets.getValue("refresh")}\"}").toByteArray(),
            AuthTestClock().operation(),
        )
        val error = authFailure(ChatGptAuthHttpFailure.INVALID_FORM) {
            authFail(ChatGptAuthHttpFailure.INVALID_FORM)
        }
        val oidcError = ChatGptOidcFailure(ChatGptOidcFailure.Reason.INVALID_ID_TOKEN)
        val wrappedCauses = secretKinds.map { kind ->
            try { oidcBoundary { throw IllegalArgumentException(secrets.getValue(kind)) }; null }
            catch (failure: Throwable) { failure }
        }
        wrappedCauses.forEach { assertIs<ChatGptOidcFailure>(it, "untrusted exception is normalized to a fixed OIDC category") }
        val registration = ChatGptPlanOAuthRegistration.Returning("oaiapp_test", "host-fixture",
            idTokenHint = secrets.getValue("hint"), loginHint = secrets.getValue("hint"))
        val rig = AuthTestRig()
        var randomFill = 9
        val callbackCode = rig.use {
            val binding = rig.metadata.bindAuthorization(authSnapshot(), ChatGptPlanOAuthRedirect.of(42321),
                ChatGptPlanOAuthClock(rig.clock.nanos::get), ChatGptPlanOAuthRandom { it.fill((randomFill++).toByte()) },
                ChatGptPlanOAuthCancellation { false }, rig.clock.operation())
            var retainedAttempt: ChatGptPlanOAuthAttempt? = null
            val request = binding.authorizationRequest()
            val raw = URI(request.uri).rawQuery
            val state = URLDecoder.decode(raw.split('&').first { it.startsWith("state=") }.substringAfter('='), Charsets.UTF_8)
            val code = binding.receiveCode(object : ChatGptAuthCodeReceiver() {
                override fun await(attempt: ChatGptPlanOAuthAttempt): ChatGptPlanOAuthAttempt.CallbackResult {
                    retainedAttempt = attempt
                    return attempt.consumeCallback("GET", "127.0.0.1:42321",
                        "/auth/callback?state=$state&code=${URLEncoder.encode(secrets.getValue("code"), Charsets.UTF_8)}&client_id=oaiapp_test")
                }
            })
            assertTrue(code is ChatGptPlanOAuthAttempt.CallbackResult.Code, "synthetic canary code reaches actual OAuth result")
            val callback = code as ChatGptPlanOAuthAttempt.CallbackResult.Code
            val form = callback.prepareExchange()
            fun field(encoded: String, name: String): String = URLDecoder.decode(
                encoded.split('&').first { it.startsWith("$name=") }.substringAfter('='), Charsets.UTF_8)
            val actualFields = listOf(state, field(raw, "nonce"), field(form.encodedBody, "code_verifier"))
            // Bind the checks to the actual attempt and form, not unrelated named canaries.
            // The fixed seed correspondence also keeps the pre-persistence runner guards aligned.
            assertTrue(actualFields.distinct().size == 3, "actual OAuth privacy fields are distinct")
            actualFields.forEachIndexed { index, value ->
                val guarded = Base64.getUrlEncoder().withoutPadding().encodeToString(ByteArray(32) { (9 + index).toByte() })
                assertTrue(value == guarded, "actual OAuth field is covered by the evidence output guard")
                variants.addAll(variantsOf(value))
            }
            assertTrue(callback.nonceForValidation == actualFields[1], "callback carries the actual attempt nonce")
            listOf(request, code, retainedAttempt, registration, form)
        }
        val publicViews = listOf(tokenSet, json, error, oidcError, ChatGptPlanOAuthException(ChatGptPlanOAuthFailure.INVALID_CODE)) +
            wrappedCauses + callbackCode
        val rendered = publicViews.map(ChatGptAuthBoundaryFixtures::safeString)
        for (projection in rendered) {
            for (canary in variants) assertFalse(projection.contains(canary), "secret canary absent from safe projection")
        }
        assertNull(error.cause, "transport failure has no cause")
        assertEquals(0, error.suppressed.size, "transport failure has no suppressed throwable")
        assertTrue(wrappedCauses.all { it?.cause == null }, "normalized OIDC exceptions drop untrusted causes")
    }

    @Test fun publicAccountIdentityMetadataRemainsIntentionallyVisible() {
        val publicClient = "oaiapp_" + "z".repeat(13)
        val publicSubject = "canary_subject_" + "z".repeat(13)
        val client = "oaiapp_public_client"
        val subject = "public-subject-fixture"
        val label = "Fixture Account"
        val email = "fixture@example.invalid"
        val account = ChatGptPlanAccount("account-public-id", "https://issuer.example", client, label, email,
            "fixture-model", 4, 9, ChatGptPlanAccount.State.READY, setOf("resource.invoke"), null)
        val safe = account.toString()
        // Account id/client/label/email are declared public UI metadata. Keep these
        // checks explicit so privacy tests do not accidentally forbid required views.
        assertTrue(safe.contains("credentials=[redacted]"), "account rendering labels credential omission")
        assertFalse(safe.contains("access") || safe.contains("refresh"), "account rendering omits credential material")
        assertEquals("account-public-id", account.accountId, "account identifier is exposed by the declared public UI model")
        assertEquals(client, account.clientId, "client identifier is exposed by the declared public UI model")
        assertEquals(label, account.label, "display label is exposed by the declared public UI model")
        assertEquals(email, account.email, "display email is exposed by the declared public UI model")
        val registration = ChatGptPlanValidatedRegistration("https://issuer.example", client, subject, label, email,
            ChatGptPlanTokenSet("secret" + "-access", "secret" + "-refresh", "secret" + "-id", "Bearer", Instant.EPOCH,
                Instant.EPOCH.plusSeconds(60), emptySet()))
        val registrationView = registration.toString()
        assertTrue(registrationView.contains("[redacted]"), "validated registration redacts its complete identity and token bundle")
        assertFalse(registrationView.contains(subject) || registrationView.contains(client), "registration object is not a UI projection")
        // Distinct subject/client canaries remain available only through the explicit
        // public account projection; they are not token, callback, or hint material.
        val publicAccount = ChatGptPlanAccount("account", "issuer", publicClient, "label", null, null, 0, 0,
            ChatGptPlanAccount.State.READY, emptySet(), null)
        val publicRegistration = ChatGptPlanValidatedRegistration("issuer", publicClient, publicSubject, "label", null,
            ChatGptPlanTokenSet("", "", "", "Bearer", Instant.EPOCH, Instant.EPOCH.plusSeconds(1), emptySet()))
        assertEquals(publicClient, publicAccount.clientId, "public account client canary follows declared metadata contract")
        assertEquals(publicSubject, publicRegistration.subject, "subject is exposed to the declared identity projection")
        assertFalse(publicRegistration.toString().contains(publicSubject) || publicRegistration.toString().contains(publicClient),
            "secret-bearing validated identity object remains redacted")
    }

    @Test fun capturedSafeDiagnosticChannelsAndSerializationHaveNoSecretBytes() {
        val secret = "canary_stdout_stderr_xml_json_token_" + "012345"
        val refresh = "canary_refresh_" + "987654321"
        val idToken = "canary_id_" + "123456789"
        val token = ChatGptPlanTokenSet(secret, refresh, idToken, "Bearer",
            Instant.EPOCH, Instant.EPOCH.plusSeconds(60), emptySet())
        val serialized = buildString {
            append("<testsuite><testcase name=\"privacy\"><system-out>")
            append(token.toString())
            append("</system-out><system-err>")
            append(ChatGptAuthHttpException(ChatGptAuthHttpFailure.INVALID_BODY, ChatGptAuthDispatchEvidence.NOT_SUBMITTED).toString())
            append("</system-err></testcase></testsuite>")
        }
        val jsonDiagnostic = "{\"tokenSet\":\"${token}\",\"failure\":\"" +
            ChatGptAuthHttpException(ChatGptAuthHttpFailure.INVALID_BODY, ChatGptAuthDispatchEvidence.NOT_SUBMITTED).toString() + "\"}"
        val diagnostics = listOf(serialized, token.toString(), ChatGptAuthHttpException(
            ChatGptAuthHttpFailure.INVALID_BODY, ChatGptAuthDispatchEvidence.NOT_SUBMITTED).toString(), jsonDiagnostic)
        for (diagnostic in diagnostics) {
            assertFalse(diagnostic.contains(secret), "access canary absent from captured diagnostics")
            assertFalse(diagnostic.contains(refresh), "refresh canary absent from captured diagnostics")
            assertFalse(diagnostic.contains(idToken), "ID canary absent from captured diagnostics")
        }
    }
}
