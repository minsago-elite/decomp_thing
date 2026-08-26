package decompengine.acp

import com.agentclientprotocol.acp.LIB_VERSION
import com.agentclientprotocol.model.AcpMethod
import com.agentclientprotocol.model.AcpNotification
import com.agentclientprotocol.model.AcpRequest
import com.agentclientprotocol.model.AcpResponse
import com.agentclientprotocol.rpc.ACPJson
import com.agentclientprotocol.rpc.JsonRpcNotification
import com.agentclientprotocol.rpc.JsonRpcRequest
import com.agentclientprotocol.rpc.JsonRpcResponse
import com.agentclientprotocol.rpc.decodeJsonRpcMessage
import kotlin.test.Test
import kotlin.test.assertEquals
import kotlin.test.assertIs
import kotlin.test.assertNotNull
import kotlinx.serialization.KSerializer
import kotlinx.serialization.json.JsonElement
import kotlinx.serialization.json.JsonObject
import kotlinx.serialization.json.int
import kotlinx.serialization.json.jsonObject
import kotlinx.serialization.json.jsonPrimitive

/**
 * Versioned ACP v1 golden messages at the SDK boundary.
 *
 * The production adapter uses these same ACP method serializers and JSON-RPC decoder. An SDK
 * upgrade that changes a method name, discriminator, omitted/default field, or request/response
 * shape must therefore fail here with the exact message that drifted. The fixture contains only
 * bounded, synthetic, program-neutral values.
 */
class AcpV1WireContractGoldenTest {
    private val fixture: JsonObject = loadFixture()
    private val messages: JsonObject = fixture.getValue("messages").jsonObject

    @Test
    fun `golden fixture is explicitly versioned for the stable protocol`() {
        assertEquals(
            "decomp-engine-acp-wire-contract",
            fixture.getValue("fixtureFormat").jsonPrimitive.content,
            "unknown ACP golden fixture format",
        )
        assertEquals(
            1,
            fixture.getValue("fixtureFormatVersion").jsonPrimitive.int,
            "ACP golden fixture reader must be updated for a new fixture format",
        )
        assertEquals(
            ACP_STABLE_PROTOCOL_VERSION,
            fixture.getValue("protocolVersion").jsonPrimitive.int,
            "ACP golden protocol version drifted from the production stable-version gate",
        )
        assertEquals(
            ACP_KOTLIN_SDK_VERSION,
            fixture.getValue("sdkArtifactVersion").jsonPrimitive.content,
            "ACP golden fixture must identify the configured Maven artifact version",
        )
        assertEquals(
            LIB_VERSION,
            fixture.getValue("sdkReportedVersion").jsonPrimitive.content,
            "ACP golden fixture must identify the version reported by the linked SDK artifact",
        )
        assertEquals(
            ACP_STABLE_PROTOCOL_VERSION,
            message("initialize.request")
                .getValue("params").jsonObject
                .getValue("protocolVersion").jsonPrimitive.int,
            "initialize must advertise exactly the stable ACP protocol version",
        )
    }

    @Test
    fun `sdk serializers match every versioned v1 golden message`() {
        assertExchange("initialize", AcpMethod.AgentMethods.V1.Initialize)
        assertExchange("session-new", AcpMethod.AgentMethods.V1.SessionNew)
        assertRequest("session-prompt.request", AcpMethod.AgentMethods.V1.SessionPrompt)
        assertResponse(
            "session-prompt-end-turn.response",
            "session-prompt.request",
            AcpMethod.AgentMethods.V1.SessionPrompt,
        )
        assertResponse(
            "session-prompt-max-tokens.response",
            "session-prompt.request",
            AcpMethod.AgentMethods.V1.SessionPrompt,
        )
        assertResponse(
            "session-prompt-max-turn-requests.response",
            "session-prompt.request",
            AcpMethod.AgentMethods.V1.SessionPrompt,
        )
        assertResponse(
            "session-prompt-refusal.response",
            "session-prompt.request",
            AcpMethod.AgentMethods.V1.SessionPrompt,
        )
        assertResponse(
            "session-prompt-cancelled.response",
            "session-prompt.request",
            AcpMethod.AgentMethods.V1.SessionPrompt,
        )
        assertNotification(
            "session-update-agent-message.notification",
            AcpMethod.ClientMethods.V1.SessionUpdate,
        )
        assertNotification(
            "session-update-user-message.notification",
            AcpMethod.ClientMethods.V1.SessionUpdate,
        )
        assertNotification(
            "session-update-agent-thought.notification",
            AcpMethod.ClientMethods.V1.SessionUpdate,
        )
        assertNotification("session-update-plan.notification", AcpMethod.ClientMethods.V1.SessionUpdate)
        assertNotification("session-update-tool-call.notification", AcpMethod.ClientMethods.V1.SessionUpdate)
        assertNotification(
            "session-update-tool-call-update.notification",
            AcpMethod.ClientMethods.V1.SessionUpdate,
        )
        assertExchange("fs-read", AcpMethod.ClientMethods.V1.FsReadTextFile)
        assertExchange("fs-write", AcpMethod.ClientMethods.V1.FsWriteTextFile)
        assertExchange("terminal-create", AcpMethod.ClientMethods.V1.TerminalCreate)
        assertExchange("terminal-output", AcpMethod.ClientMethods.V1.TerminalOutput)
        assertExchange("terminal-wait-for-exit", AcpMethod.ClientMethods.V1.TerminalWaitForExit)
        assertExchange("terminal-kill", AcpMethod.ClientMethods.V1.TerminalKill)
        assertExchange("terminal-release", AcpMethod.ClientMethods.V1.TerminalRelease)
        assertExchange("permission", AcpMethod.ClientMethods.V1.SessionRequestPermission)
        assertNotification("session-cancel.notification", AcpMethod.AgentMethods.V1.SessionCancel)

        assertEquals(
            EXPECTED_MESSAGE_NAMES,
            messages.keys,
            "ACP v1 golden fixture has an unvalidated or missing message",
        )
    }

    private fun <TRequest : AcpRequest, TResponse : AcpResponse> assertExchange(
        name: String,
        method: AcpMethod.AcpRequestResponseMethod<TRequest, TResponse>,
    ) {
        val requestName = "$name.request"
        val responseName = "$name.response"
        assertRequest(requestName, method)
        assertResponse(responseName, requestName, method)
    }

    private fun <TRequest : AcpRequest, TResponse : AcpResponse> assertRequest(
        requestName: String,
        method: AcpMethod.AcpRequestResponseMethod<TRequest, TResponse>,
    ) {
        val request = message(requestName)

        val decodedRequest = assertIs<JsonRpcRequest>(
            decodeJsonRpcMessage(request.toString()),
            "$requestName is not a JSON-RPC request accepted by the production decoder",
        )
        assertEquals(
            method.toString(),
            request.getValue("method").jsonPrimitive.content,
            driftMessage(requestName, "method name"),
        )
        assertTypedRoundTrip(
            requestName,
            method.requestSerializer,
            assertNotNull(decodedRequest.params, "$requestName must carry params"),
        )
        assertEnvelopeRoundTrip(requestName, request)
    }

    private fun <TRequest : AcpRequest, TResponse : AcpResponse> assertResponse(
        responseName: String,
        requestName: String,
        method: AcpMethod.AcpRequestResponseMethod<TRequest, TResponse>,
    ) {
        val request = message(requestName)
        val response = message(responseName)

        val decodedResponse = assertIs<JsonRpcResponse>(
            decodeJsonRpcMessage(response.toString()),
            "$responseName is not a JSON-RPC response accepted by the production decoder",
        )
        assertEquals(
            request.getValue("id"),
            response.getValue("id"),
            "$responseName must correlate with $requestName",
        )
        assertTypedRoundTrip(
            responseName,
            method.responseSerializer,
            assertNotNull(decodedResponse.result, "$responseName must carry result"),
        )
        assertEnvelopeRoundTrip(responseName, response)
    }

    private fun <TNotification : AcpNotification> assertNotification(
        name: String,
        method: AcpMethod.AcpNotificationMethod<TNotification>,
    ) {
        val notification = message(name)
        val decoded = assertIs<JsonRpcNotification>(
            decodeJsonRpcMessage(notification.toString()),
            "$name is not a JSON-RPC notification accepted by the production decoder",
        )
        assertEquals(
            method.toString(),
            notification.getValue("method").jsonPrimitive.content,
            driftMessage(name, "method name"),
        )
        assertTypedRoundTrip(
            name,
            method.serializer,
            assertNotNull(decoded.params, "$name must carry params"),
        )
        assertEnvelopeRoundTrip(name, notification)
    }

    private fun <T> assertTypedRoundTrip(name: String, serializer: KSerializer<T>, params: JsonElement) {
        val decoded = ACPJson.decodeFromJsonElement(serializer, params)
        val encoded = ACPJson.encodeToJsonElement(serializer, decoded)
        assertEquals(params, encoded, driftMessage(name, "typed params/result schema"))
    }

    private fun assertEnvelopeRoundTrip(name: String, expected: JsonObject) {
        val decoded = decodeJsonRpcMessage(expected.toString())
        val encoded = when (decoded) {
            is JsonRpcRequest -> ACPJson.encodeToJsonElement(JsonRpcRequest.serializer(), decoded)
            is JsonRpcNotification -> ACPJson.encodeToJsonElement(JsonRpcNotification.serializer(), decoded)
            is JsonRpcResponse -> ACPJson.encodeToJsonElement(JsonRpcResponse.serializer(), decoded)
        }
        assertEquals(expected, encoded, driftMessage(name, "JSON-RPC envelope"))
    }

    private fun message(name: String): JsonObject =
        messages[name]?.jsonObject ?: error("ACP v1 golden fixture is missing $name")

    private fun driftMessage(name: String, surface: String): String =
        "ACP v1 SDK wire drift in $name ($surface); review the protocol change before updating " +
            "src/test/resources/acp/v1/wire-contract.json"

    private fun loadFixture(): JsonObject {
        val resource = requireNotNull(javaClass.getResource("/acp/v1/wire-contract.json")) {
            "missing versioned ACP v1 wire-contract fixture"
        }
        val text = resource.readText(Charsets.UTF_8)
        require(text.toByteArray(Charsets.UTF_8).size <= MAX_FIXTURE_BYTES) {
            "ACP v1 wire-contract fixture exceeds the $MAX_FIXTURE_BYTES-byte test bound"
        }
        return ACPJson.parseToJsonElement(text).jsonObject
    }

    private companion object {
        const val MAX_FIXTURE_BYTES: Int = 64 * 1024

        val EXPECTED_MESSAGE_NAMES: Set<String> = linkedSetOf(
            "initialize.request",
            "initialize.response",
            "session-new.request",
            "session-new.response",
            "session-prompt.request",
            "session-prompt-end-turn.response",
            "session-prompt-max-tokens.response",
            "session-prompt-max-turn-requests.response",
            "session-prompt-refusal.response",
            "session-prompt-cancelled.response",
            "session-update-agent-message.notification",
            "session-update-user-message.notification",
            "session-update-agent-thought.notification",
            "session-update-plan.notification",
            "session-update-tool-call.notification",
            "session-update-tool-call-update.notification",
            "fs-read.request",
            "fs-read.response",
            "fs-write.request",
            "fs-write.response",
            "terminal-create.request",
            "terminal-create.response",
            "terminal-output.request",
            "terminal-output.response",
            "terminal-wait-for-exit.request",
            "terminal-wait-for-exit.response",
            "terminal-kill.request",
            "terminal-kill.response",
            "terminal-release.request",
            "terminal-release.response",
            "permission.request",
            "permission.response",
            "session-cancel.notification",
        )
    }
}
