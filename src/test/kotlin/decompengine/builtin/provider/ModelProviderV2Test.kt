package decompengine.builtin.provider

import decompengine.builtin.*
import java.util.UUID
import kotlin.test.*

class ModelProviderV2Test {
    @Test fun `V2 has no V1 inheritance or public permit constructor`() {
        assertFalse(ModelProvider::class.java.isAssignableFrom(ModelProviderV2::class.java))
        assertTrue(AdmittedModelRunV2::class.java.declaredConstructors.any { java.lang.reflect.Modifier.isPrivate(it.modifiers) })
        assertTrue(CheckedAdmissionV2::class.java.declaredConstructors.any { java.lang.reflect.Modifier.isPrivate(it.modifiers) })
        assertFalse(java.io.Serializable::class.java.isAssignableFrom(AdmittedModelRunV2::class.java))
        assertEquals(1, MODEL_PROVIDER_CONTRACT_VERSION)
        assertEquals(8192, ModelCallLimits().maxOutputTokens)
    }
    @Test fun `call and validated turn copy every mutable byte container and redact payloads`() {
        val run = V2Fixture().bind(); val ledger = AttemptLedgerV2(run)
        val bytes = ByteArray(100) { 1 }
        val lease = ledger.reserve(UUID(1, 1), 1, 100, 64)
        ledger.markDispatchIntent(lease, ledger.durableSequence() + 1)
        val call = ledger.call(lease, bytes)
        bytes[0] = 9; call.encodedInput()[1] = 9
        assertEquals(1.toByte(), call.encodedInput()[0]); assertEquals(1.toByte(), call.encodedInput()[1])
        val item = "private-fixture-reasoning".toByteArray(); val items = mutableListOf(item)
        val proposals = mutableListOf<ToolProposalV2>()
        val turn = ValidatedResponsesTurnV1(call, "resp_1", items, proposals, "a".repeat(64))
        val original = turn.orderedItems().single().copyOf()
        item[0] = 0; items.clear(); proposals += ToolProposalV2("decomp", "write", "call_1", "item_1", "{}")
        turn.orderedItems().single()[0] = 0
        assertContentEquals(original, turn.orderedItems().single()); assertTrue(turn.proposals.isEmpty())
        assertFalse(turn.toString().contains("private-fixture"))
        assertFalse(call.toString().contains(run.binding.issuedClient))
        assertEquals("ModelResponseV2(redacted)", ModelResponseV2("secret fixture", ModelFinishReason.STOP, turn, null).toString())
    }
    @Test fun `provider events carry no accounting transition and cannot authorize batches`() {
        val f = BatchFixtureV2()
        val response = f.response(settle = false)
        val seen = mutableListOf<ModelEventV2>()
        val provider = object : ModelProviderV2 {
            override fun capabilities() = ProviderCapabilitiesV2.siwc()
            override fun generate(call: AdmittedModelCallV2, sink: ModelEventV2Sink): ModelResponseV2 {
                sink.emit(ModelEventV2.TextDelta("done")); sink.emit(ModelEventV2.Finished(ModelFinishReason.TOOL_CALLS)); return response
            }
        }
        provider.generate(response.continuation.call, ModelEventV2Sink { seen += it })
        assertEquals(2, seen.size)
        assertFailsWith<ModelProviderException> { f.batch.previewBatch(response) }
        assertEquals(0, f.effects)
    }
}
