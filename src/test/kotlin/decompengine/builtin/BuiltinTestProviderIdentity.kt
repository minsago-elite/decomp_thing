package decompengine.builtin

import decompengine.builtin.provider.ModelEvent
import decompengine.builtin.provider.ModelProvider
import decompengine.builtin.provider.ModelProviderIdentity
import decompengine.builtin.provider.ModelRequest
import decompengine.builtin.provider.ModelResponse

internal val BUILTIN_TEST_PROVIDER_IDENTITY = ModelProviderIdentity("fixture", "scripted-v1")

internal fun ModelProvider.withBuiltinTestIdentity(identity: ModelProviderIdentity = BUILTIN_TEST_PROVIDER_IDENTITY): ModelProvider {
    val delegate = this
    return object : ModelProvider {
        override val identity = identity
        override fun generate(request: ModelRequest, onEvent: (ModelEvent) -> Unit): ModelResponse = delegate.generate(request, onEvent)
    }
}
