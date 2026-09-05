package decompengine.acp

import com.agentclientprotocol.model.AuthMethod
import com.agentclientprotocol.rpc.ACPJson
import decompengine.jobs.ProgressRedactor
import decompengine.oracle.core.OracleJson
import decompengine.oracle.core.StrictJsonException
import decompengine.oracle.core.StrictJsonLimits
import kotlinx.serialization.json.*
import java.security.MessageDigest
import java.util.Collections

/** Operator-only advertisement; no method is executable merely because it appears here. */
class AcpAuthenticationMethod internal constructor(
    val id: String,
    val variant: String,
    val idPreview: String,
    val namePreview: String,
    val descriptionPreview: String?,
) {
    val loginSupported: Boolean = false
    override fun toString(): String = "AcpAuthenticationMethod(variant=$variant, loginSupported=false)"
}

class AcpAuthenticationInventory private constructor(
    methods: List<AcpAuthenticationMethod>,
    val sha256: String,
    val logoutAdvertised: Boolean,
) {
    /** Advertisement does not grant permission or establish an executable logout lifecycle. */
    val logoutSupported: Boolean = false
    val methods: List<AcpAuthenticationMethod> = Collections.unmodifiableList(methods.toList())
    override fun toString(): String = "AcpAuthenticationInventory(count=${methods.size}, sha256=$sha256)"

    companion object {
        internal fun capture(
            methods: List<AuthMethod>,
            sensitiveValues: Collection<String>,
            logoutAdvertised: Boolean = false,
        ): AcpAuthenticationInventory {
            requireInventory(methods.size <= 32) { "ACP authentication inventory exceeds its method limit" }
            val ids = HashSet<String>()
            val redactor = ProgressRedactor(sensitiveValues)
            val commitment = buildJsonArray {
                methods.forEach { method ->
                    requireInventory(method.id.value.isNotBlank() && method.id.value.toByteArray().size <= 256 && ids.add(method.id.value)) {
                        "ACP authentication inventory contains an invalid or duplicate method ID"
                    }
                    requireInventory(method.name.toByteArray().size <= 512 && (method.description?.toByteArray()?.size ?: 0) <= 2048) {
                        "ACP authentication inventory exceeds its text limit"
                    }
                    add(buildJsonObject {
                        put("id", method.id.value); put("variant", variant(method))
                        put("name", method.name); put("description", method.description?.let(::JsonPrimitive) ?: JsonNull)
                    })
                }
            }
            validatePayload(methods)
            val digest = MessageDigest.getInstance("SHA-256").digest(OracleJson.canonicalBytes(commitment))
                .joinToString("") { "%02x".format(it) }
            return AcpAuthenticationInventory(methods.map {
                AcpAuthenticationMethod(it.id.value, variant(it), redactor.text(it.id.value, 128), redactor.text(it.name, 128),
                    it.description?.let { description -> redactor.text(description, 256) })
            }, digest, logoutAdvertised)
        }

        /** Bound all SDK-retained fields, including metadata and unsupported variant payloads. */
        private fun validatePayload(methods: List<AuthMethod>) {
            val payload = buildJsonArray {
                methods.forEach { add(ACPJson.encodeToJsonElement(AuthMethod.serializer(), it)) }
            }
            try {
                OracleJson.canonicalBytes(payload, StrictJsonLimits(
                    maximumCanonicalBytes = 64 * 1024,
                    maximumDepth = 16,
                    maximumNodes = 4096,
                    maximumNumberCharacters = 256,
                    maximumStringBytes = 16 * 1024,
                    maximumTotalStringBytes = 64 * 1024,
                ))
            } catch (_: StrictJsonException) {
                throw AcpAuthenticationInventoryFailure("ACP authentication inventory exceeds its payload limits")
            }
        }

        private inline fun requireInventory(condition: Boolean, message: () -> String) {
            if (!condition) throw AcpAuthenticationInventoryFailure(message())
        }

        private fun variant(method: AuthMethod): String = when (method) {
            is AuthMethod.AgentAuth -> "agent"
            is AuthMethod.EnvVarAuth -> "environment"
            is AuthMethod.TerminalAuth -> "terminal"
            else -> "unknown"
        }
    }
}

internal class AcpAuthenticationInventoryFailure(message: String) : IllegalArgumentException(message)
