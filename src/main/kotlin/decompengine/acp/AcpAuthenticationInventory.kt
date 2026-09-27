package decompengine.acp

import com.agentclientprotocol.model.AuthMethod
import com.agentclientprotocol.rpc.ACPJson
import decompengine.jobs.ProgressRedactor
import decompengine.oracle.core.OracleJson
import decompengine.oracle.core.StrictJsonException
import decompengine.oracle.core.StrictJsonLimits
import kotlinx.serialization.json.*
import java.util.Collections
import java.util.UUID
import javax.crypto.KeyGenerator
import javax.crypto.Mac

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
    val commitment: String,
    val logoutAdvertised: Boolean,
) {
    val commitmentFormat: String = COMMITMENT_FORMAT
    val commitmentScope: String = COMMITMENT_SCOPE

    /** Advertisement does not grant permission or establish an executable logout lifecycle. */
    val logoutSupported: Boolean = false
    val methods: List<AcpAuthenticationMethod> = Collections.unmodifiableList(methods.toList())
    override fun toString(): String = "AcpAuthenticationInventory(count=${methods.size}, commitment=$commitment, scope=$commitmentScope)"

    companion object {
        private const val COMMITMENT_FORMAT = "sdk-auth-methods-hmac-sha256-v2"
        // Never persist or expose this key. Comparisons are valid only within this JVM's scope.
        private val COMMITMENT_KEY = KeyGenerator.getInstance("HmacSHA256").apply { init(256) }.generateKey()
        private val COMMITMENT_SCOPE = UUID.randomUUID().toString()

        internal fun capture(
            methods: List<AuthMethod>,
            sensitiveValues: Collection<String>,
            logoutAdvertised: Boolean = false,
        ): AcpAuthenticationInventory {
            if (methods.size > 32) throw AcpProtocolFailure("ACP authentication inventory exceeds its method limit")
            val ids = HashSet<String>()
            val redactor = ProgressRedactor(sensitiveValues)
            val fragments = AuthenticationPreviewFragments(sensitiveValues)
            fun preview(text: String, limit: Int) = fragments.conceal(redactor.text(text, limit))
            methods.forEach { method ->
                if (method.id.value.isBlank() || method.id.value.toByteArray().size > 256 || !ids.add(method.id.value)) {
                    throw AcpProtocolFailure("ACP authentication inventory contains an invalid or duplicate method ID")
                }
                if (method.name.toByteArray().size > 512 || (method.description?.toByteArray()?.size ?: 0) > 2048) {
                    throw AcpProtocolFailure("ACP authentication inventory exceeds its text limit")
                }
                listOfNotNull(method.id.value, method.name, method.description).forEach { value ->
                    if (!Charsets.UTF_8.newEncoder().canEncode(value)) {
                        throw AcpProtocolFailure("ACP authentication inventory contains invalid Unicode")
                    }
                }
            }
            val payload = canonicalPayload(methods)
            val hash = Mac.getInstance("HmacSHA256").apply { init(COMMITMENT_KEY) }
            hash.update(COMMITMENT_FORMAT.toByteArray(Charsets.UTF_8))
            hash.update(0.toByte())
            val digest = hash.doFinal(payload).joinToString("") { "%02x".format(it) }
            return AcpAuthenticationInventory(methods.map {
                AcpAuthenticationMethod(it.id.value, variant(it), preview(it.id.value, 128), preview(it.name, 128),
                    it.description?.let { description -> preview(description, 256) })
            }, digest, logoutAdvertised)
        }

        /** Bound all SDK-retained fields, including metadata and unsupported variant payloads. */
        private fun canonicalPayload(methods: List<AuthMethod>): ByteArray {
            val payload = buildJsonArray {
                methods.forEach { add(ACPJson.encodeToJsonElement(AuthMethod.serializer(), it)) }
            }
            return try {
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

        private fun variant(method: AuthMethod): String = when (method) {
            is AuthMethod.AgentAuth -> "agent"
            is AuthMethod.EnvVarAuth -> "environment"
            is AuthMethod.TerminalAuth -> "terminal"
            else -> "unknown"
        }
    }
}

internal class AcpAuthenticationInventoryFailure(message: String) : IllegalArgumentException(message)
