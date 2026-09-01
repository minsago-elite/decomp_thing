package decompengine.oracle.behavior

import java.nio.charset.StandardCharsets
import java.util.Collections

internal class LlvmBehaviorHostedContainerV1DockerOutputException(message: String) :
    IllegalArgumentException(message)

/** Immutable, non-authoritative projection of one syntactically accepted create-output candidate. */
internal data class LlvmBehaviorHostedContainerV1CreateOutputProjection(
    val containerId: String,
)

/** Immutable, non-authoritative projection of one syntactically accepted ID acknowledgement candidate. */
internal data class LlvmBehaviorHostedContainerV1AcknowledgementProjection(
    val containerId: String,
)

/** Immutable, non-authoritative projection of one syntactically accepted wait-output candidate. */
internal data class LlvmBehaviorHostedContainerV1WaitOutputProjection(
    val statusCode: Int,
)

/** Immutable, non-authoritative projection of a bounded ID-only container inventory. */
internal data class LlvmBehaviorHostedContainerV1InventoryOutputProjection(
    val containerIds: List<String>,
)

/**
 * Parses the exact Linux stdout grammar emitted by the hosted-container v1 Docker CLI suffixes.
 *
 * These functions parse stdout bytes only. They do not run Docker, inspect stderr or process exit
 * state, authenticate a Docker endpoint, establish a lifecycle fact, authorize START or cleanup,
 * or grant oracle authority. A live coordinator must bind those concerns separately.
 */
internal object LlvmBehaviorHostedContainerV1DockerOutput {
    fun parseCreate(stdoutBytes: ByteArray): LlvmBehaviorHostedContainerV1CreateOutputProjection =
        LlvmBehaviorHostedContainerV1CreateOutputProjection(
            containerId = parseContainerIdLine(stdoutBytes, "container create stdout"),
        )

    fun parseStartAcknowledgement(
        stdoutBytes: ByteArray,
        expectedContainerId: String,
    ): LlvmBehaviorHostedContainerV1AcknowledgementProjection =
        parseExpectedAcknowledgement(stdoutBytes, expectedContainerId, "container start stdout")

    fun parseWait(stdoutBytes: ByteArray): LlvmBehaviorHostedContainerV1WaitOutputProjection {
        if (stdoutBytes.size !in MINIMUM_WAIT_BYTES..MAXIMUM_WAIT_BYTES) {
            dockerOutputFail("container wait stdout is not one bounded status record")
        }
        if (stdoutBytes.last() != LINE_FEED) {
            dockerOutputFail("container wait stdout is not LF-terminated")
        }

        val digitCount = stdoutBytes.size - 1
        if (digitCount > 1 && stdoutBytes[0] == ASCII_ZERO) {
            dockerOutputFail("container wait status is not canonical decimal")
        }
        var statusCode = 0
        for (index in 0 until digitCount) {
            val byte = stdoutBytes[index]
            if (byte !in ASCII_ZERO..ASCII_NINE) {
                dockerOutputFail("container wait status contains a non-decimal byte")
            }
            statusCode = statusCode * 10 + (byte - ASCII_ZERO)
        }
        if (statusCode !in MINIMUM_CONTAINER_STATUS..MAXIMUM_CONTAINER_STATUS) {
            dockerOutputFail("container wait status is outside the accepted range")
        }
        return LlvmBehaviorHostedContainerV1WaitOutputProjection(statusCode)
    }

    fun parseRemoveAcknowledgement(
        stdoutBytes: ByteArray,
        expectedContainerId: String,
    ): LlvmBehaviorHostedContainerV1AcknowledgementProjection =
        parseExpectedAcknowledgement(stdoutBytes, expectedContainerId, "container remove stdout")

    fun parseInventory(stdoutBytes: ByteArray): LlvmBehaviorHostedContainerV1InventoryOutputProjection {
        if (stdoutBytes.isEmpty()) {
            return LlvmBehaviorHostedContainerV1InventoryOutputProjection(emptyList())
        }
        if (stdoutBytes.size > MAXIMUM_INVENTORY_BYTES || stdoutBytes.size % CONTAINER_ID_LINE_BYTES != 0) {
            dockerOutputFail("container inventory stdout is not a bounded sequence of complete ID records")
        }

        val recordCount = stdoutBytes.size / CONTAINER_ID_LINE_BYTES
        if (recordCount !in 1..MAXIMUM_INVENTORY_RECORDS) {
            dockerOutputFail("container inventory stdout has too many records")
        }
        val ids = ArrayList<String>(recordCount)
        val uniqueIds = HashSet<String>(recordCount)
        for (recordIndex in 0 until recordCount) {
            val offset = recordIndex * CONTAINER_ID_LINE_BYTES
            val containerId = parseContainerIdAt(stdoutBytes, offset, "container inventory record $recordIndex")
            if (!uniqueIds.add(containerId)) {
                dockerOutputFail("container inventory stdout contains a duplicate ID")
            }
            ids.add(containerId)
        }
        return LlvmBehaviorHostedContainerV1InventoryOutputProjection(
            Collections.unmodifiableList(ids),
        )
    }
}

private fun parseExpectedAcknowledgement(
    stdoutBytes: ByteArray,
    expectedContainerId: String,
    label: String,
): LlvmBehaviorHostedContainerV1AcknowledgementProjection {
    requireContainerId(expectedContainerId, "expected container ID")
    val parsedContainerId = parseContainerIdLine(stdoutBytes, label)
    if (parsedContainerId != expectedContainerId) {
        dockerOutputFail("$label does not acknowledge the expected container ID")
    }
    return LlvmBehaviorHostedContainerV1AcknowledgementProjection(parsedContainerId)
}

private fun parseContainerIdLine(stdoutBytes: ByteArray, label: String): String {
    if (stdoutBytes.size != CONTAINER_ID_LINE_BYTES) {
        dockerOutputFail("$label is not exactly one container ID record")
    }
    return parseContainerIdAt(stdoutBytes, 0, label)
}

private fun parseContainerIdAt(stdoutBytes: ByteArray, offset: Int, label: String): String {
    for (index in 0 until CONTAINER_ID_CHARACTERS) {
        if (!stdoutBytes[offset + index].isLowerHex()) {
            dockerOutputFail("$label contains a malformed container ID")
        }
    }
    if (stdoutBytes[offset + CONTAINER_ID_CHARACTERS] != LINE_FEED) {
        dockerOutputFail("$label is not LF-terminated")
    }
    return String(stdoutBytes, offset, CONTAINER_ID_CHARACTERS, StandardCharsets.US_ASCII)
}

private fun requireContainerId(containerId: String, label: String) {
    if (containerId.length != CONTAINER_ID_CHARACTERS || containerId.any { !it.isLowerHex() }) {
        dockerOutputFail("$label is malformed")
    }
}

private fun Byte.isLowerHex(): Boolean = this in ASCII_ZERO..ASCII_NINE || this in ASCII_A..ASCII_F

private fun Char.isLowerHex(): Boolean = this in '0'..'9' || this in 'a'..'f'

private fun dockerOutputFail(message: String): Nothing =
    throw LlvmBehaviorHostedContainerV1DockerOutputException(message)

private const val CONTAINER_ID_CHARACTERS = 64
private const val CONTAINER_ID_LINE_BYTES = CONTAINER_ID_CHARACTERS + 1
private const val MAXIMUM_INVENTORY_RECORDS = 16
private const val MAXIMUM_INVENTORY_BYTES = MAXIMUM_INVENTORY_RECORDS * CONTAINER_ID_LINE_BYTES
private const val MINIMUM_WAIT_BYTES = 2
private const val MAXIMUM_WAIT_BYTES = 4
private const val MINIMUM_CONTAINER_STATUS = 0
private const val MAXIMUM_CONTAINER_STATUS = 255
private const val LINE_FEED: Byte = 0x0a
private const val ASCII_ZERO: Byte = 0x30
private const val ASCII_NINE: Byte = 0x39
private const val ASCII_A: Byte = 0x61
private const val ASCII_F: Byte = 0x66
