package decompengine.oracle.behavior

import java.lang.reflect.Modifier
import kotlin.test.Test
import kotlin.test.assertEquals
import kotlin.test.assertFailsWith
import kotlin.test.assertTrue

class LlvmBehaviorHostedContainerV1DockerOutputTest {
    @Test
    fun `canonical create acknowledgement wait and inventory bytes produce immutable projections`() {
        val otherId = "0123456789abcdef".repeat(4)
        val createBytes = "$CONTAINER_ID\n".encodeToByteArray()
        val inventoryBytes = "$CONTAINER_ID\n$otherId\n".encodeToByteArray()

        val create = LlvmBehaviorHostedContainerV1DockerOutput.parseCreate(createBytes)
        val start = LlvmBehaviorHostedContainerV1DockerOutput.parseStartAcknowledgement(
            "$CONTAINER_ID\n".encodeToByteArray(),
            CONTAINER_ID,
        )
        val wait = LlvmBehaviorHostedContainerV1DockerOutput.parseWait("137\n".encodeToByteArray())
        val remove = LlvmBehaviorHostedContainerV1DockerOutput.parseRemoveAcknowledgement(
            "$CONTAINER_ID\n".encodeToByteArray(),
            CONTAINER_ID,
        )
        val inventory = LlvmBehaviorHostedContainerV1DockerOutput.parseInventory(inventoryBytes)

        createBytes.fill('0'.code.toByte())
        inventoryBytes.fill('0'.code.toByte())
        assertEquals(CONTAINER_ID, create.containerId)
        assertEquals(CONTAINER_ID, start.containerId)
        assertEquals(137, wait.statusCode)
        assertEquals(CONTAINER_ID, remove.containerId)
        assertEquals(listOf(CONTAINER_ID, otherId), inventory.containerIds)

        @Suppress("UNCHECKED_CAST")
        val mutableInventory = inventory.containerIds as MutableList<String>
        assertFailsWith<UnsupportedOperationException> { mutableInventory.add("f".repeat(64)) }
        assertFailsWith<UnsupportedOperationException> { mutableInventory[0] = "f".repeat(64) }

        listOf(create, start, wait, remove, inventory).forEach { projection ->
            val fields = projection.javaClass.declaredFields.filterNot { Modifier.isStatic(it.modifiers) }
            assertTrue(fields.none { it.type == Boolean::class.java || it.type == Boolean::class.javaObjectType })
            assertTrue(fields.none { it.type == Process::class.java || it.type == ProcessBuilder::class.java })
        }
    }

    @Test
    fun `create rejects every noncanonical ID record shape`() {
        val mutations = listOf(
            byteArrayOf(),
            CONTAINER_ID.encodeToByteArray(),
            "$CONTAINER_ID\r\n".encodeToByteArray(),
            "$CONTAINER_ID\n\n".encodeToByteArray(),
            "${CONTAINER_ID.dropLast(1)}\n".encodeToByteArray(),
            "${CONTAINER_ID}0\n".encodeToByteArray(),
            "${CONTAINER_ID.uppercase()}\n".encodeToByteArray(),
            "sha256:$CONTAINER_ID\n".encodeToByteArray(),
            " $CONTAINER_ID\n".encodeToByteArray(),
            "${CONTAINER_ID.dropLast(1)}g\n".encodeToByteArray(),
            "$CONTAINER_ID\n$CONTAINER_ID\n".encodeToByteArray(),
        )

        mutations.forEachIndexed { index, bytes ->
            assertFailsWith<LlvmBehaviorHostedContainerV1DockerOutputException>("mutation $index") {
                LlvmBehaviorHostedContainerV1DockerOutput.parseCreate(bytes)
            }
        }
    }

    @Test
    fun `start and remove require the well-formed cross-paired expected ID`() {
        val otherId = "c".repeat(64)
        listOf<(ByteArray, String) -> Unit>(
            { bytes, expected ->
                LlvmBehaviorHostedContainerV1DockerOutput.parseStartAcknowledgement(bytes, expected)
            },
            { bytes, expected ->
                LlvmBehaviorHostedContainerV1DockerOutput.parseRemoveAcknowledgement(bytes, expected)
            },
        ).forEachIndexed { parserIndex, parser ->
            parser("$CONTAINER_ID\n".encodeToByteArray(), CONTAINER_ID)
            assertFailsWith<LlvmBehaviorHostedContainerV1DockerOutputException>("cross-pair $parserIndex") {
                parser("$otherId\n".encodeToByteArray(), CONTAINER_ID)
            }
            assertFailsWith<LlvmBehaviorHostedContainerV1DockerOutputException>("short expected $parserIndex") {
                parser("$CONTAINER_ID\n".encodeToByteArray(), CONTAINER_ID.dropLast(1))
            }
            assertFailsWith<LlvmBehaviorHostedContainerV1DockerOutputException>("uppercase expected $parserIndex") {
                parser("$CONTAINER_ID\n".encodeToByteArray(), CONTAINER_ID.uppercase())
            }
            assertFailsWith<LlvmBehaviorHostedContainerV1DockerOutputException>("CRLF $parserIndex") {
                parser("$CONTAINER_ID\r\n".encodeToByteArray(), CONTAINER_ID)
            }
        }
    }

    @Test
    fun `wait accepts only canonical decimal Linux container statuses`() {
        listOf(0, 1, 125, 126, 127, 137, 255).forEach { status ->
            assertEquals(
                status,
                LlvmBehaviorHostedContainerV1DockerOutput.parseWait("$status\n".encodeToByteArray()).statusCode,
            )
        }

        listOf(
            "",
            "\n",
            "00\n",
            "01\n",
            "+1\n",
            "-1\n",
            " 1\n",
            "1 \n",
            "1\r\n",
            "1",
            "1\n\n",
            "256\n",
            "999\n",
            "1000\n",
            "１\n",
        ).forEach { output ->
            assertFailsWith<LlvmBehaviorHostedContainerV1DockerOutputException>(output) {
                LlvmBehaviorHostedContainerV1DockerOutput.parseWait(output.encodeToByteArray())
            }
        }
    }

    @Test
    fun `inventory accepts empty or bounded unique IDs and rejects hostile record streams`() {
        assertEquals(
            emptyList(),
            LlvmBehaviorHostedContainerV1DockerOutput.parseInventory(byteArrayOf()).containerIds,
        )
        val maximumIds = (0 until 16).map { index -> index.toString(16).padStart(64, '0') }
        assertEquals(
            maximumIds,
            LlvmBehaviorHostedContainerV1DockerOutput.parseInventory(
                maximumIds.joinToString(separator = "\n", postfix = "\n").encodeToByteArray(),
            ).containerIds,
        )

        val otherId = "c".repeat(64)
        val malformed = listOf(
            CONTAINER_ID.encodeToByteArray(),
            "$CONTAINER_ID\r\n".encodeToByteArray(),
            "$CONTAINER_ID\n\n".encodeToByteArray(),
            "$CONTAINER_ID\n$CONTAINER_ID\n".encodeToByteArray(),
            "${CONTAINER_ID.uppercase()}\n".encodeToByteArray(),
            "sha256:$CONTAINER_ID\n".encodeToByteArray(),
            " $CONTAINER_ID\n".encodeToByteArray(),
            "$CONTAINER_ID \n".encodeToByteArray(),
            "$CONTAINER_ID\n${otherId.dropLast(1)}\n".encodeToByteArray(),
            (0 until 17)
                .joinToString(separator = "\n", postfix = "\n") { index ->
                    index.toString(16).padStart(64, '0')
                }
                .encodeToByteArray(),
            ByteArray(16 * 65 + 1) { 'a'.code.toByte() },
        )
        malformed.forEachIndexed { index, bytes ->
            assertFailsWith<LlvmBehaviorHostedContainerV1DockerOutputException>("mutation $index") {
                LlvmBehaviorHostedContainerV1DockerOutput.parseInventory(bytes)
            }
        }
    }
}

private const val CONTAINER_ID = "bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb"
