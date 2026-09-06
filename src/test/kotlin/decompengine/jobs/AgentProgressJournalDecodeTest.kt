package decompengine.jobs

import java.nio.file.Files
import kotlin.io.path.createTempDirectory
import kotlin.test.*

class AgentProgressJournalDecodeTest {
    @Test fun `byte decoding matches a persisted journal without reopening its path`() {
        val root = createTempDirectory("progress-decode-")
        try {
            AgentProgressJournal(root, "reconstruct").use { }
            val path = root.resolve(AgentProgressJournal.FILE_NAME)
            val bytes = Files.readAllBytes(path)
            val expected = AgentProgressJournal.read(root)
            Files.delete(path)
            assertEquals(expected, AgentProgressJournal.decode(bytes))
            assertNull(AgentProgressJournal.read(root))
        } finally {
            Files.walk(root).use { paths -> paths.sorted(Comparator.reverseOrder()).forEach(Files::deleteIfExists) }
        }
    }

    @Test fun `decoder retains exact sequence boundaries and explicit omissions`() {
        val bytes = snapshot("9223372036854775806", """{"sequence":9223372036854775804},{"sequence":9223372036854775805}""",
            historyDropped = "9223372036854775804")
        val decoded = AgentProgressJournal.decode(bytes)
        assertTrue(decoded.toString().contains("9223372036854775805"))
        assertTrue(decoded.toString().contains("\"historyDropped\":9223372036854775804"))
    }

    @Test fun `decoder rejects oversized malformed and ambiguous snapshots`() {
        val invalid = listOf(
            ByteArray(AgentProgressJournal.MAXIMUM_READ_BYTES + 1) { 32 },
            "{".toByteArray(),
            snapshot("2", """{"sequence":1},{"sequence":1}"""),
            snapshot("2", """{"sequence":2}"""),
            snapshot("2", """{"sequence":-1}"""),
            snapshot("9223372036854775807", ""),
            snapshot("2", "").toString(Charsets.UTF_8).replace("\"displayOnly\":true", "\"displayOnly\":false").toByteArray(),
            snapshot("2", "").toString(Charsets.UTF_8).replace("\"schemaVersion\":1", "\"schemaVersion\":1,\"schemaVersion\":1").toByteArray(),
            snapshot("2000", (0..1024).joinToString(",") { "{\"sequence\":$it}" }),
        )
        invalid.forEachIndexed { index, bytes -> assertFails("invalid snapshot $index") { AgentProgressJournal.decode(bytes) } }
    }

    private fun snapshot(next: String, events: String, historyDropped: String = "3"): ByteArray =
        """{"schemaVersion":1,"displayOnly":true,"nextSequence":$next,"queueDropped":0,"historyDropped":$historyDropped,"truncated":true,"events":[$events]}""".toByteArray()
}
