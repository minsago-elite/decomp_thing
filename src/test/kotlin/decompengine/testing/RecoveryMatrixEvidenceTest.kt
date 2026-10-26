package decompengine.testing

import java.nio.file.Files
import java.nio.file.Path
import java.nio.file.attribute.PosixFilePermissions
import kotlinx.serialization.json.jsonArray
import kotlinx.serialization.json.jsonObject
import kotlinx.serialization.json.jsonPrimitive
import kotlin.test.Test
import kotlin.test.assertEquals
import kotlin.test.assertFailsWith
import kotlin.test.assertFalse
import kotlin.test.assertTrue
import org.junit.jupiter.api.extension.ExtendWith

@ExtendWith(RecoveryMatrixEvidence::class)
class RecoveryMatrixEvidenceTest {
    @Test
    fun `fixture context binds actual test and omits private directory values`() {
        val directory = recoveryMatrixTempDirectory("PRIVATE-CONTEXT-",
            PosixFilePermissions.asFileAttribute(PosixFilePermissions.fromString("rwx------")))
        try {
            val snapshot = RecoveryMatrixEvidence.snapshot()
            assertEquals(javaClass.name, snapshot.getValue("caseClass").jsonPrimitive.content)
            assertEquals("fixture context binds actual test and omits private directory values()",
                snapshot.getValue("caseMethod").jsonPrimitive.content)
            assertEquals("OBSERVED", snapshot.getValue("filesystemDisposition").jsonPrimitive.content)
            val observed = snapshot.getValue("fixtureRoots").jsonArray.single().jsonObject
            assertEquals("1", observed.getValue("ordinal").jsonPrimitive.content)
            assertEquals(Files.getFileStore(directory).type(), observed.getValue("type").jsonPrimitive.content)
            assertEquals(directory.fileSystem.provider().javaClass.name, observed.getValue("provider").jsonPrimitive.content)
            assertFalse(directory.toString() in snapshot.toString() || "PRIVATE-CONTEXT" in snapshot.toString())
            assertTrue(directory.startsWith(Path.of("").toRealPath()))
            if (Files.getFileStore(directory).supportsFileAttributeView("posix")) {
                assertEquals(PosixFilePermissions.fromString("rwx------"), Files.getPosixFilePermissions(directory))
            }
        } finally { Files.delete(directory) }
    }

    @Test
    fun `each test starts with empty fixture observations and captures an explicit parent`() {
        val before = RecoveryMatrixEvidence.snapshot()
        assertTrue(before.getValue("fixtureRoots").jsonArray.isEmpty())
        assertEquals("NOT_EXERCISED", before.getValue("filesystemDisposition").jsonPrimitive.content)
        val parent = recoveryMatrixTempDirectory("PRIVATE-PARENT-")
        try {
            val child = recoveryMatrixTempDirectory(parent, "PRIVATE-CHILD-")
            try {
                assertEquals(parent, child.parent)
                val roots = RecoveryMatrixEvidence.snapshot().getValue("fixtureRoots").jsonArray
                assertEquals(listOf("1", "2"), roots.map { it.jsonObject.getValue("ordinal").jsonPrimitive.content })
                assertFalse("PRIVATE-" in roots.toString())
            } finally { Files.delete(child) }
        } finally { Files.delete(parent) }
    }

    @Test
    fun `outside parent refuses before directory creation`() {
        val repository = Path.of("").toRealPath()
        assertFailsWith<IllegalArgumentException> {
            requireRecoveryRepositoryParent(repository, repository.parent)
        }
        assertTrue(RecoveryMatrixEvidence.snapshot().getValue("fixtureRoots").jsonArray.isEmpty())
    }
}
