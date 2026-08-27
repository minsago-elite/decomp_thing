package decompengine.repair

import decompengine.acp.LinuxFilesystemSyscalls
import java.nio.file.Path
import kotlin.io.path.createTempDirectory
import kotlin.io.path.exists
import kotlin.io.path.readBytes
import kotlin.test.Test
import kotlin.test.assertContentEquals
import kotlin.test.assertFailsWith
import kotlin.test.assertFalse

class RepairStateStoreTest {
    @Test
    fun `ordinary precommit failure removes a newly published target`() {
        val project = createTempDirectory("repair-state-new-rollback-")
        var armed = false
        withStore(
            project,
            ModuleRevisionFaultInjector { point ->
                if (armed && point == ModuleRevisionFaultPoint.AfterStatePublicationExchange("repair-report", "fresh.json")) {
                    throw IllegalStateException("ordinary precommit failure")
                }
            },
        ) { store ->
            armed = true
            assertFailsWith<IllegalStateException> {
                store.writeReport("fresh.json", "new state".toByteArray())
            }
        }

        assertFalse(project.resolve("reports/fresh.json").exists())
        assertFalse(project.resolve("reports/.fresh.json.repair-atomic.tmp").exists())
    }

    @Test
    fun `ordinary postcommit failure returns successful new publication`() {
        val project = createTempDirectory("repair-state-new-commit-")
        var armed = false
        withStore(
            project,
            ModuleRevisionFaultInjector { point ->
                if (armed && point == ModuleRevisionFaultPoint.AfterStatePublicationDirectorySync("repair-report", "fresh.json")) {
                    throw IllegalStateException("ordinary postcommit failure")
                }
            },
        ) { store ->
            armed = true
            store.writeReport("fresh.json", "committed state".toByteArray())
        }

        assertContentEquals("committed state".toByteArray(), project.resolve("reports/fresh.json").readBytes())
        assertFalse(project.resolve("reports/.fresh.json.repair-atomic.tmp").exists())
    }

    @Test
    fun `non-exception new publication is reusable after reopen`() {
        val project = createTempDirectory("repair-state-new-termination-")
        var armed = false
        assertFailsWith<SimulatedStateTermination> {
            withStore(
                project,
                ModuleRevisionFaultInjector { point ->
                    if (armed && point == ModuleRevisionFaultPoint.AfterStatePublicationExchange("repair-report", "fresh.json")) {
                        throw SimulatedStateTermination()
                    }
                },
            ) { store ->
                armed = true
                store.writeReport("fresh.json", "crash-complete state".toByteArray())
            }
        }
        assertContentEquals("crash-complete state".toByteArray(), project.resolve("reports/fresh.json").readBytes())

        withStore(project) { store ->
            store.writeReport("fresh.json", "replacement state".toByteArray())
        }
        assertContentEquals("replacement state".toByteArray(), project.resolve("reports/fresh.json").readBytes())
        assertFalse(project.resolve("reports/.fresh.json.repair-atomic.tmp").exists())
    }

    private fun withStore(
        project: Path,
        faultInjector: ModuleRevisionFaultInjector? = null,
        action: (RepairStateStore) -> Unit,
    ) {
        LinuxFilesystemSyscalls.requireSupported(project)
        LinuxFilesystemSyscalls.openRoot(project).use { root ->
            RepairStateStore.open(root, faultInjector).use(action)
        }
    }

    private class SimulatedStateTermination : Throwable("simulated state-store process termination")
}
