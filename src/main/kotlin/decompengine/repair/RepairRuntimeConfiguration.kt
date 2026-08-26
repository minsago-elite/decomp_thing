package decompengine.repair

import java.nio.file.FileSystems
import java.nio.file.Path

/**
 * Data-only configuration accepted by [SecureRepairRuntime].
 *
 * Executable profiles, transports, validation strategies, staging authorities, callbacks, and
 * filesystem implementations are deliberately absent. Production implementations are selected
 * from the application-owned registry inside the Java gate.
 */
class RepairRuntimeConfiguration(
    profileId: String,
    historyPath: Path,
    val resourceBudget: RepairResourceBudget = RepairResourceBudget(),
) {
    val profileId: String = profileId.also {
        require(it.matches(Regex("[A-Za-z0-9_][A-Za-z0-9_.-]{0,127}"))) { "invalid repair profile ID" }
    }

    val historyPath: Path = historyPath.also {
        require(it.fileSystem == FileSystems.getDefault()) {
            "secure repair history requires the default filesystem provider"
        }
    }.toAbsolutePath().normalize()
}
