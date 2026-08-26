package decompengine.project

import decompengine.repair.RepairIndexProfile
import decompengine.repair.RepairRuntimeProfileProvider
import decompengine.repair.RepairValidationStrategy

/** Application adapter registration for generated C/Make projects. */
class GeneratedCRepairRuntimeProvider : RepairRuntimeProfileProvider {
    override fun profileId(): String = GeneratedCRepairIndexProfile.profileId()

    override fun indexProfile(): RepairIndexProfile = GeneratedCRepairIndexProfile

    override fun createValidationStrategy(): RepairValidationStrategy =
        GeneratedCRepairValidationStrategy(UnavailableGeneratedCRepairValidationBoundary)
}
