package decompengine.project

import decompengine.repair.RepairIndexProfile
import decompengine.repair.RepairRuntimeProfileProvider
import decompengine.repair.RepairValidationStrategy

/** Application adapter registration for generated C/Make projects. */
class GeneratedCRepairRuntimeProvider : RepairRuntimeProfileProvider {
    private val registration = GeneratedCValidationProfile.registeredMake
    override fun profileId(): String = registration.indexProfile.profileId()

    override fun indexProfile(): RepairIndexProfile = registration.indexProfile

    override fun createValidationStrategy(): RepairValidationStrategy =
        GeneratedCRepairValidationStrategy(LinuxGeneratedCRepairValidationBoundary.create(registration))
}
