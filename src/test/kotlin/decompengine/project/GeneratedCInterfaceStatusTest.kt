package decompengine.project

import kotlin.test.Test
import kotlin.test.assertContains

class GeneratedCInterfaceStatusTest {
    @Test
    fun `shared public and private declarations retain extraction status without semantic claims`() {
        val model = RecoveredProgramModel(
            inputSha256 = "interface-status",
            functions = listOf(
                RecoveredFunction(
                    id = "fn_entry",
                    name = "main",
                    address = 0x1000u,
                    prototype = "int main(void)",
                    calls = setOf("fn_api"),
                    status = RecoveryStatus.FAILED,
                ),
                RecoveredFunction(
                    id = "fn_api",
                    name = "api_call",
                    address = 0x1010u,
                    prototype = "int api_call(void)",
                    status = RecoveryStatus.PARTIAL,
                ),
                RecoveredFunction(
                    id = "fn_local",
                    name = "local_helper",
                    address = 0x1020u,
                    prototype = "static int local_helper(void)",
                    status = RecoveryStatus.SYNTHETIC,
                ),
            ),
            globals = listOf(
                RecoveredGlobal(
                    id = "global_api",
                    name = "api_value",
                    address = 0x2000u,
                    type = "int",
                    status = RecoveryStatus.FAILED,
                ),
            ),
            types = listOf(
                RecoveredType(
                    id = "type_api",
                    declaration = "typedef int api_value_t;",
                    sourceAddress = 0x2000u,
                    status = RecoveryStatus.PARTIAL,
                ),
            ),
        )
        val plan = DeterministicModulePlanner().plan(
            model,
            overrides = mapOf(
                "fn_entry" to "entry",
                "fn_api" to "api",
                "fn_local" to "api",
                "global_api" to "api",
            ),
        )
        val rendering = GeneratedCProjectRendering(model, plan)
        val apiModule = plan.modules.single { it.id == "api" }

        assertContains(rendering.sharedInterface(), "type_api; extraction-status=partial; recovery-assessment=unassessed; @ 0x2000")
        assertContains(rendering.moduleInterface(apiModule), "global_api @ 0x2000; extraction-status=failed; recovery-assessment=unassessed")
        assertContains(rendering.moduleInterface(apiModule), "fn_api @ 0x1010; extraction-status=partial; recovery-assessment=unassessed")
        assertContains(rendering.privateInterface(apiModule), "private fn_local @ 0x1020; extraction-status=synthetic; recovery-assessment=unassessed")
        assertContains(rendering.moduleInterface(plan.modules.single { it.id == "entry" }),
            "fn_entry @ 0x1000; extraction-status=failed; recovery-assessment=unassessed")
    }
}
