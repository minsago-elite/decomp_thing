package decompengine.project

import kotlin.test.Test
import kotlin.test.assertEquals
import kotlin.test.assertTrue

class GeneratedCInterfaceStatusTest {
    @Test
    fun `public and private declarations retain provenance for every extraction status`() {
        val statuses = RecoveryStatus.entries
        val publicFunctions = statuses.mapIndexed { index, status ->
            RecoveredFunction("public$index", "public$index", (0x1000 + index).toULong(), "int public$index(void)", status = status)
        }
        val privateFunctions = statuses.mapIndexed { index, status ->
            RecoveredFunction("private$index", "private$index", (0x1100 + index).toULong(), "int private$index(void)", status = status)
        }
        val global = statuses.mapIndexed { index, status ->
            RecoveredGlobal("global$index", "value$index", (0x2000 + index).toULong(), "int", status = status)
        }
        val caller = RecoveredFunction("caller", "caller", 0x3000u, "void caller(void)", calls = publicFunctions.mapTo(linkedSetOf()) { it.id })
        val model = RecoveredProgramModel(
            inputSha256 = "0".repeat(64),
            functions = publicFunctions + privateFunctions + caller,
            globals = global,
        )
        val modules = listOf(
            PlannedModule("alpha", "src/alpha.c", "include/alpha.h", publicFunctions.map { it.id }, global.map { it.id }, boundaryEvidence = emptyList()),
            PlannedModule("beta", "src/beta.c", "include/beta.h", privateFunctions.map { it.id } + "caller", emptyList(), boundaryEvidence = emptyList()),
        )
        val rendering = GeneratedCProjectRendering(model, ModulePlan(modules = modules))
        val alpha = rendering.moduleInterface(modules[0])
        val alphaPrivate = rendering.privateInterface(modules[0])
        val beta = rendering.moduleInterface(modules[1])
        val betaPrivate = rendering.privateInterface(modules[1])

        for ((index, status) in statuses.withIndex()) {
            val expected = "extraction-status=${status.name.lowercase()}"
            assertTrue("global$index @ 0x${(0x2000 + index).toString(16)}; $expected" in alpha, alpha)
            assertTrue("public$index @ 0x${(0x1000 + index).toString(16)}; $expected" in alpha, alpha)
            assertTrue("private private$index @ 0x${(0x1100 + index).toString(16)}; $expected" in betaPrivate, betaPrivate)
        }
        assertTrue("#ifndef DECOMP_MODULE_ALPHA_H" in alpha && "#ifndef DECOMP_MODULE_ALPHA_INTERNAL_H" in alphaPrivate)
        assertTrue(alpha.indexOf("global0") < alpha.indexOf("global1"))
        assertTrue(alpha.indexOf("public0") < alpha.indexOf("public1") && alpha.indexOf("public1") < alpha.indexOf("public2") && alpha.indexOf("public2") < alpha.indexOf("public3"))
        assertTrue(betaPrivate.indexOf("private private0") < betaPrivate.indexOf("private private1") && betaPrivate.indexOf("private private1") < betaPrivate.indexOf("private private2") && betaPrivate.indexOf("private private2") < betaPrivate.indexOf("private private3"))
        assertEquals(1, alpha.lines().count { "public0" in it })
        assertTrue("private private0" !in beta && "private private0" in betaPrivate)
    }
}
