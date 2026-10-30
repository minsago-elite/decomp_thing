package decompengine.oracle.gcc

import java.net.URLClassLoader
import java.nio.file.Path
import kotlin.test.Test
import kotlin.test.assertEquals
import kotlin.test.assertFalse
import kotlin.test.assertTrue

class BundledExportPhaseRouteTest {
    @Test
    fun invocationNineAndTenBothEnterSharedStagingAccountingOnlyForExactExporterShapes() {
        val bridge = Path.of("ghidra-bridge/build/libs/decomp-ghidra-bridge.jar").toAbsolutePath().normalize()
        URLClassLoader(arrayOf(bridge.toUri().toURL()), null).use { loader ->
            val selector = Class.forName("BundledExportPhaseRoute", true, loader)
            val route = selector.getMethod("route", Array<String>::class.java)
            val bounded = selector.getMethod("hasSharedStagingBudget", Array<String>::class.java)
            val v9 = Array(27) { "unused" }.also { it[14] = "ExportInferredInterfacesV1.class" }
            val v10 = Array(34) { "unused" }.also {
                it[14] = "ExportInferredInterfacesV1.class"
                it[27] = "ExportGlobalTypeObservationsV1.class"
            }
            val malformed = v10.copyOf().also { it[27] = "unexpected.class" }

            assertEquals("invocation9", route.invoke(null, v9))
            assertEquals("invocation10", route.invoke(null, v10))
            assertTrue(bounded.invoke(null, v9) as Boolean)
            assertTrue(bounded.invoke(null, v10) as Boolean)
            assertEquals("none", route.invoke(null, malformed))
            assertFalse(bounded.invoke(null, malformed) as Boolean)
        }
    }
}
