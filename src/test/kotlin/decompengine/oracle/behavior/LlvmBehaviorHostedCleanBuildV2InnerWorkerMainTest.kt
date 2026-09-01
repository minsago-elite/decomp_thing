package decompengine.oracle.behavior

import java.lang.reflect.Modifier
import kotlin.test.Test
import kotlin.test.assertEquals
import kotlin.test.assertFailsWith
import kotlin.test.assertTrue

class LlvmBehaviorHostedCleanBuildV2InnerWorkerMainTest {
    @Test
    fun `fixed worker launcher exposes one static JVM main and no return-value fact surface`() {
        val methods = LlvmBehaviorHostedCleanBuildV2InnerWorkerMain::class.java.declaredMethods
            .filterNot { it.isSynthetic }

        assertEquals(1, methods.size)
        val main = methods.single()
        assertEquals("main", main.name)
        assertTrue(Modifier.isPublic(main.modifiers))
        assertTrue(Modifier.isStatic(main.modifiers))
        assertEquals(Void.TYPE, main.returnType)
        assertEquals(listOf(Array<String>::class.java), main.parameterTypes.toList())
    }

    @Test
    fun `fixed worker launcher rejects caller-selected arguments before worker launch`() {
        val failure = assertFailsWith<LlvmBehaviorHostedCleanBuildV2Exception> {
            LlvmBehaviorHostedCleanBuildV2InnerWorkerMain.main(arrayOf("/caller/selected/input"))
        }

        assertEquals("hosted clean-build inner worker accepts no arguments", failure.message)
    }
}
