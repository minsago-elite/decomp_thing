package decompengine.project

import java.nio.charset.StandardCharsets
import java.nio.file.Path
import kotlin.test.Test
import kotlin.test.assertEquals
import kotlin.test.assertFailsWith

class ContainedModuleMountPolicyTest {
    @Test
    fun `mount parser decodes escaped path and uses per-mount read-only flags`() {
        val mounts = ContainedModuleMountPolicy.parse(
            (record(1, 99, "/", "rw") + record(9, 1, "/runtime/a\\040b", "ro", superOptions = "rw"))
                .toByteArray(StandardCharsets.US_ASCII),
        )
        assertEquals(Path.of("/runtime/a b"), mounts.last().mountPoint)
        assertEquals(true, mounts.last().readOnly)
        ContainedModuleMountPolicy.requireReadOnlyTarget(Path.of("/runtime/a b/bin"), 9, directory = true, mounts = mounts)
    }

    @Test
    fun `mount parser preserves valid UTF-8 paths`() {
        val path = "/home/사용자/project/snapshot"
        val mounts = ContainedModuleMountPolicy.parse(
            (record(1, 99, "/", "rw") + record(9, 1, path, "ro"))
                .toByteArray(StandardCharsets.UTF_8),
        )
        assertEquals(Path.of(path), mounts.last().mountPoint)
        ContainedModuleMountPolicy.requireReadOnlyTarget(Path.of("$path/src/main.c"), 9, directory = true, mounts = mounts)
    }

    @Test
    fun `mount parser permits kernel mount roots containing parent traversal`() {
        val mounts = ContainedModuleMountPolicy.parse(
            record(1, 99, "/", "ro", root = "/../../../../host-root").toByteArray(StandardCharsets.US_ASCII),
        )
        assertEquals(Path.of("/"), mounts.single().mountPoint)
    }

    @Test
    fun `read-only directory rejects writable child and grandchild mounts`() {
        val parent = ContainedModuleMountPolicy.parse(
            (record(1, 99, "/", "ro") + record(9, 1, "/runtime", "ro") +
                record(10, 9, "/runtime/child", "ro") + record(11, 10, "/runtime/child/grandchild", "rw"))
                .toByteArray(StandardCharsets.US_ASCII),
        )
        assertFailsWith<IllegalArgumentException> {
            ContainedModuleMountPolicy.requireReadOnlyTarget(Path.of("/runtime"), 9, directory = true, mounts = parent)
        }
    }

    @Test
    fun `mount matching is descriptor-bound and component-aware`() {
        val mounts = ContainedModuleMountPolicy.parse(
            (record(1, 99, "/", "ro") + record(9, 1, "/runtime", "ro") +
                record(10, 1, "/runtime-old", "rw"))
                .toByteArray(StandardCharsets.US_ASCII),
        )
        ContainedModuleMountPolicy.requireReadOnlyTarget(Path.of("/runtime/bin/tool"), 9, directory = false, mounts = mounts)
        assertFailsWith<IllegalArgumentException> {
            ContainedModuleMountPolicy.requireReadOnlyTarget(Path.of("/runtime/bin/tool"), 1, directory = false, mounts = mounts)
        }
    }

    @Test
    fun `malformed duplicate and oversized mount tables fail closed`() {
        assertFailsWith<IllegalArgumentException> {
            ContainedModuleMountPolicy.parse(record(1, 99, "/bad\\999", "ro").toByteArray(StandardCharsets.US_ASCII))
        }
        assertFailsWith<IllegalArgumentException> {
            ContainedModuleMountPolicy.parse(record(1, 99, "/", "ro,rw").toByteArray(StandardCharsets.US_ASCII))
        }
        assertFailsWith<IllegalArgumentException> {
            ContainedModuleMountPolicy.parse((record(1, 99, "/", "ro") + record(1, 1, "/other", "ro"))
                .toByteArray(StandardCharsets.US_ASCII))
        }
        assertFailsWith<IllegalArgumentException> {
            val prefix = "1 99 0:42 / /home/".toByteArray(StandardCharsets.US_ASCII)
            val suffix = " ro shared:1 - ext4 /dev/test rw\n".toByteArray(StandardCharsets.US_ASCII)
            ContainedModuleMountPolicy.parse(prefix + byteArrayOf(0xc3.toByte(), 0x28) + suffix)
        }
        assertFailsWith<IllegalArgumentException> {
            ContainedModuleMountPolicy.parse(ByteArray(4 * 1024 * 1024 + 1) { 'x'.code.toByte() })
        }
    }

    private fun record(id: Long, parent: Long, mountPoint: String, mode: String, superOptions: String = "rw",
        root: String = "/") =
        "$id $parent 0:42 $root $mountPoint $mode shared:1 - ext4 /dev/test $superOptions\n"
}
