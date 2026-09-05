package decompengine.oracle.fulltree

import kotlin.test.Test
import kotlin.test.assertFailsWith
import kotlin.test.assertTrue

class FullTreeFunctionObservationSystemdFeaturesTest {
    @Test
    fun `Ubuntu 255 manager build capabilities and default hierarchy are admitted`() {
        requireColdSystemdManagerFeaturesUnfiltered(
            "+PAM +AUDIT +SELINUX +APPARMOR +IMA +SMACK +SECCOMP +GCRYPT -GNUTLS +OPENSSL " +
                "+ACL +BLKID +CURL +ELFUTILS +FIDO2 +IDN2 -IDN +IPTC +KMOD +LIBCRYPTSETUP " +
                "+LIBFDISK +PCRE2 -PWQUALITY +P11KIT +QRENCODE +TPM2 +BZIP2 +LZ4 +XZ +ZLIB " +
                "+ZSTD -BPF_FRAMEWORK -XKBCOMMON +UTMP +SYSVINIT default-hierarchy=unified\n",
            "255.4-1ubuntu8.17\n",
        )
    }

    @Test
    fun `reviewed manager versions do not confuse MAC build capabilities with active policy`() {
        listOf("255", "256.9", "257.4-1", "258~rc1").forEach { version ->
            (0..7).forEach { capabilities ->
                val features = listOf("SELINUX", "APPARMOR", "SMACK").mapIndexed { index, feature ->
                    "${if (capabilities and (1 shl index) == 0) '-' else '+'}$feature"
                }.joinToString(" ")
                requireColdSystemdManagerFeaturesUnfiltered("+PAM $features +SECCOMP\n", "$version\n")
            }
        }
    }

    @Test
    fun `known legacy hierarchy metadata is not a signed capability`() {
        listOf("legacy", "hybrid", "unified").forEach { hierarchy ->
            requireColdSystemdManagerFeaturesUnfiltered(
                "$VALID_FEATURES default-hierarchy=$hierarchy\n",
                "255\n",
            )
        }
    }

    @Test
    fun `unreviewed or malformed manager versions fail closed`() {
        listOf(
            "", "255", "254\n", "259\n", "999\n", "0255\n", "2550\n", "255.\n",
            "255\r\n", "255\n\n", "255\u0000\n", " 255\n", "systemd 255\n",
            "255\n258\n", "255.${"1".repeat(256)}\n",
        ).forEach { version ->
            val failure = assertFailsWith<FullTreeFunctionObservationIsolationException>(version) {
                requireColdSystemdManagerFeaturesUnfiltered("$VALID_FEATURES\n", version)
            }
            assertTrue(failure.message.orEmpty().contains("manager version"), failure.message)
        }
    }

    @Test
    fun `missing contradictory duplicate or malformed feature declarations fail closed`() {
        listOf(
            "", VALID_FEATURES, "$VALID_FEATURES\n\n", "$VALID_FEATURES\r\n",
            "$VALID_FEATURES \n", " $VALID_FEATURES\n", "$VALID_FEATURES  +AUDIT\n",
            "$VALID_FEATURES\t+AUDIT\n", "$VALID_FEATURES\u0000\n",
            "+SELINUX +APPARMOR\n", "+SELINUX +SMACK\n", "+APPARMOR +SMACK\n",
            "$VALID_FEATURES +SELINUX\n", "$VALID_FEATURES -SELINUX\n",
            "$VALID_FEATURES +APPARMOR\n", "$VALID_FEATURES -APPARMOR\n",
            "$VALID_FEATURES +SMACK\n", "$VALID_FEATURES -SMACK\n",
            "$VALID_FEATURES +PAM -PAM\n", "$VALID_FEATURES +PAM +PAM\n",
            "$VALID_FEATURES SELINUX\n", "$VALID_FEATURES +selinux\n",
            "$VALID_FEATURES unknown=value\n", "$VALID_FEATURES default-hierarchy=unknown\n",
            "default-hierarchy=unified $VALID_FEATURES\n",
            "$VALID_FEATURES default-hierarchy=unified default-hierarchy=unified\n",
            "$VALID_FEATURES +${"A".repeat(16 * 1024)}\n",
        ).forEach { features ->
            val failure = assertFailsWith<FullTreeFunctionObservationIsolationException> {
                requireColdSystemdManagerFeaturesUnfiltered(features, "255\n")
            }
            assertTrue(failure.message.orEmpty().contains("manager features"), failure.message)
        }
    }

    @Test
    fun `denied or failed enumeration never establishes absence even with empty output`() {
        listOf("unit inventory", "job inventory").forEach { label ->
            listOf(-1, 1, 4, 13, 127).forEach { exitCode ->
                listOf("", "Access denied\n").forEach { output ->
                    val failure = assertFailsWith<FullTreeFunctionObservationIsolationException> {
                        requireColdSystemdEnumerationEmpty(output, label, exitCode)
                    }
                    assertTrue(failure.message.orEmpty().contains("failed safely"), failure.message)
                }
            }
            requireColdSystemdEnumerationEmpty("", label, 0)
            listOf("\n", "Access denied\n", "unexpected unit\n").forEach { output ->
                assertFailsWith<FullTreeFunctionObservationIsolationException> {
                    requireColdSystemdEnumerationEmpty(output, label, 0)
                }
            }
        }
    }

    private companion object {
        const val VALID_FEATURES = "+SELINUX +APPARMOR +SMACK"
    }
}
