package decompengine.acp

import decompengine.agent.AGENT_EXECUTION_CONTRACT_VERSION
import decompengine.repair.RepairClientAgentHarness
import java.nio.file.Files
import java.nio.file.Path
import java.nio.file.StandardCopyOption
import java.nio.file.attribute.PosixFilePermission
import kotlin.io.path.createTempFile
import kotlin.io.path.writeBytes
import kotlin.io.path.writeText
import kotlin.test.Test
import kotlin.test.assertEquals
import kotlin.test.assertFailsWith
import kotlin.test.assertFalse
import kotlin.test.assertIs
import kotlin.test.assertNotEquals
import kotlin.test.assertNotNull
import kotlin.test.assertNull
import kotlin.test.assertTrue

class AcpHarnessFactoryTest {
    @Test
    fun `omitted selection defaults to a fully provisioned ACP harness`() {
        val config = writeConfig(validConfig())
        val selection = AcpHarnessFactory.fromEnvironment(
            mapOf(
                "ACP_CONFIG_FILE" to config.toString(),
                "TEST_ACP_SECRET" to "first-secret-canary",
            ),
        )

        assertEquals(AcpHarnessKind.ACP, selection.kind)
        assertIs<AcpAgentHarness>(selection.createHarness())
        val provisioned = assertNotNull(selection.configuration)
        assertEquals(
            listOf("--mode", "two words", "", "literal-\$()"),
            provisioned.arguments,
            "ordered argv must not be shell-split, trimmed, or interpreted",
        )
        assertFalse(provisioned.inheritParentEnvironment)
        assertEquals(AcpEnvironmentProvenance.PUBLIC, provisioned.environment.getValue("PUBLIC_MODE").provenance)
        assertEquals(AcpEnvironmentProvenance.SECRET, provisioned.environment.getValue("AGENT_TOKEN").provenance)
        assertEquals("first-secret-canary", provisioned.environment.getValue("AGENT_TOKEN").value)
        assertEquals(
            setOf(AcpRequiredAgentCapability.LOAD_SESSION, AcpRequiredAgentCapability.PROMPT_EMBEDDED_CONTEXT),
            provisioned.requiredAgentCapabilities,
        )
        assertEquals(1_200_000, provisioned.timeouts.request.toMillis())
        assertEquals(1_048_576, provisioned.maximumFrameBytes)
        assertEquals(1_024, provisioned.maximumProtocolFrames)
        assertEquals(262_144, provisioned.maximumStderrBytes)
        assertEquals(8 * 1024 * 1024, provisioned.filesystemLimits.maximumReadBytes)
        assertNull(provisioned.sessionPreferences.modelId)
        assertNull(provisioned.sessionPreferences.modeId)
        assertTrue(provisioned.sessionPreferences.configOptions.isEmpty())
        val sandbox = assertNotNull(provisioned.sandboxBoundary)
        assertEquals(Path.of("/usr/bin/bwrap"), sandbox.bubblewrapExecutable)
        assertEquals(Path.of("/tmp"), sandbox.agentWorkingDirectory)
        assertEquals(1, sandbox.launcherRuntimeMounts.size)
        assertEquals(1, sandbox.agentRuntimeMounts.size)
        assertEquals(32, sandbox.agentResourceLimits.maximumProcesses)
        assertNull(provisioned.terminalPolicy, "terminal authority must be derived by a workflow, not static JSON")
        assertEquals("acp", selection.provenance.harness)
        assertFalse(selection.provenance.deprecated)
        assertTrue(selection.provenance.configurationSha256.orEmpty().matches(Regex("[0-9a-f]{64}")))
        assertTrue(selection.provenance.stableDescriptor.startsWith("agent-harness-v1:acp:"))
        assertFalse(selection.provenance.stableDescriptor.contains("first-secret-canary"))
    }

    @Test
    fun `secret resolution is explicit and excluded from stable configuration provenance`() {
        val config = writeConfig(validConfig())
        val first = AcpHarnessFactory.fromEnvironment(
            mapOf("ACP_CONFIG_FILE" to config.toString(), "TEST_ACP_SECRET" to "secret-one"),
        )
        val second = AcpHarnessFactory.fromEnvironment(
            mapOf("ACP_CONFIG_FILE" to config.toString(), "TEST_ACP_SECRET" to "secret-two"),
        )

        assertNotEquals(
            first.configuration?.environment?.getValue("AGENT_TOKEN")?.value,
            second.configuration?.environment?.getValue("AGENT_TOKEN")?.value,
        )
        assertEquals(first.provenance.configurationSha256, second.provenance.configurationSha256)
        assertEquals(first.provenance.stableDescriptor, second.provenance.stableDescriptor)
        val missing = assertFailsWith<IllegalArgumentException> {
            AcpHarnessFactory.fromEnvironment(mapOf("ACP_CONFIG_FILE" to config.toString()))
        }
        assertTrue(missing.message.orEmpty().contains("unavailable secret source"))
        assertFalse(missing.message.orEmpty().contains("TEST_ACP_SECRET"))
    }

    @Test
    fun `legacy OpenAI compatibility requires an explicit non-ACP selection`() {
        val selection = AcpHarnessFactory.fromEnvironment(
            mapOf(
                "ACP_HARNESS" to "legacy-openai",
                "BASE_URL" to "https://example.invalid/v1",
                "API_KEY" to "legacy-key",
                "MODEL" to "legacy-model",
            ),
        )

        assertEquals(AcpHarnessKind.LEGACY_OPENAI, selection.kind)
        assertNull(selection.configuration)
        assertTrue(selection.provenance.deprecated)
        assertEquals("legacy-openai", selection.provenance.harness)
        assertIs<RepairClientAgentHarness>(selection.createHarness())
    }

    @Test
    fun `legacy resolution reads only its explicit compatibility environment`() {
        val allowed = mapOf(
            "ACP_HARNESS" to "legacy-openai",
            "BASE_URL" to "https://example.invalid/v1",
            "API_KEY" to "legacy-key",
            "MODEL" to "legacy-model",
        )
        val nonEnumerableEnvironment = object : AbstractMap<String, String>() {
            override val entries: Set<Map.Entry<String, String>>
                get() = error("legacy selection must not enumerate or retain the ambient environment")

            override fun get(key: String): String? = allowed[key]
        }

        val selection = AcpHarnessFactory.fromEnvironment(nonEnumerableEnvironment)
        assertIs<RepairClientAgentHarness>(selection.createHarness())
    }

    @Test
    fun `harness provenance rejects incoherent ACP and legacy identities`() {
        assertFailsWith<IllegalArgumentException> {
            AcpHarnessProvenance(
                harness = "acp",
                implementationId = "fixture",
                agentExecutionContractVersion = AGENT_EXECUTION_CONTRACT_VERSION,
                acpProtocolVersion = ACP_STABLE_PROTOCOL_VERSION,
                acpSdkVersion = ACP_KOTLIN_SDK_VERSION,
                configurationSha256 = null,
                deprecated = false,
            )
        }
        assertFailsWith<IllegalArgumentException> {
            AcpHarnessProvenance(
                harness = "legacy-openai",
                implementationId = "fixture",
                agentExecutionContractVersion = AGENT_EXECUTION_CONTRACT_VERSION,
                acpProtocolVersion = ACP_STABLE_PROTOCOL_VERSION,
                acpSdkVersion = ACP_KOTLIN_SDK_VERSION,
                configurationSha256 = "1".repeat(64),
                deprecated = true,
            )
        }
    }

    @Test
    fun `old direct selection unknown values and blank selection fail closed`() {
        listOf("direct", "builtin", "unexpected", "ACP", " acp", "legacy-openai ", "").forEach { selected ->
            val failure = assertFailsWith<IllegalArgumentException>(selected) {
                AcpHarnessFactory.fromEnvironment(mapOf("ACP_HARNESS" to selected))
            }
            if (selected == "direct") assertTrue(failure.message.orEmpty().contains("no longer supported"))
        }
        val missing = assertFailsWith<IllegalArgumentException> { AcpHarnessFactory.fromEnvironment(emptyMap()) }
        assertTrue(missing.message.orEmpty().contains("ACP_CONFIG_FILE is required"))
    }

    @Test
    fun `ACP rejects obsolete split environment configuration`() {
        val config = writeConfig(validConfig())
        val failure = assertFailsWith<IllegalArgumentException> {
            AcpHarnessFactory.fromEnvironment(
                mapOf(
                    "ACP_CONFIG_FILE" to config.toString(),
                    "ACP_AGENT_ARGS" to "--unsafe split value",
                    "TEST_ACP_SECRET" to "secret",
                ),
            )
        }
        assertTrue(failure.message.orEmpty().contains("ACP_AGENT_ARGS is obsolete"))
    }

    @Test
    fun `strict document rejects duplicate unknown missing and trailing fields`() {
        val mutations = listOf(
            validConfig().replace(
                "\"schemaVersion\": 2,",
                "\"schemaVersion\": 2,\n  \"schemaVersion\": 2,",
            ) to "duplicate JSON key",
            validConfig().replace(
                "\"schemaVersion\": 2,",
                "\"schemaVersion\": 2,\n  \"unknown\": true,",
            ) to "unknown field",
            validConfig().replace("  \"implementationId\": \"fixture-acp\",\n", "") to "missing required field",
            validConfig() + " false" to "trailing JSON data",
        )
        mutations.forEach { (payload, expected) ->
            val config = writeConfig(payload)
            val failure = assertFailsWith<IllegalArgumentException>(expected) {
                select(config)
            }
            assertTrue(failure.message.orEmpty().contains(expected), failure.message)
        }
    }

    @Test
    fun `schema v2 binds nullable or omitted model and mode plus ordered typed config options`() {
        val configured = select(writeConfig(validConfig(session = """
            {
              "modelId": "model-safe",
              "modeId": "mode-safe",
              "configOptions": [
                {"id":"reasoning","type":"select","value":"high"},
                {"id":"telemetry","type":"boolean","value":false}
              ]
            }
        """.trimIndent()))).configuration!!.sessionPreferences

        assertEquals("model-safe", configured.modelId)
        assertEquals("mode-safe", configured.modeId)
        assertEquals(
            listOf(
                AcpSessionConfigPreference("reasoning", AcpSessionConfigValue.Select("high")),
                AcpSessionConfigPreference("telemetry", AcpSessionConfigValue.BooleanValue(false)),
            ),
            configured.configOptions,
        )

        val explicitNull = select(writeConfig(validConfig(session = """
            {"modelId":null,"modeId":null,"configOptions":[]}
        """.trimIndent()))).configuration!!.sessionPreferences
        assertNull(explicitNull.modelId)
        assertNull(explicitNull.modeId)
        assertTrue(explicitNull.configOptions.isEmpty())
    }

    @Test
    fun `schema v1 and ambiguous or unbounded session preferences fail closed`() {
        val legacy = assertFailsWith<IllegalArgumentException> {
            select(writeConfig(validConfig().replace("\"schemaVersion\": 2", "\"schemaVersion\": 1")))
        }
        assertTrue(legacy.message.orEmpty().contains("migrate to schemaVersion 2"), legacy.message)

        val invalidSessions = listOf(
            """{"configOptions":[{"id":"reasoning","type":"select","value":"high"},{"id":"reasoning","type":"select","value":"low"}]}""" to "duplicated",
            """{"configOptions":[{"id":"reasoning","type":"boolean","value":"false"}]}""" to "JSON boolean",
            """{"configOptions":[{"id":"reasoning","type":"opaque","value":"high"}]}""" to "unsupported type",
            """{"configOptions":[],"unknown":true}""" to "unknown field",
        )
        invalidSessions.forEach { (session, expected) ->
            val failure = assertFailsWith<IllegalArgumentException>(expected) {
                select(writeConfig(validConfig(session = session)))
            }
            assertTrue(failure.message.orEmpty().contains(expected), failure.message)
        }

        val overBound = (0..MAXIMUM_CONFIGURED_ACP_SESSION_OPTIONS).joinToString(",") { index ->
            """{"id":"option-$index","type":"boolean","value":false}"""
        }
        val bounded = assertFailsWith<IllegalArgumentException> {
            select(writeConfig(validConfig(session = """{"configOptions":[$overBound]}""")))
        }
        assertTrue(bounded.message.orEmpty().contains("entry limit"), bounded.message)

        listOf(
            { AcpSessionPreferences(modelId = "model\u0000id") },
            { AcpSessionPreferences(modeId = "mode\nid") },
            {
                AcpSessionPreferences(configOptions = listOf(
                    AcpSessionConfigPreference("option\u007fid", AcpSessionConfigValue.BooleanValue(false)),
                ))
            },
            {
                AcpSessionPreferences(configOptions = listOf(
                    AcpSessionConfigPreference("reasoning", AcpSessionConfigValue.Select("high\u0085value")),
                ))
            },
        ).forEach { constructor ->
            val control = assertFailsWith<IllegalArgumentException> { constructor() }
            assertTrue(control.message.orEmpty().contains("control characters"), control.message)
        }

        val escapedControl = assertFailsWith<IllegalArgumentException> {
            select(writeConfig(validConfig(session =
                "{\"modelId\":\"model-\\u0000id\",\"configOptions\":[]}",
            )))
        }
        assertTrue(escapedControl.message.orEmpty().contains("control characters"), escapedControl.message)
    }

    @Test
    fun `strict document rejects non-ASCII digits in Unicode escapes`() {
        val asciiEscape = validConfig().replace(
            "\"implementationId\": \"fixture-acp\"",
            "\"implementationId\": \"fixture-\\u0041cp\"",
        )
        val malformedEscape = validConfig().replace(
            "\"implementationId\": \"fixture-acp\"",
            "\"implementationId\": \"fixture-\\u٠٠٤١cp\"",
        )

        assertEquals("fixture-Acp", select(writeConfig(asciiEscape)).configuration?.implementationId)
        val failure = assertFailsWith<IllegalArgumentException> {
            select(writeConfig(malformedEscape))
        }

        assertTrue(failure.message.orEmpty().contains("Unicode escape is malformed"), failure.message)
    }

    @Test
    fun `structured collections reject duplicate environment and capability entries`() {
        val duplicateEnvironment = validConfig(
            environmentEntries = """
                {"name":"PUBLIC_MODE","provenance":"public","value":"safe"},
                {"name":"PUBLIC_MODE","provenance":"public","value":"other"}
            """.trimIndent(),
            capabilities = "\"loadSession\"",
        )
        val duplicateCapability = validConfig(capabilities = "\"loadSession\", \"loadSession\"")
        val first = assertFailsWith<IllegalArgumentException> { select(writeConfig(duplicateEnvironment)) }
        assertTrue(first.message.orEmpty().contains("duplicate name"))
        val second = assertFailsWith<IllegalArgumentException> { select(writeConfig(duplicateCapability)) }
        assertTrue(second.message.orEmpty().contains("duplicate ACP required capability"))
    }

    @Test
    fun `configuration input is bounded private normalized and strict UTF-8`() {
        val relative = assertFailsWith<IllegalArgumentException> {
            AcpHarnessFactory.fromEnvironment(
                mapOf("ACP_CONFIG_FILE" to "relative.json", "TEST_ACP_SECRET" to "secret"),
            )
        }
        assertTrue(relative.message.orEmpty().contains("absolute normalized"))

        val publicFile = writeConfig(validConfig())
        Files.setPosixFilePermissions(publicFile, setOf(
            PosixFilePermission.OWNER_READ,
            PosixFilePermission.OWNER_WRITE,
            PosixFilePermission.GROUP_READ,
        ))
        val permissions = assertFailsWith<IllegalArgumentException> { select(publicFile) }
        assertTrue(permissions.message.orEmpty().contains("group or other"))

        val malformed = createTempFile("acp-config-malformed-", ".json").toAbsolutePath().normalize()
        malformed.writeBytes(byteArrayOf(0xc3.toByte(), 0x28))
        makePrivate(malformed)
        val utf8 = assertFailsWith<IllegalArgumentException> { select(malformed) }
        assertTrue(utf8.message.orEmpty().contains("strict UTF-8"))

        val oversized = createTempFile("acp-config-oversized-", ".json").toAbsolutePath().normalize()
        oversized.writeBytes(ByteArray(4 * 1024 * 1024 + 1) { ' '.code.toByte() })
        makePrivate(oversized)
        val size = assertFailsWith<IllegalArgumentException> { select(oversized) }
        assertTrue(size.message.orEmpty().contains("between 1 and"))

        val linked = writeConfig(validConfig())
        val secondLink = linked.resolveSibling("${linked.fileName}.hard-link")
        Files.createLink(secondLink, linked)
        val links = assertFailsWith<IllegalArgumentException> { select(linked) }
        assertTrue(links.message.orEmpty().contains("exactly one filesystem link"))

        val symlinkTarget = writeConfig(validConfig())
        val symlink = symlinkTarget.resolveSibling("${symlinkTarget.fileName}.symbolic-link")
        Files.createSymbolicLink(symlink, symlinkTarget)
        val symbolic = assertFailsWith<IllegalArgumentException> { select(symlink) }
        assertTrue(symbolic.message.orEmpty().contains("regular file without following links"))
    }

    @Test
    fun `configuration bytes stay bound to the pinned inode during pathname replacement`() {
        val trusted = writeConfig(validConfig(implementationId = "trusted-acp"))
        val replacement = writeConfig(validConfig(implementationId = "hostile-acp"))
        val pinnedName = trusted.resolveSibling("${trusted.fileName}.pinned")
        val expected = AcpHarnessProvisioning.load(
            trusted.toString(),
            mapOf("TEST_ACP_SECRET" to "secret"),
        )
        var swapped = false

        val actual = try {
            AcpHarnessProvisioning.loadForTesting(
                trusted.toString(),
                mapOf("TEST_ACP_SECRET" to "secret"),
                AcpProvisioningReadTestHook(
                    afterPinned = {
                        Files.move(trusted, pinnedName)
                        Files.move(replacement, trusted)
                        Files.setPosixFilePermissions(
                            trusted,
                            setOf(PosixFilePermission.OWNER_READ, PosixFilePermission.GROUP_READ),
                        )
                        swapped = true
                    },
                    afterRead = {
                        Files.move(trusted, replacement, StandardCopyOption.REPLACE_EXISTING)
                        Files.move(pinnedName, trusted)
                        swapped = false
                    },
                ),
            )
        } finally {
            if (swapped || Files.exists(pinnedName)) {
                if (Files.exists(trusted)) {
                    Files.move(trusted, replacement, StandardCopyOption.REPLACE_EXISTING)
                }
                if (Files.exists(pinnedName)) {
                    Files.move(pinnedName, trusted, StandardCopyOption.REPLACE_EXISTING)
                }
            }
        }

        assertEquals("trusted-acp", actual.configuration.implementationId)
        assertEquals(expected.canonicalSha256, actual.canonicalSha256)
    }

    @Test
    fun `sandbox provisioning cannot widen defaults or overlap the agent executable`() {
        val widened = validConfig().replace("\"maximumProcesses\": 32", "\"maximumProcesses\": 33")
        val widenedFailure = assertFailsWith<IllegalArgumentException> { select(writeConfig(widened)) }
        assertTrue(widenedFailure.message.orEmpty().contains("maximumProcesses"))

        val overlap = validConfig().replace(
            "\"destination\":\"/runtime/agent\"",
            "\"destination\":\"/opt/decomp\"",
        )
        val overlapFailure = assertFailsWith<IllegalArgumentException> { select(writeConfig(overlap)) }
        assertTrue(overlapFailure.message.orEmpty().contains("overlap the agent executable"))
    }

    @Test
    fun `static runtime mounts allow the full boundary count and reserve the executable separately`() {
        val mounts = (0 until MAXIMUM_SANDBOX_MOUNTS).joinToString(",\n") { index ->
            """{"source":"/opt/acp-runtime-$index","destination":"/runtime/acp-$index","expectedManifestSha256":"${"2".repeat(64)}"}"""
        }
        val atLimit = select(writeConfig(validConfig(
            launcherMountEntries = mounts,
            agentMountEntries = "",
        )))
        assertEquals(
            MAXIMUM_SANDBOX_MOUNTS,
            assertNotNull(atLimit.configuration?.sandboxBoundary).launcherRuntimeMounts.size,
        )

        val overLimit = assertFailsWith<IllegalArgumentException> {
            select(writeConfig(validConfig(
                launcherMountEntries = mounts,
                agentMountEntries =
                    """{"source":"/opt/acp-extra","destination":"/runtime/acp-extra","expectedManifestSha256":"${"3".repeat(64)}"}""",
            )))
        }
        assertTrue(overLimit.message.orEmpty().contains("combined ACP runtime mounts exceed"))
    }

    private fun select(path: Path): AcpHarnessSelection = AcpHarnessFactory.fromEnvironment(
        mapOf("ACP_CONFIG_FILE" to path.toString(), "TEST_ACP_SECRET" to "secret"),
    )

    private fun writeConfig(payload: String): Path =
        createTempFile("acp-config-", ".json").toAbsolutePath().normalize().also { path ->
            path.writeText(payload)
            makePrivate(path)
        }

    private fun makePrivate(path: Path) {
        Files.setPosixFilePermissions(path, setOf(
            PosixFilePermission.OWNER_READ,
            PosixFilePermission.OWNER_WRITE,
        ))
    }

    private fun validConfig(
        implementationId: String = "fixture-acp",
        environmentEntries: String = """
            {"name":"PUBLIC_MODE","provenance":"public","value":"safe"},
            {"name":"AGENT_TOKEN","provenance":"secret","valueFromEnvironment":"TEST_ACP_SECRET"}
        """.trimIndent(),
        capabilities: String = "\"loadSession\", \"promptCapabilities.embeddedContext\"",
        launcherMountEntries: String =
            """{"source":"/usr/lib/liblauncher.so","destination":"/runtime/launcher/liblauncher.so","expectedManifestSha256":"${"2".repeat(64)}"}""",
        agentMountEntries: String =
            """{"source":"/opt/decomp/acp-runtime","destination":"/runtime/agent","expectedManifestSha256":"${"3".repeat(64)}"}""",
        session: String = """{"configOptions":[]}""",
    ): String = """
        {
          "schemaVersion": 2,
          "implementationId": "$implementationId",
          "agent": {
            "executable": "/opt/decomp/acp-agent",
            "arguments": ["--mode", "two words", "", "literal-${'$'}()"],
            "environment": [$environmentEntries],
            "inheritParentEnvironment": false,
            "requiredCapabilities": [$capabilities],
            "timeoutsMillis": {
              "startup": 20000,
              "request": 1200000,
              "cancellationGrace": 2000,
              "transportDrainGrace": 100,
              "shutdown": 5000
            },
            "protocolLimits": {
              "maximumFrameBytes": 1048576,
              "maximumProtocolFrames": 1024,
              "maximumStderrBytes": 262144
            },
            "filesystemLimits": {
              "maximumReadBytes": 8388608,
              "maximumWriteBytes": 8388608
            },
            "permissionMode": "default-deny",
            "expectedExecutableManifestSha256": "${"1".repeat(64)}"
          },
          "session": $session,
          "sandbox": {
            "bubblewrapExecutable": "/usr/bin/bwrap",
            "resourceLimiterExecutable": "/usr/bin/prlimit",
            "scopeSupervisorExecutable": "/usr/bin/systemd-run",
            "scopeInspectorExecutable": "/usr/bin/systemctl",
            "environmentFdOpenerExecutable": "/usr/bin/bash",
            "sandboxGateHelperExecutable": "/opt/decomp/acp-gate-helper",
            "systemdUserRuntimeDirectory": "/run/user/1000",
            "agentWorkingDirectory": "/tmp",
            "launcherRuntimeMounts": [
              $launcherMountEntries
            ],
            "agentRuntimeMounts": [
              $agentMountEntries
            ],
            "agentResourceLimits": {
              "maximumProcesses": 32,
              "maximumOpenFiles": 256,
              "maximumFileBytes": 67108864,
              "maximumAddressSpaceBytes": 2147483648,
              "maximumCpuSeconds": 120
            },
            "runtimeClosureLimits": {
              "maximumEntries": 100000,
              "maximumUserOwnedFileBytes": 2147483648,
              "maximumDepth": 64
            },
            "expectedBubblewrapSha256": "${"4".repeat(64)}",
            "expectedResourceLimiterSha256": "${"5".repeat(64)}",
            "expectedScopeSupervisorSha256": "${"6".repeat(64)}",
            "expectedScopeInspectorSha256": "${"7".repeat(64)}",
            "expectedEnvironmentFdOpenerSha256": "${"8".repeat(64)}",
            "expectedSandboxGateHelperSha256": "${"9".repeat(64)}",
            "expectedSandboxGateHelperManifestSha256": "${"a".repeat(64)}"
          }
        }
    """.trimIndent() + "\n"
}
