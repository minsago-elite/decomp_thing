package decompengine.acp

import java.nio.ByteBuffer
import java.nio.charset.CodingErrorAction
import java.nio.charset.StandardCharsets
import java.nio.file.Files
import java.nio.file.InvalidPathException
import java.nio.file.Path
import java.nio.file.attribute.BasicFileAttributes
import java.security.MessageDigest
import java.time.Duration

internal data class ProvisionedAcpHarness(
    val configuration: AcpProcessConfiguration,
    val canonicalSha256: String,
)

internal class AcpProvisioningReadTestHook(
    val afterPinned: () -> Unit = {},
    val afterRead: () -> Unit = {},
)

/** Strict, bounded provisioning for the complete static ACP process/sandbox authority. */
internal object AcpHarnessProvisioning {
    fun load(configuredPath: String, hostEnvironment: Map<String, String>): ProvisionedAcpHarness {
        return load(configuredPath, hostEnvironment, null)
    }

    internal fun loadForTesting(
        configuredPath: String,
        hostEnvironment: Map<String, String>,
        readHook: AcpProvisioningReadTestHook,
    ): ProvisionedAcpHarness = load(configuredPath, hostEnvironment, readHook)

    private fun load(
        configuredPath: String,
        hostEnvironment: Map<String, String>,
        readHook: AcpProvisioningReadTestHook?,
    ): ProvisionedAcpHarness {
        val path = provisioningPath(configuredPath)
        val bytes = readBoundedPrivateFile(path, readHook)
        val text = try {
            StandardCharsets.UTF_8.newDecoder()
                .onMalformedInput(CodingErrorAction.REPORT)
                .onUnmappableCharacter(CodingErrorAction.REPORT)
                .decode(ByteBuffer.wrap(bytes))
                .toString()
        } catch (failure: Exception) {
            throw IllegalArgumentException("ACP configuration must be strict UTF-8", failure)
        }
        val document = BoundedProvisioningJsonParser(text).parse()
        val configuration = parseConfiguration(document, hostEnvironment)
        val canonical = document.canonicalJson().toByteArray(StandardCharsets.UTF_8)
        return ProvisionedAcpHarness(configuration, sha256(canonical))
    }

    private fun parseConfiguration(
        document: ProvisioningJsonValue,
        hostEnvironment: Map<String, String>,
    ): AcpProcessConfiguration {
        val root = document.requireObject("ACP configuration")
        root.requireExactKeys(ROOT_KEYS, "ACP configuration")
        require(root.requiredInt("schemaVersion", 1..1, "ACP configuration") == CONFIG_SCHEMA_VERSION)
        val implementationId = root.requiredString("implementationId", MAXIMUM_IDENTIFIER_BYTES, "ACP configuration")
        require(implementationId.matches(Regex("[A-Za-z0-9_][A-Za-z0-9_.-]{0,127}"))) {
            "ACP implementationId must use portable identifier syntax"
        }

        val agent = root.requiredObject("agent", "ACP configuration")
        agent.requireExactKeys(AGENT_KEYS, "ACP agent configuration")
        require(!agent.requiredBoolean("inheritParentEnvironment", "ACP agent configuration")) {
            "ACP inheritParentEnvironment must be false"
        }
        require(agent.requiredString("permissionMode", 64, "ACP agent configuration") == "default-deny") {
            "ACP permissionMode must be default-deny"
        }
        val executable = agent.requiredPath("executable", "ACP agent configuration")
        val arguments = agent.requiredArray("arguments", MAXIMUM_SANDBOX_ARGUMENTS - 1, "ACP agent configuration")
            .mapIndexed { index, value ->
                value.requireString("ACP agent argument $index", MAXIMUM_CONFIG_STRING_BYTES)
            }
        val environment = parseEnvironment(agent.requiredArray(
            "environment",
            MAXIMUM_SANDBOX_ENVIRONMENT_BINDINGS,
            "ACP agent configuration",
        ), hostEnvironment)
        val capabilities = parseCapabilities(agent.requiredArray(
            "requiredCapabilities",
            AcpRequiredAgentCapability.entries.size,
            "ACP agent configuration",
        ))
        val timeouts = parseTimeouts(agent.requiredObject("timeoutsMillis", "ACP agent configuration"))
        val protocolLimits = agent.requiredObject("protocolLimits", "ACP agent configuration")
        protocolLimits.requireExactKeys(PROTOCOL_LIMIT_KEYS, "ACP protocol limits")
        val filesystemLimits = agent.requiredObject("filesystemLimits", "ACP agent configuration")
        filesystemLimits.requireExactKeys(FILESYSTEM_LIMIT_KEYS, "ACP filesystem limits")

        val sandbox = parseSandbox(root.requiredObject("sandbox", "ACP configuration"), executable)
        return AcpProcessConfiguration(
            executable = executable,
            arguments = arguments,
            environment = environment,
            inheritParentEnvironment = false,
            requiredAgentCapabilities = capabilities,
            timeouts = timeouts,
            maximumFrameBytes = protocolLimits.requiredInt(
                "maximumFrameBytes",
                1..MAXIMUM_ACP_FRAME_BYTES,
                "ACP protocol limits",
            ),
            maximumProtocolFrames = protocolLimits.requiredInt(
                "maximumProtocolFrames",
                1..MAXIMUM_ACP_PROTOCOL_FRAMES,
                "ACP protocol limits",
            ),
            maximumStderrBytes = protocolLimits.requiredInt(
                "maximumStderrBytes",
                1..MAXIMUM_ACP_STDERR_BYTES,
                "ACP protocol limits",
            ),
            implementationId = implementationId,
            filesystemLimits = AcpFilesystemLimits(
                maximumReadBytes = filesystemLimits.requiredInt(
                    "maximumReadBytes",
                    1..MAXIMUM_CONFIGURED_FILESYSTEM_BYTES,
                    "ACP filesystem limits",
                ),
                maximumWriteBytes = filesystemLimits.requiredInt(
                    "maximumWriteBytes",
                    1..MAXIMUM_CONFIGURED_FILESYSTEM_BYTES,
                    "ACP filesystem limits",
                ),
            ),
            sandboxBoundary = sandbox,
            // Terminal authority contains workflow-created staging identities and cannot safely be
            // provisioned statically. Workflow wiring must derive it from the exact request.
            terminalPolicy = null,
            permissionDecider = AcpNonInteractivePermissionDecider.DEFAULT_DENY,
            expectedExecutableManifestSha256 = agent.requiredSha256(
                "expectedExecutableManifestSha256",
                "ACP agent configuration",
            ),
        )
    }

    private fun parseEnvironment(
        values: List<ProvisioningJsonValue>,
        hostEnvironment: Map<String, String>,
    ): Map<String, AcpEnvironmentValue> {
        val result = LinkedHashMap<String, AcpEnvironmentValue>()
        values.forEachIndexed { index, value ->
            val entry = value.requireObject("ACP environment entry $index")
            val name = entry.requiredString("name", MAXIMUM_ENVIRONMENT_NAME_BYTES, "ACP environment entry $index")
            require(name.matches(Regex("[A-Za-z_][A-Za-z0-9_]*"))) {
                "ACP environment entry $index has an invalid name"
            }
            require(name !in result) { "ACP environment contains a duplicate name" }
            val provenanceText = entry.requiredString("provenance", 16, "ACP environment entry $index")
            val (provenance, configuredValue) = when (provenanceText) {
                "public" -> {
                    entry.requireExactKeys(PUBLIC_ENVIRONMENT_KEYS, "ACP environment entry $index")
                    AcpEnvironmentProvenance.PUBLIC to entry.requiredString(
                        "value",
                        MAXIMUM_CONFIG_STRING_BYTES,
                        "ACP environment entry $index",
                    )
                }
                "secret" -> {
                    entry.requireExactKeys(SECRET_ENVIRONMENT_KEYS, "ACP environment entry $index")
                    val sourceName = entry.requiredString(
                        "valueFromEnvironment",
                        MAXIMUM_ENVIRONMENT_NAME_BYTES,
                        "ACP environment entry $index",
                    )
                    require(sourceName.matches(Regex("[A-Za-z_][A-Za-z0-9_]*"))) {
                        "ACP environment entry $index has an invalid secret source name"
                    }
                    val secret = hostEnvironment[sourceName]
                        ?: throw IllegalArgumentException(
                            "ACP environment entry $index requires an unavailable secret source",
                        )
                    AcpEnvironmentProvenance.SECRET to secret
                }
                else -> throw IllegalArgumentException(
                    "ACP environment entry $index provenance must be public or secret",
                )
            }
            result[name] = AcpEnvironmentValue(configuredValue, provenance)
        }
        return result
    }

    private fun parseCapabilities(values: List<ProvisioningJsonValue>): Set<AcpRequiredAgentCapability> {
        val byWireName = AcpRequiredAgentCapability.entries.associateBy(AcpRequiredAgentCapability::diagnosticName)
        val result = linkedSetOf<AcpRequiredAgentCapability>()
        values.forEachIndexed { index, value ->
            val wireName = value.requireString("ACP required capability $index", 128)
            val capability = byWireName[wireName]
                ?: throw IllegalArgumentException("unknown ACP required capability at index $index")
            require(result.add(capability)) { "duplicate ACP required capability at index $index" }
        }
        return result
    }

    private fun parseTimeouts(value: ProvisioningJsonObject): AcpLifecycleTimeouts {
        value.requireExactKeys(TIMEOUT_KEYS, "ACP lifecycle timeouts")
        fun duration(name: String): Duration = Duration.ofMillis(
            value.requiredLong(name, 1L..MAXIMUM_TIMEOUT_MILLIS, "ACP lifecycle timeouts"),
        )
        return AcpLifecycleTimeouts(
            startup = duration("startup"),
            request = duration("request"),
            cancellationGrace = duration("cancellationGrace"),
            transportDrainGrace = duration("transportDrainGrace"),
            shutdown = duration("shutdown"),
        )
    }

    private fun parseSandbox(
        value: ProvisioningJsonObject,
        agentExecutable: Path,
    ): AcpLinuxSandboxConfiguration {
        value.requireExactKeys(SANDBOX_KEYS, "ACP sandbox configuration")
        val launcherMounts = parseMounts(value.requiredArray(
            "launcherRuntimeMounts",
            MAXIMUM_SANDBOX_MOUNTS,
            "ACP sandbox configuration",
        ), "launcher")
        val agentMounts = parseMounts(value.requiredArray(
            "agentRuntimeMounts",
            MAXIMUM_SANDBOX_MOUNTS,
            "ACP sandbox configuration",
        ), "agent")
        // The static policy owns at most MAXIMUM_SANDBOX_MOUNTS entries. The outer launch's
        // separately authenticated agent executable is the one additional mount accepted by the
        // boundary, matching AcpLinuxSandboxConfiguration and buildBubblewrapCommand.
        require(launcherMounts.size + agentMounts.size <= MAXIMUM_SANDBOX_MOUNTS) {
            "combined ACP runtime mounts exceed the authenticated count limit"
        }
        require((launcherMounts + agentMounts).none { mount ->
            mount.destination == agentExecutable ||
                mount.destination.startsWith(agentExecutable) ||
                agentExecutable.startsWith(mount.destination)
        }) { "ACP runtime mount destinations must not overlap the agent executable" }
        val resources = value.requiredObject("agentResourceLimits", "ACP sandbox configuration")
        resources.requireExactKeys(RESOURCE_LIMIT_KEYS, "ACP agent resource limits")
        val closure = value.requiredObject("runtimeClosureLimits", "ACP sandbox configuration")
        closure.requireExactKeys(CLOSURE_LIMIT_KEYS, "ACP runtime closure limits")
        return AcpLinuxSandboxConfiguration(
            bubblewrapExecutable = value.requiredPath("bubblewrapExecutable", "ACP sandbox configuration"),
            resourceLimiterExecutable = value.requiredPath("resourceLimiterExecutable", "ACP sandbox configuration"),
            scopeSupervisorExecutable = value.requiredPath("scopeSupervisorExecutable", "ACP sandbox configuration"),
            scopeInspectorExecutable = value.requiredPath("scopeInspectorExecutable", "ACP sandbox configuration"),
            environmentFdOpenerExecutable = value.requiredPath("environmentFdOpenerExecutable", "ACP sandbox configuration"),
            sandboxGateHelperExecutable = value.requiredPath("sandboxGateHelperExecutable", "ACP sandbox configuration"),
            launcherRuntimeMounts = launcherMounts,
            agentRuntimeMounts = agentMounts,
            systemdUserRuntimeDirectory = value.requiredPath("systemdUserRuntimeDirectory", "ACP sandbox configuration"),
            agentWorkingDirectory = value.requiredPath("agentWorkingDirectory", "ACP sandbox configuration"),
            agentResourceLimits = AcpSandboxResourceLimits(
                maximumProcesses = resources.requiredInt(
                    "maximumProcesses", 6..MAXIMUM_CONFIGURED_PROCESSES, "ACP agent resource limits",
                ),
                maximumOpenFiles = resources.requiredInt(
                    "maximumOpenFiles", 16..MAXIMUM_CONFIGURED_OPEN_FILES, "ACP agent resource limits",
                ),
                maximumFileBytes = resources.requiredLong(
                    "maximumFileBytes", 1L..MAXIMUM_CONFIGURED_FILE_BYTES, "ACP agent resource limits",
                ),
                maximumAddressSpaceBytes = resources.requiredLong(
                    "maximumAddressSpaceBytes",
                    MINIMUM_CONFIGURED_ADDRESS_SPACE_BYTES..MAXIMUM_CONFIGURED_ADDRESS_SPACE_BYTES,
                    "ACP agent resource limits",
                ),
                maximumCpuSeconds = resources.requiredInt(
                    "maximumCpuSeconds", 1..MAXIMUM_CONFIGURED_CPU_SECONDS, "ACP agent resource limits",
                ),
            ),
            runtimeClosureLimits = AcpRuntimeClosureLimits(
                maximumEntries = closure.requiredInt(
                    "maximumEntries", 1..MAXIMUM_CONFIGURED_CLOSURE_ENTRIES, "ACP runtime closure limits",
                ),
                maximumUserOwnedFileBytes = closure.requiredLong(
                    "maximumUserOwnedFileBytes",
                    1L..MAXIMUM_CONFIGURED_CLOSURE_BYTES,
                    "ACP runtime closure limits",
                ),
                maximumDepth = closure.requiredInt(
                    "maximumDepth", 1..MAXIMUM_CONFIGURED_CLOSURE_DEPTH, "ACP runtime closure limits",
                ),
            ),
            expectedBubblewrapSha256 = value.requiredSha256("expectedBubblewrapSha256", "ACP sandbox configuration"),
            expectedResourceLimiterSha256 = value.requiredSha256(
                "expectedResourceLimiterSha256", "ACP sandbox configuration",
            ),
            expectedScopeSupervisorSha256 = value.requiredSha256(
                "expectedScopeSupervisorSha256", "ACP sandbox configuration",
            ),
            expectedScopeInspectorSha256 = value.requiredSha256(
                "expectedScopeInspectorSha256", "ACP sandbox configuration",
            ),
            expectedEnvironmentFdOpenerSha256 = value.requiredSha256(
                "expectedEnvironmentFdOpenerSha256", "ACP sandbox configuration",
            ),
            expectedSandboxGateHelperSha256 = value.requiredSha256(
                "expectedSandboxGateHelperSha256", "ACP sandbox configuration",
            ),
            expectedSandboxGateHelperManifestSha256 = value.requiredSha256(
                "expectedSandboxGateHelperManifestSha256", "ACP sandbox configuration",
            ),
        )
    }

    private fun parseMounts(
        values: List<ProvisioningJsonValue>,
        group: String,
    ): List<AcpSandboxReadOnlyMount> = values.mapIndexed { index, value ->
        val mount = value.requireObject("ACP $group runtime mount $index")
        mount.requireExactKeys(MOUNT_KEYS, "ACP $group runtime mount $index")
        AcpSandboxReadOnlyMount(
            source = mount.requiredPath("source", "ACP $group runtime mount $index"),
            destination = mount.requiredPath("destination", "ACP $group runtime mount $index"),
            expectedManifestSha256 = mount.requiredSha256(
                "expectedManifestSha256",
                "ACP $group runtime mount $index",
            ),
        )
    }

    private fun provisioningPath(configuredPath: String): Path {
        val path = try {
            Path.of(configuredPath)
        } catch (failure: InvalidPathException) {
            throw IllegalArgumentException("ACP_CONFIG_FILE is not a valid path", failure)
        }
        require(path.isAbsolute && path == path.normalize()) {
            "ACP_CONFIG_FILE must be an absolute normalized path"
        }
        require(utf8Length(path.toString()) <= MAXIMUM_SANDBOX_PATH_BYTES) {
            "ACP_CONFIG_FILE exceeds the path-byte limit"
        }
        return path
    }

    private fun readBoundedPrivateFile(
        path: Path,
        readHook: AcpProvisioningReadTestHook?,
    ): ByteArray {
        try {
            val authorized = LinuxFilesystemSyscalls.openAbsolutePathOrNull(path)
                ?: throw IllegalArgumentException("ACP_CONFIG_FILE does not exist")
            authorized.use { pinned ->
                requirePrivateConfigurationIdentity(pinned.identity)
                readHook?.afterPinned?.invoke()
                LinuxFilesystemSyscalls.openReadableFrom(pinned).use { readable ->
                    val identityBefore = LinuxFilesystemSyscalls.identity(readable.fd)
                    requirePrivateConfigurationIdentity(identityBefore)
                    require(identityBefore.key == pinned.identity.key && identityBefore.mountId == pinned.identity.mountId) {
                        "ACP_CONFIG_FILE identity changed before it was read"
                    }
                    val descriptorPath = LinuxFilesystemSyscalls.stableDescriptorPath(readable.fd)
                    val before = Files.readAttributes(descriptorPath, BasicFileAttributes::class.java)
                    require(before.isRegularFile && !before.isSymbolicLink) {
                        "ACP_CONFIG_FILE must name a regular file without following links"
                    }
                    require(before.size() in 1..MAXIMUM_ACP_CONFIG_BYTES.toLong()) {
                        "ACP_CONFIG_FILE must contain between 1 and $MAXIMUM_ACP_CONFIG_BYTES bytes"
                    }
                    val bytes = try {
                        LinuxFilesystemSyscalls.read(readable, MAXIMUM_ACP_CONFIG_BYTES + 1) {}
                    } catch (failure: LinuxResourceLimitException) {
                        throw IllegalArgumentException(
                            "ACP_CONFIG_FILE exceeds the $MAXIMUM_ACP_CONFIG_BYTES-byte limit",
                            failure,
                        )
                    }
                    readHook?.afterRead?.invoke()
                    val identityAfter = LinuxFilesystemSyscalls.identity(readable.fd)
                    val after = Files.readAttributes(descriptorPath, BasicFileAttributes::class.java)
                    require(
                        identityAfter == identityBefore &&
                            after.isRegularFile &&
                            !after.isSymbolicLink &&
                            after.fileKey() == before.fileKey() &&
                            after.size() == before.size() &&
                            after.lastModifiedTime() == before.lastModifiedTime() &&
                            bytes.size.toLong() == before.size()
                    ) { "ACP_CONFIG_FILE changed while it was read" }
                    return bytes
                }
            }
        } catch (failure: IllegalArgumentException) {
            throw failure
        } catch (failure: Exception) {
            throw IllegalArgumentException("ACP_CONFIG_FILE could not be read securely", failure)
        }
    }

    private fun requirePrivateConfigurationIdentity(identity: LinuxFileIdentity) {
        require(identity.isRegularFile && !identity.isDirectory && !identity.isSymbolicLink) {
            "ACP_CONFIG_FILE must name a regular file without following links"
        }
        require(identity.mode.permissions and NON_OWNER_PERMISSION_MASK == 0) {
            "ACP_CONFIG_FILE must not grant group or other permissions"
        }
        val currentUid = (Files.getAttribute(Path.of("/proc/self"), "unix:uid") as Number).toInt()
        require(identity.uid == currentUid) { "ACP_CONFIG_FILE must be owned by the current user" }
        require(identity.linkCount == 1) { "ACP_CONFIG_FILE must have exactly one filesystem link" }
    }
}

private sealed interface ProvisioningJsonValue {
    fun canonicalJson(): String = buildString { appendCanonical(this@ProvisioningJsonValue) }
}

private data class ProvisioningJsonObject(val values: Map<String, ProvisioningJsonValue>) : ProvisioningJsonValue
private data class ProvisioningJsonArray(val values: List<ProvisioningJsonValue>) : ProvisioningJsonValue
private data class ProvisioningJsonString(val value: String) : ProvisioningJsonValue
private data class ProvisioningJsonNumber(val token: String) : ProvisioningJsonValue
private data class ProvisioningJsonBoolean(val value: Boolean) : ProvisioningJsonValue
private data object ProvisioningJsonNull : ProvisioningJsonValue

/** Small strict parser: duplicate names, excess depth/nodes, malformed Unicode, and trailing data fail. */
private class BoundedProvisioningJsonParser(private val source: String) {
    private var position = 0
    private var nodes = 0

    fun parse(): ProvisioningJsonValue {
        skipWhitespace()
        val result = parseValue(0)
        skipWhitespace()
        require(position == source.length) { "ACP configuration has trailing JSON data" }
        return result
    }

    private fun parseValue(depth: Int): ProvisioningJsonValue {
        require(depth <= MAXIMUM_CONFIG_JSON_DEPTH) { "ACP configuration exceeds the JSON depth limit" }
        nodes++
        require(nodes <= MAXIMUM_CONFIG_JSON_NODES) { "ACP configuration exceeds the JSON node limit" }
        require(position < source.length) { "ACP configuration JSON ended unexpectedly" }
        return when (source[position]) {
            '{' -> parseObject(depth)
            '[' -> parseArray(depth)
            '"' -> ProvisioningJsonString(parseString())
            't' -> parseLiteral("true", ProvisioningJsonBoolean(true))
            'f' -> parseLiteral("false", ProvisioningJsonBoolean(false))
            'n' -> parseLiteral("null", ProvisioningJsonNull)
            '-', in '0'..'9' -> ProvisioningJsonNumber(parseNumber())
            else -> throw IllegalArgumentException("ACP configuration contains invalid JSON at byte-character $position")
        }
    }

    private fun parseObject(depth: Int): ProvisioningJsonObject {
        position++
        skipWhitespace()
        val values = LinkedHashMap<String, ProvisioningJsonValue>()
        if (consume('}')) return ProvisioningJsonObject(values)
        while (true) {
            require(position < source.length && source[position] == '"') {
                "ACP configuration object key must be a string"
            }
            val name = parseString()
            require(name !in values) { "ACP configuration contains a duplicate JSON key" }
            skipWhitespace()
            require(consume(':')) { "ACP configuration object key is missing ':'" }
            skipWhitespace()
            values[name] = parseValue(depth + 1)
            skipWhitespace()
            if (consume('}')) break
            require(consume(',')) { "ACP configuration object is missing ','" }
            skipWhitespace()
        }
        return ProvisioningJsonObject(values)
    }

    private fun parseArray(depth: Int): ProvisioningJsonArray {
        position++
        skipWhitespace()
        val values = ArrayList<ProvisioningJsonValue>()
        if (consume(']')) return ProvisioningJsonArray(values)
        while (true) {
            values += parseValue(depth + 1)
            skipWhitespace()
            if (consume(']')) break
            require(consume(',')) { "ACP configuration array is missing ','" }
            skipWhitespace()
        }
        return ProvisioningJsonArray(values)
    }

    private fun parseString(): String {
        require(consume('"')) { "ACP configuration string is missing its opening quote" }
        val result = StringBuilder()
        while (position < source.length) {
            when (val character = source[position++]) {
                '"' -> {
                    require(utf8Length(result.toString()) <= MAXIMUM_CONFIG_STRING_BYTES) {
                        "ACP configuration string exceeds the byte limit"
                    }
                    return result.toString()
                }
                '\\' -> appendEscape(result)
                else -> {
                    require(character.code >= 0x20) { "ACP configuration string contains a control character" }
                    when {
                        Character.isHighSurrogate(character) -> {
                            require(position < source.length && Character.isLowSurrogate(source[position])) {
                                "ACP configuration string contains malformed Unicode"
                            }
                            result.append(character).append(source[position++])
                        }
                        Character.isLowSurrogate(character) -> throw IllegalArgumentException(
                            "ACP configuration string contains malformed Unicode",
                        )
                        else -> result.append(character)
                    }
                }
            }
            require(result.length <= MAXIMUM_CONFIG_STRING_CHARACTERS) {
                "ACP configuration string exceeds the character limit"
            }
        }
        throw IllegalArgumentException("ACP configuration string is unterminated")
    }

    private fun appendEscape(result: StringBuilder) {
        require(position < source.length) { "ACP configuration JSON escape is incomplete" }
        when (val escaped = source[position++]) {
            '"', '\\', '/' -> result.append(escaped)
            'b' -> result.append('\b')
            'f' -> result.append('\u000c')
            'n' -> result.append('\n')
            'r' -> result.append('\r')
            't' -> result.append('\t')
            'u' -> {
                val first = readUnicodeEscape()
                when {
                    Character.isHighSurrogate(first) -> {
                        require(position + 1 < source.length && source[position] == '\\' && source[position + 1] == 'u') {
                            "ACP configuration string contains an unpaired high surrogate"
                        }
                        position += 2
                        val second = readUnicodeEscape()
                        require(Character.isLowSurrogate(second)) {
                            "ACP configuration string contains an unpaired high surrogate"
                        }
                        result.append(first).append(second)
                    }
                    Character.isLowSurrogate(first) -> throw IllegalArgumentException(
                        "ACP configuration string contains an unpaired low surrogate",
                    )
                    else -> result.append(first)
                }
            }
            else -> throw IllegalArgumentException("ACP configuration contains invalid JSON escape: \\$escaped")
        }
    }

    private fun readUnicodeEscape(): Char {
        require(position + 4 <= source.length) { "ACP configuration Unicode escape is incomplete" }
        var value = 0
        repeat(4) {
            val digit = when (val character = source[position++]) {
                in '0'..'9' -> character.code - '0'.code
                in 'a'..'f' -> character.code - 'a'.code + 10
                in 'A'..'F' -> character.code - 'A'.code + 10
                else -> throw IllegalArgumentException("ACP configuration Unicode escape is malformed")
            }
            value = value * 16 + digit
        }
        return value.toChar()
    }

    private fun parseNumber(): String {
        val start = position
        consume('-')
        require(position < source.length) { "ACP configuration number is incomplete" }
        if (consume('0')) {
            require(position >= source.length || source[position] !in '0'..'9') {
                "ACP configuration number has a leading zero"
            }
        } else {
            require(position < source.length && source[position] in '1'..'9') {
                "ACP configuration number is malformed"
            }
            while (position < source.length && source[position] in '0'..'9') position++
        }
        if (consume('.')) {
            require(position < source.length && source[position] in '0'..'9') {
                "ACP configuration fraction is malformed"
            }
            while (position < source.length && source[position] in '0'..'9') position++
        }
        if (position < source.length && source[position] in setOf('e', 'E')) {
            position++
            if (position < source.length && source[position] in setOf('+', '-')) position++
            require(position < source.length && source[position] in '0'..'9') {
                "ACP configuration exponent is malformed"
            }
            while (position < source.length && source[position] in '0'..'9') position++
        }
        return source.substring(start, position)
    }

    private fun <T : ProvisioningJsonValue> parseLiteral(token: String, value: T): T {
        require(source.regionMatches(position, token, 0, token.length)) {
            "ACP configuration contains malformed JSON literal"
        }
        position += token.length
        return value
    }

    private fun skipWhitespace() {
        while (position < source.length && source[position] in JSON_WHITESPACE) position++
    }

    private fun consume(expected: Char): Boolean {
        if (position >= source.length || source[position] != expected) return false
        position++
        return true
    }
}

private fun ProvisioningJsonValue.requireObject(label: String): ProvisioningJsonObject =
    this as? ProvisioningJsonObject ?: throw IllegalArgumentException("$label must be a JSON object")

private fun ProvisioningJsonValue.requireString(label: String, maximumBytes: Int): String {
    val value = (this as? ProvisioningJsonString)?.value
        ?: throw IllegalArgumentException("$label must be a JSON string")
    require(utf8Length(value) <= maximumBytes.toLong()) { "$label exceeds the $maximumBytes-byte limit" }
    return value
}

private fun ProvisioningJsonObject.requireExactKeys(expected: Set<String>, label: String) {
    val missing = expected - values.keys
    require(missing.isEmpty()) { "$label is missing required field ${missing.sorted().first()}" }
    val unknown = values.keys - expected
    require(unknown.isEmpty()) { "$label contains an unknown field" }
}

private fun ProvisioningJsonObject.requiredValue(name: String, label: String): ProvisioningJsonValue =
    values[name] ?: throw IllegalArgumentException("$label is missing required field $name")

private fun ProvisioningJsonObject.requiredObject(name: String, label: String): ProvisioningJsonObject =
    requiredValue(name, label).requireObject("$label.$name")

private fun ProvisioningJsonObject.requiredArray(
    name: String,
    maximumEntries: Int,
    label: String,
): List<ProvisioningJsonValue> {
    val array = requiredValue(name, label) as? ProvisioningJsonArray
        ?: throw IllegalArgumentException("$label.$name must be a JSON array")
    require(array.values.size <= maximumEntries) {
        "$label.$name exceeds the $maximumEntries-entry limit"
    }
    return array.values
}

private fun ProvisioningJsonObject.requiredString(
    name: String,
    maximumBytes: Int,
    label: String,
): String = requiredValue(name, label).requireString("$label.$name", maximumBytes)

private fun ProvisioningJsonObject.requiredBoolean(name: String, label: String): Boolean =
    (requiredValue(name, label) as? ProvisioningJsonBoolean)?.value
        ?: throw IllegalArgumentException("$label.$name must be a JSON boolean")

private fun ProvisioningJsonObject.requiredInt(
    name: String,
    range: IntRange,
    label: String,
): Int {
    val value = requiredLong(name, range.first.toLong()..range.last.toLong(), label)
    return value.toInt()
}

private fun ProvisioningJsonObject.requiredLong(
    name: String,
    range: LongRange,
    label: String,
): Long {
    val token = (requiredValue(name, label) as? ProvisioningJsonNumber)?.token
        ?: throw IllegalArgumentException("$label.$name must be a JSON integer")
    require('.' !in token && 'e' !in token.lowercase()) { "$label.$name must be a JSON integer" }
    val value = token.toLongOrNull() ?: throw IllegalArgumentException("$label.$name is outside the integer range")
    require(value in range) { "$label.$name must be in ${range.first}..${range.last}" }
    return value
}

private fun ProvisioningJsonObject.requiredPath(name: String, label: String): Path {
    val text = requiredString(name, MAXIMUM_SANDBOX_PATH_BYTES.toInt(), label)
    val path = try {
        Path.of(text)
    } catch (failure: InvalidPathException) {
        throw IllegalArgumentException("$label.$name is not a valid path", failure)
    }
    require(path.isAbsolute && path == path.normalize()) { "$label.$name must be an absolute normalized path" }
    return path
}

private fun ProvisioningJsonObject.requiredSha256(name: String, label: String): String {
    val digest = requiredString(name, 64, label)
    require(digest.matches(Regex("[0-9a-f]{64}"))) { "$label.$name must be lowercase SHA-256" }
    return digest
}

private fun StringBuilder.appendCanonical(value: ProvisioningJsonValue) {
    when (value) {
        is ProvisioningJsonObject -> {
            append('{')
            value.values.toSortedMap().entries.forEachIndexed { index, (name, child) ->
                if (index > 0) append(',')
                appendCanonicalString(name)
                append(':')
                appendCanonical(child)
            }
            append('}')
        }
        is ProvisioningJsonArray -> {
            append('[')
            value.values.forEachIndexed { index, child ->
                if (index > 0) append(',')
                appendCanonical(child)
            }
            append(']')
        }
        is ProvisioningJsonString -> appendCanonicalString(value.value)
        is ProvisioningJsonNumber -> append(value.token)
        is ProvisioningJsonBoolean -> append(if (value.value) "true" else "false")
        ProvisioningJsonNull -> append("null")
    }
}

private fun StringBuilder.appendCanonicalString(value: String) {
    append('"')
    value.forEach { character ->
        when (character) {
            '"' -> append("\\\"")
            '\\' -> append("\\\\")
            '\b' -> append("\\b")
            '\u000c' -> append("\\f")
            '\n' -> append("\\n")
            '\r' -> append("\\r")
            '\t' -> append("\\t")
            else -> if (character.code < 0x20) {
                append("\\u").append(character.code.toString(16).padStart(4, '0'))
            } else append(character)
        }
    }
    append('"')
}

private fun sha256(bytes: ByteArray): String = MessageDigest.getInstance("SHA-256")
    .digest(bytes)
    .joinToString("") { "%02x".format(it) }

private const val CONFIG_SCHEMA_VERSION = 1
private const val MAXIMUM_ACP_CONFIG_BYTES = 4 * 1024 * 1024
private const val MAXIMUM_CONFIG_JSON_DEPTH = 16
private const val MAXIMUM_CONFIG_JSON_NODES = 16_384
private const val MAXIMUM_CONFIG_STRING_BYTES = 1024 * 1024
private const val MAXIMUM_CONFIG_STRING_CHARACTERS = 1024 * 1024
private const val MAXIMUM_IDENTIFIER_BYTES = 128
private const val MAXIMUM_ENVIRONMENT_NAME_BYTES = 256
private const val MAXIMUM_CONFIGURED_FILESYSTEM_BYTES = 8 * 1024 * 1024
private const val MAXIMUM_CONFIGURED_PROCESSES = 32
private const val MAXIMUM_CONFIGURED_OPEN_FILES = 256
private const val MAXIMUM_CONFIGURED_FILE_BYTES = 64L * 1024 * 1024
private const val MINIMUM_CONFIGURED_ADDRESS_SPACE_BYTES = 64L * 1024 * 1024
private const val MAXIMUM_CONFIGURED_ADDRESS_SPACE_BYTES = 2L * 1024 * 1024 * 1024
private const val MAXIMUM_CONFIGURED_CPU_SECONDS = 120
private const val MAXIMUM_CONFIGURED_CLOSURE_ENTRIES = 100_000
private const val MAXIMUM_CONFIGURED_CLOSURE_BYTES = 2L * 1024 * 1024 * 1024
private const val MAXIMUM_CONFIGURED_CLOSURE_DEPTH = 64
private const val MAXIMUM_TIMEOUT_MILLIS = 60L * 60 * 1000

private val JSON_WHITESPACE = setOf(' ', '\t', '\r', '\n')
private const val NON_OWNER_PERMISSION_MASK = 0x3f // 0077
private val ROOT_KEYS = setOf("schemaVersion", "implementationId", "agent", "sandbox")
private val AGENT_KEYS = setOf(
    "executable",
    "arguments",
    "environment",
    "inheritParentEnvironment",
    "requiredCapabilities",
    "timeoutsMillis",
    "protocolLimits",
    "filesystemLimits",
    "permissionMode",
    "expectedExecutableManifestSha256",
)
private val PUBLIC_ENVIRONMENT_KEYS = setOf("name", "value", "provenance")
private val SECRET_ENVIRONMENT_KEYS = setOf("name", "valueFromEnvironment", "provenance")
private val TIMEOUT_KEYS = setOf(
    "startup",
    "request",
    "cancellationGrace",
    "transportDrainGrace",
    "shutdown",
)
private val PROTOCOL_LIMIT_KEYS = setOf("maximumFrameBytes", "maximumProtocolFrames", "maximumStderrBytes")
private val FILESYSTEM_LIMIT_KEYS = setOf("maximumReadBytes", "maximumWriteBytes")
private val MOUNT_KEYS = setOf("source", "destination", "expectedManifestSha256")
private val RESOURCE_LIMIT_KEYS = setOf(
    "maximumProcesses",
    "maximumOpenFiles",
    "maximumFileBytes",
    "maximumAddressSpaceBytes",
    "maximumCpuSeconds",
)
private val CLOSURE_LIMIT_KEYS = setOf("maximumEntries", "maximumUserOwnedFileBytes", "maximumDepth")
private val SANDBOX_KEYS = setOf(
    "bubblewrapExecutable",
    "resourceLimiterExecutable",
    "scopeSupervisorExecutable",
    "scopeInspectorExecutable",
    "environmentFdOpenerExecutable",
    "sandboxGateHelperExecutable",
    "systemdUserRuntimeDirectory",
    "agentWorkingDirectory",
    "launcherRuntimeMounts",
    "agentRuntimeMounts",
    "agentResourceLimits",
    "runtimeClosureLimits",
    "expectedBubblewrapSha256",
    "expectedResourceLimiterSha256",
    "expectedScopeSupervisorSha256",
    "expectedScopeInspectorSha256",
    "expectedEnvironmentFdOpenerSha256",
    "expectedSandboxGateHelperSha256",
    "expectedSandboxGateHelperManifestSha256",
)
