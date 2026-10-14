package decompengine.acp

import java.util.Collections
import kotlinx.serialization.json.*

/** Closed, domain-separated DAG candidates. None authenticate a signature or grant policy authority. */
internal object AcpProviderDnsApprovalCandidates {
    enum class Node { A, I, M, P, E, F, Q }
    class Candidate internal constructor(val node: Node, val sha256: String, references: Map<Node, String>,
        internal val document: JsonObject) {
        val references: Map<Node, String> = Collections.unmodifiableMap(references.toMap())
    }
    class Receipt internal constructor(val sha256: String, val kind: String, val root: String,
        subjects: Map<Node, String>) {
        internal val subjects: Map<Node, String> = Collections.unmodifiableMap(subjects.toMap())
    }
    private val receiptSubjects = mapOf("source" to setOf(Node.A, Node.I), "provisioning" to setOf(Node.P),
        "policy-decision" to setOf(Node.P), "independent-review" to setOf(Node.M, Node.P))
    private val generatedResources = setOf("META-INF/provider-dns/application-input-v1.json",
        "META-INF/provider-dns/build-input-v1.json", "META-INF/provider-dns/runtime-manifest-v2.json",
        "META-INF/provider-dns/resolver-core-v2.json", "META-INF/provider-dns/approval-envelope-v2.json")

    /** A hashes the closed code/build-input manifest, with schema-fixed generated-resource exclusions. */
    fun applicationInput(bytes: ByteArray): Candidate {
        val obj = dnsObject(bytes)
        obj.dnsKeys("schema", "sourceFiles", "dependencyLocks", "buildRecipeSha256", "workerSha256")
        require(obj.dnsText("schema") == "provider-dns-application-input-v1")
        val allPaths = hashSetOf<String>()
        for (key in listOf("sourceFiles", "dependencyLocks")) {
            val entries = obj.getValue(key).jsonArray
            require(entries.size in 1..2048)
            val paths = entries.map { raw -> val entry = raw.jsonObject; entry.dnsKeys("path", "size", "sha256")
                val path = dnsRelativePath(entry.dnsText("path"))
                require(path !in generatedResources && !path.startsWith("META-INF/provider-dns/") &&
                    !path.startsWith("receipts/") && allPaths.add(path))
                require(entry.dnsLong("size") in 1..AcpProviderDnsBuildInputs.MEMBER_BYTES); entry.dnsHash("sha256"); path }
            require(paths == paths.sorted())
        }
        obj.dnsHash("buildRecipeSha256"); obj.dnsHash("workerSha256")
        return candidate(Node.A, obj, emptyMap())
    }

    fun inputLock(lock: AcpProviderDnsBuildInputs.InputLock): Candidate = Candidate(Node.I, lock.sha256, emptyMap(),
        buildJsonObject { put("schema", "provider-dns-build-input-v1-reference"); put("inputLockSha256", lock.sha256) })

    /** M v2 binds A/I and the separately inspected regular archive/tree/ABI/loader/mount identities. */
    fun runtimeManifest(bytes: ByteArray, a: Candidate, i: Candidate): Candidate {
        require(a.node == Node.A && i.node == Node.I)
        val obj = dnsObject(bytes)
        obj.dnsKeys("schema", "profileId", "applicationInputSha256", "buildInputLockSha256", "archiveSha256",
            "fileManifestSha256", "workerSha256", "abi", "loaderClosureSha256", "dependencyClosureSha256", "mountClosureSha256", "limits")
        require(obj.dnsText("schema") == "provider-dns-runtime-manifest-v2" &&
            obj.dnsText("profileId") == "linux-x86_64-jdk21-dns-v2" && obj.dnsText("abi") == "linux-glibc-x86_64")
        require(obj.dnsHash("applicationInputSha256") == a.sha256 && obj.dnsHash("buildInputLockSha256") == i.sha256 &&
            obj.dnsHash("workerSha256") == a.document.dnsHash("workerSha256"))
        for (key in listOf("archiveSha256", "fileManifestSha256", "loaderClosureSha256", "dependencyClosureSha256", "mountClosureSha256")) obj.dnsHash(key)
        val limits = obj.getValue("limits").jsonObject
        val bounds = mapOf("entries" to 2048L, "depth" to 16L, "bytes" to 256L * 1024 * 1024,
            "fileBytes" to 16L * 1024 * 1024, "moduleBytes" to 192L * 1024 * 1024, "edges" to 256L, "nativeLibraries" to 32L)
        limits.dnsKeys(*bounds.keys.toTypedArray())
        bounds.forEach { (key, maximum) -> require(limits.dnsLong(key) in 1..maximum) }
        return candidate(Node.M, obj, mapOf(Node.A to a.sha256, Node.I to i.sha256))
    }

    /** P contains policy inputs and exact resolver bytes, never decisions/reviews attesting P. */
    fun resolverCore(bytes: ByteArray, a: Candidate, m: Candidate): Candidate {
        require(a.node == Node.A && m.node == Node.M && m.references[Node.A] == a.sha256)
        val obj = dnsObject(bytes)
        obj.dnsKeys("schema", "policyId", "revision", "applicationInputSha256", "runtimeManifestSha256", "workerSha256",
            "resolverFiles", "resolverPolicySha256", "transport", "network", "dnsDestinations", "sourceOwner", "queryPolicy",
            "launchClosureSha256", "sourceClosureSha256")
        require(obj.dnsText("schema") == "provider-dns-resolver-core-v2")
        dnsIdentifier(obj.dnsText("policyId")); require(obj.dnsLong("revision") > 0)
        require(obj.dnsHash("applicationInputSha256") == a.sha256 && obj.dnsHash("runtimeManifestSha256") == m.sha256 &&
            obj.dnsHash("workerSha256") == m.document.dnsHash("workerSha256"))
        val files = obj.getValue("resolverFiles").jsonObject
        files.dnsKeys("resolv.conf", "nsswitch.conf", "hosts")
        fun file(name: String): ByteArray {
            val record = files.getValue(name).jsonObject; record.dnsKeys("bytes", "size", "sha256")
            val text = record.dnsText("bytes")
            require(text.all { it == '\n' || it.code in 32..126 })
            return text.toByteArray(Charsets.US_ASCII).also { require(record.dnsLong("size") == it.size.toLong() && record.dnsHash("sha256") == dnsSha(it)) }
        }
        val resolverBytes = file("resolv.conf")
        val resolver = AcpProviderDnsResolverCandidate.parseForValidation(resolverBytes, file("nsswitch.conf"), file("hosts"))
        require(obj.dnsHash("resolverPolicySha256") == resolver.sha256)
        val addresses = resolverBytes.toString(Charsets.US_ASCII).lineSequence().filter { it.startsWith("nameserver ") }
            .map { it.removePrefix("nameserver ") }.toList()
        val transport = obj.getValue("transport").jsonObject
        transport.dnsKeys("descriptorSha256", "endpoint", "operation")
        transport.dnsHash("descriptorSha256")
        require(transport.dnsText("endpoint") == "https://chatgpt.com/backend-api/codex/responses" && transport.dnsText("operation") == "RESPONSES_CREATE")
        val network = obj.getValue("network").jsonObject
        network.dnsKeys("authorityId", "authoritySha256", "placementId", "policyInputSha256")
        dnsIdentifier(network.dnsText("authorityId")); dnsIdentifier(network.dnsText("placementId"))
        network.dnsHash("authoritySha256"); network.dnsHash("policyInputSha256")
        val destinations = obj.getValue("dnsDestinations").jsonArray
        require(destinations.size == addresses.size)
        destinations.forEachIndexed { index, raw ->
            val destination = raw.jsonObject
            destination.dnsKeys("address", "port", "transports", "operatorId", "classification", "permissionInputSha256")
            require(destination.dnsText("address") == addresses[index] && destination.dnsLong("port") == 53L)
            val transports = destination.getValue("transports").jsonArray.map { it.dnsString() }
            require(transports == listOf("UDP") || transports == listOf("UDP", "TCP"))
            dnsIdentifier(destination.dnsText("operatorId"))
            require(destination.dnsText("classification") in setOf("public", "private", "local"))
            destination.dnsHash("permissionInputSha256") // A declaration of an input, not inferred resolver permission.
        }
        val owner = obj.getValue("sourceOwner").jsonObject
        owner.dnsKeys("policy", "uid", "gid", "treeIdentitySha256", "mode", "links", "acl", "capabilities", "xattrs")
        val uid = owner.dnsLong("uid"); val gid = owner.dnsLong("gid")
        require(uid <= Int.MAX_VALUE && gid <= Int.MAX_VALUE &&
            (owner.dnsText("policy") == "root" && uid == 0L && gid == 0L || owner.dnsText("policy") == "service" && uid > 0L))
        require(owner.dnsText("mode") == "0644" && owner.dnsLong("links") == 1L &&
            owner.dnsText("acl") == "absent" && owner.dnsText("capabilities") == "absent" && owner.getValue("xattrs").jsonArray.isEmpty())
        owner.dnsHash("treeIdentitySha256")
        val query = obj.getValue("queryPolicy").jsonObject
        query.dnsKeys("hostname", "types", "search", "utsHostname", "semanticsInputSha256")
        require(query.dnsText("hostname") == "chatgpt.com" && query.getValue("types").jsonArray.map { it.dnsString() } == listOf("A", "AAAA") &&
            query.dnsText("search") == "none" && query.dnsText("utsHostname").matches(Regex("[a-z0-9][a-z0-9-]{0,62}")))
        query.dnsHash("semanticsInputSha256"); obj.dnsHash("launchClosureSha256"); obj.dnsHash("sourceClosureSha256")
        return candidate(Node.P, obj, mapOf(Node.A to a.sha256, Node.M to m.sha256))
    }

    /** Detached receipt syntax only. Signature/evidence hashes and roots are not verification. */
    fun receipt(bytes: ByteArray): Receipt {
        val obj = dnsObject(bytes)
        obj.dnsKeys("schema", "kind", "rootSha256", "subjects", "evidenceSha256", "signatureSha256")
        require(obj.dnsText("schema") == "provider-dns-approval-receipt-candidate-v1")
        val kind = obj.dnsText("kind"); val required = requireNotNull(receiptSubjects[kind])
        val subjects = obj.getValue("subjects").jsonObject
        subjects.dnsKeys(*required.map { it.name }.toTypedArray())
        val refs = required.associateWith { subjects.dnsHash(it.name) }
        obj.dnsHash("evidenceSha256"); obj.dnsHash("signatureSha256")
        return Receipt(dnsDomainHash("provider-dns-approval-receipt-candidate-v1", obj), kind, obj.dnsHash("rootSha256"), refs)
    }

    /** E cites earlier immutable receipts. Caller expectations here remain inert validation inputs. */
    fun envelope(bytes: ByteArray, a: Candidate, i: Candidate, m: Candidate, p: Candidate,
        receipts: List<Receipt>, recognizedRootCandidates: Map<String, String> = emptyMap()): Candidate {
        require(a.node == Node.A && i.node == Node.I && m.node == Node.M && p.node == Node.P)
        require(m.references == mapOf(Node.A to a.sha256, Node.I to i.sha256) && p.references == mapOf(Node.A to a.sha256, Node.M to m.sha256))
        val obj = dnsObject(bytes); obj.dnsKeys("schema", "A", "I", "M", "P", "receipts")
        require(obj.dnsText("schema") == "provider-dns-approval-envelope-v2")
        val refs = mapOf(Node.A to a.sha256, Node.I to i.sha256, Node.M to m.sha256, Node.P to p.sha256)
        refs.forEach { (node, hash) -> require(obj.dnsHash(node.name) == hash) }
        require(receipts.size == receiptSubjects.size && receipts.map { it.kind }.toSet() == receiptSubjects.keys)
        val declarations = obj.getValue("receipts").jsonObject
        declarations.dnsKeys(*receiptSubjects.keys.toTypedArray())
        receipts.forEach { receipt ->
            require(recognizedRootCandidates[receipt.kind] == receipt.root && declarations.dnsHash(receipt.kind) == receipt.sha256 &&
                receipt.subjects.all { refs[it.key] == it.value })
        }
        return candidate(Node.E, obj, refs)
    }

    class FinalArtifactObservation internal constructor(val artifactSha256: String, resources: Map<Node, String>) {
        val resources = Collections.unmodifiableMap(resources.toMap())
    }

    /** External post-packaging observation candidate; parsing does not verify the packaged bytes. */
    fun finalArtifactObservation(bytes: ByteArray, a: Candidate, i: Candidate, m: Candidate, p: Candidate, e: Candidate): FinalArtifactObservation {
        require(listOf(a, i, m, p, e).map { it.node } == listOf(Node.A, Node.I, Node.M, Node.P, Node.E))
        val obj = dnsObject(bytes)
        obj.dnsKeys("schema", "artifactSha256", "embeddedResources")
        require(obj.dnsText("schema") == "provider-dns-final-artifact-observation-candidate-v1")
        val resources = obj.getValue("embeddedResources").jsonObject
        resources.dnsKeys("A", "I", "M", "P", "E")
        val refs = listOf(a, i, m, p, e).associate { it.node to it.sha256 }
        refs.forEach { (node, hash) -> require(resources.dnsHash(node.name) == hash) }
        val f = obj.dnsHash("artifactSha256"); require(f !in refs.values)
        return FinalArtifactObservation(f, refs)
    }

    /** Q is external; F is the actual final artifact digest, not A or a hash embedded back into F. */
    fun qualification(bytes: ByteArray, a: Candidate, i: Candidate, m: Candidate, p: Candidate, e: Candidate,
        observedFinalArtifact: FinalArtifactObservation): Candidate {
        require(listOf(a, i, m, p, e).map { it.node } == listOf(Node.A, Node.I, Node.M, Node.P, Node.E))
        val obj = dnsObject(bytes)
        obj.dnsKeys("schema", "A", "I", "M", "P", "E", "finalArtifactSha256", "nativeEvidenceSha256", "qualificationReviewSha256", "deploymentDecisionSha256")
        require(obj.dnsText("schema") == "provider-dns-external-qualification-candidate-v1")
        val refs = listOf(a, i, m, p, e).associate { it.node to it.sha256 }
        require(e.references == refs.filterKeys { it != Node.E })
        refs.forEach { (node, hash) -> require(obj.dnsHash(node.name) == hash) }
        val f = observedFinalArtifact.artifactSha256
        require(observedFinalArtifact.resources == refs && f !in refs.values && obj.dnsHash("finalArtifactSha256") == f)
        listOf("nativeEvidenceSha256", "qualificationReviewSha256", "deploymentDecisionSha256").forEach { obj.dnsHash(it) }
        return candidate(Node.Q, obj, refs + (Node.F to f))
    }

    private fun candidate(node: Node, obj: JsonObject, refs: Map<Node, String>) =
        Candidate(node, dnsDomainHash(obj.dnsText("schema"), obj), refs, obj)
    private fun dnsIdentifier(value: String) { require(value.matches(Regex("[a-z0-9][a-z0-9._-]{0,127}"))) }
}
