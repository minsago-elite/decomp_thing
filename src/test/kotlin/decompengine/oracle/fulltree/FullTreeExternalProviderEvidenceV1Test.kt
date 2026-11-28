package decompengine.oracle.fulltree

import decompengine.analysis.AnalysisDeadline
import decompengine.oracle.core.OracleArtifacts
import decompengine.oracle.core.OracleJson
import decompengine.oracle.externalcalls.BoundedElfDynamicBindingsV1
import decompengine.oracle.externalcalls.DynamicBindingElfFixtureV1
import java.nio.file.Files
import java.util.concurrent.TimeUnit
import kotlin.test.*
import kotlinx.serialization.json.*

class FullTreeExternalProviderEvidenceV1Test {
    @Test fun `R2 V2 V3 loader cache present accepts only boolean tokens including populated true`() {
        for (version in listOf(2, 3)) {
            val raw = OracleJson.parseCanonical(candidate(version)).jsonObject
            val graph = raw["subjectStaticElfClosure"]!!.jsonObject
            val populated = buildJsonObject {
                put("present", true); put("path", "/etc/ld.so.cache"); put("inode", 3); put("bytes", 100)
                put("sha256", "b".repeat(64)); put("format", "glibc-ld.so.cache-1.1"); put("legacyCompatibilityPrefix", false); put("entries", 1)
                put("extensions", buildJsonArray { add(buildJsonObject {
                    put("tag", 1); put("flags", 0); put("bytes", 8); put("hwcapNames", buildJsonArray { add("x86-64-v3") })
                }) })
            }
            fun adapt(cache: JsonObject) = FullTreeExternalProviderEvidenceV1.fromRawMeasurement(OracleJson.canonicalBytes(
                JsonObject(raw + ("subjectStaticElfClosure" to JsonObject(graph + ("loaderCache" to cache))))), budget())
            for (cache in listOf(graph["loaderCache"]!!.jsonObject, populated)) {
                val result = adapt(cache)
                assertEquals(cache, result.staticGraph["loaderCache"])
                for (bad in listOf(JsonPrimitive(cache["present"]!!.jsonPrimitive.content), JsonNull, JsonPrimitive(0), JsonPrimitive(1), JsonArray(emptyList()), JsonObject(emptyMap())))
                    assertFails("V$version cache present=$bad") { adapt(JsonObject(cache + ("present" to bad))) }
                assertFails { adapt(JsonObject(cache - "present")) }
            }
        }
    }

    @Test fun `complete inert V2 and V3 producer shapes are retained without authority`() {
        for (version in listOf(2, 3)) {
            val raw = candidate(version)
            val retained = FullTreeExternalProviderEvidenceV1.fromRawMeasurement(raw, budget())
            assertEquals(version, retained.schemaVersion)
            assertEquals(0, retained.candidateCount)
            assertContentEquals(raw, retained.snapshot())
            assertEquals("native-runtime-measurement-candidate-v$version", retained.schemaKind)
            assertTrue(retained.limitations.isNotEmpty())
            val callerBytes = retained.snapshot(); callerBytes.fill(0)
            assertContentEquals(raw, retained.snapshot())
            assertFails { (retained.nodes as MutableList).clear() }
            val altered = mutate(raw) { put("containmentProved", JsonPrimitive(true)) }
            assertFails { FullTreeExternalProviderEvidenceV1.fromRawMeasurement(altered, budget()) }
        }
    }

    @Test fun `static candidate graph path and layer facts reject inconsistent substitutions`() {
        val raw = candidate(2)
        val altered = mutate(raw) {
            val layers = getValue("orderedRawLayers").jsonArray
            val layer = layers.single().jsonObject
            val changed = JsonObject(layer + ("uncompressedDiffId" to JsonPrimitive("sha256:${"c".repeat(64)}")))
            put("orderedRawLayers", JsonArray(listOf(changed)))
        }
        // Empty layer populations remain invalid because inspect/export layer order must be nonempty.
        assertFails { FullTreeExternalProviderEvidenceV1.fromRawMeasurement(altered, budget()) }
        val graphChanged = mutate(raw) {
            val graph = getValue("subjectStaticElfClosure").jsonObject
            put("subjectStaticElfClosure", JsonObject(graph + ("libraryClosureQualified" to JsonPrimitive(true))))
        }
        assertFails { FullTreeExternalProviderEvidenceV1.fromRawMeasurement(graphChanged, budget()) }
    }

    @Test fun `recorded closure verifies exact hash and retains no executable binding`() {
        val raw = closure()
        val projected = FullTreeExternalProviderEvidenceV1.fromRecordedClosure(raw, budget())
        assertFalse(projected.executableBindingPresent)
        assertEquals(1, projected.interpreterCount)
        assertEquals(1, projected.libraryCount)
        assertTrue(projected.limitations.any { it.contains("binding is absent") })
        val forged = mutate(raw) {
            val rows = getValue("interpreters").jsonArray
            val mount = rows.single().jsonObject
            put("interpreters", JsonArray(listOf(JsonObject(mount + ("snapshotPath" to JsonPrimitive("/changed/root/ld.so"))))))
        }
        assertFails { FullTreeExternalProviderEvidenceV1.fromRecordedClosure(forged, budget()) }
    }

    @Test fun `existing inert ELF fixture projection binds stage output digest`() {
        val root = java.nio.file.Path.of("build/orchestration/external-provider-boundary-implementation/test-fixtures")
        Files.createDirectories(root)
        val path = root.resolve("provider-ledger.elf")
        val bytes = DynamicBindingElfFixtureV1().bytes
        try {
            Files.write(path, bytes)
            StableControlFile.open(path, bytes.size.toLong(), "provider ledger fixture").use { file ->
                val digest = OracleArtifacts.sha256(bytes)
                val inventory = BoundedElfDynamicBindingsV1.scan(file, digest)
                val stage = ExternalLinkStageIdentityV1("run", "action", 0, digest, digest, digest, "executable", bytes.size.toLong(), digest)
                val projected = FullTreeExternalProviderEvidenceV1.fromElf(stage, inventory, budget())
                assertEquals(inventory.dynamicSymbols.size, projected.symbolCount)
                assertEquals(inventory.relocations.size, projected.relocationCount)
                assertTrue(projected.unsupportedReasons.isNotEmpty())
                val callerSnapshot = projected.snapshot(); callerSnapshot.fill(0)
                assertContentEquals(OracleJson.canonicalBytes(inventory.toJson()), projected.snapshot())
                assertFails { (projected.symbols as MutableList).clear() }
                assertTrue(projected.toJson()["references"]!!.jsonArray.all { it.jsonObject["artifactSha256"] == JsonPrimitive(digest) })
                assertFails { FullTreeExternalProviderEvidenceV1.fromElf(stage.copy(outputSha256 = "0".repeat(64)), inventory, budget()) }
            }
        } finally {
            Files.deleteIfExists(path)
            if (Files.isDirectory(root) && Files.list(root).use { !it.findAny().isPresent }) Files.deleteIfExists(root)
        }
    }

    @Test fun `F7 exact typed nested output node depth strings records and work limits reject N minus one`() {
        withInventory { stage, inventory ->
            fun run(limits: ExternalProviderLimitsV1): RecordedElfEvidenceV1 = FullTreeExternalProviderEvidenceV1.fromElf(stage,inventory,ExternalBoundaryBudgetV1(limits,AnalysisDeadline.start(TimeUnit.SECONDS.toNanos(20),"typed ceiling")))
            val full=run(ExternalProviderLimitsV1())
            val actual=OracleJson.canonicalBytes(full.toJson())
            val counter=BoundaryTreeV1(null,false); counter.json(null,full.toJson())
            assertEquals(actual.size.toLong(),counter.bytes,"independent canonical encoder and counting visitor must agree")
            fun exact(label: String, n: Int, limits: (Int)->ExternalProviderLimitsV1) {
                assertNotNull(run(limits(n)),"$label N=$n")
                assertFails("$label N+1 against cap=${n-1}") { run(limits(n-1)) }
            }
            exact("output bytes",actual.size) { ExternalProviderLimitsV1(maximumDocumentBytes=it) }
            exact("nested nodes",counter.nodes.toInt()) { ExternalProviderLimitsV1(maximumNodes=it) }
            exact("nested depth",counter.maximumDepth) { ExternalProviderLimitsV1(maximumDepth=it) }
            exact("individual UTF8 string",counter.largestString.toInt()) { ExternalProviderLimitsV1(maximumStringBytes=it) }
            exact("aggregate UTF8 strings",counter.strings.toInt()) { ExternalProviderLimitsV1(maximumTotalStringBytes=it) }
            fun threshold(max: Int, make: (Int)->ExternalProviderLimitsV1): Int {
                var low=1;var high=max
                while(low<high) { val middle=(low+high)/2; if(runCatching { run(make(middle)) }.isSuccess) high=middle else low=middle+1 }
                return low
            }
            val records=threshold(65536) { ExternalProviderLimitsV1(maximumReferencesAndEvents=it) }
            exact("aggregate nested population",records) { ExternalProviderLimitsV1(maximumReferencesAndEvents=it) }
            val work=threshold(10_000_000) { ExternalProviderLimitsV1(maximumWorkUnits=it.toLong()) }
            exact("typed work",work) { ExternalProviderLimitsV1(maximumWorkUnits=it.toLong()) }
        }
    }

    @Test fun `F9 all recorded constructors deep own nested JSON lists and bytes`() {
        val map=mutableMapOf<String,JsonElement>("nested" to JsonArray(mutableListOf(JsonPrimitive("original"))))
        val raw=JsonObject(map);val list=mutableListOf(raw);val bytes=byteArrayOf(1,2,3);val h="a".repeat(64)
        val stage=ExternalLinkStageIdentityV1("run","action",0,h,h,h,"executable",3,h)
        val elf=RecordedElfEvidenceV1("elf",h,stage,h,1,0,list,emptyList(),emptyList(),emptyList(),bytes,raw)
        val runtime=RecordedRuntimeCandidatesV1("runtime",h,2,bytes,list,list,list,raw,raw,h,1,0,emptyList())
        val closure=RecordedRuntimeClosureV1("closure",h,bytes,false,1,1,true,true,emptyList(),list,list,raw,raw)
        val refs=mutableListOf("proof");val finding=ExternalBoundaryFindingV1("test","qualification",evidenceRefs=refs)
        val assessment=ExternalProviderAssessmentV1(bytes,listOf(finding),true,h)
        map["nested"]=JsonNull;list.clear();bytes.fill(9);refs.clear()
        assertEquals(JsonArray(listOf(JsonPrimitive("original"))),elf.symbols.single()["nested"])
        assertEquals(elf.symbols.single(),runtime.nodes.single());assertEquals(runtime.nodes.single(),closure.interpreters.single())
        for(snapshot in listOf(elf.snapshot(),runtime.snapshot(),closure.snapshot(),assessment.canonicalBytes())) assertContentEquals(byteArrayOf(1,2,3),snapshot)
        assertEquals(listOf("proof"),assessment.blockers.single().evidenceRefs)
        assertFails { (runtime.nodes.single() as MutableMap<String,JsonElement>)["extra"]=JsonNull }
    }

    @Test fun `F8 runtime raw enums booleans paths and collisions are individually rejected`() {
        val raw=OracleJson.parseCanonical(candidate(2)).jsonObject
        assertFails { FullTreeExternalProviderEvidenceV1.fromRawMeasurement(OracleJson.canonicalBytes(JsonObject(raw+("schemaVersion" to JsonPrimitive("2")))),budget()) }
        val graph=raw["subjectStaticElfClosure"]!!.jsonObject
        val node=buildJsonObject {
            put("resolvedPath","/subject/lib/libx.so");put("inode",1);put("bytes",10);put("sha256","a".repeat(64));put("elfType","ET_DYN")
            put("needed",JsonArray(emptyList()));put("soname","libx.so");put("interpreter",JsonNull);put("rpath",JsonNull);put("runpath",JsonNull);put("flags1",0);put("unsupportedDynamicTags",JsonArray(emptyList()))
        }
        fun adapt(nodes: List<JsonObject>, extra: Pair<String,JsonElement>?=null): RecordedRuntimeCandidatesV1 {
            var g=JsonObject(graph+("nodes" to JsonArray(nodes))); if(extra!=null) g=JsonObject(g+extra)
            return FullTreeExternalProviderEvidenceV1.fromRawMeasurement(OracleJson.canonicalBytes(JsonObject(raw+("subjectStaticElfClosure" to g))),budget())
        }
        assertEquals(1,adapt(listOf(node)).nodes.size)
        for((key,value) in listOf("resolvedPath" to JsonPrimitive("/subject/../host"),"flags1" to JsonPrimitive("0"),"flags1" to JsonObject(emptyMap()),"elfType" to JsonPrimitive("ET_UNKNOWN"),"bytes" to JsonPrimitive(-1)))
            assertFails(key) { adapt(listOf(JsonObject(node+(key to value)))) }
        assertFails { adapt(listOf(node,node)) }
        assertFails { adapt(listOf(node,JsonObject(node+mapOf("resolvedPath" to JsonPrimitive("/other"),"sha256" to JsonPrimitive("b".repeat(64)))))) }
        assertFails { adapt(listOf(node),"staticGraphCompleteUnderStatedModel" to JsonPrimitive("false")) }
        val c=OracleJson.parseCanonical(closure()).jsonObject
        val duplicate=JsonObject(c+("libraries" to JsonArray(c["libraries"]!!.jsonArray+c["libraries"]!!.jsonArray)))
        val payload=JsonObject(duplicate-"closureSha256")
        val forged=JsonObject(payload+("closureSha256" to JsonPrimitive(OracleArtifacts.sha256(OracleJson.canonicalBytes(payload)))))
        assertFails { FullTreeExternalProviderEvidenceV1.fromRecordedClosure(OracleJson.canonicalBytes(forged),budget()) }
    }

    @Test fun `bounded snapshots reject deep oversized and malformed unicode before copy`() {
        var nested: JsonElement=JsonNull
        repeat(33) { nested=JsonArray(listOf(nested)) }
        assertFails { BoundaryOwnedSnapshotV1(byteArrayOf(),listOf(nested)) }
        assertFails { BoundaryOwnedSnapshotV1(ByteArray(4*1024*1024+1),emptyList()) }
        assertFails { BoundaryOwnedSnapshotV1(byteArrayOf(),listOf(JsonPrimitive("\uD800"))) }
        val multibyte=JsonPrimitive("é🙂")
        val m=BoundaryTreeV1(null,false);m.json(null,multibyte)
        assertEquals(6,m.largestString.toInt()); assertEquals(OracleJson.canonicalBytes(multibyte).size.toLong(),m.bytes)
        val good=ExternalBoundaryBudgetV1(ExternalProviderLimitsV1(maximumStringBytes=6),AnalysisDeadline.start(TimeUnit.SECONDS.toNanos(10),"unicode"))
        BoundaryOwnedSnapshotV1(byteArrayOf(),listOf(multibyte),good)
        val bad=ExternalBoundaryBudgetV1(ExternalProviderLimitsV1(maximumStringBytes=5),AnalysisDeadline.start(TimeUnit.SECONDS.toNanos(10),"unicode"))
        assertFails { BoundaryOwnedSnapshotV1(byteArrayOf(),listOf(multibyte),bad) }
        assertFails { budget().retain(Long.MAX_VALUE,Long.MAX_VALUE) }; assertFails { budget().checkpoint("overflow",Long.MAX_VALUE) }
    }

    private fun withInventory(block: (ExternalLinkStageIdentityV1,decompengine.oracle.externalcalls.ElfDynamicBindingInventoryV1)->Unit) {
        val root=java.nio.file.Path.of("build/remediation-adapter");Files.createDirectories(root);val file=root.resolve("fixture.elf")
        val bytes=DynamicBindingElfFixtureV1().bytes;Files.write(file,bytes)
        try { StableControlFile.open(file,bytes.size.toLong(),"remediation adapter").use { stable ->
            val digest=OracleArtifacts.sha256(bytes);val inventory=BoundedElfDynamicBindingsV1.scan(stable,digest)
            block(ExternalLinkStageIdentityV1("run","action",0,digest,digest,digest,"executable",bytes.size.toLong(),digest),inventory)
        } } finally { Files.delete(file);Files.delete(root) }
    }

    private fun candidate(version: Int): ByteArray {
        val h = "a".repeat(64)
        val layer = buildJsonObject { put("blobSha256", h); put("blobBytes", 10); put("mediaType", "application/vnd.oci.image.layer.v1.tar"); put("uncompressedDiffId", "sha256:$h"); put("uncompressedBytes", 10) }
        val versionFacts = buildJsonObject { put("Version", "29.7.2"); put("ApiVersion", "1.55"); put("Os", "linux"); put("Arch", "amd64"); put("GitCommit", "6a43e3d") }
        val infoFacts = buildJsonObject { put("ServerVersion", "29.7.2"); put("OSType", "linux"); put("Driver", "overlay2"); put("CgroupVersion", "2"); put("SecurityOptions", buildJsonArray { add("name=rootless") }) }
        val inspectFacts = buildJsonObject { put("Os", "linux"); put("Architecture", "amd64"); put("RootFS", buildJsonObject { put("Type", "layers"); put("Layers", buildJsonArray { add("sha256:$h") }) }) }
        fun digest(value: JsonObject) = OracleArtifacts.sha256(OracleJson.canonicalBytes(value))
        val runtime = buildJsonObject {
            put("apiVersion", "1.55"); put("serverVersion", "29.7.2"); put("fixedReadOnlyRequests", buildJsonArray {
                add("HEAD /_ping"); add("GET /version"); add("GET /info"); add("GET /v1.55/images/sha256:$h/json"); add("GET /v1.55/images/sha256:$h/get")
            })
            put("version", versionFacts); put("versionCanonicalSha256", digest(versionFacts)); put("info", infoFacts); put("infoCanonicalSha256", digest(infoFacts))
            put("inspect", inspectFacts); put("inspectCanonicalSha256", digest(inspectFacts)); put("exportConfigSha256", h); put("exportLayerDiffIds", buildJsonArray { add("sha256:$h") })
            put("exportSha256", h); put("exportBytes", 10); put("exportMergedNamespaceSha256", h)
            if (version == 3) put("observedListenerContinuity", buildJsonObject {
                put("schemaVersion", 1); put("identityKind", "linux-af-unix-listener-credential-snapshot"); put("identifierNamespace", "observer")
                put("peerHandleMechanism", "SO_PEERPIDFD"); put("fixedExchangeCount", 5); put("sameListenerSnapshot", true); put("retentionBoundary", "final-factory-guard")
                put("daemonExecutableApproved", false); put("httpResponderIdentityProved", false); put("pid", 100); put("uid", 100); put("gid", 100)
            })
        }
        val graph = buildJsonObject {
            put("scope", "read-only-ELF64-x86-64-static-dependency-candidates"); put("subjectRequestedPath", "/subject/bin/app"); put("interpreter", buildJsonObject { put("present", false) })
            put("glibcSearchModelVersion", "2.39-static-source-model"); put("loaderSearchImplementationQualified", false); put("loaderBuiltInDirectoriesQualified", false)
            put("processEnvironmentAndAuxvQualified", false); put("dynamicDlopenAndSymbolResolutionQualified", false); put("libraryClosureQualified", false)
            put("staticGraphCompleteUnderStatedModel", false); put("loaderCache", buildJsonObject { put("present", false) }); put("nodes", JsonArray(emptyList()))
            put("edges", JsonArray(emptyList())); put("incompleteReasons", buildJsonArray { add("fixture has no subject executable") })
        }
        return OracleJson.canonicalBytes(buildJsonObject {
            put("schemaVersion", version); put("artifactKind", "native-runtime-measurement-candidate"); put("authority", "unapproved-raw-measurement-only")
            for (name in listOf("oracleAuthority", "runtimeProfileApproved", "startAuthorized", "containmentProved", "scoringAuthority", "releaseEligible")) put(name, false)
            put("deploymentJarSha256", h); put("deploymentJarBytes", 10); put("codecDeploymentInputs", JsonArray(emptyList()))
            put("measurementRecipeBinding", buildJsonObject {
                put("ownJarResource", "fixture.jar"); put("containerPath", "/measurement/fixture.jar"); put("bytes", 10); put("sha256", h)
                put("rawImageBytesMatchDeployment", true); put("buildExecutionAuthenticated", false); put("runtimeProfileApproved", false)
            })
            put("rawOciIndexSha256", h); put("rawOciIndexBytes", 10); put("rawOciManifestSha256", h); put("rawOciManifestBytes", 10)
            put("rawConfigSha256", h); put("rawConfigBytes", 10); put("mergedNamespaceSha256", h); put("mergedNamespaceEntries", 1)
            put("orderedRawLayers", buildJsonArray { add(layer) }); put("readOnlyRuntime", runtime); put("subjectStaticElfClosure", graph)
        })
    }

    private fun closure(): ByteArray {
        val h = "b".repeat(64)
        val payload = buildJsonObject {
            put("schemaVersion", 1); put("provider", "bounded-elf-needed-runtime-v1"); put("elfMachine", 62); put("elfClass", 64); put("elfOsAbi", 0); put("elfAbiFlags", 0); put("byteOrder", "little")
            put("resolver", buildJsonObject { put("bytes", 10); put("sha256", h); put("path", "/sys/bin/ldconfig") })
            put("loaderCache", buildJsonObject { put("bytes", 10); put("sha256", h); put("path", "/sys/etc/ld.so.cache") })
            put("resolverListingBytes", 10); put("resolverListingSha256", h)
            put("interpreters", buildJsonArray { add(buildJsonObject {
                put("guestPath", "/sys/lib/ld-linux-x86-64.so.2"); put("sourcePath", "/capture/sys/lib/ld-linux-x86-64.so.2")
                put("snapshotPath", "/snapshot/sys/lib/ld-linux-x86-64.so.2"); put("bytes", 10); put("sha256", h)
            }) })
            put("libraries", buildJsonArray { add(buildJsonObject {
                put("name", "libc.so.6"); put("sourcePath", "/capture/sys/lib/libc.so.6"); put("snapshotPath", "/snapshot/sys/lib/libc.so.6"); put("bytes", 10); put("sha256", h)
            }) }); put("visibleSearchPath", "/sys/lib:/sys/lib64")
            put("hostRuntimeRootsVisible", false); put("closureSha256", "")
        }
        val sha = OracleArtifacts.sha256(OracleJson.canonicalBytes(JsonObject(payload - "closureSha256")))
        return OracleJson.canonicalBytes(JsonObject(payload + ("closureSha256" to JsonPrimitive(sha))))
    }

    private fun mutate(bytes: ByteArray, block: MutableMap<String, JsonElement>.() -> Unit): ByteArray {
        val root = (OracleJson.parseCanonical(bytes) as JsonObject).toMutableMap(); root.block(); return OracleJson.canonicalBytes(JsonObject(root))
    }
    private fun budget() = ExternalBoundaryBudgetV1(ExternalProviderLimitsV1(), AnalysisDeadline.start(TimeUnit.SECONDS.toNanos(20), "test"))
}
