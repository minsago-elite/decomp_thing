package decompengine.oracle.gcc

import decompengine.acp.LinuxDescriptor
import decompengine.acp.LinuxFileIdentity
import decompengine.acp.LinuxFilesystemSyscalls
import decompengine.oracle.core.OracleArtifacts
import decompengine.oracle.core.OracleJson
import decompengine.oracle.fulltree.FullTreeElfExecutableRange
import decompengine.project.NativeInferredInterfaceObservationLimitsV1
import decompengine.project.NativeInferredInterfaceObservationsV1
import java.nio.file.Files
import java.nio.file.Path
import java.nio.file.StandardCopyOption
import java.nio.file.attribute.PosixFilePermissions
import kotlin.test.*
import kotlinx.serialization.json.*

/** Filesystem controls use authored bytes; they cannot issue the coordinator's live operation. */
class GccBundledInferredInterfaceCaptureTest {
    @Test
    fun `complete owned bytes retain all nine dispositions both populations and ambiguous mapping`() {
        fixture { f ->
            val captured = f.capture()
            assertEquals(1L, captured.model.functionCount)
            assertEquals(10L, captured.summary.scan.functions)
            assertEquals(1L, captured.summary.scan.externalFunctions)
            assertEquals(1L, captured.summary.scan.thunks)
            assertEquals(1L, captured.summary.scan.observed)
            assertEquals(7L, captured.summary.scan.attempted)
            assertEquals(9, captured.summary.scan.dispositions.size)
            assertTrue(captured.summary.scan.dispositions.values.all { it > 0 })
            assertEquals("ambiguous-native-address", captured.summary.listing.modelFunctions.single().state)
            assertEquals(2, captured.summary.listing.modelFunctions.single().candidateEntries.size)
            assertEquals(10, captured.summary.listing.observedFunctions.size)
            assertTrue(captured.summary.listing.observedFunctions.any { it.state == "external-unmapped" })
            assertTrue(captured.summary.listing.observedFunctions.any { it.state == "unmatched-observed-function" })
            assertTrue(captured.completeObservedNativeCensus)
            assertFalse(captured.complete); assertFalse(captured.scored); assertFalse(captured.releaseEligible)
            assertFalse(captured.authoritativeOracleEvidence); assertFalse(captured.productionInterfacesAdmitted)
            assertContentEquals(Files.readAllBytes(f.reportsPath.resolve("program_model.json")), captured.programModelBytes)
            assertContentEquals(Files.readAllBytes(f.listing.resolve("native-interfaces.json")), captured.listingObservationsBytes)
            assertContentEquals(Files.readAllBytes(f.inferred.resolve("native-inferred-interfaces.json")), captured.inferredObservationsBytes)
            f.requireUnchanged(captured)
            fun moveNative(value: JsonElement): JsonElement = when (value) {
                is JsonObject -> {
                    val rebuilt = JsonObject(value.mapValues { moveNative(it.value) })
                    if (value["kind"] == JsonPrimitive("address") && value["offsetBits"] == JsonPrimitive("0000000000400010"))
                        rebuilt.with("offsetBits", JsonPrimitive("0000000000400011")) else rebuilt
                }
                is JsonArray -> JsonArray(value.map(::moveNative))
                else -> value
            }
            f.write(listing = moveNative(f.listingObject()).jsonObject, transformInferred = { moveNative(it).jsonObject })
            val missing = f.capture()
            assertEquals("missing-listing-function", missing.summary.listing.modelFunctions.single().state)
            assertEquals(10, missing.summary.listing.observedFunctions.size)
        }
    }

    @Test
    fun `default address space index is derived from independent descriptor rather than report ordinal`() {
        fixture { f ->
            fun reindex(value: JsonElement): JsonElement = when(value) {
                is JsonObject -> {
                    val fields=JsonObject(value.mapValues { reindex(it.value) })
                    if (value["kind"]==JsonPrimitive("address") && value["spaceIndex"]==JsonPrimitive(1)) fields.with("spaceIndex",JsonPrimitive(2)) else fields
                }
                is JsonArray -> JsonArray(value.map(::reindex))
                else -> value
            }
            val spaces=JsonArray(listOf(space(0,"EXTERNAL",10),space(1,"register",4),space(2,"ram",1),space(3,"overlay",1,true)))
            val listing=reindex(f.listingObject()).jsonObject.with("addressSpaces",spaces)
            f.write(listing=listing, transformInferred={ reindex(it).jsonObject.with("addressSpaces",spaces) })
            assertEquals(2,f.capture().summary.listing.bindings.imageBase.spaceIndex)
            assertFails { f.capture(target=f.target.copy(defaultAddressSpace=f.target.defaultAddressSpace.copy(name="invented"))) }
            assertFails { f.capture(target=f.target.copy(imageBase=0x400001uL)) }
        }
    }

    @Test
    fun `every independently expected source helper runtime target and exact model binding is enforced`() {
        fixture { f ->
            for (runtime in listOf(RUNTIME.copy(listingCollectorSha256=OTHER),RUNTIME.copy(inferredCollectorSha256=OTHER),
                RUNTIME.copy(typeGraphSha256=OTHER),RUNTIME.copy(wrapperSha256=OTHER),RUNTIME.copy(nativeDecompilerSha256=OTHER))) {
                assertFails { f.capture(runtime=runtime) }
            }
            assertFails { f.capture(target=f.target.copy(inputSha256=OTHER)) }
            assertFails { f.capture(target=f.target.copy(inputBytes=2)) }
            assertFails { f.capture(target=f.target.copy(languageId="different-language")) }
            assertFails { f.capture(target=f.target.copy(compilerSpecId="windows")) }
            assertFails { f.capture(expectedReports=f.control) }
            assertFails { f.capture(expectedControl=f.reports) }
            val modelPath=f.reportsPath.resolve("program_model.json")
            val functionPath=f.reportsPath.resolve("program_model.json.export/functions/fn_0000000000400010.json")
            Files.writeString(modelPath,Files.readString(modelPath).replace("int f(void)","int g(void)"))
            Files.writeString(functionPath,Files.readString(functionPath).replace("int f(void)","int g(void)"))
            assertFails { f.capture() }
        }
    }

    @Test
    fun `fixed interface sibling inventory does not widen ordinary or native call captures`() {
        fixture { f ->
            assertFails { GccBundledFullExportCapture.capture(f.run,f.reports,artifacts()) }
            assertFails { GccBundledFullExportCapture.captureWithNativeCallSibling(f.run,f.reports,artifacts()) }
            f.capture()
            Files.createDirectory(f.reportsPath.resolve("native-calls-v1"))
            assertFails { f.capture() }
        }
        for (relative in listOf("reports/extra","reports/native-interfaces-v1/extra","reports/native-inferred-interfaces-v1/.manifest.pending",
            "reports/program_model.json.export/extra","reports/program_model.json.export/planning-batches/extra")) fixture { f ->
            Files.writeString(f.root.resolve(relative),"uncommitted")
            assertFails { f.capture() }
        }
    }

    @Test
    fun `single link private ownership and complete tree aliases remain mandatory`() {
        val mutations=listOf<(Fixture)->Unit>(
            { f -> Files.createLink(f.root.resolve("alias"),f.listing.resolve("native-interfaces.json")) },
            { f -> Files.createLink(f.root.resolve("alias"),f.reportsPath.resolve("program_model.json.export/functions/fn_0000000000400010.json")) },
            { f -> val p=f.inferred.resolve("native-inferred-interfaces.json"); val saved=f.root.resolve("saved");Files.move(p,saved);Files.createSymbolicLink(p,saved) },
            { f -> Files.setPosixFilePermissions(f.listing,PosixFilePermissions.fromString("rwxr-xr-x")) },
            { f -> Files.setPosixFilePermissions(f.inferred.resolve("manifest.json"),PosixFilePermissions.fromString("rw-rw----")) },
            { f -> Files.setPosixFilePermissions(f.reportsPath.resolve("program_model.json.export/functions"),PosixFilePermissions.fromString("rwxrwx---")) },
        )
        for (mutate in mutations) fixture { f -> mutate(f);assertFails { f.capture() } }
    }

    @Test
    fun `same byte replacement of every full tree and sibling file invalidates retained pins`() {
        for (relative in FILES) fixture { f ->
            val captured=f.capture()
            val path=f.root.resolve(relative);val replacement=path.resolveSibling("replacement")
            Files.write(replacement,Files.readAllBytes(path));privateFile(replacement)
            Files.move(replacement,path,StandardCopyOption.REPLACE_EXISTING)
            assertFails(relative) { f.requireUnchanged(captured) }
        }
    }

    @Test
    fun `last checkpoint cannot mutate an earlier full sidecar after validation`() {
        var checkpoints=0
        fixture { f -> f.capture(checkpoint={checkpoints++}) }
        assertTrue(checkpoints>0)
        fixture { f ->
            var calls=0
            assertFails {
                f.capture(checkpoint={
                    if (++calls==checkpoints) {
                        val path=f.reportsPath.resolve("program_model.json.export/functions/fn_0000000000400010.json")
                        Files.write(path,Files.readAllBytes(path))
                    }
                })
            }
            assertEquals(checkpoints,calls)
        }
        fixture { f ->
            val captured=f.capture();var expectedCalls=0
            f.requireUnchanged(captured) {expectedCalls++}
            var calls=0
            assertFails {
                f.requireUnchanged(captured) {
                    if (++calls==expectedCalls) Files.write(f.listing.resolve("manifest.json"),captured.listingManifestBytes)
                }
            }
            assertEquals(expectedCalls,calls)
        }
    }

    @Test
    fun `one aggregate charges full tree duplication and all siblings before allocating their bytes`() {
        fixture { f ->
            val captured=f.capture()
            val exact=NativeInferredInterfaceObservationLimitsV1(maximumCombinedBytes=captured.capturedBytes)
            assertEquals(captured.capturedBytes,f.capture(limits=exact).capturedBytes)
            assertFails { f.capture(limits=exact.copy(maximumCombinedBytes=captured.capturedBytes-1)) }
            assertTrue(captured.capturedBytes>captured.model.programModelBytes+captured.listingObservationsBytes.size+captured.inferredObservationsBytes.size)
            assertFails { f.capture(limits=exact.copy(maximumFunctions=1)) }
            assertFails { f.capture(limits=exact.copy(maximumManifestBytes=1)) }
            assertFails { f.capture(limits=exact.copy(maximumModelBytes=captured.model.programModelBytes.toInt()-1)) }
        }
    }

    @Test
    fun `cancellation produces no snapshot while returned arrays maps and owner closure are defensive`() {
        fixture { f ->
            var calls=0
            val failure=assertFails { f.capture(checkpoint={if(++calls==20) throw InterruptedException("authored deadline")}) }
            assertTrue(generateSequence(failure) {it.cause}.any {it is InterruptedException})
            assertFalse(Files.exists(f.root.resolve("result.json")))
            val captured=f.capture()
            val model=captured.programModelBytes;model.fill(0)
            val listing=captured.listingObservationsBytes;listing.fill(0)
            val listingManifest=captured.listingManifestBytes;listingManifest.fill(0)
            val inferred=captured.inferredObservationsBytes;inferred.fill(0)
            val inferredManifest=captured.inferredManifestBytes;inferredManifest.fill(0)
            val assessment=captured.assessmentBytes;assessment.fill(0)
            assertEquals(captured.model.programModelSha256,OracleArtifacts.sha256(captured.programModelBytes))
            assertEquals(captured.summary.bindings.listingSha256,OracleArtifacts.sha256(captured.listingObservationsBytes))
            assertEquals(captured.summary.manifest.sha256,OracleArtifacts.sha256(captured.inferredObservationsBytes))
            assertEquals(captured.summary.bindings.listingManifestSha256,OracleArtifacts.sha256(captured.listingManifestBytes))
            assertTrue(captured.inferredManifestBytes.any {it!=0.toByte()})
            assertTrue(captured.assessmentBytes.any {it!=0.toByte()})
            assertFails {(captured.files as MutableMap).clear()}
            assertFails {(captured.files.values.first().metadata as MutableMap).clear()}
            assertFails {(captured.directories.values.first { it.entries != null }.entries as MutableSet).clear()}
            assertFails {(captured.directories as MutableMap).clear()}
            assertFails {(captured.target.executableRanges as MutableList).clear()}
            f.run.close()
            assertFails {f.requireUnchanged(captured)}
        }
    }

    @Test
    fun `missing duplicate and partial successful native populations cannot freeze`() {
        for (mutation in listOf<(JsonObject)->JsonObject>(
            { doc -> doc.with("records",JsonArray(doc.getValue("records").jsonArray.dropLast(1))) },
            { doc -> doc.with("records",JsonArray(doc.getValue("records").jsonArray + doc.getValue("records").jsonArray.last())) },
            { doc -> doc.with("summary",doc.getValue("summary").jsonObject.with("functions",JsonPrimitive(9))) },
            { doc -> doc.with("summary",doc.getValue("summary").jsonObject.with("productionInterfacesAdmitted",JsonPrimitive(true))) },
        )) fixture { f ->f.write(transformInferred=mutation);assertFails {f.capture()} }
    }

    @Test
    fun `valid raw capture and caller receipts cannot construct factory owned interface evidence`() {
        fixture { f ->
            val raw = f.capture()
            val intent = "{\"provider\":\"caller-authored\",\"productionVerified\":true}".toByteArray()
            val execution = "{\"unitAbsent\":true,\"cgroupAbsent\":true,\"processesAbsent\":true}".toByteArray()
            val assessment = raw.assessmentBytes
            val operation = GccBundledInterfaceOperation(raw, intent, execution, assessment)
            assertUnregistered(operation)
            assertTrue(raw.completeObservedNativeCensus)
            assertFalse(raw.complete)
            assertFalse(raw.authoritativeOracleEvidence)
            assertFalse(raw.productionInterfacesAdmitted)
            assertFalse(raw.scored)
            assertFalse(raw.releaseEligible)
            assertFalse(operation.complete)
            assertFalse(operation.authoritativeOracleEvidence)
            assertFalse(operation.productionInterfacesAdmitted)
            assertFalse(operation.scored)
            assertFalse(operation.releaseEligible)
            // Constructor receipt copies and genuine raw bytes never substitute for membership.
            intent.fill(0); execution.fill(0); assessment.fill(0)
            assertUnregistered(operation)
        }
    }

    @Test
    fun `distinct operation clones sharing captured bytes never acquire factory identity`() {
        fixture { f ->
            val raw = f.capture()
            val bytes = "{}".toByteArray()
            val first = GccBundledInterfaceOperation(raw, bytes, bytes, raw.assessmentBytes)
            val clone = GccBundledInterfaceOperation(raw, bytes.copyOf(), bytes.copyOf(), raw.assessmentBytes)
            assertNotSame(first, clone)
            assertUnregistered(first)
            assertUnregistered(clone)
            // Explicit membership checks and rejected publication cannot register either instance.
            for (operation in listOf(first, clone)) {
                val membership = assertFailsWith<IllegalStateException> {
                    GccBundledOperationCoordinator.requireOwnedInterfaceOperation(operation)
                }
                assertTrue(membership.message.orEmpty().contains("factory-owned identity"))
                assertUnregistered(operation)
            }
            f.requireUnchanged(raw)
        }
    }

    private fun assertUnregistered(operation: GccBundledInterfaceOperation) {
        val accessors: List<Pair<String, () -> Any?>> = listOf(
            "requireCurrent" to { operation.requireCurrent() },
            "snapshot" to { operation.snapshot },
            "intentBytes" to { operation.intentBytes },
            "executionReceiptBytes" to { operation.executionReceiptBytes },
            "assessmentReceiptBytes" to { operation.assessmentReceiptBytes },
            "binding" to { GccBundledInterfaceCliResultV1.binding(operation) },
            "result" to { GccBundledInterfaceCliResultV1.result(operation, byteArrayOf(),
                Path.of("build").toAbsolutePath(), Path.of("build").toAbsolutePath(), Path.of("build").toAbsolutePath(), JsonObject(emptyMap())) },
        )
        for ((name, read) in accessors) {
            val failure = assertFailsWith<IllegalStateException>(name) { read() }
            assertTrue(failure.message.orEmpty().contains("factory-owned identity"), name)
        }
    }

    private class Fixture(val root:Path,val run:LinuxDescriptor,val reports:LinuxFileIdentity,val control:LinuxFileIdentity) {
        val reportsPath:Path=root.resolve("reports")
        val listing:Path=reportsPath.resolve("native-interfaces-v1")
        val inferred:Path=reportsPath.resolve("native-inferred-interfaces-v1")
        val model:ByteArray get()=Files.readAllBytes(reportsPath.resolve("program_model.json"))
        val target=GccBundledInterfaceTargetEvidenceV1("f".repeat(64),"x86_64-linux-gnu",INPUT,1,0x400000uL,"x86:LE:64:default","gcc",
            GccBundledInterfaceAddressSpaceIdentityV1("ram",1,64,1,false,false),listOf(FullTreeElfExecutableRange(0uL,0x1000uL)))
        fun capture(limits:NativeInferredInterfaceObservationLimitsV1=NativeInferredInterfaceObservationLimitsV1(),
            target:GccBundledInterfaceTargetEvidenceV1=this.target,runtime:GccBundledInterfaceCaptureBindingsV1=RUNTIME,
            expectedReports:LinuxFileIdentity=reports,expectedControl:LinuxFileIdentity=control,checkpoint:()->Unit={}) =
            GccBundledInferredInterfaceCapture.capture(run,expectedReports,CONTROL,expectedControl,artifacts(),target,runtime,limits,checkpoint)
        fun requireUnchanged(snapshot:GccBundledInferredInterfaceSnapshot,checkpoint:()->Unit={}) =
            GccBundledInferredInterfaceCapture.requireUnchanged(run,snapshot,artifacts(),checkpoint)
        private fun binding()=obj("collectorSha256" to RUNTIME.listingCollectorSha256,"compilerSpecId" to "gcc","ghidraArchiveSha256" to ARCHIVE,
            "imageBase" to address(1,0x400000uL),"inputSha256" to INPUT,"languageId" to "x86:LE:64:default","programModelBytes" to model.size,
            "programModelExporterSha256" to EXPORTER,"programModelSha256" to OracleArtifacts.sha256(model))
        fun listingObject()=obj("addressSpaces" to SPACES,"bindings" to binding(),"policy" to "ghidra-native-interface-observations-v1","schemaVersion" to 1,
            "records" to (0..9).map {index ->obj("recordKind" to "function","entry" to entry(index),"name" to "unparsed-name-$index","isExternal" to (index==0),"isThunk" to (index==2),
                "immediateThunkTarget" to if(index==2) entry(1) else null,"signatureSource" to "DEFAULT","convention" to obj("name" to "default","resolvedModel" to "__cdecl","state" to "default"),
                "varArgs" to false,"customStorage" to false,"parameterCount" to 0,"autoParameterCount" to 0,"return" to null,"parameters" to emptyList<Any>(),"highFunction" to "not-captured")},
            "summary" to obj("coverage" to "all-currently-listed-internal-and-external-functions","functions" to 10,"internalFunctions" to 9,"externalFunctions" to 1,"thunks" to 1,
                "parameters" to 0,"autoParameters" to 0,"types" to 0,"storageVarnodes" to 0,"highFunction" to "not-captured","typeClosure" to "not-captured","abiClassification" to "not-captured"))
        fun write(listing:JsonObject=listingObject(),transformInferred:(JsonObject)->JsonObject={it}) {
            val listingBytes=OracleJson.canonicalBytes(listing)
            val listingManifest=OracleJson.canonicalBytes(obj("bytes" to listingBytes.size,"collectorSha256" to RUNTIME.listingCollectorSha256,
                "file" to "native-interfaces.json","inputSha256" to INPUT,"kind" to "ghidra-native-interface-observation-manifest-v1",
                "programModelSha256" to OracleArtifacts.sha256(model),"schemaVersion" to 1,"sha256" to OracleArtifacts.sha256(listingBytes)))
            val binding=obj("listingBindings" to listing.getValue("bindings"),"collectorSha256" to RUNTIME.inferredCollectorSha256,
                "wrapperSha256" to RUNTIME.wrapperSha256,"nativeDecompilerSha256" to RUNTIME.nativeDecompilerSha256,"typeGraphSha256" to RUNTIME.typeGraphSha256,
                "listingBytes" to listingBytes.size,"listingSha256" to OracleArtifacts.sha256(listingBytes),"listingManifestSha256" to OracleArtifacts.sha256(listingManifest),
                "configurationSha256" to NativeInferredInterfaceObservationsV1.configurationSha256)
            val records=mutableListOf<JsonObject>()
            for(index in 0..9) {
                val state=STATES[index]
                if(index==1) records += obj("recordKind" to "type-root","channel" to "inferred","functionOrdinal" to 1,"role" to "inferred-return","slot" to -1,"listingTypeOrdinal" to null,"node" to null)
                val attempted=!state.startsWith("not-attempted-")
                records += obj("recordKind" to "function","functionOrdinal" to index,"entry" to entry(index),"isExternal" to (index==0),"isThunk" to (index==2),
                    "disposition" to state,"attempt" to if(attempted) 1 else 0,"result" to if(attempted) result(state) else null,"prototype" to if(index==1) prototype() else null,"parameters" to emptyList<Any>())
            }
            val inferredObject=transformInferred(obj("addressSpaces" to SPACES,"bindings" to binding,"configuration" to NativeInferredInterfaceObservationsV1.configurationJson,
                "dataOrganization" to organization(),"policy" to "ghidra-native-inferred-interface-observations-v1","records" to records,"schemaVersion" to 1,
                "summary" to obj("functions" to 10,"internalFunctions" to 9,"externalFunctions" to 1,"thunks" to 1,"attempted" to 7,"observed" to 1,"parameters" to 0,
                    "storageVarnodes" to 0,"roots" to 1,"graphNodes" to 0,"graphEdges" to 0,"graphWork" to 3,"dispositions" to JsonObject(NativeInferredInterfaceObservationsV1.dispositions.associateWith {JsonPrimitive(STATES.count {s->s==it})}),
                    "coverage" to "all-currently-listed-internal-and-external-functions","authoritativeOracleEvidence" to false,"recoveredModelScored" to false,"productionInterfacesAdmitted" to false,"releaseEligible" to false,
                    "abiClassification" to "not-captured","sourceTypeIdentity" to "not-captured")))
            val inferredBytes=OracleJson.canonicalBytes(inferredObject)
            val inferredManifest=OracleJson.canonicalBytes(obj("bytes" to inferredBytes.size,"collectorSha256" to RUNTIME.inferredCollectorSha256,"typeGraphSha256" to RUNTIME.typeGraphSha256,
                "configurationSha256" to NativeInferredInterfaceObservationsV1.configurationSha256,"file" to "native-inferred-interfaces.json","inputSha256" to INPUT,
                "kind" to "ghidra-native-inferred-interface-observation-manifest-v1","listingSha256" to OracleArtifacts.sha256(listingBytes),"programModelSha256" to OracleArtifacts.sha256(model),"schemaVersion" to 1,"sha256" to OracleArtifacts.sha256(inferredBytes)))
            mapOf(this.listing.resolve("manifest.json") to listingManifest,this.listing.resolve("native-interfaces.json") to listingBytes,
                inferred.resolve("manifest.json") to inferredManifest,inferred.resolve("native-inferred-interfaces.json") to inferredBytes).forEach {(path,bytes)->Files.write(path,bytes);privateFile(path)}
        }
    }

    private fun fixture(action:(Fixture)->Unit) {
        val base=Files.createDirectories(Path.of("build","inferred-interface-capture-tests"))
        val root=privateDirectory(Files.createTempDirectory(base,"capture-")).toRealPath()
        try {
            val reports=privateDirectory(Files.createDirectory(root.resolve("reports")))
            val export=privateDirectory(Files.createDirectory(reports.resolve("program_model.json.export")))
            listOf("planning-batches","functions","globals","types","failures").forEach {privateDirectory(Files.createDirectory(export.resolve(it)))}
            val record="{\n    \"id\": \"fn_0000000000400010\",\n    \"name\": \"f\",\n    \"address\": \"0x400010\",\n    \"prototype\": \"int f(void)\",\n    \"extractionStatus\": \"recovered\",\n    \"recoveryAssessment\": \"unassessed\",\n    \"calls\": [],\n    \"referencedGlobals\": [],\n    \"strings\": [],\n    \"decompiledC\": \"int f(void) { return 1; }\"\n}"
            val producerRecord=record.lines().mapIndexed {index,line->if(index==0||line=="}") "    $line" else "  $line"}.joinToString("\n")
            Files.writeString(export.resolve("functions/fn_0000000000400010.json"),producerRecord)
            Files.writeString(reports.resolve("program_model.json"),"{\n  \"schemaVersion\": 4,\n  \"inputSha256\": \"$INPUT\",\n  \"functions\": [\n$producerRecord\n  ],\n  \"globals\": [\n  ],\n  \"types\": [\n  ]\n}\n")
            Files.writeString(export.resolve("state.json"),"{\"schemaVersion\":2,\"exporterVersion\":17,\"exporterSha256\":\"$EXPORTER\",\"analysisToolSha256\":\"$ARCHIVE\",\"recoveryMode\":\"full\",\"decompilationWorkers\":1,\"inputSha256\":\"$INPUT\",\"language\":\"x86:LE:64:default\",\"compilerSpec\":\"gcc\",\"semanticStateBinding\":null}\n")
            Files.writeString(reports.resolve("program_model.json.progress.json"),"{\"schemaVersion\":1,\"phase\":\"complete\",\"completed\":1,\"total\":1,\"recovered\":1,\"partial\":0,\"failed\":0,\"reused\":0,\"currentFunction\":null}\n")
            privateDirectory(Files.createDirectory(root.resolve(CONTROL)))
            privateDirectory(Files.createDirectory(reports.resolve("native-interfaces-v1")))
            privateDirectory(Files.createDirectory(reports.resolve("native-inferred-interfaces-v1")))
            LinuxFilesystemSyscalls.openRoot(root).use {run->LinuxFilesystemSyscalls.openDirectoryAt(run.fd,"reports").use {rd->LinuxFilesystemSyscalls.openDirectoryAt(run.fd,CONTROL).use {control->
                val fixture=Fixture(root,run,rd.identity,control.identity);fixture.write();action(fixture)
            }}}
        } finally {Files.walk(root).use {files->files.sorted(Comparator.reverseOrder()).forEach(Files::delete)}}
    }

    companion object {
        private val INPUT=OracleArtifacts.sha256("interface-input".toByteArray())
        private val EXPORTER=OracleArtifacts.sha256("exporter".toByteArray())
        private val ARCHIVE=OracleArtifacts.sha256("ghidra-archive".toByteArray())
        private val OTHER="0".repeat(64)
        private val CONTROL="control-${"a".repeat(64)}"
        private val RUNTIME=GccBundledInterfaceCaptureBindingsV1("1".repeat(64),"2".repeat(64),"3".repeat(64),"4".repeat(64),"5".repeat(64),"6".repeat(64),"7".repeat(64),"8".repeat(64))
        private val SPACES=listOf(space(0,"EXTERNAL",10),space(1,"ram",1),space(2,"register",4),space(3,"overlay",1,true))
        private val STATES=listOf("not-attempted-external","high-function-observed","not-attempted-unsupported-body","decompile-timeout","decompile-cancelled","decompiler-start-failed","decompiler-error","completed-without-high-function","unsupported-high-representation","not-attempted-unsupported-body")
        private val FILES=listOf("reports/program_model.json","reports/program_model.json.progress.json","reports/program_model.json.export/state.json","reports/program_model.json.export/functions/fn_0000000000400010.json",
            "reports/native-interfaces-v1/manifest.json","reports/native-interfaces-v1/native-interfaces.json","reports/native-inferred-interfaces-v1/manifest.json","reports/native-inferred-interfaces-v1/native-inferred-interfaces.json")
        private fun artifacts()=listOf(GccCompilerEngineContainmentArtifactIdentity(GccCompilerEngineContainmentArtifactRole.ENGINE_BINARY,Path.of("/fixture/engine"),1,INPUT),
            GccCompilerEngineContainmentArtifactIdentity(GccCompilerEngineContainmentArtifactRole.EXPORTER_SOURCE,Path.of("/fixture/exporter"),1,EXPORTER),
            GccCompilerEngineContainmentArtifactIdentity(GccCompilerEngineContainmentArtifactRole.GHIDRA_ARCHIVE,Path.of("/fixture/archive"),1,ARCHIVE))
        private fun prototype()=obj("parameterCount" to 0,"localSymbolParameterCount" to 0,"parameterCountsMatch" to true,"backedByLocalSymbols" to true,"modelName" to null,
            "varArgs" to false,"extraPop" to 0,"hasThis" to false,"noReturn" to false,"inline" to false,"constructor" to false,"destructor" to false,"returnType" to null,
            "returnStorage" to obj("state" to "absent","size" to null,"autoStorage" to null,"autoParameterType" to null,"forcedIndirect" to null,"varnodes" to emptyList<Any>()),
            "formalEffectiveRelation" to "unavailable-native-api","allMappings" to "first-mapping-only","privateFlags" to "unavailable-native-api")
        private fun result(state:String)=obj("completed" to (state in setOf("high-function-observed","completed-without-high-function","unsupported-high-representation")),"valid" to false,
            "timedOut" to (state=="decompile-timeout"),"cancelled" to (state=="decompile-cancelled"),"failedToStart" to (state=="decompiler-start-failed"),"diagnostic" to "authored raw result")
        private fun organization():JsonObject {
            val scalars=listOf("pointerSize","pointerShift","charSize","wideCharSize","shortSize","integerSize","longSize","longLongSize","floatSize","doubleSize","longDoubleSize","absoluteMaxAlignment","machineAlignment","defaultAlignment","defaultPointerAlignment")
            return JsonObject(scalars.associateWith {JsonPrimitive(8)}+mapOf("bigEndian" to JsonPrimitive(false),"signedChar" to JsonPrimitive(true),"sizeAlignments" to JsonArray(listOf(obj("size" to 8,"alignment" to 8))),
                "bitFieldPacking" to obj("msConvention" to false,"typeAlignmentEnabled" to true,"zeroLengthBoundary" to 0)))
        }
        private fun entry(index:Int)=when(index){0->address(0,0x80uL);9->address(3,0x400010uL);else->address(1,0x400000uL+index.toULong()*0x10uL)}
        private fun space(index:Int,name:String,type:Int,overlay:Boolean=false)=obj("index" to index,"name" to name,"type" to type,"sizeBits" to 64,"addressableUnitSize" to 1,"overlay" to overlay,"signedOffsets" to false)
        private fun address(space:Int,value:ULong)=obj("kind" to "address","spaceIndex" to space,"offsetBits" to value.toString(16).padStart(16,'0'))
        private fun privateDirectory(path:Path)=Files.setPosixFilePermissions(path,PosixFilePermissions.fromString("rwx------"))
        private fun privateFile(path:Path)=Files.setPosixFilePermissions(path,PosixFilePermissions.fromString("rw-------"))
        private fun JsonObject.with(name:String,value:JsonElement)=JsonObject(this+(name to value))
        private fun obj(vararg pairs:Pair<String,Any?>)=JsonObject(pairs.associate {it.first to json(it.second)})
        private fun json(value:Any?):JsonElement=when(value){null->JsonNull;is JsonElement->value;is String->JsonPrimitive(value);is Boolean->JsonPrimitive(value);is Number->JsonPrimitive(value);is List<*>->JsonArray(value.map(::json));else->error("unsupported authored value")}
    }
}
