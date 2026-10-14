package decompengine.oracle.gcc
import decompengine.oracle.structural.*
import decompengine.oracle.core.*
import decompengine.oracle.fulltree.*
import kotlinx.serialization.json.*
import java.nio.file.*
import java.security.MessageDigest
import java.util.zip.ZipFile

private fun hash(bytes: ByteArray) = MessageDigest.getInstance("SHA-256").digest(bytes).joinToString("") { "%02x".format(it) }
/** Diagnostic retained-source replay; no entity, model, seal or aggregate resource qualification. */
internal object GccAbiPopulationSourceRetainedReplay {
@JvmStatic fun main(args: Array<String>) {
 if (args.size == 3 && args[0] == "--rich-only") { replayRich(Path.of(args[1]), Path.of(args[2])); return }
 require(args.size == 2 || args.size == 4) { "usage: <authenticated artifact.zip> <pinned physical-census.json> [<rich ELF> <repository scratch>]" }
 val censusPath = Path.of(args[1])
 require(Files.size(censusPath) == 26503L) { "pinned census length differs" }
 val censusBytes=Files.newInputStream(censusPath).use { it.readNBytes(26504) }
 require(censusBytes.size == 26503) { "pinned census length changed" }
 require(hash(censusBytes)=="9cc51b702f6c354d51d0b16e7a90a9c74e169b84b7f59eb91670b9d2e938bff8")
 val census=OracleJson.parse(censusBytes).jsonObject
 val artifact=census.getValue("artifact").jsonObject
 val zipPath=Path.of(args[0])
 val digest=MessageDigest.getInstance("SHA-256")
 Files.newInputStream(zipPath).use { stream -> val buf=ByteArray(65536); while(true) {val n=stream.read(buf);if(n<0)break;digest.update(buf,0,n)} }
 require(digest.digest().joinToString("") { "%02x".format(it) }=="d5d2cabf6b2640e7a71d91fe082009c52ad66fa4c92fe48a53ecc078838bcb8c")
 val parts=artifact.getValue("usedParts").jsonArray.map { it.jsonObject }.filter { it.getValue("kind").jsonPrimitive.content=="physicalDies" }
 val limits=StrictJsonLimits(maximumInputBytes=8*1024*1024,maximumCanonicalBytes=8*1024*1024,maximumStringBytes=8*1024*1024,maximumTotalStringBytes=8*1024*1024)
 var passes=0
 fun replay(): Sequence<DwarfPhysicalDieCensus> = sequence {
  passes++
  ZipFile(zipPath.toFile()).use { zip ->
   var ordinal=0
   for(part in parts) {
    val entry=zip.getEntry("gcc-driver-dwarf-interfaces/"+part.getValue("path").jsonPrimitive.content)
    require(entry.size==part.getValue("bytes").jsonPrimitive.long && entry.size<=8*1024*1024)
    val bytes=zip.getInputStream(entry).use { it.readNBytes(8*1024*1024+1) }
    require(hash(bytes)==part.getValue("sha256").jsonPrimitive.content)
    val doc=OracleJson.parse(bytes,limits).jsonObject
    require(OracleJson.canonicalBytes(doc,limits).contentEquals(bytes))
    for(tab in doc.getValue("records").jsonArray) {
     val obj=tab.jsonObject
     require(DwarfPhysicalDieTableEncoding.firstOrdinal(obj)==ordinal)
     DwarfPhysicalDieTableEncoding.logicalRowCount(obj)
     for(row in obj.getValue("rows").jsonArray) {
      yield(DwarfPhysicalDieRowEncoding.decode(JsonObject(mapOf("row" to row))))
      ordinal++
     }
    }
   }
   require(ordinal==696357)
  }
 }
 val obligations=replay().mapIndexed { index,die ->
  var result:AbiSourceObligation?=null
  AbiPopulationSourceObligations.build(sequenceOf(die)) { result=it }
  result!!.copy(ordinal=index.toLong())
 }
 val totals=AbiPopulationSourceVerifier.verify(::replay,obligations)
 require(totals.physicalRows==696357L && totals.referenceRows==800159L && passes==3)
 if (args.size == 4) replayRich(Path.of(args[2]), Path.of(args[3]))
 println("actual retained source replay PASS rows=${totals.physicalRows} references=${totals.referenceRows} verifierWork=${totals.rowEdgeVisits} passes=$passes aggregateRowEdgeVisits=${3*(totals.physicalRows+totals.referenceRows)} semanticPopulationComplete=false modelBound=false sealed=false")
}

private fun replayRich(path: Path, scratch: Path) {
 Files.createDirectories(scratch)
 val control = FullTreeControlLimits()
 val limits = BoundedDwarfInterfaceFactLimits()
 val budget = FullTreeDwarfParseBudget(control.maximumDwarfParseSteps)
 var units = 0L; var dies = 0L; var attributes = 0L; var uncaptured = 0L; var payloadCharacters = 0L
 val tags = mutableSetOf<Long>()
 StableControlFile.open(path, limits.maximumArtifactBytes, "rich scalar replay").use { artifact ->
  require(artifact.size == 20713760L && artifact.sha256() == "8009c7cfc4f66017aa932d86a6d4ec7f374e6ab7a01b3ef5ab3d2fcc78c2378b")
  FullTreeDwarfSections.open(artifact, scratch, control,
    FullTreeDwarfSections.FUNCTION_OBSERVATION_SECTION_NAMES).use { sections ->
   val info = sections.required(".debug_info")
   val headers = FullTreeDwarfCompilationUnitHeaders(info, control.maximumCompilationUnits.toLong(), budget)
   while(headers.hasNext()) {
    val header = headers.next(); units++
    val index = FullTreeDwarfDies.readCompilationUnit(info, sections.required(".debug_abbrev"), header, control,
      FullTreeDwarfDieLimits(limits.maximumScannedDies, limits.maximumScannedDies.toInt(),
       minOf(50_000_000L, limits.maximumScannedDies * 10), 65_536, limits.maximumRetainedUnitBytes), budget,
      contextForAttribute = { attribute -> when(attribute.name) {
       0x2L -> FullTreeDwarfFormContext.LOCATION
       0x1cL -> FullTreeDwarfFormContext.DATA_VALUE
       0x3fL, 0x17L, 0x13L, 0x36L, 0x27L, 0x34L,
       in INTERFACE_TYPE_CONSTANT_ATTRIBUTES -> FullTreeDwarfFormContext.CONSTANT
       else -> functionAttributeContext(attribute)
      } })
    for(die in index.recordsInPhysicalOrder) {
     require(++dies <= limits.maximumScannedDies); tags.add(die.tag)
     val rows = ArrayList<AbiScalarObservation>(die.attributes.size)
     AbiPopulationScalarEnrichment.observe(header.offset, die) { row ->
      attributes++
      if(row.kind == "uncaptured-payload" || row.kind.startsWith("unsupported-")) uncaptured++
      payloadCharacters = Math.addExact(payloadCharacters,
       (row.locator.length + row.kind.length + (row.value?.length ?: 0) + (row.auxiliary?.length ?: 0)).toLong())
      require(payloadCharacters <= limits.maximumOutputBytes)
      rows.add(row)
     }
     AbiPopulationScalarVerifier.verify(header.offset, die, rows)
    }
   }
  }
  artifact.verifyUnchanged("after rich scalar replay")
 }
 require(units == 111L && dies == 696357L && tags.size == 37)
 // Test-only observation of the existing counter, not an override or a production admission seam.
 val consumed = budget.javaClass.getDeclaredField("consumed").also { it.isAccessible = true }.getLong(budget)
 println("actual rich scalar replay PASS units=$units dies=$dies attributes=$attributes uncapturedOrUnsupported=$uncaptured payloadCharacters=$payloadCharacters parserSteps=$consumed parserStepLimit=${control.maximumDwarfParseSteps} maximumRetainedUnitBytes=${limits.maximumRetainedUnitBytes} semanticPopulationComplete=false modelBound=false sealed=false aggregateResourceQualified=false")
}

}
