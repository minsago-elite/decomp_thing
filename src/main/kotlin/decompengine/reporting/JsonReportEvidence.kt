package decompengine.reporting

/** Records configured ceilings; these fields do not claim measured process memory or durability. */
internal fun BoundedJsonReportWriter.publicationLimitFields(limits: JsonReportLimits) {
    field("maximumBytes", limits.maximumBytes)
    field("maximumStringCharacters", limits.maximumStringCharacters.toLong())
    field("maximumCollectionItems", limits.maximumCollectionItems)
    field("maximumDepth", limits.maximumDepth.toLong())
    field("maximumWallClockMillis", limits.maximumWallClockMillis)
}
