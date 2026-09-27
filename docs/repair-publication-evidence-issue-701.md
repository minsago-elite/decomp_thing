# Repair publication and evidence entry-point record

Issue #701 records the current reconciliation boundary from the repository's
existing contracts. `RepairStateStore` opens descriptor-owned project, report,
revision, and blob directories; its legacy migration writes exact historical
graph/history bytes as content-addressed `legacy-*.json` files under
`reports/repair-revisions/`. `TraceGuidedRepair` treats the revision graph as
canonical and refreshes `repair_history.json` and the compatibility log as
projections. A projection failure is retained for recovery on the next open and
does not manufacture an accepted revision.

`BehaviorEvidence` binds a behavior report to the project revision, source
inputs, rebuilt artifact identity, retained corpus, and report hash. The archive
verifier requires schema-3 graph and history together, rejects pending or legacy
state as release authority, and admits preserved legacy bytes only by their
exact archive commitment. These are the publication and evidence contracts
available in the current source.

The historical direct repair-history read is gone. `UploadServer.handleJob`
selects the report namespace and passes the compatibility projection through
`WebJobService.readArtifact`, `JobStore.readArtifact`, and the bounded,
descriptor-bound `readStableRegularFile` operation. `WebViews.renderRepairHistory`
only renders the supplied JSON; it never opens the job path. The web report
listing uses path-based metadata for display, but artifact downloads repeat the
bounded descriptor-bound read. `UploadServerTest` now checks both ordinary
history presentation and rejection of a symlinked history that points at a
foreign file: the foreign bytes appear neither on the page nor as a download.
The compatibility projection is still not a release verifier or repair
acceptance authority; canonical graph and archive verification retain those
roles.

This record does not claim production qualification. The strict contained
generated-C validation provider remains unavailable behind its production
qualification guard. A real bounded GCC-driver repair, independent resource
accounting, and production-shaped restart/archive evidence remain open under
#236, #702, and #703. No test-only compiler/behavior fixture, host fallback,
external `GHIDRA_HOME`, or `analyzeHeadless` installation changes that status;
bundled Ghidra isolation, authenticated oracle boundaries, provenance, and
unresolved outcomes remain in force.

Source facts: `src/main/kotlin/decompengine/repair/RepairStateStore.kt`,
`src/main/kotlin/decompengine/repair/TraceGuidedRepair.kt`,
`src/main/kotlin/decompengine/validation/BehaviorEvidence.kt`,
`src/main/kotlin/decompengine/project/RepairAcpEvidenceArchiveVerifier.kt`,
`src/main/kotlin/decompengine/web/WebViews.kt`, and
`src/test/kotlin/decompengine/web/UploadServerTest.kt`.
