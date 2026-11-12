import test from 'node:test';
import assert from 'node:assert/strict';
import { evaluate } from './evaluate.mjs';

function good() { return { coverage: { activityRows: 120 * 205, fourJobs: true, slots: 120, reconnects: 20, reconnectDeliveries: 20, visibilityTransitions: 10,
  naturalLeaseRenewals: 4, retentionGapRecovered: true, sourceReads: 240, finalCleanup: true,
  successfulStreamOpens: 8, streamLimitResponses: 0 }, jobSwitches: 119, sameDocument: true,
  applicationJvmProfile: 'default', applicationJvmOptions: [],
  packagedJvmDefaultOptions: ['-Xms64m'],
  initialBrowserHeapMiB: 128, finalBrowserHeapMiB: 192, baseline: { jvmTreeRssMiB: 100, fdCount: 0, pids: { 1: 10 } },
  postLogoutQuiescent: { jvmTreeRssMiB: 100, fdCount: 8, rootPid: 1, rootStartTime: 10 },
  activityReadLatencyMs: Array(20).fill(1000), routeFeedbackLatencyMs: Array(120).fill(100), firstDataLatencyMs: 500,
  workloadDurationMs: 20 * 60_000, wallDurationMs: 20 * 60_000,
  samples: Array.from({ length: 1201 }, (_, index) => ({ pid: 1, startTime: 10, jvmTreeRssMiB: 100, fdCount: 5,
    rendererHeapMiB: 10, streamCount: 1, eventLatencyMs: 1, routeLatencyMs: 1, sampledAtMonotonicMs: index * 1000 })),
  checkpoints: [5,10,15,20].map((minute, index) => ({ minute, browserHeapMiB: 128 + index * 16, jvmTreeRssMiB: 100 })),
  fdPeak: 5, fdQuiescent: 8, drainSeconds: 35,
  leaseRenewals: Array.from({ length: 4 }, (_, index) => ({ dwellMs: 35000, streamOpensBefore: index, streamOpensAfter: index + 1 })) }; }
test('accepts equal thresholds and complete workload', () => { const r=good(); r.initialBrowserHeapMiB=128; r.finalBrowserHeapMiB=192; r.checkpoints[0].browserHeapMiB=128; r.checkpoints[1].browserHeapMiB=144; r.checkpoints[3].browserHeapMiB=176; r.samples[0].jvmTreeRssMiB=356; r.samples[0].fdCount=64; r.fdPeak=64; r.fdQuiescent=8; r.drainSeconds=35; assert.equal(evaluate(r).passed,true); });
test('rejects one over each resource limit', () => { for (const mutate of [r=>r.initialBrowserHeapMiB++, r=>r.finalBrowserHeapMiB=193, r=>r.checkpoints[3].browserHeapMiB=193, r=>r.checkpoints[1].browserHeapMiB=145, r=>r.samples[0].jvmTreeRssMiB=357, r=>r.checkpoints[0].jvmTreeRssMiB=357, r=>r.samples[0].streamCount=3, r=>r.fdPeak=65, r=>r.fdQuiescent=9, r=>r.drainSeconds=36]) { const r=good(); mutate(r); assert.throws(()=>evaluate(r)); } });
test('rejects absent/truncated data, PID reuse, stopped pagination and stale identities', () => { for(const mutate of [r=>r.samples=[], r=>r.telemetryTruncated=true, r=>r.coverage.activityRows=200, r=>r.identityViolation=true, r=>r.samples[0].startTime=11]) { const r=good(); mutate(r); assert.throws(()=>evaluate(r,{pids:{1:10}})); } });
test('requires post-logout process identity and complete resource counters', () => { for (const mutate of [r=>delete r.postLogoutQuiescent, r=>r.postLogoutQuiescent.rootStartTime++, r=>delete r.fdQuiescent, r=>r.postLogoutQuiescent.jvmTreeRssMiB=357]) { const r=good(); mutate(r); assert.throws(()=>evaluate(r)); } });
test('cleanup lease remains charged until released', () => { const r=good(); r.cleanupHeldLease=true; assert.throws(()=>evaluate(r),/lease/); r.cleanupCharged=true; assert.equal(evaluate(r).passed,true); });
test('requires a full bounded Activity page per slot and retention recovery', () => { for(const mutate of [r=>r.coverage.activityRows=120*199, r=>r.coverage.sourceReads=0, r=>r.coverage.retentionGapRecovered=false]) { const r=good(); mutate(r); assert.throws(()=>evaluate(r), /coverage|volume/); } });
test('requires latency samples and exact profile coverage', () => { for (const mutate of [r=>r.routeFeedbackLatencyMs=[], r=>r.activityReadLatencyMs.fill(1001), r=>r.activityReadLatencyMs.pop(), r=>r.routeFeedbackLatencyMs.fill(101), r=>r.coverage.slots=119, r=>r.coverage.reconnects=19, r=>r.coverage.reconnectDeliveries=19, r=>r.coverage.sourceReads=239, r=>r.jobSwitches=118, r=>r.sameDocument=false]) { const r=good(); mutate(r); assert.throws(()=>evaluate(r)); } });
test('requires a measured first-data sample within the inherited budget', () => {
  for (const mutate of [r => { r.firstDataLatencyMs = null; }, r => { delete r.firstDataLatencyMs; },
    r => { r.firstDataLatencyMs = 501; }]) {
    const report = good(); mutate(report); assert.throws(() => evaluate(report), /first-data/);
  }
});
test('requires four observed natural lease renewals', () => { const r=good(); r.leaseRenewals[0].streamOpensAfter = r.leaseRenewals[0].streamOpensBefore; assert.throws(()=>evaluate(r), /renewal/); });
test('requires successful stream-open and capacity-rejection counts', () => { for(const mutate of [r=>delete r.coverage.successfulStreamOpens, r=>r.coverage.successfulStreamOpens=3, r=>r.coverage.streamLimitResponses=-1]) { const r=good(); mutate(r); assert.throws(()=>evaluate(r), /coverage/); } });
test('rejects a short or temporally gapped telemetry run', () => { for (const mutate of [r=>r.wallDurationMs=1199999, r=>r.samples[5].sampledAtMonotonicMs=8000]) { const r=good(); mutate(r); assert.throws(()=>evaluate(r), /duration|samples/); } });
test('rejects experimental JVM options as product qualification', () => { for (const profile of ['xms64', 'xms64-xmx384']) { const report=good(); report.applicationJvmProfile=profile; report.applicationJvmOptions=['-Xms64m']; assert.throws(()=>evaluate(report), /JVM profile/); } });
test('requires the packaged JVM default to be bound to the report', () => { for (const options of [undefined, [], ['-Xmx384m'], ['-Xms64m', '-Xmx384m']]) { const report=good(); report.packagedJvmDefaultOptions=options; assert.throws(()=>evaluate(report), /packaged JVM defaults/); } });
