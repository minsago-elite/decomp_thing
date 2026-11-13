// Heap/RSS limits are inherited from D0. FD ceilings and drain allowance are proposed #626 values,
// not an existing delivery-contract commitment; keep that distinction in every retained report.
export const LIMITS = Object.freeze({ initialHeapMiB: 128, finalHeapMiB: 192, retainedMiB: 16,
  retainedBackingStorageGrowthBytes: 1024 * 1024, jvmGrowthMiB: 256, fdPeak: 64, fdQuiescent: 8, drainSeconds: 35 });
const RETENTION_EVENT_TYPES = new Set(['abort', 'blur', 'change', 'click', 'error', 'focus', 'input', 'keydown', 'keyup',
  'load', 'message', 'offline', 'online', 'pointerdown', 'pointerup', 'submit', 'visibilitychange', 'other']);

const fail = (message) => { throw new Error(message); };
const percentile95 = (values) => {
  if (!Array.isArray(values) || !values.length || values.some(value => !Number.isFinite(value) || value < 0)) return NaN;
  return [...values].sort((a, b) => a - b)[Math.ceil(values.length * 0.95) - 1];
};
export function evaluate(report, baseline = {}) {
  if (!report || report.telemetryTruncated || !Array.isArray(report.samples) || !report.samples.length) fail('missing or truncated telemetry');
  if (report.applicationJvmProfile !== 'default' || !Array.isArray(report.applicationJvmOptions) || report.applicationJvmOptions.length !== 0) {
    fail('non-default packaged JVM profile cannot qualify the resource budget');
  }
  if (!Array.isArray(report.packagedJvmDefaultOptions) || report.packagedJvmDefaultOptions.length !== 1 ||
      report.packagedJvmDefaultOptions[0] !== '-Xms64m') fail('packaged JVM defaults do not match the qualified profile');
  if (!report.coverage || report.coverage.activityRows <= 200 || report.coverage.fourJobs !== true ||
      report.coverage.slots !== 120 || report.coverage.reconnects !== 20 || report.coverage.visibilityTransitions !== 10 ||
      report.coverage.reconnectDeliveries !== 20 ||
      report.coverage.naturalLeaseRenewals !== 4 || report.coverage.retentionGapRecovered !== true ||
      report.coverage.sourceReads <= 0 || report.coverage.finalCleanup !== true ||
      !Number.isSafeInteger(report.coverage.successfulStreamOpens) || report.coverage.successfulStreamOpens < 4 ||
      !Number.isSafeInteger(report.coverage.streamLimitResponses) || report.coverage.streamLimitResponses < 0) fail('workload coverage incomplete');
  if (report.coverage.activityRows < report.coverage.slots * 200 || report.coverage.sourceReads < report.coverage.slots * 2 ||
      report.jobSwitches !== 119 || report.sameDocument !== true) fail('workload volume or document continuity is incomplete');
  const retention = report.retention;
  if (retention?.version !== 1 || retention.complete !== true || retention.sampleEverySlots !== 5 ||
      !Array.isArray(retention.samples) || retention.samples.length !== 24 || report.coverage.listenerRetentionSamples !== 24 ||
      report.coverage.retentionNavigations !== 24) {
    fail('listener-retention sampling coverage incomplete');
  }
  const firstRetention = retention.samples[0];
  let previousRetention = null;
  for (const [index, sample] of retention.samples.entries()) {
    if (sample.index !== (index + 1) * 5 || sample.settledRoute !== '/nested/' || sample.openStreamCount !== 0 ||
        ![sample.activeListeners, sample.activeListenerTargets, sample.registrations, sample.explicitRemovals,
          sample.automaticRemovals, sample.collectedTargets, sample.collectedListeners, sample.gcPrunedTargets,
          sample.gcPrunedListeners, sample.rendererHeapBytesAfterGc, sample.rendererBackingStorageBytesAfterGc,
          sample.dashboardNavigationMs, sample.streamDrainMs, sample.dashboardListing?.requestCount,
          sample.dashboardListing?.completedCount, sample.dashboardListing?.durationMs].every(Number.isSafeInteger) ||
        sample.activeListeners < 0 || sample.activeListenerTargets < 0 || sample.rendererHeapBytesAfterGc < 0 ||
        sample.activeListenerTargets > sample.activeListeners || sample.rendererBackingStorageBytesAfterGc < 0 ||
        [sample.registrations, sample.explicitRemovals, sample.automaticRemovals, sample.collectedTargets,
          sample.collectedListeners, sample.gcPrunedTargets, sample.gcPrunedListeners].some(value => value < 0) ||
        sample.dashboardNavigationMs < 0 || sample.streamDrainMs < 0 || sample.streamDrainMs > LIMITS.drainSeconds * 1000 ||
        sample.dashboardListing.requestCount < 1 || sample.dashboardListing.requestCount > 16 ||
        sample.dashboardListing.completedCount !== sample.dashboardListing.requestCount || sample.dashboardListing.durationMs < 0 ||
        !Array.isArray(sample.dashboardListing.responseStatuses) ||
        sample.dashboardListing.responseStatuses.length !== sample.dashboardListing.requestCount ||
        sample.dashboardListing.responseStatuses.some(status => status !== 200) ||
        sample.trackingOverflow !== false || !sample.activeListenersByType || typeof sample.activeListenersByType !== 'object' ||
        Array.isArray(sample.activeListenersByType)) {
      fail('malformed or non-quiescent listener-retention sample');
    }
    const typeEntries = Object.entries(sample.activeListenersByType);
    if (typeEntries.some(([type, count]) => !RETENTION_EVENT_TYPES.has(type) || !Number.isSafeInteger(count) || count <= 0)) {
      fail('listener-retention event-type counts are malformed or unbounded');
    }
    const typeCount = typeEntries.reduce((sum, [, count]) => sum + count, 0);
    if (!Number.isSafeInteger(typeCount) || typeCount !== sample.activeListeners ||
        sample.registrations - sample.explicitRemovals - sample.automaticRemovals - sample.collectedListeners !== sample.activeListeners) {
      fail('listener-retention counts do not reconcile');
    }
    if (previousRetention && ['registrations', 'explicitRemovals', 'automaticRemovals', 'collectedTargets', 'collectedListeners']
      .some(field => sample[field] < previousRetention[field])) {
      fail('listener-retention cumulative counts decreased');
    }
    const previousCollectedTargets = previousRetention?.collectedTargets ?? 0;
    const previousCollectedListeners = previousRetention?.collectedListeners ?? 0;
    if (sample.collectedTargets - previousCollectedTargets !== sample.gcPrunedTargets ||
        sample.collectedListeners - previousCollectedListeners !== sample.gcPrunedListeners) {
      fail('listener-retention GC samples do not match cumulative collected counts');
    }
    if (sample.activeListeners > firstRetention.activeListeners) fail('active listener registrations accumulated after warm-up');
    if (sample.rendererBackingStorageBytesAfterGc - firstRetention.rendererBackingStorageBytesAfterGc > LIMITS.retainedMiB * 1024 * 1024) {
      fail('retained renderer backing-storage growth exceeded the inherited 16 MiB ceiling');
    }
    previousRetention = sample;
  }
  if (retention.samples.at(-1).rendererBackingStorageBytesAfterGc - firstRetention.rendererBackingStorageBytesAfterGc >
      LIMITS.retainedBackingStorageGrowthBytes) fail('renderer backing storage did not return to its stable post-warm-up range');
  if (report.identityViolation) fail('cross-job stale result');
  if (report.cleanupHeldLease && report.cleanupCharged !== true) fail('cleanup-held stream lease was not charged');
  const checkpoints = report.checkpoints;
  if (!Array.isArray(checkpoints) || checkpoints.length !== 4 || checkpoints.some((c, i) => c.minute !== (i + 1) * 5 || !Number.isFinite(c.browserHeapMiB) || !Number.isFinite(c.jvmTreeRssMiB))) fail('missing checkpoint telemetry');
  if (!Number.isFinite(report.initialBrowserHeapMiB) || report.initialBrowserHeapMiB > LIMITS.initialHeapMiB) fail('initial browser heap budget exceeded');
  if (!Number.isFinite(report.finalBrowserHeapMiB) || report.finalBrowserHeapMiB > LIMITS.finalHeapMiB) fail('final browser heap budget exceeded');
  if (!Number.isFinite(report.baseline?.jvmTreeRssMiB) || !Number.isFinite(report.baseline?.fdCount)) fail('missing warmed resource baseline');
  if (!report.postLogoutQuiescent || !Number.isFinite(report.postLogoutQuiescent.jvmTreeRssMiB) ||
      !Number.isFinite(report.postLogoutQuiescent.fdCount) || !Number.isFinite(report.postLogoutQuiescent.rootPid) ||
      !Number.isFinite(report.postLogoutQuiescent.rootStartTime)) fail('missing post-logout quiescent resource sample');
  if (![report.fdPeak, report.fdQuiescent, report.drainSeconds].every(Number.isFinite)) fail('missing descriptor or drain telemetry');
  if (report.baseline.pids?.[report.postLogoutQuiescent.rootPid] !== report.postLogoutQuiescent.rootStartTime) fail('JVM root identity changed before post-logout sample');
  if (report.fdQuiescent !== report.postLogoutQuiescent.fdCount - report.baseline.fdCount) fail('post-logout descriptor count does not reconcile');
  for (const c of checkpoints) if (c.browserHeapMiB > LIMITS.finalHeapMiB) fail('browser heap budget exceeded');
  for (let i = 1; i < checkpoints.length; i++) if (checkpoints[i].browserHeapMiB - checkpoints[i - 1].browserHeapMiB > LIMITS.retainedMiB) fail('retained browser growth budget exceeded');
  const peakRssMiB = Math.max(report.postLogoutQuiescent.jvmTreeRssMiB,
    ...report.samples.map(sample => sample.jvmTreeRssMiB), ...checkpoints.map(checkpoint => checkpoint.jvmTreeRssMiB));
  if (peakRssMiB - report.baseline.jvmTreeRssMiB > LIMITS.jvmGrowthMiB) fail('JVM process-tree RSS budget exceeded');
  const eventP95 = percentile95(report.activityReadLatencyMs);
  const routeP95 = percentile95(report.routeFeedbackLatencyMs);
  if (!Number.isFinite(eventP95) || !Number.isFinite(routeP95)) fail('missing latency samples');
  if (report.activityReadLatencyMs.length !== 20 || report.routeFeedbackLatencyMs.length < 120) fail('latency sample coverage is incomplete');
  if (eventP95 > 1000 || routeP95 > 100) fail('interaction or activity latency budget exceeded');
  if (!Number.isFinite(report.firstDataLatencyMs) || report.firstDataLatencyMs > 500) fail('first-data latency budget exceeded');
  if (report.workloadDurationMs !== 20 * 60_000 || !Number.isFinite(report.wallDurationMs) || report.wallDurationMs < report.workloadDurationMs) fail('soak workload or wall duration is shorter than twenty minutes');
  const sampleTimes = report.samples.map(sample => sample.sampledAtMonotonicMs);
  if (sampleTimes.some(value => !Number.isFinite(value)) || sampleTimes[0] > 2500 || report.wallDurationMs - sampleTimes.at(-1) > 2500 ||
      sampleTimes.some((value, index) => index > 0 && value - sampleTimes[index - 1] > 2500)) fail('missing or gapped one-second resource samples');
  for (const s of report.samples) {
    if (![s.pid, s.startTime, s.jvmTreeRssMiB, s.fdCount, s.rendererHeapMiB, s.streamCount, s.eventLatencyMs, s.routeLatencyMs].every(Number.isFinite)) fail('missing sample field');
    if (s.streamCount > 2) fail('single-session Activity stream quota exceeded');
    const prior = report.baseline.pids?.[s.pid] ?? baseline.pids?.[s.pid];
    if (prior !== undefined && prior !== s.startTime) fail('PID reused with changed start identity');
  }
  if (report.fdPeak !== Math.max(report.baseline.fdCount, ...report.samples.map(sample => sample.fdCount))) fail('descriptor peak does not match samples');
  if (!Array.isArray(report.leaseRenewals) || report.leaseRenewals.length !== 4 || report.leaseRenewals.some(renewal =>
      !Number.isFinite(renewal.dwellMs) || renewal.dwellMs < 35_000 || renewal.streamOpensAfter <= renewal.streamOpensBefore)) fail('natural stream renewal evidence is incomplete');
  if (report.fdPeak > report.baseline.fdCount + LIMITS.fdPeak || report.fdQuiescent > LIMITS.fdQuiescent) fail('proposed #626 descriptor profile limit exceeded');
  if (report.drainSeconds > LIMITS.drainSeconds) fail('stream drain limit exceeded');
  return { passed: true, sampleCount: report.samples.length };
}
