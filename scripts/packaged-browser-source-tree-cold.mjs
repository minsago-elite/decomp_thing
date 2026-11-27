import assert from 'node:assert/strict';
import { nearestRankPercentile, sourceTreeBudgetsForProfile } from './packaged-browser-source-tree.mjs';

export const SOURCE_TREE_COLD_SAMPLE_COUNT = 20;

function median(values) {
  const sorted = [...values].sort((left, right) => left - right);
  const middle = Math.floor(sorted.length / 2);
  return sorted.length % 2 === 0 ? (sorted[middle - 1] + sorted[middle]) / 2 : sorted[middle];
}

/** Keep every attempt; an invalid or failed sample is never replaced or dropped. */
export function summarizeSourceTreeColdSamples(samples, profile) {
  assert.ok(profile === 'loopback' || profile === 'constrained');
  const durations = samples.map(sample => sample?.result?.durationMs);
  const failures = samples.filter(sample => sample?.status !== 'passed' || sample?.cleanup?.cleanup !== 'clean'
    || sample?.result?.browserExceptions !== 0 || sample?.result?.externalRequests !== 0);
  const finite = durations.length === samples.length && durations.every(value => Number.isFinite(value) && value >= 0);
  const identities = samples.map(sample => sample?.result?.browserProcessIdentity);
  const jvmIdentities = samples.map(sample => sample?.result?.jvmProcessIdentity);
  const profileIds = samples.map(sample => sample?.result?.profileId);
  const validIdentity = identity => Number.isSafeInteger(identity?.pid) && identity.pid > 0
    && Number.isSafeInteger(identity?.startTicks) && identity.startTicks >= 0;
  const browserKeys = identities.map(identity => validIdentity(identity) ? `${identity.pid}:${identity.startTicks}` : null);
  const jvmKeys = jvmIdentities.map(identity => validIdentity(identity) ? `${identity.pid}:${identity.startTicks}` : null);
  const identitiesUnique = browserKeys.every(Boolean) && new Set(browserKeys).size === samples.length
    && jvmKeys.every(Boolean) && new Set(jvmKeys).size === samples.length
    && profileIds.every(value => typeof value === 'string' && value.length >= 16) && new Set(profileIds).size === samples.length;
  const provenance = samples.map(sample => {
    const result = sample?.result;
    const driverHashes = result?.sourceTreeDriverSha256;
    return result && typeof result.archiveSha256 === 'string' && typeof result.applicationJarSha256 === 'string'
      && typeof result.buildId === 'string' && driverHashes && typeof driverHashes === 'object'
      && !Array.isArray(driverHashes) && Object.keys(driverHashes).length >= 16
      && Object.values(driverHashes).every(value => typeof value === 'string' && /^[a-f0-9]{64}$/u.test(value))
      && typeof result.chromeSha256 === 'string' && typeof result.browserProduct === 'string'
      && typeof result.javaSha256 === 'string' && /^[a-f0-9]{64}$/u.test(result.javaSha256)
      && typeof result.javaModulesSha256 === 'string' && /^[a-f0-9]{64}$/u.test(result.javaModulesSha256)
      && typeof result.javaReleaseSha256 === 'string' && /^[a-f0-9]{64}$/u.test(result.javaReleaseSha256)
      && result.sourceTreeWorktreeClean === true
      && [result.workflowSha, result.driverCommit].some(value => typeof value === 'string' && /^[a-f0-9]{40}$/iu.test(value))
      && typeof result.fixture?.jobId === 'string' && typeof result.fixture?.runId === 'string'
      && typeof result.fixture?.revisionId === 'string' && typeof result.fixture?.sourceSha256 === 'string'
      && typeof result.fixture?.binarySha256 === 'string' && typeof result.fixture?.profileId === 'string'
      && typeof result.fixture?.profileSha256 === 'string' && Number.isSafeInteger(result.fixture?.fileCount)
      ? JSON.stringify([result.archiveSha256, result.applicationJarSha256, result.buildId,
        result.chromeSha256, result.javaSha256, result.javaModulesSha256, result.javaReleaseSha256,
        result.browserProduct, result.workflowSha, result.driverCommit,
        result.checkoutParents, result.pullRequestIdentity, result.sourceTreeWorktreeClean,
        result.fixture.jobId, result.fixture.runId, result.fixture.revisionId,
        result.fixture.sourceSha256, result.fixture.binarySha256, result.fixture.fileCount,
        result.fixture.profileId, result.fixture.profileSha256,
        result.sourceTreeDriverSha256]) : null;
  });
  const provenanceConsistent = provenance.every(Boolean) && new Set(provenance).size === 1;
  const exactCount = samples.length === SOURCE_TREE_COLD_SAMPLE_COUNT;
  const p95 = finite && samples.length ? nearestRankPercentile(durations, 0.95) : null;
  const maximum = sourceTreeBudgetsForProfile(profile).firstDataPageP95Ms;
  const gate = {
    passed: exactCount && finite && identitiesUnique && provenanceConsistent && failures.length === 0 && p95 !== null && p95 <= maximum,
    requiredSamples: SOURCE_TREE_COLD_SAMPLE_COUNT,
    attemptedSamples: samples.length,
    successfulSamples: samples.filter(sample => sample?.status === 'passed').length,
    failedSamples: failures.length,
    uniqueProcessAndProfileIdentities: identitiesUnique,
    sourceAndArchiveIdentityConsistent: provenanceConsistent,
    finiteTimings: finite,
    p95Ms: p95,
    maximumP95Ms: maximum,
  };
  return {
    profile,
    definition: 'fresh packaged JVM and Chromium process per sample; unique empty browser profile; fixture written before JVM startup; OS page cache uncontrolled; authentication and startup excluded; timing begins at direct modules-route navigation dispatch and ends after exact first-page render plus completed directory response',
    filesystemState: { fixtureSeededBeforeJVM: true, osPageCacheControlled: false,
      runtimeIdentityHashReadsMayWarmOsPageCache: true, coldDiskPerformanceClaimed: false },
    sampleCount: SOURCE_TREE_COLD_SAMPLE_COUNT,
    samples,
    medianMs: finite && samples.length ? median(durations) : null,
    nearestRankP95Ms: p95,
    gate,
  };
}
