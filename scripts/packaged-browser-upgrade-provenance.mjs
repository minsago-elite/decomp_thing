import assert from 'node:assert/strict';

const SHA1 = /^[a-f0-9]{40}$/;
const SHA256 = /^[a-f0-9]{64}$/;

function validateBuildRecord(provenance, schema, repository, expectedSource, archive) {
  assert.equal(provenance?.schema, schema, 'Package provenance schema is invalid');
  assert.equal(provenance.repository, repository, 'Package repository differs from its source');
  assert.match(provenance.commit ?? '', SHA1, 'Package source commit is invalid');
  assert.match(provenance.tree ?? '', SHA1, 'Package source tree is invalid');
  assert.equal(provenance.commit, expectedSource.commit, 'Package was not built from the expected commit');
  assert.equal(provenance.tree, expectedSource.tree, 'Package source tree differs from the expected tree');
  assert.equal(provenance.cleanSource, true, 'Package source checkout was not clean');
  assert.equal(provenance.archive?.file, expectedSource.archiveFile, 'Package filename is invalid');
  assert.match(provenance.archive?.sha256 ?? '', SHA256, 'Package SHA-256 is invalid');
  assert.equal(provenance.archive.sha256, archive.sha256, 'Package SHA-256 differs from the downloaded ZIP');
  assert.equal(provenance.archive.bytes, archive.bytes, 'Package byte count differs from the downloaded ZIP');
  assert.ok(Number.isSafeInteger(provenance.archive.bytes) && provenance.archive.bytes > 0,
    'Package byte count is invalid');
  for (const [key, maxLength] of [['gradleVersion', 128], ['javaVersion', 128], ['nodeVersion', 64]]) {
    assert.ok(typeof provenance.build?.[key] === 'string' && provenance.build[key].length > 0 &&
      provenance.build[key].length <= maxLength, `Package ${key} is invalid`);
  }
  assert.equal(provenance.build?.workflow, 'CI', 'Package workflow identity is invalid');
  assert.match(provenance.build?.runId ?? '', /^\d{1,20}$/, 'Package CI run identity is missing');
  assert.match(provenance.build?.runAttempt ?? '', /^\d{1,10}$/, 'Package CI run attempt is missing');
  return provenance;
}

export function validatePreviousBuildProvenance(pin, provenance, archive) {
  assert.equal(pin?.schema, 'packaged-upgrade-source-pin/v1', 'Previous source pin schema is invalid');
  assert.equal(pin.repository, 'minsago-elite/decomp_thing', 'Previous source pin repository is invalid');
  assert.match(pin.commit, SHA1, 'Previous source pin commit is invalid');
  assert.match(pin.tree, SHA1, 'Previous source pin tree is invalid');
  assert.ok(typeof pin.reason === 'string' && pin.reason.length > 0 && pin.reason.length <= 256,
    'Previous source pin reason is invalid');
  validateBuildRecord(provenance, 'packaged-previous-build/v1', pin.repository,
    { commit: pin.commit, tree: pin.tree, archiveFile: 'previous-package.zip' }, archive);
  return {
    schema: provenance.schema,
    repository: provenance.repository,
    commit: provenance.commit,
    tree: provenance.tree,
    cleanSource: provenance.cleanSource,
    build: { workflow: provenance.build.workflow, runId: provenance.build.runId,
      runAttempt: provenance.build.runAttempt, gradleVersion: provenance.build.gradleVersion,
      javaVersion: provenance.build.javaVersion, nodeVersion: provenance.build.nodeVersion },
    archive: { file: provenance.archive.file, sha256: provenance.archive.sha256, bytes: provenance.archive.bytes },
  };
}

export function validateCurrentBuildProvenance(provenance, repository, currentSource, archive) {
  validateBuildRecord(provenance, 'packaged-current-build/v2', repository,
    { ...currentSource, archiveFile: 'current-package.zip' }, archive);
  const expectedPullRequest = currentSource.pullRequest ?? null;
  if (expectedPullRequest === null) {
    assert.equal(provenance.pullRequest, null, 'Current package unexpectedly claims pull-request source identity');
  } else {
    assert.match(expectedPullRequest.headCommit ?? '', SHA1, 'Expected pull-request head commit is invalid');
    assert.match(expectedPullRequest.baseCommit ?? '', SHA1, 'Expected pull-request base commit is invalid');
    assert.deepEqual(provenance.pullRequest, expectedPullRequest,
      'Current package pull-request head/base identity differs from the browser qualification checkout');
  }
  return {
    schema: provenance.schema,
    repository: provenance.repository,
    commit: provenance.commit,
    tree: provenance.tree,
    pullRequest: provenance.pullRequest,
    cleanSource: provenance.cleanSource,
    build: { workflow: provenance.build.workflow, runId: provenance.build.runId,
      runAttempt: provenance.build.runAttempt, gradleVersion: provenance.build.gradleVersion,
      javaVersion: provenance.build.javaVersion, nodeVersion: provenance.build.nodeVersion },
    archive: { file: provenance.archive.file, sha256: provenance.archive.sha256, bytes: provenance.archive.bytes },
  };
}

export function assertSameUpgradeRun(previous, current, expectedRunId = null) {
  assert.equal(previous.build.workflow, current.build.workflow, 'Previous and current packages use different workflows');
  assert.equal(previous.build.runId, current.build.runId, 'Previous and current packages must come from the same workflow run');
  assert.equal(previous.build.runAttempt, current.build.runAttempt,
    'Previous and current packages must come from the same workflow attempt');
  if (expectedRunId !== null) {
    assert.match(expectedRunId, /^\d{1,20}$/, 'Browser qualification CI run identity is invalid');
    assert.equal(current.build.runId, expectedRunId,
      'Package artifacts were not produced by the workflow run performing this browser qualification');
  }
}
