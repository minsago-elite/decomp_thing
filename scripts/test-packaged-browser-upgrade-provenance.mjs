import assert from 'node:assert/strict';
import test from 'node:test';
import { readFileSync } from 'node:fs';
import { fileURLToPath } from 'node:url';
import { assertSameUpgradeRun, validateCurrentBuildProvenance, validatePreviousBuildProvenance } from './packaged-browser-upgrade-provenance.mjs';

const pin = JSON.parse(readFileSync(fileURLToPath(new URL('./packaged-browser-upgrade-pin.json', import.meta.url)), 'utf8'));
const expectedPin = {
  schema: 'packaged-upgrade-source-pin/v1',
  repository: 'minsago-elite/decomp_thing',
  commit: 'd9132c61f3cd2a1a357ead56010b488a8fdeeaf8',
  tree: '098fe6cfe201dace7ac6afa40faa45a67d1ff227',
};
const archive = { sha256: 'a'.repeat(64), bytes: 1234 };
const provenance = {
  schema: 'packaged-previous-build/v1',
  repository: pin.repository,
  commit: pin.commit,
  tree: pin.tree,
  cleanSource: true,
  build: { workflow: 'CI', gradleVersion: '8.14', javaVersion: '21.0.9', nodeVersion: '24.20.0', runId: '42100000000', runAttempt: '1' },
  archive: { file: 'previous-package.zip', ...archive },
};

test('accepts the exact pinned source tree and downloaded package digest', () => {
  assert.deepEqual(pin, {
    ...expectedPin,
    reason: 'Pinned pre-notice source for comparing the prior Runtime lazy-chunk asset with later package builds.',
  });
  assert.deepEqual(validatePreviousBuildProvenance(pin, provenance, archive), provenance);
});

test('rejects source, cleanliness, artifact, and toolchain provenance drift', () => {
  const mutations = [
    ['commit', { commit: 'b'.repeat(40) }],
    ['tree', { tree: 'b'.repeat(40) }],
    ['dirty source', { cleanSource: false }],
    ['archive digest', { archive: { ...provenance.archive, sha256: 'b'.repeat(64) } }],
    ['archive size', { archive: { ...provenance.archive, bytes: 5678 } }],
    ['archive name', { archive: { ...provenance.archive, file: 'other.zip' } }],
    ['missing Gradle version', { build: { ...provenance.build, gradleVersion: '' } }],
    ['missing Java version', { build: { ...provenance.build, javaVersion: '' } }],
    ['missing Node version', { build: { ...provenance.build, nodeVersion: '' } }],
    ['workflow identity', { build: { ...provenance.build, workflow: 'other' } }],
    ['missing CI run identity', { build: { ...provenance.build, runId: '' } }],
  ];
  for (const [label, patch] of mutations) {
    assert.throws(() => validatePreviousBuildProvenance(pin, { ...provenance, ...patch }, archive), undefined, label);
  }
  assert.throws(() => validatePreviousBuildProvenance({ ...pin, tree: 'x' }, provenance, archive), /pin tree/);
});

test('binds the current package to the exact driver checkout and ZIP bytes', () => {
  const current = {
    ...provenance,
    schema: 'packaged-current-build/v2',
    commit: 'c'.repeat(40),
    tree: 'd'.repeat(40),
    pullRequest: { headCommit: 'e'.repeat(40), baseCommit: 'f'.repeat(40) },
    archive: { file: 'current-package.zip', ...archive },
  };
  assert.equal(validateCurrentBuildProvenance(current, pin.repository,
    { commit: current.commit, tree: current.tree, pullRequest: current.pullRequest }, archive).commit, current.commit);
  assert.throws(() => validateCurrentBuildProvenance(current, pin.repository,
    { commit: pin.commit, tree: current.tree, pullRequest: current.pullRequest }, archive), /expected commit/);
  assert.throws(() => validateCurrentBuildProvenance(current, pin.repository,
    { commit: current.commit, tree: pin.tree, pullRequest: current.pullRequest }, archive), /expected tree/);
  assert.throws(() => validateCurrentBuildProvenance(current, pin.repository,
    { commit: current.commit, tree: current.tree, pullRequest: { ...current.pullRequest, headCommit: 'a'.repeat(40) } }, archive), /head\/base identity/);
  const pushBuild = { ...current, pullRequest: null };
  assert.equal(validateCurrentBuildProvenance(pushBuild, pin.repository,
    { commit: current.commit, tree: current.tree, pullRequest: null }, archive).pullRequest, null);
  assert.throws(() => validateCurrentBuildProvenance(current, pin.repository,
    { commit: current.commit, tree: current.tree, pullRequest: null }, archive), /unexpectedly claims pull-request/);
  const previous = validatePreviousBuildProvenance(pin, provenance, archive);
  const verifiedCurrent = validateCurrentBuildProvenance(current, pin.repository,
    { commit: current.commit, tree: current.tree, pullRequest: current.pullRequest }, archive);
  assert.doesNotThrow(() => assertSameUpgradeRun(previous, verifiedCurrent));
  assert.doesNotThrow(() => assertSameUpgradeRun(previous, verifiedCurrent, previous.build.runId));
  assert.throws(() => assertSameUpgradeRun(previous, verifiedCurrent, '42200000000'), /performing this browser qualification/);
  assert.throws(() => assertSameUpgradeRun(previous, {
    ...verifiedCurrent, build: { ...verifiedCurrent.build, runAttempt: '2' },
  }), /same workflow attempt/);
});
