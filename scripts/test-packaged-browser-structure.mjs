import assert from 'node:assert/strict';
import test from 'node:test';
import { assertStructureSourceLink, nearestRankP95 } from './packaged-browser-structure.mjs';

const revision = `/nested/jobs/${'f'.repeat(32)}/runs/run_structure_scale/revisions/revision_structure_scale`;
const browserOrigin = 'http://127.0.0.1:12345';
const snapshot = { sourceSha256: 'a'.repeat(64), metadataVersion: 'b'.repeat(64),
  module: { implementationFileId: `file_42_${'c'.repeat(64)}` } };
const path = `${revision}/source-files/${snapshot.module.implementationFileId}`;
const pins = `sourceSha256=${snapshot.sourceSha256}&metadataVersion=${snapshot.metadataVersion}`;
const check = href => assertStructureSourceLink(href, { revision, browserOrigin, snapshot });

test('structure scale p95 uses nearest rank and refuses missing or invalid timings', () => {
  assert.equal(nearestRankP95(Array.from({ length: 50 }, (_, index) => index + 1)), 48);
  assert.equal(nearestRankP95([3, 1, 2]), 3);
  for (const values of [[], [Number.NaN], [Number.POSITIVE_INFINITY], [-1], null]) {
    assert.throws(() => nearestRankP95(values), TypeError);
  }
});

test('packaged structure accepts only source links pinned to the originating module snapshot', () => {
  check(`${path}?${pins}`);
  check(`${browserOrigin}${path}?metadataVersion=${snapshot.metadataVersion}&sourceSha256=${snapshot.sourceSha256}`);
});

for (const [name, href] of [
  ['missing link', null],
  ['unpinned link', path],
  ['missing metadata pin', `${path}?sourceSha256=${snapshot.sourceSha256}`],
  ['missing source pin', `${path}?metadataVersion=${snapshot.metadataVersion}`],
  ['foreign source pin', `${path}?${pins.replace(snapshot.sourceSha256, 'd'.repeat(64))}`],
  ['foreign metadata pin', `${path}?${pins.replace(snapshot.metadataVersion, 'e'.repeat(64))}`],
  ['extra query key', `${path}?${pins}&unexpected=1`],
  ['duplicate source pin', `${path}?${pins}&sourceSha256=${snapshot.sourceSha256}`],
  ['duplicate metadata pin', `${path}?${pins}&metadataVersion=${snapshot.metadataVersion}`],
  ['foreign file', `${path.replace('file_42_', 'file_43_')}?${pins}`],
  ['foreign revision', `${path.replace('revision_structure_scale', 'revision_other')}?${pins}`],
  ['foreign origin', `http://127.0.0.1:54321${path}?${pins}`],
  ['fragment', `${path}?${pins}#unrelated`],
  ['URL credentials', `http://user:password@127.0.0.1:12345${path}?${pins}`],
]) {
  test(`packaged structure rejects ${name}`, () => assert.throws(() => check(href)));
}
