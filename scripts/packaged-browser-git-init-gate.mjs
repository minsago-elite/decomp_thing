// Parent-side, fail-closed verifier for the #1897 fixture-only packaged command journey.
import { readFileSync } from 'node:fs';
import { dirname, join, resolve } from 'node:path';
import { fileURLToPath } from 'node:url';
import { isDeepStrictEqual } from 'node:util';
import { bindGitInitFixtures, assessGitInitReport, GIT_INIT_CASES, verifyGitInitPng } from './packaged-browser-git-init.mjs';
import { readStateFixtures } from './packaged-browser-read-states.mjs';

const cap = (value) => String(value ?? '').slice(0, 200);
const repo = resolve(dirname(fileURLToPath(import.meta.url)), '..');

function recomputeFixtureIdentity(report) {
  const readStates = report?.auditReadStates;
  if (report?.auditReadStatesGate?.passed !== true || report.auditReadStatesGate.failures?.length !== 0
    || typeof report?.buildId !== 'string' || !report.buildId
    || !/^[a-f0-9]{64}$/.test(String(readStates?.fixtures?.generatorSha256))
    || !/^[a-f0-9]{64}$/.test(String(readStates?.fixtures?.outputSha256))) throw new Error('passed #628 fixture provenance and package build identity are required');

  // The verifier reruns the pinned generator, then derives the complete expected Git-init fixture identity
  // from its bytes and the retained contract files. Only the bootstrap's runtime expiry varies; bind that
  // one hash to #628's independently verified S10 variant record before comparing the complete object.
  const generated = readStateFixtures({ repo, python: process.env.PYTHON ?? 'python3', buildId: report.buildId });
  if (generated.identity.generatorSha256 !== readStates.fixtures.generatorSha256
    || generated.identity.outputSha256 !== readStates.fixtures.outputSha256) throw new Error('pinned read-state generator provenance differs');
  const expected = structuredClone(bindGitInitFixtures(generated, { readContract: (name) => readFileSync(join(repo, 'contracts/web/v1/fixtures', name)) }).identity);
  const bootstrapSha256 = readStates.fixtures.variants?.['628-git-supported']?.postSha256;
  if (!/^[a-f0-9]{64}$/.test(String(bootstrapSha256))) throw new Error('verified S10 bootstrap variant hash is missing');
  expected.bootstrapSha256 = bootstrapSha256;
  expected.sources[0].servedSha256 = bootstrapSha256;
  return expected;
}

export const GIT_INIT_PNG_NAMES = Object.freeze(GIT_INIT_CASES.map(({ id }) => `git-init-${id}.png`));

export async function applyAuditGitInitGate(results, load) {
  for (const result of results) {
    if (!result.ok || result.mode !== 'audit') continue;
    const failures = [];
    try {
      const report = await load(result.directory); const section = report.auditGitInit;
      failures.push(...assessGitInitReport(section));
      const expectedIdentity = recomputeFixtureIdentity(report);
      if (!isDeepStrictEqual(section?.fixtureIdentity, expectedIdentity)) failures.push('Git-init fixture identity differs from pinned generator/contract recomputation');
      const parent = report.auditGitInitParent;
      if (parent?.schema !== 'packaged-git-init-parent/v1') failures.push('parent evidence schema missing');
      if (!Array.isArray(parent?.lateSink) || parent.lateSink.length !== 0) failures.push('late request/target sink is not empty');
      if (!Array.isArray(parent?.lateTargetCleanup) || parent.lateTargetCleanup.some((x) => x.outcome !== 'closed' || typeof x.targetId !== 'string' || !x.targetId)) failures.push('late target cleanup incomplete');
      if (!Array.isArray(parent?.assessment) || parent.assessment.length) failures.push('parent assessment is not empty');
      if (report.auditGitInitGate?.passed !== true || report.auditGitInitGate?.failures?.length !== 0) failures.push('driver gate is missing or failed');
      const screenshots = (section?.cases ?? []).map((x) => x.screenshot).filter(Boolean); const names = screenshots.map((x) => x.name).sort();
      const expected = [...GIT_INIT_PNG_NAMES].sort();
      if (names.length !== expected.length || names.some((name, i) => name !== expected[i])) failures.push('fixed screenshot set mismatch');
      else for (const screenshot of screenshots) { try { await verifyGitInitPng(result.directory, screenshot); } catch (error) { failures.push(cap(error?.message ?? error)); } }
    } catch (error) { failures.push(`report load or Git-init assessment failed: ${cap(error?.message ?? error)}`); }
    result.gitInitGate = failures.length ? 'failed' : 'passed';
    if (failures.length) { result.ok = false; result.error = `integrity verified; #1897 packaged Git-init gate failed: ${failures.slice(0, 6).join('; ')}`; }
  }
  return results;
}
