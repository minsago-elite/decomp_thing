import assert from 'node:assert/strict';
import { test } from 'node:test';
import { readFileSync, mkdtempSync, rmSync } from 'node:fs';
import { join, resolve } from 'node:path';
import { bindGitInitFixtures, createGitInitSection, qualifyGitInitialization, assessGitInitReport, GIT_INIT_CASES, GIT_INIT_COPY } from './packaged-browser-git-init.mjs';
import { applyAuditGitInitGate } from './packaged-browser-git-init-gate.mjs';
import { readStateFixtures } from './packaged-browser-read-states.mjs';

const repo = resolve(new URL('..', import.meta.url).pathname);
const readContract = (name) => readFileSync(join(repo, 'contracts/web/v1/fixtures', name));
const fixtureBundle = () => {
  // Use the interpreter selected by the CI toolchain (setup-python), not Ubuntu's system Python.
  const readStates = readStateFixtures({ repo, python: process.env.PYTHON ?? 'python3', buildId: 'git-init-test-build' });
  return { readStates, gitInit: bindGitInitFixtures(readStates, { readContract }) };
};

class FakeCdp {
  handlers = new Map(); closeCount = 0; disabled = 0; failed = []; continued = 0; responses = []; releases = new Map();
  on(name, fn, sessionId) { this.handlers.set(`${name}:${sessionId}`, fn); }
  off(name, fn, sessionId) { if (this.handlers.get(`${name}:${sessionId}`) === fn) this.handlers.delete(`${name}:${sessionId}`); }
  async issue(sessionId, id, method, path, extra = {}) {
    const handler = this.handlers.get(`Fetch.requestPaused:${sessionId}`);
    assert.ok(handler, 'Fetch handler is installed before any page request');
    await handler({ requestId: id, request: { url: `http://127.0.0.1${path}`, method, headers: {}, ...extra } });
  }
  async call(method, params = {}, sessionId) {
    if (method === 'Network.setCookie') return { success: true };
    if (method === 'Network.getCookies') return { cookies: [{ name: 'git_init_session', value: 'synthetic_cookie_value', path: '/nested/', httpOnly: true, sameSite: 'Strict', secure: false }] };
    if (method === 'Network.deleteCookies') return {};
    if (method === 'Fetch.enable') return {};
    if (method === 'Page.navigate') {
      const f = this.currentFixtures; const id = this.currentCase;
      await this.issue(sessionId, `${id}-bootstrap`, 'GET', '/nested/api/v1/bootstrap');
      await this.issue(sessionId, `${id}-job`, 'GET', `/nested/api/v1/jobs/${f.jobId}`);
      await this.issue(sessionId, `${id}-repositories-0`, 'GET', f.repositoriesPath);
      await this.issue(sessionId, `${id}-run`, 'GET', f.runPath);
      return {};
    }
    if (method === 'Input.dispatchMouseEvent' && params.type === 'mouseReleased') {
      const f = this.currentFixtures; const id = this.currentCase; const scenario = f.scenario(id);
      const release = (this.releases.get(id) ?? 0) + 1; this.releases.set(id, release);
      if (id === 'G9' && release === 2) {
        await this.issue(sessionId, `${id}-dashboard-jobs`, 'GET', '/nested/api/v1/jobs?limit=50');
        await this.issue(sessionId, `${id}-dashboard-recovery`, 'GET', '/nested/api/v1/recovery');
        const loadFailed = this.handlers.get(`Network.loadingFailed:${sessionId}`);
        assert.ok(loadFailed, 'network cancellation observer is installed before navigation');
        loadFailed({ requestId: `${id}-poll`, canceled: true });
        return {};
      }
      await this.issue(sessionId, `${id}-post`, 'POST', f.repositoriesPath, { postData: JSON.stringify({ action: 'git.init', runId: f.runId, revisionId: f.revisionId, initialBranch: null }), headers: {
        'X-CSRF-Token': 'synthetic_non_secret_csrf_fixture_1234567890', 'If-Match': '"job_version_1"', 'Idempotency-Key': '12345678-1234-4123-8123-123456789012',
        'Content-Type': 'application/json', Origin: 'http://127.0.0.1' } });
      const mismatchAck = ['G3', 'G4', 'G5'].includes(id);
      if (id !== 'G2' && !mismatchAck) {
        await this.issue(sessionId, `${id}-poll`, 'GET', f.pollPath);
        if (['G1'].includes(id)) {
          await this.issue(sessionId, `${id}-repositories-1`, 'GET', f.repositoriesPath);
          await this.issue(sessionId, `${id}-workspace`, 'GET', `${f.repositoriesPath}/${f.repositoryId}`);
        }
      } else if (id === 'G2') {
        await this.issue(sessionId, `${id}-repositories-1`, 'GET', f.repositoriesPath);
        await this.issue(sessionId, `${id}-run-readback`, 'GET', f.runPath);
      }
      return {};
    }
    if (method === 'Fetch.fulfillRequest') { this.responses.push({ id: params.requestId, code: params.responseCode }); return {}; }
    if (method === 'Fetch.failRequest') { this.failed.push({ id: params.requestId, reason: params.errorReason }); return {}; }
    if (method === 'Fetch.continueRequest') { this.continued++; throw new Error('fixture request must never continue to server'); }
    if (method === 'Fetch.disable') { this.disabled++; return {}; }
    if (method === 'Target.closeTarget') { this.closeCount++; return { success: true }; }
    if (method === 'Page.captureScreenshot') {
      const png = Buffer.alloc(33); Buffer.from([0x89,0x50,0x4e,0x47,0x0d,0x0a,0x1a,0x0a]).copy(png); png.write('IHDR',12,'ascii'); png.writeUInt32BE(1,16); png.writeUInt32BE(1,20);
      return { data: png.toString('base64') };
    }
    if (method === 'Runtime.evaluate') return {};
    if (method === 'Input.dispatchMouseEvent') return {};
    throw new Error(`unexpected CDP call ${method}`);
  }
}

test('fixture binding derives a finite supported-Git command scenario from pinned sources', () => {
  const { gitInit: f } = fixtureBundle();
  assert.match(f.identity.generatorSha256, /^[a-f0-9]{64}$/);
  assert.match(f.identity.outputSha256, /^[a-f0-9]{64}$/);
  assert.equal(f.respond('G1', 'GET', f.repositoriesPath, 0).entry.status, 200);
  assert.equal(f.respond('G1', 'POST', f.repositoriesPath).write, true);
  assert.equal(f.respond('G1', 'GET', '/nested/api/v1/anything').unknown, true);
  assert.equal(JSON.parse(f.respond('G1', 'GET', f.runPath).entry.body).data.resultRevisionId, f.revisionId);
  assert.deepEqual(f.scenario('G1').listings.map((x) => x.transformation), [['data.jobId', 'data.repositories=[]', 'data.operations=[]'], ['data.jobId', 'data.repositories[0].runId', 'data.operations[0].jobId']]);
});

test('assessor rejects missing command binding, extra writes, missing reference, and cleanup gaps', () => {
  const section = createGitInitSection(); section.fixtureIdentity = { fixtureOnly: true, generatorSha256: 'a'.repeat(64), outputSha256: 'b'.repeat(64) };
  assert.ok(assessGitInitReport(section).length > 0);
  section.cases = GIT_INIT_CASES.map(({ id }) => ({ id, status: 'observed', nonGetCount: 1, readbackCount: 0,
    requests: [{ method: 'POST', path: '/repositories', csrf: true, ifMatch: '"job_version_1"', idempotency: true }], state: { text: GIT_INIT_COPY.unverified, reference: null, rawRequestIdAbsent: true } }));
  section.cleanup = GIT_INIT_CASES.map(({ id }) => ({ id, fetchDisabled: true, cookieDeleted: true, closed: true, listener: 'removed' }));
  section.failures = []; section.assessment = [];
  assert.ok(assessGitInitReport(section).length > 0);
  section.cases.find((x) => x.id === 'G3').state.reference = '62800000-0000-4000-8000-000000000630';
  section.cases.find((x) => x.id === 'G4').requests.push({ method: 'POST', path: '/repositories', csrf: true, ifMatch: '"job_version_1"', idempotency: true });
  assert.ok(assessGitInitReport(section).some((x) => x.includes('G4')));
  section.cleanup[0].closed = false;
  assert.ok(assessGitInitReport(section).some((x) => x.includes('cleanup')));
});

test('scripted CDP drive keeps every API request intercepted and records the fixed nine cases', async () => {
  const { readStates, gitInit: f } = fixtureBundle(); const cdp = new FakeCdp(); const temp = mkdtempSync(join(repo, 'build', 'git-init-controls-'));
  let targetId = 0;
  const evaluate = async (_target, expression) => {
    if (expression.includes('location.pathname ===')) return true;
    if (expression.includes('window.__gitInitClickLog=[]')) return true;
    if (expression.includes('document.querySelectorAll(\'button\')')) return true;
    if (expression.includes('performance.getEntriesByType')) return { status: '', button: true, sessionRequests: 0 };
    if (expression.includes('getBoundingClientRect')) return { x: 200, y: 400, visible: true };
    if (expression.includes('rawRequestIdAbsent')) {
      const expected = cdp.currentCase === 'G1' ? GIT_INIT_COPY.repositoryRead : cdp.currentCase === 'G2' ? GIT_INIT_COPY.interrupted : cdp.currentCase === 'G9' ? GIT_INIT_COPY.noJobs : GIT_INIT_COPY.unverified;
      const ref = ({ G3:'62800000-0000-4000-8000-000000000630', G4:'62800000-0000-4000-8000-000000000631',
        G5:'62800000-0000-4000-8000-000000000632', G6:'62800000-0000-4000-8000-000000000633',
        G7:'62800000-0000-4000-8000-000000000634', G8:'62800000-0000-4000-8000-000000000635' })[cdp.currentCase] ?? null;
      return { text: expected, rawRequestIdAbsent: true, clickTrusted: true, rebindClickTrusted: cdp.currentCase === 'G9', reference: ref };
    }
    if (expression.includes('.git-repository [role="status"]')) return true;
    throw new Error(`unexpected expression ${expression.slice(0, 80)}`);
  };
  cdp.currentFixtures = f;
  const section = createGitInitSection();
  try {
    const makeTarget = async () => { cdp.currentCase = GIT_INIT_CASES[targetId].id; return { targetId: `target-${++targetId}`, sessionId: `session-${targetId}` }; };
    const result = await qualifyGitInitialization({ cdp, makeTarget, evaluate, ready: async () => true, delay: async () => {}, root: temp,
      origin: 'http://127.0.0.1', fixtures: f, cookie: { name: 'git_init_session', value: 'synthetic_cookie_value' }, section });
    assert.equal(result.cases.length, 9);
    assert.equal(cdp.continued, 0);
    assert.equal(cdp.closeCount, 9);
    assert.equal(cdp.disabled, 9);
    assert.deepEqual(cdp.failed, [], JSON.stringify(result.cases.map((x) => ({ id: x.id, errors: x.errors, requests: x.requests }))));
    assert.deepEqual(result.assessment, [], JSON.stringify(result.cases.map((x) => ({ id: x.id, errors:x.errors, state: x.state, readbackCount: x.readbackCount, requests: x.requests.map((r) => [r.method, r.path]) }))));
    assert.ok(Buffer.byteLength(JSON.stringify(result)) <= 48 * 1024);
    for (const mutate of [
      (copy) => copy.cases.find((x) => x.id === 'G3').requests.push({ method: 'GET', path: f.pollPath }),
      (copy) => copy.cases.find((x) => x.id === 'G7').requests.push({ method: 'GET', path: f.repositoriesPath }),
      (copy) => { copy.cases.find((x) => x.id === 'G4').clickTrusted = false; },
      (copy) => { copy.cases.find((x) => x.id === 'G8').state.reference = null; },
      (copy) => { copy.cases.find((x) => x.id === 'G1').requests.find((r) => r.method === 'POST').csrf = false; },
      (copy) => { copy.cases.find((x) => x.id === 'G9').pollCancelled = false; },
      (copy) => { copy.cases.find((x) => x.id === 'G9').pollHeld = false; },
      (copy) => { copy.cases.find((x) => x.id === 'G9').reboundToHome = false; },
      (copy) => { copy.cases.find((x) => x.id === 'G9').rebindClickTrusted = false; },
      (copy) => { copy.cases.find((x) => x.id === 'G9').requests = copy.cases.find((x) => x.id === 'G9').requests.filter((r) => r.path !== '/nested/api/v1/recovery'); },
      (copy) => { copy.cases.find((x) => x.id === 'G1').state.reference = '62800000-0000-4000-8000-000000000630'; },
    ]) { const copy = structuredClone(result); mutate(copy); assert.ok(assessGitInitReport(copy).length > 0); }
    const reorderedInitialWave = structuredClone(result); const g1Requests = reorderedInitialWave.cases.find((x) => x.id === 'G1').requests;
    [g1Requests[1], g1Requests[2], g1Requests[3]] = [g1Requests[3], g1Requests[1], g1Requests[2]];
    assert.deepEqual(assessGitInitReport(reorderedInitialWave), [], 'parallel job, repository and run reads may arrive in any order after bootstrap');
    const report = { buildId: 'git-init-test-build', auditReadStates: { fixtures: readStates.identity }, auditReadStatesGate: { passed: true, failures: [] },
      auditGitInit: result, auditGitInitGate: { passed: true, failures: [] },
      auditGitInitParent: { schema: 'packaged-git-init-parent/v1', lateSink: [], lateTargetCleanup: [], assessment: [] } };
    const passed = await applyAuditGitInitGate([{ ok: true, mode: 'audit', status: 'passed', directory: temp }], async () => report);
    assert.equal(passed[0].ok, true); assert.equal(passed[0].gitInitGate, 'passed');
    const tamperedReport = structuredClone(report); tamperedReport.auditGitInit.cases.find((x) => x.id === 'G1').screenshot.sha256 = '0'.repeat(64);
    const failed = await applyAuditGitInitGate([{ ok: true, mode: 'audit', status: 'passed', directory: temp }], async () => tamperedReport);
    assert.equal(failed[0].ok, false); assert.equal(failed[0].gitInitGate, 'failed');
    const tamperedDimensions = structuredClone(report); tamperedDimensions.auditGitInit.cases.find((x) => x.id === 'G9').screenshot.width = 2;
    const dimensionsDenied = await applyAuditGitInitGate([{ ok: true, mode: 'audit', status: 'passed', directory: temp }], async () => tamperedDimensions);
    assert.equal(dimensionsDenied[0].ok, false); assert.equal(dimensionsDenied[0].gitInitGate, 'failed');
    for (const alter of ['requestBodySha256', 'pollPath', 'contracts']) {
      const forged = structuredClone(report); const identity = forged.auditGitInit.fixtureIdentity;
      if (alter === 'requestBodySha256') {
        identity.requestBodySha256 = 'f'.repeat(64);
        forged.auditGitInit.cases.find((x) => x.id === 'G1').requests.find((x) => x.method === 'POST').bodySha256 = identity.requestBodySha256;
      } else if (alter === 'pollPath') {
        identity.pollPath = `${identity.repositoriesPath}/repository_forged/operations/operation_forged`;
        for (const c of forged.auditGitInit.cases) for (const request of c.requests) if (request.path.includes('/operations/')) request.path = identity.pollPath;
      } else identity.contracts['request-git-init.json'] = 'f'.repeat(64);
      const denied = await applyAuditGitInitGate([{ ok: true, mode: 'audit', status: 'passed', directory: temp }], async () => forged);
      assert.equal(denied[0].ok, false, `forged ${alter} should fail the report verifier`);
    }
  } finally { rmSync(temp, { recursive: true, force: true }); }
});
