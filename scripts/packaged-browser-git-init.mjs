// Fixture-only packaged browser qualification for #1897. No request may escape DevTools interception.
import { createHash } from 'node:crypto';
import { constants as fsConstants, promises as fs } from 'node:fs';
import { join } from 'node:path';
import { isDeepStrictEqual } from 'node:util';
import { BASE, API, JOB, RUN, pngDimensions, withDeadline } from './packaged-browser-read-states.mjs';

const sha256 = (bytes) => createHash('sha256').update(bytes).digest('hex');
const HEX64 = /^[0-9a-f]{64}$/;
const UUID = /^[0-9a-f]{8}-[0-9a-f]{4}-[1-8][0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$/;
const CAP = 200;
export const GIT_INIT_LIMITS = Object.freeze({ callMs: 10_000, caseMs: 25_000, sectionMs: 240_000, bytes: 48 * 1024, pngBytes: 2 * 1024 * 1024 });
export const GIT_INIT_CASES = Object.freeze([
  { id: 'G1', kind: 'success' }, { id: 'G2', kind: 'terminal-interrupted' },
  { id: 'G3', kind: 'ack-job' }, { id: 'G4', kind: 'ack-action' }, { id: 'G5', kind: 'ack-repository' },
  { id: 'G6', kind: 'poll-job' }, { id: 'G7', kind: 'poll-repository' }, { id: 'G8', kind: 'poll-operation' }, { id: 'G9', kind: 'cancel-rebind' },
]);
export const GIT_INIT_COPY = Object.freeze({
  initialize: 'Initialize repository from the latest candidate',
  unverified: 'The server response did not match this initialization request, so its outcome is unverified. Refresh to read the recorded operation before trying again.',
  repositoryRead: 'Repository state was read from the server.',
  interrupted: 'The last repository operation was interrupted. Refresh to read the recorded state before trying again.',
  noJobs: 'No uploaded jobs yet.',
});

function documentOf(entry, where) {
  if (!entry || !Buffer.isBuffer(entry.body) || sha256(entry.body) !== entry.servedSha256) throw new Error(`${where}: source entry is invalid`);
  return JSON.parse(entry.body.toString('utf8'));
}
function entry(path, status, document, source, sourceSha256, transformation = []) {
  const body = Buffer.from(JSON.stringify(document));
  const parsed = JSON.parse(body.toString('utf8'));
  if (!/^[A-Za-z0-9][A-Za-z0-9_-]{0,127}$/.test(parsed.requestId ?? '')) throw new Error(`${path}: requestId is invalid`);
  if ((status >= 400) !== (parsed.kind === 'error')) throw new Error(`${path}: status and envelope kind disagree`);
  return Object.freeze({ path, status, source, sourceSha256, servedSha256: sha256(body), bytes: body.length,
    requestId: parsed.requestId, transformation: [...transformation], body });
}
function derive(source, path, mutate, transformation) {
  const document = documentOf(source, path);
  mutate(document);
  return entry(path, source.status, document, `${source.source}-derived`, source.sourceSha256, transformation);
}
function contract(readContract, name) {
  const body = readContract(name);
  if (!Buffer.isBuffer(body)) throw new Error(`${name}: contract loader must return Buffer`);
  const document = JSON.parse(body.toString('utf8'));
  if (!['gitRepositories', 'operation', 'gitWorkspace', 'gitRepositoryInitRequest'].includes(document.kind)) throw new Error(`${name}: unexpected Git contract kind`);
  return { name, body, sha256: sha256(body), document };
}

/**
 * Binds a finite command fixture set to the already reviewed S10 bootstrap/job/run sources. Derivations are
 * field-allowlisted and hashed; the candidate revision is the sole generated-run patch. The five retained
 * contract templates remain byte-pinned as inputs. No browser or API request can reach the application server.
 */
export function bindGitInitFixtures(readStates, { readContract }) {
  const base = `${API}/jobs/${JOB}`; const repositoriesPath = `${base}/repositories`;
  const bootstrap = readStates.entry('S10', `${API}/bootstrap`);
  const job = readStates.entry('S10', base);
  const run = readStates.entry('S10', `${base}/runs/${RUN}`);
  const dashboardJobs = readStates.entry('S3', `${API}/jobs?limit=50`);
  const dashboardRecovery = readStates.entry('S3', `${API}/recovery`);
  if (!bootstrap || !job || !run || !dashboardJobs || !dashboardRecovery) throw new Error('reviewed S10 and S3 sources are required');
  const repoTemplate = contract(readContract, 'git-repositories.json');
  const workspaceTemplate = contract(readContract, 'git-workspace-unborn-dirty.json');
  const completedTemplate = contract(readContract, 'git-operation-init-completed.json');
  const interruptedTemplate = contract(readContract, 'git-operation-init-interrupted.json');
  const requestTemplate = contract(readContract, 'request-git-init.json');
  const repositoryId = completedTemplate.document.data.repositoriesId ?? completedTemplate.document.data.repositoryId;
  const operationId = completedTemplate.document.data.operationId;
  const worktreeId = completedTemplate.document.data.worktreeId;
  const revisionId = 'fixture_revision_responsive';
  if (!repositoryId || !operationId || !worktreeId) throw new Error('completed operation contract lacks identity fields');
  const requestDocument = structuredClone(requestTemplate.document);
  Object.assign(requestDocument.data, { runId: RUN, revisionId });
  // The client validates the retained request envelope, then sends only the data object as HTTP JSON.
  const requestBody = Buffer.from(JSON.stringify(requestDocument.data));
  const requestBodySha256 = sha256(requestBody);

  const initialRun = derive(run, `${base}/runs/${RUN}`, (doc) => { doc.data.resultRevisionId = revisionId; }, ['data.resultRevisionId']);
  const makeOperation = (template, { requestId = template.document.requestId, jobId = JOB, action = 'git.init', repositoryId: repo = template.document.data.repositoryId, operationId: op = template.document.data.operationId, state, endedAt } = {}) => {
    const doc = structuredClone(template.document);
    doc.requestId = requestId;
    Object.assign(doc.data, { jobId, action, repositoryId: repo, operationId: op });
    if (state !== undefined) doc.data.state = state;
    if (endedAt !== undefined) doc.data.endedAt = endedAt;
    return entry(`${repositoriesPath}/${repo}/operations/${op}`, 200, doc, `contract-derived:${template.name}`,
      template.sha256, ['data.jobId', 'data.action', 'data.repositoryId', 'data.operationId', ...(state === undefined ? [] : ['data.state']), ...(endedAt === undefined ? [] : ['data.endedAt']), ...(requestId === template.document.requestId ? [] : ['requestId'])]);
  };
  const validAck = makeOperation(completedTemplate, { state: 'running', endedAt: null });
  const completePoll = makeOperation(completedTemplate);
  const interruptedAck = makeOperation(interruptedTemplate, { jobId: JOB });
  const canonical = (n) => `62800000-0000-4000-8000-${String(n).padStart(12, '0')}`;
  const ackJob = makeOperation(completedTemplate, { jobId: '1234567890abcdef1234567890abcdef', state: 'completed', requestId: canonical(630) });
  const ackAction = makeOperation(completedTemplate, { action: 'git.commit', state: 'completed', requestId: canonical(631) });
  const ackRepository = makeOperation(completedTemplate, { repositoryId: null, state: 'completed', requestId: canonical(632) });
  const pollJob = makeOperation(completedTemplate, { jobId: '1234567890abcdef1234567890abcdef', requestId: canonical(633) });
  const pollRepository = makeOperation(completedTemplate, { repositoryId: 'repository_example_3', requestId: canonical(634) });
  const pollOperation = makeOperation(completedTemplate, { operationId: 'operation_example_3', requestId: canonical(635) });
  const emptyListing = (operation = null) => {
    const doc = structuredClone(repoTemplate.document);
    doc.data.jobId = JOB; doc.data.repositories = []; doc.data.operations = operation ? [JSON.parse(operation.body.toString()).data] : [];
    return entry(repositoriesPath, 200, doc, `contract-derived:${repoTemplate.name}`, repoTemplate.sha256,
      ['data.jobId', 'data.repositories=[]', ...(operation ? ['data.operations[0]'] : ['data.operations=[]'])]);
  };
  const initialListing = emptyListing();
  const completedListing = derive(entry(repositoriesPath, 200, repoTemplate.document, `contract:${repoTemplate.name}`, repoTemplate.sha256), repositoriesPath, (doc) => {
    doc.data.jobId = JOB;
    doc.data.repositories[0].runId = RUN;
    doc.data.operations[0].jobId = JOB;
  }, ['data.jobId', 'data.repositories[0].runId', 'data.operations[0].jobId']);
  const workspaceDoc = structuredClone(workspaceTemplate.document);
  const workspace = entry(`${repositoriesPath}/${repositoryId}`, 200, workspaceDoc, `contract:${workspaceTemplate.name}`, workspaceTemplate.sha256);
  const scenarios = new Map([
    ['G1', { ack: validAck, poll: completePoll, listings: [initialListing, completedListing], workspace }],
    ['G2', { ack: interruptedAck, poll: null, listings: [initialListing, emptyListing(interruptedAck)], workspace: null }],
    ['G3', { ack: ackJob, poll: null, listings: [initialListing], workspace: null }],
    ['G4', { ack: ackAction, poll: null, listings: [initialListing], workspace: null }],
    ['G5', { ack: ackRepository, poll: null, listings: [initialListing], workspace: null }],
    ['G6', { ack: validAck, poll: pollJob, listings: [initialListing], workspace: null }],
    ['G7', { ack: validAck, poll: pollRepository, listings: [initialListing], workspace: null }],
    ['G8', { ack: validAck, poll: pollOperation, listings: [initialListing], workspace: null }],
    ['G9', { ack: validAck, poll: completePoll, listings: [initialListing], workspace: null }],
  ]);
  const pollPath = `${repositoriesPath}/${repositoryId}/operations/${operationId}`;
  const sources = [bootstrap, job, run, initialRun, repoTemplate, workspaceTemplate, completedTemplate, interruptedTemplate, requestTemplate]
    .map((source) => ({ source: source.source ?? `contract:${source.name}`, sourceSha256: source.sourceSha256 ?? source.sha256, servedSha256: source.servedSha256 ?? source.sha256 }));
  return Object.freeze({ base, repositoriesPath, runPath: `${base}/runs/${RUN}`, pollPath, jobId: JOB, runId: RUN, revisionId, repositoryId, operationId, requestBody,
    identity: Object.freeze({ schema: 'packaged-git-init-fixtures/v1', generator: readStates.identity.generator,
      generatorSha256: readStates.identity.generatorSha256, outputSha256: readStates.identity.outputSha256,
      bootstrapSha256: bootstrap.servedSha256, jobSha256: job.servedSha256, runSourceSha256: run.servedSha256,
      runServedSha256: initialRun.servedSha256, runPatch: initialRun.transformation,
      opaqueRequestIds: [...readStates.identity.opaqueRequestIds],
      jobId: JOB, runId: RUN, repositoryId, operationId, pollPath, repositoriesPath, runPath: `${base}/runs/${RUN}`,
      dashboardJobsSha256: dashboardJobs.servedSha256, dashboardRecoverySha256: dashboardRecovery.servedSha256,
      contracts: Object.fromEntries([repoTemplate, workspaceTemplate, completedTemplate, interruptedTemplate, requestTemplate].map((c) => [c.name, c.sha256])),
      requestBodySourceSha256: requestTemplate.sha256, requestBodySha256,
      sources: sources.map((x) => ({ ...x })), fixtureOnly: true }),
    scenario: (id) => scenarios.get(id),
    respond(id, method, path, ordinal = 0) {
      const s = scenarios.get(id); if (!s) return { unknown: true, reason: 'unknown-scenario' };
      if (method === 'GET' && path === `${API}/bootstrap`) return { entry: bootstrap };
      if (method === 'GET' && path === base) return { entry: job };
      if (method === 'GET' && path === this.runPath) return { entry: initialRun };
      if (method === 'GET' && path === this.repositoriesPath) return s.listings[ordinal] ? { entry: s.listings[ordinal] } : { unknown: true, reason: 'unexpected-repository-read' };
      if (method === 'GET' && path === this.pollPath) return s.poll ? { entry: s.poll } : { unknown: true, reason: 'unexpected-poll' };
      if (id === 'G9' && method === 'GET' && path === `${API}/jobs?limit=50`) return { entry: dashboardJobs };
      if (id === 'G9' && method === 'GET' && path === `${API}/recovery`) return { entry: dashboardRecovery };
      if (method === 'GET' && path === `${this.repositoriesPath}/${this.repositoryId}`) return s.workspace ? { entry: s.workspace } : { unknown: true, reason: 'unexpected-workspace-read' };
      if (method === 'POST' && path === this.repositoriesPath) return { entry: s.ack, write: true };
      return { unknown: true, reason: 'unmapped-route' };
    },
  });
}

export function createGitInitSection() {
  return { schema: 'packaged-git-init/v1', qualification: 'frontend-fixture-command-path', limits: { ...GIT_INIT_LIMITS },
    fixtureIdentity: null, cases: [], cleanup: [], failures: [], assessment: [], elapsedMs: 0 };
}

/** Recomputed semantic gate for a completed packaged command journey. */
export function assessGitInitReport(section) {
  const failures = [];
  const need = (ok, message) => { if (!ok) failures.push(message); };
  need(section?.schema === 'packaged-git-init/v1' && section?.qualification === 'frontend-fixture-command-path', 'schema or scope');
  need(section?.fixtureIdentity?.fixtureOnly === true && HEX64.test(String(section?.fixtureIdentity?.generatorSha256)) && HEX64.test(String(section?.fixtureIdentity?.outputSha256)), 'fixture provenance');
  need(Array.isArray(section?.cases) && section.cases.length === GIT_INIT_CASES.length, 'fixed case set');
  for (const expected of GIT_INIT_CASES) {
    const c = section.cases?.find((x) => x.id === expected.id);
    need(c?.status === 'observed', `${expected.id} missing observation`); if (!c) continue;
    const requests = c.requests ?? [];
    need(Array.isArray(c.errors) && c.errors.length === 0, `${expected.id} driver errors`);
    const posts = requests.filter((x) => x.method === 'POST');
    const polls = requests.filter((x) => x.method === 'GET' && x.path.includes('/operations/'));
    need(polls.every((x) => x.path === section?.fixtureIdentity?.pollPath), `${expected.id} poll path is not acknowledgement-bound`);
    const postIndex = requests.findIndex((x) => x.method === 'POST');
    const observedReadbacks = postIndex < 0 ? -1 : requests.slice(postIndex + 1).filter((x) => x.method === 'GET'
      && isCommandReadbackPath(x.path, section?.fixtureIdentity)).length;
    need(observedReadbacks === c.readbackCount, `${expected.id} readback ledger mismatch`);
    const initial = requests.slice(0, 4).map(({ method, path }) => [method, path]);
    const expectedInitialTail = [['GET', `${API}/jobs/${JOB}`], ['GET', `${API}/jobs/${JOB}/repositories`], ['GET', `${API}/jobs/${JOB}/runs/${RUN}`]];
    need(initial.length === 4 && JSON.stringify(initial[0]) === JSON.stringify(['GET', `${API}/bootstrap`])
      && JSON.stringify(initial.slice(1).sort((a, b) => a[1].localeCompare(b[1])))
        === JSON.stringify(expectedInitialTail.sort((a, b) => a[1].localeCompare(b[1]))), `${expected.id} initial packaged read wave`);
    need(c.nonGetCount === 1, `${expected.id} must have exactly one intercepted non-GET`);
    need(posts.length === 1 && posts[0].path.endsWith('/repositories') && posts[0].bodyBound === true && posts[0].bodySha256 === section?.fixtureIdentity?.requestBodySha256
      && posts[0].csrf === true && posts[0].contentType === true && posts[0].origin === true && posts[0].ifMatch === '"job_version_1"' && posts[0].idempotency === true, `${expected.id} POST binding`);
    need(c.clickTrusted === true, `${expected.id} command was not started by a trusted click`);
    need(!requests.some((x) => x.path === `${BASE}/session` || x.path.endsWith('/session') || x.path.toLowerCase().includes('csrf')), `${expected.id} exposed a credential exchange`);
    const mismatch = expected.id === 'G3' || expected.id === 'G4' || expected.id === 'G5' || expected.id === 'G6' || expected.id === 'G7' || expected.id === 'G8';
    if (mismatch) {
      need(c.state?.text === GIT_INIT_COPY.unverified, `${expected.id} fixed unverified copy`);
      need(c.state?.reference === canonicalReferenceFor(expected.id), `${expected.id} canonical reference`);
      need(c.state?.rawRequestIdAbsent === true, `${expected.id} withheld opaque ID`);
      need(polls.length === (expected.id === 'G6' || expected.id === 'G7' || expected.id === 'G8' ? 1 : 0), `${expected.id} poll count`);
      need(c.readbackCount === 0, `${expected.id} must not read back after mismatch`);
    } else if (expected.id === 'G1') {
      need(polls.length === 1 && c.readbackCount === 2, 'G1 success poll/readback counts');
      need(c.state?.text === GIT_INIT_COPY.repositoryRead, 'G1 successful repository state');
    } else if (expected.id === 'G2') {
      need(polls.length === 0 && c.readbackCount === 2, 'G2 terminal failure counts');
      need(c.state?.text === GIT_INIT_COPY.interrupted, 'G2 interrupted outcome copy');
    } else if (expected.id === 'G9') {
      const afterPost = postIndex < 0 ? [] : requests.slice(postIndex + 1);
      const dashboardReads = afterPost.filter((x) => x.method === 'GET' && [ `${API}/jobs?limit=50`, `${API}/recovery` ].includes(x.path));
      need(polls.length === 1 && polls[0]?.held === true && c.readbackCount === 0 && c.pollHeld === true && c.pollCancelled === true, 'G9 pending poll cancellation');
      need(dashboardReads.length === 2 && dashboardReads.some((x) => x.path === `${API}/jobs?limit=50`)
        && dashboardReads.some((x) => x.path === `${API}/recovery`), 'G9 destination request wave');
      need(c.reboundToHome === true && c.state?.text === GIT_INIT_COPY.noJobs && c.rebindClickTrusted === true, 'G9 trusted SPA rebind');
    }
    if (expected.id === 'G1' || expected.id === 'G2' || expected.id === 'G9') need(c.state?.reference === null, `${expected.id} must not display a request reference`);
  }
  need(section.cleanup?.length === GIT_INIT_CASES.length && section.cleanup.every((x) => x.fetchDisabled && x.cookieDeleted && x.closed && x.listener !== 'active'), 'target cleanup');
  need(section.failures?.length === 0 && section.assessment?.length === 0, 'driver failures or assessment');
  return failures.slice(0, 64);
}

const canonicalReferenceFor = (id) => ({ G3: '62800000-0000-4000-8000-000000000630', G4: '62800000-0000-4000-8000-000000000631', G5: '62800000-0000-4000-8000-000000000632', G6: '62800000-0000-4000-8000-000000000633', G7: '62800000-0000-4000-8000-000000000634', G8: '62800000-0000-4000-8000-000000000635' })[id] ?? null;

export async function verifyGitInitPng(root, screenshot) {
  if (!screenshot || !/^git-init-G[1-9]\.png$/.test(screenshot.name) || !Number.isSafeInteger(screenshot.bytes) || screenshot.bytes <= 0 || screenshot.bytes > GIT_INIT_LIMITS.pngBytes || !HEX64.test(String(screenshot.sha256))) throw new Error('invalid Git-init screenshot record');
  const path = join(root, screenshot.name); const handle = await fs.open(path, fsConstants.O_RDONLY | fsConstants.O_NOFOLLOW);
  let bytes; try { const stat = await handle.stat(); if (!stat.isFile() || stat.size !== screenshot.bytes) throw new Error(`${screenshot.name}: unsafe or mismatched file`); bytes = await handle.readFile(); }
  finally { await handle.close(); }
  if (sha256(bytes) !== screenshot.sha256) throw new Error(`${screenshot.name}: sha256 mismatch`);
  const dimensions = pngDimensions(bytes);
  if (dimensions.width !== screenshot.width || dimensions.height !== screenshot.height) throw new Error(`${screenshot.name}: PNG dimensions differ from its record`);
  return true;
}

const header = (headers, wanted) => Object.entries(headers ?? {}).find(([name]) => name.toLowerCase() === wanted.toLowerCase())?.[1] ?? null;
const isCommandReadbackPath = (path, fixtureIdentity) => path === fixtureIdentity?.repositoriesPath || path === fixtureIdentity?.runPath
  || (path.startsWith(`${fixtureIdentity?.repositoriesPath}/`) && !path.includes('/operations/'));
const bounded = (promise, label) => withDeadline(promise, GIT_INIT_LIMITS.callMs, label);

/** Runs one real packaged page per case. All API requests are intercepted at Request stage; unknowns are failed. */
export async function qualifyGitInitialization({ cdp, makeTarget, evaluate, delay, root, origin, section = createGitInitSection(), fixtures, cookie, now = Date.now, lateSink = [] }) {
  const started = now(); section.started = true; section.fixtureIdentity = fixtures.identity;
  if (!cookie || typeof cookie.name !== 'string' || typeof cookie.value !== 'string') throw new Error('synthetic cookie is required');
  section.precondition = { kind: 'Network.setCookie', name: cookie.name, valueSha256: sha256(cookie.value), path: `${BASE}/`, request: false };
  const rootRoute = `${origin}${API}/*`; const lateAcquisitions = [];
  for (const spec of GIT_INIT_CASES) {
    if (now() - started >= GIT_INIT_LIMITS.sectionMs) { section.failures.push('section deadline before next case'); break; }
    const caseStart = now(); const deadline = caseStart + GIT_INIT_LIMITS.caseMs;
    const record = { id: spec.id, status: 'failed', requests: [], nonGetCount: 0, readbackCount: 0, errors: [] };
    section.cases.push(record);
    let target = null; let handler = null; let loadFailedHandler = null; let phase = 'running'; let posts = 0; let repositoryReads = 0; let postSent = false;
    const held = new Map(); const pending = new Set(); let heldPollId = null;
    let resolvePollHeld; const pollHeldPromise = new Promise((resolve) => { resolvePollHeld = resolve; });
    const stillLive = () => { if (now() >= deadline) throw new Error(`${spec.id} case deadline`); };
    const addError = (message) => { if (record.errors.length < 8) record.errors.push(String(message).slice(0, CAP)); };
    try {
      stillLive();
      const acquiring = Promise.resolve().then(() => makeTarget());
      target = await bounded(acquiring, `${spec.id} target`).catch((error) => { lateAcquisitions.push({ id: spec.id, acquiring }); throw error; });
      const callCase = async (method, params, label = method) => {
      if (phase !== 'running' || now() >= deadline) throw new Error(`${spec.id} ${label} after cutoff`);
        const result = await bounded(cdp.call(method, params, target.sessionId), `${spec.id} ${label}`);
        if (phase !== 'running' || now() >= deadline) throw new Error(`${spec.id} ${label} completed after cutoff`);
        return result;
      };
      await callCase('Network.setCookie', { name: cookie.name, value: cookie.value, url: `${origin}${BASE}/`, path: `${BASE}/`, httpOnly: true, sameSite: 'Strict', secure: false }, 'set cookie');
      const { cookies } = await callCase('Network.getCookies', { urls: [`${origin}${BASE}/`] }, 'read cookie');
      const cookieMatches = (cookies ?? []).filter((x) => x.name === cookie.name);
      if (cookieMatches.length !== 1 || cookieMatches[0].path !== `${BASE}/` || cookieMatches[0].httpOnly !== true || cookieMatches[0].sameSite !== 'Strict'
        || cookieMatches[0].secure !== false || sha256(String(cookieMatches[0].value)) !== section.precondition.valueSha256) throw new Error(`${spec.id} cookie binding failed`);

      const refuse = (requestId, reason) => {
        const work = bounded(cdp.call('Fetch.failRequest', { requestId, errorReason: reason }, target.sessionId), `${spec.id} fail request`)
          .catch((error) => addError(`refuse: ${error?.message ?? error}`));
        pending.add(work); void work.finally(() => pending.delete(work));
      };
      loadFailedHandler = (event) => {
        if (event.requestId === heldPollId) {
          record.pollCancelled = event.canceled === true;
          if (record.pollCancelled) held.delete(event.requestId);
        }
      };
      cdp.on('Network.loadingFailed', loadFailedHandler, target.sessionId);
      const evalCase = async (expression, label) => {
        if (phase !== 'running' || now() >= deadline) throw new Error(`${spec.id} ${label} after cutoff`);
        const result = await bounded(evaluate(target, expression), `${spec.id} ${label}`);
        if (phase !== 'running' || now() >= deadline) throw new Error(`${spec.id} ${label} completed after cutoff`);
        return result;
      };
      const waitCase = async (expression, label) => {
        while (now() < deadline && phase === 'running') {
          if (await evalCase(`document.body !== null && (${expression})`, label)) return true;
          await delay(Math.min(100, Math.max(1, deadline - now())));
        }
        throw new Error(`${spec.id} ${label} deadline`);
      };
      handler = (event) => {
        if (phase !== 'running') {
          if (phase === 'cleaning') { addError('request arrived after case stop'); refuse(event.requestId, 'Aborted'); }
          else if (lateSink.length < 64) lateSink.push({ id: spec.id, kind: 'request-after-close' });
          return;
        }
        let url; try { url = new URL(event.request.url); } catch { refuse(event.requestId, 'Failed'); addError('invalid intercepted URL'); return; }
        if (url.origin !== origin || !url.pathname.startsWith(`${API}/`)) { refuse(event.requestId, 'Failed'); addError('non-API or foreign request intercepted'); return; }
        const method = String(event.request.method); const path = url.pathname + url.search;
        let postMeta = null;
        if (method === 'POST') {
          posts++; record.nonGetCount++;
          const rawPostData = Buffer.from(event.request.postData ?? '');
          let parsed; try { parsed = JSON.parse(rawPostData.toString('utf8')); } catch { parsed = null; }
          const headers = event.request.headers ?? {};
          const csrf = typeof header(headers, 'X-CSRF-Token') === 'string' && /^[A-Za-z0-9_-]{32,256}$/.test(header(headers, 'X-CSRF-Token'));
          const contentType = String(header(headers, 'Content-Type') ?? '').split(';')[0].toLowerCase() === 'application/json';
          const requestOrigin = header(headers, 'Origin');
          const requestBodyBound = rawPostData.equals(fixtures.requestBody)
            && isDeepStrictEqual(parsed, JSON.parse(fixtures.requestBody.toString('utf8')));
          const idempotency = typeof header(headers, 'Idempotency-Key') === 'string' && /^[A-Za-z0-9_-]{16,128}$/.test(header(headers, 'Idempotency-Key'));
          postMeta = { bodySha256: rawPostData.length ? sha256(rawPostData) : null, bodyBound: requestBodyBound, csrf, contentType, origin: requestOrigin === origin,
            ifMatch: header(headers, 'If-Match'), idempotency };
          if (posts !== 1 || path !== fixtures.repositoriesPath || !requestBodyBound || !csrf || !contentType || postMeta.origin !== true || postMeta.ifMatch !== '"job_version_1"' || !idempotency) {
            refuse(event.requestId, 'Failed'); addError('POST did not match the one bound git.init command'); return;
          }
          postSent = true;
        } else if (method !== 'GET') {
          record.nonGetCount++; refuse(event.requestId, 'Failed'); addError(`unexpected non-GET ${method}`); return;
        }
        const ordinal = method === 'GET' && path === fixtures.repositoriesPath ? repositoryReads++ : 0;
        const response = fixtures.respond(spec.id, method, path, ordinal);
        const item = { method, path, status: response.entry?.status ?? null, source: response.entry?.source ?? null,
          sourceSha256: response.entry?.sourceSha256 ?? null, servedSha256: response.entry?.servedSha256 ?? null,
          bytes: response.entry?.bytes ?? null, ...(postMeta ?? {}) };
        if (postSent && method === 'GET' && isCommandReadbackPath(path, fixtures)) record.readbackCount++;
        record.requests.push(item);
        if (record.requests.length > 32 || response.unknown || !response.entry) { refuse(event.requestId, 'Failed'); addError(`unmapped request ${method} ${path}`); return; }
        if (spec.id === 'G9' && method === 'GET' && path === fixtures.pollPath) {
          item.held = true; record.pollHeld = true; heldPollId = event.requestId;
          held.set(event.requestId, { entry: item }); resolvePollHeld(event.requestId); return;
        }
        const work = Promise.resolve().then(() => {
          if (phase !== 'running' || now() >= deadline) throw new Error('fulfil after cutoff');
          const body = response.entry.body;
          if (sha256(body) !== response.entry.servedSha256 || body.length !== response.entry.bytes) throw new Error('fixture changed after bind');
          const encoded = body.toString('base64');
          return bounded(cdp.call('Fetch.fulfillRequest', { requestId: event.requestId, responseCode: response.entry.status, body: encoded,
            responseHeaders: [{ name: 'Content-Type', value: 'application/json' }, { name: 'Cache-Control', value: 'no-store' }, { name: 'X-Request-ID', value: response.entry.requestId }] }, target.sessionId), `${spec.id} fulfill`);
        }).catch((error) => addError(`fulfil: ${error?.message ?? error}`));
        pending.add(work); void work.finally(() => pending.delete(work));
      };
      cdp.on('Fetch.requestPaused', handler, target.sessionId);
      await callCase('Fetch.enable', { patterns: [{ urlPattern: rootRoute, requestStage: 'Request' }] }, 'Fetch.enable');
      await callCase('Page.navigate', { url: `${origin}${BASE}/jobs/${fixtures.jobId}` }, 'navigate');
      const buttonReady = `(() => { const b=[...document.querySelectorAll('button')].find(x=>x.textContent.trim()===${JSON.stringify(GIT_INIT_COPY.initialize)}); return !!b && !b.disabled; })()`;
      await waitCase(buttonReady, 'initialization available');
      // Read wave and session exchange settle before the sole trusted click.
      await delay(200);
      await evalCase(`(() => { window.__gitInitClickLog=[]; window.__gitInitNavLog=[]; document.addEventListener('click', e=>{const b=e.target.closest?.('button'); if(b&&b.closest('.git-repository'))window.__gitInitClickLog.push({trusted:e.isTrusted,text:b.textContent.trim()}); const a=e.target.closest?.('a'); if(a)window.__gitInitNavLog.push({trusted:e.isTrusted,text:a.textContent.trim()})},true); return true })()`, 'click recorder');
      const before = await evalCase(`(() => ({ status: document.querySelector('.git-repository [role="status"]')?.textContent.trim() ?? '', button: [...document.querySelectorAll('.git-repository button')].some(x=>x.textContent.trim()===${JSON.stringify(GIT_INIT_COPY.initialize)}), sessionRequests: performance.getEntriesByType('resource').filter(x=>x.name.includes('/session')).length }))()`, 'precondition');
      if (!before.button || before.sessionRequests !== 0) throw new Error(`${spec.id} precondition: no candidate button or session exchange`);
      const rect = await evalCase(`(() => { const b=[...document.querySelectorAll('.git-repository button')].find(x=>x.textContent.trim()===${JSON.stringify(GIT_INIT_COPY.initialize)}); if(!b||b.disabled)return null; b.scrollIntoView({block:'center'}); const r=b.getBoundingClientRect(); return {x:r.left+r.width/2,y:r.top+r.height/2,visible:r.width>0&&r.height>0&&r.top>=0&&r.bottom<=innerHeight}; })()`, 'button coordinates');
      if (!rect || !rect.visible || !Number.isFinite(rect.x) || !Number.isFinite(rect.y)) throw new Error(`${spec.id} button coordinates unavailable`);
      await callCase('Input.dispatchMouseEvent', { type: 'mouseMoved', x: rect.x, y: rect.y }, 'mouse move');
      await callCase('Input.dispatchMouseEvent', { type: 'mousePressed', x: rect.x, y: rect.y, button: 'left', clickCount: 1 }, 'mouse press');
      await callCase('Input.dispatchMouseEvent', { type: 'mouseReleased', x: rect.x, y: rect.y, button: 'left', clickCount: 1 }, 'mouse release');
      if (spec.id === 'G9') {
        const requestId = await bounded(pollHeldPromise, 'G9 held poll');
        if (!requestId) throw new Error('G9 poll was not held');
        const nav = await evalCase(`(() => { const a=[...document.querySelectorAll('a')].find(x=>x.textContent.trim()==='All jobs'); if(!a)return null; a.scrollIntoView({block:'center'}); const r=a.getBoundingClientRect(); return {x:r.left+r.width/2,y:r.top+r.height/2,visible:r.width>0&&r.height>0&&r.top>=0&&r.bottom<=innerHeight}; })()`, 'rebind link coordinates');
        if (!nav?.visible) throw new Error('G9 All jobs link is not visible');
        await callCase('Input.dispatchMouseEvent', { type: 'mouseMoved', x: nav.x, y: nav.y }, 'rebind mouse move');
        await callCase('Input.dispatchMouseEvent', { type: 'mousePressed', x: nav.x, y: nav.y, button: 'left', clickCount: 1 }, 'rebind mouse press');
        await callCase('Input.dispatchMouseEvent', { type: 'mouseReleased', x: nav.x, y: nav.y, button: 'left', clickCount: 1 }, 'rebind mouse release');
        await waitCase(`location.pathname === ${JSON.stringify(`${BASE}/`)} && document.body.innerText.includes(${JSON.stringify(GIT_INIT_COPY.noJobs)})`, 'home route rebind');
        record.reboundToHome = true;
        const cancelUntil = Math.min(deadline, now() + 1_000);
        while (!record.pollCancelled && now() < cancelUntil) await delay(Math.min(20, Math.max(1, cancelUntil - now())));
        if (record.pollCancelled !== true) throw new Error('G9 did not observe the browser cancelling the held poll');
      }
      const expectedText = spec.id === 'G1' ? GIT_INIT_COPY.repositoryRead : spec.id === 'G2' ? GIT_INIT_COPY.interrupted : spec.id === 'G9' ? GIT_INIT_COPY.noJobs : GIT_INIT_COPY.unverified;
      if (spec.id !== 'G9') await waitCase(`document.querySelector('.git-repository [role="status"]')?.textContent.trim() === ${JSON.stringify(expectedText)}`, 'outcome');
      await bounded(Promise.allSettled([...pending]), `${spec.id} request settlement`);
      const opaque = fixtures.identity.opaqueRequestIds;
      const state = await evalCase(`(() => { const text=document.body.innerText; const status=${spec.id === 'G9' ? 'text.includes(' + JSON.stringify(GIT_INIT_COPY.noJobs) + ') ? ' + JSON.stringify(GIT_INIT_COPY.noJobs) + ' : ""' : 'document.querySelector(\'.git-repository [role="status"]\')?.textContent.trim() ?? ""'}; return {text:status,rawRequestIdAbsent:${JSON.stringify(opaque)}.every(x=>!text.includes(x)),clickTrusted:window.__gitInitClickLog?.filter(x=>x.text===${JSON.stringify(GIT_INIT_COPY.initialize)}).length===1&&window.__gitInitClickLog.find(x=>x.text===${JSON.stringify(GIT_INIT_COPY.initialize)})?.trusted===true,rebindClickTrusted:${spec.id === 'G9' ? 'window.__gitInitNavLog?.some(x=>x.text==="All jobs"&&x.trusted===true)' : 'false'},reference:(status.match(/[0-9a-f]{8}-[0-9a-f]{4}-[1-8][0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}/)||[])[0]??null}; })()`, 'state projection');
      if (state.text !== expectedText || !state.rawRequestIdAbsent) throw new Error(`${spec.id} rendered an unexpected or opaque response identity: ${JSON.stringify(state)}`);
      if (spec.id.startsWith('G3') || spec.id === 'G4' || spec.id === 'G5' || spec.id.startsWith('G6') || spec.id === 'G7' || spec.id === 'G8') {
        if (state.reference !== canonicalReferenceFor(spec.id)) throw new Error(`${spec.id} vetted reference missing`);
      } else if (state.reference !== null) throw new Error(`${spec.id} unexpectedly disclosed a request reference`);
      const shot = await callCase('Page.captureScreenshot', { format: 'png', captureBeyondViewport: false }, 'screenshot');
      const png = Buffer.from(shot.data, 'base64');
      if (png.length === 0 || png.length > GIT_INIT_LIMITS.pngBytes) throw new Error(`${spec.id} screenshot size`);
      const dims = pngDimensions(png); const name = `git-init-${spec.id}.png`;
      if (phase !== 'running' || now() >= deadline) throw new Error(`${spec.id} screenshot write after cutoff`);
      await bounded(fs.writeFile(join(root, name), png, { flag: 'wx' }), `${spec.id} screenshot write`);
      if (phase !== 'running' || now() >= deadline) throw new Error(`${spec.id} screenshot write completed after cutoff`);
      record.state = { ...state }; record.clickTrusted = state.clickTrusted; record.rebindClickTrusted = state.rebindClickTrusted;
      record.screenshot = { name, bytes: png.length, sha256: sha256(png), ...dims };
      record.status = 'observed';
    } catch (error) { addError(error?.message ?? error); section.failures.push(`${spec.id}: ${record.errors[0] ?? 'failed'}`); }
    finally {
      phase = 'cleaning';
      if (target) {
        for (const [requestId] of held) { try { await bounded(cdp.call('Fetch.failRequest', { requestId, errorReason: 'Aborted' }, target.sessionId), `${spec.id} abort held`); } catch (error) { addError(`held cleanup: ${error?.message ?? error}`); } }
        held.clear();
        try { await bounded(Promise.allSettled([...pending]), `${spec.id} settle pending`); } catch (error) { addError(`pending cleanup: ${error?.message ?? error}`); }
        let fetchDisabled = false; try { await bounded(cdp.call('Fetch.disable', {}, target.sessionId), `${spec.id} Fetch.disable`); fetchDisabled = true; } catch (error) { addError(`Fetch.disable: ${error?.message ?? error}`); }
        let cookieDeleted = false; try { await bounded(cdp.call('Network.deleteCookies', { name: cookie.name, url: `${origin}${BASE}/` }, target.sessionId), `${spec.id} delete cookie`); cookieDeleted = true; } catch (error) { addError(`cookie cleanup: ${error?.message ?? error}`); }
        if (handler && typeof cdp.off === 'function') cdp.off('Fetch.requestPaused', handler, target.sessionId);
        if (loadFailedHandler && typeof cdp.off === 'function') cdp.off('Network.loadingFailed', loadFailedHandler, target.sessionId);
        phase = 'closed';
        let closed = false; try { await bounded(cdp.call('Target.closeTarget', { targetId: target.targetId }), `${spec.id} close`); closed = true; } catch (error) { addError(`close: ${error?.message ?? error}`); }
        section.cleanup.push({ id: spec.id, fetchDisabled, cookieDeleted, listener: handler ? (typeof cdp.off === 'function' ? 'removed' : 'inert') : 'none', closed });
      }
    }
    if (now() - started >= GIT_INIT_LIMITS.sectionMs) { section.failures.push('section deadline'); break; }
  }
  for (const acquisition of lateAcquisitions) {
    try {
      const late = await bounded(acquisition.acquiring, `${acquisition.id} late target acquisition`);
      lateSink.push({ id: acquisition.id, kind: 'target-acquired-after-cutoff', targetId: late?.targetId ?? null });
    } catch (error) {
      lateSink.push({ id: acquisition.id, kind: 'target-unresolved', detail: String(error?.message ?? error).slice(0, CAP) });
      void acquisition.acquiring.then((late) => { if (lateSink.length < 64) lateSink.push({ id: acquisition.id, kind: 'target-acquired-after-cutoff', targetId: late?.targetId ?? null }); }).catch(() => undefined);
    }
  }
  section.elapsedMs = Math.max(0, now() - started);
  section.assessment = assessGitInitReport(section);
  if (Buffer.byteLength(JSON.stringify(section)) > GIT_INIT_LIMITS.bytes) section.assessment.push('section exceeds 48 KiB');
  if (section.assessment.length) section.failures.push(...section.assessment);
  return section;
}

export const gitInitInternals = Object.freeze({ sha256, UUID, CAP, withDeadline });
