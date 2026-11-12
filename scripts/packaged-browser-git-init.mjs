import assert from 'node:assert/strict';
import { readFileSync } from 'node:fs';
import { join } from 'node:path';

/** Exercise the packaged job page's Git command with authenticated, schema-valid API fixtures. */
export async function qualifyGitInitIdentity({ repo, origin, makeTarget, cdp, evaluate, ready }) {
  const fixture = (name) => JSON.parse(readFileSync(join(repo, 'contracts/web/v1/fixtures', name + '.json'), 'utf8'));
  const jobId = 'c'.repeat(32);
  const runId = 'run_packaged_git_init';
  const repositoryId = 'repository_packaged_git_init';
  const operationId = 'operation_packaged_git_init';
  async function runCase(mismatch) {
    const job = fixture('job-lossless');
    Object.assign(job.data, { jobId, latestRunId: runId, version: 'job_version_packaged_git_init' });
    const run = fixture('run-completed-unaccepted');
    Object.assign(run.data, { jobId, runId, resultRevisionId: 'revision_packaged_git_init' });
    const repositories = fixture('git-repositories');
    const repositorySummary = repositories.data.repositories[0];
    Object.assign(repositorySummary, { repositoryId, worktreeId: 'worktree_packaged_git_init', operationId, runId,
      candidateRevisionId: run.data.resultRevisionId });
    Object.assign(repositories.data, { jobId, repositories: [], operations: [] });
    const acknowledgement = fixture('git-operation');
    Object.assign(acknowledgement.data, { operationId, jobId, repositoryId,
      worktreeId: 'worktree_packaged_git_init', action: 'git.init', state: 'queued', recoveryRequired: false,
      endedAt: null, resultObjectId: null, message: null });
    const completed = structuredClone(acknowledgement);
    Object.assign(completed.data, { state: 'completed', endedAt: '2026-11-13T00:00:01Z', message: null });
    const workspace = fixture('git-workspace');
    Object.assign(workspace.data, { repositoryId, worktreeId: 'worktree_packaged_git_init',
      candidateRevisionId: run.data.resultRevisionId, headRefName: 'refs/heads/packaged-init' });

    const tab = await makeTarget();
    const prefix = '/nested/api/v1/jobs/' + jobId;
    const requests = [];
    const unexpected = [];
    const errors = [];
    let fetchEnabled = false;
    let primaryFailure = null;
    try {
    const source = [
      '(() => {',
      'let csrf = null;',
      'const original = window.fetch;',
      'window.fetch = function(input, options) {',
      'const url = new URL(typeof input === "string" ? input : input.url, location.href);',
      'const response = original.apply(this, arguments);',
      'if (url.pathname.endsWith("/api/v1/session") || url.pathname.endsWith("/api/v1/bootstrap")) {',
      'return response.then(async result => {',
      'const document = await result.clone().json();',
      'if (typeof document.data?.csrfToken === "string") csrf = document.data.csrfToken;',
      'return result;',
      '});',
      '}',
      'return response;',
      '};',
      'Object.defineProperty(window, "__packagedGitInitMatchesCsrf", { value: token => typeof csrf === "string" && token === csrf });',
      '})();',
    ].join('\n');
    await cdp.call('Page.addScriptToEvaluateOnNewDocument', { source }, tab.sessionId);
    cdp.on('Fetch.requestPaused', (event) => {
      const pathname = new URL(event.request.url).pathname;
      const method = event.request.method;
      const headers = Object.fromEntries(Object.entries(event.request.headers ?? {}).map(([name, value]) => [name.toLowerCase(), value]));
      requests.push({ method, pathname, headers, body: event.request.postData ?? null });
      let document = null;
      let status = 200;
      if (method === 'GET' && pathname === prefix) document = job;
      else if (method === 'GET' && pathname === prefix + '/repositories') {
        document = structuredClone(repositories);
        if (!mismatch && requests.filter((request) => request.method === 'GET' && request.pathname === prefix + '/repositories').length > 1) {
          document.data.repositories = [repositorySummary];
          document.data.operations = [completed.data];
        }
      } else if (method === 'GET' && pathname === prefix + '/runs/' + runId) document = run;
      else if (method === 'POST' && pathname === prefix + '/repositories') {
        document = structuredClone(acknowledgement);
        if (mismatch) document.data.jobId = 'd'.repeat(32);
        status = 202;
      } else if (!mismatch && method === 'GET' && pathname === prefix + '/repositories/' + repositoryId + '/operations/' + operationId) {
        document = completed;
      } else if (!mismatch && method === 'GET' && pathname === prefix + '/repositories/' + repositoryId) {
        document = workspace;
      } else unexpected.push(method + ' ' + pathname);
      if (!document) {
        void cdp.call('Fetch.continueRequest', { requestId: event.requestId }, tab.sessionId).catch((error) => errors.push(String(error)));
        return;
      }
      void cdp.call('Fetch.fulfillRequest', { requestId: event.requestId, responseCode: status,
        responseHeaders: [{ name: 'Content-Type', value: 'application/json; charset=utf-8' },
          { name: 'X-Request-ID', value: document.requestId }],
        body: Buffer.from(JSON.stringify(document)).toString('base64') }, tab.sessionId)
        .catch((error) => errors.push(String(error)));
    }, tab.sessionId);
    fetchEnabled = true;
    await cdp.call('Fetch.enable', { patterns: [{ urlPattern: origin + prefix + '*', requestStage: 'Request' }] }, tab.sessionId);
    await cdp.call('Page.navigate', { url: origin + '/nested/jobs/' + jobId }, tab.sessionId);
    const button = "[...document.querySelectorAll('.git-repository button')].find(button => button.textContent.trim() === 'Initialize repository from the latest candidate')";
    await ready(tab, '!!' + button, 'packaged Git initialization control');
    await evaluate(tab, button + '.click()');
    if (mismatch) {
      await ready(tab, "document.body.innerText.includes('The initialization could not be confirmed.') && [...document.querySelectorAll('.git-repository button')].every(button => !button.disabled)",
        'refused mismatched acknowledgement and settled command');
    } else {
      await ready(tab, "document.body.innerText.includes('Branch packaged-init') && [...document.querySelectorAll('.git-repository button')].every(button => !button.disabled)",
        'successful packaged initialization readback');
    }
    const post = requests.filter((request) => request.method === 'POST');
    assert.equal(post.length, 1, 'One explicit click must issue exactly one initialization POST');
    assert.equal(post[0].pathname, prefix + '/repositories');
    assert.equal(await evaluate(tab, 'window.__packagedGitInitMatchesCsrf(' + JSON.stringify(post[0].headers['x-csrf-token'] ?? '') + ')'), true,
      'Packaged command must retain the authenticated session CSRF token');
    assert.equal(post[0].headers['if-match'], '"job_version_packaged_git_init"');
    assert.match(post[0].headers['idempotency-key'] ?? '', /^[A-Za-z0-9_-]{16,128}$/);
    assert.deepEqual(JSON.parse(post[0].body ?? '{}'), { action: 'git.init', runId,
      revisionId: run.data.resultRevisionId, initialBranch: null });
    if (mismatch) {
      assert.equal(requests.filter((request) => request.pathname.includes('/operations/')).length, 0,
        'A mismatched acknowledgement must not trigger an operation poll');
      assert.equal(requests.filter((request) => request.method === 'GET' && request.pathname.startsWith(prefix + '/repositories/')).length, 0,
        'A mismatched acknowledgement must not trigger repository readback');
      assert.deepEqual(requests.map((request) => request.method + ' ' + request.pathname), [
        'GET ' + prefix, 'GET ' + prefix + '/repositories', 'GET ' + prefix + '/runs/' + runId, 'POST ' + prefix + '/repositories',
      ]);
    } else {
      assert.deepEqual(requests.map((request) => request.method + ' ' + request.pathname), [
        'GET ' + prefix, 'GET ' + prefix + '/repositories', 'GET ' + prefix + '/runs/' + runId, 'POST ' + prefix + '/repositories',
        'GET ' + prefix + '/repositories/' + repositoryId + '/operations/' + operationId,
        'GET ' + prefix + '/repositories', 'GET ' + prefix + '/repositories/' + repositoryId,
      ]);
    }
    assert.deepEqual(unexpected, [], 'Every API request for the synthetic job must receive an explicit fixture');
    assert.deepEqual(errors, []);
    assert.deepEqual(tab.exceptions, []);
    return mismatch
      ? { mismatchedAcknowledgementRefused: true, operationPolls: 0, repositoryReadbacks: 0, initializationPosts: 1 }
      : { matchingAcknowledgementCompleted: true, operationPolls: 1, repositoryReadbacks: 1, initializationPosts: 1 };
    } catch (failure) {
      primaryFailure = failure;
      throw failure;
    } finally {
      const cleanupFailures = [];
      if (fetchEnabled) await cdp.call('Fetch.disable', {}, tab.sessionId).catch((failure) => cleanupFailures.push(String(failure)));
      await cdp.call('Target.closeTarget', { targetId: tab.targetId }).catch((failure) => cleanupFailures.push(String(failure)));
      if (cleanupFailures.length) {
        const detail = 'Packaged Git identity test cleanup failed: ' + cleanupFailures.join('; ');
        if (primaryFailure instanceof Error) primaryFailure.message += '\n' + detail;
        else throw new Error(detail);
      }
    }
  }
  const refused = await runCase(true);
  const accepted = await runCase(false);
  return { packagedJobRoute: true, authenticatedFixtureApi: true, ...refused, ...accepted,
    csrfMatchesSession: true, ifMatch: true, idempotencyKey: true, noAutomaticRetry: true };
}
