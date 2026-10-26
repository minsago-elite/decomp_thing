import { fireEvent, render, screen, waitFor, within } from '@testing-library/preact';
import { beforeEach, expect, it, vi } from 'vitest';
import type * as ClientModule from '../src/api/client';
import { ApiClientError } from '../src/api/client';
import type { Capability } from '../src/api/generated';
import { GitWorkspace } from '../src/git/GitWorkspace';

const transport = vi.hoisted(() => ({
  get: vi.fn<(kind: string, path: string, settings?: { signal?: AbortSignal }) => Promise<unknown>>(),
  post: vi.fn<(kind: string, path: string, request: string, data: unknown, settings: { csrfToken: string; ifMatch: string; idempotencyKey: string; signal?: AbortSignal }) => Promise<unknown>>(),
}));
vi.mock('../src/api/client', async load => ({ ...await load<typeof ClientModule>(), createApiClient: () => transport }));

const jobId = '0123456789abcdef0123456789abcdef';
const repositoryId = 'repository_' + '1'.repeat(32);
const worktreeId = 'worktree_' + '2'.repeat(32);
const linkedId = 'worktree_' + '3'.repeat(32);
const head = 'a'.repeat(40), older = 'b'.repeat(40), other = 'c'.repeat(40);
const base = `/jobs/${jobId}/repositories/${repositoryId}`;
const session = { csrf: () => 'a'.repeat(43) };
const capability = (id: string, state: Capability['state'], message: string | null = null, reasonCode: string | null = null): Capability =>
  ({ id, state, reasonCode, message, workflows: [], agentContractVersion: null, limits: null });
const supported = [capability('git', 'supported'), capability('git-import', 'supported')];

const repository = { repositoryId, worktreeId, operationId: 'operation_0', origin: 'initialized', objectFormat: 'sha1',
  trackingPolicy: 'source-only-v1', createdAt: '2026-10-25T00:00:00Z', runId: 'run_1', candidateRevisionId: 'revision_1' };
const entry = (fileId: string, path: string, staged: string, unstaged: string, untracked = false) =>
  ({ fileId, path, pathEscaped: false, originalPath: null, staged, unstaged, untracked, ignored: false, conflict: null, submodule: false });
const mapping = { repositoryId, objectId: older, revisionId: 'revision_1', sourceSha256: 'd'.repeat(64), archiveArtifactId: null,
  acceptance: 'accepted', acceptanceArtifactId: 'artifact_1' };
const commitSummary = (objectId: string, subject: string, mapped: boolean) => ({ objectId, parentObjectIds: [], authorName: 'Workbench',
  authorEmail: 'workbench@localhost', authoredAt: '2026-10-25T00:00:00Z', committedAt: '2026-10-25T00:00:00Z', subject,
  subjectTruncated: false, mapping: mapped ? mapping : null });
const operation = (state: string, action = 'git.stage') => ({ data: { operationId: 'operation_1', jobId, repositoryId, worktreeId, action, state,
  version: 'operation_v1', createdAt: '2026-10-25T00:00:00Z', endedAt: null, resultObjectId: null, recoveryRequired: false,
  message: state === 'completed' ? 'Done.' : 'Queued.' } });

let entries: unknown[];
let historyPages: Record<string, { entries: unknown[]; nextCursor: string | null }>;
let listing: unknown[];
let paged: boolean;
let provenanceFails = false;
let jobFails = false;

function status(dirty: boolean) {
  return { repositoryId, worktreeId, repositoryVersion: 'repo_v1', worktreeVersion: 'tree_v1', headState: 'attached', headObjectId: head,
    headRefName: 'refs/heads/main', busy: false, complete: true,
    counts: { staged: 0, unstaged: 0, untracked: 0, ignored: 2, conflicted: 0 },
    notices: [{ code: dirty ? 'dirty' : 'clean', message: dirty ? 'The work tree has changes.' : 'The work tree is clean.' }], entries, nextCursor: null };
}

let historyGate: Promise<void> | null = null;
let unstagedDiffGate: Promise<void> | null = null;

function serve(kind: string, path: string): Promise<unknown> {
  if (unstagedDiffGate && path.includes('scope=unstaged')) { const gate = unstagedDiffGate; unstagedDiffGate = null; return gate.then(() => serve(kind, path)); }
  if (historyGate && path.includes('/history?cursor=')) { const gate = historyGate; historyGate = null; return gate.then(() => serve(kind, path)); }
  const [route = '', query = ''] = path.split('?');
  let data: unknown;
  try { data = (() => {
    if (route === `/jobs/${jobId}/repositories`) return { jobId, repositories: listing, operations: [] };
    if (route === `${base}/status`) {
      const cursor = new URLSearchParams(query).get('cursor');
      const all = status(entries.length > 0);
      if (!paged) return all;
      // Second page holds the remaining entries; the first page names its anchored cursor.
      return cursor === 'status_page_2' ? { ...all, entries: entries.slice(1), nextCursor: null }
        : { ...all, entries: entries.slice(0, 1), nextCursor: 'status_page_2' };
    }
    if (route === `${base}/worktrees`) return { repositoryId, worktrees: [
      { worktreeId, primary: true, ownerRunId: null, worktreeVersion: 'tree_v1', headState: 'attached', headObjectId: head, headRefName: 'refs/heads/main', dirty: entries.length > 0 },
      { worktreeId: linkedId, primary: false, ownerRunId: 'run_2', worktreeVersion: 'tree_v2', headState: 'detached', headObjectId: older, headRefName: null, dirty: false },
    ] };
    if (route === `${base}/refs`) {
      const main = { refId: 'ref_main', kind: 'branch', displayName: 'refs/heads/main', objectId: head, peeledObjectId: null, version: 'v1', current: true };
      const topic = { refId: 'ref_topic', kind: 'branch', displayName: 'refs/heads/topic', objectId: other, peeledObjectId: null, version: 'v2', current: false };
      if (new URLSearchParams(query).get('cursor') === 'refs_page_2') return { repositoryId, nextCursor: null, refs: [topic] };
      return paged ? { repositoryId, nextCursor: 'refs_page_2', refs: [main] } : { repositoryId, nextCursor: null, refs: [main, topic] };
    }
    if (route === `${base}/history`) {
      const page = historyPages[new URLSearchParams(query).get('cursor') ?? 'first'];
      if (!page) throw new ApiClientError('http_error', { status: 409 });
      return { repositoryId, worktreeId, startObjectId: head, ...page };
    }
    if (route === `${base}/diff`) {
      const params = new URLSearchParams(query);
      if (params.get('scope') === 'commit') {
        const file = (fileId: string, path: string) => ({ fileId, path, pathEscaped: false, originalPath: null,
          change: 'added', oldObjectId: null, newObjectId: other, oldMode: '000000', newMode: '100644', binary: false, additions: 3, deletions: 0, newSizeBytes: 40 });
        const second = params.get('cursor') === 'diff_page_2';
        return { repositoryId, worktreeId, scope: 'commit', commitObjectId: params.get('commit'), parentObjectId: null, complete: true, patch: null,
          nextCursor: paged && !second ? 'diff_page_2' : null, files: second ? [file('file_d', 'src/second.c')] : [file('file_c', 'src/main.c')] };
      }
      return { repositoryId, worktreeId, scope: params.get('scope'), commitObjectId: null, parentObjectId: head, complete: true, nextCursor: null,
        files: [{ fileId: params.get('file'), path: 'src/util.c', pathEscaped: false, originalPath: null, change: 'modified', oldObjectId: older,
          newObjectId: other, oldMode: '100644', newMode: '100644', binary: false, additions: 1, deletions: 1, newSizeBytes: 12 }],
        patch: { fileId: params.get('file'), text: '@@ -1 +1 @@\n-int a;\n+int b;\n', truncated: false, binary: false } };
    }
    if (route === `${base}/provenance/${older}` && provenanceFails) throw new ApiClientError('http_error', { status: 422 });
    if (route === `/jobs/${jobId}` && jobFails) throw new ApiClientError('timeout');
    if (route === `${base}/provenance/${older}`) return { repositoryId, objectId: older, objectFormat: 'sha1', committedAt: '2026-10-25T00:00:00Z',
      subject: 'Record candidate', refNames: ['refs/tags/v1'], mapping, worktreeDirtyAtCommit: false,
      export: { sha256: 'e'.repeat(64), sizeBytes: 512, files: 1, skippedEntries: 0, verification: 'tree-blob-ids-match' } };
    if (route.startsWith(`${base}/operations/`)) return operation('completed').data;
    if (route === `/jobs/${jobId}`) return { jobId, version: 'job_v3' };
    if (route.startsWith(`/jobs/${jobId}/repositories/`) && route.includes('/operations/')) return operation('completed', 'git.attach').data;
    throw new Error(`unexpected ${kind} ${path}`);
  })(); } catch (failure: unknown) { return Promise.reject(failure instanceof Error ? failure : new Error(String(failure))); }
  return Promise.resolve({ data });
}

beforeEach(() => {
  transport.get.mockReset(); transport.post.mockReset();
  transport.get.mockImplementation(serve);
  listing = [repository];
  paged = false;
  provenanceFails = false;
  jobFails = false;
  historyGate = null;
  unstagedDiffGate = null;
  entries = [entry('file_s', 'src/util.c', 'modified', 'modified'), entry('file_u', 'src/new.c', 'none', 'none', true)];
  historyPages = { first: { entries: [commitSummary(head, 'Work in progress', false)], nextCursor: 'page2' },
    page2: { entries: [commitSummary(older, 'Record candidate', true)], nextCursor: null } };
});

function mount(capabilities: Capability[] = supported) {
  return render(<GitWorkspace jobId={jobId} basePath="/nested/" session={session} capabilities={capabilities} pollIntervalMs={1} />);
}

function deferred() {
  let resolve = () => {};
  const promise = new Promise<void>(done => { resolve = done; });
  return { promise, resolve };
}

it.each(['diff', 'provenance'])('keeps the latest inspection and tag draft when an older %s answers late', async delayed => {
  const gate = deferred();
  historyPages.first = { entries: [commitSummary(head, 'Newest', false), commitSummary(older, 'Previous', true)], nextCursor: null };
  transport.get.mockImplementation(async (kind, path) => {
    if (path === `${base}/provenance/${head}`) {
      if (delayed === 'provenance') await gate.promise;
      return serve(kind, `${base}/provenance/${older}`);
    }
    if (delayed === 'diff' && path.includes(`commit=${head}`)) await gate.promise;
    return serve(kind, path);
  });
  transport.post.mockResolvedValueOnce(operation('completed', 'git.tag'));
  mount();
  fireEvent.click(await screen.findByRole('button', { name: `Inspect ${head.slice(0, 12)}` }));
  fireEvent.click(screen.getByRole('button', { name: `Inspect ${older.slice(0, 12)}` }));
  await screen.findByRole('heading', { name: `Commit ${older.slice(0, 12)}` });
  fireEvent.input(screen.getByLabelText('Tag name'), { target: { value: 'reviewed-target' } });
  gate.resolve();
  await new Promise(resolve => setTimeout(resolve, 20));
  expect(screen.queryByRole('heading', { name: `Commit ${head.slice(0, 12)}` })).toBeNull();
  expect(screen.getByLabelText('Tag name')).toHaveProperty('value', 'reviewed-target');
  expect(screen.getByRole('link', { name: 'Download source export' }).getAttribute('href')).toContain(`/exports/${older}`);
  fireEvent.click(screen.getByRole('button', { name: 'Tag this commit' }));
  await waitFor(() => expect(transport.post).toHaveBeenCalledOnce());
  expect(transport.post.mock.calls[0]?.[3]).toMatchObject({ name: 'reviewed-target', targetObjectId: older });
});

it('ignores an obsolete inspection failure and resets a tag draft on a deliberate target change', async () => {
  const gate = deferred();
  historyPages.first = { entries: [commitSummary(head, 'Newest', false), commitSummary(older, 'Previous', true)], nextCursor: null };
  transport.get.mockImplementation(async (kind, path) => {
    if (path.includes(`commit=${head}`)) { await gate.promise; throw new ApiClientError('timeout'); }
    if (path === `${base}/provenance/${head}`) return serve(kind, `${base}/provenance/${older}`);
    return serve(kind, path);
  });
  mount();
  fireEvent.click(await screen.findByRole('button', { name: `Inspect ${head.slice(0, 12)}` }));
  fireEvent.click(screen.getByRole('button', { name: `Inspect ${older.slice(0, 12)}` }));
  fireEvent.input(await screen.findByLabelText('Tag name'), { target: { value: 'old-target-draft' } });
  gate.resolve();
  await new Promise(resolve => setTimeout(resolve, 20));
  expect(screen.getByRole('status').textContent).toBe('');
  transport.get.mockImplementation((kind, path) => serve(kind, path === `${base}/provenance/${head}` ? `${base}/provenance/${older}` : path));
  fireEvent.click(screen.getByRole('button', { name: `Inspect ${head.slice(0, 12)}` }));
  await screen.findByRole('heading', { name: `Commit ${head.slice(0, 12)}` });
  expect(screen.getByLabelText('Tag name')).toHaveProperty('value', '');
});

it('explains active worker refusals using fixed local copy without retrying', async () => {
  entries = [];
  transport.post.mockRejectedValueOnce(new ApiClientError('http_error', { status: 409, serverCode: 'ACTIVE_RUN' }));
  mount();
  fireEvent.click(await screen.findByRole('button', { name: 'Switch to topic' }));
  await waitFor(() => expect(screen.getByRole('status').textContent).toMatch(/worker.*Wait/i));
  expect(transport.post).toHaveBeenCalledOnce();
});

it('admits import once and never posts after leaving while the initial job read is pending', async () => {
  listing = [];
  const gate = deferred();
  let signal: AbortSignal | undefined;
  transport.get.mockImplementation(async (kind, path, settings) => {
    if (kind === 'job') { signal = settings?.signal; await gate.promise; }
    return serve(kind, path);
  });
  const view = mount();
  fireEvent.input(await screen.findByLabelText('Repository name'), { target: { value: 'local' } });
  const form = screen.getByRole('button', { name: 'Import repository' }).closest('form')!;
  fireEvent.submit(form); fireEvent.submit(form);
  expect(transport.get.mock.calls.filter(call => call[0] === 'job')).toHaveLength(1);
  view.unmount();
  expect(signal?.aborted).toBe(true);
  gate.resolve();
  await new Promise(resolve => setTimeout(resolve, 20));
  expect(transport.post).not.toHaveBeenCalled();
});

it('stops observing an admitted import on unmount without sending a server cancellation', async () => {
  listing = [];
  const gate = deferred();
  let signal: AbortSignal | undefined;
  transport.post.mockResolvedValueOnce(operation('queued', 'git.attach'));
  transport.get.mockImplementation(async (kind, path, settings) => {
    if (kind === 'operation') { signal = settings?.signal; await gate.promise; }
    return serve(kind, path);
  });
  const view = mount();
  fireEvent.input(await screen.findByLabelText('Repository name'), { target: { value: 'local' } });
  fireEvent.click(screen.getByRole('button', { name: 'Import repository' }));
  await waitFor(() => expect(transport.get.mock.calls.filter(call => call[0] === 'operation')).toHaveLength(1));
  expect(transport.post.mock.calls[0]?.[4].signal).toBe(signal);
  view.unmount();
  expect(signal?.aborted).toBe(true);
  gate.resolve();
  await new Promise(resolve => setTimeout(resolve, 20));
  expect(transport.post).toHaveBeenCalledOnce();
  expect(transport.get.mock.calls.filter(call => call[0] === 'operation')).toHaveLength(1);
});

it('offers bounded anchored continuation beyond 2,000 refs without duplicate admission', async () => {
  entries = [];
  const gate = deferred();
  transport.get.mockImplementation(async (kind, path) => {
    if (kind !== 'gitRefs') return serve(kind, path);
    const start = Number(new URLSearchParams(path.split('?')[1]).get('cursor') ?? 0);
    if (start === 2000) await gate.promise;
    return { data: { repositoryId, nextCursor: start < 2000 ? String(start + 200) : null,
      refs: Array.from({ length: start === 2000 ? 1 : 200 }, (_, index) => ({ refId: `ref_${start + index}`, kind: 'branch',
        displayName: `refs/heads/topic${start + index}`, objectId: other, peeledObjectId: null, version: 'v1', current: false })) } };
  });
  transport.post.mockResolvedValueOnce(operation('completed', 'git.switch'));
  const view = mount();
  // Avoid computing thousands of accessible names in jsdom; these are native, text-labelled buttons.
  const button = (name: string) => [...view.container.querySelectorAll('button')].find(item => item.textContent === name);
  await waitFor(() => expect(button('Switch to topic1999')).toBeTruthy());
  expect(button('Switch to topic2000')).toBeUndefined();
  expect(screen.getByText(/branch and tag list is incomplete/i)).toBeTruthy();
  const more = button('More branches and tags')!;
  fireEvent.click(more); fireEvent.click(more);
  expect(transport.get.mock.calls.filter(call => call[1].includes('cursor=2000'))).toHaveLength(1);
  gate.resolve();
  await waitFor(() => expect(button('Switch to topic2000')).toBeTruthy());
  expect(button('More branches and tags')).toBeUndefined();
  fireEvent.click(button('Switch to topic2000')!);
  await waitFor(() => expect(transport.post).toHaveBeenCalledOnce());
  expect(transport.post.mock.calls[0]?.[3]).toMatchObject({ refId: 'ref_2000', objectId: other });
}, 20_000);

it('discards a ref continuation after refresh, including obsolete failures', async () => {
  const gate = deferred();
  transport.get.mockImplementation(async (kind, path) => {
    if (kind !== 'gitRefs') return serve(kind, path);
    const cursor = new URLSearchParams(path.split('?')[1]).get('cursor');
    if (cursor === 'last') { await gate.promise; throw new ApiClientError('timeout'); }
    const page = Number(cursor ?? 0);
    return { data: { repositoryId, refs: [], nextCursor: page === 9 ? 'last' : String(page + 1) } };
  });
  mount();
  fireEvent.click(await screen.findByRole('button', { name: 'More branches and tags' }));
  transport.get.mockImplementation(serve);
  fireEvent.click(screen.getByRole('button', { name: 'Refresh repository' }));
  await screen.findByRole('button', { name: 'Switch to topic' });
  gate.resolve();
  await new Promise(resolve => setTimeout(resolve, 20));
  expect(screen.getByRole('status').textContent).toBe('');
  expect(screen.queryByRole('button', { name: 'More branches and tags' })).toBeNull();
});

it('traverses a 1,001-commit history without omissions, duplicates or mutations', async () => {
  entries = [];
  const all = Array.from({ length: 1001 }, (_, index) => commitSummary((index + 1).toString(16).padStart(40, '0'), `Commit number ${index}`, false));
  historyPages = {};
  for (let start = 0; start < all.length; start += 20) {
    historyPages[start === 0 ? 'first' : `history_${start}`] = {
      entries: all.slice(start, start + 20), nextCursor: start + 20 < all.length ? `history_${start + 20}` : null };
  }
  const view = mount();
  const items = () => view.container.querySelectorAll('ol[aria-label="History"] > li');
  await waitFor(() => expect(items().length).toBe(20));
  for (let count = 20; count < all.length; count += 20) {
    const more = [...view.container.querySelectorAll('button')].find(button => button.textContent === 'Older commits')!;
    fireEvent.click(more);
    await waitFor(() => expect(items().length).toBe(Math.min(count + 20, all.length)));
  }
  expect([...items()].map(item => item.querySelector('code')?.title)).toEqual(all.map(item => item.objectId));
  expect(transport.get.mock.calls.filter(call => call[0] === 'gitHistory')).toHaveLength(51);
  expect(transport.post).not.toHaveBeenCalled();
}, 20_000);

it('explains unavailable Git without any request and keeps the route usable', () => {
  mount([capability('git', 'unavailable', 'Git 2.20.1 is older than the required 2.36.0.', 'GIT_VERSION_UNSUPPORTED')]);
  expect(screen.getByText('Git on this server: unavailable')).toBeTruthy();
  expect(screen.getByText('Git 2.20.1 is older than the required 2.36.0.')).toBeTruthy();
  expect(screen.getByText(/Source and evidence browsing stay available/)).toBeTruthy();
  expect(screen.queryByRole('button')).toBeNull();
  expect(transport.get).not.toHaveBeenCalled();
});

it('groups status, selects per group and stages exactly the chosen file under the reviewed guards', async () => {
  transport.post.mockResolvedValueOnce(operation('queued'));
  mount();
  const staged = await screen.findByRole('group', { name: 'Staged' });
  expect(within(staged).getByText('src/util.c')).toBeTruthy();
  expect(within(screen.getByRole('group', { name: 'Not staged' })).getByText('src/util.c')).toBeTruthy();
  expect(screen.getByText('2 ignored by the source-only policy')).toBeTruthy();
  const stage = screen.getByRole('button', { name: 'Stage selected' });
  const unstage = screen.getByRole('button', { name: 'Unstage selected' });
  expect(stage).toHaveProperty('disabled', true);
  fireEvent.click(screen.getByRole('checkbox', { name: 'Select src/new.c (Untracked)' }));
  expect(stage).toHaveProperty('disabled', false);
  expect(unstage).toHaveProperty('disabled', true);
  fireEvent.click(stage); fireEvent.click(stage);
  expect(await screen.findByText('Stage selected: Done.')).toBeTruthy();
  expect(transport.post).toHaveBeenCalledOnce();
  expect(transport.post.mock.calls[0]?.slice(0, 4)).toEqual(['operation', `${base}/operations`, 'gitStageRequest', {
    action: 'git.stage', worktreeId, selectedFileIds: ['file_u'],
    guards: { repositoryVersion: 'repo_v1', worktreeVersion: 'tree_v1', expectedHeadObjectId: head, expectedRefId: null, expectedRefObjectId: null } }]);
  expect(transport.post.mock.calls[0]?.[4]).toMatchObject({ csrfToken: session.csrf(), ifMatch: '"tree_v1"' });
  expect(transport.get).toHaveBeenCalledWith('operation', `${base}/operations/operation_1`, expect.anything());
});

it('reviews the exact staged files and parent, shows a diff and commits the reviewed selection', async () => {
  transport.post.mockResolvedValueOnce(operation('completed', 'git.commit'));
  mount();
  const review = await screen.findByRole('list', { name: /Exactly these staged files/ });
  expect(within(review).getAllByRole('listitem').map(item => item.textContent)).toEqual(['src/util.c modified']);
  expect(screen.getByText(`Parent commit: ${head}`)).toBeTruthy();
  fireEvent.click(within(screen.getByRole('group', { name: 'Staged' })).getByRole('button', { name: 'Show diff for src/util.c' }));
  expect(await screen.findByText(/\+int b;/)).toBeTruthy();
  expect(transport.get).toHaveBeenCalledWith('gitDiff', `${base}/diff?scope=staged&file=file_s`);
  fireEvent.input(screen.getByLabelText('Commit message'), { target: { value: 'Rename the helper' } });
  fireEvent.click(screen.getByRole('button', { name: 'Commit staged files' }));
  await waitFor(() => expect(transport.post).toHaveBeenCalledOnce());
  expect(transport.post.mock.calls[0]?.[3]).toMatchObject({ action: 'git.commit', worktreeId, selectedFileIds: ['file_s'], message: 'Rename the helper' });
});

it('pages history, links a mapped commit to its recorded source and verifies its export', async () => {
  mount();
  expect(await screen.findByText('Work in progress')).toBeTruthy();
  expect(screen.getByText('Not mapped to a reconstruction revision')).toBeTruthy();
  fireEvent.click(screen.getByRole('button', { name: 'Older commits' }));
  expect(await screen.findByText('Reconstruction revision revision_1 (accepted)')).toBeTruthy();
  expect(screen.queryByRole('button', { name: 'Older commits' })).toBeNull();
  const sources = screen.getByRole('link', { name: 'Open the recorded source revision' });
  expect(sources.getAttribute('href')).toBe(`/nested/jobs/${jobId}/runs/run_1/revisions/revision_1/sources/root`);
  fireEvent.click(screen.getByRole('button', { name: `Inspect ${older.slice(0, 12)}` }));
  expect(await screen.findByText(`Source export SHA-256: ${'e'.repeat(64)}`)).toBeTruthy();
  expect(screen.getByText(/Export verified against the commit tree/)).toBeTruthy();
  expect(screen.getByRole('link', { name: 'Download source export' }).getAttribute('href')).toBe(`/nested/api/v1${base}/exports/${older}`);
  expect(screen.getByText('Named by: refs/tags/v1')).toBeTruthy();
});

it('disables switching while the work tree is dirty and switches to the exact ref when clean', async () => {
  const view = mount();
  const dirtySwitch = await screen.findByRole('button', { name: 'Switch to topic' });
  expect(dirtySwitch).toHaveProperty('disabled', true);
  expect(screen.getByText(/Switching needs a clean work tree/)).toBeTruthy();
  view.unmount();
  entries = [];
  transport.post.mockResolvedValueOnce(operation('completed', 'git.switch'));
  mount();
  const cleanSwitch = await screen.findByRole('button', { name: 'Switch to topic' });
  expect(cleanSwitch).toHaveProperty('disabled', false);
  expect(screen.getByText('No changes.')).toBeTruthy();
  fireEvent.click(cleanSwitch);
  await waitFor(() => expect(transport.post).toHaveBeenCalledOnce());
  expect(transport.post.mock.calls[0]?.slice(2, 4)).toEqual(['gitSwitchRequest', { action: 'git.switch', worktreeId, refId: 'ref_topic', objectId: other,
    guards: { repositoryVersion: 'repo_v1', worktreeVersion: 'tree_v1', expectedHeadObjectId: head, expectedRefId: null, expectedRefObjectId: null } }]);
  expect(screen.getByText(/owned by attempt run_2/)).toBeTruthy();
  expect(screen.getByRole('button', { name: `Remove ${linkedId}` })).toHaveProperty('disabled', true);
});

it('imports an admitted repository by name when the job has none', async () => {
  listing = [];
  transport.post.mockResolvedValueOnce(operation('queued', 'git.attach'));
  mount();
  fireEvent.input(await screen.findByLabelText('Repository name'), { target: { value: 'local' } });
  listing = [repository];
  fireEvent.click(screen.getByRole('button', { name: 'Import repository' }));
  await waitFor(() => expect(transport.post).toHaveBeenCalledOnce());
  expect(transport.post.mock.calls[0]?.slice(1, 4)).toEqual([`/jobs/${jobId}/repositories`, 'gitRepositoryAttachRequest', { action: 'git.attach', sourceName: 'local' }]);
  expect(transport.post.mock.calls[0]?.[4]).toMatchObject({ ifMatch: '"job_v3"' });
  expect(await screen.findByRole('group', { name: 'Staged' })).toBeTruthy();
});

it('reports a refused change without retrying it', async () => {
  transport.post.mockRejectedValueOnce(new ApiClientError('http_error', { status: 409 }));
  mount();
  fireEvent.click(await screen.findByRole('checkbox', { name: 'Select src/util.c (Staged)' }));
  fireEvent.click(screen.getByRole('button', { name: 'Unstage selected' }));
  expect(await screen.findByText(/The server refused Unstage selected/)).toBeTruthy();
  expect(transport.post).toHaveBeenCalledOnce();
  expect(transport.post.mock.calls[0]?.[3]).toMatchObject({ action: 'git.unstage', selectedFileIds: ['file_s'] });
});

it('reads every status page before review and keeps the commit message when the commit fails', async () => {
  paged = true;
  entries = [entry('file_s', 'src/util.c', 'modified', 'none'), entry('file_t', 'src/two.c', 'added', 'none')];
  transport.post.mockResolvedValueOnce({ data: { ...operation('failed', 'git.commit').data, message: 'The staged set changed.' } });
  mount();
  const review = await screen.findByRole('list', { name: /Exactly these staged files/ });
  expect(within(review).getAllByRole('listitem').map(item => item.textContent)).toEqual(['src/util.c modified', 'src/two.c added']);
  expect(transport.get).toHaveBeenCalledWith('gitStatus', `${base}/status?limit=200&cursor=status_page_2`, expect.anything());
  fireEvent.input(screen.getByLabelText('Commit message'), { target: { value: 'Keep this draft' } });
  fireEvent.click(screen.getByRole('button', { name: 'Commit staged files' }));
  expect(await screen.findByText(/Commit staged files did not complete/)).toBeTruthy();
  expect(transport.post.mock.calls[0]?.[3]).toMatchObject({ selectedFileIds: ['file_s', 'file_t'] });
  expect(screen.getByLabelText('Commit message')).toHaveProperty('value', 'Keep this draft');
});

it('follows ref pages so every branch stays reachable, and drops a displayed diff when the status is read again', async () => {
  paged = true;
  entries = [entry('file_s', 'src/util.c', 'modified', 'none')];
  mount();
  expect(await screen.findByRole('button', { name: 'Switch to topic' })).toBeTruthy();
  expect(transport.get).toHaveBeenCalledWith('gitRefs', `${base}/refs?limit=200&cursor=refs_page_2`, expect.anything());
  fireEvent.click(within(screen.getByRole('group', { name: 'Staged' })).getByRole('button', { name: 'Show diff for src/util.c' }));
  expect(await screen.findByText(/\+int b;/)).toBeTruthy();
  fireEvent.click(screen.getByRole('button', { name: 'Refresh repository' }));
  await waitFor(() => expect(screen.queryByText(/\+int b;/)).toBeNull());
});

it('explains and disables a commit or selection beyond the 200-file request bound', async () => {
  entries = Array.from({ length: 201 }, (_, index) => entry(`file_${index}`, `src/f${index}.c`, 'added', 'none'));
  mount();
  expect(await screen.findByText(/201 files are staged, but one commit can include at most 200/)).toBeTruthy();
  expect(screen.getByRole('button', { name: 'Commit staged files' })).toHaveProperty('disabled', true);
  document.querySelectorAll<HTMLInputElement>('input[type="checkbox"]').forEach(box => { fireEvent.click(box); });
  expect(screen.getByText(/At most 200 files can be staged or unstaged in one action/)).toBeTruthy();
  expect(screen.getByRole('button', { name: 'Unstage selected' })).toHaveProperty('disabled', true);
}, 20_000);

it('lists every file of an inspected commit and drops an older-history page that arrives after a refresh', async () => {
  paged = true;
  entries = [];
  mount();
  fireEvent.click(await screen.findByRole('button', { name: 'Older commits' }));
  expect(await screen.findByText('Record candidate')).toBeTruthy();
  fireEvent.click(screen.getByRole('button', { name: `Inspect ${older.slice(0, 12)}` }));
  expect(await screen.findByText('src/second.c')).toBeTruthy();
  expect(screen.getByText('src/main.c')).toBeTruthy();
  expect(transport.get).toHaveBeenCalledWith('gitDiff', `${base}/diff?scope=commit&commit=${older}&limit=200&cursor=diff_page_2`);
  // A pending older page must not be appended to history that was read again meanwhile.
  let open = () => {};
  historyGate = new Promise<void>(resolve => { open = resolve; });
  fireEvent.click(screen.getByRole('button', { name: 'Refresh repository' }));
  await waitFor(() => expect(screen.queryByText('Record candidate')).toBeNull());
  fireEvent.click(await screen.findByRole('button', { name: 'Older commits' }));
  fireEvent.click(screen.getByRole('button', { name: 'Refresh repository' }));
  await waitFor(() => expect(transport.get.mock.calls.filter(call => String(call[1]).includes('/history?limit=20')).length).toBeGreaterThanOrEqual(3));
  open();
  await new Promise(resolve => setTimeout(resolve, 50));
  expect(screen.queryByText('Record candidate')).toBeNull();
});

it('requests each older history page once and keeps changed files visible when provenance is unavailable', async () => {
  provenanceFails = true;
  mount();
  const olderButton = await screen.findByRole('button', { name: 'Older commits' });
  fireEvent.click(olderButton); fireEvent.click(olderButton);
  expect(await screen.findByText('Record candidate')).toBeTruthy();
  expect(screen.getAllByText('Record candidate')).toHaveLength(1);
  expect(transport.get.mock.calls.filter(call => String(call[1]).includes('/history?cursor=page2'))).toHaveLength(1);
  fireEvent.click(screen.getByRole('button', { name: `Inspect ${older.slice(0, 12)}` }));
  expect(await screen.findByText('src/main.c')).toBeTruthy();
  expect(screen.getByText(/provenance and source export of this commit are unavailable/)).toBeTruthy();
  expect(screen.queryByRole('link', { name: 'Download source export' })).toBeNull();
  expect(screen.getByLabelText('Tag name')).toBeTruthy();
});

it('reports a failed job read during import instead of stopping silently', async () => {
  listing = [];
  jobFails = true;
  mount();
  fireEvent.input(await screen.findByLabelText('Repository name'), { target: { value: 'local' } });
  fireEvent.click(screen.getByRole('button', { name: 'Import repository' }));
  expect(await screen.findByText(/The server refused Import repository/)).toBeTruthy();
  expect(transport.post).not.toHaveBeenCalled();
  expect(screen.getByRole('button', { name: 'Import repository' })).toHaveProperty('disabled', false);
});

it('shows only the latest requested diff even when an earlier one answers later', async () => {
  mount();
  await screen.findByRole('group', { name: 'Staged' });
  let open = () => {};
  unstagedDiffGate = new Promise<void>(resolve => { open = resolve; });
  fireEvent.click(within(screen.getByRole('group', { name: 'Not staged' })).getByRole('button', { name: 'Show diff for src/util.c' }));
  fireEvent.click(within(screen.getByRole('group', { name: 'Staged' })).getByRole('button', { name: 'Show diff for src/util.c' }));
  expect(await screen.findByText('Staged diff: src/util.c')).toBeTruthy();
  open();
  await new Promise(resolve => setTimeout(resolve, 50));
  expect(screen.getByText('Staged diff: src/util.c')).toBeTruthy();
  expect(screen.queryByText('Not staged diff: src/util.c')).toBeNull();
});
