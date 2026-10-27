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
const supported = [capability('git', 'supported'), capability('git-import', 'supported'), capability('git-remotes', 'supported')];

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
let remoteList: unknown[];
let operationReads: unknown[];
let pushState: { fastForward: boolean; unconfirmed: string | null };
let conflictState: { repositoryId: string; worktreeId: string; mergeInProgress: boolean; integration: unknown; files: { fileId: string; path: string }[] };
let conflictReads = 0;
let divergenceHead: string;
let operationOverride: (() => unknown) | null = null;
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
    if (route === `${base}/remotes`) return { repositoryId, configured: true, remotes: remoteList };
    if (route === `${base}/conflicts`) return { offset: 0, totalCount: conflictState.files.length, nextOffset: null, ...conflictState };
    if (route === `${base}/push-preview`) return { repositoryId, worktreeId, remoteId: 'remote_1', destination: 'https://git.example.org/team/project.git',
      allowed: true, localRefId: 'ref_main', localRefName: 'refs/heads/main', localObjectId: head,
      remoteBranch: new URLSearchParams(query).get('branch'), expectedRemoteObjectId: older, fetchedAt: '2026-10-25T00:00:00Z', remoteState: 'current',
      fastForward: pushState.fastForward, commitCount: '1', commits: [{ objectId: head, subject: 'Work in progress' }],
      unconfirmedPushOperationId: pushState.unconfirmed };
    if (route === `${base}/conflicts/file_conflict`) return { repositoryId, worktreeId, file: conflictState.files[0],
      base: 'int a;\n', ours: 'int a = 1;\n', theirs: 'int a = 2;\n', current: '<<<<<<< ours\nint a = 1;\n=======\nint a = 2;\n>>>>>>> theirs\n',
      currentSha256: (conflictReads++ === 0 ? 'c' : 'd').repeat(64), currentSizeBytes: '60', supported: true, reason: null };
    if (route === `${base}/divergence`) return { repositoryId, worktreeId, localRefName: 'refs/heads/main', localObjectId: divergenceHead,
      trackingRefId: 'ref_origin_main', trackingRefName: 'refs/remotes/origin/main', trackingObjectId: other, remoteId: 'remote_1',
      fetchedAt: null, remoteState: 'unknown', ahead: '1', behind: '2', mergeBaseObjectId: older, mergeInProgress: false, strategies: [
        { strategy: 'fast-forward', available: false, reason: 'The branch has 1 local commit(s), so it cannot be fast-forwarded.' },
        { strategy: 'merge', available: true, reason: null },
        { strategy: 'rebase', available: false, reason: 'Rebasing rewrites history and is not supported by the workbench.' }] };
    if (route === `${base}/audit`) return { repositoryId, entries: [{ at: '2026-10-25T00:00:00Z', action: 'remote.add', operationId: 'operation_0',
      outcome: 'completed', remoteId: 'remote_1', destination: 'https://git.example.org/team/project.git', ref: null, oldObjectId: null,
      newObjectId: null, detail: null }] };
    if (route.startsWith(`${base}/operations/`)) return operationOverride?.() ?? operationReads.shift() ?? operation('completed').data;
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
  operationReads = [];
  pushState = { fastForward: true, unconfirmed: null };
  conflictState = { repositoryId, worktreeId, mergeInProgress: false, integration: null, files: [] };
  conflictReads = 0;
  divergenceHead = head;
  operationOverride = null;
  remoteList = [{ remoteId: 'remote_1', name: 'origin', transport: 'https', display: 'https://git.example.org/team/project.git',
    credential: 'configured', allowed: true, fetchedAt: null, fetchOperationId: null,
    trackingRefs: [{ refId: 'ref_origin_main', name: 'refs/remotes/origin/main', objectId: other }] }];
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

it.each(['refused request', 'failed operation'])('keeps a tag draft after a %s, refreshes guards and clears only after a successful retry', async failure => {
  if (failure === 'refused request') transport.post.mockRejectedValueOnce(new ApiClientError('http_error', { status: 409 }));
  else transport.post.mockResolvedValueOnce(operation('failed', 'git.tag'));
  transport.post.mockResolvedValueOnce(operation('completed', 'git.tag'));
  mount();
  const inspect = async () => {
    fireEvent.click(await screen.findByRole('button', { name: 'Older commits' }));
    fireEvent.click(await screen.findByRole('button', { name: `Inspect ${older.slice(0, 12)}` }));
    return screen.findByLabelText('Tag name');
  };
  fireEvent.input(await inspect(), { target: { value: 'keep-my-tag-draft' } });
  // The refusal still refreshes the reviewed guards; it must not discard the draft with the detail.
  transport.get.mockImplementation(async (kind, path) => {
    const result = await serve(kind, path);
    return kind === 'gitStatus' ? { data: { ...status(true), repositoryVersion: 'repo_v2', worktreeVersion: 'tree_v2' } } : result;
  });
  fireEvent.click(screen.getByRole('button', { name: 'Tag this commit' }));
  await screen.findByText(failure === 'refused request' ? /The server refused Tag this commit/ : /Tag this commit did not complete/);
  await waitFor(() => expect(transport.get.mock.calls.filter(call => call[0] === 'gitRepositories')).toHaveLength(2));
  await waitFor(() => expect(screen.queryByLabelText('Tag name')).toBeNull());
  expect(transport.post).toHaveBeenCalledOnce();
  expect(await inspect()).toHaveProperty('value', 'keep-my-tag-draft');
  fireEvent.click(screen.getByRole('button', { name: 'Tag this commit' }));
  await screen.findByText('Tag this commit: Done.');
  expect(transport.post).toHaveBeenCalledTimes(2);
  expect(transport.post.mock.calls[1]?.[3]).toMatchObject({ name: 'keep-my-tag-draft', targetObjectId: older,
    guards: { repositoryVersion: 'repo_v2', worktreeVersion: 'tree_v2' } });
  expect(transport.post.mock.calls[1]?.[4]).toMatchObject({ ifMatch: '"tree_v2"' });
  await waitFor(() => expect(transport.get.mock.calls.filter(call => call[0] === 'gitRepositories')).toHaveLength(3));
  await waitFor(() => expect(screen.queryByLabelText('Tag name')).toBeNull());
  expect(await inspect()).toHaveProperty('value', '');
});

it('retains a tag draft through a manual refresh but discards it after inspecting another target', async () => {
  historyPages.first = { entries: [commitSummary(head, 'Newest', false), commitSummary(older, 'Previous', true)], nextCursor: null };
  mount();
  fireEvent.click(await screen.findByRole('button', { name: `Inspect ${older.slice(0, 12)}` }));
  fireEvent.input(await screen.findByLabelText('Tag name'), { target: { value: 'same-target-draft' } });
  fireEvent.click(screen.getByRole('button', { name: 'Refresh repository' }));
  await waitFor(() => expect(screen.queryByLabelText('Tag name')).toBeNull());
  fireEvent.click(screen.getByRole('button', { name: `Inspect ${older.slice(0, 12)}` }));
  expect(await screen.findByLabelText('Tag name')).toHaveProperty('value', 'same-target-draft');
  fireEvent.click(screen.getByRole('button', { name: `Inspect ${head.slice(0, 12)}` }));
  await screen.findByRole('heading', { name: `Commit ${head.slice(0, 12)}` });
  expect(screen.getByLabelText('Tag name')).toHaveProperty('value', '');
  fireEvent.click(screen.getByRole('button', { name: `Inspect ${older.slice(0, 12)}` }));
  await screen.findByRole('heading', { name: `Commit ${older.slice(0, 12)}` });
  expect(screen.getByLabelText('Tag name')).toHaveProperty('value', '');
});

it('does not reuse a tag draft for the same object in a different repository', async () => {
  historyPages.first = { entries: [commitSummary(older, 'Previous', true)], nextCursor: null };
  mount();
  fireEvent.click(await screen.findByRole('button', { name: `Inspect ${older.slice(0, 12)}` }));
  fireEvent.input(await screen.findByLabelText('Tag name'), { target: { value: 'old-repository-draft' } });
  const replacementId = 'repository_' + '4'.repeat(32);
  listing = [{ ...repository, repositoryId: replacementId }];
  transport.get.mockImplementation(async (kind, path) => {
    const result = await serve(kind, path.replace(replacementId, repositoryId)) as { data: Record<string, unknown> };
    return kind === 'gitRepositories' ? result : { data: { ...result.data, repositoryId: replacementId } };
  });
  fireEvent.click(screen.getByRole('button', { name: 'Refresh repository' }));
  await screen.findByText(replacementId);
  fireEvent.click(screen.getByRole('button', { name: `Inspect ${older.slice(0, 12)}` }));
  expect(await screen.findByLabelText('Tag name')).toHaveProperty('value', '');
  expect(transport.post).not.toHaveBeenCalled();
});

it('does not clear another target draft when an earlier tag completes', async () => {
  const gate = deferred();
  historyPages.first = { entries: [commitSummary(head, 'Newest', false), commitSummary(older, 'Previous', true)], nextCursor: null };
  transport.get.mockImplementation((kind, path) => serve(kind, path === `${base}/provenance/${head}` ? `${base}/provenance/${older}` : path));
  transport.post.mockImplementationOnce(async () => { await gate.promise; return operation('completed', 'git.tag'); });
  mount();
  fireEvent.click(await screen.findByRole('button', { name: `Inspect ${older.slice(0, 12)}` }));
  fireEvent.input(await screen.findByLabelText('Tag name'), { target: { value: 'submitted-for-previous' } });
  fireEvent.click(screen.getByRole('button', { name: 'Tag this commit' }));
  await waitFor(() => expect(transport.post).toHaveBeenCalledOnce());
  fireEvent.click(screen.getByRole('button', { name: `Inspect ${head.slice(0, 12)}` }));
  await screen.findByRole('heading', { name: `Commit ${head.slice(0, 12)}` });
  fireEvent.input(screen.getByLabelText('Tag name'), { target: { value: 'new-target-draft' } });
  gate.resolve();
  await screen.findByText('Tag this commit: Done.');
  await waitFor(() => expect(transport.get.mock.calls.filter(call => call[0] === 'gitRepositories')).toHaveLength(2));
  await waitFor(() => expect(screen.queryByLabelText('Tag name')).toBeNull());
  fireEvent.click(screen.getByRole('button', { name: `Inspect ${head.slice(0, 12)}` }));
  expect(await screen.findByLabelText('Tag name')).toHaveProperty('value', 'new-target-draft');
  expect(transport.post.mock.calls[0]?.[3]).toMatchObject({ name: 'submitted-for-previous', targetObjectId: older });
});

it('explains active worker refusals using fixed local copy without retrying', async () => {
  entries = [];
  transport.post.mockRejectedValueOnce(new ApiClientError('http_error', { status: 409, serverCode: 'ACTIVE_RUN' }));
  mount();
  fireEvent.click(await screen.findByRole('button', { name: 'Switch to topic' }));
  await waitFor(() => expect(screen.getByRole('status').textContent).toMatch(/worker.*Wait/i));
  expect(transport.post).toHaveBeenCalledOnce();
});

it.each(['import', 'clone'])('admits %s once and never posts after leaving while the initial job read is pending', async action => {
  listing = [];
  const gate = deferred();
  let signal: AbortSignal | undefined;
  transport.get.mockImplementation(async (kind, path, settings) => {
    if (kind === 'job') { signal = settings?.signal; await gate.promise; }
    return serve(kind, path);
  });
  const view = mount();
  fireEvent.input(await screen.findByLabelText(action === 'import' ? 'Repository name' : 'Remote URL'),
    { target: { value: action === 'import' ? 'local' : 'https://git.example.org/team/project.git' } });
  const form = screen.getByRole('button', { name: action === 'import' ? 'Import repository' : 'Clone repository' }).closest('form')!;
  fireEvent.submit(form); fireEvent.submit(form);
  expect(transport.get.mock.calls.filter(call => call[0] === 'job')).toHaveLength(1);
  view.unmount();
  expect(signal?.aborted).toBe(true);
  gate.resolve();
  await new Promise(resolve => setTimeout(resolve, 20));
  expect(transport.post).not.toHaveBeenCalled();
});

it.each(['import', 'clone'])('stops observing an admitted %s on unmount without sending a server cancellation', async action => {
  listing = [];
  const gate = deferred();
  let signal: AbortSignal | undefined;
  transport.post.mockResolvedValueOnce(operation('queued', action === 'import' ? 'git.attach' : 'git.clone'));
  transport.get.mockImplementation(async (kind, path, settings) => {
    if (kind === 'operation') { signal = settings?.signal; await gate.promise; }
    return serve(kind, path);
  });
  const view = mount();
  fireEvent.input(await screen.findByLabelText(action === 'import' ? 'Repository name' : 'Remote URL'),
    { target: { value: action === 'import' ? 'local' : 'https://git.example.org/team/project.git' } });
  fireEvent.click(screen.getByRole('button', { name: action === 'import' ? 'Import repository' : 'Clone repository' }));
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

it('fetches a remote with visible progress, cancels it explicitly and never shows a credential', async () => {
  transport.post.mockResolvedValueOnce({ data: { ...operation('running', 'git.fetch').data, progress: { phase: 'Receiving objects', percent: 40 } } });
  operationReads = [{ ...operation('running', 'git.fetch').data, progress: { phase: 'Receiving objects', percent: 45 } },
    { ...operation('running', 'git.fetch').data, progress: { phase: 'Receiving objects', percent: 50 } },
    { ...operation('cancelled', 'git.fetch').data, message: 'The transfer was cancelled.' }];
  mount();
  const remotes = await screen.findByRole('list', { name: 'Remotes' });
  expect(within(remotes).getAllByText(/Credential configured on the server/)[0]).toBeTruthy();
  expect(within(remotes).getAllByText(/Never fetched; remote state is unknown/)[0]).toBeTruthy();
  expect(screen.getByRole('list', { name: 'Remote-tracking refs of origin' }).textContent).toContain('refs/remotes/origin/main');
  transport.post.mockResolvedValueOnce({ data: { ...operation('cancelling', 'git.fetch').data } });
  fireEvent.click(screen.getByRole('button', { name: 'Fetch origin' }));
  fireEvent.click(await screen.findByRole('button', { name: 'Cancel transfer' }));
  await waitFor(() => expect(transport.post).toHaveBeenCalledTimes(2));
  expect(transport.post.mock.calls[0]?.slice(2, 4)).toEqual(['gitFetchRequest', { action: 'git.fetch', worktreeId, remoteId: 'remote_1',
    guards: { repositoryVersion: 'repo_v1', worktreeVersion: 'tree_v1', expectedHeadObjectId: head, expectedRefId: null, expectedRefObjectId: null } }]);
  expect(transport.post.mock.calls[1]?.slice(1, 4)).toEqual([`${base}/operations/operation_1/cancel`, 'gitOperationCancelRequest', { action: 'git.cancel' }]);
  expect(transport.post.mock.calls[1]?.[4]).toMatchObject({ ifMatch: '"operation_v1"' });
  expect(await screen.findByText(/Fetch origin did not complete: The transfer was cancelled/)).toBeTruthy();
  expect(document.body.textContent).not.toMatch(/token=|Authorization:|Basic [A-Za-z0-9+/=]{8}/);
});

it('adds a remote by URL only and explains when remote operations are unavailable', async () => {
  transport.post.mockResolvedValueOnce(operation('completed', 'git.remote.add'));
  const view = mount();
  fireEvent.input(await screen.findByLabelText('Remote name'), { target: { value: 'upstream' } });
  fireEvent.input(screen.getByLabelText('Remote URL'), { target: { value: 'admitted:upstream.git' } });
  fireEvent.click(screen.getByRole('button', { name: 'Add remote' }));
  await waitFor(() => expect(transport.post).toHaveBeenCalledOnce());
  expect(transport.post.mock.calls[0]?.[3]).toMatchObject({ action: 'git.remote.add', name: 'upstream', url: 'admitted:upstream.git' });
  view.unmount();
  mount([capability('git', 'supported'), capability('git-remotes', 'unavailable', 'Remote clone, fetch and push need operator-allowed destinations.', 'GIT_REMOTES_UNCONFIGURED')]);
  expect(await screen.findByText(/need operator-allowed destinations/)).toBeTruthy();
  expect(screen.queryByRole('button', { name: 'Add remote' })).toBeNull();
  expect(screen.getByRole('button', { name: 'Fetch origin' })).toHaveProperty('disabled', true);
});

it('clones a new repository from a remote URL when the job has none', async () => {
  listing = [];
  transport.post.mockResolvedValueOnce(operation('queued', 'git.clone'));
  mount();
  fireEvent.input(await screen.findByLabelText('Remote URL'), { target: { value: 'https://git.example.org/team/project.git' } });
  listing = [repository];
  fireEvent.click(screen.getByRole('button', { name: 'Clone repository' }));
  await waitFor(() => expect(transport.post).toHaveBeenCalledOnce());
  expect(transport.post.mock.calls[0]?.slice(1, 4)).toEqual([`/jobs/${jobId}/repositories`, 'gitRepositoryCloneRequest',
    { action: 'git.clone', url: 'https://git.example.org/team/project.git', remoteName: 'origin', branch: null }]);
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

it('reviews and commits the complete merge index beyond the ordinary 200-file selection bound', async () => {
  conflictState = { repositoryId, worktreeId, mergeInProgress: true, integration: null, files: [] };
  entries = Array.from({ length: 201 }, (_, index) => entry(`file_${index}`, `src/f${index}.c`, 'added', 'none'));
  transport.post.mockResolvedValueOnce(operation('completed', 'git.commit'));
  mount();
  await screen.findByLabelText('Commit message');
  expect(screen.queryByText(/one commit can include at most 200/)).toBeNull();
  const commitReview = screen.getByRole('list', { name: 'Exactly these staged files will be committed:' });
  expect(within(commitReview).getAllByRole('listitem')).toHaveLength(201);
  expect(screen.getByRole('button', { name: 'Commit staged files' })).toHaveProperty('disabled', false);
  fireEvent.input(screen.getByLabelText('Commit message'), { target: { value: 'Merge all incoming changes' } });
  fireEvent.click(screen.getByRole('button', { name: 'Commit staged files' }));
  await waitFor(() => expect(transport.post).toHaveBeenCalledOnce());
  expect(transport.post.mock.calls[0]?.[3]).toMatchObject({ action: 'git.commit', selectedFileIds: [], reviewedMergeIndex: true,
    guards: { worktreeVersion: 'tree_v1' } });
});

it('reviews fetched divergence and offers only reviewed fast-forward or merge, never rebase', async () => {
  transport.post.mockResolvedValueOnce(operation('completed', 'git.merge'));
  mount();
  fireEvent.click(await screen.findByRole('button', { name: 'Review divergence' }));
  expect(await screen.findByText(/1 local commit\(s\) not on the remote; 2 remote commit\(s\) not on your branch/)).toBeTruthy();
  expect(screen.getByText('Never fetched; state unknown')).toBeTruthy();
  expect(screen.getByRole('button', { name: 'Fast-forward to the remote commit' })).toHaveProperty('disabled', true);
  expect(screen.getByRole('button', { name: 'Rebase' })).toHaveProperty('disabled', true);
  expect(screen.getByText(/Rebasing rewrites history/)).toBeTruthy();
  fireEvent.click(screen.getByRole('button', { name: 'Merge the remote commit' }));
  await waitFor(() => expect(transport.post).toHaveBeenCalledOnce());
  expect(transport.post.mock.calls[0]?.slice(2, 4)).toEqual(['gitMergeRequest', { action: 'git.merge', worktreeId, trackingRefId: 'ref_origin_main',
    targetObjectId: other, strategy: 'merge',
    guards: { repositoryVersion: 'repo_v1', worktreeVersion: 'tree_v1', expectedHeadObjectId: head, expectedRefId: null, expectedRefObjectId: null } }]);
});

it('never shows or acts on a divergence review of another destination', async () => {
  // The review answers for a HEAD the work tree is no longer on (it moved, or another work tree was chosen).
  divergenceHead = older;
  mount();
  fireEvent.click(await screen.findByRole('button', { name: 'Review divergence' }));
  await waitFor(() => expect(transport.get).toHaveBeenCalledWith('gitDivergence', expect.stringContaining('/divergence?tracking=ref_origin_main')));
  await new Promise(resolve => setTimeout(resolve, 20));
  expect(screen.queryByRole('button', { name: 'Merge the remote commit' })).toBeNull();
  expect(transport.post).not.toHaveBeenCalled();
});

it('keeps an edited resolution when its save is refused and saves it with the refreshed token', async () => {
  conflictState = { repositoryId, worktreeId, mergeInProgress: true, integration: null,
    files: [{ fileId: 'file_conflict', path: 'src/a.c', pathEscaped: false, baseObjectId: older, oursObjectId: head, theirsObjectId: other } as never] };
  transport.post.mockRejectedValueOnce(new ApiClientError('http_error', { status: 409 }));
  transport.post.mockResolvedValueOnce(operation('completed', 'git.conflict.save'));
  mount();
  fireEvent.click(await screen.findByRole('button', { name: 'Review src/a.c' }));
  fireEvent.input(await screen.findByLabelText('Resolved text'), { target: { value: 'int a = 3;\n' } });
  fireEvent.click(screen.getByRole('button', { name: 'Save resolution' }));
  await waitFor(() => expect(conflictReads).toBe(2));
  expect(await screen.findByLabelText('Resolved text')).toHaveProperty('value', 'int a = 3;\n');
  fireEvent.click(screen.getByRole('button', { name: 'Save resolution' }));
  await waitFor(() => expect(transport.post).toHaveBeenCalledTimes(2));
  expect(transport.post.mock.calls[1]?.[3]).toMatchObject({ action: 'git.conflict.save', expectedSha256: 'd'.repeat(64),
    resolution: 'text', content: 'int a = 3;\n' });
});

it('commits a pending merge whose resolution matches the current commit', async () => {
  conflictState = { repositoryId, worktreeId, mergeInProgress: true, integration: null, files: [] };
  entries = [];
  transport.post.mockResolvedValueOnce(operation('completed', 'git.commit'));
  mount();
  expect(await screen.findByText(/Committing records the merge with both parents/)).toBeTruthy();
  fireEvent.input(screen.getByLabelText('Commit message'), { target: { value: 'Merge keeping ours' } });
  fireEvent.click(screen.getByRole('button', { name: 'Commit staged files' }));
  await waitFor(() => expect(transport.post).toHaveBeenCalledOnce());
  expect(transport.post.mock.calls[0]?.[3]).toMatchObject({ action: 'git.commit', selectedFileIds: [], message: 'Merge keeping ours' });
});

it('navigates live conflict pages without carrying a reviewed selection to another page', async () => {
  conflictState = { repositoryId, worktreeId, mergeInProgress: true, integration: null,
    files: [{ fileId: 'file_conflict', path: 'src/a.c' }] };
  transport.get.mockImplementation((kind, path) => {
    const [route, query] = path.split('?');
    if (route === `${base}/conflicts`) {
      const offset = Number(new URLSearchParams(query).get('offset') ?? 0);
      return Promise.resolve({ data: { ...conflictState, offset, totalCount: 201, nextOffset: offset === 0 ? 200 : null,
        files: offset === 0 ? conflictState.files : [{ fileId: 'file_last', path: 'src/z.c' }] } });
    }
    return serve(kind, path);
  });
  render(<GitWorkspace jobId={jobId} basePath="/workbench" session={session} capabilities={supported} pollIntervalMs={1} />);
  await screen.findByText('Showing 1 of 201 unresolved paths. Pages reflect the live index; staging a batch refreshes the first page.');
  fireEvent.click(screen.getByRole('button', { name: 'Review src/a.c' }));
  await screen.findByRole('group', { name: 'Conflict in src/a.c' });
  fireEvent.click(screen.getByRole('checkbox', { name: 'Mark src/a.c reviewed' }));
  fireEvent.click(screen.getByRole('button', { name: 'Next conflicts' }));
  await screen.findByRole('button', { name: 'Review src/z.c' });
  expect(transport.get.mock.calls.some(call => call[1] === `${base}/conflicts?offset=200`)).toBe(true);
  expect(screen.getByRole<HTMLButtonElement>('button', { name: 'Stage reviewed resolutions' }).disabled).toBe(true);
  expect(screen.queryByRole('group', { name: 'Conflict in src/a.c' })).toBeNull();
  fireEvent.click(screen.getByRole('button', { name: 'Previous conflicts' }));
  await screen.findByRole('button', { name: 'Review src/a.c' });
});

it('retains status and explicit abort when conflict enumeration fails', async () => {
  transport.get.mockImplementation((kind, path) => kind === 'gitConflicts'
    ? Promise.reject(new ApiClientError('http_error', { status: 503 })) : serve(kind, path));
  transport.post.mockResolvedValue(operation('completed', 'git.merge.abort'));
  render(<GitWorkspace jobId={jobId} basePath="/workbench" session={session} capabilities={supported} pollIntervalMs={1} />);
  await screen.findByText('The conflict list could not be read. Refresh to retry, or explicitly abort an in-progress merge. No conflicts are assumed resolved.');
  expect(screen.getByRole('heading', { name: 'Source repository' })).toBeTruthy();
  fireEvent.click(screen.getByRole('button', { name: 'Abort merge' }));
  await waitFor(() => expect(transport.post).toHaveBeenCalledOnce());
  expect(transport.post.mock.calls[0]?.[2]).toBe('gitMergeAbortRequest');
  expect(transport.post.mock.calls[0]?.[3]).toMatchObject({ action: 'git.merge.abort',
    guards: { repositoryVersion: 'repo_v1', worktreeVersion: 'tree_v1' } });
});

it('resolves a conflict with a concurrency token, stages only reviewed files and can abort', async () => {
  conflictState = { repositoryId, worktreeId, mergeInProgress: true, integration: { operationId: 'operation_7', strategy: 'merge',
    branch: 'refs/heads/main', headBeforeObjectId: head, targetObjectId: other, trackingRefName: 'refs/remotes/origin/main', startedAt: '2026-10-25T00:00:00Z' },
    files: [{ fileId: 'file_conflict', path: 'src/a.c', pathEscaped: false, baseObjectId: older, oursObjectId: head, theirsObjectId: other } as never] };
  transport.post.mockResolvedValue(operation('completed', 'git.conflict.save'));
  mount();
  expect(await screen.findByText(/Merging refs\/remotes\/origin\/main/)).toBeTruthy();
  expect(screen.getByRole('button', { name: 'Stage reviewed resolutions' })).toHaveProperty('disabled', true);
  fireEvent.click(screen.getByRole('button', { name: 'Review src/a.c' }));
  expect(await screen.findByText('int a = 2;')).toBeTruthy();
  fireEvent.click(screen.getByRole('button', { name: 'Use the remote version' }));
  await waitFor(() => expect(transport.post).toHaveBeenCalledOnce());
  expect(transport.post.mock.calls[0]?.slice(2, 4)).toEqual(['gitConflictSaveRequest', expect.objectContaining({ action: 'git.conflict.save',
    fileId: 'file_conflict', expectedSha256: 'c'.repeat(64), resolution: 'theirs', content: null })]);
  // The checkbox is enabled again only once the saved file has been read back.
  await waitFor(() => expect(screen.getByRole('checkbox', { name: 'Mark src/a.c reviewed' })).toHaveProperty('disabled', false));
  fireEvent.click(screen.getByRole('checkbox', { name: 'Mark src/a.c reviewed' }));
  fireEvent.click(screen.getByRole('button', { name: 'Stage reviewed resolutions' }));
  await waitFor(() => expect(transport.post).toHaveBeenCalledTimes(2));
  // Marked at the digest read after the save, never at the pre-save one.
  expect(transport.post.mock.calls[1]?.[3]).toMatchObject({ action: 'git.conflict.complete', files: [{ fileId: 'file_conflict', sha256: 'd'.repeat(64) }] });
  fireEvent.click(screen.getByRole('button', { name: 'Abort merge' }));
  await waitFor(() => expect(transport.post).toHaveBeenCalledTimes(3));
  expect(transport.post.mock.calls[2]?.[3]).toMatchObject({ action: 'git.merge.abort' });
  expect(screen.getByText(/does not commit/)).toBeTruthy();
});

it('previews exactly what a push publishes and submits it only on explicit request', async () => {
  transport.post.mockResolvedValueOnce(operation('completed', 'git.push'));
  mount();
  fireEvent.click(await screen.findByRole('button', { name: 'Preview push' }));
  expect(await screen.findByText('This push publishes 1 commit(s):')).toBeTruthy();
  expect(transport.get).toHaveBeenCalledWith('gitPushPreview', `${base}/push-preview?remote=remote_1&branch=main`);
  expect(transport.post).not.toHaveBeenCalled();
  fireEvent.click(screen.getByRole('button', { name: 'Push 1 commit(s) to main' }));
  await waitFor(() => expect(transport.post).toHaveBeenCalledOnce());
  expect(transport.post.mock.calls[0]?.slice(2, 4)).toEqual(['gitPushRequest', { action: 'git.push', worktreeId, remoteId: 'remote_1',
    localRefId: 'ref_main', remoteBranch: 'main', localObjectId: head, expectedRemoteObjectId: older,
    guards: { repositoryVersion: 'repo_v1', worktreeVersion: 'tree_v1', expectedHeadObjectId: head, expectedRefId: null, expectedRefObjectId: null } }]);
});

it('drops a pending push preview as soon as the selected worktree changes', async () => {
  let resolve!: (value: unknown) => void;
  const pending = new Promise(done => { resolve = done; });
  transport.get.mockImplementation((kind, path) => kind === 'gitPushPreview' ? pending : serve(kind, path));
  mount();
  fireEvent.click(await screen.findByRole('button', { name: 'Preview push' }));
  fireEvent.click(screen.getByRole('button', { name: `Show ${linkedId}` }));
  await waitFor(() => expect(screen.queryByRole('button', { name: 'Preview push' })).toBeNull());
  resolve(await serve('gitPushPreview', `${base}/push-preview?remote=remote_1&branch=main`));
  await pending;
  expect(screen.queryByRole('button', { name: /^Push / })).toBeNull();
  expect(transport.post).not.toHaveBeenCalled();
});

it('refuses to offer a non-fast-forward push and asks to reconcile an unconfirmed one', async () => {
  pushState = { fastForward: false, unconfirmed: null };
  const view = mount();
  fireEvent.click(await screen.findByRole('button', { name: 'Preview push' }));
  expect(await screen.findByText(/would not fast-forward the remote branch/)).toBeTruthy();
  expect(screen.queryByRole('button', { name: /^Push / })).toBeNull();
  view.unmount();
  pushState = { fastForward: true, unconfirmed: 'operation_9' };
  transport.post.mockResolvedValueOnce(operation('completed', 'git.push.reconcile'));
  mount();
  fireEvent.click(await screen.findByRole('button', { name: 'Preview push' }));
  fireEvent.click(await screen.findByRole('button', { name: 'Reconcile with the remote' }));
  await waitFor(() => expect(transport.post).toHaveBeenCalledOnce());
  expect(transport.post.mock.calls[0]?.[3]).toMatchObject({ action: 'git.push.reconcile', pushOperationId: 'operation_9' });
  expect(screen.queryByRole('button', { name: /^Push / })).toBeNull();
});

it('offers cancellation while the first repository is being cloned', async () => {
  listing = [];
  transport.post.mockResolvedValueOnce({ data: { ...operation('running', 'git.clone').data, progress: { phase: 'Receiving objects', percent: 10 } } });
  let cancelled = false;
  operationOverride = () => cancelled ? { ...operation('cancelled', 'git.clone').data, message: 'The clone was cancelled.' }
    : { ...operation('running', 'git.clone').data, progress: { phase: 'Receiving objects', percent: 20 } };
  mount();
  fireEvent.input(await screen.findByLabelText('Remote URL'), { target: { value: 'https://git.example.org/team/project.git' } });
  fireEvent.click(screen.getByRole('button', { name: 'Clone repository' }));
  transport.post.mockImplementationOnce(() => {
    cancelled = true;
    return Promise.resolve({ data: { ...operation('cancelling', 'git.clone').data } });
  });
  await waitFor(() => expect(transport.post).toHaveBeenCalledOnce());
  expect(await screen.findByText(/Receiving objects 20%/)).toBeTruthy();
  fireEvent.click(screen.getByRole('button', { name: 'Cancel transfer' }));
  await waitFor(() => expect(transport.post).toHaveBeenCalledTimes(2));
  expect(transport.post.mock.calls[1]?.slice(1, 4)).toEqual([`/jobs/${jobId}/repositories/${repositoryId}/operations/operation_1/cancel`,
    'gitOperationCancelRequest', { action: 'git.cancel' }]);
  expect(await screen.findByText(/Clone repository did not complete: The clone was cancelled/)).toBeTruthy();
});

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

it('shows the selected work tree worker lock before checkout and removal, without blocking reads or ref creation', async () => {
  entries = [];
  const notice = { code: 'active-worker', message: 'A worker owns this work tree. Switching and removal wait; refresh after it finishes.' };
  transport.get.mockImplementation(async (kind, path) => {
    if (kind === 'gitStatus') return { data: { ...status(false), worktreeId: path.includes(`worktree=${linkedId}`) ? linkedId : worktreeId, notices: [notice] } };
    return serve(kind, path);
  });
  mount();
  expect(await screen.findByText(notice.message)).toBeTruthy();
  expect(screen.getByRole('button', { name: 'Switch to topic' })).toHaveProperty('disabled', true);
  fireEvent.click(screen.getByRole('button', { name: `Show ${linkedId}` }));
  await waitFor(() => expect(transport.get.mock.calls.some(call => call[1].includes(`worktree=${linkedId}`))).toBe(true));
  await waitFor(() => expect(screen.getByRole('button', { name: `Show ${linkedId}` })).toHaveProperty('disabled', true));
  expect(screen.getByRole('button', { name: `Remove ${linkedId}` })).toHaveProperty('disabled', true);
  expect(screen.getByRole('button', { name: 'Create branch at HEAD' })).toHaveProperty('disabled', false);
  expect(screen.getByRole('button', { name: 'Older commits' })).toHaveProperty('disabled', false);
  expect(transport.post).not.toHaveBeenCalled();
  transport.get.mockImplementation(async (kind, path) => {
    if (kind === 'gitStatus') return { data: { ...status(false), worktreeId: linkedId } };
    return serve(kind, path);
  });
  fireEvent.click(screen.getByRole('button', { name: 'Refresh repository' }));
  await waitFor(() => expect(screen.getByRole('button', { name: 'Switch to topic' })).toHaveProperty('disabled', false));
  expect(screen.getByRole('button', { name: `Remove ${linkedId}` })).toHaveProperty('disabled', false);
});

it('retains the selected linked tree after a refused removal and prevents tree changes during the mutation', async () => {
  entries = [];
  transport.get.mockImplementation(async (kind, path) => {
    if (kind === 'gitStatus') return { data: { ...status(false), worktreeId: path.includes(`worktree=${linkedId}`) ? linkedId : worktreeId } };
    return serve(kind, path);
  });
  const gate = deferred();
  transport.post.mockImplementationOnce(async () => { await gate.promise; throw new ApiClientError('http_error', { status: 409 }); });
  mount();
  fireEvent.click(await screen.findByRole('button', { name: `Show ${linkedId}` }));
  await waitFor(() => expect(screen.getByRole('button', { name: `Remove ${linkedId}` })).toHaveProperty('disabled', false));
  fireEvent.click(screen.getByRole('button', { name: `Remove ${linkedId}` }));
  await waitFor(() => expect(transport.post).toHaveBeenCalledOnce());
  expect(screen.getByRole('button', { name: `Show ${worktreeId}` })).toHaveProperty('disabled', true);
  gate.resolve();
  await screen.findByText(/The server refused Remove/);
  await waitFor(() => expect(transport.get.mock.calls.filter(call => call[0] === 'gitRepositories')).toHaveLength(3));
  expect(screen.getByRole('button', { name: `Show ${linkedId}` })).toHaveProperty('disabled', true);
  expect(transport.post.mock.calls[0]?.[3]).toMatchObject({ worktreeId: linkedId });
});

it.each(['diff selection', 'diff refresh', 'history refresh'])('drops obsolete errors after a newer %s', async scenario => {
  const gate = deferred();
  let answered = false;
  transport.get.mockImplementation(async (kind, path) => {
    if ((scenario.startsWith('diff') && kind === 'gitDiff' && path.includes('scope=unstaged')) ||
        (scenario === 'history refresh' && kind === 'gitHistory' && path.includes('cursor='))) {
      await gate.promise; answered = true;
      throw new ApiClientError('http_error', { status: 409 });
    }
    return serve(kind, path);
  });
  mount();
  await screen.findByRole('group', { name: 'Not staged' });
  if (scenario === 'history refresh') fireEvent.click(screen.getByRole('button', { name: 'Older commits' }));
  else fireEvent.click(within(screen.getByRole('group', { name: 'Not staged' })).getByRole('button', { name: 'Show diff for src/util.c' }));
  if (scenario === 'diff selection') {
    fireEvent.click(within(screen.getByRole('group', { name: 'Staged' })).getByRole('button', { name: 'Show diff for src/util.c' }));
    await screen.findByText('Staged diff: src/util.c');
  } else {
    historyPages.first = { entries: [commitSummary(other, 'New generation', false)], nextCursor: null };
    fireEvent.click(screen.getByRole('button', { name: 'Refresh repository' }));
    await screen.findByText('New generation');
  }
  gate.resolve();
  await waitFor(() => expect(answered).toBe(true));
  expect(screen.getByRole('status').textContent).toBe('');
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
