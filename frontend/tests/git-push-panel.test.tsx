import { act, fireEvent, render, screen } from '@testing-library/preact';
import { expect, it, vi } from 'vitest';
import type { GitPushPreview, GitRemotes } from '../src/api/generated';
import { GitPushPanel } from '../src/git/GitPushPanel';

const remotes: GitRemotes = { repositoryId: 'repository_1', configured: true, remotes: ['a', 'b'].map(id => ({
  remoteId: id, name: id, transport: 'https', display: `https://${id}.example/repo.git`, credential: 'none', allowed: true,
  fetchedAt: null, fetchOperationId: null, trackingRefs: [],
})) };
function preview(remoteId = 'a', remoteBranch = 'main'): GitPushPreview {
  return { repositoryId: 'repository_1', worktreeId: 'worktree_1', remoteId, destination: `https://${remoteId}.example/repo.git`,
    allowed: true, localRefId: 'ref_main', localRefName: 'refs/heads/main', localObjectId: 'a'.repeat(40), remoteBranch,
    expectedRemoteObjectId: 'b'.repeat(40), fetchedAt: null, remoteState: 'unknown', fastForward: true, commitCount: '1',
    commits: [{ objectId: 'a'.repeat(40), subject: 'Reviewed commit' }], unconfirmedPushOperationId: null };
}
function deferred() {
  let resolve!: (value: GitPushPreview | null) => void;
  const promise = new Promise<GitPushPreview | null>(done => { resolve = done; });
  return { promise, resolve };
}

it('invalidates pending responses on remote and branch edits, even if inputs change back', async () => {
  const pending = [deferred(), deferred()];
  const readPreview = vi.fn().mockReturnValueOnce(pending[0]!.promise).mockReturnValueOnce(pending[1]!.promise);
  const onPush = vi.fn().mockResolvedValue(true);
  render(<GitPushPanel remotes={remotes} branch="refs/heads/main" writable readPreview={readPreview} onPush={onPush} onReconcile={vi.fn()} />);
  fireEvent.click(screen.getByRole('button', { name: 'Preview push' }));
  fireEvent.change(screen.getByLabelText('Remote'), { target: { value: 'b' } });
  fireEvent.change(screen.getByLabelText('Remote'), { target: { value: 'a' } });
  await act(async () => { pending[0]!.resolve(preview()); await pending[0]!.promise; });
  expect(screen.queryByRole('button', { name: /^Push / })).toBeNull();
  fireEvent.click(screen.getByRole('button', { name: 'Preview push' }));
  fireEvent.input(screen.getByLabelText('Remote branch'), { target: { value: 'topic' } });
  fireEvent.input(screen.getByLabelText('Remote branch'), { target: { value: 'main' } });
  await act(async () => { pending[1]!.resolve(preview()); await pending[1]!.promise; });
  expect(screen.queryByRole('button', { name: /^Push / })).toBeNull();
  expect(onPush).not.toHaveBeenCalled();
});

it('only the latest preview can supply an explicit push, not an out-of-order response', async () => {
  const first = deferred(), second = deferred();
  const readPreview = vi.fn().mockReturnValueOnce(first.promise).mockReturnValueOnce(second.promise);
  const onPush = vi.fn().mockResolvedValue(true);
  render(<GitPushPanel remotes={remotes} branch="refs/heads/main" writable readPreview={readPreview} onPush={onPush} onReconcile={vi.fn()} />);
  fireEvent.click(screen.getByRole('button', { name: 'Preview push' }));
  fireEvent.change(screen.getByLabelText('Remote'), { target: { value: 'b' } });
  fireEvent.input(screen.getByLabelText('Remote branch'), { target: { value: 'topic' } });
  fireEvent.click(screen.getByRole('button', { name: 'Preview push' }));
  await act(async () => { second.resolve(preview('b', 'topic')); await second.promise; });
  await act(async () => { first.resolve(preview()); await first.promise; });
  expect(screen.queryByText('https://a.example/repo.git')).toBeNull();
  expect(screen.getByText('https://b.example/repo.git')).toBeTruthy();
  expect(onPush).not.toHaveBeenCalled();
  fireEvent.click(screen.getByRole('button', { name: 'Push 1 commit(s) to topic' }));
  expect(onPush).toHaveBeenCalledExactlyOnceWith(preview('b', 'topic'));
});

it('a newer request for the same destination also invalidates an older preview', async () => {
  const first = deferred(), second = deferred();
  const readPreview = vi.fn().mockReturnValueOnce(first.promise).mockReturnValueOnce(second.promise);
  render(<GitPushPanel remotes={remotes} branch="refs/heads/main" writable readPreview={readPreview} onPush={vi.fn()} onReconcile={vi.fn()} />);
  fireEvent.click(screen.getByRole('button', { name: 'Preview push' }));
  fireEvent.click(screen.getByRole('button', { name: 'Preview push' }));
  await act(async () => { second.resolve(null); await second.promise; });
  await act(async () => { first.resolve(preview()); await first.promise; });
  expect(screen.queryByRole('button', { name: /^Push / })).toBeNull();
});

it('keyed repository and worktree context changes discard both installed and pending previews', async () => {
  const first = deferred(), second = deferred();
  const readPreview = vi.fn().mockReturnValueOnce(first.promise).mockReturnValueOnce(second.promise);
  const onPush = vi.fn().mockResolvedValue(true);
  const panel = (context: string) => <GitPushPanel key={context} remotes={remotes} branch="refs/heads/main" writable
    readPreview={readPreview} onPush={onPush} onReconcile={vi.fn()} />;
  const view = render(panel('repository_1:worktree_1'));
  fireEvent.click(screen.getByRole('button', { name: 'Preview push' }));
  await act(async () => { first.resolve(preview()); await first.promise; });
  expect(screen.getByRole('button', { name: /^Push / })).toBeTruthy();
  fireEvent.click(screen.getByRole('button', { name: 'Preview push' }));
  view.rerender(panel('repository_2:worktree_2'));
  await act(async () => { second.resolve(preview()); await second.promise; });
  expect(screen.queryByRole('button', { name: /^Push / })).toBeNull();
  expect(onPush).not.toHaveBeenCalled();
});
