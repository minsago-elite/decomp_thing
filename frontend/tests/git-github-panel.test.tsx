import { fireEvent, render, screen, waitFor } from '@testing-library/preact';
import { expect, it, vi } from 'vitest';
import type { Capability, GitHubStatus, GitRemotes } from '../src/api/generated';
import { GitHubPanel } from '../src/git/GitHubPanel';

const head = 'a'.repeat(40), base = 'b'.repeat(40), moved = 'c'.repeat(40);
const capability: Capability = { id: 'github', state: 'supported', reasonCode: null, message: null,
  workflows: [], agentContractVersion: null, limits: null };
function remotes(baseObjectId = base): GitRemotes {
  return { repositoryId: 'repository_1', configured: true, remotes: ['origin', 'upstream'].map((name, index) => ({
    remoteId: `remote_${index + 1}`, name, transport: 'https', display: `https://example.org/${name}.git`,
    credential: 'configured', allowed: true, fetchedAt: null, fetchOperationId: null,
    trackingRefs: ['main', 'release', 'stable'].map(branch => ({ refId: `ref_${name}_${branch}`,
      name: `refs/remotes/${name}/${branch}`, objectId: branch === 'main' ? head : baseObjectId })),
  })) };
}
function status(remoteId: string, headBranch: string, baseBranch: string | null): GitHubStatus {
  return { repositoryId: 'repository_1', remoteId, access: 'write', repository: 'owner/repository', headBranch,
    pushedObjectId: head, baseBranch, baseObjectId: base, commitCount: '1',
    commits: [{ objectId: head, subject: 'Reviewed commit' }], pulls: [], problem: null, unconfirmedOperationIds: [] };
}
function setup() {
  const readStatus = vi.fn((remote: string, branch: string, baseBranch: string | null) => Promise.resolve(status(remote, branch, baseBranch)));
  const props = { capability, remotes: remotes(), branch: 'refs/heads/main', writable: true, readStatus,
    onCreate: vi.fn(() => Promise.resolve(true)), onReconcile: vi.fn(() => Promise.resolve(true)) };
  return { props, readStatus };
}
async function review() {
  fireEvent.click(screen.getByRole('button', { name: 'Check pull requests' }));
  await screen.findByRole('button', { name: 'Create pull request' });
}

it('never resurrects a reviewed range after switching away from a remote and back', async () => {
  const { props } = setup();
  render(<GitHubPanel {...props} />);
  await review();
  fireEvent.change(screen.getByLabelText('Remote'), { target: { value: 'remote_2' } });
  fireEvent.change(screen.getByLabelText('Remote'), { target: { value: 'remote_1' } });
  expect(screen.queryByRole('button', { name: 'Create pull request' })).toBeNull();
  expect(props.onCreate).not.toHaveBeenCalled();
});

it('discards a late read even after switching away from its remote and back', async () => {
  const { props, readStatus } = setup();
  let finish!: (result: GitHubStatus) => void;
  readStatus.mockImplementationOnce(() => new Promise(resolve => { finish = resolve; }));
  render(<GitHubPanel {...props} />);
  fireEvent.click(screen.getByRole('button', { name: 'Check pull requests' }));
  fireEvent.change(screen.getByLabelText('Remote'), { target: { value: 'remote_2' } });
  fireEvent.change(screen.getByLabelText('Remote'), { target: { value: 'remote_1' } });
  finish(status('remote_1', 'main', 'release'));
  await waitFor(() => expect(readStatus).toHaveResolved());
  expect(screen.queryByRole('button', { name: 'Create pull request' })).toBeNull();
  await review();
});

it('discards a late branch read after switching branches and returning', async () => {
  const { props, readStatus } = setup();
  let finish!: (result: GitHubStatus) => void;
  readStatus.mockImplementationOnce(() => new Promise(resolve => { finish = resolve; }));
  const view = render(<GitHubPanel {...props} />);
  fireEvent.click(screen.getByRole('button', { name: 'Check pull requests' }));
  view.rerender(<GitHubPanel {...props} branch="refs/heads/topic" />);
  view.rerender(<GitHubPanel {...props} />);
  finish(status('remote_1', 'main', 'release'));
  await waitFor(() => expect(readStatus).toHaveResolved());
  expect(screen.queryByRole('button', { name: 'Create pull request' })).toBeNull();
  await review();
});

it('drops the entire review when the tracked base changes, even if the head is unchanged', async () => {
  const { props } = setup();
  const view = render(<GitHubPanel {...props} />);
  await review();
  view.rerender(<GitHubPanel {...props} remotes={remotes(moved)} />);
  expect(screen.queryByText('Reviewed commit')).toBeNull();
  expect(screen.queryByRole('button', { name: 'Create pull request' })).toBeNull();
  view.rerender(<GitHubPanel {...props} />);
  expect(screen.queryByRole('button', { name: 'Create pull request' })).toBeNull();
});

it('does not let an outstanding read restore a review after choosing another base', async () => {
  const { props, readStatus } = setup();
  render(<GitHubPanel {...props} />);
  await review();
  let finish!: (result: GitHubStatus) => void;
  readStatus.mockImplementationOnce(() => new Promise(resolve => { finish = resolve; }));
  fireEvent.click(screen.getByRole('button', { name: 'Check pull requests' }));
  fireEvent.change(screen.getByLabelText('Base branch'), { target: { value: 'stable' } });
  finish(status('remote_1', 'main', 'release'));
  await waitFor(() => expect(readStatus).toHaveResolvedTimes(2));
  expect(screen.queryByRole('button', { name: 'Create pull request' })).toBeNull();
  await review();
  expect(readStatus).toHaveBeenLastCalledWith('remote_1', 'main', 'stable');
});
