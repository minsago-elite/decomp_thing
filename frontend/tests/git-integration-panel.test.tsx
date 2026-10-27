import { act, fireEvent, render, screen, waitFor } from '@testing-library/preact';
import { expect, it, vi } from 'vitest';
import type { GitConflictFile, GitConflicts } from '../src/api/generated';
import { GitIntegrationPanel } from '../src/git/GitIntegrationPanel';

const head = 'a'.repeat(40), target = 'b'.repeat(40);
const file = { fileId: 'file_same_path', path: 'src/a.c', pathEscaped: false,
  baseObjectId: head, oursObjectId: head, theirsObjectId: target };
const integration = (operationId: string): NonNullable<GitConflicts['integration']> => ({ operationId, strategy: 'merge',
  branch: 'refs/heads/main', headBeforeObjectId: head, targetObjectId: target, trackingRefName: 'refs/remotes/origin/main',
  startedAt: '2026-10-25T00:00:00Z' });
const conflicts = (operationId: string): GitConflicts => ({ repositoryId: 'repo_1', worktreeId: 'tree_1', mergeInProgress: true,
  integration: integration(operationId), offset: 0, totalCount: 1, nextOffset: null, files: [file] });
const detail = (_operationId: string, theirs: string): GitConflictFile => ({ repositoryId: 'repo_1', worktreeId: 'tree_1',
  file, supported: true, reason: null, base: 'base', ours: 'same ours', theirs,
  current: 'same ours', currentSha256: 'c'.repeat(64), currentSizeBytes: '9' });
const defaults = { remotes: null, destination: { worktreeId: 'tree_1', headRefName: 'refs/heads/main', headObjectId: head },
  writable: true, readDivergence: () => Promise.resolve(null), onConflictPage: () => undefined };

it('invalidates old detail, draft and checked review after abort and another integration of the same path', async () => {
  const readConflict = vi.fn().mockResolvedValueOnce(detail('merge_1', 'old remote')).mockResolvedValueOnce(detail('merge_2', 'new remote'));
  const onAction = vi.fn().mockResolvedValue(true);
  const props = { ...defaults, readConflict, onAction };
  const view = render(<GitIntegrationPanel {...props} conflicts={conflicts('merge_1')} />);
  fireEvent.click(screen.getByRole('button', { name: 'Review src/a.c' }));
  await screen.findByText('old remote');
  fireEvent.input(screen.getByLabelText('Resolved text'), { target: { value: 'old draft' } });
  fireEvent.click(screen.getByRole('checkbox', { name: 'Mark src/a.c reviewed' }));
  expect(screen.getByRole('button', { name: 'Stage reviewed resolutions' })).toHaveProperty('disabled', false);
  fireEvent.click(screen.getByRole('button', { name: 'Abort merge' }));
  await waitFor(() => expect(onAction).toHaveBeenCalledWith({ kind: 'gitMergeAbortRequest' }));
  view.rerender(<GitIntegrationPanel {...props} conflicts={{ ...conflicts('merge_1'), mergeInProgress: false, integration: null, files: [], totalCount: 0 }} />);
  view.rerender(<GitIntegrationPanel {...props} conflicts={conflicts('merge_2')} />);
  expect(screen.queryByText('old remote')).toBeNull();
  expect(screen.queryByLabelText('Resolved text')).toBeNull();
  expect(screen.getByRole('checkbox', { name: 'Mark src/a.c reviewed' })).toHaveProperty('checked', false);
  expect(screen.getByRole('button', { name: 'Stage reviewed resolutions' })).toHaveProperty('disabled', true);
  fireEvent.click(screen.getByRole('button', { name: 'Review src/a.c' }));
  await screen.findByText('new remote');
  expect(screen.getByLabelText('Resolved text')).toHaveProperty('value', 'same ours');
  fireEvent.click(screen.getByRole('button', { name: 'Use the remote version' }));
  await waitFor(() => expect(onAction).toHaveBeenCalledWith(expect.objectContaining({ kind: 'gitConflictSaveRequest', resolution: 'theirs' })));
});

it('discards late conflict reads from a previous integration even if the path and digest match', async () => {
  let finish!: (value: GitConflictFile) => void;
  const readConflict = vi.fn().mockImplementationOnce(() => new Promise<GitConflictFile>(resolve => { finish = resolve; }))
    .mockResolvedValueOnce(detail('merge_2', 'new remote'));
  const props = { ...defaults, readConflict, onAction: vi.fn().mockResolvedValue(true) };
  const view = render(<GitIntegrationPanel {...props} conflicts={conflicts('merge_1')} />);
  fireEvent.click(screen.getByRole('button', { name: 'Review src/a.c' }));
  view.rerender(<GitIntegrationPanel {...props} conflicts={conflicts('merge_2')} />);
  fireEvent.click(screen.getByRole('button', { name: 'Review src/a.c' }));
  await screen.findByText('new remote');
  await act(() => { finish(detail('merge_1', 'old remote')); return Promise.resolve(); });
  expect(screen.queryByText('old remote')).toBeNull();
  expect(screen.getByText('new remote')).toBeTruthy();
  expect(screen.getByRole('checkbox', { name: 'Mark src/a.c reviewed' })).toHaveProperty('checked', false);
});
