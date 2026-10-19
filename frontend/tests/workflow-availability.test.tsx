import { readFileSync } from 'node:fs';
import { resolve } from 'node:path';
import { cleanup, render, within } from '@testing-library/preact';
import { afterEach, expect, it } from 'vitest';
import type { Bootstrap, Capability } from '../src/api/generated';
import { WorkflowAvailability } from '../src/jobs/WorkflowAvailability';
import type { RuntimeSnapshot } from '../src/session/session';

afterEach(cleanup);

function snapshot(capabilities: Capability[] = []): RuntimeSnapshot {
  const { data } = JSON.parse(readFileSync(resolve(process.cwd(), '../contracts/web/v1/fixtures/bootstrap.json'), 'utf8')) as { data: Bootstrap };
  const { applicationBuildId, uiBuildId, readiness, limits, runtime } = data;
  return { applicationBuildId, uiBuildId, readiness, capabilities, limits, runtime };
}

function capability(state: Capability['state'], workflows: Capability['workflows'] = ['repair']): Capability {
  return { id: 'harness_acp', state, reasonCode: 'SELECTED_HARNESS_NOT_READY',
    message: 'The selected harness cannot start this workflow.', workflows, agentContractVersion: 1, limits: null };
}

it('shows all five workflow states without start controls or alternate-harness selection', () => {
  const workflows: Capability['workflows'] = ['explore', 'reconstruct', 'build', 'validate', 'repair'];
  const runtime = snapshot([capability('unavailable', workflows), {
    ...capability('supported', workflows), id: 'harness_builtin', reasonCode: null,
    message: 'Another harness reports support.',
  }]);
  const view = render(<WorkflowAvailability runtime={runtime} />);
  expect(view.getAllByRole('heading', { level: 4 }).map(heading => heading.textContent))
    .toEqual(['Exploration', 'Reconstruction', 'Build', 'Validation', 'Repair']);
  expect(view.getAllByText('Starting this workflow is unavailable in this preview.')).toHaveLength(5);
  expect(view.getAllByText('SELECTED_HARNESS_NOT_READY')).toHaveLength(5);
  expect(view.getAllByText('Another harness reports support.')).toHaveLength(5);
  expect(view.getByText(/A supported harness alone does not confirm/)).toBeTruthy();
  expect(view.queryByRole('button')).toBeNull();
  expect(view.queryByRole('combobox')).toBeNull();
});

it('matches reports only to their declared workflows and leaves missing reports unknown', () => {
  const view = render(<WorkflowAvailability runtime={snapshot([capability('unsupported')])} />);
  const list = view.getByRole('list', { name: 'Workflow availability' });
  const repair = within(within(list).getByRole('heading', { name: 'Repair' }).closest('li')!);
  expect(repair.getByText('unsupported')).toBeTruthy();
  expect(repair.getByText('SELECTED_HARNESS_NOT_READY')).toBeTruthy();
  const explore = within(within(list).getByRole('heading', { name: 'Exploration' }).closest('li')!);
  expect(explore.getByText('No capability for this workflow was reported. Its availability is unknown.')).toBeTruthy();
  expect(explore.queryByText('harness_acp')).toBeNull();
  expect(explore.queryByText('unsupported')).toBeNull();
  expect(view.getAllByText('No capability for this workflow was reported. Its availability is unknown.')).toHaveLength(4);
});

it('retains every reported capability and readiness state without inferring job admission', () => {
  const states = ['supported', 'unavailable', 'unsupported', 'unknown'] as const;
  const readiness = ['ready', 'degraded', 'draining', 'unavailable'] as const;
  for (const [index, state] of states.entries()) {
    const view = render(<WorkflowAvailability runtime={{ ...snapshot([capability(state)]), readiness: readiness[index]! }} />);
    const repair = within(view.getByRole('heading', { name: 'Repair' }).closest('li')!);
    expect(repair.getByText(state)).toBeTruthy();
    expect(view.getByText(/^Last reported server readiness:/).textContent)
      .toBe('Last reported server readiness: ' + readiness[index]);
    expect(view.getByText(/Job-specific input and revision prerequisites have not been reported/)).toBeTruthy();
    expect(view.queryByRole('button')).toBeNull();
    view.unmount();
  }
});

it('renders reported reason text and identities without interpreting markup', () => {
  const report = { ...capability('unavailable'), message: '<img src=x onerror=run()> & unavailable',
    reasonCode: 'NO_PROVIDER_CHANNEL' };
  const view = render(<WorkflowAvailability runtime={snapshot([report])} />);
  expect(view.getByText(report.message)).toBeTruthy();
  expect(view.getByText('NO_PROVIDER_CHANNEL')).toBeTruthy();
  expect(view.container.querySelector('img')).toBeNull();
  expect(view.queryByRole('button')).toBeNull();
});

it('replaces obsolete reports when the authenticated runtime snapshot changes', () => {
  const view = render(<WorkflowAvailability runtime={snapshot([capability('unavailable')])} />);
  expect(view.getByText('SELECTED_HARNESS_NOT_READY')).toBeTruthy();
  view.rerender(<WorkflowAvailability runtime={snapshot([])} />);
  expect(view.queryByText('SELECTED_HARNESS_NOT_READY')).toBeNull();
  expect(view.queryByText('harness_acp')).toBeNull();
  expect(view.getAllByText('No capability for this workflow was reported. Its availability is unknown.')).toHaveLength(5);
  expect(view.queryByRole('button')).toBeNull();
});
