import { readFileSync } from 'node:fs';
import { resolve } from 'node:path';
import { cleanup, render, screen, within } from '@testing-library/preact';
import { afterEach, expect, it } from 'vitest';
import type { Run } from '../src/api/generated';
import { decodeContract } from '../src/api/decode';
import { RecordedConfiguration } from '../src/jobs/RecordedConfiguration';

const fixture = (name: string) => readFileSync(resolve(process.cwd(), `../contracts/web/v1/fixtures/${name}.json`), 'utf8');
const run = (name: string) => (decodeContract(fixture(name), { mode: 'producer' }) as { data: Run }).data;
afterEach(cleanup);

it('shows the exact admission record, including harness provenance, as recorded with the attempt', () => {
  const recorded = run('run-configured-agent');
  render(<RecordedConfiguration run={recorded} />);
  const section = within(screen.getByRole('region', { name: 'Recorded configuration' }));
  expect(section.getByText('workflow-reconstruct-agent-acp')).toBeTruthy();
  expect(section.getByText('fixture-agent')).toBeTruthy();
  expect(section.getByText('a'.repeat(64))).toBeTruthy();
  expect(section.getByText('0.30.1')).toBeTruthy();
  expect(section.getByText('Current')).toBeTruthy();
  expect(section.getByText(/is not the configuration and does not prove that an agent session ran/)).toBeTruthy();
});

it('keeps an attempt without a record distinct from one that never contacts an agent', () => {
  const { unmount } = render(<RecordedConfiguration run={run('run-completed-unaccepted')} />);
  expect(screen.getByText(/recorded before admission configuration was retained/)).toBeTruthy();
  unmount();
  const evidence = run('run-configured-agent');
  render(<RecordedConfiguration run={{ ...evidence, harnessCapabilityId: 'evidence-only', configuration: {
    ...evidence.configuration!, optionId: 'workflow-reconstruct-evidence-only', mode: 'evidence-only', contactsAgent: false, harness: null,
  } }} />);
  expect(screen.getByText('No agent harness: this attempt never contacts an agent.')).toBeTruthy();
});

it('refuses a recorded harness that disagrees with the harness the attempt submitted', () => {
  expect(() => decodeContract(fixture('invalid-run-configuration-harness-mismatch'), { mode: 'producer' })).toThrow();
  expect(() => decodeContract(fixture('invalid-run-configuration-secret-field'), { mode: 'producer' })).toThrow();
});
