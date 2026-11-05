import { readFileSync } from 'node:fs';
import { resolve } from 'node:path';
import { fireEvent, render, screen } from '@testing-library/preact';
import { beforeEach, expect, it, vi } from 'vitest';
import type * as ClientModule from '../src/api/client';
import { decodeContract } from '../src/api/decode';
import { StorageSummary } from '../src/jobs/StorageSummary';

// #621: the protected-job count is an exact uint64 sum and must not round through Number.
const transport = vi.hoisted(() => ({ get: vi.fn<(kind: string, path: string, options: { signal: AbortSignal }) => Promise<unknown>>() }));
vi.mock('../src/api/client', async load => ({ ...await load<typeof ClientModule>(), createApiClient: () => transport }));

type Fixture = { data: Record<string, unknown> & { protectedJobs: unknown[] } };
const fixture = (name: string) => JSON.parse(readFileSync(resolve(process.cwd(), `../contracts/web/v1/fixtures/${name}.json`), 'utf8')) as Fixture;

function preview(omittedProtectedJobs: string, protectedCount: number) {
  const document = fixture('maintenance-preview');
  document.data.protectedJobs = document.data.protectedJobs.slice(0, protectedCount);
  document.data.omittedProtectedJobs = omittedProtectedJobs;
  // The fixture is a valid response under the published contract before it reaches the component.
  const decoded = decodeContract(JSON.stringify(document), { mode: 'response' });
  expect(decoded.kind).toBe('maintenancePreview');
  return decoded;
}

let current: unknown;
beforeEach(() => {
  transport.get.mockReset();
  transport.get.mockImplementation(kind => Promise.resolve(kind === 'storageSummary' ? fixture('storage-summary') : current));
});

it.each([
  ['0', 0, '0'],
  ['0', 1, '1'],
  ['1', 0, '1'],
  ['9007199254740993', 1, '9007199254740994'],
  ['18446744073709551614', 1, '18446744073709551615'],
  ['18446744073709551615', 0, '18446744073709551615'],
])('renders %s omitted plus %i listed protected jobs exactly as %s', async (omitted, listed, expected) => {
  current = preview(omitted, listed);
  render(<StorageSummary basePath="/nested" />);
  fireEvent.click(screen.getByRole('button', { name: 'Read storage and maintenance preview' }));
  const line = await screen.findByText(/jobs are protected from deletion now/);
  expect(line.textContent).toBe(`${expected} jobs are protected from deletion now (active work, pins, downloads or holds).`);
  expect(transport.get.mock.calls.map(([kind, path]) => [kind, path])).toEqual([
    ['storageSummary', '/storage'], ['maintenancePreview', '/storage/maintenance-preview'],
  ]);
});
