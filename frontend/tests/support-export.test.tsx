import { readFileSync } from 'node:fs';
import { resolve } from 'node:path';
import { act, cleanup, fireEvent, render, screen } from '@testing-library/preact';
import axe from 'axe-core';
import { afterEach, expect, it, vi } from 'vitest';
import { createApiClient } from '../src/api/client';
import { ApiClientError } from '../src/api/errors';
import { decodeResponse } from '../src/api/decode';
import type { SupportExport as SupportExportData } from '../src/api/generated';
import { SupportExport, supportExportDownload } from '../src/jobs/SupportExport';

type Client = ReturnType<typeof createApiClient>;
const fixture = (name: string) => JSON.parse(readFileSync(resolve(process.cwd(), `../contracts/web/v1/fixtures/${name}`), 'utf8')) as {
  requestId: string; data: SupportExportData;
};
const server = fixture('support-export-server.json');
const job = fixture('support-export-job.json');
afterEach(() => { cleanup(); vi.restoreAllMocks(); });

function fakeClient(implementation: (kind: string, path: string) => Promise<unknown>) {
  const get = vi.fn(implementation);
  return { get, client: { get } as unknown as Client };
}
async function click(name: string) {
  await act(async () => { fireEvent.click(screen.getByRole('button', { name })); await Promise.resolve(); });
}

it('previews an explicitly scoped export only on request and downloads exactly the previewed document', async () => {
  const { get, client } = fakeClient(() => Promise.resolve({ requestId: server.requestId, data: server.data }));
  render(<SupportExport client={client} />);
  expect(get).not.toHaveBeenCalled();
  await click('Preview export');
  expect(get).toHaveBeenCalledOnce();
  expect(get.mock.calls[0]?.slice(0, 2)).toEqual(['supportExport', '/support-export?scope=server']);
  expect(await screen.findByText('Preview ready. Review it before downloading.')).toBeTruthy();
  expect(screen.getByText('web-redaction-v1')).toBeTruthy();
  expect(screen.getByText('runtime, limits, capabilities, recovery, audit')).toBeTruthy();
  expect(screen.getByText('credentials').parentElement?.textContent).toBe('credentials: credentials are never exported');
  expect(screen.getByText('job').parentElement?.textContent).toBe('job: outside the selected scope');
  expect(document.activeElement?.id).toBe('support-export-preview');
  const link = screen.getByRole('link', { name: /Download previewed export/ });
  const expected = supportExportDownload(server.data, server.requestId);
  expect(link.getAttribute('download')).toBe('support-export-server.json');
  const text = decodeURIComponent((link.getAttribute('href') ?? '').replace('data:application/json;charset=utf-8,', ''));
  expect((JSON.parse(text) as { data: unknown }).data).toEqual(server.data);
  // The saved file is a complete contract envelope that the shared decoder accepts.
  expect(decodeResponse(text, 'supportExport').data).toEqual(server.data);
  expect(decodeResponse(text, 'supportExport').requestId).toBe(server.requestId);
  expect(link.getAttribute('href')).toBe(expected?.href);
  expect(get).toHaveBeenCalledOnce();
});

it('validates the job scope before any request and reports omitted unreadable sections as unknown', async () => {
  const { get, client } = fakeClient(() => Promise.resolve({ requestId: job.requestId, data: job.data }));
  render(<SupportExport client={client} />);
  fireEvent.click(screen.getByRole('radio', { name: /One job/ }));
  fireEvent.input(screen.getByLabelText(/Job ID/), { target: { value: '../etc/passwd' } });
  await click('Preview export');
  expect(screen.getByRole('alert').textContent).toBe('Enter a 32-character lowercase hexadecimal job ID.');
  expect(screen.getByLabelText(/Job ID/).getAttribute('aria-invalid')).toBe('true');
  expect(get).not.toHaveBeenCalled();
  const id = job.data.scope.jobId ?? '';
  fireEvent.input(screen.getByLabelText(/Job ID/), { target: { value: id } });
  await click('Preview export');
  expect(get.mock.calls[0]?.[1]).toBe(`/support-export?scope=job&jobId=${id}`);
  expect((await screen.findByText('recovery')).parentElement?.textContent).toBe('recovery: could not be read; its state is unknown');
  expect(screen.getByRole('link', { name: /Download previewed export/ }).getAttribute('download')).toBe(`support-export-job-${id}.json`);
});

it('keeps a failed preview explicit and never offers a stale download', async () => {
  let fail = false;
  const { client } = fakeClient(() => fail ? Promise.reject(new ApiClientError('http_error', { status: 503, requestId: 'request_example_9' }))
    : Promise.resolve({ requestId: server.requestId, data: server.data }));
  render(<SupportExport client={client} />);
  await click('Preview export');
  expect(await screen.findByRole('link', { name: /Download previewed export/ })).toBeTruthy();
  fail = true;
  await click('Preview export');
  expect(screen.queryByRole('link', { name: /Download previewed export/ })).toBeNull();
  expect(screen.getByRole('status').textContent).toContain('The support export could not be prepared.');
});

it('decodes both contract fixtures through the real typed client', async () => {
  for (const document of [server, job]) {
    const fetch = vi.fn(() => Promise.resolve(new Response(JSON.stringify({ apiVersion: 1, kind: 'supportExport', requestId: document.requestId, data: document.data }), {
      status: 200, headers: { 'Content-Type': 'application/json; charset=utf-8', 'X-Request-ID': document.requestId },
    })));
    const client = createApiClient({ basePath: '/', fetch });
    const response = await client.get('supportExport', '/support-export?scope=server');
    expect(response.data).toEqual(document.data);
  }
});

it('has no automated WCAG A/AA violations in the invalid and previewed states', async () => {
  const { client } = fakeClient(() => Promise.resolve({ requestId: job.requestId, data: job.data }));
  render(<main><SupportExport client={client} /></main>);
  const check = async () => (await axe.run(document.body, {
    runOnly: { type: 'tag', values: ['wcag2a', 'wcag2aa', 'wcag21a', 'wcag21aa', 'wcag22aa'] },
    rules: { 'color-contrast': { enabled: false } }, resultTypes: ['violations'],
  })).violations.map(violation => violation.id);
  fireEvent.click(screen.getByRole('radio', { name: /One job/ }));
  await click('Preview export');
  expect(await check()).toEqual([]);
  fireEvent.input(screen.getByLabelText(/Job ID/), { target: { value: job.data.scope.jobId } });
  await click('Preview export');
  await screen.findByRole('link', { name: /Download previewed export/ });
  expect(await check()).toEqual([]);
});
