import { readFileSync } from 'node:fs';
import { resolve } from 'node:path';
import { act, fireEvent, render, screen, waitFor } from '@testing-library/preact';
import { expect, it, vi } from 'vitest';
import type { Bootstrap } from '../src/api/generated';
import { ApiClientError } from '../src/api/errors';
import { formatExactBytes } from '../src/copy/format';
import Runtime from '../src/routes/Runtime';
import { createBrowserSession } from '../src/session/session';

it('projects existing session evidence, reports mismatches, and clears it at logout without probes', async () => {
  const fixture = JSON.parse(readFileSync(resolve(process.cwd(), '../contracts/web/v1/fixtures/bootstrap-scheduler-saturated.json'), 'utf8')) as { data: Bootstrap };
  const data = { ...fixture.data, sessionExpiresAt: new Date(Date.now() + 60_000).toISOString() };
  data.limits.maxUploadBytes = '0';
  const gateway = {
    bootstrap: vi.fn(() => Promise.resolve(data)),
    exchange: vi.fn(),
    logout: vi.fn(() => Promise.resolve()),
  };
  const session = createBrowserSession(gateway, '/');
  try {
    await session.initialize({ kind: 'absent' });
    render(<Runtime identity={{ applicationVersion: '0.1.0', uiBuildId: 'old_ui' }} session={session} />);
    expect(screen.getByText('Web workflow scheduler')).toBeTruthy();
    expect(screen.getByText('Queued tasks (count)')).toBeTruthy();
    expect(screen.getAllByText('32')).toHaveLength(2);
    expect(screen.getByText(/approximate aggregate observations/)).toBeTruthy();
    expect(screen.getByText(/own approximate queue position is shown on its attempt page/)).toBeTruthy();
    expect(screen.getByText('degraded')).toBeTruthy();
    expect(screen.getByText('Uploads unavailable')).toBeTruthy();
    expect(screen.getByText('Server instance').nextElementSibling?.textContent).toBe('Not reported');
    expect(screen.getByText('AGENT_NOT_CONFIGURED')).toBeTruthy();
    expect(screen.getByText(/server reports a different UI build/)).toBeTruthy();
    expect(document.body.textContent).not.toContain(data.csrfToken);
    expect(JSON.stringify(session.snapshot())).not.toContain(data.csrfToken);
    expect(gateway.bootstrap).toHaveBeenCalledOnce();
    expect(gateway.exchange).not.toHaveBeenCalled();
    await act(async () => { await session.logout(); });
    expect(screen.queryByText('Web workflow scheduler')).toBeNull();
    expect(screen.queryByText('degraded')).toBeNull();
    expect(screen.queryByText('AGENT_NOT_CONFIGURED')).toBeNull();
    expect(screen.getByText('Runtime information is not connected')).toBeTruthy();
    expect(gateway.bootstrap).toHaveBeenCalledOnce();
  } finally { session.dispose(); }
});


it('reports a new server instance with unchanged builds and does not fetch on render', async () => {
  const fixture = JSON.parse(readFileSync(resolve(process.cwd(), '../contracts/web/v1/fixtures/bootstrap.json'), 'utf8')) as { data: Bootstrap };
  const data = { ...fixture.data, sessionExpiresAt: new Date(Date.now() + 60_000).toISOString() };
  const gateway = { bootstrap: vi.fn().mockResolvedValue(data), exchange: vi.fn(), logout: vi.fn() };
  const session = createBrowserSession(gateway, '/');
  try {
    await session.initialize({ kind: 'absent' });
    render(<Runtime identity={{ applicationVersion: '0.1.0', uiBuildId: data.uiBuildId }} session={session} />);
    expect(screen.getByText('server_fixture_1')).toBeTruthy();
    expect(screen.queryByText(/server reports a different UI build/)).toBeNull();
    expect(gateway.bootstrap).toHaveBeenCalledOnce();
    gateway.bootstrap.mockResolvedValueOnce({ ...data, serverInstanceId: 'server_fixture_2' });
    await act(async () => { await session.refresh(); });
    expect(screen.queryByText('server_fixture_1')).toBeNull();
    expect(screen.getByText('server_fixture_2')).toBeTruthy();
    expect(screen.queryByText(/server reports a different UI build/)).toBeNull();
    expect(gateway.bootstrap).toHaveBeenCalledTimes(2);
    expect(gateway.exchange).not.toHaveBeenCalled();
    expect(gateway.logout).not.toHaveBeenCalled();
    expect(document.body.textContent).not.toContain(data.csrfToken);
  } finally { session.dispose(); }
});

it('retains only the last runtime receipt across a transient reconnect read and ages it without another request', async () => {
  vi.useFakeTimers(); vi.setSystemTime(0);
  let monotonic = 0;
  vi.spyOn(performance, 'now').mockImplementation(() => monotonic);
  const fixture = JSON.parse(readFileSync(resolve(process.cwd(), '../contracts/web/v1/fixtures/bootstrap.json'), 'utf8')) as { data: Bootstrap };
  const data = { ...fixture.data, sessionExpiresAt: new Date(Date.now() + 60_000).toISOString() };
  const gateway = { bootstrap: vi.fn().mockResolvedValueOnce(data).mockRejectedValueOnce(new Error('offline')).mockResolvedValueOnce(data), exchange: vi.fn(), logout: vi.fn() };
  const session = createBrowserSession(gateway, '/');
  try {
    await session.initialize({ kind: 'absent' });
    const view = render(<Runtime identity={{ applicationVersion: '0.1.0', uiBuildId: data.uiBuildId }} session={session} />);
    const report = screen.getByLabelText('Runtime report');
    const receipt = report.querySelector<HTMLElement>('[data-received-at]')?.getAttribute('data-received-at');
    expect(receipt).toBeTruthy();
    const instance = screen.getByText('server_fixture_1');
    instance.tabIndex = -1; instance.focus();
    const range = document.createRange(); range.selectNodeContents(instance);
    window.getSelection()?.removeAllRanges(); window.getSelection()?.addRange(range);
    document.documentElement.scrollTop = 543;
    await act(async () => { await session.refresh(); });
    expect(screen.getByText('Connected server')).toBeTruthy();
    expect(screen.getByText('server_fixture_1')).toBeTruthy();
    expect(screen.getByText('Previously loaded metadata may be outdated. Refresh to read current details.')).toBeTruthy();
    expect(screen.getByLabelText('Runtime report').querySelector<HTMLElement>('[data-received-at]')?.getAttribute('data-received-at')).toBe(receipt);
    expect(screen.getByText('server_fixture_1')).toBe(instance);
    expect(document.activeElement).toBe(instance);
    expect(window.getSelection()?.toString()).toBe('server_fixture_1');
    expect(document.documentElement.scrollTop).toBe(543);
    expect(gateway.bootstrap).toHaveBeenCalledTimes(2);
    monotonic = 10_000;
    await act(async () => { await vi.advanceTimersByTimeAsync(10_000); });
    expect(screen.getByLabelText('Runtime report').textContent).toContain('about 10 seconds ago');
    expect(gateway.bootstrap).toHaveBeenCalledTimes(2);
    await act(async () => { await session.refresh(); });
    expect(screen.queryByText('Previously loaded metadata may be outdated. Refresh to read current details.')).toBeNull();
    expect(screen.getByText('server_fixture_1')).toBe(instance);
    expect(document.activeElement).toBe(instance);
    expect(window.getSelection()?.toString()).toBe('server_fixture_1');
    expect(document.documentElement.scrollTop).toBe(543);
    expect(gateway.bootstrap).toHaveBeenCalledTimes(3);
    expect(document.body.textContent).not.toContain(data.csrfToken);
    view.unmount();
  } finally { session.dispose(); vi.restoreAllMocks(); vi.useRealTimers(); }
});

it('keeps the Runtime retry control focused after a transient session check failure', async () => {
  const fixture = JSON.parse(readFileSync(resolve(process.cwd(), '../contracts/web/v1/fixtures/bootstrap.json'), 'utf8')) as { data: Bootstrap };
  const data = { ...fixture.data, sessionExpiresAt: new Date(Date.now() + 60_000).toISOString() };
  const gateway = { bootstrap: vi.fn().mockResolvedValueOnce(data).mockRejectedValueOnce(new Error('offline')),
    exchange: vi.fn(), logout: vi.fn() };
  const session = createBrowserSession(gateway, '/');
  try {
    await session.initialize({ kind: 'absent' });
    render(<Runtime identity={{ applicationVersion: '0.1.0', uiBuildId: data.uiBuildId }} session={session} />);
    const check = screen.getByRole('button', { name: 'Check session' });
    check.focus();
    expect(document.activeElement).toBe(check);
    fireEvent.click(check);
    await act(async () => { await Promise.resolve(); await Promise.resolve(); });
    expect(screen.getByText('Previously loaded metadata may be outdated. Refresh to read current details.')).toBeTruthy();
    expect(screen.getByRole('button', { name: 'Check session' })).toBe(check);
    expect(document.activeElement).toBe(check);
    expect(gateway.bootstrap).toHaveBeenCalledTimes(2);
  } finally { session.dispose(); }
});

it('discards instance-bound storage and maintenance results when the Runtime server changes', async () => {
  const fixture = JSON.parse(readFileSync(resolve(process.cwd(), '../contracts/web/v1/fixtures/bootstrap.json'), 'utf8')) as { data: Bootstrap };
  const data = { ...fixture.data, sessionExpiresAt: new Date(Date.now() + 60_000).toISOString() };
  const storage = JSON.parse(readFileSync(resolve(process.cwd(), '../contracts/web/v1/fixtures/storage-summary.json'), 'utf8')) as { requestId: string; data: { totalBytes: string } };
  const maintenance = JSON.parse(readFileSync(resolve(process.cwd(), '../contracts/web/v1/fixtures/maintenance-preview.json'), 'utf8')) as { requestId: string };
  const responses = new Map([
    ['/api/v1/storage', storage], ['/api/v1/storage/maintenance-preview', maintenance],
  ]);
  const fetcher = vi.fn<typeof fetch>(async input => {
    const path = new URL(String(input), window.location.origin).pathname;
    const suffix = path.endsWith('/storage/maintenance-preview') ? '/api/v1/storage/maintenance-preview' : '/api/v1/storage';
    const document = responses.get(suffix);
    expect(document).toBeTruthy();
    return new Response(JSON.stringify(document), { status: 200, headers: {
      'Content-Type': 'application/json; charset=utf-8', 'X-Request-ID': document!.requestId,
    } });
  });
  vi.stubGlobal('fetch', fetcher);
  const gateway = { bootstrap: vi.fn().mockResolvedValueOnce(data).mockResolvedValueOnce({ ...data, serverInstanceId: 'server_fixture_2' }),
    exchange: vi.fn(), logout: vi.fn() };
  const session = createBrowserSession(gateway, '/');
  try {
    await session.initialize({ kind: 'absent' });
    render(<Runtime identity={{ applicationVersion: '0.1.0', uiBuildId: data.uiBuildId }} session={session} />);
    fireEvent.click(screen.getByRole('button', { name: 'Read storage and maintenance preview' }));
    await waitFor(() => expect(screen.getByText('Total').nextElementSibling?.textContent).toBe(formatExactBytes(storage.data.totalBytes)));
    expect(screen.getByText('Maintenance preview (dry run)')).toBeTruthy();
    await act(async () => { await session.refresh(); });
    expect(screen.getByText('server_fixture_2')).toBeTruthy();
    expect(screen.queryByText(formatExactBytes(storage.data.totalBytes))).toBeNull();
    expect(screen.queryByText('Maintenance preview (dry run)')).toBeNull();
    expect(fetcher).toHaveBeenCalledTimes(2);
  } finally { session.dispose(); }
});

it('clears retained Runtime facts after a non-transient session refusal', async () => {
  const fixture = JSON.parse(readFileSync(resolve(process.cwd(), '../contracts/web/v1/fixtures/bootstrap.json'), 'utf8')) as { data: Bootstrap };
  const data = { ...fixture.data, sessionExpiresAt: new Date(Date.now() + 60_000).toISOString() };
  const gateway = { bootstrap: vi.fn().mockResolvedValueOnce(data).mockRejectedValueOnce(
    new ApiClientError('http_error', { status: 401, serverCode: 'SESSION_EXPIRED' })).mockRejectedValueOnce(new ApiClientError('network_error')),
    exchange: vi.fn(), logout: vi.fn() };
  const session = createBrowserSession(gateway, '/');
  try {
    await session.initialize({ kind: 'absent' });
    render(<Runtime identity={{ applicationVersion: '0.1.0', uiBuildId: data.uiBuildId }} session={session} />);
    expect(screen.getByText('server_fixture_1')).toBeTruthy();
    await act(async () => { await session.refresh(); });
    expect(screen.queryByText('server_fixture_1')).toBeNull();
    expect(screen.queryByLabelText('Runtime report')).toBeNull();
    expect(screen.queryByText(/Previously loaded metadata may be outdated/)).toBeNull();
    expect(screen.getByText('Runtime information is not connected')).toBeTruthy();
    await act(async () => { await session.refresh(); });
    expect(screen.queryByText('server_fixture_1')).toBeNull();
    expect(screen.queryByLabelText('Runtime report')).toBeNull();
  } finally { session.dispose(); }
});

it('clears connection-retained Runtime facts when another tab invalidates the session', async () => {
  const fixture = JSON.parse(readFileSync(resolve(process.cwd(), '../contracts/web/v1/fixtures/bootstrap.json'), 'utf8')) as { data: Bootstrap };
  const data = { ...fixture.data, sessionExpiresAt: new Date(Date.now() + 60_000).toISOString() };
  const listeners = new Set<EventListenerOrEventListenerObject>();
  class TestBroadcastChannel {
    static current: TestBroadcastChannel | null = null;
    constructor() { TestBroadcastChannel.current = this; }
    addEventListener(_type: string, listener: EventListenerOrEventListenerObject) {
      listeners.add(listener);
    }
    removeEventListener(_type: string, listener: EventListenerOrEventListenerObject) {
      listeners.delete(listener);
    }
    postMessage() {}
    close() {}
    emit(data: unknown) {
      const event = { data } as MessageEvent;
      for (const listener of listeners) {
        if (typeof listener === 'function') listener(event);
        else listener.handleEvent(event);
      }
    }
  }
  vi.stubGlobal('BroadcastChannel', TestBroadcastChannel);
  const gateway = { bootstrap: vi.fn().mockResolvedValueOnce(data).mockRejectedValueOnce(new ApiClientError('network_error')),
    exchange: vi.fn(), logout: vi.fn() };
  const session = createBrowserSession(gateway, '/');
  try {
    await session.initialize({ kind: 'absent' });
    render(<Runtime identity={{ applicationVersion: '0.1.0', uiBuildId: data.uiBuildId }} session={session} />);
    await act(async () => { await session.refresh(); });
    expect(screen.getByText('server_fixture_1')).toBeTruthy();
    expect(screen.getByText('Previously loaded metadata may be outdated. Refresh to read current details.')).toBeTruthy();
    await act(async () => {
      TestBroadcastChannel.current?.emit({ version: 1, type: 'session-invalidated' });
      await Promise.resolve();
    });
    expect(screen.queryByText('server_fixture_1')).toBeNull();
    expect(screen.queryByLabelText('Runtime report')).toBeNull();
    expect(screen.queryByText(/Previously loaded metadata may be outdated/)).toBeNull();
    expect(session.snapshot()).toMatchObject({ status: 'unavailable', reason: 'connection' });
    expect(session.snapshot()).not.toHaveProperty('runtime');
    expect(gateway.bootstrap).toHaveBeenCalledTimes(2);
  } finally { session.dispose(); }
});

it('keeps missing scheduler metadata unknown', async () => {
  const { SchedulerSummary } = await import('../src/jobs/SchedulerSummary');
  render(<SchedulerSummary />);
  expect(screen.getByText('Scheduler measurements were not reported.')).toBeTruthy();
  expect(screen.queryByText('0')).toBeNull();
});

it('explains unavailable borrowed-executor telemetry without zero metrics', async () => {
  const { SchedulerSummary } = await import('../src/jobs/SchedulerSummary');
  render(<SchedulerSummary scheduler={{ state: 'unavailable', reasonCode: 'EXTERNAL_EXECUTOR', sampledAt: '2026-09-05T00:00:00Z' }} />);
  expect(screen.getByText(/unavailable for the externally supplied executor/)).toBeTruthy();
  expect(screen.queryByText('Active workers (count)')).toBeNull();
});


it('uses accepted bootstrap time across late runtime mounts without another session read', async () => {
  const epoch = Date.parse('2026-09-05T00:00:00Z'); let elapsed = 0;
  vi.spyOn(Date, 'now').mockImplementation(() => epoch + elapsed);
  vi.spyOn(performance, 'now').mockImplementation(() => elapsed);
  const fixture = JSON.parse(readFileSync(resolve(process.cwd(), '../contracts/web/v1/fixtures/bootstrap.json'), 'utf8')) as { data: Bootstrap };
  const data = { ...fixture.data, sessionExpiresAt: new Date(epoch + 120_000).toISOString() };
  const gateway = { bootstrap: vi.fn().mockResolvedValue(data), exchange: vi.fn(), logout: vi.fn() };
  const session = createBrowserSession(gateway, '/');
  try {
    await session.initialize({ kind: 'absent' });
    elapsed = 40_000;
    const view = render(<Runtime identity={{ applicationVersion: '0.1.0', uiBuildId: data.uiBuildId }} session={session} />);
    const at = screen.getByLabelText('Runtime report').querySelector<HTMLElement>('[data-received-at]')?.getAttribute('data-received-at');
    expect(at).toBe(new Date(epoch).toISOString());
    expect(screen.getByLabelText('Runtime report').textContent).toContain('about 40 seconds ago');
    view.unmount(); elapsed = 60_000;
    const later = render(<Runtime identity={{ applicationVersion: '0.1.0', uiBuildId: data.uiBuildId }} session={session} />);
    expect(screen.getByLabelText('Runtime report').querySelector<HTMLElement>('[data-received-at]')?.getAttribute('data-received-at')).toBe(at);
    expect(screen.getByLabelText('Runtime report').textContent).toContain('about 1 minute ago');
    expect(gateway.bootstrap).toHaveBeenCalledOnce();
    expect(gateway.exchange).not.toHaveBeenCalled(); expect(gateway.logout).not.toHaveBeenCalled();
    expect(document.body.textContent).not.toContain(data.csrfToken);
    expect(JSON.stringify(session.snapshot())).not.toContain(data.csrfToken);
    later.unmount();
  } finally { session.dispose(); vi.restoreAllMocks(); }
});
