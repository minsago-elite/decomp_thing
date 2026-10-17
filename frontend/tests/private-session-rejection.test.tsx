import { readFileSync } from 'node:fs';
import { resolve } from 'node:path';
import { act, fireEvent, render, screen, waitFor } from '@testing-library/preact';
import { afterEach, expect, it, vi } from 'vitest';
import type { Bootstrap, Job as JobData } from '../src/api/generated';
import { PrivateSessionContext, usePrivateTransport } from '../src/session/PrivateTransport';
import { createBrowserSession } from '../src/session/session';
import { SessionStatus } from '../src/session/SessionStatus';
import Runtime from '../src/routes/Runtime';
import Job from '../src/routes/Job';

const fixture = JSON.parse(readFileSync(resolve('../contracts/web/v1/fixtures/bootstrap-scheduler-saturated.json'), 'utf8')) as { data: Bootstrap };
const error = { apiVersion: 1, kind: 'error', requestId: 'request_example_1', error: {
  code: 'SESSION_EXPIRED', message: 'Session expired.', retryable: false, details: [], retryAfterMs: null,
} };
afterEach(() => vi.unstubAllGlobals());

for (const reported of [true, false]) {
  it(`refresh replaces private job state and ignores old completions with ${reported ? 'changed' : 'unreported'} instance identity`, async () => {
    const jobFixture = JSON.parse(readFileSync(resolve('../contracts/web/v1/fixtures/job-lossless.json'), 'utf8')) as {
      apiVersion: 1; kind: 'job'; requestId: string; data: JobData;
    };
    const jobId = 'a'.repeat(32);
    const reply = (displayFilename: string) => new Response(JSON.stringify({
      ...jobFixture, data: { ...jobFixture.data, jobId, displayFilename },
    }), { headers: { 'Content-Type': 'application/json', 'X-Request-ID': jobFixture.requestId } });
    let completeOld!: (response: Response) => void;
    const oldRead = new Promise<Response>((complete) => { completeOld = complete; });
    const fetcher = vi.fn<typeof fetch>().mockReturnValueOnce(oldRead).mockResolvedValueOnce(reply('fresh-instance.elf'));
    vi.stubGlobal('fetch', fetcher);
    const data: Bootstrap = { ...fixture.data, sessionExpiresAt: new Date(Date.now() + 60_000).toISOString(),
      ...(reported ? { serverInstanceId: 'server_fixture_1' } : {}) };
    const gateway = { bootstrap: vi.fn().mockResolvedValue(data), exchange: vi.fn(), logout: vi.fn() };
    const session = createBrowserSession(gateway, '/');
    try {
      await session.initialize({ kind: 'absent' });
      render(<PrivateSessionContext.Provider value={session}>
        <Job jobId={jobId} basePath="" session={session} />
      </PrivateSessionContext.Provider>);
      await waitFor(() => expect(fetcher).toHaveBeenCalledOnce());
      gateway.bootstrap.mockResolvedValueOnce({ ...data, ...(reported ? { serverInstanceId: 'server_fixture_2' } : {}) });
      await act(async () => { await session.refresh(); });
      await screen.findByText('fresh-instance.elf');
      expect(fetcher).toHaveBeenCalledTimes(2);
      expect(fetcher.mock.calls[0]?.[1]?.signal?.aborted).toBe(true);
      await act(async () => { completeOld(reply('stale-instance.elf')); await Promise.resolve(); });
      expect(screen.queryByText('stale-instance.elf')).toBeNull();
      expect(screen.getByText('fresh-instance.elf')).toBeTruthy();
      expect(gateway.bootstrap).toHaveBeenCalledTimes(2);
      expect(gateway.exchange).not.toHaveBeenCalled();
      expect(gateway.logout).not.toHaveBeenCalled();
    } finally { session.dispose(); }
  });
}

function Reader({ mode }: { mode: 'get' | 'stream' | 'put' }) {
  const { client, stream } = usePrivateTransport('/');
  async function read() {
    try {
      if (mode === 'stream') await stream({ jobId: 'a'.repeat(32), runId: 'run_fixture' }).next();
      else if (mode === 'put') await client.put('progressPin', '/jobs/job_fixture/runs/run_fixture/progress-pin',
        'progressPinRequest', { pinned: true }, {
          csrfToken: 'a'.repeat(43), idempotencyKey: 'fixture_intent_12345', ifMatch: '"version_fixture"',
        });
      else await client.get('jobs', '/jobs');
    } catch { /* The transport informs shared session state; no retry. */ }
  }
  return <button onClick={() => { void read(); }}>Request private data</button>;
}

for (const mode of ['get', 'stream', 'put'] as const) {
  it(`${mode} rejection clears sibling runtime evidence and credentials without another request`, async () => {
    const fetcher = vi.fn<typeof fetch>().mockResolvedValue(new Response(JSON.stringify(error), {
      status: 401, headers: { 'Content-Type': 'application/json', 'X-Request-ID': error.requestId },
    }));
    vi.stubGlobal('fetch', fetcher);
    const gateway = {
      bootstrap: vi.fn().mockResolvedValue({ ...fixture.data, sessionExpiresAt: new Date(Date.now() + 60_000).toISOString() }),
      exchange: vi.fn(), logout: vi.fn(),
    };
    const session = createBrowserSession(gateway, '/');
    try {
      await session.initialize({ kind: 'absent' });
      render(<PrivateSessionContext.Provider value={session}>
        <SessionStatus session={session} />
        <Reader mode={mode} />
        <Runtime identity={{ applicationVersion: '0.1.0', uiBuildId: 'fixture' }} session={session} />
      </PrivateSessionContext.Provider>);
      expect(screen.getByText('Web workflow scheduler')).toBeTruthy();
      await act(() => { fireEvent.click(screen.getByText('Request private data')); });
      await waitFor(() => expect(screen.queryByText('Web workflow scheduler')).toBeNull());
      expect(screen.getByText(/Your local session expired/)).toBeTruthy();
      expect(session.csrf()).toBeNull();
      expect(fetcher).toHaveBeenCalledOnce();
      expect(gateway.bootstrap).toHaveBeenCalledOnce();
      expect(gateway.exchange).not.toHaveBeenCalled();
      expect(gateway.logout).not.toHaveBeenCalled();
    } finally { session.dispose(); }
  });
}
