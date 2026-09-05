import { readFileSync } from 'node:fs';
import { resolve } from 'node:path';
import { act, render, screen } from '@testing-library/preact';
import { expect, it, vi } from 'vitest';
import type { Bootstrap } from '../src/api/generated';
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
    expect(screen.getByText(/queue position and start time are not reported/)).toBeTruthy();
    expect(screen.getByText('degraded')).toBeTruthy();
    expect(screen.getByText('Uploads unavailable')).toBeTruthy();
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
