import { act, cleanup, fireEvent, render, screen } from '@testing-library/preact';
import { afterEach, beforeEach, expect, it, vi } from 'vitest';
import { MetadataReceipt } from '../src/shared/MetadataReceipt';
import { receive } from '../src/shared/receiptTime';

let monotonic = 0;
let visible = true;
let useWallClock = false;
beforeEach(() => {
  vi.useFakeTimers(); vi.setSystemTime(0); monotonic = 0; visible = true; useWallClock = false;
  vi.spyOn(performance, 'now').mockImplementation(() => useWallClock ? Date.now() : monotonic);
  vi.spyOn(document, 'visibilityState', 'get').mockImplementation(() => visible ? 'visible' : 'hidden');
});
afterEach(() => { cleanup(); vi.restoreAllMocks(); vi.useRealTimers(); });

it('ages one accepted snapshot without changing focus selection URL or a live region', async () => {
  const snapshot = receive({ selected: 'retained-case' });
  const view = render(<><input aria-label="Local case filter" value="retained-case" /><MetadataReceipt kind="validationReport" receipt={snapshot.receipt} /></>);
  const input = screen.getByRole<HTMLInputElement>('textbox');
  input.focus(); input.setSelectionRange(2, 6);
  const time = screen.getByLabelText('Selected validation report').querySelector<HTMLElement>('[data-received-at]');
  const url = location.href;
  useWallClock = true;
  await act(async () => { await vi.advanceTimersByTimeAsync(60_000); });
  expect(screen.getByLabelText('Selected validation report').textContent).toContain('about 1 minute ago');
  expect(document.activeElement).toBe(input);
  expect([input.selectionStart, input.selectionEnd]).toEqual([2, 6]);
  expect(location.href).toBe(url);
  expect(screen.getByLabelText('Selected validation report').querySelector<HTMLElement>('[data-received-at]')).toBe(time);
  expect(time?.getAttribute('data-received-at')).toBe(snapshot.receipt.at);
  expect(document.querySelector('[role="status"], [aria-live]')).toBeNull();
  expect(snapshot.value.selected).toBe('retained-case');
  view.unmount(); expect(vi.getTimerCount()).toBe(0);
});

it('keeps missing receipt time unknown without inventing a mount timestamp or clock', async () => {
  const view = render(<MetadataReceipt kind="runtime" receipt={undefined} />);
  expect(screen.getByLabelText('Runtime report').textContent).toContain('Receipt time was not recorded');
  expect(document.querySelector('time')).toBeNull();
  expect(document.querySelector<HTMLElement>('[data-received-at]')).toBeNull();
  expect(vi.getTimerCount()).toBe(0);
  await act(async () => { await vi.advanceTimersByTimeAsync(60_000); });
  expect(document.querySelector('time')).toBeNull();
  expect(document.querySelector<HTMLElement>('[data-received-at]')).toBeNull();
  view.unmount(); expect(vi.getTimerCount()).toBe(0);
});

it('stops a hidden clock and resets all receipt coordinates after suspended delivery', async () => {
  const old = receive('old');
  const view = render(<MetadataReceipt kind="file" receipt={old.receipt} />);
  visible = false; fireEvent(document, new Event('visibilitychange'));
  await act(async () => { await Promise.resolve(); });
  expect(vi.getTimerCount()).toBe(0);
  vi.setSystemTime(3_600_000);
  visible = true; fireEvent(document, new Event('visibilitychange'));
  await act(async () => { await Promise.resolve(); });
  expect(screen.getByLabelText('Source file metadata').textContent).toContain('about 1 hour ago');
  const fresh = receive('fresh');
  expect(fresh.receipt.monotonicMs).toBe(old.receipt.monotonicMs);
  view.rerender(<MetadataReceipt kind="file" receipt={fresh.receipt} />);
  await act(async () => { await Promise.resolve(); });
  expect(screen.getByLabelText('Source file metadata').textContent).toContain('less than 10 seconds ago');
  expect(document.querySelector<HTMLElement>('[data-received-at]')?.getAttribute('data-received-at')).toBe(fresh.receipt.at);
  expect(vi.getTimerCount()).toBe(1);
  view.unmount(); expect(vi.getTimerCount()).toBe(0);
});


it('reconciles a retained receipt suspended before its first mounted sample', async () => {
  const retained = receive('accepted before suspension');
  monotonic = 1000; vi.setSystemTime(3_601_000);
  const view = render(<MetadataReceipt kind="runtime" receipt={retained.receipt} />);
  await act(async () => { await Promise.resolve(); });
  expect(screen.getByLabelText('Runtime report').textContent).toContain('about 1 hour ago');
  expect(screen.getByLabelText('Runtime report').querySelector<HTMLElement>('[data-received-at]')?.getAttribute('data-received-at')).toBe(retained.receipt.at);
  expect(document.querySelector('[role="status"], [aria-live]')).toBeNull();
  view.unmount(); expect(vi.getTimerCount()).toBe(0);
});

it('reconciles a cached receipt after an unmounted interval longer than a display sample', async () => {
  const retained = receive('cached original page');
  const first = render(<MetadataReceipt kind="library" receipt={retained.receipt} />);
  await act(async () => { await Promise.resolve(); });
  first.unmount(); expect(vi.getTimerCount()).toBe(0);
  // Two minutes of active time and one hour of suspended time pass off this view.
  monotonic = 120_000; vi.setSystemTime(3_720_000);
  const returned = render(<MetadataReceipt kind="library" receipt={retained.receipt} />);
  await act(async () => { await Promise.resolve(); });
  expect(screen.getByLabelText('Displayed job library').textContent).toContain('about 1 hour ago');
  expect(screen.getByLabelText('Displayed job library').querySelector<HTMLElement>('[data-received-at]')?.getAttribute('data-received-at')).toBe(retained.receipt.at);
  expect(retained.value).toBe('cached original page');
  expect(vi.getTimerCount()).toBe(1);
  returned.unmount(); expect(vi.getTimerCount()).toBe(0);
});


it('keeps persisted server timestamps separate from local receipt coordinates', async () => {
  const receipt = receive('job snapshot').receipt;
  const createdAt = '2026-09-05T00:00:00.123456789Z';
  const view = render(<><dl><dt>Created</dt><dd><time dateTime={createdAt} title={createdAt}>2026-09-05 00:00:00.123456789 UTC</time></dd></dl>
    <MetadataReceipt kind="job" receipt={receipt} /></>);
  await act(async () => { await Promise.resolve(); });
  const persisted = [...view.container.querySelectorAll('time')];
  expect(persisted).toHaveLength(1);
  expect(persisted[0]?.dateTime).toBe(createdAt);
  expect(persisted[0]?.title).toBe(createdAt);
  const coordinate = screen.getByLabelText('Job metadata').querySelector<HTMLElement>('[data-received-at]');
  expect(coordinate?.getAttribute('data-received-at')).toBe(receipt.at);
  expect(coordinate?.title).toBe(receipt.at);
  expect(coordinate?.textContent).toBe('1970-01-01 00:00:00.000 UTC');
  expect(screen.getByLabelText('Job metadata').textContent).toContain('less than 10 seconds ago');
  expect(document.querySelector('[role="status"], [aria-live]')).toBeNull();
  view.unmount(); expect(vi.getTimerCount()).toBe(0);
});
