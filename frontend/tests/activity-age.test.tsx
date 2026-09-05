import { act, cleanup, render, screen } from '@testing-library/preact';
import { afterEach, beforeEach, expect, it, vi } from 'vitest';
import { ActivityReceiptAge } from '../src/jobs/ActivityReceiptAge';

const receipt = { at: '2026-09-05T00:00:00Z', monotonicMs: 0 };
let clock = 0;
beforeEach(() => {
  vi.useFakeTimers(); clock = 0;
  vi.spyOn(performance, 'now').mockImplementation(() => clock);
});
afterEach(() => { cleanup(); vi.restoreAllMocks(); vi.useRealTimers(); });
async function tick(ms: number) {
  clock += ms;
  await act(async () => { await vi.advanceTimersByTimeAsync(ms); });
}

it('advances a coalesced receipt age without changing the original timestamp or asserting source freshness', async () => {
  render(<p><ActivityReceiptAge receipt={receipt} visible /></p>);
  expect(screen.getByText(/less than 10 seconds ago/)).toBeTruthy();
  expect(document.querySelector('time')?.dateTime).toBe(receipt.at);
  await tick(10000);
  expect(screen.getByText(/about 10 seconds ago/)).toBeTruthy();
  await tick(50000);
  expect(screen.getByText(/about 1 minute ago/)).toBeTruthy();
  expect(screen.getByText(/not the age of the source observations/)).toBeTruthy();
  expect(document.querySelector('[role="status"], [aria-live]')).toBeNull();
});

it('uses monotonic elapsed time when the system clock jumps in either direction', async () => {
  render(<ActivityReceiptAge receipt={receipt} visible />);
  vi.setSystemTime(new Date('2030-01-01T00:00:00Z'));
  await tick(10000);
  expect(screen.getByText(/about 10 seconds ago/)).toBeTruthy();
  vi.setSystemTime(new Date('2000-01-01T00:00:00Z'));
  await tick(10000);
  expect(screen.getByText(/about 20 seconds ago/)).toBeTruthy();
  expect(document.querySelector('time')?.dateTime).toBe(receipt.at);
});

it('releases the timer while hidden, catches up on return, and cleans up on unmount', async () => {
  const view = render(<ActivityReceiptAge receipt={receipt} visible />);
  expect(vi.getTimerCount()).toBe(1);
  view.rerender(<ActivityReceiptAge receipt={receipt} visible={false} />);
  await act(async () => { await Promise.resolve(); });
  expect(vi.getTimerCount()).toBe(0);
  clock = 7200000;
  view.rerender(<ActivityReceiptAge receipt={receipt} visible />);
  expect(screen.getByText(/about 2 hours ago/)).toBeTruthy();
  await act(async () => { await Promise.resolve(); });
  expect(vi.getTimerCount()).toBe(1);
  view.unmount(); expect(vi.getTimerCount()).toBe(0);
});

it('resets the receipt age when a new verified page arrives', async () => {
  const view = render(<ActivityReceiptAge receipt={receipt} visible />);
  await tick(60000);
  const updated = { at: '2026-09-05T00:01:00Z', monotonicMs: clock };
  view.rerender(<ActivityReceiptAge receipt={updated} visible />);
  expect(screen.getByText(/less than 10 seconds ago/)).toBeTruthy();
  expect(document.querySelector('time')?.dateTime).toBe(updated.at);
});
