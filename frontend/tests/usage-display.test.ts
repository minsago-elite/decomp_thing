import { expect, it } from 'vitest';
import type { WebEvent } from '../src/api/generated';
import { createUsageDisplay, isContextUsageUpdate } from '../src/jobs/usageDisplay';

interface DisplaySnapshot { readonly records: readonly number[]; readonly cursor: string; readonly receivedAt: number }
const snapshot = (count: number): DisplaySnapshot => Object.freeze({
  records: Object.freeze(Array.from({ length: count }, (_, index) => index + 1)),
  cursor: `cursor_${count}`, receivedAt: 1000 + count,
});

/** Synchronous callbacks and frozen DTOs only; no timers, DOM, transport or provider is opened. */
function controls() {
  let current: DisplaySnapshot | undefined;
  let nextHandle = 0;
  const waiting = new Map<number, () => void>();
  const callbacks = new Map<number, () => void>();
  const published: DisplaySnapshot[] = [];
  const display = createUsageDisplay<DisplaySnapshot, number>({
    schedule(callback) {
      const handle = ++nextHandle;
      waiting.set(handle, callback); callbacks.set(handle, callback); return handle;
    },
    cancel(handle) { waiting.delete(handle); },
    isCurrent(value) { return value === current; },
    publish(value) { published.push(value); },
  });
  return {
    display, waiting, callbacks, published,
    update(value: DisplaySnapshot, coalesce: boolean) { current = value; display.update(value, coalesce); },
    select(value: DisplaySnapshot) { current = value; },
    tick() {
      const next = waiting.entries().next();
      if (next.done) throw new Error('No scheduled display callback');
      const [handle, callback] = next.value; waiting.delete(handle); callback();
    },
    late(handle: number) {
      const callback = callbacks.get(handle);
      if (!callback) throw new Error('No captured display callback');
      callback();
    },
  };
}

it('coalesces a usage burst into the latest complete checked snapshot without changing records or receipt time', () => {
  const control = controls(); const first = snapshot(1); let latest = first;
  control.update(first, true);
  for (let count = 2; count <= 100; count++) {
    latest = snapshot(count); control.update(latest, true);
  }
  expect(control.published).toEqual([first]);
  expect(control.waiting.size).toBe(1);
  expect(control.callbacks.size).toBe(1);
  control.tick();
  expect(control.published).toEqual([first, latest]);
  expect(control.published.at(-1)).toBe(latest);
  expect(latest.records).toHaveLength(100);
  expect(latest.cursor).toBe('cursor_100');
  expect(latest.receivedAt).toBe(1100);
  expect(control.waiting.size).toBe(1);
  control.tick();
  expect(control.waiting.size).toBe(0);
  expect(control.published).toHaveLength(2);
});

it('publishes barriers immediately and flushes the final checked snapshot once on pause', () => {
  const control = controls(); const first = snapshot(1); const barrier = snapshot(3);
  control.update(first, true); control.update(snapshot(2), true); control.update(barrier, false);
  expect(control.published).toEqual([first, barrier]);
  expect(control.published.at(-1)).toBe(barrier);
  expect(control.waiting.size).toBe(0);
  control.late(1);
  expect(control.published).toEqual([first, barrier]);
  const fourth = snapshot(4); const fifth = snapshot(5);
  control.update(fourth, true); control.update(fifth, true); control.late(1);
  expect(control.published).toEqual([first, barrier, fourth]);
  expect(control.waiting.size).toBe(1);
  control.display.close();
  expect(control.published).toEqual([first, barrier, fourth, fifth]);
  expect(control.waiting.size).toBe(0);
  control.late(2); control.update(snapshot(6), true); control.display.close();
  expect(control.published).toEqual([first, barrier, fourth, fifth]);
  expect(control.waiting.size).toBe(0);
});

it('discards a pending snapshot after reset or scope replacement and ignores cancelled callbacks', () => {
  const control = controls(); const first = snapshot(1);
  control.update(first, true); control.update(snapshot(2), true);
  control.select(snapshot(0)); control.display.close(); control.late(1);
  expect(control.published).toEqual([first]);
  expect(control.waiting.size).toBe(0);
});

it('coalesces only context usage metadata without reading private fields or delaying outcome records', () => {
  const observation = (kind: string) => ({ type: 'workflow.observation', payload: {
    observationKind: kind, get fields(): never { throw new Error('Unrelated fields must not be read'); },
  } }) as unknown as WebEvent;
  expect(isContextUsageUpdate(observation('context_usage'))).toBe(true);
  for (const kind of ['agent_finished', 'message', 'tool', 'permission', 'workflow_phase', 'unknown']) {
    expect(isContextUsageUpdate(observation(kind))).toBe(false);
  }
  const state = { type: 'run.state', get payload(): never { throw new Error('State payload must not be read'); } } as unknown as WebEvent;
  expect(isContextUsageUpdate(state)).toBe(false);
});
