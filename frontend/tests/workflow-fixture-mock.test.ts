import { afterEach, expect, it, vi } from 'vitest';
import { createEventStream } from '../src/api/eventStream';
import { controlledWorkflow } from './fixtures/workflow';

afterEach(() => vi.useRealTimers());

it('mock workflow replays exact identities and logical timestamps across fresh scenarios', async () => {
  vi.useFakeTimers();
  async function scenario() {
    vi.setSystemTime(new Date('2026-09-08T00:00:00Z'));
    const workflow = controlledWorkflow();
    const first = workflow.event();
    await vi.advanceTimersByTimeAsync(2000);
    const second = workflow.event();
    expect(first.occurredAt).toBe('2026-09-08T00:00:00.000Z');
    expect(second.occurredAt).toBe('2026-09-08T00:00:02.000Z');
    expect(BigInt(second.sequence!) - BigInt(first.sequence!)).toBe(1n);
    const live = workflow.connection();
    const resumed = workflow.connection();
    const fetcher = vi.fn<typeof fetch>().mockResolvedValueOnce(live.response).mockResolvedValueOnce(resumed.response);
    const events = createEventStream({ basePath: '/', fetch: fetcher });
    // Late publication and replay are explicit; no network or elapsed-time race is claimed.
    const stream = events(workflow.selection);
    const pending = stream.next();
    live.send(first);
    expect((await pending).value).toEqual(first);
    live.send(first, second);
    expect((await stream.next()).value).toEqual(first);
    expect((await stream.next()).value).toEqual(second);
    await stream.return(undefined);
    expect(live.cancel).toHaveBeenCalledOnce();
    const replay = events({ ...workflow.selection, after: first.cursor! });
    const next = replay.next();
    resumed.send(second); resumed.close();
    expect((await next).value).toEqual(second);
    expect((await replay.next()).done).toBe(true);
    expect(new Headers(fetcher.mock.calls[1]![1]?.headers).get('Last-Event-ID')).toBe(first.cursor);
    return [first, second];
  }
  expect(await scenario()).toEqual(await scenario());
});

it('mock fixture event values cannot mutate a later publication', () => {
  const fixture = controlledWorkflow(() => 0);
  const first = fixture.event();
  if (first.type !== 'workflow.observation') throw new Error('Unexpected event');
  first.payload.fields = {};
  const second = fixture.event();
  if (second.type !== 'workflow.observation') throw new Error('Unexpected event');
  expect(second.payload.fields).not.toEqual({});
});
