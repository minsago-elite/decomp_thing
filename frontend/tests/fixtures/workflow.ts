import { readFileSync } from 'node:fs';
import { resolve } from 'node:path';
import { vi } from 'vitest';
import { decodeContract } from '../../src/api/decode';
import type { WebEvent } from '../../src/api/generated';

/** Mock transport only: no HTTP server, authentication or persisted workflow runs here. */
export function controlledWorkflow(now: () => number = Date.now) {
  const decoded = decodeContract(readFileSync(resolve('../contracts/web/v1/fixtures/event-observation-public-metadata.json'), 'utf8'));
  if (decoded.kind !== 'event' || decoded.type !== 'workflow.observation') throw new Error('Invalid workflow fixture');
  const base = decoded;
  let sequence = BigInt(base.sequence);
  return {
    selection: { jobId: base.jobId, runId: base.runId },
    // Capture time at publication; replay the returned event unchanged, including its identity.
    event(): WebEvent {
      const next = sequence++;
      return { ...base, payload: structuredClone(base.payload), sequence: String(next), cursor: `cursor_fixture_${next}`,
        occurredAt: new Date(now()).toISOString() };
    },
    connection: controlledEventConnection,
  };
}

/** Explicit send/close controls permit late, duplicate and reordered delivery without sleeps. */
export function controlledEventConnection() {
  let controller!: ReadableStreamDefaultController<Uint8Array>;
  const cancel = vi.fn();
  const body = new ReadableStream<Uint8Array>({ start(value) { controller = value; }, cancel });
  return {
    cancel,
    close: () => controller.close(),
    send: (...events: WebEvent[]) => controller.enqueue(new TextEncoder().encode(events.map(event =>
      `${event.type === 'retention.gap' ? '' : `id: ${event.cursor}\n`}event: ${event.type}\ndata: ${JSON.stringify(event)}\n\n`).join(''))),
    response: new Response(body, { headers: { 'Content-Type': 'text/event-stream', 'X-Request-ID': 'request_example_1' } }),
  };
}
