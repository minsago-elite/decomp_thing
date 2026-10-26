import type { WebEvent } from '../api/generated';

/** Only live context counts may wait; outcomes and other observations are display barriers. */
export function isContextUsageUpdate(event: WebEvent): boolean {
  return event.type === 'workflow.observation' && event.payload.observationKind === 'context_usage';
}

/** Keep one pending display snapshot, never a second event queue or an acknowledgement cursor. */
export function createUsageDisplay<T extends object, Handle>(options: {
  schedule: (callback: () => void) => Handle;
  cancel: (handle: Handle) => void;
  isCurrent: (value: T) => boolean;
  publish: (value: T) => void;
}) {
  let handle: Handle | undefined;
  let windowToken: object | undefined;
  let pending: T | undefined;
  let closed = false;

  const cancelWindow = () => {
    windowToken = undefined;
    if (handle !== undefined) options.cancel(handle);
    handle = undefined;
  };
  const beginWindow = () => {
    const token = {};
    windowToken = token;
    handle = options.schedule(() => {
      if (closed || windowToken !== token) return;
      windowToken = undefined; handle = undefined;
      const value = pending; pending = undefined;
      if (value !== undefined && options.isCurrent(value)) {
        beginWindow();
        options.publish(value);
      }
    });
  };

  return {
    update(value: T, coalesce: boolean) {
      if (closed) return;
      if (!options.isCurrent(value)) {
        pending = undefined; cancelWindow(); return;
      }
      if (!coalesce) {
        pending = undefined; cancelWindow(); options.publish(value); return;
      }
      if (windowToken !== undefined) {
        pending = value; return;
      }
      beginWindow();
      options.publish(value);
    },
    close() {
      if (closed) return;
      closed = true;
      const value = pending; pending = undefined;
      cancelWindow();
      if (value !== undefined && options.isCurrent(value)) options.publish(value);
    },
  };
}
