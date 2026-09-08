/** Same-origin, deployment-scoped invalidation hints carry no session or job material. */
export function createInvalidationChannel(basePath: string, invalidate: () => void) {
  let channel: BroadcastChannel | null = null;
  const receive = (event: MessageEvent<unknown>) => {
    const data = event.data;
    if (typeof data !== 'object' || data === null || Array.isArray(data)) return;
    const message = data as Record<string, unknown>;
    if (Object.keys(message).length === 2 && Object.hasOwn(message, 'version') && Object.hasOwn(message, 'type') && message.version === 1 && message.type === 'session-invalidated') invalidate();
  };
  try {
    if (typeof window !== 'undefined' && typeof window.BroadcastChannel === 'function') {
      channel = new window.BroadcastChannel(`decomp-session-v1:${basePath}`);
      channel.addEventListener('message', receive);
    }
  } catch { channel?.close(); channel = null; }
  return {
    notify() {
      try { channel?.postMessage({ version: 1, type: 'session-invalidated' }); }
      catch { /* A notification failure must not change confirmed server logout. */ }
    },
    close() {
      channel?.removeEventListener('message', receive);
      channel?.close(); channel = null;
    },
  };
}
