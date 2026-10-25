/**
 * Same-origin, deployment-scoped hint that the job library changed (a deletion or organization
 * edit in another tab). It carries no job, session or credential material: receivers re-read
 * their own resources from the server, which remains the only authority.
 */
const channelName = (basePath: string) => `decomp-jobs-v1:${basePath.replace(/\/$/, '')}`;

export function onLibraryChange(basePath: string, changed: () => void): () => void {
  let channel: BroadcastChannel | null = null;
  try {
    channel = new BroadcastChannel(channelName(basePath));
    channel.onmessage = (event: MessageEvent<unknown>) => {
      const data = event.data as Record<string, unknown> | null;
      if (data && typeof data === 'object' && Object.keys(data).length === 2 && data.version === 1 && data.type === 'jobs-changed') changed();
    };
  } catch { channel = null; }
  return () => { channel?.close(); };
}

export function notifyLibraryChanged(basePath: string) {
  try {
    const channel = new BroadcastChannel(channelName(basePath));
    channel.postMessage({ version: 1, type: 'jobs-changed' });
    channel.close();
  } catch { /* A missing hint never changes server state; other tabs reconcile on their next read. */ }
}
