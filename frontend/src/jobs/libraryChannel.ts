/**
 * Same-origin, deployment-scoped hint that the job library changed (a deletion or organization
 * edit in another tab). It carries no job, session or credential material: receivers re-read
 * their own resources from the server, which remains the only authority.
 */
export const libraryChannelName = (basePath: string) => `decomp-jobs-v1:${basePath.replace(/\/$/, '')}`;

export function onLibraryChange(basePath: string, changed: () => void): () => void {
  let channel: BroadcastChannel | null = null;
  try {
    channel = new BroadcastChannel(libraryChannelName(basePath));
    channel.onmessage = (event: MessageEvent<unknown>) => {
      const data = event.data as Record<string, unknown> | null;
      if (data && typeof data === 'object' && Object.keys(data).length === 2 && data.version === 1 && data.type === 'jobs-changed') changed();
    };
  } catch { channel = null; }
  return () => { channel?.close(); };
}
