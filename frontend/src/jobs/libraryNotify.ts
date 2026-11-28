import { libraryChannelName } from './libraryChannel';

/** Sender half, loaded only by the lazily loaded routes that change the job library. */
export function notifyLibraryChanged(basePath: string) {
  try {
    const channel = new BroadcastChannel(libraryChannelName(basePath));
    channel.postMessage({ version: 1, type: 'jobs-changed' });
    channel.close();
  } catch { /* A missing hint never changes server state; other tabs reconcile on their next read. */ }
}
