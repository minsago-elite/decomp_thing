import { createContext } from 'preact';
import { useContext, useMemo } from 'preact/hooks';
import { createApiClient } from '../api/client';
import { createEventStream } from '../api/eventStream';
import type { BrowserSession } from './session';

export const PrivateSessionContext = createContext<BrowserSession | null>(null);

/** Each request captures its own session generation, including after a new sign-in. */
export function usePrivateTransport(basePath: string, timeoutMs?: number) {
  const session = useContext(PrivateSessionContext);
  return useMemo(() => {
    const observation = session ? { observeFailure: () => session.observeRequestFailure() } : {};
    return {
      client: createApiClient({ basePath, ...(timeoutMs === undefined ? {} : { timeoutMs }), ...observation }),
      stream: createEventStream({ basePath, ...observation }),
    };
  }, [basePath, timeoutMs, session]);
}
