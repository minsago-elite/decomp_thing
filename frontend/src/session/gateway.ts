import { createApiClient } from '../api/client';
import type { SessionGateway } from './session';

export function createSessionGateway(basePath: string): SessionGateway {
  const client = createApiClient({ basePath });
  return {
    exchange: async (token, signal) => (await client.post('session', '/session', 'sessionStartRequest', { token }, { signal })).data,
    bootstrap: async (signal) => (await client.get('bootstrap', '/bootstrap', { signal })).data,
    logout: async (csrfToken, signal) => { await client.deleteSession({ csrfToken, signal }); },
  };
}
